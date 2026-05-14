package metrics_test

import (
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/sourcehealth"
)

// fakeAdapter is the minimal contract a Registry consumer satisfies:
// a sourcehealth tracker exposed via Health() and a single int64 event
// counter exposed via EventsTotal. Mirrors the structural-typed
// adapterMetrics interface in cmd/olaitan/metrics.go without dragging
// in the cmd package.
type fakeAdapter struct {
	tracker sourcehealth.Tracker
	events  atomic.Int64
}

func (f *fakeAdapter) Health() sourcehealth.Reader { return &f.tracker }
func (f *fakeAdapter) EventsTotal() int64          { return f.events.Load() }

func TestNewRegistry_NotNil(t *testing.T) {
	t.Parallel()
	r := metrics.NewRegistry()
	if r == nil {
		t.Fatal("NewRegistry returned nil")
	}
	if r.Handler() == nil {
		t.Fatal("Handler returned nil")
	}
	if r.Gatherer() == nil {
		t.Fatal("Gatherer returned nil")
	}
}

func TestRegisterAdapter_NilRegistryRejected(t *testing.T) {
	t.Parallel()
	var r *metrics.Registry
	a := &fakeAdapter{}
	if err := r.RegisterAdapter("falco", a.Health(), a.EventsTotal); !errors.Is(err, metrics.ErrNilRegistry) {
		t.Errorf("RegisterAdapter on nil: got %v, want ErrNilRegistry", err)
	}
}

func TestRegisterAdapter_NilArgsRejected(t *testing.T) {
	t.Parallel()
	r := metrics.NewRegistry()
	a := &fakeAdapter{}

	if err := r.RegisterAdapter("", a.Health(), a.EventsTotal); err == nil {
		t.Error("empty source: got nil error, want rejection")
	}
	if err := r.RegisterAdapter("falco", nil, a.EventsTotal); err == nil {
		t.Error("nil health reader: got nil error, want rejection")
	}
	if err := r.RegisterAdapter("falco", a.Health(), nil); err == nil {
		t.Error("nil events getter: got nil error, want rejection")
	}
}

func TestRegisterAdapter_DuplicateSourceRejected(t *testing.T) {
	t.Parallel()
	r := metrics.NewRegistry()
	a := &fakeAdapter{}
	if err := r.RegisterAdapter("falco", a.Health(), a.EventsTotal); err != nil {
		t.Fatalf("first register: %v", err)
	}
	if err := r.RegisterAdapter("falco", a.Health(), a.EventsTotal); err == nil {
		t.Error("duplicate source: got nil error, want rejection")
	}
}

func TestRegisterAdapter_HealthGaugeTracksTracker(t *testing.T) {
	t.Parallel()
	r := metrics.NewRegistry()
	a := &fakeAdapter{}
	if err := r.RegisterAdapter("falco", a.Health(), a.EventsTotal); err != nil {
		t.Fatalf("RegisterAdapter: %v", err)
	}

	// Initial state: tracker reports (false, nil), gauge reads 0.
	body := scrape(t, r)
	if !strings.Contains(body, `olaitan_source_healthy{source="falco"} 0`) {
		t.Errorf("initial: expected gauge=0, body:\n%s", body)
	}

	a.tracker.MarkHealthy()
	body = scrape(t, r)
	if !strings.Contains(body, `olaitan_source_healthy{source="falco"} 1`) {
		t.Errorf("after MarkHealthy: expected gauge=1, body:\n%s", body)
	}

	a.tracker.MarkUnhealthy(errors.New("disconnected"))
	body = scrape(t, r)
	if !strings.Contains(body, `olaitan_source_healthy{source="falco"} 0`) {
		t.Errorf("after MarkUnhealthy: expected gauge=0, body:\n%s", body)
	}
}

func TestRegisterAdapter_EventsCounterAdvances(t *testing.T) {
	t.Parallel()
	r := metrics.NewRegistry()
	a := &fakeAdapter{}
	if err := r.RegisterAdapter("audit", a.Health(), a.EventsTotal); err != nil {
		t.Fatalf("RegisterAdapter: %v", err)
	}
	a.events.Store(42)
	body := scrape(t, r)
	if !strings.Contains(body, `olaitan_sensor_events_total{source="audit"} 42`) {
		t.Errorf("expected counter=42, body:\n%s", body)
	}
}

func TestRegisterAdapter_ConcurrentIncrementsNoDataRace(t *testing.T) {
	t.Parallel()
	r := metrics.NewRegistry()
	a := &fakeAdapter{}
	if err := r.RegisterAdapter("cri", a.Health(), a.EventsTotal); err != nil {
		t.Fatalf("RegisterAdapter: %v", err)
	}

	// Race detector + 1M parallel increments + concurrent scrapes
	// asserts the reader-side path never observes a torn counter
	// (guardrail 26: the prometheus surface is a pure reader of an
	// existing atomic).
	const writers, perWriter = 8, 125_000
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perWriter; j++ {
				a.events.Add(1)
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = scrape(t, r)
			}
		}()
	}
	wg.Wait()

	if got := a.EventsTotal(); got != int64(writers*perWriter) {
		t.Errorf("counter: got %d, want %d", got, writers*perWriter)
	}
}

// TestRegisterAllFiveAdaptersRendered is a Registry-contract test: it
// verifies that the Registry renders olaitan_source_healthy and
// olaitan_sensor_events_total for each of the five canonical source
// label values when wired with a generic fakeAdapter. Production wiring
// only registers four of these (falco, audit, runtime, network) from
// cmd/olaitan/main.go startCollectorRing; the applog source is
// per-pod-sidecar (cmd/olaitan/applog.go runApplogSidecar) and has no
// production metrics surface as of Story 1.12. See Dev Notes binding
// interpretation #8 in the story file for the rationale and the
// deferred-work entry for the applog sidecar metrics surface.
func TestRegisterAllFiveAdaptersRendered(t *testing.T) {
	t.Parallel()
	r := metrics.NewRegistry()
	sources := []string{"falco", "audit", "runtime", "network", "applog"}
	for _, s := range sources {
		a := &fakeAdapter{}
		a.tracker.MarkHealthy()
		a.events.Store(10)
		if err := r.RegisterAdapter(s, a.Health(), a.EventsTotal); err != nil {
			t.Fatalf("RegisterAdapter(%q): %v", s, err)
		}
	}
	body := scrape(t, r)
	for _, s := range sources {
		if !strings.Contains(body, `olaitan_source_healthy{source="`+s+`"} 1`) {
			t.Errorf("missing healthy gauge for %q", s)
		}
		if !strings.Contains(body, `olaitan_sensor_events_total{source="`+s+`"}`) {
			t.Errorf("missing events counter for %q", s)
		}
	}
	if !strings.Contains(body, "# HELP olaitan_source_healthy") {
		t.Error("missing HELP for olaitan_source_healthy")
	}
	if !strings.Contains(body, "# TYPE olaitan_source_healthy gauge") {
		t.Error("missing TYPE gauge for olaitan_source_healthy")
	}
	if !strings.Contains(body, "# HELP olaitan_sensor_events_total") {
		t.Error("missing HELP for olaitan_sensor_events_total")
	}
	if !strings.Contains(body, "# TYPE olaitan_sensor_events_total counter") {
		t.Error("missing TYPE counter for olaitan_sensor_events_total")
	}
}

func TestRegisterPostureCounters_HappyPath(t *testing.T) {
	t.Parallel()
	r := metrics.NewRegistry()
	getters := metrics.PostureGetters{
		"cache_hit":    func() int64 { return 3 },
		"cache_miss":   func() int64 { return 5 },
		"cache_bypass": func() int64 { return 7 },
		"api_errors":   func() int64 { return 11 },
		"orphan_pods":  func() int64 { return 13 },
		"unavailable":  func() int64 { return 17 },
	}
	if err := r.RegisterPostureCounters(getters); err != nil {
		t.Fatalf("RegisterPostureCounters: %v", err)
	}
	body := scrape(t, r)
	want := map[string]string{
		"olaitan_sensor_posture_cache_hit_total":    "3",
		"olaitan_sensor_posture_cache_miss_total":   "5",
		"olaitan_sensor_posture_cache_bypass_total": "7",
		"olaitan_sensor_posture_api_errors_total":   "11",
		"olaitan_sensor_posture_orphan_pods_total":  "13",
		"olaitan_sensor_posture_unavailable_total":  "17",
	}
	for name, value := range want {
		needle := name + " " + value
		if !strings.Contains(body, needle) {
			t.Errorf("missing %q in body:\n%s", needle, body)
		}
	}
}

func TestRegisterPostureCounters_MissingGetterRejected(t *testing.T) {
	t.Parallel()
	r := metrics.NewRegistry()
	// Drop cache_bypass to assert the atomic precondition check fires
	// before any metric is registered.
	getters := metrics.PostureGetters{
		"cache_hit":   func() int64 { return 0 },
		"cache_miss":  func() int64 { return 0 },
		"api_errors":  func() int64 { return 0 },
		"orphan_pods": func() int64 { return 0 },
		"unavailable": func() int64 { return 0 },
	}
	if err := r.RegisterPostureCounters(getters); err == nil {
		t.Error("missing getter: got nil error, want rejection")
	}
	// And the registry should NOT have partially registered metrics.
	body := scrape(t, r)
	if strings.Contains(body, "olaitan_sensor_posture_") {
		t.Errorf("partial registration leaked: body has posture metrics\n%s", body)
	}
}

func TestRegisterPostureDisabled(t *testing.T) {
	t.Parallel()
	r := metrics.NewRegistry()
	if err := r.RegisterPostureDisabled(); err != nil {
		t.Fatalf("RegisterPostureDisabled: %v", err)
	}
	body := scrape(t, r)
	if !strings.Contains(body, "olaitan_sensor_posture_disabled 1") {
		t.Errorf("expected posture_disabled gauge=1, body:\n%s", body)
	}
	// The six posture_*_total counters must NOT appear in disabled mode.
	if strings.Contains(body, "olaitan_sensor_posture_cache_hit_total") {
		t.Errorf("posture_cache_hit_total leaked into disabled mode")
	}
}

func TestRegisterCounter_LabelMerge(t *testing.T) {
	t.Parallel()
	r := metrics.NewRegistry()
	var n atomic.Int64
	n.Store(99)
	err := r.RegisterCounter(
		"olaitan_sensor_audit_rejected_total",
		"audit",
		"Audit-webhook rejected events bucketed by reason.",
		prometheus.Labels{"reason": "malformed"},
		n.Load,
	)
	if err != nil {
		t.Fatalf("RegisterCounter: %v", err)
	}
	body := scrape(t, r)
	if !strings.Contains(body, `olaitan_sensor_audit_rejected_total{reason="malformed",source="audit"} 99`) {
		t.Errorf("expected merged labels, body:\n%s", body)
	}
}

func TestRegisterCounter_NilGetterRejected(t *testing.T) {
	t.Parallel()
	r := metrics.NewRegistry()
	if err := r.RegisterCounter("x", "", "h", nil, nil); err == nil {
		t.Error("nil getter: got nil error, want rejection")
	}
	if err := r.RegisterCounter("", "", "h", nil, func() int64 { return 0 }); err == nil {
		t.Error("empty name: got nil error, want rejection")
	}
}

// TestRegisterGauge_RendersAsGauge locks in the CR2 (Copilot review on
// PR #21) contract: gauges have `# TYPE ... gauge`, no _total suffix,
// and reflect the current getter value rather than monotonic history.
// The CNI consecutive_eofs metric is the canonical use case (resets
// to 0 on Recv success).
func TestRegisterGauge_RendersAsGauge(t *testing.T) {
	t.Parallel()
	r := metrics.NewRegistry()
	var n atomic.Int64
	n.Store(3)
	err := r.RegisterGauge(
		"olaitan_sensor_cni_consecutive_eofs",
		"network",
		"EOFs since last successful Recv (resets on success).",
		nil,
		n.Load,
	)
	if err != nil {
		t.Fatalf("RegisterGauge: %v", err)
	}
	body := scrape(t, r)
	if !strings.Contains(body, "# TYPE olaitan_sensor_cni_consecutive_eofs gauge") {
		t.Errorf("expected TYPE line declaring gauge, body:\n%s", body)
	}
	if !strings.Contains(body, `olaitan_sensor_cni_consecutive_eofs{source="network"} 3`) {
		t.Errorf("expected initial gauge value 3, body:\n%s", body)
	}

	// Gauge decreases to 0 on the next read (mimicking ConsecutiveEOFs
	// reset on a successful Recv). A counter could not represent this
	// transition without violating Prometheus monotonicity.
	n.Store(0)
	body = scrape(t, r)
	if !strings.Contains(body, `olaitan_sensor_cni_consecutive_eofs{source="network"} 0`) {
		t.Errorf("expected gauge value 0 after reset, body:\n%s", body)
	}
}

func TestRegisterGauge_NilGetterRejected(t *testing.T) {
	t.Parallel()
	r := metrics.NewRegistry()
	if err := r.RegisterGauge("x", "", "h", nil, nil); err == nil {
		t.Error("nil getter: got nil error, want rejection")
	}
	if err := r.RegisterGauge("", "", "h", nil, func() int64 { return 0 }); err == nil {
		t.Error("empty name: got nil error, want rejection")
	}
}

// scrape renders the metrics surface to text/plain via the same
// HandlerFor path Server uses. Tests fail fast on body-read or
// non-empty error.
func scrape(t *testing.T, r *metrics.Registry) string {
	t.Helper()
	srv := httptest.NewServer(r.Handler())
	t.Cleanup(srv.Close)
	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatalf("scrape GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("scrape body: %v", err)
	}
	return string(body)
}

// TestRegister_GatherCount sanity-checks that the prometheus.testutil
// helper CollectAndCount agrees with the rendered HTTP surface: useful
// for asserting metric counts when label values are dynamic.
func TestRegister_GatherCount(t *testing.T) {
	t.Parallel()
	r := metrics.NewRegistry()
	a := &fakeAdapter{}
	if err := r.RegisterAdapter("falco", a.Health(), a.EventsTotal); err != nil {
		t.Fatalf("RegisterAdapter: %v", err)
	}
	// Each RegisterAdapter contributes two metrics: source_healthy and
	// sensor_events_total. testutil.CollectAndCount returns the
	// per-sample count; one sample for the gauge, one for the counter.
	if n, err := gatherCount(r); err != nil {
		t.Fatalf("gatherCount: %v", err)
	} else if n != 2 {
		t.Errorf("expected 2 samples, got %d", n)
	}
}

// gatherCount counts the number of samples exposed by the registry.
// Uses the underlying gatherer rather than the HTTP surface so the
// test does not depend on the text-format encoder for cardinality.
func gatherCount(r *metrics.Registry) (int, error) {
	mfs, err := r.Gatherer().Gather()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, mf := range mfs {
		n += len(mf.Metric)
	}
	return n, nil
}

// _ pins the testutil import so renaming the field above does not
// silently drop the test dependency.
var _ = testutil.CollectAndCount

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestMain(m *testing.M) {
	// Hush the package logger across all package tests, including the
	// server tests in server_test.go.
	slog.SetDefault(quietLogger())
	os.Exit(m.Run())
}
