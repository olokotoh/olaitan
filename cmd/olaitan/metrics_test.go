package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	natsjs "github.com/nats-io/nats.go/jetstream"
	"golang.org/x/sync/errgroup"
	kubefake "k8s.io/client-go/kubernetes/fake"

	"github.com/olokotoh/olaitan/internal/collector/applog"
	"github.com/olokotoh/olaitan/internal/collector/falco"
	"github.com/olokotoh/olaitan/internal/collector/podidentity"
	"github.com/olokotoh/olaitan/internal/config"
	"github.com/olokotoh/olaitan/internal/metrics"
	responseaudit "github.com/olokotoh/olaitan/internal/response/audit"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/sourcehealth"
)

// fakeAdapter satisfies the adapterMetrics structural-typed contract
// without dragging in a real adapter and its NATS / gRPC dependencies.
type fakeAdapter struct {
	tracker sourcehealth.Tracker
	events  atomic.Int64
	engaged atomic.Int64
}

func (f *fakeAdapter) Health() sourcehealth.Reader { return &f.tracker }
func (f *fakeAdapter) EventsTotal() int64          { return f.events.Load() }
func (f *fakeAdapter) EngagedTotal() int64         { return f.engaged.Load() }

func quietTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestStartMetricsServer_NilConfigRejected(t *testing.T) {
	t.Parallel()
	g, _ := errgroup.WithContext(context.Background())
	if _, err := startMetricsServer(context.Background(), g, quietTestLogger(), nil, "node", nil, nil); err == nil {
		t.Error("nil config: got nil error, want rejection")
	}
}

func TestStartMetricsServer_EmptyAddressRejected(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{Metrics: config.MetricsConfig{Address: ""}}
	g, _ := errgroup.WithContext(context.Background())
	if _, err := startMetricsServer(context.Background(), g, quietTestLogger(), cfg, "node", nil, nil); err == nil {
		t.Error("empty address: got nil error, want rejection")
	}
}

func TestStartMetricsServer_RegistersStreamingAdapters(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g, gctx := errgroup.WithContext(ctx)
	cfg := &config.Config{
		Metrics: config.MetricsConfig{Address: "127.0.0.1:0"},
	}
	a1, a2 := &fakeAdapter{}, &fakeAdapter{}
	a1.tracker.MarkHealthy()
	a1.events.Store(10)
	a2.events.Store(20)
	sources := map[string]adapterMetrics{
		"falco": a1,
		"audit": a2,
	}

	reg, err := startMetricsServer(gctx, g, quietTestLogger(), cfg, "node-a", sources, nil)
	if err != nil {
		t.Fatalf("startMetricsServer: %v", err)
	}
	if reg == nil {
		t.Fatal("startMetricsServer returned nil registry")
	}

	// Gather metric families through the gatherer (no HTTP round-trip
	// needed). Verify both adapters' gauges and counters are present.
	mfs, err := reg.Gatherer().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	names := map[string]bool{}
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	wantNames := []string{
		"olaitan_source_healthy",
		"olaitan_sensor_events_total",
		"olaitan_sensor_circuit_breaker_engaged_total",
		"olaitan_sensor_posture_disabled", // posture disabled by default in cfg
	}
	for _, n := range wantNames {
		if !names[n] {
			t.Errorf("missing metric family %q in %v", n, names)
		}
	}

	cancel()
	_ = g.Wait() // metrics server exits cleanly on ctx cancel
}

func TestStartMetricsServer_PostureDisabledGaugeRegistered(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g, gctx := errgroup.WithContext(ctx)
	cfg := &config.Config{Metrics: config.MetricsConfig{Address: "127.0.0.1:0"}}
	// Posture disabled (default), so posture_disabled gauge appears
	// rather than the six counters.
	reg, err := startMetricsServer(gctx, g, quietTestLogger(), cfg, "", nil, nil)
	if err != nil {
		t.Fatalf("startMetricsServer: %v", err)
	}

	mfs, _ := reg.Gatherer().Gather()
	found := false
	for _, mf := range mfs {
		if strings.Contains(mf.GetName(), "posture_disabled") {
			found = true
		}
		if strings.Contains(mf.GetName(), "posture_cache_hit_total") {
			t.Errorf("posture_cache_hit_total should not be registered when disabled, got %s", mf.GetName())
		}
	}
	if !found {
		t.Errorf("posture_disabled gauge not registered when posture is disabled")
	}

	cancel()
	_ = g.Wait()
}

func TestStartMetricsServer_DuplicateAdapterRegistrationSurfaces(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g, gctx := errgroup.WithContext(ctx)
	cfg := &config.Config{Metrics: config.MetricsConfig{Address: "127.0.0.1:0"}}
	// Two adapters registered under the same source label simulates a
	// wiring bug; the helper should surface it rather than the
	// metrics server crashing at scrape time.
	a := &fakeAdapter{}
	// Single map can't hold a duplicate key, so we exercise the
	// duplicate path via two sequential calls in the same way the
	// production wiring would (e.g. a future Story 1.14 retry-wires
	// the collector against an already-registered Registry).
	reg, err := startMetricsServer(gctx, g, quietTestLogger(), cfg, "node-a",
		map[string]adapterMetrics{"falco": a}, nil)
	if err != nil {
		t.Fatalf("startMetricsServer: %v", err)
	}
	if err := reg.RegisterAdapter("falco", a.Health(), a.EventsTotal); err == nil {
		t.Error("duplicate RegisterAdapter: got nil error, want rejection")
	}

	cancel()
	_ = g.Wait()
}

func TestRegisterAdapterCounters_FalcoBindsCircuitBreaker(t *testing.T) {
	t.Parallel()
	// Falco's switch case has no per-adapter detail counters beyond the
	// circuit-breaker counter Story 1.13 added before the switch. This
	// test asserts the switch path does not panic on the pseudo-default
	// fall-through and that calling registerAdapterCounters directly on
	// a pre-built registry surfaces the duplicate-registration error.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g, gctx := errgroup.WithContext(ctx)
	cfg := &config.Config{Metrics: config.MetricsConfig{Address: "127.0.0.1:0"}}
	a := &fakeAdapter{}
	reg, err := startMetricsServer(gctx, g, quietTestLogger(), cfg, "node-a",
		map[string]adapterMetrics{"falco": a}, nil)
	if err != nil {
		t.Fatalf("startMetricsServer: %v", err)
	}
	// Calling registerAdapterCounters a second time on the same registry
	// must surface the duplicate-counter error rather than silently
	// double-registering: defensive lock-in against a future refactor
	// that re-enters the helper on retry.
	if err := registerAdapterCounters(reg, "falco", "node-a", a); err == nil {
		t.Errorf("registerAdapterCounters(falco) returned nil on a re-registration; want duplicate-counter rejection")
	}
	cancel()
	_ = g.Wait()
}

func TestStartMetricsServer_PropagatesRegistrationError(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g, gctx := errgroup.WithContext(ctx)
	cfg := &config.Config{Metrics: config.MetricsConfig{Address: "127.0.0.1:0"}}

	// Bare empty-source-label key triggers the RegisterAdapter "empty
	// source" rejection. The helper must surface this rather than
	// proceeding to bind a server on a half-registered registry.
	a := &fakeAdapter{}
	_, err := startMetricsServer(gctx, g, quietTestLogger(), cfg, "node-a",
		map[string]adapterMetrics{"": a}, nil)
	if err == nil {
		t.Errorf("startMetricsServer with empty source: got nil error, want propagation of RegisterAdapter rejection")
	}
	// Defensive: ensure the surface error chain contains the helper
	// boundary prefix.
	if err != nil && !strings.Contains(err.Error(), "register adapter") {
		t.Errorf("error does not wrap RegisterAdapter boundary: %v", err)
	}

	// Sanity: errgroup did not start a server on the empty-config
	// path (no goroutines to wait on).
	cancel()
	_ = g.Wait()
}

// TestAuditDroppedCounterSurfacesSinkDrops pins Story 2.9 BI-5: the pull-based
// audit drop counters wired in startAggregatorRing surface the buffered sinks'
// Dropped() count. It exercises the exact RegisterCounter+getter pattern used
// in main.go against a real TransitionAuditSink driven into overflow.
func TestAuditDroppedCounterSurfacesSinkDrops(t *testing.T) {
	sink, err := responseaudit.NewTransitionAuditSink(
		&nopTransitionPublisher{}, slog.New(slog.NewTextHandler(io.Discard, nil)),
		responseaudit.TransitionAuditSinkConfig{BufferCap: 1},
	)
	if err != nil {
		t.Fatalf("NewTransitionAuditSink: %v", err)
	}
	// Overflow the cap-1 buffer to force drops.
	for i := 0; i < 4; i++ {
		sink.Publish(schema.StateTransition{FromState: schema.StateClean, ToState: schema.StateRestricted, WorkloadID: "w"})
	}
	if sink.Dropped() == 0 {
		t.Fatal("expected the sink to have dropped events")
	}

	reg := metrics.NewRegistry()
	if err := reg.RegisterCounter(
		"olaitan_response_audit_transitions_dropped_total", "", "test",
		nil, func() int64 { return sink.Dropped() },
	); err != nil {
		t.Fatalf("RegisterCounter: %v", err)
	}
	// The registered pull-counter must reflect the sink's drop count on scrape.
	mfs, err := reg.Gatherer().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	var got float64 = -1
	for _, mf := range mfs {
		if mf.GetName() == "olaitan_response_audit_transitions_dropped_total" {
			got = mf.GetMetric()[0].GetCounter().GetValue()
		}
	}
	if int64(got) != sink.Dropped() {
		t.Errorf("scraped dropped counter = %v, want %d (the sink's Dropped())", got, sink.Dropped())
	}
}

type nopTransitionPublisher struct{}

func (nopTransitionPublisher) PublishAuditTransition(context.Context, responseaudit.AuditTransition) error {
	return nil
}

// TestRegisterAdapterCounters_FalcoHTTPReceiver is Story 10.2's metrics AC:
// the http_output receiver exports its request outcomes per status code,
// the alerts it received (published or not) and the heartbeats that prove
// Falco is alive. Every code series exists before its first request.
func TestRegisterAdapterCounters_FalcoHTTPReceiver(t *testing.T) {
	t.Parallel()
	a, err := falco.New(falco.Config{
		ListenAddr: "127.0.0.1:0",
		Token:      "0123456789abcdef0123456789abcdef",
		Hostname:   "node-a",
	}, nopPublisher{}, quietTestLogger())
	if err != nil {
		t.Fatalf("falco.New: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/falco/wrong-token", strings.NewReader("{}"))
	a.Handler().ServeHTTP(httptest.NewRecorder(), req)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g, gctx := errgroup.WithContext(ctx)
	cfg := &config.Config{Metrics: config.MetricsConfig{Address: "127.0.0.1:0"}}
	reg, err := startMetricsServer(gctx, g, quietTestLogger(), cfg, "node-a",
		map[string]adapterMetrics{"falco": a}, nil)
	if err != nil {
		t.Fatalf("startMetricsServer: %v", err)
	}
	mfs, err := reg.Gatherer().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	codes := map[string]float64{}
	seen := map[string]bool{}
	for _, mf := range mfs {
		seen[mf.GetName()] = true
		if mf.GetName() != "olaitan_sensor_falco_http_requests_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "code" {
					codes[lp.GetValue()] = m.GetCounter().GetValue()
				}
			}
		}
	}
	for _, n := range []string{
		"olaitan_sensor_falco_http_requests_total",
		"olaitan_sensor_falco_alerts_received_total",
		"olaitan_sensor_falco_heartbeats_total",
		"olaitan_sensor_falco_publish_drops_total",
		"olaitan_sensor_falco_buffer_dropped_total",
		"olaitan_sensor_falco_buffer_depth",
		"olaitan_sensor_falco_buffer_bytes",
	} {
		if !seen[n] {
			t.Errorf("metric family %s not registered", n)
		}
	}
	for _, c := range falco.ResponseCodes {
		if _, ok := codes[c]; !ok {
			t.Errorf("no series for code=%s before its first request", c)
		}
	}
	if codes["401"] != 1 {
		t.Errorf("requests{code=401} = %v, want 1", codes["401"])
	}
	cancel()
	_ = g.Wait()
}

// Story 10.10: the collector's applog sidecar tracker surfaces as the
// applog source (source_healthy, sensor_events_total) plus a per-state
// sidecar gauge, so an operator can see sidecars that went silent.
func TestRegisterAdapterCounters_ApplogSidecarTracker(t *testing.T) {
	t.Parallel()
	tr := applog.NewSidecarTracker("node-a", time.Minute)
	tr.Observe([]byte(`{"namespace":"shop","pod":"api-1","node":"node-a","healthy":true,"events":7}`))
	tr.Observe([]byte(`{"namespace":"shop","pod":"api-2","node":"node-a","healthy":false,"events":2}`))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g, gctx := errgroup.WithContext(ctx)
	cfg := &config.Config{Metrics: config.MetricsConfig{Address: "127.0.0.1:0"}}
	reg, err := startMetricsServer(gctx, g, quietTestLogger(), cfg, "node-a",
		map[string]adapterMetrics{"applog": tr}, nil)
	if err != nil {
		t.Fatalf("startMetricsServer: %v", err)
	}
	mfs, err := reg.Gatherer().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	states := map[string]float64{}
	var healthy, events float64 = -1, -1
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, lp := range m.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			if labels["source"] != "applog" {
				continue
			}
			switch mf.GetName() {
			case "olaitan_sensor_applog_sidecars":
				states[labels["state"]] = m.GetGauge().GetValue()
			case "olaitan_source_healthy":
				healthy = m.GetGauge().GetValue()
			case "olaitan_sensor_events_total":
				events = m.GetCounter().GetValue()
			}
		}
	}
	if states["live"] != 2 || states["stale"] != 0 || states["unhealthy"] != 1 {
		t.Errorf("olaitan_sensor_applog_sidecars = %v, want live=2 stale=0 unhealthy=1", states)
	}
	if healthy != 0 {
		t.Errorf("source_healthy{source=applog} = %v, want 0 while a sidecar reports unhealthy", healthy)
	}
	if events != 9 {
		t.Errorf("sensor_events_total{source=applog} = %v, want 9", events)
	}
	cancel()
	_ = g.Wait()
}

type nopPublisher struct{}

func (nopPublisher) PublishJS(context.Context, string, any, ...natsjs.PublishOpt) (*natsjs.PubAck, error) {
	return &natsjs.PubAck{}, nil
}

// Story 11.2d (#195): with pod identity enrichment on, the Falco adapter's
// metrics include the cache size, hits, misses, wait-recovered hits and cap
// rejections. With it off, none of them is registered.
func TestRegisterAdapterCounters_FalcoPodIdentity(t *testing.T) {
	t.Parallel()
	names := []string{
		"olaitan_sensor_falco_pod_identity_cache_entries",
		"olaitan_sensor_falco_pod_identity_enriched_total",
		"olaitan_sensor_falco_pod_identity_misses_total",
		"olaitan_sensor_falco_pod_identity_wait_recovered_total",
		"olaitan_sensor_falco_pod_identity_cap_rejected_total",
	}
	gather := func(t *testing.T, pi falco.PodIdentityResolver) map[string]bool {
		t.Helper()
		a, err := falco.New(falco.Config{
			ListenAddr:  "127.0.0.1:0",
			Token:       "0123456789abcdef0123456789abcdef",
			Hostname:    "node-a",
			PodIdentity: pi,
		}, nopPublisher{}, quietTestLogger())
		if err != nil {
			t.Fatalf("falco.New: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		g, gctx := errgroup.WithContext(ctx)
		cfg := &config.Config{Metrics: config.MetricsConfig{Address: "127.0.0.1:0"}}
		reg, err := startMetricsServer(gctx, g, quietTestLogger(), cfg, "node-a",
			map[string]adapterMetrics{"falco": a}, nil)
		if err != nil {
			t.Fatalf("startMetricsServer: %v", err)
		}
		mfs, err := reg.Gatherer().Gather()
		if err != nil {
			t.Fatalf("gather: %v", err)
		}
		seen := map[string]bool{}
		for _, mf := range mfs {
			seen[mf.GetName()] = true
		}
		cancel()
		_ = g.Wait()
		return seen
	}

	c, err := podidentity.New(kubefake.NewClientset(), podidentity.Config{NodeName: "node-a"}, quietTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	on := gather(t, falcoPodIdentity{c})
	for _, n := range names {
		if !on[n] {
			t.Errorf("metric family %s not registered with enrichment on", n)
		}
	}
	off := gather(t, nil)
	for _, n := range names {
		if off[n] {
			t.Errorf("metric family %s registered with enrichment off", n)
		}
	}
}
