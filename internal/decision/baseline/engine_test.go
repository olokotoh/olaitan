package baseline

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"

	"github.com/olokotoh/olaitan/internal/correlator/trigger"
	"github.com/olokotoh/olaitan/internal/metrics"
	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/schema"
)

type stubEmitter struct {
	calls atomic.Int64
	last  atomic.Value // schema.BaselineDeviation
}

func (s *stubEmitter) FireBaselineDeviation(_ context.Context, _ string, dev schema.BaselineDeviation) (*schema.EvidencePackage, error) {
	s.calls.Add(1)
	s.last.Store(dev)
	return nil, nil
}

func testEngine(t *testing.T) *Engine {
	t.Helper()
	e := &Engine{
		log:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		metricList:      MetricNames(),
		deviationsTotal: map[string]*atomic.Int64{},
	}
	for _, n := range e.metricList {
		var c atomic.Int64
		e.deviationsTotal[n] = &c
	}
	sigma := DefaultSigmaMultiplier
	e.sigmaMul.Store(&sigma)
	return e
}

func TestNew_RejectsNilNATS(t *testing.T) {
	_, err := New(Config{NATS: nil, Store: &Store{}, Warmup: &Warmup{}, Emitter: &stubEmitter{}})
	if err == nil {
		t.Errorf("New(nil NATS) should error")
	}
}

func TestNew_RejectsNilStore(t *testing.T) {
	_, err := New(Config{NATS: &natsclient.Client{}, Store: nil, Warmup: &Warmup{}, Emitter: &stubEmitter{}})
	if err == nil {
		t.Errorf("New(nil Store) should error")
	}
}

func TestNew_RejectsNilWarmup(t *testing.T) {
	_, err := New(Config{NATS: &natsclient.Client{}, Store: &Store{}, Warmup: nil, Emitter: &stubEmitter{}})
	if err == nil {
		t.Errorf("New(nil Warmup) should error")
	}
}

func TestNew_RejectsNilEmitter(t *testing.T) {
	_, err := New(Config{NATS: &natsclient.Client{}, Store: &Store{}, Warmup: &Warmup{}, Emitter: nil})
	if err == nil {
		t.Errorf("New(nil Emitter) should error")
	}
}

func TestNew_HappyPath_RegistersAllMetrics(t *testing.T) {
	reg := metrics.NewRegistry()
	e, err := New(Config{
		NATS:    &natsclient.Client{},
		Store:   &Store{},
		Warmup:  &Warmup{},
		Emitter: &stubEmitter{},
		Metrics: reg,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if e == nil {
		t.Fatalf("Engine: nil")
	}
	mfs, err := reg.Gatherer().Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	want := map[string]bool{
		"olaitan_decision_baseline_evaluations_total":  false,
		"olaitan_decision_baseline_deviations_total":   false,
		"olaitan_decision_baseline_skipped_self_total": false,
		"olaitan_decision_baseline_warmup_active":      false,
		"olaitan_decision_baseline_evaluation_seconds": false,
	}
	for _, mf := range mfs {
		if _, ok := want[mf.GetName()]; ok {
			want[mf.GetName()] = true
		}
	}
	for n, present := range want {
		if !present {
			t.Errorf("metric %q not registered", n)
		}
	}
}

func TestEngine_HistogramBucketsMatchNFR3(t *testing.T) {
	want := []float64{0.001, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250}
	if len(histogramBuckets) != len(want) {
		t.Fatalf("histogramBuckets len=%d want %d", len(histogramBuckets), len(want))
	}
	for i, b := range want {
		if histogramBuckets[i] != b {
			t.Errorf("histogramBuckets[%d] = %v, want %v", i, histogramBuckets[i], b)
		}
	}
}

func TestApplyReEntrancyGuard_SkipsBaselineDeviationPackages(t *testing.T) {
	e := testEngine(t)
	pkg := &schema.EvidencePackage{Trigger: schema.EvidenceTrigger{Type: trigger.TypeBaselineDeviation}}
	if !e.applyReEntrancyGuard(pkg) {
		t.Errorf("expected guard to fire on baseline_deviation trigger")
	}
	if e.skippedSelf.Load() != 1 {
		t.Errorf("skippedSelf = %d, want 1", e.skippedSelf.Load())
	}
}

func TestApplyReEntrancyGuard_AllowsMultiSignalPackages(t *testing.T) {
	e := testEngine(t)
	pkg := &schema.EvidencePackage{Trigger: schema.EvidenceTrigger{Type: trigger.TypeMultiSignal}}
	if e.applyReEntrancyGuard(pkg) {
		t.Errorf("guard should NOT fire on multi_signal trigger")
	}
	if e.skippedSelf.Load() != 0 {
		t.Errorf("skippedSelf = %d, want 0", e.skippedSelf.Load())
	}
}

func TestResolveWorkloadKey_PrefersWorkloadIdentity(t *testing.T) {
	pkg := &schema.EvidencePackage{
		WorkloadIdentity: schema.WorkloadIdentity{
			Namespace: "tenant-acme",
			OwnerKind: "Deployment",
			OwnerName: "web",
		},
	}
	ns, pod := resolveWorkloadKey(pkg)
	if ns != "tenant-acme" || pod != "Deployment-web" {
		t.Errorf("got (%q,%q) want (tenant-acme, Deployment-web)", ns, pod)
	}
}

func TestResolveWorkloadKey_OrphanFallback(t *testing.T) {
	pkg := &schema.EvidencePackage{
		WorkloadIdentity: schema.WorkloadIdentity{Namespace: "default", PodName: "orphan-pod"},
	}
	ns, pod := resolveWorkloadKey(pkg)
	if ns != "default" || pod != "orphan-pod" {
		t.Errorf("got (%q,%q) want (default, orphan-pod)", ns, pod)
	}
}

func TestResolveWorkloadKey_PodRefFallback(t *testing.T) {
	pkg := &schema.EvidencePackage{
		Events: []schema.Event{{Pod: schema.PodRef{Namespace: "ns", Name: "pod-0"}}},
	}
	ns, pod := resolveWorkloadKey(pkg)
	if ns != "ns" || pod != "pod-0" {
		t.Errorf("got (%q,%q) want (ns, pod-0)", ns, pod)
	}
}

func TestResolveWorkloadKey_UnresolvableReturnsEmpty(t *testing.T) {
	pkg := &schema.EvidencePackage{}
	ns, pod := resolveWorkloadKey(pkg)
	if ns != "" || pod != "" {
		t.Errorf("got (%q,%q) want empty", ns, pod)
	}
}

func TestDetectRestart_TaggedLifecycleTriggers(t *testing.T) {
	e := testEngine(t)
	pkg := &schema.EvidencePackage{
		Events: []schema.Event{
			{Category: schema.CategoryLifecycle, Tags: []string{"attempt:1"}},
		},
	}
	if !e.detectRestart(pkg) {
		t.Errorf("expected restart detection on attempt:1 tag")
	}
}

func TestDetectRestart_AttemptZeroDoesNotTrigger(t *testing.T) {
	e := testEngine(t)
	pkg := &schema.EvidencePackage{
		Events: []schema.Event{
			{Category: schema.CategoryLifecycle, Tags: []string{"attempt:0"}},
		},
	}
	if e.detectRestart(pkg) {
		t.Errorf("attempt:0 should NOT trigger restart detection")
	}
}

func TestEngine_SetSigmaMultiplier(t *testing.T) {
	e := testEngine(t)
	if e.SigmaMultiplier() != DefaultSigmaMultiplier {
		t.Errorf("default sigma=%v want %v", e.SigmaMultiplier(), DefaultSigmaMultiplier)
	}
	e.SetSigmaMultiplier(2.5)
	if e.SigmaMultiplier() != 2.5 {
		t.Errorf("after Set: sigma=%v want 2.5", e.SigmaMultiplier())
	}
	e.SetSigmaMultiplier(-1)
	if e.SigmaMultiplier() != 2.5 {
		t.Errorf("negative Set should be ignored; sigma=%v want 2.5", e.SigmaMultiplier())
	}
}
