package baseline

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/olokotoh/olaitan/internal/keys"
	"github.com/olokotoh/olaitan/internal/metrics"
	redisclient "github.com/olokotoh/olaitan/internal/redis"
	"github.com/olokotoh/olaitan/internal/schema"
)

// newRealStoreAndWarmup constructs a Store + Warmup backed by an
// in-process miniredis instance.
func newRealStoreAndWarmup(t *testing.T) (*Store, *Warmup) {
	t.Helper()
	_, store, warmup := newMiniredisStore(t)
	return store, warmup
}

func newMiniredisStore(t *testing.T) (*miniredis.Miniredis, *Store, *Warmup) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	store, warmup := storeOn(t, mr)
	return mr, store, warmup
}

func storeOn(t *testing.T, mr *miniredis.Miniredis) (*Store, *Warmup) {
	t.Helper()
	cfg := redisclient.DefaultConfig()
	cfg.Addr = mr.Addr()
	rc, err := redisclient.NewClient(cfg)
	if err != nil {
		t.Fatalf("redis client: %v", err)
	}
	t.Cleanup(func() { _ = rc.Close(context.Background()) })
	store, err := NewStore(rc)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	warmup, err := NewWarmup(store, WarmupConfig{Duration: DefaultWarmupDuration})
	if err != nil {
		t.Fatalf("NewWarmup: %v", err)
	}
	return store, warmup
}

type recEmitter struct {
	mu   sync.Mutex
	devs []schema.BaselineDeviation
	ids  []string
}

func (r *recEmitter) FireBaselineDeviation(_ context.Context, workloadID string, _ schema.WorkloadIdentity, dev schema.BaselineDeviation) (*schema.EvidencePackage, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.devs = append(r.devs, dev)
	r.ids = append(r.ids, workloadID)
	return nil, nil
}

func (r *recEmitter) all() []schema.BaselineDeviation {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]schema.BaselineDeviation(nil), r.devs...)
}

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// harness drives an Engine on a virtual clock with real event shapes.
type harness struct {
	t      *testing.T
	mr     *miniredis.Miniredis
	store  *Store
	warmup *Warmup
	e      *Engine
	emit   *recEmitter
	fx     realFixtures
	t0     time.Time
	clock  time.Time
	seq    int
}

var steadyIdentity = schema.WorkloadIdentity{Namespace: "olt-baseline", OwnerKind: "Deployment", OwnerName: "steady"}

const steadyWorkloadID = "olt-baseline/Deployment/steady"

func newHarness(t *testing.T, warm time.Duration) *harness {
	t.Helper()
	mr, store, warmup := newMiniredisStore(t)
	h := &harness{t: t, mr: mr, store: store, warmup: warmup, emit: &recEmitter{}, fx: loadReal(t)}
	// A minute boundary, so offsets read as "minute N".
	h.t0 = time.Date(2026, 10, 19, 20, 51, 0, 0, time.UTC)
	h.clock = h.t0
	warmup.SetConfig(WarmupConfig{Duration: warm})
	warmup.SetNow(func() time.Time { return h.clock })
	h.e = h.newEngine(store, warmup, metrics.NewRegistry())
	return h
}

func (h *harness) newEngine(store *Store, warmup *Warmup, reg *metrics.Registry) *Engine {
	h.t.Helper()
	e, err := New(Config{Store: store, Warmup: warmup, Emitter: h.emit, Metrics: reg, Log: discardLog(), OwnNamespaces: []string{"default"}})
	if err != nil {
		h.t.Fatalf("New: %v", err)
	}
	e.now = func() time.Time { return h.clock }
	return e
}

func (h *harness) at(d time.Duration) time.Time { return h.t0.Add(d) }

func (h *harness) ingest(ev schema.Event, at time.Time) {
	h.clock = at
	h.seq++
	ev.ID = fmt.Sprintf("%s-%d", ev.ID, h.seq)
	ev.Timestamp = at
	h.e.Ingest(context.Background(), Observation{WorkloadID: steadyWorkloadID, Identity: steadyIdentity, Event: ev}, at)
}

func (h *harness) tick(at time.Time) {
	h.clock = at
	h.e.Tick(context.Background(), at)
}

// tickThrough ticks every 5 s (the production cadence) up to end.
func (h *harness) tickThrough(from, end time.Time) {
	for t := from; !t.After(end); t = t.Add(tickInterval) {
		h.tick(t)
	}
}

// workloadGET is a real audit event (the 2026-10-19 shape) re-attributed
// to the steady workload's own ServiceAccount: what its wget against its
// own pod produces.
func (h *harness) workloadGET() schema.Event {
	return withRaw(h.t, h.fx.AuditOperatorExec, func(r map[string]any) {
		r["user"] = map[string]any{"username": "system:serviceaccount:olt-baseline:steady"}
		r["verb"] = "get"
		if ref, ok := r["objectRef"].(map[string]any); ok {
			delete(ref, "subresource")
		}
	})
}

func (h *harness) falcoExec(path string) schema.Event {
	return withRaw(h.t, h.fx.FalcoK8sAPIWget, func(r map[string]any) { r["process.exe"] = path })
}

// steadyCycles replays the live workload: every 180 s it does n GETs on
// its own pod (n from the real cycle log), its wget trips Falco's
// "Contact K8S API Server", and the aggregator's own identity lookup lands
// on the pod (excluded). The n sequence is part3-steady-cycles of the
// 2026-10-19 run without the cycle-12 burst.
var liveCycleGets = []int{2, 3, 3, 1, 1, 2, 3, 2, 2, 1, 3, 2, 2, 1, 1, 3, 2}

func (h *harness) steadyCycles(from time.Duration, cycles int, extra func(at time.Time)) time.Time {
	var last time.Time
	for c := 0; c < cycles; c++ {
		start := h.at(from + time.Duration(c)*180*time.Second + 18*time.Second)
		n := liveCycleGets[c%len(liveCycleGets)]
		for i := 0; i < n; i++ {
			h.ingest(h.workloadGET(), start.Add(time.Duration(i)*200*time.Millisecond))
		}
		h.ingest(h.falcoExec("/bin/wget"), start.Add(time.Second))
		h.ingest(h.fx.AuditOlaitanSelfLookup, start.Add(2*time.Second))
		if extra != nil {
			extra(start)
		}
		h.tickThrough(start.Add(5*time.Second), start.Add(180*time.Second-time.Second))
		last = start
	}
	return last
}

func (h *harness) welford(metric string) *Welford {
	h.t.Helper()
	st, err := h.store.LoadState(context.Background(), "olt-baseline", "Deployment-steady", MetricNames())
	if err != nil {
		h.t.Fatalf("LoadState: %v", err)
	}
	return st.Welfords[metric]
}

// AC1 + AC5: the benign steady workload from the live run, replayed for
// 75 minutes, produces no deviation; warm-up started on its first sample.
func TestBenignSteadyWorkloadProducesNoDeviation(t *testing.T) {
	h := newHarness(t, DefaultWarmupDuration)
	h.ingest(h.workloadGET(), h.at(0))
	if active, _ := h.warmup.IsActive(context.Background(), "olt-baseline", "Deployment-steady"); active {
		t.Fatal("warm-up active before the first sample closed")
	}
	h.tick(h.at(BucketWidth + time.Second))
	if active, _ := h.warmup.IsActive(context.Background(), "olt-baseline", "Deployment-steady"); !active {
		t.Fatal("a new workload is not in warm-up after its first sample (Story 10.12 B1)")
	}
	h.steadyCycles(2*time.Minute, 25, nil) // 75 minutes
	if devs := h.emit.all(); len(devs) != 0 {
		t.Fatalf("benign steady workload produced %d deviation(s): %+v", len(devs), devs)
	}
	w := h.welford(MetricAuditEventsPerMin)
	if w.Count < 70 {
		t.Fatalf("audit_events_per_min has %d samples over 77 minutes, want one per minute including idle zeros", w.Count)
	}
	if w.Mean > 1 {
		t.Fatalf("audit_events_per_min mean = %v, want under 1/min (1-3 GETs per 3 minutes; the aggregator's own lookups excluded)", w.Mean)
	}
	if h.welford(MetricOutboundBytes).Count != 0 {
		t.Fatal("outbound_bytes was sampled although no flow source was ever seen")
	}
}

// AC2: the real 80-GET burst the live run missed is flagged.
func TestAPIBurstIsFlagged(t *testing.T) {
	h := newHarness(t, DefaultWarmupDuration)
	last := h.steadyCycles(0, 14, nil) // 42 minutes
	burst := last.Add(180 * time.Second)
	for i := 0; i < 80; i++ {
		h.ingest(h.workloadGET(), burst.Add(time.Duration(i)*100*time.Millisecond))
	}
	h.tickThrough(burst.Add(10*time.Second), burst.Add(2*time.Minute))
	dev := requireDeviation(t, h.emit.all(), MetricAuditEventsPerMin)
	if dev.Value != 80 || dev.Sigma < 3 {
		t.Fatalf("API burst deviation = %+v, want value 80 and sigma >= 3", dev)
	}
	if h.emit.ids[0] != steadyWorkloadID {
		t.Fatalf("deviation fired for %q, want %q", h.emit.ids[0], steadyWorkloadID)
	}
}

// AC2: an exec burst (six distinct binaries in a minute) is flagged.
func TestExecBurstIsFlagged(t *testing.T) {
	h := newHarness(t, DefaultWarmupDuration)
	last := h.steadyCycles(0, 14, nil)
	burst := last.Add(180 * time.Second)
	for i, p := range []string{"/bin/sh", "/usr/bin/id", "/bin/cat", "/tmp/x", "/bin/ls", "/usr/bin/nc"} {
		h.ingest(h.falcoExec(p), burst.Add(time.Duration(i)*time.Second))
	}
	h.tickThrough(burst.Add(10*time.Second), burst.Add(2*time.Minute))
	dev := requireDeviation(t, h.emit.all(), MetricDistinctExecPaths)
	if dev.Value != 6 {
		t.Fatalf("exec burst deviation = %+v, want value 6", dev)
	}
}

// AC2: new egress destinations are flagged, on the real flow shape.
func TestNewEgressDestinationsAreFlagged(t *testing.T) {
	h := newHarness(t, DefaultWarmupDuration)
	src := h.fx.CNIFlowsS4[1] // a Src report
	dst := h.fx.CNIFlowsS4[0] // its Dst twin
	steadyFlow := func(at time.Time) {
		h.ingest(src, at)
		h.ingest(dst, at)
	}
	// One flow to the same peer every minute (the live peer client).
	var last time.Time
	for m := 0; m < 45; m++ {
		at := h.at(time.Duration(m)*time.Minute + 30*time.Second)
		steadyFlow(at)
		h.tickThrough(at.Add(5*time.Second), at.Add(30*time.Second))
		last = at
	}
	burst := last.Add(time.Minute)
	for i := 0; i < 6; i++ {
		ev := withRaw(t, src, func(r map[string]any) {
			r["network.dest_name"] = fmt.Sprintf("new-dest-%d-*", i)
		})
		h.ingest(ev, burst.Add(time.Duration(i)*time.Second))
	}
	h.tickThrough(burst.Add(10*time.Second), burst.Add(2*time.Minute))
	dev := requireDeviation(t, h.emit.all(), MetricOutboundUniqueDst)
	if dev.Value != 6 {
		t.Fatalf("egress deviation = %+v, want 6 destinations", dev)
	}
	for _, d := range h.emit.all() {
		if d.Metric == MetricOutboundBytes {
			t.Fatalf("Dst twins must not double the steady byte rate into a false bytes deviation: %+v", d)
		}
	}
}

func requireDeviation(t *testing.T, devs []schema.BaselineDeviation, metric string) schema.BaselineDeviation {
	t.Helper()
	for _, d := range devs {
		if d.Metric == metric {
			if d.StdDev <= 0 || d.Sigma != (d.Value-d.Mean)/d.StdDev {
				t.Fatalf("deviation %+v: sigma is not (value-mean)/std_dev", d)
			}
			return d
		}
	}
	t.Fatalf("no %s deviation; got %+v", metric, devs)
	return schema.BaselineDeviation{}
}

// AC5: a new workload cannot deviate during warm-up.
func TestNewWorkloadCannotDeviateDuringWarmup(t *testing.T) {
	h := newHarness(t, DefaultWarmupDuration)
	h.steadyCycles(0, 3, nil)
	burst := h.at(10 * time.Minute)
	for i := 0; i < 80; i++ {
		h.ingest(h.workloadGET(), burst)
	}
	h.tickThrough(burst.Add(time.Second), burst.Add(3*time.Minute))
	if devs := h.emit.all(); len(devs) != 0 {
		t.Fatalf("new workload deviated during warm-up: %+v", devs)
	}
}

// AC7 / D4: MinSamples holds even when warm-up is configured very short
// (the e2e overlays use 5 s).
func TestNoDeviationBeforeMinSamples(t *testing.T) {
	h := newHarness(t, 5*time.Second)
	h.ingest(h.workloadGET(), h.at(0))
	h.tickThrough(h.at(time.Second), h.at(5*time.Minute))
	burst := h.at(5*time.Minute + 10*time.Second)
	for i := 0; i < 80; i++ {
		h.ingest(h.workloadGET(), burst)
	}
	h.tickThrough(burst.Add(time.Second), burst.Add(2*time.Minute))
	if devs := h.emit.all(); len(devs) != 0 {
		t.Fatalf("deviated on fewer than %d samples: %+v", MinSamples, devs)
	}
}

// AC7: a perfectly steady workload (exactly 5 calls a minute) does not
// fire on +1 or +2, and does fire on a real jump.
func TestPerfectlySteadyWorkloadIgnoresSmallChanges(t *testing.T) {
	h := newHarness(t, 30*time.Minute)
	minute := func(m, n int) {
		at := h.at(time.Duration(m)*time.Minute + 10*time.Second)
		for i := 0; i < n; i++ {
			h.ingest(h.workloadGET(), at)
		}
		h.tickThrough(at.Add(5*time.Second), at.Add(49*time.Second))
	}
	m := 0
	for ; m < 40; m++ {
		minute(m, 5)
	}
	minute(m, 6)
	minute(m+1, 7)
	minute(m+2, 5)
	h.tick(h.at(time.Duration(m+4) * time.Minute))
	if devs := h.emit.all(); len(devs) != 0 {
		t.Fatalf("steady workload fired on a +1/+2 change: %+v", devs)
	}
	// The audit floor is 2 (Story 10.12 review): +7 on a mean of 5 is
	// sigma 3.5.
	minute(m+4, 12)
	h.tick(h.at(time.Duration(m+6) * time.Minute))
	requireDeviation(t, h.emit.all(), MetricAuditEventsPerMin)
}

// AC6: a restart keeps the restart-aware behaviour (baselines zeroed,
// warm-up, no deviation during it) except restarts/hour, which keeps its
// history; an in-place container restart (container_attempt) is detected.
func TestRestartZeroesBaselinesAndWarmsUp(t *testing.T) {
	h := newHarness(t, DefaultWarmupDuration)
	restartAt := h.steadyCycles(0, 14, func(at time.Time) {
		h.ingest(h.fx.CRIContainerCreated, at.Add(3*time.Second)) // runtime source live, attempt 0
	}).Add(180 * time.Second)
	before := h.welford(MetricRestartsPerHour).Count
	if before < 40 || h.welford(MetricAuditEventsPerMin).Count < 40 {
		t.Fatalf("not enough history before the restart: restarts=%d", before)
	}
	restarted := h.fx.CRIContainerCreated
	restarted.Tags = append(append([]string(nil), restarted.Tags...), "container_attempt:1")
	h.ingest(restarted, restartAt)
	for i := 0; i < 80; i++ {
		h.ingest(h.workloadGET(), restartAt.Add(time.Second))
	}
	h.tickThrough(restartAt.Add(5*time.Second), restartAt.Add(2*time.Minute))
	if active, _ := h.warmup.IsActive(context.Background(), "olt-baseline", "Deployment-steady"); !active {
		t.Fatal("restart did not engage warm-up")
	}
	if devs := h.emit.all(); len(devs) != 0 {
		t.Fatalf("deviation during post-restart warm-up: %+v", devs)
	}
	if c := h.welford(MetricAuditEventsPerMin).Count; c > 3 {
		t.Fatalf("audit_events_per_min count = %d after restart, want reset", c)
	}
	if c := h.welford(MetricRestartsPerHour).Count; c <= before {
		t.Fatalf("restarts/hour history was zeroed by the restart (count %d, before %d)", c, before)
	}
}

// AC6: Welford and warm-up state survive an aggregator restart, and a
// workload with history is not put back into warm-up.
func TestStateSurvivesAggregatorRestart(t *testing.T) {
	h := newHarness(t, DefaultWarmupDuration)
	last := h.steadyCycles(0, 14, nil)
	// A new aggregator process: fresh engine, fresh Warmup cache, same Redis.
	store2, warm2 := storeOn(t, h.mr)
	warm2.SetConfig(WarmupConfig{Duration: DefaultWarmupDuration})
	warm2.SetNow(func() time.Time { return h.clock })
	h.store, h.warmup = store2, warm2
	h.e = h.newEngine(store2, warm2, metrics.NewRegistry())
	resume := last.Add(180 * time.Second)
	h.ingest(h.workloadGET(), resume)
	h.tickThrough(resume.Add(time.Second), resume.Add(2*time.Minute))
	if active, _ := warm2.IsActive(context.Background(), "olt-baseline", "Deployment-steady"); active {
		t.Fatal("a known workload was put back into warm-up by an aggregator restart")
	}
	burst := resume.Add(3 * time.Minute)
	for i := 0; i < 80; i++ {
		h.ingest(h.workloadGET(), burst)
	}
	h.tickThrough(burst.Add(time.Second), burst.Add(2*time.Minute))
	requireDeviation(t, h.emit.all(), MetricAuditEventsPerMin)
}

// D5: a hash learnt under the pre-10.12 package-window semantics is not
// compared against: it is discarded and the workload warms up.
func TestLegacyBaselineIsDiscarded(t *testing.T) {
	h := newHarness(t, DefaultWarmupDuration)
	key, err := keys.BaselineMetrics("olt-baseline", "Deployment-steady")
	if err != nil {
		t.Fatal(err)
	}
	// The live run's poisoned audit baseline: mean about 70, std about 11.
	h.mr.HSet(key, "audit_events_per_min.count", "40", "audit_events_per_min.mean", "68.88", "audit_events_per_min.m2", "5106")
	h.ingest(h.workloadGET(), h.at(0))
	h.tick(h.at(BucketWidth + time.Second))
	if active, _ := h.warmup.IsActive(context.Background(), "olt-baseline", "Deployment-steady"); !active {
		t.Fatal("legacy baseline did not trigger warm-up")
	}
	if w := h.welford(MetricAuditEventsPerMin); w.Count != 1 || w.Mean != 1 {
		t.Fatalf("legacy Welford kept: %+v", w)
	}
}

func TestZeroFillAndIdleEviction(t *testing.T) {
	h := newHarness(t, DefaultWarmupDuration)
	h.ingest(h.workloadGET(), h.at(10*time.Second))
	h.tick(h.at(4*time.Minute + time.Second))
	if c := h.welford(MetricAuditEventsPerMin).Count; c != 4 {
		t.Fatalf("after 4 minutes: %d samples, want 4 (one real minute plus three idle zeros)", c)
	}
	if got := h.e.trackedWorkloads.Load(); got != 1 {
		t.Fatalf("tracked = %d, want 1", got)
	}
	h.tick(h.at(idleEvictAfter + time.Minute))
	if got := h.e.trackedWorkloads.Load(); got != 0 {
		t.Fatalf("tracked = %d after an idle hour, want 0", got)
	}
	// 4 samples, then the minutes up to the eviction tick: minute 4 to
	// minute 60 is 57 more zero samples.
	if c := h.welford(MetricAuditEventsPerMin).Count; c != 61 {
		t.Fatalf("after eviction: %d samples, want 61", c)
	}
}

// A pause longer than maxGapFill back-fills exactly maxGapFill zero
// minutes plus the closed minute, in one batch.
func TestGapFillIsCapped(t *testing.T) {
	h := newHarness(t, DefaultWarmupDuration)
	h.ingest(h.workloadGET(), h.at(10*time.Second))
	// Keep the tracker alive across the pause with an event 90 minutes
	// later (no tick in between).
	h.ingest(h.workloadGET(), h.at(90*time.Minute+10*time.Second))
	if c := h.welford(MetricAuditEventsPerMin).Count; c != int64(maxGapFill)+1 {
		t.Fatalf("samples after a 90-minute pause = %d, want %d (closed minute plus %d zero minutes)", c, maxGapFill+1, maxGapFill)
	}
}

func TestObserveEventNeverBlocks(t *testing.T) {
	store, warmup := newRealStoreAndWarmup(t)
	e, err := New(Config{Store: store, Warmup: warmup, Emitter: &recEmitter{}, Log: discardLog()})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		for i := 0; i < observationQueueSize+5; i++ {
			e.ObserveEvent("w", steadyIdentity, schema.Event{ID: "x"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ObserveEvent blocked on a full queue")
	}
	if got := e.observationsDropped.Load(); got != 5 {
		t.Fatalf("dropped = %d, want 5", got)
	}
}

func TestDeviationsVecLabelledBySigmaBucket(t *testing.T) {
	h := newHarness(t, DefaultWarmupDuration)
	reg := metrics.NewRegistry()
	h.e = h.newEngine(h.store, h.warmup, reg)
	ctx := context.Background()
	// Three workloads with thirty minutes of history alternating 15 and
	// 25 calls a minute (mean 20, std about 5.08) and an expired warm-up.
	for i, n := range []int{37, 50, 80} {
		name := fmt.Sprintf("w%d", i)
		wf := &Welford{}
		for m := 0; m < 30; m++ {
			v := 15.0
			if m%2 == 0 {
				v = 25.0
			}
			wf.Update(v)
		}
		pre := map[string]*Welford{}
		for _, mn := range MetricNames() {
			pre[mn] = &Welford{}
		}
		pre[MetricAuditEventsPerMin] = wf
		if err := h.store.Save(ctx, "olt-baseline", "Deployment-"+name, pre); err != nil {
			t.Fatal(err)
		}
		if err := h.store.SaveWarmup(ctx, "olt-baseline", "Deployment-"+name, h.t0.Add(-2*time.Hour), DefaultWarmupDuration); err != nil {
			t.Fatal(err)
		}
		id := schema.WorkloadIdentity{Namespace: "olt-baseline", OwnerKind: "Deployment", OwnerName: name}
		at := h.at(10 * time.Second)
		h.clock = at
		for j := 0; j < n; j++ {
			ev := h.workloadGET()
			ev.ID = fmt.Sprintf("%s-%d", name, j)
			h.e.Ingest(ctx, Observation{WorkloadID: "olt-baseline/Deployment/" + name, Identity: id, Event: ev}, at)
		}
	}
	h.tick(h.at(time.Minute + time.Second))
	for _, b := range []string{"3-5", "5-10", "10+"} {
		if got := testutil.ToFloat64(h.e.deviationsVec.WithLabelValues(MetricAuditEventsPerMin, b)); got != 1 {
			t.Errorf("sigma bucket %s = %v, want 1", b, got)
		}
	}
}

func TestNew_Validation(t *testing.T) {
	store, warmup := newRealStoreAndWarmup(t)
	for name, cfg := range map[string]Config{
		"nil store":   {Warmup: warmup, Emitter: &recEmitter{}},
		"zero store":  {Store: &Store{}, Warmup: warmup, Emitter: &recEmitter{}},
		"nil warmup":  {Store: store, Emitter: &recEmitter{}},
		"zero warmup": {Store: store, Warmup: &Warmup{}, Emitter: &recEmitter{}},
		"nil emitter": {Store: store, Warmup: warmup},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: New accepted an invalid config", name)
		}
	}
	// NATS is optional since Story 10.12 (only used to delete the legacy
	// EVIDENCE consumer).
	if _, err := New(Config{Store: store, Warmup: warmup, Emitter: &recEmitter{}}); err != nil {
		t.Fatalf("New without NATS: %v", err)
	}
}

func TestNew_RegistersMetrics(t *testing.T) {
	store, warmup := newRealStoreAndWarmup(t)
	reg := metrics.NewRegistry()
	e, err := New(Config{Store: store, Warmup: warmup, Emitter: &recEmitter{}, Metrics: reg, Log: discardLog()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e.deviationsVec.WithLabelValues(MetricAuditEventsPerMin, "3-5").Add(0)
	mfs, err := reg.Gatherer().Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	want := map[string]bool{
		"olaitan_decision_baseline_evaluations_total":          false,
		"olaitan_decision_baseline_deviations_total":           false,
		"olaitan_decision_baseline_observations_dropped_total": false,
		"olaitan_decision_baseline_tracked_workloads":          false,
		"olaitan_decision_baseline_warmup_active":              false,
		"olaitan_decision_baseline_evaluation_seconds":         false,
	}
	for _, mf := range mfs {
		if _, ok := want[mf.GetName()]; ok {
			want[mf.GetName()] = true
		}
		if mf.GetName() == "olaitan_decision_baseline_skipped_self_total" {
			t.Error("retired metric skipped_self_total still registered (the engine no longer reads packages)")
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

func TestWorkloadKey(t *testing.T) {
	cases := []struct {
		id       schema.WorkloadIdentity
		ref      schema.PodRef
		ns, want string
	}{
		{steadyIdentity, schema.PodRef{}, "olt-baseline", "Deployment-steady"},
		{schema.WorkloadIdentity{Namespace: "default", OwnerKind: "Pod", OwnerName: "web-0", PodName: "web-0"}, schema.PodRef{}, "default", "web-0"},
		{schema.WorkloadIdentity{}, schema.PodRef{Namespace: "default", Name: "pod-1"}, "default", "pod-1"},
		{schema.WorkloadIdentity{}, schema.PodRef{}, "", ""},
	}
	for _, c := range cases {
		ns, k := workloadKey(c.id, c.ref)
		if ns != c.ns || k != c.want {
			t.Errorf("workloadKey(%+v, %+v) = (%q, %q), want (%q, %q)", c.id, c.ref, ns, k, c.ns, c.want)
		}
	}
}

func TestEngine_SetSigmaMultiplier(t *testing.T) {
	store, warmup := newRealStoreAndWarmup(t)
	e, err := New(Config{Store: store, Warmup: warmup, Emitter: &recEmitter{}})
	if err != nil {
		t.Fatal(err)
	}
	if e.SigmaMultiplier() != DefaultSigmaMultiplier {
		t.Errorf("default sigma=%v want %v", e.SigmaMultiplier(), DefaultSigmaMultiplier)
	}
	e.SetSigmaMultiplier(2.5)
	e.SetSigmaMultiplier(-1)
	if e.SigmaMultiplier() != 2.5 {
		t.Errorf("sigma=%v want 2.5 (negative ignored)", e.SigmaMultiplier())
	}
}

// Story 10.12 review: a replayed backlog (correlator or aggregator
// restart) arrives all at once; folding it into the current minute fired a
// false deviation (sigma 6.9 in the Edge Case Hunter's scratch test).
// Events older than maxLateness are not folded in, and counted.
func TestReplayedBacklogIsNotABurst(t *testing.T) {
	h := newHarness(t, DefaultWarmupDuration)
	last := h.steadyCycles(0, 14, nil)
	replayAt := last.Add(180 * time.Second)
	h.clock = replayAt
	for i := 0; i < 80; i++ {
		ev := h.workloadGET()
		ev.ID = fmt.Sprintf("backlog-%d", i)
		ev.Timestamp = replayAt.Add(-time.Duration(10+i) * time.Minute)
		h.e.Ingest(context.Background(), Observation{WorkloadID: steadyWorkloadID, Identity: steadyIdentity, Event: ev}, replayAt)
	}
	h.tickThrough(replayAt.Add(time.Second), replayAt.Add(2*time.Minute))
	if devs := h.emit.all(); len(devs) != 0 {
		t.Fatalf("replayed backlog fired %d deviation(s): %+v", len(devs), devs)
	}
	if got := h.e.observationsLate.Load(); got != 80 {
		t.Fatalf("late observations = %d, want 80", got)
	}
}

// The live gate's workload: a 60 s cycle (so some minutes hold two
// cycles and some none, as the cycle drifts against the minute) with all
// three sources: 1-3 GETs on its own pod, Falco's wget alert, and a
// Goldmane flow to its peer reported by both ends. Ninety minutes, no
// deviation.
func TestLiveGateCycleShapeStaysQuiet(t *testing.T) {
	h := newHarness(t, DefaultWarmupDuration)
	src, dst := h.fx.CNIFlowsS4[1], h.fx.CNIFlowsS4[0]
	at := h.at(5 * time.Second)
	for c := 0; at.Before(h.at(90 * time.Minute)); c++ {
		n := liveCycleGets[c%len(liveCycleGets)]
		for i := 0; i < n; i++ {
			h.ingest(h.workloadGET(), at.Add(time.Duration(i)*300*time.Millisecond))
		}
		h.ingest(h.falcoExec("/bin/wget"), at.Add(time.Second))
		h.ingest(h.fx.AuditOlaitanSelfLookup, at.Add(time.Second))
		h.ingest(src, at.Add(2*time.Second))
		h.ingest(dst, at.Add(2*time.Second))
		next := at.Add(61500 * time.Millisecond)
		h.tickThrough(at.Add(3*time.Second), next.Add(-time.Second))
		at = next
	}
	if devs := h.emit.all(); len(devs) != 0 {
		t.Fatalf("live-gate workload shape produced deviation(s): %+v", devs)
	}
	for _, m := range []string{MetricAuditEventsPerMin, MetricDistinctExecPaths, MetricOutboundUniqueDst, MetricOutboundBytes} {
		if c := h.welford(m).Count; c < 85 {
			t.Errorf("%s has %d samples over 90 minutes", m, c)
		}
	}
}

// Exact own identities are excluded wherever Olaitan is installed, and a
// non-own ServiceAccount in a shared namespace is still counted.
func TestOwnActorIsExact(t *testing.T) {
	store, warmup := newRealStoreAndWarmup(t)
	e, err := New(Config{Store: store, Warmup: warmup, Emitter: &recEmitter{}, OwnActors: []string{"system:serviceaccount:default:olaitan-aggregator"}})
	if err != nil {
		t.Fatal(err)
	}
	if !e.isOwnActor("system:serviceaccount:default:olaitan-aggregator") {
		t.Fatal("own ServiceAccount not recognised")
	}
	if e.isOwnActor("system:serviceaccount:default:someone-else") || e.isOwnActor("kubernetes-admin") {
		t.Fatal("a non-Olaitan actor in the release namespace was excluded")
	}
}
