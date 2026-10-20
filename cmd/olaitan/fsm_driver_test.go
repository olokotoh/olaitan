package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/olokotoh/olaitan/internal/agent/provider"
	"github.com/olokotoh/olaitan/internal/decision/analyst"
	"github.com/olokotoh/olaitan/internal/decision/score"
	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/response/fsm"
	"github.com/olokotoh/olaitan/internal/response/risk"
	"github.com/olokotoh/olaitan/internal/schema"
)

// Story 7.4 (issue #186): the analyst chain runs OFF the FSM path. These tests
// drive the per-package and per-result handlers the consumer loop calls, with
// a real fsm.Machine, score.Calculator and risk.Window, so the ordering
// guarantees are pinned without a live JetStream consumer (the embedded-NATS
// proof of the wired loop is fsm_consumer_integration_test.go).

// syncBuffer is a goroutine-safe log sink (workers log too).
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// recordingSink records every published transition (the AUDIT.transitions
// stand-in).
type recordingSink struct {
	mu  sync.Mutex
	got []schema.StateTransition
}

func (r *recordingSink) Publish(st schema.StateTransition) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, st)
}

func (r *recordingSink) all() []schema.StateTransition {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]schema.StateTransition(nil), r.got...)
}

// blockingRunner is a chain run func that blocks until released (or ctx is
// cancelled) and then returns a fixed capped confidence.
type blockingRunner struct {
	release chan struct{}
	capped  int
	started chan string
	calls   atomic.Int64
}

func newBlockingRunner(capped int) *blockingRunner {
	return &blockingRunner{release: make(chan struct{}), capped: capped, started: make(chan string, 16)}
}

func (b *blockingRunner) run(ctx context.Context, pkg schema.EvidencePackage) (int, bool) {
	b.calls.Add(1)
	b.started <- pkg.WorkloadID
	select {
	case <-b.release:
		return b.capped, true
	case <-ctx.Done():
		return 0, false // cut short: not a verdict
	}
}

type driverFixture struct {
	t     *testing.T
	d     *fsmDriver
	sink  *recordingSink
	logs  *syncBuffer
	disp  *chainDispatcher
	cnt   *prometheus.CounterVec
	stop  context.CancelFunc
	acked *ackLog
}

// ackLog records which package ids were acked.
type ackLog struct {
	mu  sync.Mutex
	ids []string
}

func (a *ackLog) ackFor(id string) func() {
	return func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		a.ids = append(a.ids, id)
	}
}

func (a *ackLog) has(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, x := range a.ids {
		if x == id {
			return true
		}
	}
	return false
}

func newDriverFixture(t *testing.T, run chainRunFunc, window *risk.Window, workers, queue int) *driverFixture {
	t.Helper()
	sink := &recordingSink{}
	m, err := fsm.New(nil, nil, sink, nil) // defaults: bands 20/40/70, SUSPICIOUS dwell 0
	if err != nil {
		t.Fatalf("fsm.New: %v", err)
	}
	calc, err := score.New(nil, metrics.NewRegistry()) // 0.4/0.3/0.3, llm_cap 35
	if err != nil {
		t.Fatalf("score.New: %v", err)
	}
	logs := &syncBuffer{}
	log := slog.New(slog.NewJSONHandler(logs, nil))
	f := &driverFixture{t: t, sink: sink, logs: logs, acked: &ackLog{}}
	f.d = &fsmDriver{log: log, scoreCalc: calc, machine: m, window: window, chainMode: analyst.ChainModeFull, now: time.Now}
	if run != nil {
		reg := metrics.NewRegistry()
		cnt, cerr := analyst.RegisterChainDispatchMetric(reg)
		if cerr != nil {
			t.Fatalf("dispatch metric: %v", cerr)
		}
		f.cnt = cnt
		f.disp = newChainDispatcher(workers, queue, run, cnt, log)
		f.disp.heartbeat = 5 * time.Millisecond
		ctx, cancel := context.WithCancel(context.Background())
		f.stop = cancel
		f.disp.start(ctx)
		f.d.dispatcher = f.disp
		t.Cleanup(func() {
			cancel()
			f.disp.shutdown(2 * time.Second)
		})
	}
	return f
}

// handle runs the per-package handler under a deadline, so a regression
// that blocks the consumer on the chain FAILS the test instead of hanging it.
func (f *driverFixture) handle(pkg schema.EvidencePackage) {
	f.handleWith(pkg, func() {})
}

func (f *driverFixture) handleWith(pkg schema.EvidencePackage, inProgress func()) {
	f.t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.d.handlePackage(pkg, f.acked.ackFor(pkg.PackageID), inProgress)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		f.t.Fatalf("handlePackage(%s) blocked: the consumer must never wait on the chain", pkg.PackageID)
	}
}

// awaitResult blocks until one chain result is available and applies it on
// the calling goroutine, exactly as the consumer loop does.
func (f *driverFixture) awaitResult(t *testing.T) {
	t.Helper()
	select {
	case r := <-f.disp.results():
		f.d.applyResult(r)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a chain result")
	}
}

func awaitStarted(t *testing.T, b *blockingRunner) string {
	t.Helper()
	select {
	case wl := <-b.started:
		return wl
	case <-time.After(5 * time.Second):
		t.Fatal("chain never started")
		return ""
	}
}

func pkgFor(wl, id, severity string) schema.EvidencePackage {
	return schema.EvidencePackage{
		PackageID:   id,
		WorkloadID:  wl,
		RuleMatches: []schema.RuleMatch{{RuleID: "OLT-CRED-001", Severity: severity, EventID: "evt-" + id}},
		Events:      []schema.Event{{ID: "evt-" + id}},
	}
}

// (a) A package whose rules cross SUSPICIOUS transitions IMMEDIATELY even
// though the chain it triggered is blocked indefinitely.
func TestFSMDriver_DeterministicTransitionDoesNotWaitForChain(t *testing.T) {
	br := newBlockingRunner(35)
	f := newDriverFixture(t, br.run, risk.New(0), 2, 4)

	done := make(chan struct{})
	go func() {
		f.handle(pkgFor("ns/Deployment/a", "p-a1", "80")) // 0.4*80 = 32: SUSPICIOUS
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handlePackage blocked on the analyst chain")
	}
	awaitStarted(t, br)

	got := f.sink.all()
	if len(got) != 1 || got[0].ToState != schema.StateSuspicious || got[0].PackageID != "p-a1" {
		t.Fatalf("want one immediate CLEAN->SUSPICIOUS for p-a1 while the chain is blocked, got %+v", got)
	}
	if f.acked.has("p-a1") {
		t.Fatal("a package with an in-flight chain must stay un-acked (Story 3.9 resume)")
	}
}

// (b) Releasing the chain re-scores the workload and the model verdict that
// moves the band is its OWN audited transition, keyed by the triggering
// package id.
func TestFSMDriver_ChainReturnReScoresAsSecondTransition(t *testing.T) {
	br := newBlockingRunner(35) // 0.3*35 = 10.5 -> 32 + 10.5 = 42.5: RESTRICTED
	f := newDriverFixture(t, br.run, risk.New(60*time.Second), 2, 4)

	f.handle(pkgFor("ns/Deployment/a", "p-a1", "80"))
	awaitStarted(t, br)
	close(br.release)
	f.awaitResult(t)

	got := f.sink.all()
	if len(got) != 2 {
		t.Fatalf("want two audited transitions (deterministic, then model), got %+v", got)
	}
	if got[0].ToState != schema.StateSuspicious || got[1].FromState != schema.StateSuspicious || got[1].ToState != schema.StateRestricted {
		t.Fatalf("want CLEAN->SUSPICIOUS then SUSPICIOUS->RESTRICTED, got %+v", got)
	}
	if got[1].PackageID != "p-a1" || got[1].WorkloadID != "ns/Deployment/a" {
		t.Fatalf("the re-score transition must carry the triggering package and workload, got %+v", got[1])
	}
	if got[1].Confidence <= got[0].Confidence {
		t.Fatalf("re-score %v must exceed the deterministic %v", got[1].Confidence, got[0].Confidence)
	}
	if !f.acked.has("p-a1") {
		t.Fatal("the triggering package must be acked once its chain result is applied")
	}
	if !strings.Contains(f.logs.String(), `"source":"analyst_chain"`) {
		t.Fatalf("the re-score transition log line must carry source=analyst_chain:\n%s", f.logs.String())
	}
	// The retained verdict keeps contributing to later packages (risk window).
	if len(f.disp.inflightIDs()) != 0 {
		t.Fatalf("in-flight set not cleared after apply: %v", f.disp.inflightIDs())
	}
}

// (c) While workload A's chain is blocked, workload B's package is evaluated.
func TestFSMDriver_OtherWorkloadEvaluatedWhileChainBlocked(t *testing.T) {
	br := newBlockingRunner(35)
	f := newDriverFixture(t, br.run, risk.New(0), 1, 4) // ONE worker, busy with A

	f.handle(pkgFor("ns/Deployment/a", "p-a1", "80"))
	awaitStarted(t, br)
	f.handle(pkgFor("ns/Deployment/b", "p-b1", "80"))

	var sawB bool
	for _, st := range f.sink.all() {
		if st.WorkloadID == "ns/Deployment/b" && st.ToState == schema.StateSuspicious {
			sawB = true
		}
	}
	if !sawB {
		t.Fatalf("workload B was not evaluated while A's chain was blocked: %+v", f.sink.all())
	}
}

// (d) At most one chain in flight per workload: a second triggering package
// for A is coalesced (no second run, acked at once, metric recorded); a
// different workload still dispatches.
func TestFSMDriver_CoalescesPerWorkload(t *testing.T) {
	br := newBlockingRunner(35)
	f := newDriverFixture(t, br.run, risk.New(0), 2, 4)

	f.handle(pkgFor("ns/Deployment/a", "p-a1", "80"))
	awaitStarted(t, br)
	f.handle(pkgFor("ns/Deployment/a", "p-a2", "90"))
	f.handle(pkgFor("ns/Deployment/b", "p-b1", "80"))
	awaitStarted(t, br)

	if n := br.calls.Load(); n != 2 {
		t.Fatalf("chain runs = %d, want 2 (A once, B once)", n)
	}
	if !f.acked.has("p-a2") {
		t.Fatal("a coalesced package must be acked at once")
	}
	if f.acked.has("p-a1") || f.acked.has("p-b1") {
		t.Fatal("dispatched packages must stay un-acked until their result is applied")
	}
	if v := testutil.ToFloat64(f.cnt.WithLabelValues(analyst.ChainDispatchCoalesced)); v != 1 {
		t.Fatalf("coalesced metric = %v, want 1", v)
	}
	if v := testutil.ToFloat64(f.cnt.WithLabelValues(analyst.ChainDispatchDispatched)); v != 2 {
		t.Fatalf("dispatched metric = %v, want 2", v)
	}
	// Once A's result is applied a new chain for A may start.
	close(br.release)
	f.awaitResult(t)
	f.awaitResult(t)
	f.handle(pkgFor("ns/Deployment/a", "p-a3", "90"))
	awaitStarted(t, br)
	if n := br.calls.Load(); n != 3 {
		t.Fatalf("chain runs after A completed = %d, want 3", n)
	}
}

// A saturated pool rejects (queue_full) without blocking and acks the
// package; the deterministic score already drove the FSM.
func TestFSMDriver_QueueFullRejectsWithoutBlocking(t *testing.T) {
	br := newBlockingRunner(35)
	f := newDriverFixture(t, br.run, risk.New(0), 1, 0) // capacity 1
	f.handle(pkgFor("ns/Deployment/a", "p-a1", "80"))
	awaitStarted(t, br)
	f.handle(pkgFor("ns/Deployment/b", "p-b1", "80"))
	if !f.acked.has("p-b1") {
		t.Fatal("a queue_full package must be acked")
	}
	if v := testutil.ToFloat64(f.cnt.WithLabelValues(analyst.ChainDispatchQueueFull)); v != 1 {
		t.Fatalf("queue_full metric = %v, want 1", v)
	}
	var sawB bool
	for _, st := range f.sink.all() {
		sawB = sawB || st.WorkloadID == "ns/Deployment/b"
	}
	if !sawB {
		t.Fatal("a queue_full package must still be evaluated deterministically")
	}
}

// A non-triggering package never reaches the dispatcher and is acked.
func TestFSMDriver_NonTriggeringPackageAckedNoDispatch(t *testing.T) {
	br := newBlockingRunner(35)
	f := newDriverFixture(t, br.run, risk.New(0), 2, 4)
	f.handle(pkgFor("ns/Deployment/a", "p-a1", "30")) // below the FR19 floor of 50
	if !f.acked.has("p-a1") {
		t.Fatal("non-triggering package must be acked at once")
	}
	if br.calls.Load() != 0 {
		t.Fatal("non-triggering package must not run the chain")
	}
}

// A zero verdict (degraded, error, no-citable) is not re-scored: no extra
// Evaluate, but the package is acked and the in-flight slot freed.
func TestFSMDriver_ZeroVerdictNotReScored(t *testing.T) {
	br := newBlockingRunner(0)
	f := newDriverFixture(t, br.run, risk.New(0), 2, 4)
	f.handle(pkgFor("ns/Deployment/a", "p-a1", "80"))
	awaitStarted(t, br)
	close(br.release)
	f.awaitResult(t)
	if n := len(f.sink.all()); n != 1 {
		t.Fatalf("transitions = %d, want only the deterministic one", n)
	}
	if !f.acked.has("p-a1") || len(f.disp.inflightIDs()) != 0 {
		t.Fatal("a zero verdict must still ack and free the in-flight slot")
	}
}

// AC4: the re-score keeps the live deterministic terms, so it is never below
// the deterministic aggregate at that instant (the model cannot lower a state
// below what the deterministic signal justified).
func TestFSMDriver_ReScoreNeverBelowDeterministic(t *testing.T) {
	for _, sev := range []string{"50", "60", "75", "100"} {
		br := newBlockingRunner(5)
		f := newDriverFixture(t, br.run, risk.New(60*time.Second), 2, 4)
		f.handle(pkgFor("ns/Deployment/a", "p-1", sev))
		awaitStarted(t, br)
		det := f.d.last.Total
		close(br.release)
		f.awaitResult(t)
		if f.d.last.Total < det {
			t.Fatalf("severity %s: re-score %v below deterministic %v", sev, f.d.last.Total, det)
		}
	}
}

// (e) A nil chain (RS mode / provider=none) is byte-identical to the
// pre-Story-7.4 path: the same transitions, and transition log lines with
// exactly the pre-existing key set (no source field).
func TestFSMDriver_NilChainIdenticalToDeterministicPath(t *testing.T) {
	seq := []schema.EvidencePackage{
		pkgFor("ns/Deployment/a", "p1", "80"),
		pkgFor("ns/Deployment/b", "p2", "30"),
		{PackageID: "p3", WorkloadID: "ns/Deployment/a", BaselineDeviations: []schema.BaselineDeviation{{Metric: "m", Sigma: 4}}},
		pkgFor("ns/Deployment/a", "p4", "100"),
	}
	for _, ttl := range []time.Duration{0, 60 * time.Second} {
		f := newDriverFixture(t, nil, risk.New(ttl), 0, 0)
		for _, p := range seq {
			f.handle(p)
			if !f.acked.has(p.PackageID) {
				t.Fatalf("ttl=%v: nil-chain package %s not acked", ttl, p.PackageID)
			}
		}

		// Reference: the pre-7.4 nil-chain composition, verbatim.
		refSink := &recordingSink{}
		m, _ := fsm.New(nil, nil, refSink, nil)
		calc, _ := score.New(nil, metrics.NewRegistry())
		w := risk.New(ttl)
		for _, p := range seq {
			rules, devs, llm := w.Observe(p.WorkloadID, p, 0, time.Now())
			agg := p
			agg.RuleMatches, agg.BaselineDeviations = rules, devs
			sc, _ := calc.Score(&agg, llm)
			m.Evaluate(p.WorkloadID, sc.Total, p.PackageID)
		}
		got, want := f.sink.all(), refSink.all()
		if len(got) != len(want) {
			t.Fatalf("ttl=%v: transitions %d, want %d", ttl, len(got), len(want))
		}
		for i := range got {
			g, w := got[i], want[i]
			g.Timestamp, w.Timestamp = time.Time{}, time.Time{}
			if !reflect.DeepEqual(g, w) {
				t.Fatalf("ttl=%v: transition %d = %+v, want %+v", ttl, i, g, w)
			}
		}
		wantKeys := "from_state,level,msg,package_id,reason,risk_window,score,score_baseline,score_llm,score_rules,time,to_state,workload_id"
		wantOrder := []string{"time", "level", "msg", "workload_id", "from_state", "to_state", "reason", "score", "score_rules", "score_baseline", "score_llm", "risk_window", "package_id"}
		for _, line := range strings.Split(strings.TrimSpace(f.logs.String()), "\n") {
			if !strings.Contains(line, "aggregator: fsm transition") {
				continue
			}
			var m map[string]any
			if err := json.Unmarshal([]byte(line), &m); err != nil {
				t.Fatalf("log line: %v", err)
			}
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			if strings.Join(keys, ",") != wantKeys {
				t.Fatalf("ttl=%v: transition log keys changed:\n got %s\nwant %s", ttl, strings.Join(keys, ","), wantKeys)
			}
			// Attribute ORDER is part of the byte-identical line too.
			if !ordered(line, wantOrder) {
				t.Fatalf("ttl=%v: transition log attribute order changed: %s", ttl, line)
			}
		}
	}
}

// (f) Shutdown with an in-flight chain that does not finish within the
// grace: it is cancelled, shutdown returns within the bound, and the package
// is NOT acked, so JetStream redelivers it and Story 3.9 checkpoints resume.
func TestChainDispatcher_ShutdownWithInFlightChain(t *testing.T) {
	br := newBlockingRunner(35)
	f := newDriverFixture(t, br.run, risk.New(0), 2, 4)
	f.handle(pkgFor("ns/Deployment/a", "p-a1", "80"))
	awaitStarted(t, br)

	start := time.Now()
	if f.disp.shutdown(100 * time.Millisecond) {
		t.Fatal("a chain still running at the grace must be reported unfinished")
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("shutdown took %v", el)
	}
	f.d.drainResults()
	if f.acked.has("p-a1") {
		t.Fatal("a chain cut short by shutdown must leave its package un-acked for redelivery")
	}
	if n := len(f.sink.all()); n != 1 {
		t.Fatalf("transitions = %d, want only the deterministic one", n)
	}
}

// Graceful shutdown lets a RUNNING chain finish within the grace, and the
// consumer then applies and acks its verdict (no duplicate assessment after
// redelivery); a QUEUED chain is not started and stays un-acked.
func TestChainDispatcher_ShutdownDrainsFinishedChains(t *testing.T) {
	br := newBlockingRunner(35)
	f := newDriverFixture(t, br.run, risk.New(0), 1, 4)
	f.handle(pkgFor("ns/Deployment/a", "p-a1", "80"))
	awaitStarted(t, br)
	f.handle(pkgFor("ns/Deployment/b", "p-b1", "80")) // queued behind A

	go func() {
		time.Sleep(50 * time.Millisecond)
		close(br.release) // A finishes inside the grace
	}()
	if !f.disp.shutdown(2 * time.Second) {
		t.Fatal("the running chain finished inside the grace")
	}
	f.d.drainResults()
	if !f.acked.has("p-a1") {
		t.Fatal("a chain that finished inside the grace must be applied and acked")
	}
	if f.acked.has("p-b1") || br.calls.Load() != 1 {
		t.Fatalf("a queued chain must not start during shutdown (runs=%d) and must stay un-acked", br.calls.Load())
	}
	got := f.sink.all()
	if got[len(got)-1].ToState != schema.StateRestricted || got[len(got)-1].PackageID != "p-a1" {
		t.Fatalf("the drained verdict must be applied as its own transition, got %+v", got)
	}
}

// The shutdown wait is BOUNDED even when a chain ignores cancellation.
func TestChainDispatcher_ShutdownWaitIsBounded(t *testing.T) {
	stuck := make(chan struct{})
	defer close(stuck)
	started := make(chan struct{}, 1)
	run := func(context.Context, schema.EvidencePackage) (int, bool) {
		started <- struct{}{}
		<-stuck // ignores ctx on purpose
		return 0, true
	}
	d := newChainDispatcher(1, 0, run, nil, chainTestLogger())
	d.start(context.Background())
	if got := d.dispatch(chainJob{pkg: pkgFor("w", "p", "80"), ack: func() {}, inProgress: func() {}}); got != analyst.ChainDispatchDispatched {
		t.Fatalf("dispatch = %q", got)
	}
	<-started
	start := time.Now()
	if d.shutdown(100 * time.Millisecond) {
		t.Fatal("shutdown must report false when a chain outlives the grace")
	}
	if el := time.Since(start); el > chainAbortGrace+time.Second {
		t.Fatalf("bounded shutdown took %v", el)
	}
}

// A queued job (worker busy) is heartbeated from DISPATCH, so it cannot
// outlive AckWait while it waits for a worker; the heartbeat stops once the
// verdict is applied.
func TestChainDispatcher_HeartbeatsQueuedJob(t *testing.T) {
	br := newBlockingRunner(35)
	f := newDriverFixture(t, br.run, risk.New(0), 1, 4)
	f.handle(pkgFor("ns/Deployment/a", "p-a1", "80"))
	awaitStarted(t, br)
	var beats atomic.Int64
	f.handleWith(pkgFor("ns/Deployment/b", "p-b1", "80"), func() { beats.Add(1) })
	deadline := time.Now().Add(2 * time.Second)
	for beats.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if beats.Load() < 2 {
		t.Fatalf("queued job heartbeats = %d, want >= 2 while it waits for a worker", beats.Load())
	}
	close(br.release)
	f.awaitResult(t)
	awaitStarted(t, br)
	f.awaitResult(t)
	n := beats.Load()
	time.Sleep(30 * time.Millisecond)
	if beats.Load() != n {
		t.Fatal("heartbeat must stop once the verdict is applied")
	}
}

// The heartbeat must stay well under the consumer's AckWait.
func TestChainHeartbeatWellUnderAckWait(t *testing.T) {
	if 3*chainHeartbeat > fsmConsumerAckWait {
		t.Fatalf("chainHeartbeat %v must be at most a third of fsmConsumerAckWait %v", chainHeartbeat, fsmConsumerAckWait)
	}
}

// A JetStream redelivery of the package whose chain is in flight is left to
// the in-flight job: not acked (that would settle the message and lose the
// Story 3.9 resume), not re-evaluated, not re-counted by the breaker.
func TestFSMDriver_RedeliveryOfInFlightPackageLeftAlone(t *testing.T) {
	br := newBlockingRunner(35)
	f := newDriverFixture(t, br.run, risk.New(0), 2, 4)
	f.d.breaker = analyst.NewCircuitBreaker(analyst.CircuitBreakerOptions{RatePerMin: 100, Cooling: time.Minute, Enabled: true})
	pkg := pkgFor("ns/Deployment/a", "p-a1", "80")
	f.handle(pkg)
	awaitStarted(t, br)
	before := len(f.sink.all())
	redelivered := &ackLog{}
	f.d.handlePackage(pkg, redelivered.ackFor("p-a1"), func() {})
	if redelivered.has("p-a1") {
		t.Fatal("the redelivered copy must not be acked while its chain is in flight")
	}
	if br.calls.Load() != 1 || len(f.sink.all()) != before {
		t.Fatal("a redelivery must not re-run the chain or re-evaluate")
	}
	if v := testutil.ToFloat64(f.cnt.WithLabelValues(analyst.ChainDispatchCoalesced)); v != 0 {
		t.Fatalf("a redelivery is not a coalesced package, got %v", v)
	}
	close(br.release)
	f.awaitResult(t)
	if !f.acked.has("p-a1") {
		t.Fatal("the in-flight job acks the message once the verdict is applied")
	}
}

// Escalate-only re-score: a verdict whose re-score does not point above the
// current state is folded into the window but NOT fed to Evaluate, so it can
// neither start de-escalation nor reset the kill-sustain anchor. Default
// (window disabled) mode, where the re-score is the triggering package's own
// signals: a later package already escalated the workload.
func TestFSMDriver_StaleVerdictDoesNotEvaluate(t *testing.T) {
	br := newBlockingRunner(35)
	f := newDriverFixture(t, br.run, risk.New(0), 2, 4)
	f.handle(pkgFor("ns/Deployment/a", "p-a1", "80")) // 32: SUSPICIOUS, chain dispatched
	awaitStarted(t, br)
	f.handle(pkgFor("ns/Deployment/a", "p-a2", "100")) // 40: RESTRICTED (coalesced)
	got := f.sink.all()
	if got[len(got)-1].ToState != schema.StateRestricted {
		t.Fatalf("setup: want RESTRICTED, got %+v", got)
	}
	n := len(got)
	close(br.release)
	f.awaitResult(t) // re-score 32 + 10.5 = 42.5: RESTRICTED band = current
	if len(f.sink.all()) != n {
		t.Fatalf("a non-escalating verdict must not transition: %+v", f.sink.all())
	}
	if strings.Contains(f.logs.String(), `"source":"analyst_chain"`) {
		t.Fatal("no analyst_chain transition expected")
	}
	if !f.acked.has("p-a1") {
		t.Fatal("the package is still acked")
	}
}

// While a chain runs, the dispatcher heartbeats the message (InProgress) so
// JetStream does not redeliver it during a slow model call.
func TestChainDispatcher_HeartbeatsInFlightMessage(t *testing.T) {
	br := newBlockingRunner(35)
	d := newChainDispatcher(1, 0, br.run, nil, chainTestLogger())
	d.heartbeat = 5 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); d.shutdown(time.Second) }()
	d.start(ctx)
	var beats atomic.Int64
	d.dispatch(chainJob{pkg: pkgFor("w", "p", "80"), ack: func() {}, inProgress: func() { beats.Add(1) }})
	awaitStarted(t, br)
	deadline := time.Now().Add(2 * time.Second)
	for beats.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if beats.Load() < 2 {
		t.Fatalf("heartbeats = %d, want >= 2 while the chain runs", beats.Load())
	}
	close(br.release)
}

// blockingProvider gates every Analyse on a channel, to run the REAL
// analyst.Chain through the production run func on a worker.
type blockingProvider struct {
	scriptedProvider
	gate chan struct{}
}

func (b *blockingProvider) Analyse(ctx context.Context, req provider.Request) (provider.Response, error) {
	select {
	case <-b.gate:
	case <-ctx.Done():
		return provider.Response{}, ctx.Err()
	}
	return b.scriptedProvider.Analyse(ctx, req)
}

// The production run func (newChainRunFunc) drives the real chain on a worker:
// the assessment is audited, the chain-runs metric records assessed, and the
// capped confidence reaches the FSM as a second transition.
func TestFSMDriver_RealChainOnWorker(t *testing.T) {
	bp := &blockingProvider{scriptedProvider: scriptedProvider{byRole: map[provider.Role]string{
		provider.RoleL1:     `{"hypothesis":"credential theft","cited_evidence":[{"event_id":"evt-p-a1"}],"confidence":70}`,
		provider.RoleL2:     `{"verdict":"confirmed","verified_evidence":[{"event_id":"evt-p-a1","finding":"confirmed"}],"confidence":66}`,
		provider.RoleSenior: `{"threat_type":"credential_access","reasoning":"shadow read confirmed","confidence":80}`,
	}}, gate: make(chan struct{})}
	reg := metrics.NewRegistry()
	l1, _ := analyst.NewL1(bp, analyst.PromptSpec{System: "s", Version: "v"}, reg, nil)
	l2, _ := analyst.NewL2(bp, analyst.PromptSpec{System: "s", Version: "v"}, reg, nil)
	sr, _ := analyst.NewSenior(bp, analyst.PromptSpec{System: "s", Version: "v"}, reg, nil)
	chain, err := analyst.NewChain(l1, l2, sr, reg, nil)
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	runs, _ := analyst.RegisterChainRunsMetric(reg)
	pub := &fakeAssessmentPub{}

	f := newDriverFixture(t, newChainRunFunc(chain, chain.Mode(), pub, runs, chainTestLogger()), risk.New(0), 2, 4)
	f.d.chainRuns = runs
	f.handle(pkgFor("ns/Deployment/a", "p-a1", "80"))
	if n := len(f.sink.all()); n != 1 {
		t.Fatalf("want the deterministic transition before the model answers, got %d", n)
	}
	close(bp.gate)
	f.awaitResult(t)
	got := f.sink.all()
	if len(got) != 2 || got[1].ToState != schema.StateRestricted {
		t.Fatalf("want the model verdict as a second transition to RESTRICTED, got %+v", got)
	}
	if n := len(pub.all()); n != 1 {
		t.Fatalf("assessment publishes = %d, want 1", n)
	}
	if v := testutil.ToFloat64(runs.WithLabelValues(chain.Mode(), analyst.ChainOutcomeAssessed)); v != 1 {
		t.Fatalf("chain runs assessed = %v, want 1", v)
	}
}

// A panicking chain on a worker degrades to a zero verdict and never kills
// the worker or the consumer.
func TestChainRunFunc_RecoversFromPanic(t *testing.T) {
	pp := panicProvider{}
	reg := metrics.NewRegistry()
	l1, _ := analyst.NewL1(pp, analyst.PromptSpec{System: "s", Version: "v"}, reg, nil)
	l2, _ := analyst.NewL2(pp, analyst.PromptSpec{System: "s", Version: "v"}, reg, nil)
	sr, _ := analyst.NewSenior(pp, analyst.PromptSpec{System: "s", Version: "v"}, reg, nil)
	chain, err := analyst.NewChain(l1, l2, sr, reg, nil)
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	run := newChainRunFunc(chain, chain.Mode(), &fakeAssessmentPub{}, nil, chainTestLogger())
	got, completed := run(context.Background(), triggeringPackage("80"))
	if got != 0 || !completed {
		t.Fatalf("a panicking chain must fold 0 and count as completed (so a poison package is acked), got %d/%v", got, completed)
	}
}

// Env knobs: defaults, valid values, and loud fallback on bad values.
func TestChainPoolEnv(t *testing.T) {
	t.Setenv("OLT_LLM_CHAIN_WORKERS", "")
	t.Setenv("OLT_LLM_CHAIN_QUEUE", "")
	w, q := chainPoolSize(chainTestLogger())
	if w != defaultChainWorkers || q != defaultChainQueue {
		t.Fatalf("defaults = %d/%d", w, q)
	}
	t.Setenv("OLT_LLM_CHAIN_WORKERS", "4")
	t.Setenv("OLT_LLM_CHAIN_QUEUE", "0")
	if w, q = chainPoolSize(chainTestLogger()); w != 4 || q != 0 {
		t.Fatalf("explicit = %d/%d, want 4/0", w, q)
	}
	var buf syncBuffer
	t.Setenv("OLT_LLM_CHAIN_WORKERS", "0")
	t.Setenv("OLT_LLM_CHAIN_QUEUE", "lots")
	if w, q = chainPoolSize(slog.New(slog.NewJSONHandler(&buf, nil))); w != defaultChainWorkers || q != defaultChainQueue {
		t.Fatalf("invalid values must fall back to defaults, got %d/%d", w, q)
	}
	if !strings.Contains(buf.String(), "OLT_LLM_CHAIN_WORKERS") || !strings.Contains(buf.String(), "OLT_LLM_CHAIN_QUEUE") {
		t.Fatalf("invalid values must be warned about by name: %s", buf.String())
	}
}

// ordered reports whether the JSON keys appear in line in the given order.
func ordered(line string, keys []string) bool {
	pos := -1
	for _, k := range keys {
		i := strings.Index(line, `"`+k+`":`)
		if i <= pos {
			return false
		}
		pos = i
	}
	return true
}

// The sink context outlives the ring context until the FSM consumer's drain
// is done, and is bounded when the consumer never signals (PR #209 round 2).
func TestDrainAwareContext_WaitsForFSMDrainWithBound(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	dctx := drainAwareContext(ctx, done, 5*time.Second)
	cancel()
	select {
	case <-dctx.Done():
		t.Fatal("sink context ended before the FSM drain finished")
	case <-time.After(50 * time.Millisecond):
	}
	close(done)
	select {
	case <-dctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("sink context not cancelled after the FSM drain finished")
	}

	ctx2, cancel2 := context.WithCancel(context.Background())
	never := make(chan struct{})
	dctx2 := drainAwareContext(ctx2, never, 50*time.Millisecond)
	cancel2()
	select {
	case <-dctx2.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the wait for the FSM drain must be bounded")
	}
}

// The bound covers the consumer's own drain budget.
func TestFSMShutdownBoundCoversDrain(t *testing.T) {
	if fsmShutdownBound <= chainShutdownGrace+chainAbortGrace {
		t.Fatalf("fsmShutdownBound %v must exceed the drain budget %v", fsmShutdownBound, chainShutdownGrace+chainAbortGrace)
	}
	if fsmShutdownBound+2*time.Second > 30*time.Second {
		t.Fatalf("fsmShutdownBound %v plus the 2s NATS close must fit the 30s termination grace", fsmShutdownBound)
	}
}
