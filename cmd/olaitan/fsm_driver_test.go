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

func (b *blockingRunner) run(ctx context.Context, pkg schema.EvidencePackage) int {
	b.calls.Add(1)
	b.started <- pkg.WorkloadID
	select {
	case <-b.release:
		return b.capped
	case <-ctx.Done():
		return 0
	}
}

type driverFixture struct {
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
	f := &driverFixture{sink: sink, logs: logs, acked: &ackLog{}}
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
			f.disp.wait(2 * time.Second)
		})
	}
	return f
}

func (f *driverFixture) handle(pkg schema.EvidencePackage) {
	f.d.handlePackage(pkg, f.acked.ackFor(pkg.PackageID), func() {})
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
		det := f.d.lastScore
		close(br.release)
		f.awaitResult(t)
		if f.d.lastScore < det {
			t.Fatalf("severity %s: re-score %v below deterministic %v", sev, f.d.lastScore, det)
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
		}
	}
}

// (f) Shutdown with an in-flight chain: cancelling the context stops the
// worker, wait returns within the bound, and the package is NOT acked so
// JetStream redelivers it and Story 3.9 checkpoints resume the chain.
func TestChainDispatcher_ShutdownWithInFlightChain(t *testing.T) {
	br := newBlockingRunner(35)
	f := newDriverFixture(t, br.run, risk.New(0), 2, 4)
	f.handle(pkgFor("ns/Deployment/a", "p-a1", "80"))
	awaitStarted(t, br)

	f.stop()
	start := time.Now()
	if !f.disp.wait(2 * time.Second) {
		t.Fatal("workers did not stop after cancellation")
	}
	if time.Since(start) > time.Second {
		t.Fatalf("shutdown took %v", time.Since(start))
	}
	if f.acked.has("p-a1") {
		t.Fatal("a chain cut short by shutdown must leave its package un-acked for redelivery")
	}
	select {
	case r := <-f.disp.results():
		t.Fatalf("a cancelled chain must not deliver a result: %+v", r)
	default:
	}
}

// The shutdown wait is BOUNDED even when a chain ignores cancellation.
func TestChainDispatcher_ShutdownWaitIsBounded(t *testing.T) {
	stuck := make(chan struct{})
	defer close(stuck)
	started := make(chan struct{}, 1)
	run := func(context.Context, schema.EvidencePackage) int {
		started <- struct{}{}
		<-stuck // ignores ctx on purpose
		return 0
	}
	d := newChainDispatcher(1, 0, run, nil, chainTestLogger())
	ctx, cancel := context.WithCancel(context.Background())
	d.start(ctx)
	if got := d.dispatch(chainJob{pkg: pkgFor("w", "p", "80"), ack: func() {}, inProgress: func() {}}); got != analyst.ChainDispatchDispatched {
		t.Fatalf("dispatch = %q", got)
	}
	<-started
	cancel()
	start := time.Now()
	if d.wait(100 * time.Millisecond) {
		t.Fatal("wait must report false when a chain outlives the bound")
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("bounded wait took %v", el)
	}
}

// While a chain runs, the dispatcher heartbeats the message (InProgress) so
// JetStream does not redeliver it during a slow model call.
func TestChainDispatcher_HeartbeatsInFlightMessage(t *testing.T) {
	br := newBlockingRunner(35)
	d := newChainDispatcher(1, 0, br.run, nil, chainTestLogger())
	d.heartbeat = 5 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); d.wait(time.Second) }()
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
	if got := run(context.Background(), triggeringPackage("80")); got != 0 {
		t.Fatalf("a panicking chain must fold 0, got %d", got)
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
