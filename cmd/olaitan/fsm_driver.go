package main

import (
	"context"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/olokotoh/olaitan/internal/decision/analyst"
	"github.com/olokotoh/olaitan/internal/decision/score"
	"github.com/olokotoh/olaitan/internal/response/fsm"
	"github.com/olokotoh/olaitan/internal/response/risk"
	"github.com/olokotoh/olaitan/internal/schema"
)

// Story 7.4 (issue #186): score before the analyst chain, re-score when it
// returns.
//
// Before this story the single FSM consumer ran the L1/L2/Senior chain INLINE
// before fsm.Evaluate, so with a CPU model the first transition of a real
// attack waited minutes (727 s in one live run) and every other workload's
// packages queued behind it. Now:
//
//  1. Every package is folded into the risk window with a ZERO LLM term from
//     this package (a still-live verdict already in the window is kept),
//     scored, and evaluated at once (handlePackage). The deterministic path
//     never waits on the chain.
//  2. When the chain is enabled and the FR19 gate + breaker admit the
//     package, it is dispatched to a bounded worker pool with at most ONE
//     chain in flight per workload (chainDispatcher).
//  3. Workers run ONLY the chain + the AUDIT.assessments publish. The result
//     comes back over a channel and is applied on the consumer goroutine
//     (applyResult): the capped verdict is folded into the window, the
//     aggregate re-scored, and fsm.Evaluate called again with the triggering
//     package id, so a verdict that moves the band is its own audited
//     transition. Keeping every window/score/Evaluate call on one goroutine
//     preserves Story 3.11's single-FSM-driver invariant and the order in
//     which transitions reach the audit/Redis sinks (Machine.Evaluate
//     publishes after releasing its lock, so concurrent Evaluate calls could
//     deliver transitions out of order).
//
// A dispatched package is acked only once its result is applied, so a
// restart mid-chain still redelivers it and the Story 3.9 checkpoints resume
// the chain (FR29). A heartbeat (InProgress) keeps JetStream from
// redelivering it while a slow model runs. Every other package is acked at
// once.

const (
	// defaultChainWorkers is the default number of concurrent chains. Two
	// keeps a single in-cluster CPU model from being oversubscribed while
	// still letting a second workload's investigation proceed.
	defaultChainWorkers = 2
	// defaultChainQueue is the default number of admitted chains that may
	// wait for a free worker before new dispatches are rejected.
	defaultChainQueue = 16
	maxChainWorkers   = 32
	maxChainQueue     = 1024

	// chainHeartbeat is how often an in-flight chain's message is marked
	// InProgress. It must stay well under fsmConsumerAckWait.
	chainHeartbeat = 10 * time.Second
	// chainShutdownGrace bounds how long the consumer waits for in-flight
	// chains after cancellation.
	chainShutdownGrace = 10 * time.Second
)

// chainRunFunc runs the chain for one admitted package and returns the
// per-provider-capped LLM confidence (0 on error / degrade / panic).
type chainRunFunc func(ctx context.Context, pkg schema.EvidencePackage) int

// chainJob is one admitted package plus its JetStream message controls.
type chainJob struct {
	pkg        schema.EvidencePackage
	ack        func()
	inProgress func()
}

// chainResult is a finished chain, handed back to the consumer goroutine.
type chainResult struct {
	job    chainJob
	capped int
}

// chainDispatcher is a bounded worker pool for the analyst chain with
// per-workload coalescing. The in-flight set covers a workload from dispatch
// until the consumer has APPLIED its result (complete), so at most one chain
// per workload is queued, running, or awaiting application at any time.
type chainDispatcher struct {
	run        chainRunFunc
	jobs       chan chainJob
	out        chan chainResult
	capacity   int
	workers    int
	dispatches *prometheus.CounterVec
	log        *slog.Logger
	heartbeat  time.Duration

	mu       sync.Mutex
	inflight map[string]struct{}
	wg       sync.WaitGroup
}

// newChainDispatcher builds a pool of workers goroutines (min 1) with room
// for queue admitted chains waiting for a worker (min 0). The total in-flight
// capacity is workers+queue; the job and result channels are sized to it, so
// neither a dispatch nor a worker's result hand-off ever blocks.
func newChainDispatcher(workers, queue int, run chainRunFunc, dispatches *prometheus.CounterVec, log *slog.Logger) *chainDispatcher {
	if workers < 1 {
		workers = 1
	}
	if queue < 0 {
		queue = 0
	}
	capacity := workers + queue
	return &chainDispatcher{
		run:        run,
		jobs:       make(chan chainJob, capacity),
		out:        make(chan chainResult, capacity),
		capacity:   capacity,
		workers:    workers,
		dispatches: dispatches,
		log:        log,
		heartbeat:  chainHeartbeat,
		inflight:   make(map[string]struct{}, capacity),
	}
}

// start launches the workers. They stop when ctx is cancelled.
func (d *chainDispatcher) start(ctx context.Context) {
	for i := 0; i < d.workers; i++ {
		d.wg.Add(1)
		go d.worker(ctx)
	}
}

func (d *chainDispatcher) worker(ctx context.Context) {
	defer d.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-d.jobs:
			stop := d.keepAlive(ctx, job.inProgress)
			capped := d.run(ctx, job.pkg)
			stop()
			if ctx.Err() != nil {
				// Shutdown cut the chain short: leave the message un-acked
				// so JetStream redelivers it and the Story 3.9 checkpoints
				// resume the chain after restart.
				return
			}
			select {
			case d.out <- chainResult{job: job, capped: capped}:
			case <-ctx.Done():
				return
			}
		}
	}
}

// keepAlive marks the job's message InProgress every heartbeat until the
// returned stop func is called, so a slow chain does not exceed AckWait.
func (d *chainDispatcher) keepAlive(ctx context.Context, inProgress func()) (stop func()) {
	if inProgress == nil || d.heartbeat <= 0 {
		return func() {}
	}
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		t := time.NewTicker(d.heartbeat)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				inProgress()
			}
		}
	}()
	return func() {
		close(done)
		<-finished
	}
}

// dispatch admits job to the pool, or coalesces / rejects it, and records the
// decision. It never blocks. The caller acks the message itself unless the
// result is dispatched.
func (d *chainDispatcher) dispatch(job chainJob) string {
	wl := job.pkg.WorkloadID
	d.mu.Lock()
	result := analyst.ChainDispatchDispatched
	switch {
	case d.hasLocked(wl):
		result = analyst.ChainDispatchCoalesced
	case len(d.inflight) >= d.capacity:
		result = analyst.ChainDispatchQueueFull
	default:
		d.inflight[wl] = struct{}{}
		// Cannot block: len(jobs) <= len(inflight) <= capacity == cap(jobs).
		d.jobs <- job
	}
	d.mu.Unlock()
	if d.dispatches != nil {
		d.dispatches.WithLabelValues(result).Inc()
	}
	return result
}

func (d *chainDispatcher) hasLocked(wl string) bool {
	_, ok := d.inflight[wl]
	return ok
}

// results is the channel of finished chains the consumer drains.
func (d *chainDispatcher) results() <-chan chainResult { return d.out }

// complete frees the workload's in-flight slot once its result is applied.
func (d *chainDispatcher) complete(workloadID string) {
	d.mu.Lock()
	delete(d.inflight, workloadID)
	d.mu.Unlock()
}

// inflightIDs returns the in-flight workloads, sorted (diagnostics, tests).
func (d *chainDispatcher) inflightIDs() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	ids := make([]string, 0, len(d.inflight))
	for id := range d.inflight {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// wait blocks until every worker has exited or bound elapses, and reports
// whether the workers exited. Call it after cancelling the start context.
func (d *chainDispatcher) wait(bound time.Duration) bool {
	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()
	t := time.NewTimer(bound)
	defer t.Stop()
	select {
	case <-done:
		return true
	case <-t.C:
		return false
	}
}

// fsmDriver holds the per-package and per-result logic of the single FSM
// consumer. All of its methods run on the consumer goroutine.
type fsmDriver struct {
	log        *slog.Logger
	scoreCalc  *score.Calculator
	machine    *fsm.Machine
	window     *risk.Window
	chainMode  string
	breaker    *analyst.CircuitBreaker
	chainRuns  *prometheus.CounterVec
	dispatcher *chainDispatcher // nil = no chain (RS mode / provider=none)
	now        func() time.Time

	// lastScore is the most recent total passed to Evaluate (diagnostics).
	lastScore float64
}

// handlePackage scores pkg deterministically, evaluates the FSM at once, and
// (when the chain is enabled and admits the package) dispatches the chain.
// ack is called here unless the chain was dispatched, in which case
// applyResult calls it.
func (d *fsmDriver) handlePackage(pkg schema.EvidencePackage, ack, inProgress func()) {
	// time.Now() keeps the monotonic reading so the window's TTL arithmetic
	// is immune to wall-clock steps (PR #92 review).
	now := d.now()
	// Fold this package's signals into the workload's rolling risk aggregate
	// and score the aggregate, so recent correlated evidence (rule + baseline
	// + any still-live LLM verdict) sums rather than each single-signal
	// package scoring alone. This package contributes a ZERO LLM term: its
	// own verdict, if any, arrives later through applyResult. A disabled
	// window returns the package's own signals, so the score is unchanged.
	rules, devs, llm := d.window.Observe(pkg.WorkloadID, pkg, 0, now)
	agg := pkg
	agg.RuleMatches = rules
	agg.BaselineDeviations = devs
	sc, err := d.scoreCalc.Score(&agg, llm)
	if err != nil {
		d.log.Warn("aggregator: fsm score failed; dropping", "err", err, "package_id", pkg.PackageID)
		ack()
		return
	}
	d.evaluate(pkg.WorkloadID, pkg.PackageID, sc)

	if d.dispatcher == nil {
		ack()
		return
	}
	if ok, _ := admitChainPackage(pkg, d.chainMode, d.breaker, d.chainRuns); !ok {
		ack()
		return
	}
	switch res := d.dispatcher.dispatch(chainJob{pkg: pkg, ack: ack, inProgress: inProgress}); res {
	case analyst.ChainDispatchDispatched:
		// Acked by applyResult once the verdict is folded (Story 3.9 resume).
	default:
		d.log.Info("aggregator: investigation chain not dispatched",
			"result", res, "workload_id", pkg.WorkloadID, "package_id", pkg.PackageID)
		ack()
	}
}

// applyResult folds a finished chain's capped verdict into the workload's risk
// window, re-scores the aggregate, and evaluates the FSM again keyed by the
// same workload with the triggering package id, so a verdict that changes the
// state is its own audited transition. A zero verdict (degraded, errored,
// no citable evidence) has nothing to fold and is not re-evaluated.
func (d *fsmDriver) applyResult(r chainResult) {
	pkg := r.job.pkg
	defer r.job.ack()
	defer d.dispatcher.complete(pkg.WorkloadID)
	if r.capped <= 0 {
		return
	}
	rules, devs, llm := d.window.FoldLLM(pkg.WorkloadID, pkg, r.capped, d.now())
	agg := pkg
	agg.RuleMatches = rules
	agg.BaselineDeviations = devs
	sc, err := d.scoreCalc.Score(&agg, llm)
	if err != nil {
		d.log.Warn("aggregator: fsm re-score failed", "err", err, "package_id", pkg.PackageID)
		return
	}
	d.evaluate(pkg.WorkloadID, pkg.PackageID, sc, "source", "analyst_chain", "llm_capped", r.capped)
}

// drainResults applies every finished chain without blocking.
func (d *fsmDriver) drainResults() {
	if d.dispatcher == nil {
		return
	}
	for {
		select {
		case r := <-d.dispatcher.results():
			d.applyResult(r)
		default:
			return
		}
	}
}

// evaluate drives the FSM and logs an actual transition with the per-term
// composition. extra attributes are appended only for the analyst-chain
// re-score, so the deterministic transition line is byte-identical to the
// pre-Story-7.4 line.
func (d *fsmDriver) evaluate(workloadID, packageID string, sc schema.ConfidenceScore, extra ...any) {
	d.lastScore = sc.Total
	st := d.machine.Evaluate(workloadID, sc.Total, packageID)
	if st.FromState == st.ToState {
		return
	}
	// The per-term composition is logged with every transition so a windowed
	// score is explainable: the audit event records the total against the
	// triggering package, and this structured line records WHY the total is
	// what it is, including signals the risk window inherited from earlier
	// packages (PR #92 review; the AUDIT.transitions schema extension is
	// deferred, see docs/deferred-decisions.md).
	attrs := []any{
		"workload_id", st.WorkloadID,
		"from_state", string(st.FromState),
		"to_state", string(st.ToState),
		"reason", st.Reason,
		"score", st.Confidence,
		"score_rules", sc.Rules,
		"score_baseline", sc.Baseline,
		"score_llm", sc.LLM,
		"risk_window", d.window.Enabled(),
		"package_id", st.PackageID,
	}
	d.log.Info("aggregator: fsm transition", append(attrs, extra...)...)
}

// chainPoolSize reads OLT_LLM_CHAIN_WORKERS and OLT_LLM_CHAIN_QUEUE. An unset
// value takes the default; an unparseable or out-of-range value ALSO takes
// the default, but loudly (the envSeconds precedent: a typo here silently
// changes how the LLM tier behaves).
func chainPoolSize(log *slog.Logger) (workers, queue int) {
	workers = envIntInRange(log, "OLT_LLM_CHAIN_WORKERS", defaultChainWorkers, 1, maxChainWorkers)
	queue = envIntInRange(log, "OLT_LLM_CHAIN_QUEUE", defaultChainQueue, 0, maxChainQueue)
	return workers, queue
}

func envIntInRange(log *slog.Logger, key string, def, lo, hi int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		if log != nil {
			log.Warn("invalid integer value; using default",
				"env", key, "value", v, "default", def, "min", lo, "max", hi)
		}
		return def
	}
	return n
}
