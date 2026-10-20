package baseline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/olokotoh/olaitan/internal/metrics"
	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/schema"
)

const (
	// publishAttemptTimeout caps a single FireBaselineDeviation
	// invocation (at most five per closed bucket).
	publishAttemptTimeout = 2 * time.Second

	// DefaultSigmaMultiplier is the AC2 explicit "default 3 sigma"
	// threshold above the rolling per-workload mean.
	DefaultSigmaMultiplier = 3.0

	// MinSamples is the number of one-minute samples a metric needs
	// before it can deviate (Story 10.12 D4). It backs up warm-up when
	// warm-up is configured very short (the e2e overlays use 5 s): no
	// sigma is meaningful on a handful of samples.
	MinSamples = 10

	// observationQueueSize bounds the correlator-to-engine hand-off. The
	// correlator never blocks on it: a full queue drops the observation
	// and counts it in olaitan_decision_baseline_observations_dropped_total.
	observationQueueSize = 8192

	// evalTimeout bounds the Redis work of one evaluation (load, warm-up
	// check, save) so a slow Redis cannot stall the engine's only
	// goroutine and overflow the observation queue for long.
	evalTimeout = 3 * time.Second

	// maxLateness: an event older than this on arrival (by its own
	// timestamp) is not folded into the current minute. It is a replayed
	// backlog (correlator or aggregator restart, an outage) whose burst
	// would otherwise land in one bucket and fire a false deviation.
	// Goldmane flows arrive up to about a minute after the start of their
	// aggregation window, which this allows.
	maxLateness = 2 * time.Minute

	// tickInterval is how often the engine closes due buckets of
	// workloads that produced no event since their minute ended.
	tickInterval = 5 * time.Second

	// legacyConsumerName is the EVIDENCE durable the engine used before
	// Story 10.12, when it baselined EvidencePackages. Run deletes it so
	// it does not linger on an upgraded cluster.
	legacyConsumerName = "olaitan-baseline-engine"
)

// histogramBuckets sizes the evaluation_seconds histogram against
// the NFR3 100 ms p99 gate.
var histogramBuckets = []float64{0.001, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250}

// BaselineDeviationEmitter is the engine's only outbound dependency.
// The correlator's FireBaselineDeviation method satisfies it. Defining a
// local interface keeps the engine package one-way: the engine does NOT
// import correlator.
type BaselineDeviationEmitter interface {
	// identity is the workload identity the correlator resolved for the
	// workload's events, so the deviation package is attributed to the
	// workload rather than to whichever pod ref sits first in the window.
	FireBaselineDeviation(ctx context.Context, workloadID string, identity schema.WorkloadIdentity, deviation schema.BaselineDeviation) (*schema.EvidencePackage, error)
}

// Config configures an Engine.
type Config struct {
	// NATS is optional. When set, Run deletes the pre-Story-10.12
	// EVIDENCE durable consumer.
	NATS            *natsclient.Client
	Store           *Store
	Warmup          *Warmup
	Emitter         BaselineDeviationEmitter
	Metrics         *metrics.Registry
	Log             *slog.Logger
	SigmaMultiplier float64
	// OwnNamespaces are Olaitan's own namespaces (the correlator's
	// never-scored list). Audit events whose actor is a ServiceAccount in
	// one of them are Olaitan's own lookups, not workload behaviour, and
	// are not counted in audit_events_per_min. Hot-reloadable via
	// SetOwnNamespaces.
	OwnNamespaces []string
	// OwnActors are the exact usernames of Olaitan's own identities (the
	// aggregator's ServiceAccount, read from its projected token at
	// start). Their audit calls are excluded too, wherever Olaitan is
	// installed, without excluding every ServiceAccount of a shared
	// release namespace.
	OwnActors []string
}

// Observation is one event the correlator attributed to a workload.
type Observation struct {
	WorkloadID string
	Identity   schema.WorkloadIdentity
	Event      schema.Event
}

// Engine keeps per-workload Welford state for the five default metrics,
// sampled on fixed one-minute buckets of the events the correlator
// attributes to each workload (Story 10.12), and emits a
// BaselineDeviation through the correlator for each metric whose
// one-minute sample crosses sigma.
//
// Concurrency: ObserveEvent, SetSigmaMultiplier, SetWarmupDuration and
// SetOwnNamespaces are safe from any goroutine. Ingest and Tick mutate
// the trackers and must only be called by one goroutine at a time: Run
// in production, the test itself in tests.
type Engine struct {
	nc         *natsclient.Client
	store      *Store
	warmup     *Warmup
	emit       BaselineDeviationEmitter
	log        *slog.Logger
	metricList []string

	sigmaMul  atomic.Pointer[float64]
	ownNS     atomic.Pointer[map[string]struct{}]
	ownActors map[string]struct{}
	now       func() time.Time

	obs      chan Observation
	trackers map[string]*tracker
	live     map[schema.EventSource]bool

	evalDeviation       atomic.Int64
	evalNormal          atomic.Int64
	evalError           atomic.Int64
	observationsDropped atomic.Int64
	observationsLate    atomic.Int64
	missingIdentity     atomic.Int64
	trackedWorkloads    atomic.Int64
	warmupActiveCard    atomic.Int64
	evalSeconds         prometheus.Histogram
	deviationsVec       *prometheus.CounterVec
}

// New constructs an Engine wired against the given dependencies.
func New(cfg Config) (*Engine, error) {
	if cfg.Store == nil {
		return nil, errors.New("baseline: store is nil")
	}
	if cfg.Store.client == nil {
		return nil, errors.New("baseline: store.client is nil (Store must be constructed via NewStore)")
	}
	if cfg.Warmup == nil {
		return nil, errors.New("baseline: warmup is nil")
	}
	if cfg.Warmup.store == nil {
		return nil, errors.New("baseline: warmup.store is nil (Warmup must be constructed via NewWarmup)")
	}
	if cfg.Warmup.cfg.Load() == nil {
		return nil, errors.New("baseline: warmup.cfg is nil (Warmup must be constructed via NewWarmup)")
	}
	if cfg.Emitter == nil {
		return nil, errors.New("baseline: emitter is nil")
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.SigmaMultiplier <= 0 {
		cfg.SigmaMultiplier = DefaultSigmaMultiplier
	}
	e := &Engine{
		nc:         cfg.NATS,
		store:      cfg.Store,
		warmup:     cfg.Warmup,
		emit:       cfg.Emitter,
		log:        cfg.Log.With("component", "baseline-engine"),
		metricList: MetricNames(),
		now:        time.Now,
		obs:        make(chan Observation, observationQueueSize),
		trackers:   map[string]*tracker{},
		live:       map[schema.EventSource]bool{},
	}
	sigma := cfg.SigmaMultiplier
	e.sigmaMul.Store(&sigma)
	e.SetOwnNamespaces(cfg.OwnNamespaces)
	e.ownActors = make(map[string]struct{}, len(cfg.OwnActors))
	for _, a := range cfg.OwnActors {
		if a != "" {
			e.ownActors[a] = struct{}{}
		}
	}
	if cfg.Metrics != nil {
		if err := e.registerMetrics(cfg.Metrics); err != nil {
			return nil, fmt.Errorf("baseline: register metrics: %w", err)
		}
	}
	return e, nil
}

// SetSigmaMultiplier replaces the active sigma threshold. Called by
// the config manager's hot-reload callback; safe for concurrent use.
func (e *Engine) SetSigmaMultiplier(v float64) {
	if v <= 0 {
		return
	}
	e.sigmaMul.Store(&v)
}

// SetWarmupDuration forwards a hot-reloaded warm-up window length to the
// embedded Warmup controller.
func (e *Engine) SetWarmupDuration(d time.Duration) {
	if d <= 0 {
		return
	}
	e.warmup.SetConfig(WarmupConfig{Duration: d})
}

// SetOwnNamespaces replaces Olaitan's own namespaces (hot-reloadable).
func (e *Engine) SetOwnNamespaces(nss []string) {
	m := make(map[string]struct{}, len(nss))
	for _, ns := range nss {
		m[ns] = struct{}{}
	}
	e.ownNS.Store(&m)
}

// isOwnActor reports whether an audit actor is one of Olaitan's own
// identities: an exact OwnActors username, or a ServiceAccount in one of
// OwnNamespaces.
func (e *Engine) isOwnActor(username string) bool {
	if _, ok := e.ownActors[username]; ok {
		return true
	}
	if ns := serviceAccountNamespace(username); ns != "" {
		return e.isOwnNamespace(ns)
	}
	return false
}

func (e *Engine) isOwnNamespace(ns string) bool {
	p := e.ownNS.Load()
	if p == nil {
		return false
	}
	_, ok := (*p)[ns]
	return ok
}

// SigmaMultiplier returns the currently-active threshold.
func (e *Engine) SigmaMultiplier() float64 {
	if p := e.sigmaMul.Load(); p != nil {
		return *p
	}
	return DefaultSigmaMultiplier
}

func (e *Engine) registerMetrics(reg *metrics.Registry) error {
	for _, outcome := range []string{"deviation", "normal", "error"} {
		out := outcome
		getter := func() int64 {
			switch out {
			case "deviation":
				return e.evalDeviation.Load()
			case "normal":
				return e.evalNormal.Load()
			case "error":
				return e.evalError.Load()
			}
			return 0
		}
		if err := reg.RegisterCounter(
			"olaitan_decision_baseline_evaluations_total",
			"",
			"Per-sample baseline-evaluation outcome counter. One outcome per closed one-minute workload sample (Story 10.12): deviation (>=1 metric crossed sigma and every emit succeeded), normal (no metric crossed sigma), error (Redis or any per-metric emit failed). For per-metric cardinality see olaitan_decision_baseline_deviations_total.",
			prometheus.Labels{"outcome": out},
			getter,
		); err != nil {
			return err
		}
	}
	dv, err := reg.RegisterCounterVec(
		"olaitan_decision_baseline_deviations_total",
		"Per-(metric, sigma_bucket) baseline-deviation counter (sigma_bucket one of \"3-5\", \"5-10\", \"10+\"). Complements evaluations_total{outcome=deviation}.",
		[]string{"metric", "sigma_bucket"},
	)
	if err != nil {
		return err
	}
	e.deviationsVec = dv
	if err := reg.RegisterCounter(
		"olaitan_decision_baseline_observations_dropped_total",
		"",
		"Cumulative events the correlator handed to the baseline engine that were dropped because the engine's bounded queue was full (Story 10.12). Non-zero means the engine fell behind the event stream and baselines under-count.",
		nil,
		func() int64 { return e.observationsDropped.Load() },
	); err != nil {
		return err
	}
	if err := reg.RegisterCounter(
		"olaitan_decision_baseline_observations_late_total",
		"",
		"Cumulative events not folded into a baseline minute because they were more than 2 minutes old on arrival (Story 10.12): a replayed backlog after a restart or outage, which would otherwise land in one minute as a false burst.",
		nil,
		func() int64 { return e.observationsLate.Load() },
	); err != nil {
		return err
	}
	if err := reg.RegisterGauge(
		"olaitan_decision_baseline_tracked_workloads",
		"",
		"Workloads the baseline engine currently samples every minute (Story 10.12). A workload is dropped after an hour without events; its learnt state stays in Redis.",
		nil,
		func() int64 { return e.trackedWorkloads.Load() },
	); err != nil {
		return err
	}
	if err := reg.RegisterGauge(
		"olaitan_decision_baseline_warmup_active",
		"",
		"Count of workloads currently within an active warm-up window (FR18). Since Story 10.12 a new workload starts warm-up on its first sample, as well as a restarted one.",
		nil,
		func() int64 { return e.warmupActiveCard.Load() },
	); err != nil {
		return err
	}
	h, err := reg.RegisterHistogram(
		"olaitan_decision_baseline_evaluation_seconds",
		"",
		"Per-sample baseline-engine evaluation latency in seconds (Redis load, Welford update, save, emit); histogram buckets are sized against NFR3 (p99 <= 100 ms).",
		nil,
		histogramBuckets,
	)
	if err != nil {
		return err
	}
	e.evalSeconds = h
	return nil
}

// ObserveEvent hands one correlator-attributed event to the engine. It
// never blocks: when the queue is full the event is dropped and counted.
// The correlator calls it after identity resolution and its host and
// never-scored filters (correlator.EventObserver).
func (e *Engine) ObserveEvent(workloadID string, identity schema.WorkloadIdentity, ev schema.Event) {
	select {
	case e.obs <- Observation{WorkloadID: workloadID, Identity: identity, Event: ev}:
	default:
		e.observationsDropped.Add(1)
	}
}

// Run processes observations and closes one-minute buckets until ctx is
// cancelled. It also deletes the pre-Story-10.12 EVIDENCE durable and
// runs the warm-up gauge sampler. Returns nil on graceful shutdown.
func (e *Engine) Run(ctx context.Context) error {
	e.deleteLegacyConsumer(ctx)
	go e.sampleWarmupGauge(ctx)
	t := time.NewTicker(tickInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case o := <-e.obs:
			e.Ingest(ctx, o, e.now())
		case <-t.C:
			e.Tick(ctx, e.now())
		}
	}
}

func (e *Engine) deleteLegacyConsumer(ctx context.Context) {
	if e.nc == nil || e.nc.JetStream() == nil {
		return
	}
	stream, err := e.nc.JetStream().Stream(ctx, "EVIDENCE")
	if err != nil {
		e.log.Debug("baseline: EVIDENCE stream not available for legacy consumer cleanup", "err", err)
		return
	}
	if err := stream.DeleteConsumer(ctx, legacyConsumerName); err != nil {
		if !errors.Is(err, jetstream.ErrConsumerNotFound) {
			e.log.Warn("baseline: delete legacy EVIDENCE consumer", "consumer", legacyConsumerName, "err", err)
		}
		return
	}
	e.log.Info("baseline: deleted legacy EVIDENCE consumer (the engine samples correlator events since Story 10.12)", "consumer", legacyConsumerName)
}

// sampleWarmupGauge refreshes the warmup_active gauge every 5 s.
func (e *Engine) sampleWarmupGauge(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.warmupActiveCard.Store(int64(len(e.warmup.ActiveWorkloads())))
		}
	}
}

// Ingest folds one observation into its workload's current minute,
// closing (and evaluating) the previous minute first when now has moved
// past it. Not safe for concurrent use; see Engine.
func (e *Engine) Ingest(ctx context.Context, o Observation, now time.Time) {
	ev := o.Event
	// Source liveness (Story 10.12 D2). Only flow records feed the
	// network metrics, so only they prove the network source live.
	if ev.Source != "" && (ev.Source != schema.SourceNetwork || ev.Category == schema.CategoryFlow) {
		e.live[ev.Source] = true
	}
	if !ev.Timestamp.IsZero() && now.Sub(ev.Timestamp) > maxLateness {
		e.observationsLate.Add(1)
		return
	}
	ns, key := workloadKey(o.Identity, ev.Pod)
	if ns == "" || key == "" {
		e.missingIdentity.Add(1)
		return
	}
	id := ns + "/" + key
	tr, ok := e.trackers[id]
	if !ok {
		tr = &tracker{
			namespace: ns,
			key:       key,
			cur:       newBucket(now.Truncate(BucketWidth)),
			restarts:  map[string]time.Time{},
		}
		e.trackers[id] = tr
		e.trackedWorkloads.Store(int64(len(e.trackers)))
	} else {
		e.advance(ctx, tr, now)
	}
	if o.WorkloadID != "" {
		tr.workloadID = o.WorkloadID
		tr.identity = o.Identity
	}
	tr.add(&ev, now, e.isOwnActor)
	tr.lastEvent = now
}

// Tick closes every bucket whose minute has ended, zero-filling minutes
// with no events, and stops tracking workloads idle for idleEvictAfter.
// Not safe for concurrent use; see Engine.
func (e *Engine) Tick(ctx context.Context, now time.Time) {
	ids := make([]string, 0, len(e.trackers))
	for id := range e.trackers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		tr := e.trackers[id]
		e.advance(ctx, tr, now)
		if now.Sub(tr.lastEvent) >= idleEvictAfter {
			delete(e.trackers, id)
		}
	}
	e.trackedWorkloads.Store(int64(len(e.trackers)))
}

// advance evaluates the tracker's current minute once now has left it,
// then one zero sample per fully empty minute in between (at most
// maxGapFill), in one batch (one Redis load and one save), and opens the
// bucket for now's minute.
func (e *Engine) advance(ctx context.Context, tr *tracker, now time.Time) {
	cur := now.Truncate(BucketWidth)
	if !cur.After(tr.cur.start) {
		return
	}
	samples := []sample{tr.close(tr.cur, e.isLive)}
	gaps := int(cur.Sub(tr.cur.start)/BucketWidth) - 1
	if gaps > maxGapFill {
		gaps = maxGapFill
	}
	for i := gaps; i >= 1; i-- {
		samples = append(samples, tr.close(newBucket(cur.Add(-time.Duration(i)*BucketWidth)), e.isLive))
	}
	tr.prevIDs = tr.cur.ids
	tr.cur = newBucket(cur)
	e.evaluate(ctx, tr, samples)
}

func (e *Engine) isLive(src schema.EventSource) bool { return e.live[src] }

// evaluate folds closed samples, oldest first, into the workload's
// Welford state and emits a deviation per metric and sample that crosses
// sigma. The Redis work runs under evalTimeout so a slow or failing Redis
// cannot stall the engine's only goroutine for long (Story 10.12 review).
func (e *Engine) evaluate(parent context.Context, tr *tracker, samples []sample) {
	nonEmpty := samples[:0:0]
	for _, s := range samples {
		if len(s.values) > 0 || s.restart {
			nonEmpty = append(nonEmpty, s)
		}
	}
	if len(nonEmpty) == 0 {
		return
	}
	start := time.Now()
	defer func() {
		if e.evalSeconds != nil {
			e.evalSeconds.Observe(time.Since(start).Seconds())
		}
	}()
	ns, pod := tr.namespace, tr.key
	ctx, cancel := context.WithTimeout(parent, evalTimeout)
	defer cancel()

	st, err := e.store.LoadState(ctx, ns, pod, e.metricList)
	if err != nil {
		e.fail("store load", ns, pod, err, len(nonEmpty))
		return
	}
	active, err := e.warmup.IsActive(ctx, ns, pod)
	if err != nil {
		e.fail("warmup IsActive", ns, pod, err, len(nonEmpty))
		return
	}

	switch {
	case !st.SchemaCurrent && (st.HasHistory || st.WarmupRecorded):
		// Learnt under the pre-10.12 package-window semantics: not
		// comparable. Start over as a new workload.
		if err := e.reset(ctx, ns, pod, st, false); err != nil {
			e.fail("reset legacy baseline", ns, pod, err, len(nonEmpty))
			return
		}
		active = true
		e.log.Info("baseline: pre-10.12 baseline discarded; warm-up engaged", "namespace", ns, "workload", pod)
	case !st.HasHistory && !st.WarmupRecorded:
		// Story 10.12 B1: a new workload warms up before it can deviate.
		if err := e.warmup.Begin(ctx, ns, pod); err != nil {
			e.fail("warmup Begin (new workload)", ns, pod, err, len(nonEmpty))
			return
		}
		active = true
		e.log.Info("baseline: new workload; warm-up engaged", "namespace", ns, "workload", pod)
	}

	sigmaMul := e.SigmaMultiplier()
	var deviations []schema.BaselineDeviation
	deviating := 0
	for _, s := range nonEmpty {
		if s.restart && !active {
			// Restart-aware behaviour (Story 1.17 AC3), kept: zero the
			// baselines and warm up. Deduped while warm-up is active so a
			// crash loop cannot extend it forever. The restarts metric
			// keeps its history (Story 10.12 D5).
			if err := e.reset(ctx, ns, pod, st, true); err != nil {
				e.fail("reset after restart", ns, pod, err, len(nonEmpty))
				return
			}
			active = true
			e.log.Info("baseline: workload restart detected; warm-up engaged", "namespace", ns, "workload", pod)
		}
		found := false
		for _, name := range e.metricList {
			value, ok := s.values[name]
			if !ok {
				continue
			}
			w := st.Welfords[name]
			preCount, preMean := w.Count, w.Mean
			eff := effectiveStdDev(name, w.StdDev(), preMean)
			w.Update(value)
			if active || preCount < MinSamples {
				continue
			}
			sigma := (value - preMean) / eff
			if sigma < sigmaMul {
				continue
			}
			found = true
			deviations = append(deviations, schema.BaselineDeviation{
				Metric: name,
				Value:  value,
				Mean:   preMean,
				StdDev: eff,
				Sigma:  sigma,
				PodUID: tr.podUID,
			})
		}
		if found {
			deviating++
		}
	}

	if err := e.store.Save(ctx, ns, pod, st.Welfords); err != nil {
		e.fail("store save", ns, pod, err, len(nonEmpty))
		return
	}

	emitFailed := false
	for _, dev := range deviations {
		fireCtx, cancelFire := context.WithTimeout(parent, publishAttemptTimeout)
		if _, err := e.emit.FireBaselineDeviation(fireCtx, tr.workloadID, tr.identity, dev); err != nil {
			emitFailed = true
			e.log.Warn("baseline: emit FireBaselineDeviation failed",
				"workload_id", tr.workloadID, "metric", dev.Metric, "err", err)
		} else {
			e.log.Info("baseline: deviation",
				"workload_id", tr.workloadID, "metric", dev.Metric, "value", dev.Value,
				"mean", dev.Mean, "std_dev", dev.StdDev, "sigma", dev.Sigma)
			if e.deviationsVec != nil {
				e.deviationsVec.WithLabelValues(dev.Metric, sigmaBucket(dev.Sigma)).Inc()
			}
		}
		cancelFire()
	}
	normal := int64(len(nonEmpty) - deviating)
	switch {
	case emitFailed:
		e.evalError.Add(int64(deviating))
	default:
		e.evalDeviation.Add(int64(deviating))
	}
	e.evalNormal.Add(normal)
}

// reset zeroes the workload's Welford state (keeping the restarts metric
// when keepRestarts) and starts warm-up. The zeroed state is saved FIRST
// so a crash between the two writes leaves a zero baseline, never a
// warm-up next to a stale baseline (Story 1.17 B14/E6).
func (e *Engine) reset(ctx context.Context, ns, pod string, st State, keepRestarts bool) error {
	for _, n := range e.metricList {
		if keepRestarts && n == MetricRestartsPerHour {
			continue
		}
		st.Welfords[n].Reset()
	}
	if err := e.store.Save(ctx, ns, pod, st.Welfords); err != nil {
		return err
	}
	return e.warmup.Begin(ctx, ns, pod)
}

func (e *Engine) fail(op, ns, pod string, err error, samples int) {
	e.log.Warn("baseline: "+op+" failed; samples not folded in", "namespace", ns, "workload", pod, "samples", samples, "err", err)
	e.evalError.Add(int64(samples))
}

// workloadKey returns the (namespace, workload token) pair addressing a
// workload's baseline hash (baseline:<namespace>:<token>:metrics). The
// token is the pod name for an orphan pod and "<OwnerKind>-<OwnerName>"
// otherwise, so a Deployment "web" and a StatefulSet "web" stay
// distinct and every pod of a Deployment shares one baseline. Falls back
// to the event's PodRef when the identity is empty.
func workloadKey(id schema.WorkloadIdentity, ref schema.PodRef) (string, string) {
	if id.Namespace != "" {
		if id.OwnerKind == "Pod" && id.PodName != "" {
			return id.Namespace, id.PodName
		}
		if id.OwnerKind != "" && id.OwnerName != "" {
			return id.Namespace, id.OwnerKind + "-" + id.OwnerName
		}
	}
	if ref.Namespace != "" && ref.Name != "" {
		return ref.Namespace, ref.Name
	}
	return "", ""
}
