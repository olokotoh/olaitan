package baseline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/olokotoh/olaitan/internal/correlator/trigger"
	"github.com/olokotoh/olaitan/internal/metrics"
	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/subjects"
)

const (
	// consumerMaxDeliver caps JetStream's per-message redelivery for
	// the baseline-engine consumer. Mirrors Story 1.14 P18 and the
	// Story 1.15 rules engine so a poison package cannot loop forever.
	consumerMaxDeliver = 5

	// publishAttemptTimeout caps a single FireBaselineDeviation
	// invocation. Mirrors the correlator's publishAttemptTimeout so
	// the engine cannot accidentally block longer than the inbound
	// consumer's AckWait window.
	publishAttemptTimeout = 2 * time.Second

	// fetchBackoff is the bounded sleep between consumer.Next attempts
	// after a non-timeout error. The engine honours context
	// cancellation immediately rather than completing the backoff.
	fetchBackoff = time.Second

	// DefaultSigmaMultiplier is the AC2 explicit "default 3 sigma"
	// threshold above the rolling per-workload mean.
	DefaultSigmaMultiplier = 3.0
)

// histogramBuckets sizes the evaluation_seconds histogram against
// the NFR3 100 ms p99 gate. The buckets stop at 250 ms so a package
// that blows past the budget still buckets visibly rather than
// landing in +Inf; everything above 100 ms is already a regression.
var histogramBuckets = []float64{0.001, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250}

// BaselineDeviationEmitter is the engine's only outbound dependency.
// The correlator's FireBaselineDeviation method satisfies it.
// Defining a local interface keeps the engine package one-way: the
// engine does NOT import correlator, so future cross-engine chaining
// can extend the trigger contract without inviting an import cycle.
type BaselineDeviationEmitter interface {
	FireBaselineDeviation(ctx context.Context, workloadID string, deviation schema.BaselineDeviation) (*schema.EvidencePackage, error)
}

// Config configures an Engine.
type Config struct {
	NATS            *natsclient.Client
	Store           *Store
	Warmup          *Warmup
	Emitter         BaselineDeviationEmitter
	Metrics         *metrics.Registry
	Log             *slog.Logger
	Extractors      map[string]MetricExtractor
	SigmaMultiplier float64
}

// Engine subscribes to subjects.EvidencePackages and updates the
// per-workload Welford state for the five default metrics on every
// inbound package, emitting a BaselineDeviation through the
// correlator for each metric whose observation crosses sigma.
type Engine struct {
	nc         *natsclient.Client
	store      *Store
	warmup     *Warmup
	emit       BaselineDeviationEmitter
	log        *slog.Logger
	extractors map[string]MetricExtractor
	metricList []string

	sigmaMul atomic.Pointer[float64]

	evalDeviation    atomic.Int64
	evalNormal       atomic.Int64
	evalError        atomic.Int64
	deviationsTotal  map[string]*atomic.Int64
	skippedSelf      atomic.Int64
	evalSeconds      prometheus.Histogram
	warmupActiveCard atomic.Int64
}

// New constructs an Engine wired against the given dependencies.
// Returns an error if any required dependency is nil or if metric
// registration fails. The constructor does not subscribe to NATS;
// Run does.
func New(cfg Config) (*Engine, error) {
	if cfg.NATS == nil {
		return nil, errors.New("baseline: nats client is nil")
	}
	if cfg.Store == nil {
		return nil, errors.New("baseline: store is nil")
	}
	if cfg.Warmup == nil {
		return nil, errors.New("baseline: warmup is nil")
	}
	if cfg.Emitter == nil {
		return nil, errors.New("baseline: emitter is nil")
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Extractors == nil {
		cfg.Extractors = DefaultExtractors()
	}
	if cfg.SigmaMultiplier <= 0 {
		cfg.SigmaMultiplier = DefaultSigmaMultiplier
	}
	names := make([]string, 0, len(cfg.Extractors))
	for n := range cfg.Extractors {
		names = append(names, n)
	}
	sort.Strings(names)

	e := &Engine{
		nc:              cfg.NATS,
		store:           cfg.Store,
		warmup:          cfg.Warmup,
		emit:            cfg.Emitter,
		log:             cfg.Log.With("component", "baseline-engine"),
		extractors:      cfg.Extractors,
		metricList:      names,
		deviationsTotal: make(map[string]*atomic.Int64, len(names)),
	}
	for _, n := range names {
		var c atomic.Int64
		e.deviationsTotal[n] = &c
	}
	sigma := cfg.SigmaMultiplier
	e.sigmaMul.Store(&sigma)

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

// SigmaMultiplier returns the currently-active threshold. Test-only
// helper.
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
			"Per-package baseline-evaluation outcome counter. One outcome per handled package: deviation (>=1 metric crossed sigma and every emit succeeded), normal (no metric crossed sigma), error (decode failed or any per-metric emit failed). For per-metric cardinality see olaitan_decision_baseline_deviations_total.",
			prometheus.Labels{"outcome": out},
			getter,
		); err != nil {
			return err
		}
	}
	for _, name := range e.metricList {
		n := name
		ctr := e.deviationsTotal[n]
		if err := reg.RegisterCounter(
			"olaitan_decision_baseline_deviations_total",
			"",
			"Cumulative baseline deviations emitted by the engine; per-metric cardinality complementing the per-package evaluations_total{outcome=deviation}.",
			prometheus.Labels{"metric": n},
			func() int64 { return ctr.Load() },
		); err != nil {
			return err
		}
	}
	if err := reg.RegisterCounter(
		"olaitan_decision_baseline_skipped_self_total",
		"",
		"Cumulative inbound packages skipped because their trigger type was baseline_deviation (re-entrancy guard).",
		nil,
		func() int64 { return e.skippedSelf.Load() },
	); err != nil {
		return err
	}
	if err := reg.RegisterGauge(
		"olaitan_decision_baseline_warmup_active",
		"",
		"Count of workloads currently within an active warm-up window (FR18). Sampled from the Warmup controller cache; cardinality bounded by the workload set under the controller's reach.",
		nil,
		func() int64 { return e.warmupActiveCard.Load() },
	); err != nil {
		return err
	}
	h, err := reg.RegisterHistogram(
		"olaitan_decision_baseline_evaluation_seconds",
		"",
		"Per-package baseline-engine evaluation latency in seconds; histogram buckets are sized against NFR3 (p99 <= 100 ms).",
		nil,
		histogramBuckets,
	)
	if err != nil {
		return err
	}
	e.evalSeconds = h
	return nil
}

// applyReEntrancyGuard returns true and bumps skippedSelf if pkg is
// a baseline_deviation-triggered package the engine must not
// re-evaluate. Split out from handle() so unit tests can exercise
// the guard contract without standing up a JetStream consumer
// (mirrors Story 1.15 P8 closure).
func (e *Engine) applyReEntrancyGuard(pkg *schema.EvidencePackage) bool {
	if pkg.Trigger.Type == trigger.TypeBaselineDeviation {
		e.skippedSelf.Add(1)
		return true
	}
	return false
}

// Run subscribes to subjects.EvidencePackages and dispatches per
// metric. Returns nil on graceful shutdown, a wrapped error if
// stream/consumer setup fails. Run also spawns a warm-up gauge
// sampler goroutine that updates warmupActiveCard every 5 s.
func (e *Engine) Run(ctx context.Context) error {
	stream, err := e.nc.JetStream().Stream(ctx, "EVIDENCE")
	if err != nil {
		return fmt.Errorf("baseline: stream EVIDENCE: %w", err)
	}
	consumer, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       "olaitan-baseline-engine",
		AckPolicy:     jetstream.AckExplicitPolicy,
		FilterSubject: subjects.EvidencePackages,
		MaxDeliver:    consumerMaxDeliver,
	})
	if err != nil {
		return fmt.Errorf("baseline: consumer: %w", err)
	}

	go e.sampleWarmupGauge(ctx)

	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		msg, err := consumer.Next(jetstream.FetchMaxWait(250 * time.Millisecond))
		if err != nil {
			if isExpectedFetchTimeout(err) {
				continue
			}
			e.log.Warn("baseline: consumer fetch failed", "err", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(fetchBackoff):
			}
			continue
		}
		e.handle(ctx, msg)
	}
}

// sampleWarmupGauge runs on a 5 s tick refreshing the warmup_active
// gauge from the Warmup controller's cache. Cardinality is bounded
// by the MVP-scale workload count; the gauge value is the integer
// count of currently-active warm-up workloads.
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

// handle decodes the inbound message, applies the re-entrancy guard,
// performs restart detection, extracts metrics, updates Welford
// state, and emits deviations through cfg.Emitter. Permanent decode
// errors and per-metric emit errors are treated as drop-and-ack
// (mirrors Story 1.15 engine.go drop-and-ack discipline). Advisory
// routing to a future Story 1.18 DLQ surface is shared with the
// rules engine.
func (e *Engine) handle(ctx context.Context, msg jetstream.Msg) {
	start := time.Now()
	observed := false
	defer func() {
		if observed && e.evalSeconds != nil {
			e.evalSeconds.Observe(time.Since(start).Seconds())
		}
	}()

	var pkg schema.EvidencePackage
	if err := json.Unmarshal(msg.Data(), &pkg); err != nil {
		e.log.Warn("baseline: dropping malformed package", "err", err)
		e.evalError.Add(1)
		_ = msg.Ack()
		return
	}

	if e.applyReEntrancyGuard(&pkg) {
		_ = msg.Ack()
		return
	}
	observed = true

	namespace, pod := resolveWorkloadKey(&pkg)
	if namespace == "" || pod == "" {
		// No workload identity: nothing to baseline against. Treat as
		// normal so the per-package histogram still observes the no-op
		// path; ack and move on.
		e.log.Warn("baseline: package missing workload identity, skipping", "workload_id", pkg.WorkloadID)
		e.evalNormal.Add(1)
		_ = msg.Ack()
		return
	}

	// Restart detection: a CRI lifecycle event with attempt:N (N>0)
	// triggers warm-up + Welford reset BEFORE this evaluation folds
	// in the package's observations.
	if e.detectRestart(&pkg) {
		if err := e.warmup.Begin(ctx, namespace, pod); err != nil {
			e.log.Warn("baseline: warmup Begin failed", "namespace", namespace, "pod", pod, "err", err)
			e.evalError.Add(1)
			_ = msg.Ack()
			return
		}
		zero := make(map[string]*Welford, len(e.metricList))
		for _, n := range e.metricList {
			zero[n] = &Welford{}
		}
		if err := e.store.Save(ctx, namespace, pod, zero); err != nil {
			e.log.Warn("baseline: zero-store after restart failed", "namespace", namespace, "pod", pod, "err", err)
			e.evalError.Add(1)
			_ = msg.Ack()
			return
		}
		e.log.Info("baseline: workload restart detected; warm-up engaged", "namespace", namespace, "pod", pod)
	}

	baselines, err := e.store.Load(ctx, namespace, pod, e.metricList)
	if err != nil {
		e.log.Warn("baseline: store load failed", "namespace", namespace, "pod", pod, "err", err)
		e.evalError.Add(1)
		_ = msg.Ack()
		return
	}

	active, err := e.warmup.IsActive(ctx, namespace, pod)
	if err != nil {
		e.log.Warn("baseline: warmup IsActive failed", "namespace", namespace, "pod", pod, "err", err)
		e.evalError.Add(1)
		_ = msg.Ack()
		return
	}

	sigmaMul := e.SigmaMultiplier()
	deviations := []schema.BaselineDeviation{}
	emitFailed := false

	for _, name := range e.metricList {
		ex, ok := e.extractors[name]
		if !ok {
			continue
		}
		value, present := ex(&pkg)
		if !present {
			continue
		}
		w := baselines[name]
		// Capture pre-update stats so the sigma check is against the
		// historical baseline, not the post-update one.
		preCount := w.Count
		preMean := w.Mean
		preStd := w.StdDev()

		// AC3 explicit: observations during warm-up are recorded but no
		// anomaly results are emitted. Update Welford in both branches;
		// emit only when not active.
		w.Update(value)

		if active {
			continue
		}
		if preCount < 2 || preStd <= 0 {
			continue
		}
		sigma := (value - preMean) / preStd
		if sigma < sigmaMul {
			continue
		}
		deviations = append(deviations, schema.BaselineDeviation{
			Metric: name,
			Value:  value,
			Mean:   preMean,
			StdDev: preStd,
			Sigma:  sigma,
			PodUID: resolvePodUID(&pkg),
		})
	}

	if err := e.store.Save(ctx, namespace, pod, baselines); err != nil {
		e.log.Warn("baseline: store save failed", "namespace", namespace, "pod", pod, "err", err)
		e.evalError.Add(1)
		_ = msg.Ack()
		return
	}

	for _, dev := range deviations {
		fireCtx, cancel := context.WithTimeout(ctx, publishAttemptTimeout)
		if _, err := e.emit.FireBaselineDeviation(fireCtx, pkg.WorkloadID, dev); err != nil {
			emitFailed = true
			e.log.Warn("baseline: emit FireBaselineDeviation failed",
				"workload_id", pkg.WorkloadID, "metric", dev.Metric, "err", err)
		} else {
			if c, ok := e.deviationsTotal[dev.Metric]; ok {
				c.Add(1)
			}
		}
		cancel()
	}

	switch {
	case emitFailed:
		e.evalError.Add(1)
	case len(deviations) > 0:
		e.evalDeviation.Add(1)
	default:
		e.evalNormal.Add(1)
	}
	_ = msg.Ack()
}

// resolveWorkloadKey returns the (namespace, pod) pair used to
// address this workload's baseline hash in Redis. The architecture
// pins the key as baseline:<namespace>:<pod>:metrics; the
// WorkloadIdentity carries Namespace and OwnerName/OwnerKind, which
// we collapse to a single token via "<kind>-<name>" so a Deployment
// "web" and a StatefulSet "web" in the same namespace land in
// distinct hashes. Orphan pods carry the literal pod name and use it
// directly. When neither path resolves we fall back to the first
// event's PodRef so test fixtures that omit WorkloadIdentity still
// produce a stable key.
func resolveWorkloadKey(pkg *schema.EvidencePackage) (string, string) {
	id := pkg.WorkloadIdentity
	if id.Namespace != "" {
		if id.PodName != "" {
			return id.Namespace, id.PodName
		}
		if id.OwnerKind != "" && id.OwnerName != "" {
			return id.Namespace, id.OwnerKind + "-" + id.OwnerName
		}
	}
	for i := range pkg.Events {
		ref := pkg.Events[i].Pod
		if ref.Namespace != "" && ref.Name != "" {
			return ref.Namespace, ref.Name
		}
	}
	return "", ""
}

// resolvePodUID returns the first non-empty Pod.UID across events
// in pkg. BI-5 explicit: an empty result is acceptable; the
// downstream trigger constructor falls back to the package's
// PackageID hash for trigger.EventID.
func resolvePodUID(pkg *schema.EvidencePackage) string {
	for i := range pkg.Events {
		if uid := pkg.Events[i].Pod.UID; uid != "" {
			return uid
		}
	}
	return ""
}

// detectRestart returns true when any event in pkg is a CRI
// lifecycle event marking a non-zero attempt. The CRI adapter emits
// "attempt:N" tags per internal/collector/cri/translate.go:51-57.
func (e *Engine) detectRestart(pkg *schema.EvidencePackage) bool {
	for i := range pkg.Events {
		ev := &pkg.Events[i]
		if ev.Category != schema.CategoryLifecycle {
			continue
		}
		if hasRestartAttemptTag(ev.Tags) {
			return true
		}
	}
	return false
}

func isExpectedFetchTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, jetstream.ErrNoMessages) {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if strings.Contains(err.Error(), "nats: no messages") {
		return true
	}
	return false
}
