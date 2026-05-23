// Package rules wires the OLT Sigma rule engine into the Ring-2
// trigger contract. The engine consumes `subjects.EvidencePackages`
// from the EVIDENCE JetStream, evaluates every consumed
// EvidencePackage against the loaded rule corpus, and emits one
// downstream rule_match-triggered EvidencePackage per match via the
// correlator's FireRuleMatch entry point.
//
// Package layout:
//
//	internal/decision/rules/
//	├── engine.go         ← this file: JetStream-consuming Engine
//	├── parser/           ← OLT-dialect rule parser (wraps sigmalite)
//	├── matcher/          ← FieldResolver (k8s.* posture + event halves)
//	└── loader/           ← rule directory loader + fsnotify watcher
//
// Emit contract: the engine NEVER publishes to
// subjects.EvidencePackages directly. Every match is folded back into
// the Ring-2 trigger contract through the RuleMatchEmitter interface,
// which the correlator's FireRuleMatch satisfies. Per-match fan-out
// is unconditional: if N rules match a single inbound package, the
// engine calls FireRuleMatch N times producing N downstream packages.
// Batching is intentionally not supported: the trigger contract
// carries a single RuleMatch per Trigger, and downstream consumers
// rely on that one-to-one shape.
//
// Re-entrancy guard: the engine inspects EvidencePackage.Trigger.Type
// and short-circuits packages whose trigger type equals
// trigger.TypeRuleMatch. Without this guard a rule that matches its
// own downstream package would create an infinite fold-back loop.
// The skipped_self counter surfaces the guard's activity so
// operators can spot rules that always self-fold.
package rules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/prometheus/client_golang/prometheus"
	sigma "github.com/runreveal/sigmalite"

	"github.com/olokotoh/olaitan/internal/correlator/trigger"
	"github.com/olokotoh/olaitan/internal/decision/rules/loader"
	"github.com/olokotoh/olaitan/internal/decision/rules/matcher"
	"github.com/olokotoh/olaitan/internal/decision/rules/parser"
	"github.com/olokotoh/olaitan/internal/decision/severitybucket"
	"github.com/olokotoh/olaitan/internal/metrics"
	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// consumerMaxDeliver caps JetStream's per-message redelivery for the
// rules-engine consumer. Mirrors the correlator's Story 1.14 P18
// closure so a poison package cannot loop forever; advisory routing
// to a future Story 1.18 DLQ surface is shared with the correlator
// path.
const consumerMaxDeliver = 5

// publishAttemptTimeout caps a single FireRuleMatch invocation. The
// emitter is allowed to do a JetStream PublishJS internally; 2 s
// matches the correlator's publishAttemptTimeout so the engine
// cannot accidentally block longer than the inbound consumer's
// AckWait window.
const publishAttemptTimeout = 2 * time.Second

// fetchBackoff is the bounded sleep between consumer.Next attempts
// after a non-timeout error. Mirrors the correlator. The engine
// honours context cancellation immediately rather than completing
// the backoff.
const fetchBackoff = time.Second

// histogramBuckets sizes the evaluation_seconds histogram against
// the NFR3 100 ms p99 gate. The buckets stop at 250 ms so a rule
// that blows past the budget still buckets visibly rather than
// landing in +Inf; everything above 100 ms is already a regression.
var histogramBuckets = []float64{0.001, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250}

// RuleMatchEmitter is the engine's only outbound dependency. The
// correlator's FireRuleMatch method satisfies it. Defining a local
// interface (rather than importing *correlator.Correlator) keeps
// the engine package one-way: the engine does NOT import correlator,
// so future cross-rule chaining can extend the trigger contract
// without inviting an import cycle.
type RuleMatchEmitter interface {
	FireRuleMatch(ctx context.Context, workloadID string, match schema.RuleMatch) (*schema.EvidencePackage, error)
}

// Config configures an Engine.
type Config struct {
	NATS    *natsclient.Client
	Loader  *loader.Loader
	Emitter RuleMatchEmitter
	Metrics *metrics.Registry
	Log     *slog.Logger
}

// Engine subscribes to subjects.EvidencePackages and evaluates every
// consumed package against the active rule corpus.
type Engine struct {
	nc     *natsclient.Client
	loader *loader.Loader
	emit   RuleMatchEmitter
	log    *slog.Logger

	loadedCount    atomic.Int64
	evalMatch      atomic.Int64
	evalMiss       atomic.Int64
	evalError      atomic.Int64
	matchesTotal   atomic.Int64
	reloadSuccess  atomic.Int64
	reloadRejected atomic.Int64
	skippedSelf    atomic.Int64

	evalSeconds prometheus.Histogram

	// Story 1.18 AC2: labelled per-match counter. CounterVec carrying
	// {rule_id, severity_bucket, attack_technique}. Registered under
	// the _by_attribute_total suffix to avoid a metric-name collision
	// with the existing unlabelled matchesTotal aggregate that the
	// Story 1.15 dashboards already scrape. Per BI-4, multi-MitreTag
	// rules emit one bump per (rule, severity, technique) triple.
	matchesVec *prometheus.CounterVec
}

// New constructs an Engine wired against the given dependencies.
// Returns an error if any required dependency is nil or if metric
// registration fails. The constructor does not subscribe to NATS;
// Run does.
func New(cfg Config) (*Engine, error) {
	if cfg.NATS == nil {
		return nil, errors.New("rules: nats client is nil")
	}
	if cfg.Loader == nil {
		return nil, errors.New("rules: loader is nil")
	}
	if cfg.Emitter == nil {
		return nil, errors.New("rules: emitter is nil")
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	e := &Engine{
		nc:     cfg.NATS,
		loader: cfg.Loader,
		emit:   cfg.Emitter,
		log:    cfg.Log.With("component", "rules-engine"),
	}
	if cfg.Metrics != nil {
		if err := e.registerMetrics(cfg.Metrics); err != nil {
			return nil, fmt.Errorf("rules: register metrics: %w", err)
		}
	}
	e.refreshLoadedGauge()

	// Hot-reload bookkeeping: every successful reload updates the
	// loaded-gauge sample and bumps the reload counter. The
	// rejected counter is bumped from the loader's log path; we
	// surface it here for the metrics-registry indirection.
	cfg.Loader.Subscribe(func(c *loader.Corpus) {
		e.refreshLoadedGauge()
		e.reloadSuccess.Add(1)
	})
	return e, nil
}

func (e *Engine) registerMetrics(reg *metrics.Registry) error {
	if err := reg.RegisterGauge(
		"olaitan_decision_rules_loaded",
		"",
		"Current count of OLT Sigma rules in the active corpus; refreshed on every hot-reload (FR15).",
		nil,
		func() int64 { return e.loadedCount.Load() },
	); err != nil {
		return err
	}
	for _, outcome := range []string{"match", "miss", "error"} {
		out := outcome
		getter := func() int64 {
			switch out {
			case "match":
				return e.evalMatch.Load()
			case "miss":
				return e.evalMiss.Load()
			case "error":
				return e.evalError.Load()
			}
			return 0
		}
		if err := reg.RegisterCounter(
			"olaitan_decision_rules_evaluations_total",
			"",
			"Per-package rule-evaluation outcome counter (FR50). One outcome per handled package: match (>=1 rule fired and every fan-out emit succeeded), miss (no rules fired), or error (package decode failed or any per-match emit failed). For per-match cardinality see olaitan_decision_rules_matches_total.",
			prometheus.Labels{"outcome": out},
			getter,
		); err != nil {
			return err
		}
	}
	if err := reg.RegisterCounter(
		"olaitan_decision_rules_matches_total",
		"",
		"Cumulative rule matches emitted by the engine; increments by the number of matches per handled package (per-match cardinality, complementing the per-package evaluations_total{outcome=match}).",
		nil,
		func() int64 { return e.matchesTotal.Load() },
	); err != nil {
		return err
	}
	for _, outcome := range []string{"success", "rejected"} {
		out := outcome
		getter := func() int64 {
			if out == "success" {
				return e.reloadSuccess.Load()
			}
			return e.reloadRejected.Load()
		}
		if err := reg.RegisterCounter(
			"olaitan_decision_rules_reloads_total",
			"",
			"Cumulative rule-corpus reload attempts grouped by outcome (FR49).",
			prometheus.Labels{"outcome": out},
			getter,
		); err != nil {
			return err
		}
	}
	if err := reg.RegisterCounter(
		"olaitan_decision_rules_skipped_self_total",
		"",
		"Cumulative inbound packages skipped because their trigger type was rule_match (re-entrancy guard).",
		nil,
		func() int64 { return e.skippedSelf.Load() },
	); err != nil {
		return err
	}
	h, err := reg.RegisterHistogram(
		"olaitan_decision_rules_evaluation_seconds",
		"",
		"Per-package rule-engine evaluation latency in seconds; histogram buckets are sized against NFR3 (p99 <= 100 ms).",
		nil,
		histogramBuckets,
	)
	if err != nil {
		return err
	}
	e.evalSeconds = h

	// Story 1.18 AC2: labelled per-match counter alongside the
	// unlabelled matchesTotal aggregate. The {rule_id,
	// severity_bucket, attack_technique} cartesian is bounded by
	// corpus_size x 4 x ~30 ATT&CK techniques; real usage stays at
	// ~corpus_size series because each rule typically tags one
	// primary technique. Per BI-4, multi-tag rules emit one bump per
	// (rule, severity, technique) triple; empty MitreTags emits one
	// bump with attack_technique="unknown" (the sentinel value).
	mv, err := reg.RegisterCounterVec(
		"olaitan_decision_rules_matches_by_attribute_total",
		"Per-(rule_id, severity_bucket, attack_technique) rule-match counter (AC2 of Story 1.18). Complements the unlabelled olaitan_decision_rules_matches_total: sum without (rule_id, severity_bucket, attack_technique)(rate(matches_by_attribute_total[5m])) reproduces the aggregate. A rule carrying N MitreTags increments this counter N times (one per technique); a rule with empty MitreTags emits one bump with attack_technique=\"unknown\".",
		[]string{"rule_id", "severity_bucket", "attack_technique"},
	)
	if err != nil {
		return err
	}
	e.matchesVec = mv
	return nil
}

// refreshLoadedGauge updates the loaded-gauge sample atomically from
// the loader's current corpus pointer. Cheap; called on every
// reload and from New.
func (e *Engine) refreshLoadedGauge() {
	if e.loader == nil {
		return
	}
	c := e.loader.Get()
	e.loadedCount.Store(int64(c.Len()))
}

// NoteReloadRejected is the loader-side hook that increments the
// rejected counter. The loader cannot import the engine, so the
// engine exposes this entry point and the wiring in
// startAggregatorRing connects them.
func (e *Engine) NoteReloadRejected() { e.reloadRejected.Add(1) }

// applyReEntrancyGuard returns true and bumps skippedSelf if pkg is
// a rule_match-triggered package that the engine must not
// re-evaluate. Split out from handle() so unit tests can exercise
// the guard contract without mocking jetstream.Msg (code-review P8).
func (e *Engine) applyReEntrancyGuard(pkg *schema.EvidencePackage) bool {
	if pkg.Trigger.Type == trigger.TypeRuleMatch {
		e.skippedSelf.Add(1)
		return true
	}
	return false
}

// Run subscribes to subjects.EvidencePackages and dispatches matches
// until ctx is cancelled. Returns nil on graceful shutdown, a
// wrapped error if stream/consumer setup fails.
func (e *Engine) Run(ctx context.Context) error {
	stream, err := e.nc.JetStream().Stream(ctx, "EVIDENCE")
	if err != nil {
		return fmt.Errorf("rules: stream EVIDENCE: %w", err)
	}
	consumer, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       "olaitan-rules-engine",
		AckPolicy:     jetstream.AckExplicitPolicy,
		FilterSubject: subjects.EvidencePackages,
		MaxDeliver:    consumerMaxDeliver,
	})
	if err != nil {
		return fmt.Errorf("rules: consumer: %w", err)
	}

	for {
		if err := ctx.Err(); err != nil {
			return e.drainAndStop(consumer)
		}
		msg, err := consumer.Next(jetstream.FetchMaxWait(250 * time.Millisecond))
		if err != nil {
			if isExpectedFetchTimeout(err) {
				continue
			}
			e.log.Warn("rules: consumer fetch failed", "err", err)
			select {
			case <-ctx.Done():
				return e.drainAndStop(consumer)
			case <-time.After(fetchBackoff):
			}
			continue
		}
		e.handle(ctx, msg)
	}
}

// drainAndStop returns nil so ctx-cancel is not surfaced as an
// error to the errgroup. handle() runs synchronously inside Run, so
// no in-flight goroutine work needs to drain; the caller's outer
// terminationGracePeriodSeconds covers the inbound consumer's
// AckWait window.
func (e *Engine) drainAndStop(_ jetstream.Consumer) error { return nil }

// handle decodes the inbound message, applies the re-entrancy guard,
// runs every rule against the package, fans out per-match
// FireRuleMatch calls, and acks. Permanent decoding errors and
// per-match emit errors are treated as drop-and-ack: a bad package
// must not crash-loop the ring, and a transient publish failure does
// not warrant blocking the consumer (mirrors the correlator's Story
// 1.14 P1 closure and the correlator's publishTrigger drop-and-ack
// at correlator.go:261-262). Advisory routing to a future Story 1.18
// DLQ surface is shared with the correlator path; until that lands,
// emit failures are observable via the warn log and the per-package
// evaluations_total{outcome=error} counter.
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
		e.log.Warn("rules: dropping malformed package", "err", err)
		e.evalError.Add(1)
		_ = msg.Ack()
		return
	}

	if e.applyReEntrancyGuard(&pkg) {
		// Re-entrancy guard: do NOT observe the evaluation histogram
		// for self-skipped packages so the latency distribution stays
		// honest (code-review P16).
		_ = msg.Ack()
		return
	}

	// Everything past the re-entrancy guard counts as an evaluation;
	// observe latency on the way out.
	observed = true

	corpus := e.loader.Get()
	if corpus == nil || corpus.Len() == 0 {
		// No rules loaded: treat as a no-op miss. Ack so JetStream
		// does not redeliver; the package will be evaluated again if
		// rules land and another trigger fires for the workload.
		e.evalMiss.Add(1)
		_ = msg.Ack()
		return
	}

	matches := e.evaluatePackage(&pkg, corpus)
	if len(matches) == 0 {
		e.evalMiss.Add(1)
		_ = msg.Ack()
		return
	}

	// Per-package outcome accounting (code-review P3). evalMatch
	// counts once per package with matches, regardless of how many
	// matches fired; matchesTotal carries per-match cardinality. If
	// any FireRuleMatch emit fails, the package outcome is downgraded
	// from match to error.
	e.matchesTotal.Add(int64(len(matches)))
	emitFailed := false
	for _, m := range matches {
		fireCtx, cancel := context.WithTimeout(ctx, publishAttemptTimeout)
		if _, err := e.emit.FireRuleMatch(fireCtx, pkg.WorkloadID, m); err != nil {
			emitFailed = true
			e.log.Warn("rules: emit FireRuleMatch failed",
				"workload_id", pkg.WorkloadID, "rule_id", m.RuleID, "err", err)
		} else {
			// Story 1.18 AC2: per-(rule, severity, technique) bump.
			// Done only on emit success so the labelled counter stays
			// consistent with the per-package outcome (a partial-emit
			// package is downgraded to error and the matchesVec is not
			// double-charged for the successful half). Per BI-4,
			// multi-MitreTag rules fan out across techniques.
			e.bumpMatchesVec(m)
		}
		cancel()
	}
	if emitFailed {
		e.evalError.Add(1)
	} else {
		e.evalMatch.Add(1)
	}
	_ = msg.Ack()
}

// evaluatePackage runs every rule against every event in the
// package. For each (rule, event) pair that matches, a RuleMatch is
// appended to the result. A package with N events and M rules costs
// O(NM) evaluations; per ADR-2026-04-28-01 the per-call cost is in
// the low microseconds so this loop sits comfortably under the
// NFR3 100 ms p99 gate for normal-shape packages.
//
// Package-level matches: if a rule references only k8s.* fields
// (i.e., it does not need any per-event data) the loop still
// evaluates once per event, but the resolver routes every reference
// to the posture map so the result is event-independent. A rule
// that triggers on package-level metadata alone will produce
// len(pkg.Events) matches; the spike noted this as future-work to
// suppress; for Story 1.15 the simple loop is the AC3-bounded path.
func (e *Engine) evaluatePackage(pkg *schema.EvidencePackage, corpus *loader.Corpus) []schema.RuleMatch {
	var out []schema.RuleMatch
	events := pkg.Events
	if len(events) == 0 {
		// No streaming events: evaluate once against an empty event
		// so rules that only reference k8s.* fields can still fire.
		// We leave event.id unset on the synthetic event (code-review
		// D4) so a rule referencing event.id resolves to nil and
		// fails-open as a miss; RuleMatch.EventID still falls back to
		// pkg.PackageID via chooseEventID, preserving the AC1
		// "package ID when matched on package-level metadata"
		// contract.
		matches, err := e.evaluateOnce(pkg, schema.Event{}, corpus.Rules)
		if err != nil {
			e.log.Warn("rules: evaluate empty-event package failed",
				"workload_id", pkg.WorkloadID, "package_id", pkg.PackageID, "err", err)
			e.evalError.Add(1)
			return nil
		}
		return matches
	}
	for _, ev := range events {
		matches, err := e.evaluateOnce(pkg, ev, corpus.Rules)
		if err != nil {
			// Per-event resolver-construction failure (e.g.
			// case-collision on event keys): log and skip this
			// event, but continue evaluating the rest of the
			// package so a single malformed event does not silence
			// every match (code-review P2).
			e.log.Warn("rules: evaluate event failed",
				"workload_id", pkg.WorkloadID, "event_id", ev.ID, "err", err)
			e.evalError.Add(1)
			continue
		}
		out = append(out, matches...)
	}
	return out
}

// evaluateOnce runs every rule against a single event. The resolver
// is constructed per-event (posture is fixed for the package, event
// fields are per-event), the MatchOptions struct is allocated once
// per call (it's a thin wrapper around the resolver), and each
// rule's Detection.Matches is invoked. Per ADR-2026-04-28-01 the
// hoisting target is the timed-bench loop body, not this function.
func (e *Engine) evaluateOnce(pkg *schema.EvidencePackage, ev schema.Event, rules []*parser.Rule) ([]schema.RuleMatch, error) {
	resolver, entry, err := matcher.NewResolver(pkg.WorkloadPosture, matcher.EventFields(ev))
	if err != nil {
		return nil, err
	}
	opts := &sigma.MatchOptions{FieldResolver: resolver}

	var out []schema.RuleMatch
	for _, r := range rules {
		if r.Detection == nil {
			continue
		}
		if r.Detection.Matches(entry, opts) {
			out = append(out, schema.RuleMatch{
				RuleID:    r.ID,
				RuleName:  r.Title,
				Severity:  r.SeverityString(),
				MitreTags: slices.Clone(r.Attack),
				EventID:   chooseEventID(ev.ID, pkg.PackageID),
			})
		}
	}
	return out, nil
}

// bumpMatchesVec records one counter increment per
// (rule_id, severity_bucket, attack_technique) triple for a single
// RuleMatch. Empty MitreTags emits one bump with the "unknown"
// sentinel so a rule that fires without an ATT&CK tag is still
// observable. matchesVec is nil-guarded for callers (or tests) that
// constructed the engine without a metrics registry.
//
// severity_bucket derivation: schema.RuleMatch.Severity is the
// rule's 0-100 integer score rendered as a decimal string by
// parser.Rule.SeverityString. Parse back to int and call
// severitybucket.Bucket; a parse error falls back to "low" via
// Bucket(0) (defensive; SeverityString only renders parseable
// decimals).
func (e *Engine) bumpMatchesVec(m schema.RuleMatch) {
	if e.matchesVec == nil {
		return
	}
	score, _ := strconv.Atoi(m.Severity)
	bucket := severitybucket.Bucket(score)
	if len(m.MitreTags) == 0 {
		e.matchesVec.WithLabelValues(m.RuleID, bucket, "unknown").Inc()
		return
	}
	for _, tech := range m.MitreTags {
		e.matchesVec.WithLabelValues(m.RuleID, bucket, tech).Inc()
	}
}

func chooseEventID(eventID, packageID string) string {
	if eventID != "" {
		return eventID
	}
	return packageID
}

// isExpectedFetchTimeout mirrors the correlator's helper. The
// jetstream client sometimes wraps the per-fetch timeout as a bare
// error string rather than a sentinel.
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
