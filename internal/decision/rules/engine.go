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
	reloadSuccess  atomic.Int64
	reloadRejected atomic.Int64
	skippedSelf    atomic.Int64

	evalSeconds prometheus.Histogram
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
			"Cumulative rule evaluations grouped by outcome (FR50).",
			prometheus.Labels{"outcome": out},
			getter,
		); err != nil {
			return err
		}
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
// per-rule evaluation errors are treated as drop-and-ack: a bad
// package must not crash-loop the ring (mirrors the correlator's
// Story 1.14 P1 closure).
func (e *Engine) handle(ctx context.Context, msg jetstream.Msg) {
	start := time.Now()
	defer func() {
		if e.evalSeconds != nil {
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

	if pkg.Trigger.Type == trigger.TypeRuleMatch {
		e.skippedSelf.Add(1)
		_ = msg.Ack()
		return
	}

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

	e.evalMatch.Add(int64(len(matches)))
	for _, m := range matches {
		fireCtx, cancel := context.WithTimeout(ctx, publishAttemptTimeout)
		if _, err := e.emit.FireRuleMatch(fireCtx, pkg.WorkloadID, m); err != nil {
			e.evalError.Add(1)
			e.log.Warn("rules: emit FireRuleMatch failed",
				"workload_id", pkg.WorkloadID, "rule_id", m.RuleID, "err", err)
		}
		cancel()
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
		// map so rules that only reference k8s.* fields can still
		// fire. The triggering event ID falls back to the package
		// ID per the AC1 contract.
		matches, _ := e.evaluateOnce(pkg, schema.Event{ID: pkg.PackageID}, corpus.Rules)
		return matches
	}
	for _, ev := range events {
		matches, _ := e.evaluateOnce(pkg, ev, corpus.Rules)
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
				MitreTags: r.Attack,
				EventID:   chooseEventID(ev.ID, pkg.PackageID),
			})
		}
	}
	return out, nil
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
