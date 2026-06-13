// Package score implements the Story 2.1 deterministic ThreatScore
// calculator (FR30).
//
// The calculator collapses an EvidencePackage's rule-match and
// baseline-deviation annotations into a single [0, 100] ConfidenceScore
// using the formula
//
//	total = RuleWeight * max(rule_severity) + BaselineWeight * normalised(max_sigma) + LLMWeight * llm_capped_confidence
//
// where llm_capped_confidence is hard-coded to 0 in Epic 2 and replaced
// by the actual LLM contribution in Epic 3 (epics.md:1589). Defaults
// pin the weights to 0.4 / 0.3 / 0.3 with an LLM cap of 35 (Claude Opus
// per prd.md:294) so the algebraic trust-bound holds:
//
//	max(LLM-only) = LLMWeight * LLMCap = 0.3 * 35 = 10.5 < 20 (SUSPICIOUS)
//
// The property test TestProperty_NoLLMOnlyEscalation makes that bound
// machine-checkable; the FR55 empirical adversarial-LLM experiment in
// Epic 5 is the empirical counterpart.
//
// Dependency-ring direction (architecture.md:425): score may import
// schema, config, and metrics. Nothing else. The FSM and
// NetworkPolicy manager (Ring 4) import score; score does not import
// them.
//
// Package path resolution: epics.md:1008 AC6 phrasing
// internal/response/score/ is loose -- architecture.md:439 names the
// canonical path as internal/decision/score/ (the score is consumed by
// the FSM at internal/response/fsm/ but produced upstream in the
// decision ring). The naming-rule line architecture.md:439 is
// authoritative here. The Story 2.2 FSM and the calculator never
// collide.
package score

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/olokotoh/olaitan/internal/config"
	"github.com/olokotoh/olaitan/internal/decision/severitybucket"
	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/schema"
)

// Default weights and LLM cap mirror FR30 (prd.md:504) and the
// trust-bound passage at prd.md:294. SigmaNormaliser default mirrors
// detection.baselines.sigma_multiplier (config.go DefaultBaselines).
const (
	DefaultRuleWeight      = 0.4
	DefaultBaselineWeight  = 0.3
	DefaultLLMWeight       = 0.3
	DefaultLLMCap          = 35.0
	DefaultSigmaNormaliser = 3.0
)

// Config is the resolved snapshot the calculator reads on each
// invocation. The snapshot is rebuilt from *config.Manager.Get() per
// call; Score is referentially transparent for a fixed snapshot.
type Config struct {
	RuleWeight      float64
	BaselineWeight  float64
	LLMWeight       float64
	LLMCap          float64
	SigmaNormaliser float64
}

// DefaultConfig returns the FR30 production defaults. Used as the
// fall-through when a *config.Config arrives with a zero-valued Score
// block (test fixtures that omit the detection.score block, or a
// Manager whose Get() returns nil during teardown).
func DefaultConfig() Config {
	return Config{
		RuleWeight:      DefaultRuleWeight,
		BaselineWeight:  DefaultBaselineWeight,
		LLMWeight:       DefaultLLMWeight,
		LLMCap:          DefaultLLMCap,
		SigmaNormaliser: DefaultSigmaNormaliser,
	}
}

// Calculator is the stateless ThreatScore calculator. The hot-reload
// contract (AC2) is satisfied by reading config.Manager.Get() on every
// Score() invocation; Manager.Get is a lock-free atomic-pointer load
// (watcher.go:59) so the per-call cost is negligible against the NFR3
// 100 ms p99 budget.
//
// Why Get() and not Subscribe(): the calculator holds no derived
// per-config state -- every snapshot read produces the right answer.
// Story 1.13's rate-limit limiter is the Subscribe precedent for
// stateful consumers; Story 2.2's FSM will follow Story 1.13 because
// the FSM holds thresholds in its own state. Story 2.1 uses Get
// because there is nothing to recompute on reload. Pick the right
// tool.
type Calculator struct {
	snapshot func() *config.Config
	metrics  *calcMetrics
}

// calcMetrics owns the writeable instruments. evalCount is an atomic
// counter the metrics package binds via NewCounterFunc; the histogram
// handles are owned directly per the RegisterHistogram /
// RegisterHistogramVec ownership contract.
type calcMetrics struct {
	evalCount       atomic.Int64
	anomalyCount    atomic.Int64
	scoreHist       *prometheus.HistogramVec
	evalSecondsHist prometheus.Histogram
}

// New constructs a Calculator bound to the supplied config manager and
// metrics registry. A nil mgr is permitted and degrades the calculator
// to the FR30 defaults (rule_weight=0.4, baseline_weight=0.3,
// llm_weight=0.3, llm_cap=35); this is the test-only fall-through used
// by main_test.go to construct startAggregatorRing without writing a
// real ConfigMap to disk. Production wiring in cmd/olaitan/main.go
// always passes a real Manager so the AC2 hot-reload contract is
// exercised end-to-end (the integration property test
// TestProperty_HotReloadViaSubscribe pins the full fsnotify path).
func New(mgr *config.Manager, registry *metrics.Registry) (*Calculator, error) {
	var get func() *config.Config
	if mgr == nil {
		get = func() *config.Config { return nil }
	} else {
		get = mgr.Get
	}
	return newWithGetter(get, registry)
}

// newWithGetter is the test-friendly constructor: it accepts an
// arbitrary snapshot getter so unit tests can swap the active
// *config.Config without going through the file watcher. Production
// callers go through New; the integration property test in
// score_property_test.go exercises the full fsnotify path.
func newWithGetter(get func() *config.Config, registry *metrics.Registry) (*Calculator, error) {
	if get == nil {
		return nil, errors.New("score: nil snapshot getter")
	}
	c := &Calculator{snapshot: get, metrics: &calcMetrics{}}
	if registry != nil {
		if err := c.registerMetrics(registry); err != nil {
			return nil, fmt.Errorf("score: register metrics: %w", err)
		}
	}
	return c, nil
}

func (c *Calculator) registerMetrics(r *metrics.Registry) error {
	if err := r.RegisterCounter(
		"olaitan_decision_score_evaluations_total",
		"",
		"Cumulative number of ThreatScore evaluations performed by the deterministic calculator (FR30).",
		nil,
		func() int64 { return c.metrics.evalCount.Load() },
	); err != nil {
		return err
	}

	if err := r.RegisterCounter(
		"olaitan_decision_score_anomalies_total",
		"",
		"Cumulative number of malformed baseline deviations (NaN/Inf/negative sigma) skipped during scoring. A non-zero rate means a source is emitting structurally invalid sigma; the affected deviation is dropped and scoring continues on the remaining signals (Story 2.1 code review, PR #29).",
		nil,
		func() int64 { return c.metrics.anomalyCount.Load() },
	); err != nil {
		return err
	}

	hv, err := r.RegisterHistogramVec(
		"olaitan_decision_score_total",
		"Observation of each ThreatScore component contribution (rules, baseline, llm) labelled by the package's result_bucket (FR30).",
		[]string{"component_contribution", "result_bucket"},
		[]float64{0, 25, 50, 75, 100},
	)
	if err != nil {
		return err
	}
	c.metrics.scoreHist = hv

	h, err := r.RegisterHistogram(
		"olaitan_decision_score_evaluation_seconds",
		"",
		"Wall-clock latency of the deterministic ThreatScore evaluation (NFR3 100 ms p99 budget).",
		nil,
		prometheus.ExponentialBucketsRange(1e-6, 100e-3, 10),
	)
	if err != nil {
		return err
	}
	c.metrics.evalSecondsHist = h
	return nil
}

// Snapshot returns the current resolved Config the calculator would
// read on its next Score() call. Exposed for the aggregator startup
// log line and for tests that pin the resolved weights.
func (c *Calculator) Snapshot() Config {
	return c.resolve()
}

func (c *Calculator) resolve() Config {
	cfg := DefaultConfig()
	cur := c.snapshot()
	if cur == nil {
		return cfg
	}
	s := cur.Detection.Score
	if s.RuleWeight != nil {
		cfg.RuleWeight = *s.RuleWeight
	}
	if s.BaselineWeight != nil {
		cfg.BaselineWeight = *s.BaselineWeight
	}
	if s.LLMWeight != nil {
		cfg.LLMWeight = *s.LLMWeight
	}
	if s.LLMCap != nil {
		cfg.LLMCap = float64(*s.LLMCap)
	}
	if cur.Detection.Baselines.SigmaMultiplier != nil && *cur.Detection.Baselines.SigmaMultiplier > 0 {
		cfg.SigmaNormaliser = *cur.Detection.Baselines.SigmaMultiplier
	}
	return cfg
}

// Score computes the deterministic ThreatScore for pkg using the
// active config snapshot.
//
// Algorithm (pinned by property tests for determinism):
//
//  1. nil pkg -> zero ConfidenceScore, no error (FSM treats a missing
//     package as a no-op observation).
//  2. ruleContribution: max severity across pkg.RuleMatches; per-match
//     severity parsed via strconv.Atoi (the producer is
//     parser.SeverityString() which always renders strconv.Itoa).
//     Out-of-range integers are clamped to [0, 100]; parse failures
//     fall through to 0. The calculator deliberately does NOT use
//     severitybucket.Score for parsing; that helper accepts keyword
//     labels (high/medium/low) and would let the Epic 3 LLM tier
//     drift the contract by emitting keywords. Test
//     TestScore_SeverityParseFallback locks this.
//  3. baselineContribution: max sigma across pkg.BaselineDeviations,
//     normalised against cfg.SigmaNormaliser and capped at 1.0, then
//     scaled to the [0, 100] contribution space. A NaN/Inf/negative
//     sigma is structurally invalid; the deviation is skipped (counted
//     on olaitan_decision_score_anomalies_total) and scoring continues
//     on the remaining signals.
//  4. llmContribution: 0 in Story 2.1. Epic 3 follow-up at
//     epics.md:1589 replaces this with llm_capped_confidence. There
//     is no `if cfg.LLMEnabled` branch -- a dead branch would mask
//     Epic 3 wiring failures.
//  5. total = clamp(RuleWeight*rule + BaselineWeight*baseline + LLMWeight*0, 0, 100).
//
// Ordering invariant: the returned ConfidenceScore.Total is
// referentially identical between two invocations on the same package
// with the same config snapshot. The algorithm walks slices in their
// order of appearance and tracks running maxima; no time.Now(), no
// map iteration, no goroutine scheduling.
//
// Error contract: Score never returns a non-nil error in Epic 2 -- a nil
// package is a no-op and malformed baseline deviations are skipped (see
// step 3). The (ConfidenceScore, error) signature is retained for the
// Epic 3 LLM tier, which may surface provider errors. Operator-
// misconfigured weights are rejected upstream by ScoreConfig.validate().
// Score collapses pkg's deterministic annotations plus the investigation
// chain's llmCappedConfidence into a single [0,100] ConfidenceScore (FR30).
// llmCappedConfidence is the per-provider-capped LLM confidence from the
// Story 3.7 chain (0 when the chain did not run, was not triggered, or was
// unavailable). It is clamped here to [0, LLMCap] so the Trust-Bounded
// algebraic bound (LLMWeight * LLMCap = 0.3 * 35 = 10.5 < SUSPICIOUS) is
// enforced in the same FSM-feeding code path Epic 2 validates -- a third
// defence layer below analyst.GuardCappedConfidence and the config validator.
func (c *Calculator) Score(pkg *schema.EvidencePackage, llmCappedConfidence int) (schema.ConfidenceScore, error) {
	start := time.Now()
	defer func() {
		if c.metrics != nil && c.metrics.evalSecondsHist != nil {
			c.metrics.evalSecondsHist.Observe(time.Since(start).Seconds())
		}
	}()

	if c.metrics != nil {
		c.metrics.evalCount.Add(1)
	}

	if pkg == nil {
		return schema.ConfidenceScore{}, nil
	}

	cfg := c.resolve()

	maxSeverity := 0
	for _, rm := range pkg.RuleMatches {
		s, err := strconv.Atoi(rm.Severity)
		if err != nil {
			continue
		}
		if s < 0 {
			s = 0
		}
		if s > 100 {
			s = 100
		}
		if s > maxSeverity {
			maxSeverity = s
		}
	}

	maxSigma := 0.0
	for _, bd := range pkg.BaselineDeviations {
		// A NaN/Inf/negative sigma is structurally invalid (the baseline
		// engine never emits one; the schema permits it at the type
		// level). Skip the malformed deviation and keep scoring the
		// remaining signals rather than aborting the whole package.
		// Aborting to a zero score would be fail-open for a detection
		// system: a single poisoned sigma would suppress an otherwise
		// escalating rule match, an evasion vector. The skip mirrors the
		// severity-parse fallback above and is surfaced via the anomaly
		// counter so malformed input stays visible (Story 2.1 code
		// review, PR #29).
		if math.IsNaN(bd.Sigma) || math.IsInf(bd.Sigma, 0) || bd.Sigma < 0 {
			if c.metrics != nil {
				c.metrics.anomalyCount.Add(1)
			}
			continue
		}
		if bd.Sigma > maxSigma {
			maxSigma = bd.Sigma
		}
	}

	normalised := 0.0
	if cfg.SigmaNormaliser > 0 {
		normalised = math.Min(maxSigma/cfg.SigmaNormaliser, 1.0) * 100.0
	}

	// Clamp the LLM contribution to [0, LLMCap] before folding (Story 3.11
	// BI-2): the per-provider cap is already applied upstream by
	// analyst.GuardCappedConfidence, but clamping here makes the trust-bound
	// (LLMWeight * LLMCap = 10.5) hold for ANY caller, enforced by the same
	// code path Epic 2's TestProperty_NoLLMOnlyEscalation validates.
	cappedLLM := llmCappedConfidence
	if cappedLLM < 0 {
		cappedLLM = 0
	}
	if capLimit := int(cfg.LLMCap); capLimit > 0 && cappedLLM > capLimit {
		cappedLLM = capLimit
	}
	rules := cfg.RuleWeight * float64(maxSeverity)
	baseline := cfg.BaselineWeight * normalised
	llm := cfg.LLMWeight * float64(cappedLLM)
	total := rules + baseline + llm
	if total < 0 {
		total = 0
	}
	if total > 100 {
		total = 100
	}

	result := schema.ConfidenceScore{
		Total:    total,
		Rules:    rules,
		Baseline: baseline,
		LLM:      llm,
		LLMCap:   cfg.LLMCap,
	}

	if c.metrics != nil && c.metrics.scoreHist != nil {
		bucket := severitybucket.Bucket(int(total))
		c.metrics.scoreHist.WithLabelValues("rules", bucket).Observe(rules)
		c.metrics.scoreHist.WithLabelValues("baseline", bucket).Observe(baseline)
		c.metrics.scoreHist.WithLabelValues("llm", bucket).Observe(llm)
	}

	return result, nil
}
