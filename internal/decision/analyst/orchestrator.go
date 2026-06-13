package analyst

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/schema"
)

// CapViolationMetricName is the AC3-named safety-guard counter family:
// one increment per refused attempt to carry an llm_capped_confidence
// above the per-provider score cap (Story 3.7 BI-6).
const CapViolationMetricName = "olaitan_decision_llm_cap_violation_total"

const capViolationMetricHelp = "Refused attempts to write an llm_capped_confidence above the Senior " +
	"provider's score cap (the Trust-Bounded LLM Integration code guard, " +
	"Story 3.7 AC3). Zero in healthy operation: the orchestrator caps by " +
	"construction, so any increment means a code path bypassed the cap " +
	"arithmetic. Story 3.11's FSM-feeding path MUST route through " +
	"analyst.GuardCappedConfidence."

// ErrCapViolation marks a refused assessment whose llm_capped_confidence
// exceeds the per-provider score cap (Story 3.7 AC3).
var ErrCapViolation = errors.New("analyst: llm_capped_confidence exceeds the per-provider score cap")

// L2SkipReasonL1SchemaViolation is the bounded reason label recorded
// when the chain skips L2 because L1's single pre-3.10 attempt returned
// a schema violation: there is no valid hypothesis to verify (Story 3.7
// BI-7; Story 3.10's three-strike policy re-routes this class).
const L2SkipReasonL1SchemaViolation = "l1_schema_violation"

// RegisterCapViolationMetric registers (or re-uses) the cap-violation
// counter on reg, idempotently like the other decision-ring families.
func RegisterCapViolationMetric(reg *metrics.Registry) (*prometheus.CounterVec, error) {
	return registerCounterVec(reg, CapViolationMetricName, capViolationMetricHelp, nil)
}

// CapConfidence is the AC2 arithmetic: min(raw, cap), floored at 0. The
// floor is defence-in-depth: shipped providers floor their ScoreCap() to
// a positive default, but the Provider.ScoreCap() contract makes no such
// promise, so a negative cap is clamped to 0 here rather than silently
// producing a negative capped confidence that GuardCappedConfidence's
// `>` check would wave through (Story 3.7 round-1 review).
func CapConfidence(raw, scoreCap int) int {
	if scoreCap < 0 {
		scoreCap = 0
	}
	if raw < 0 {
		return 0
	}
	if raw > scoreCap {
		return scoreCap
	}
	return raw
}

// GuardCappedConfidence is the exported AC3 chokepoint every path that
// hands an assessment toward the FSM must call (the Story 3.11 score
// fold included): if the assessment carries llm_capped_confidence above
// cap, the guard increments olaitan_decision_llm_cap_violation_total
// and refuses with ErrCapViolation. The orchestrator calls it as the
// final gate before returning an assessment; on the normal path it
// passes by construction.
func GuardCappedConfidence(a *schema.ThreatAssessment, scoreCap int, vec *prometheus.CounterVec) error {
	if a == nil {
		return errors.New("analyst: nil assessment")
	}
	if a.LLMCappedConfidence > scoreCap {
		if vec != nil {
			vec.WithLabelValues().Inc()
		}
		return fmt.Errorf("%w: capped=%d cap=%d", ErrCapViolation, a.LLMCappedConfidence, scoreCap)
	}
	return nil
}

// ChainResult is the full audit trail of one investigation chain run
// (consumed by the Story 3.14 publisher and the Story 3.9
// checkpointer). Stage pointers are nil where a stage did not run.
type ChainResult struct {
	L1         *L1Result
	L2         *L2Result
	L2Skipped  bool
	SkipReason string
	Senior     SeniorResult
	Assessment schema.ThreatAssessment
}

// Chain sequences L1 -> (gate) -> L2 -> Senior over one EvidencePackage
// (Story 3.7 BI-7). Triggering and per-role provider routing are Story
// 3.8; retries and fallback are Story 3.10.
type Chain struct {
	l1            *L1
	l2            *L2
	senior        *Senior
	skips         *prometheus.CounterVec
	capViolations *prometheus.CounterVec
	log           *slog.Logger
}

// NewChain builds the chain orchestrator from the three role runners.
func NewChain(l1 *L1, l2 *L2, senior *Senior, reg *metrics.Registry, log *slog.Logger) (*Chain, error) {
	if l1 == nil || l2 == nil || senior == nil {
		return nil, errors.New("analyst: nil runner")
	}
	if log == nil {
		log = slog.Default()
	}
	skips, err := RegisterL2SkippedMetric(reg)
	if err != nil {
		return nil, err
	}
	capViolations, err := RegisterCapViolationMetric(reg)
	if err != nil {
		return nil, err
	}
	return &Chain{l1: l1, l2: l2, senior: senior, skips: skips, capViolations: capViolations, log: log}, nil
}

// Run executes the full investigation chain for pkg. Degradation
// semantics (BI-7): an unavailable L1 skips L2 (reason l1_unavailable)
// into Senior-on-evidence-only mode; an L1 schema violation (the single
// pre-3.10 attempt IS the L1 outcome) skips L2 under
// l1_schema_violation, also evidence-only; ErrNoCitableEvents aborts
// the chain (nothing to assess); an L2 failure of any kind runs the
// Senior hypothesis-only (L2 was attempted, not skipped); a Senior
// failure aborts the chain (Story 3.10 owns retries and fallback).
func (c *Chain) Run(ctx context.Context, pkg schema.EvidencePackage) (ChainResult, error) {
	var result ChainResult

	l1res, l1err := c.l1.Run(ctx, pkg)
	result.L1 = &l1res

	var hyp *schema.L1Hypothesis
	var ver *schema.L2Verification

	if l1err != nil {
		if errors.Is(l1err, ErrNoCitableEvents) {
			result.L1 = nil
			return result, fmt.Errorf("chain aborted before L1: %w", l1err)
		}
		if skip, reason := ShouldSkipL2(l1err); skip {
			result.L2Skipped = true
			result.SkipReason = reason
			RecordL2Skip(c.skips, reason)
		} else if errors.Is(l1err, ErrSchemaViolation) {
			result.L2Skipped = true
			result.SkipReason = L2SkipReasonL1SchemaViolation
			RecordL2Skip(c.skips, L2SkipReasonL1SchemaViolation)
		} else {
			return result, fmt.Errorf("chain aborted at L1: %w", l1err)
		}
	} else {
		hyp = &l1res.Hypothesis
		l2res, l2err := c.l2.Run(ctx, pkg, l1res.Hypothesis)
		result.L2 = &l2res
		if l2err == nil {
			ver = &l2res.Verification
		}
		// On L2 failure the Senior runs hypothesis-only: L2 was
		// attempted, so no skip metric and no SkipReason.
	}

	seniorRes, seniorErr := c.senior.Run(ctx, pkg, hyp, ver)
	result.Senior = seniorRes
	if seniorErr != nil {
		return result, fmt.Errorf("chain aborted at Senior: %w", seniorErr)
	}

	scoreCap := c.senior.ScoreCap()
	verdict := seniorRes.Verdict

	disagreements := verdict.NotedDisagreements
	// AC1's explicit disagreement record must not depend on model
	// diligence: when L2 refuted and the model recorded nothing, the
	// orchestrator appends a deterministic entry (BI-7).
	if ver != nil && ver.Verdict == schema.VerdictRefuted && len(disagreements) == 0 {
		entry := "L2 refuted the L1 hypothesis"
		if len(ver.ContradictoryFindings) > 0 {
			entry += ": " + boundForLog(ver.ContradictoryFindings[0])
		}
		disagreements = []string{entry}
	}

	available := []string{}
	if l1err == nil {
		available = append(available, "l1")
	}
	if result.L2 != nil && ver != nil {
		available = append(available, "l2")
	}
	available = append(available, "senior")

	assessment := schema.ThreatAssessment{
		ThreatType:          verdict.ThreatType,
		Reasoning:           verdict.Reasoning,
		MitreTechniques:     verdict.MitreTechniques,
		KillChainStage:      verdict.KillChainStage,
		Mode:                schema.ModeLLM,
		NotedDisagreements:  disagreements,
		RawConfidence:       verdict.Confidence,
		LLMCappedConfidence: CapConfidence(verdict.Confidence, scoreCap),
		AgentsAvailable:     available,
	}
	if err := GuardCappedConfidence(&assessment, scoreCap, c.capViolations); err != nil {
		return result, err
	}
	result.Assessment = assessment
	return result, nil
}
