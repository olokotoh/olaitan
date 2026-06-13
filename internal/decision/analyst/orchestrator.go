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
//
// A non-positive scoreCap is clamped to 0 so the guard agrees with
// CapConfidence on the effective cap (Story 3.7 round-2 review): without
// this, a negative cap would make a legitimately-capped (>=0) confidence
// trip a spurious violation, misattributing a provider misconfiguration
// to "a code path bypassed the cap arithmetic" (capViolationMetricHelp).
// Real violations on positive caps are unaffected.
func GuardCappedConfidence(a *schema.ThreatAssessment, scoreCap int, vec *prometheus.CounterVec) error {
	if a == nil {
		return errors.New("analyst: nil assessment")
	}
	if scoreCap < 0 {
		scoreCap = 0
	}
	if a.LLMCappedConfidence > scoreCap {
		if vec != nil {
			vec.WithLabelValues().Inc()
		}
		return fmt.Errorf("%w: capped=%d cap=%d", ErrCapViolation, a.LLMCappedConfidence, scoreCap)
	}
	return nil
}

// Chain mode labels (Story 3.8 BI-5): which roles the chain is
// configured to run. They drive the ChainResult.Mode audit field and the
// olaitan_investigation_chain_runs_total{mode} metric. A mode is fixed at
// construction by the deliberate-ablation toggles, distinct from a
// runtime degrade (a role failing mid-run).
const (
	ChainModeFull   = "full"    // L1 -> L2 -> Senior
	ChainModeL1L2   = "l1_l2"   // L1 -> L2 (RSLT L1+L2 ablation, Senior off)
	ChainModeL1Only = "l1_only" // L1 (RSLT L1-only ablation, L2 + Senior off)
)

// ChainResult is the full audit trail of one investigation chain run
// (consumed by the Story 3.14 publisher and the Story 3.9
// checkpointer). Stage pointers are nil where a stage did not run. Mode
// records the deliberate-ablation boundary (Story 3.8 BI-5).
type ChainResult struct {
	L1         *L1Result
	L2         *L2Result
	L2Skipped  bool
	SkipReason string
	Senior     SeniorResult
	Mode       string
	Assessment schema.ThreatAssessment
}

// Chain sequences L1 -> (gate) -> L2 -> Senior over one EvidencePackage
// (Story 3.7 BI-7). Per-role provider routing and deliberate ablation
// are Story 3.8; retries and fallback are Story 3.10. The mode is fixed
// at construction: a nil senior runner = L1+L2 ablation, a nil l2 AND
// nil senior = L1-only ablation.
type Chain struct {
	l1            *L1
	l2            *L2
	senior        *Senior
	mode          string
	checkpoints   CheckpointStore
	skips         *prometheus.CounterVec
	capViolations *prometheus.CounterVec
	log           *slog.Logger
}

// Mode reports the chain's construction-time ablation mode (one of
// ChainModeFull / ChainModeL1L2 / ChainModeL1Only). The consumer uses it
// as the metric label and the audit mode (Story 3.8 BI-5/BI-8).
func (c *Chain) Mode() string { return c.mode }

// WithCheckpoints attaches a CheckpointStore so the chain checkpoints L1/L2
// outputs and resumes from them on a controller restart (Story 3.9). A nil
// store (the default) keeps the Story 3.8 behaviour byte-identical: no
// Save/Load calls. Returns the chain for fluent wiring.
func (c *Chain) WithCheckpoints(store CheckpointStore) *Chain {
	c.checkpoints = store
	return c
}

// l1Step runs L1, or resumes it from a checkpoint when one exists (Story
// 3.9 BI-4/BI-5). On a checkpoint hit the L1 runner is NOT invoked and a
// minimal success L1Result is reconstructed; on a miss L1 runs and a
// success is checkpointed. A Load error or a Save failure is logged and
// the step proceeds (best-effort durability, never a correctness gate).
func (c *Chain) l1Step(ctx context.Context, pkg schema.EvidencePackage) (L1Result, error) {
	if c.checkpoints != nil {
		if hyp, ok, err := c.checkpoints.LoadL1(ctx, pkg.PackageID); err != nil {
			c.log.Warn("checkpoint LoadL1 failed; re-running L1", "err", err, "package_id", pkg.PackageID)
		} else if ok {
			return L1Result{Hypothesis: hyp, Status: StatusSuccess}, nil
		}
	}
	res, err := c.l1.Run(ctx, pkg)
	if err == nil && c.checkpoints != nil {
		if serr := c.checkpoints.SaveL1(ctx, pkg.PackageID, res.Hypothesis); serr != nil {
			c.log.Warn("checkpoint SaveL1 failed; chain continues", "err", serr, "package_id", pkg.PackageID)
		}
	}
	return res, err
}

// l2Step runs L2, or resumes it from a checkpoint when one exists (Story
// 3.9). Same best-effort semantics as l1Step.
func (c *Chain) l2Step(ctx context.Context, pkg schema.EvidencePackage, hyp schema.L1Hypothesis) (L2Result, error) {
	if c.checkpoints != nil {
		if ver, ok, err := c.checkpoints.LoadL2(ctx, pkg.PackageID); err != nil {
			c.log.Warn("checkpoint LoadL2 failed; re-running L2", "err", err, "package_id", pkg.PackageID)
		} else if ok {
			return L2Result{Verification: ver, Status: StatusSuccess}, nil
		}
	}
	res, err := c.l2.Run(ctx, pkg, hyp)
	if err == nil && c.checkpoints != nil {
		if serr := c.checkpoints.SaveL2(ctx, pkg.PackageID, res.Verification); serr != nil {
			c.log.Warn("checkpoint SaveL2 failed; chain continues", "err", serr, "package_id", pkg.PackageID)
		}
	}
	return res, err
}

// NewChain builds the chain orchestrator from the role runners. l1 is
// always required. Deliberate ablation (Story 3.8 AC4) is expressed by
// nil runners: senior == nil (l2 present) = L1+L2; l2 == nil && senior
// == nil = L1-only. l2 == nil with a non-nil senior is rejected: that is
// not a named ablation cell.
func NewChain(l1 *L1, l2 *L2, senior *Senior, reg *metrics.Registry, log *slog.Logger) (*Chain, error) {
	if l1 == nil {
		return nil, errors.New("analyst: nil L1 runner")
	}
	if l2 == nil && senior != nil {
		return nil, errors.New("analyst: senior without L2 is not a valid ablation (want full, L1+L2, or L1-only)")
	}
	mode := ChainModeFull
	switch {
	case l2 == nil:
		mode = ChainModeL1Only
	case senior == nil:
		mode = ChainModeL1L2
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
	return &Chain{l1: l1, l2: l2, senior: senior, mode: mode, skips: skips, capViolations: capViolations, log: log}, nil
}

// Run executes the configured investigation chain for pkg, dispatching
// on the construction-time ablation mode (Story 3.8 BI-5).
func (c *Chain) Run(ctx context.Context, pkg schema.EvidencePackage) (ChainResult, error) {
	switch c.mode {
	case ChainModeL1Only:
		return c.runL1Only(ctx, pkg)
	case ChainModeL1L2:
		return c.runL1L2(ctx, pkg)
	default:
		return c.runFull(ctx, pkg)
	}
}

// runL1Only is the RSLT L1-only ablation (Story 3.8 AC4): L1 runs and the
// assessment is built from the hypothesis. There is no role below L1 to
// absorb a failure, so any L1 failure aborts the chain.
func (c *Chain) runL1Only(ctx context.Context, pkg schema.EvidencePackage) (ChainResult, error) {
	result := ChainResult{Mode: ChainModeL1Only}

	l1res, l1err := c.l1Step(ctx, pkg)
	if l1err != nil {
		if errors.Is(l1err, ErrNoCitableEvents) {
			return result, fmt.Errorf("chain aborted before L1: %w", l1err)
		}
		result.L1 = &l1res
		return result, fmt.Errorf("L1-only chain aborted at L1: %w", l1err)
	}
	result.L1 = &l1res

	hyp := l1res.Hypothesis
	scoreCap := c.l1.ScoreCap()
	assessment := schema.ThreatAssessment{
		Reasoning:           hyp.Hypothesis,
		Mode:                schema.ModeLLM,
		RawConfidence:       hyp.Confidence,
		LLMCappedConfidence: CapConfidence(hyp.Confidence, scoreCap),
		AgentsAvailable:     []string{"l1"},
	}
	if err := GuardCappedConfidence(&assessment, scoreCap, c.capViolations); err != nil {
		return result, err
	}
	result.Assessment = assessment
	return result, nil
}

// runL1L2 is the RSLT L1+L2 ablation (Story 3.8 AC4): L1 -> L2, Senior
// off. The assessment is built from L2 when it succeeds, else from L1 (a
// runtime degrade within the ablation). Any L1 failure aborts: there is
// no Senior to absorb it. The Reasoning carries the L1 hypothesis (the
// verified narrative); ThreatType/MitreTechniques are empty because no
// Senior produced them.
func (c *Chain) runL1L2(ctx context.Context, pkg schema.EvidencePackage) (ChainResult, error) {
	result := ChainResult{Mode: ChainModeL1L2}

	l1res, l1err := c.l1Step(ctx, pkg)
	if l1err != nil {
		if errors.Is(l1err, ErrNoCitableEvents) {
			return result, fmt.Errorf("chain aborted before L1: %w", l1err)
		}
		result.L1 = &l1res
		return result, fmt.Errorf("L1+L2 chain aborted at L1: %w", l1err)
	}
	result.L1 = &l1res

	l2res, l2err := c.l2Step(ctx, pkg, l1res.Hypothesis)
	result.L2 = &l2res

	var (
		raw       int
		scoreCap  int
		available []string
		disagree  []string
	)
	if l2err == nil {
		ver := l2res.Verification
		raw = ver.Confidence
		scoreCap = c.l2.ScoreCap()
		available = []string{"l1", "l2"}
		if ver.Verdict == schema.VerdictRefuted {
			entry := "L2 refuted the L1 hypothesis"
			if len(ver.ContradictoryFindings) > 0 {
				entry += ": " + boundForLog(ver.ContradictoryFindings[0])
			}
			disagree = []string{entry}
		}
	} else {
		// L2 failed; degrade to L1 within the ablation.
		raw = l1res.Hypothesis.Confidence
		scoreCap = c.l1.ScoreCap()
		available = []string{"l1"}
	}

	assessment := schema.ThreatAssessment{
		Reasoning:           l1res.Hypothesis.Hypothesis,
		Mode:                schema.ModeLLM,
		NotedDisagreements:  disagree,
		RawConfidence:       raw,
		LLMCappedConfidence: CapConfidence(raw, scoreCap),
		AgentsAvailable:     available,
	}
	if err := GuardCappedConfidence(&assessment, scoreCap, c.capViolations); err != nil {
		return result, err
	}
	result.Assessment = assessment
	return result, nil
}

// runFull is the Story 3.7 L1 -> (gate) -> L2 -> Senior path. Degradation
// semantics (3.7 BI-7): an unavailable L1 skips L2 (reason
// l1_unavailable) into Senior-on-evidence-only mode; an L1 schema
// violation (the single pre-3.10 attempt IS the L1 outcome) skips L2
// under l1_schema_violation, also evidence-only; ErrNoCitableEvents
// aborts the chain (nothing to assess); an L2 failure of any kind runs
// the Senior hypothesis-only (L2 was attempted, not skipped); a Senior
// failure aborts the chain (Story 3.10 owns retries and fallback).
func (c *Chain) runFull(ctx context.Context, pkg schema.EvidencePackage) (ChainResult, error) {
	var result ChainResult
	result.Mode = ChainModeFull

	l1res, l1err := c.l1Step(ctx, pkg)
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
		l2res, l2err := c.l2Step(ctx, pkg, l1res.Hypothesis)
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
