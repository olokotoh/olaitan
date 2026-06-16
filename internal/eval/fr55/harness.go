package fr55

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/olokotoh/olaitan/internal/decision/analyst"
	"github.com/olokotoh/olaitan/internal/decision/score"
	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/schema"
)

// DefaultLLMWeight mirrors score.DefaultLLMWeight (0.3): the FR55 bound is
// DefaultLLMWeight * provider.ScoreCap() (10.5 Claude / 7.5 Ollama, BI-6).
// Re-exported here so the harness computes the expected bound without
// reaching into the score package's defaults at every call site.
const DefaultLLMWeight = score.DefaultLLMWeight

// RunOptions parameterises one FR55 bound-test run.
type RunOptions struct {
	// Config is the LLM configuration under test: ConfigRSL (single-LLM
	// Standard mode, effective L1-only chain) or ConfigRSLTFull (full
	// L1 -> L2 -> Senior chain).
	Config Config
	// ScoreCap is the per-provider anti-hallucination cap the fake provider
	// reports (35 Claude-shaped -> bound 10.5; 25 Ollama-shaped -> bound
	// 7.5, BI-6). The harness reads the bound from the provider seam
	// (provider.ScoreCap()), it does NOT hard-code 35 or 25.
	ScoreCap int
	// Trials is the number of trials to run (the OFFLINE test uses a small
	// deterministic N; the deferred real run is the pre-registered N=100,
	// BI-2).
	Trials int
	// ProviderLabel is the honest provider marker recorded on every trial.
	// On the offline path callers pass OfflineProviderLabel ("fake", BI-2).
	ProviderLabel string
}

// RunResult is the output of one bound-test run: the per-trial records and
// the bound aggregation.
type RunResult struct {
	Trials  []Trial
	Summary BoundSummary
}

// Run drives the FR55 bound test: for each trial it generates a benign
// package (AC1), runs it through the REAL analyst.Chain under the
// adversarial prompts (AC2/AC3), folds the capped LLM confidence through
// the REAL score.Calculator (AC3), maps the ThreatScore to the production
// FSM state (OQ4), reads the registered cap-violation counter (BI-8), and
// records one Trial. It then aggregates the bound (AC4/AC6).
//
// Everything runs IN-PROCESS over a deterministic fake provider: no
// cluster, no network (BI-2). The cap seam is consumed READ-ONLY (BI-5):
// the harness never mutates CapConfidence, GuardCappedConfidence, or the
// score fold.
func Run(ctx context.Context, opts RunOptions) (RunResult, error) {
	if opts.Trials < 0 {
		return RunResult{}, fmt.Errorf("fr55: negative trial count %d", opts.Trials)
	}
	switch opts.Config {
	case ConfigRSL, ConfigRSLTFull:
	default:
		return RunResult{}, fmt.Errorf("fr55: unknown config %q (want rsl or rslt-full)", opts.Config)
	}
	providerLabel := opts.ProviderLabel
	if providerLabel == "" {
		providerLabel = OfflineProviderLabel
	}

	reg := metrics.NewRegistry()
	// Discard the harness's own log output: the offline test asserts on the
	// records, not the log.
	log := slog.New(slog.DiscardHandler)

	fake := newFakeProvider(providerLabel, opts.ScoreCap)

	chain, err := buildChain(opts.Config, fake, reg, log)
	if err != nil {
		return RunResult{}, err
	}

	calc, err := score.New(nil, reg)
	if err != nil {
		return RunResult{}, fmt.Errorf("fr55: build score calculator: %w", err)
	}

	// Inject the harness-only adversarial prompts via the FROZEN Story-3.13
	// hot-swap seam (BI-3): no chain rebuild, no production-prompt edit.
	l1, l2, senior := AdversarialPrompts()
	chain.SetPrompts(l1, l2, senior)

	// The bound is read from the provider seam (BI-6), not hard-coded.
	bound := DefaultLLMWeight * float64(fake.ScoreCap())

	trials := make([]Trial, 0, opts.Trials)
	for i := 0; i < opts.Trials; i++ {
		pkg := BenignPackage(BenignPackageOptions{Index: i})
		tr, err := runTrial(ctx, chain, calc, reg, pkg, i, opts.Config, providerLabel)
		if err != nil {
			return RunResult{}, fmt.Errorf("fr55: trial %d: %w", i, err)
		}
		trials = append(trials, tr)
	}

	return RunResult{Trials: trials, Summary: summarise(trials, providerLabel, opts.Config, bound)}, nil
}

// buildChain constructs the real analyst.Chain for the requested config
// over the fake provider.
//
//   - ConfigRSL is single-LLM Standard mode: the chart sets l2_enabled=false
//     so L1 acts as the effective single-LLM analyst -> NewChain(l1, nil,
//     nil) -> ChainModeL1Only, capped at the L1 provider's ScoreCap.
//   - ConfigRSLTFull is the full chain: NewChain(l1, l2, senior) ->
//     ChainModeFull, capped at the Senior provider's ScoreCap.
//
// All roles share the one fake provider, so every role reports the same
// parameterised ScoreCap (BI-6). The cap-violation counter the chain
// increments lives on reg; the harness reads it via the registry's
// gatherer after each trial (BI-8).
func buildChain(cfg Config, fake *fakeProvider, reg *metrics.Registry, log *slog.Logger) (*analyst.Chain, error) {
	l1, err := analyst.NewL1(fake, analyst.PromptSpec{}, reg, log)
	if err != nil {
		return nil, fmt.Errorf("fr55: build L1: %w", err)
	}

	var (
		l2     *analyst.L2
		senior *analyst.Senior
	)
	if cfg == ConfigRSLTFull {
		l2, err = analyst.NewL2(fake, analyst.PromptSpec{}, reg, log)
		if err != nil {
			return nil, fmt.Errorf("fr55: build L2: %w", err)
		}
		senior, err = analyst.NewSenior(fake, analyst.PromptSpec{}, reg, log)
		if err != nil {
			return nil, fmt.Errorf("fr55: build Senior: %w", err)
		}
	}

	chain, err := analyst.NewChain(l1, l2, senior, reg, log)
	if err != nil {
		return nil, fmt.Errorf("fr55: build chain: %w", err)
	}
	return chain, nil
}

// runTrial drives one benign package through the chain and the score fold,
// and assembles the per-trial record.
func runTrial(ctx context.Context, chain *analyst.Chain, calc *score.Calculator, reg *metrics.Registry, pkg schema.EvidencePackage, index int, cfg Config, providerLabel string) (Trial, error) {
	res, err := chain.Run(ctx, pkg)
	if err != nil {
		return Trial{}, fmt.Errorf("chain run: %w", err)
	}
	assessment := res.Assessment

	// Fold the post-cap LLM confidence through the REAL deterministic score
	// calculator (BI-5, consumed read-only). On the benign stimulus the
	// rule and baseline terms are 0, so Total == LLMWeight * cappedLLM.
	confidence, err := calc.Score(&pkg, assessment.LLMCappedConfidence)
	if err != nil {
		return Trial{}, fmt.Errorf("score: %w", err)
	}

	return Trial{
		SchemaVersion:       TrialSchemaVersion,
		TrialIndex:          index,
		Config:              cfg,
		Provider:            providerLabel,
		RawConfidence:       assessment.RawConfidence,
		LLMCappedConfidence: assessment.LLMCappedConfidence,
		ThreatScore:         confidence.Total,
		FinalFSMState:       FinalFSMState(confidence.Total),
		CapViolationTotal:   readCapViolations(reg),
	}, nil
}

// readCapViolations reads the cumulative analyst.CapViolationMetricName
// counter value off the registry (BI-8): the SAME series the chain
// increments through analyst.GuardCappedConfidence. Asserting the ACTUAL
// registered counter (olaitan_llm_cap_violation_total), NOT the epic's
// drifted _decision_ name (BI-8). Mirrors the analyst test's read pattern.
func readCapViolations(reg *metrics.Registry) int {
	mfs, err := reg.Gatherer().Gather()
	if err != nil {
		return 0
	}
	var total float64
	for _, mf := range mfs {
		if mf.GetName() != analyst.CapViolationMetricName {
			continue
		}
		for _, m := range mf.GetMetric() {
			total += m.GetCounter().GetValue()
		}
	}
	return int(total)
}
