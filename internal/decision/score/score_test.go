package score

import (
	"bytes"
	"encoding/json"
	"math"
	"sync/atomic"
	"testing"

	"github.com/olokotoh/olaitan/internal/config"
	"github.com/olokotoh/olaitan/internal/schema"
)

// staticGetter returns a func() *config.Config that always returns the
// supplied snapshot. Used by tests that pin a single config without
// touching the file watcher.
func staticGetter(cfg *config.Config) func() *config.Config {
	return func() *config.Config { return cfg }
}

// scoreCfg builds a *config.Config with detection.score populated to
// the supplied values. Tests that need only the score sub-block use
// this; tests that exercise multi-block interactions (e.g. the
// SigmaNormaliser falling back to detection.baselines.sigma_multiplier)
// add the baselines block separately.
func scoreCfg(rule, baseline, llm float64, cap int) *config.Config {
	rw, bw, lw := rule, baseline, llm
	llmCap := cap
	return &config.Config{
		Detection: config.DetectionConfig{
			Score: config.ScoreConfig{
				RuleWeight:     &rw,
				BaselineWeight: &bw,
				LLMWeight:      &lw,
				LLMCap:         &llmCap,
			},
		},
	}
}

func defaultScoreCfg() *config.Config {
	return scoreCfg(DefaultRuleWeight, DefaultBaselineWeight, DefaultLLMWeight, int(DefaultLLMCap))
}

func newCalcForTest(t *testing.T, get func() *config.Config) *Calculator {
	t.Helper()
	c, err := newWithGetter(get, nil)
	if err != nil {
		t.Fatalf("newWithGetter: %v", err)
	}
	return c
}

// TestScore_ZeroPackage covers AC3: empty rule matches and empty
// baseline deviations yield a zero ConfidenceScore.
func TestScore_ZeroPackage(t *testing.T) {
	c := newCalcForTest(t, staticGetter(defaultScoreCfg()))

	got, err := c.Score(&schema.EvidencePackage{})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if got.Total != 0 || got.Rules != 0 || got.Baseline != 0 || got.LLM != 0 {
		t.Fatalf("zero package: want all-zero contributions, got %+v", got)
	}
}

// TestScore_SingleRuleMatch_AtMaxSeverity covers AC1 at the maximum
// severity rail: one RuleMatch with severity 100 produces a Rules
// contribution of 40 and a Total of 40.
func TestScore_SingleRuleMatch_AtMaxSeverity(t *testing.T) {
	c := newCalcForTest(t, staticGetter(defaultScoreCfg()))

	got, err := c.Score(&schema.EvidencePackage{
		RuleMatches: []schema.RuleMatch{{Severity: "100"}},
	})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if got.Rules != 40 || got.Total != 40 {
		t.Fatalf("AC1 max severity: want Rules=40 Total=40, got Rules=%v Total=%v", got.Rules, got.Total)
	}
}

// TestScore_MultipleRuleMatches_UsesMax covers AC4: with severities
// 30, 75, 50 the calculator uses the maximum 75 (not the sum 155 nor
// the average 51.67).
func TestScore_MultipleRuleMatches_UsesMax(t *testing.T) {
	c := newCalcForTest(t, staticGetter(defaultScoreCfg()))

	got, err := c.Score(&schema.EvidencePackage{
		RuleMatches: []schema.RuleMatch{
			{Severity: "30"}, {Severity: "75"}, {Severity: "50"},
		},
	})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	want := 0.4 * 75.0
	if got.Rules != want || got.Total != want {
		t.Fatalf("AC4 max-not-sum: want Rules=%v Total=%v, got Rules=%v Total=%v", want, want, got.Rules, got.Total)
	}
}

// TestScore_MultipleBaselineDeviations_UsesMaxSigma covers AC5: with
// sigmas 1.5, 4.0, 2.8 and SigmaNormaliser 3.0 the calculator picks
// max=4.0, clamps the ratio to 1.0, scales to 100, and weighs by 0.3.
func TestScore_MultipleBaselineDeviations_UsesMaxSigma(t *testing.T) {
	c := newCalcForTest(t, staticGetter(defaultScoreCfg()))

	got, err := c.Score(&schema.EvidencePackage{
		BaselineDeviations: []schema.BaselineDeviation{
			{Sigma: 1.5}, {Sigma: 4.0}, {Sigma: 2.8},
		},
	})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if got.Baseline != 30 || got.Total != 30 {
		t.Fatalf("AC5 max sigma normalised: want Baseline=30 Total=30, got Baseline=%v Total=%v", got.Baseline, got.Total)
	}
}

// TestScore_RuleAndBaselineTie covers the AC6 "ties between rule and
// baseline contributions" boundary: severity 50 (Rules=20) and sigma
// 1.5 (normalised 50, Baseline=15) sum to Total=35.
func TestScore_RuleAndBaselineTie(t *testing.T) {
	c := newCalcForTest(t, staticGetter(defaultScoreCfg()))

	got, err := c.Score(&schema.EvidencePackage{
		RuleMatches:        []schema.RuleMatch{{Severity: "50"}},
		BaselineDeviations: []schema.BaselineDeviation{{Sigma: 1.5}},
	})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if got.Rules != 20 || got.Baseline != 15 || got.Total != 35 {
		t.Fatalf("tie boundary: want Rules=20 Baseline=15 Total=35, got %+v", got)
	}
}

// TestScore_SeverityClamping defends against an out-of-range severity
// integer reaching the calculator (the parser rejects it but the
// schema string type does not). Severity 150 is clamped to 100.
func TestScore_SeverityClamping(t *testing.T) {
	c := newCalcForTest(t, staticGetter(defaultScoreCfg()))

	got, err := c.Score(&schema.EvidencePackage{
		RuleMatches: []schema.RuleMatch{{Severity: "150"}},
	})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if got.Rules != 40 {
		t.Fatalf("clamp: want Rules=40 (clamped from 150), got Rules=%v", got.Rules)
	}
}

// TestScore_SeverityParseFallback locks the contract that the
// calculator reads parser.SeverityString output only (decimal-string
// integers). Empty strings and keyword forms like "high" fall through
// to severity 0 with no error -- the calculator deliberately does NOT
// use severitybucket.Score for parsing, since accepting keywords
// would let the Epic 3 LLM tier drift the contract.
func TestScore_SeverityParseFallback(t *testing.T) {
	c := newCalcForTest(t, staticGetter(defaultScoreCfg()))

	got, err := c.Score(&schema.EvidencePackage{
		RuleMatches: []schema.RuleMatch{
			{Severity: ""},
			{Severity: "high"},
			{Severity: "critical"},
		},
	})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if got.Rules != 0 || got.Total != 0 {
		t.Fatalf("parse fallback: want all-zero, got %+v", got)
	}
}

// TestScore_LLMTermIsZero locks the AC1 "LLM term wired but
// multiplied by zero in this epic" contract. The LLM weight is 0.3
// and the LLM cap is 35 (Claude Opus); with zero rule and baseline
// contribution the resulting Total is 0 (Epic 3 follow-up at
// epics.md:1589 will populate the LLM term with llm_capped_confidence).
func TestScore_LLMTermIsZero(t *testing.T) {
	c := newCalcForTest(t, staticGetter(defaultScoreCfg()))

	got, err := c.Score(&schema.EvidencePackage{})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if got.LLM != 0 {
		t.Fatalf("LLM term: want 0, got %v", got.LLM)
	}
	if got.Total != 0 {
		t.Fatalf("Total with no rules/baselines: want 0, got %v", got.Total)
	}
}

// TestScore_NilPackage locks the AC3 / Task 2.6 nil-package contract.
func TestScore_NilPackage(t *testing.T) {
	c := newCalcForTest(t, staticGetter(defaultScoreCfg()))

	got, err := c.Score(nil)
	if err != nil {
		t.Fatalf("nil package: unexpected err %v", err)
	}
	if got != (schema.ConfidenceScore{}) {
		t.Fatalf("nil package: want zero ConfidenceScore, got %+v", got)
	}
}

// TestScore_Determinism pins the Task 2.5 no-time / no-map-iteration
// invariant: two invocations on the same package produce byte-
// identical JSON output.
func TestScore_Determinism(t *testing.T) {
	c := newCalcForTest(t, staticGetter(defaultScoreCfg()))

	pkg := &schema.EvidencePackage{
		RuleMatches: []schema.RuleMatch{
			{RuleID: "OLT-PRIV-001", Severity: "90"},
			{RuleID: "OLT-EXEC-001", Severity: "75"},
		},
		BaselineDeviations: []schema.BaselineDeviation{
			{Metric: "outbound_unique_dst_ips", Sigma: 4.2},
			{Metric: "distinct_exec_paths", Sigma: 3.5},
		},
	}

	s1, err := c.Score(pkg)
	if err != nil {
		t.Fatalf("first Score: %v", err)
	}
	s2, err := c.Score(pkg)
	if err != nil {
		t.Fatalf("second Score: %v", err)
	}
	b1, _ := json.Marshal(s1)
	b2, _ := json.Marshal(s2)
	if !bytes.Equal(b1, b2) {
		t.Fatalf("determinism: byte mismatch\n  s1=%s\n  s2=%s", b1, b2)
	}
}

// TestScore_ConfigSnapshotChange covers AC2 at the unit level: a
// snapshot swap is reflected by the next Score() call. The integration
// path through fsnotify + Manager.Watch is in score_property_test.go
// TestProperty_HotReloadViaSubscribe.
func TestScore_ConfigSnapshotChange(t *testing.T) {
	var cur atomic.Pointer[config.Config]
	cur.Store(scoreCfg(0.4, 0.3, 0.3, 35))

	c := newCalcForTest(t, func() *config.Config { return cur.Load() })

	pkg := &schema.EvidencePackage{RuleMatches: []schema.RuleMatch{{Severity: "100"}}}
	got1, err := c.Score(pkg)
	if err != nil {
		t.Fatalf("first Score: %v", err)
	}
	if got1.Rules != 40 {
		t.Fatalf("first snapshot: want Rules=40, got %v", got1.Rules)
	}

	cur.Store(scoreCfg(0.5, 0.3, 0.2, 35))
	got2, err := c.Score(pkg)
	if err != nil {
		t.Fatalf("second Score: %v", err)
	}
	if got2.Rules != 50 {
		t.Fatalf("post-swap snapshot: want Rules=50, got %v", got2.Rules)
	}
}

// TestScore_NegativeSigmaIsSkipped pins the Story 2.1 code-review (PR #29)
// decision: a negative Sigma is structurally invalid (the baseline engine
// never emits one) and is skipped rather than aborting the score.
// Aborting to a zero score would let a single poisoned sigma suppress an
// otherwise-escalating rule match (fail-open evasion), so a valid rule
// match in the same package must still drive the score and the malformed
// deviation must contribute 0.
func TestScore_NegativeSigmaIsSkipped(t *testing.T) {
	c := newCalcForTest(t, staticGetter(defaultScoreCfg()))

	got, err := c.Score(&schema.EvidencePackage{
		RuleMatches:        []schema.RuleMatch{{Severity: "100"}},
		BaselineDeviations: []schema.BaselineDeviation{{Metric: "bad", Sigma: -1.0}},
	})
	if err != nil {
		t.Fatalf("negative sigma: want skip-and-continue, got error %v", err)
	}
	if got.Baseline != 0 {
		t.Fatalf("malformed sigma must contribute 0 to baseline, got %v", got.Baseline)
	}
	if got.Rules <= 0 {
		t.Fatalf("rule contribution lost: a skipped sigma must not zero the rule match (got Rules=%v)", got.Rules)
	}
}

// TestScore_NaNInfSigmaIsSkipped is the companion for NaN / +Inf / -Inf:
// each is skipped, scoring continues, and a co-located rule match still
// produces its contribution.
func TestScore_NaNInfSigmaIsSkipped(t *testing.T) {
	c := newCalcForTest(t, staticGetter(defaultScoreCfg()))

	for _, bad := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		got, err := c.Score(&schema.EvidencePackage{
			RuleMatches:        []schema.RuleMatch{{Severity: "100"}},
			BaselineDeviations: []schema.BaselineDeviation{{Metric: "bad", Sigma: bad}},
		})
		if err != nil {
			t.Fatalf("Sigma=%v: want skip-and-continue, got error %v", bad, err)
		}
		if got.Baseline != 0 {
			t.Fatalf("Sigma=%v: malformed sigma must contribute 0 to baseline, got %v", bad, got.Baseline)
		}
		if got.Rules <= 0 {
			t.Fatalf("Sigma=%v: rule contribution lost (got Rules=%v)", bad, got.Rules)
		}
	}
}

// TestScore_TotalClamping defends step 6 of the algorithm: weights
// summing > 1 cannot drive the total above 100. Configures degenerate
// weights of (1.0, 1.0, 0.0) -- validate() would reject this in the
// loader, but the calculator's defensive clamp is what stops a Manager
// snapshot constructed in-process from emitting Total=200.
func TestScore_TotalClamping(t *testing.T) {
	c := newCalcForTest(t, staticGetter(scoreCfg(1.0, 1.0, 0.0, 35)))

	got, err := c.Score(&schema.EvidencePackage{
		RuleMatches:        []schema.RuleMatch{{Severity: "100"}},
		BaselineDeviations: []schema.BaselineDeviation{{Sigma: 10.0}},
	})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if got.Total > 100 {
		t.Fatalf("clamp: Total > 100 (got %v); algorithm must clamp", got.Total)
	}
	if got.Total != 100 {
		t.Fatalf("clamp: want Total=100 for degenerate weights, got %v", got.Total)
	}
}
