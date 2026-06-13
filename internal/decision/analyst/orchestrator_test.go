package analyst

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/olokotoh/olaitan/internal/agent/provider"
	"github.com/olokotoh/olaitan/internal/decision/score"
	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/schema"
)

// newTestChain wires a chain from three scripted fake providers sharing
// one registry (the AC6 integration harness).
func newTestChain(t *testing.T, l1fp, l2fp, srfp *fakeProvider) (*Chain, *metrics.Registry) {
	t.Helper()
	reg := metrics.NewRegistry()
	l1, err := NewL1(l1fp, PromptSpec{System: "l1 sys", Version: "v1"}, reg, nil)
	if err != nil {
		t.Fatalf("NewL1: %v", err)
	}
	l2, err := NewL2(l2fp, PromptSpec{System: "l2 sys", Version: "v2"}, reg, nil)
	if err != nil {
		t.Fatalf("NewL2: %v", err)
	}
	sr, err := NewSenior(srfp, PromptSpec{System: "senior sys", Version: "v3"}, reg, nil)
	if err != nil {
		t.Fatalf("NewSenior: %v", err)
	}
	chain, err := NewChain(l1, l2, sr, reg, nil)
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	return chain, reg
}

func skipCounter(t *testing.T, reg *metrics.Registry, reason string) float64 {
	t.Helper()
	mfs, err := reg.Gatherer().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != L2SkippedMetricName {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "reason" && l.GetValue() == reason {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

func capViolations(t *testing.T, reg *metrics.Registry) float64 {
	t.Helper()
	mfs, err := reg.Gatherer().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == CapViolationMetricName {
			var total float64
			for _, m := range mf.GetMetric() {
				total += m.GetCounter().GetValue()
			}
			return total
		}
	}
	return 0
}

func TestCapConfidenceTable(t *testing.T) {
	cases := []struct{ raw, cap, want int }{
		{0, 35, 0}, {35, 35, 35}, {36, 35, 35}, {100, 35, 35},
		{100, 30, 30}, {100, 25, 25}, {10, 25, 10}, {-5, 35, 0},
		// Defence-in-depth: a misconfigured non-positive cap clamps to 0
		// (Story 3.7 round-1 review); never a negative capped confidence.
		{50, 0, 0}, {50, -5, 0}, {0, -5, 0},
	}
	for _, tc := range cases {
		if got := CapConfidence(tc.raw, tc.cap); got != tc.want {
			t.Errorf("CapConfidence(%d, %d) = %d, want %d", tc.raw, tc.cap, got, tc.want)
		}
	}
}

// TestCapBoundProperty is the BI-8 assessment-level bound proof: for
// every raw in [0,100] and every shipped cap, the capped confidence
// never exceeds the cap, and the architecture's LLM-only ThreatScore
// arithmetic never exceeds 0.3 x 35 = 10.5 (pinned to the score
// package's exported constants so a weight or cap change breaks this
// test). The integrated calculator-path proof transfers to Story 3.11.
func TestCapBoundProperty(t *testing.T) {
	for _, scoreCap := range []int{35, 30, 25} {
		for raw := 0; raw <= 100; raw++ {
			capped := CapConfidence(raw, scoreCap)
			if capped > scoreCap {
				t.Fatalf("CapConfidence(%d, %d) = %d exceeds the cap", raw, scoreCap, capped)
			}
		}
	}
	maxLLMOnly := score.DefaultLLMWeight * score.DefaultLLMCap
	if maxLLMOnly != 10.5 {
		t.Fatalf("architecture bound drifted: DefaultLLMWeight*DefaultLLMCap = %v, want 10.5 (update the trust-bound docs AND Story 3.11 if intentional)", maxLLMOnly)
	}
	adversarial := CapConfidence(100, int(score.DefaultLLMCap))
	if got := score.DefaultLLMWeight * float64(adversarial); got > 10.5 {
		t.Fatalf("adversarial LLM-only contribution %v exceeds 10.5", got)
	}
}

func TestGuardCappedConfidence(t *testing.T) {
	reg := metrics.NewRegistry()
	vec, err := RegisterCapViolationMetric(reg)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	ok := &schema.ThreatAssessment{LLMCappedConfidence: 35}
	if err := GuardCappedConfidence(ok, 35, vec); err != nil {
		t.Fatalf("guard refused a compliant assessment: %v", err)
	}
	if got := capViolations(t, reg); got != 0 {
		t.Errorf("violations = %v, want 0", got)
	}
	bad := &schema.ThreatAssessment{LLMCappedConfidence: 36}
	err = GuardCappedConfidence(bad, 35, vec)
	if !errors.Is(err, ErrCapViolation) {
		t.Fatalf("err = %v, want ErrCapViolation", err)
	}
	if got := capViolations(t, reg); got != 1 {
		t.Errorf("violations = %v, want 1", got)
	}
	// A non-positive cap clamps to 0 (mirrors CapConfidence): a
	// compliant capped=0 assessment must not trip a spurious violation
	// (Story 3.7 round-2). Without the clamp, 0 > -5 would fire.
	zeroCapped := &schema.ThreatAssessment{LLMCappedConfidence: 0}
	if err := GuardCappedConfidence(zeroCapped, -5, vec); err != nil {
		t.Fatalf("negative cap with capped=0 should pass: %v", err)
	}
	if got := capViolations(t, reg); got != 1 {
		t.Errorf("violations = %v, want 1 (negative cap must not increment)", got)
	}
	if err := GuardCappedConfidence(nil, 35, vec); err == nil {
		t.Error("nil assessment: err = nil, want error")
	}
}

func TestChainRunConfirmPath(t *testing.T) {
	l1fp := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: validVerdict}}
	l2fp := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: validL2Verdict}}
	srfp := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: validSeniorVerdict}}
	chain, reg := newTestChain(t, l1fp, l2fp, srfp)

	res, err := chain.Run(context.Background(), testPackage())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.L1 == nil || res.L2 == nil || res.L2Skipped {
		t.Fatalf("chain trail wrong: %+v", res)
	}
	if l2fp.got.PriorHypothesis == nil {
		t.Error("L2 did not receive the L1 hypothesis")
	}
	if srfp.got.PriorHypothesis == nil || srfp.got.PriorVerification == nil {
		t.Error("Senior did not receive both priors")
	}
	a := res.Assessment
	if a.ThreatType != "crypto_miner" || a.Mode != schema.ModeLLM {
		t.Errorf("assessment fields wrong: %+v", a)
	}
	if a.RawConfidence != 85 || a.LLMCappedConfidence != CapConfidence(85, 25) {
		t.Errorf("cap arithmetic wrong: raw=%d capped=%d (fake cap 25)", a.RawConfidence, a.LLMCappedConfidence)
	}
	if strings.Join(a.AgentsAvailable, ",") != "l1,l2,senior" {
		t.Errorf("agents_available = %v", a.AgentsAvailable)
	}
	// The verdict carried a model-authored disagreement; preserved as-is.
	if len(a.NotedDisagreements) != 1 || !strings.Contains(a.NotedDisagreements[0], "L2 refuted L1") {
		t.Errorf("noted_disagreements = %v", a.NotedDisagreements)
	}
	if got := familyTotal(t, reg); got != 3 {
		t.Errorf("decision family total = %v, want 3 (one per role)", got)
	}
	if got := capViolations(t, reg); got != 0 {
		t.Errorf("cap violations = %v, want 0", got)
	}
}

// TestChainRunRefuteContradiction pins the deterministic disagreement
// append: L2 refuted, the Senior verdict carries no disagreements, the
// orchestrator records one.
func TestChainRunRefuteContradiction(t *testing.T) {
	seniorNoDisagreements := `{"threat_type":"benign_operations","reasoning":"sided with L2","confidence":20}`
	l1fp := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: validVerdict}}
	l2fp := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: refutedL2Verdict}}
	srfp := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: seniorNoDisagreements}}
	chain, _ := newTestChain(t, l1fp, l2fp, srfp)

	res, err := chain.Run(context.Background(), testPackage())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Assessment.NotedDisagreements) != 1 {
		t.Fatalf("expected the orchestrator-appended disagreement, got %v", res.Assessment.NotedDisagreements)
	}
	if !strings.Contains(res.Assessment.NotedDisagreements[0], "L2 refuted the L1 hypothesis") {
		t.Errorf("appended entry wrong: %q", res.Assessment.NotedDisagreements[0])
	}
	if !strings.Contains(res.Assessment.NotedDisagreements[0], "fluent-bit") {
		t.Errorf("appended entry lost the first contradictory finding: %q", res.Assessment.NotedDisagreements[0])
	}
}

func TestChainRunL1Unavailable(t *testing.T) {
	l1fp := &fakeProvider{name: "fake", model: "m", err: errors.New("upstream 529")}
	l2fp := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: validL2Verdict}}
	srfp := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: validSeniorVerdict}}
	chain, reg := newTestChain(t, l1fp, l2fp, srfp)

	res, err := chain.Run(context.Background(), testPackage())
	if err != nil {
		t.Fatalf("Run: %v (evidence-only mode must still produce an assessment)", err)
	}
	if !res.L2Skipped || res.SkipReason != L2SkipReasonL1Unavailable {
		t.Errorf("skip state wrong: skipped=%v reason=%q", res.L2Skipped, res.SkipReason)
	}
	if l2fp.calls != 0 {
		t.Errorf("L2 provider called %d times despite the skip", l2fp.calls)
	}
	if srfp.got.PriorHypothesis != nil || srfp.got.PriorVerification != nil {
		t.Error("evidence-only Senior received prior blocks")
	}
	if strings.Join(res.Assessment.AgentsAvailable, ",") != "senior" {
		t.Errorf("agents_available = %v, want senior only", res.Assessment.AgentsAvailable)
	}
	if got := skipCounter(t, reg, L2SkipReasonL1Unavailable); got != 1 {
		t.Errorf("skip counter = %v, want 1", got)
	}
}

func TestChainRunL1SchemaViolation(t *testing.T) {
	l1fp := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: "not json at all"}}
	l2fp := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: validL2Verdict}}
	srfp := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: validSeniorVerdict}}
	chain, reg := newTestChain(t, l1fp, l2fp, srfp)

	res, err := chain.Run(context.Background(), testPackage())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.L2Skipped || res.SkipReason != L2SkipReasonL1SchemaViolation {
		t.Errorf("skip state wrong: skipped=%v reason=%q", res.L2Skipped, res.SkipReason)
	}
	if l2fp.calls != 0 {
		t.Errorf("L2 provider called %d times despite the skip", l2fp.calls)
	}
	if got := skipCounter(t, reg, L2SkipReasonL1SchemaViolation); got != 1 {
		t.Errorf("skip counter = %v, want 1", got)
	}
}

func TestChainRunL2FailureHypothesisOnly(t *testing.T) {
	l1fp := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: validVerdict}}
	l2fp := &fakeProvider{name: "fake", model: "m", err: errors.New("l2 down")}
	srfp := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: validSeniorVerdict}}
	chain, reg := newTestChain(t, l1fp, l2fp, srfp)

	res, err := chain.Run(context.Background(), testPackage())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.L2Skipped || res.SkipReason != "" {
		t.Errorf("L2 was attempted, not skipped: %+v", res)
	}
	if res.L2 == nil || res.L2.Status != StatusUnavailable {
		t.Errorf("L2 audit trail missing: %+v", res.L2)
	}
	if srfp.got.PriorHypothesis == nil || srfp.got.PriorVerification != nil {
		t.Error("hypothesis-only Senior priors wrong")
	}
	if strings.Join(res.Assessment.AgentsAvailable, ",") != "l1,senior" {
		t.Errorf("agents_available = %v", res.Assessment.AgentsAvailable)
	}
	if got := skipCounter(t, reg, L2SkipReasonL1Unavailable) + skipCounter(t, reg, L2SkipReasonL1SchemaViolation); got != 0 {
		t.Errorf("skip counter = %v, want 0", got)
	}
}

func TestChainRunSeniorFailureAborts(t *testing.T) {
	l1fp := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: validVerdict}}
	l2fp := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: validL2Verdict}}
	srfp := &fakeProvider{name: "fake", model: "m", err: errors.New("senior down")}
	chain, _ := newTestChain(t, l1fp, l2fp, srfp)

	res, err := chain.Run(context.Background(), testPackage())
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("err = %v, want ErrProviderUnavailable through the chain", err)
	}
	if res.Assessment.ThreatType != "" {
		t.Error("aborted chain returned a non-zero assessment")
	}
	if res.L1 == nil || res.L2 == nil {
		t.Error("audit trail of completed stages lost on abort")
	}
}

func TestChainRunNoCitableEventsAborts(t *testing.T) {
	l1fp := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: validVerdict}}
	l2fp := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: validL2Verdict}}
	srfp := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: validSeniorVerdict}}
	chain, reg := newTestChain(t, l1fp, l2fp, srfp)

	_, err := chain.Run(context.Background(), schema.EvidencePackage{PackageID: "pkg-empty"})
	if !errors.Is(err, ErrNoCitableEvents) {
		t.Fatalf("err = %v, want ErrNoCitableEvents", err)
	}
	if l1fp.calls+l2fp.calls+srfp.calls != 0 {
		t.Error("providers were called for an unassessable package")
	}
	if got := familyTotal(t, reg); got != 0 {
		t.Errorf("decision family total = %v, want 0", got)
	}
}

// TestChainRunAdversarialCap is the AC5 adversarial case: empty rule and
// baseline signals, raw confidence 100; the capped confidence equals the
// provider cap and the LLM-only arithmetic stays under 10.5.
func TestChainRunAdversarialCap(t *testing.T) {
	adversarialSenior := `{"threat_type":"fabricated_apocalypse","reasoning":"the model is absolutely certain","confidence":100}`
	l1fp := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: validVerdict}}
	l2fp := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: validL2Verdict}}
	srfp := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: adversarialSenior}}
	chain, reg := newTestChain(t, l1fp, l2fp, srfp)

	pkg := testPackage()
	pkg.RuleMatches = nil
	pkg.BaselineDeviations = nil

	res, err := chain.Run(context.Background(), pkg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Assessment.RawConfidence != 100 {
		t.Errorf("raw = %d, want 100", res.Assessment.RawConfidence)
	}
	if res.Assessment.LLMCappedConfidence != srfp.ScoreCap() {
		t.Errorf("capped = %d, want the provider cap %d", res.Assessment.LLMCappedConfidence, srfp.ScoreCap())
	}
	if got := score.DefaultLLMWeight * float64(res.Assessment.LLMCappedConfidence); got > 10.5 {
		t.Errorf("LLM-only contribution %v exceeds the 10.5 bound", got)
	}
	if got := capViolations(t, reg); got != 0 {
		t.Errorf("cap violations = %v, want 0 (capping is by construction)", got)
	}
}

func TestNewChainValidation(t *testing.T) {
	reg := metrics.NewRegistry()
	fp := &fakeProvider{name: "fake", model: "m"}
	l1, _ := NewL1(fp, PromptSpec{}, reg, nil)
	l2, _ := NewL2(fp, PromptSpec{}, reg, nil)
	sr, _ := NewSenior(fp, PromptSpec{}, reg, nil)
	if _, err := NewChain(nil, l2, sr, reg, nil); err == nil {
		t.Error("nil l1: err = nil, want error")
	}
	if _, err := NewChain(l1, l2, sr, nil, nil); err == nil {
		t.Error("nil registry: err = nil, want error")
	}
}
