package analyst

import (
	"context"
	"strings"
	"testing"

	"github.com/olokotoh/olaitan/internal/agent/provider"
	"github.com/olokotoh/olaitan/internal/metrics"
)

func newL1OnlyChain(t *testing.T, l1fp *fakeProvider) (*Chain, *metrics.Registry) {
	t.Helper()
	reg := metrics.NewRegistry()
	l1, err := NewL1(l1fp, PromptSpec{System: "l1 sys", Version: "v1"}, reg, nil)
	if err != nil {
		t.Fatalf("NewL1: %v", err)
	}
	chain, err := NewChain(l1, nil, nil, reg, nil)
	if err != nil {
		t.Fatalf("NewChain L1-only: %v", err)
	}
	return chain, reg
}

func newL1L2Chain(t *testing.T, l1fp, l2fp *fakeProvider) (*Chain, *metrics.Registry) {
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
	chain, err := NewChain(l1, l2, nil, reg, nil)
	if err != nil {
		t.Fatalf("NewChain L1+L2: %v", err)
	}
	return chain, reg
}

// TestNewChainAblationValidity pins the BI-5 construction rules: a nil
// senior (l2 present) is L1+L2; nil l2 AND nil senior is L1-only; nil l2
// with a non-nil senior is NOT a named ablation cell and is rejected;
// nil l1 is always rejected.
func TestNewChainAblationValidity(t *testing.T) {
	reg := metrics.NewRegistry()
	fp := &fakeProvider{name: "fake", model: "m"}
	l1, _ := NewL1(fp, PromptSpec{}, reg, nil)
	l2, _ := NewL2(fp, PromptSpec{}, reg, nil)
	sr, _ := NewSenior(fp, PromptSpec{}, reg, nil)

	if c, err := NewChain(l1, l2, nil, reg, nil); err != nil || c.mode != ChainModeL1L2 {
		t.Errorf("nil senior: mode=%q err=%v, want l1_l2/nil", modeOf(c), err)
	}
	if c, err := NewChain(l1, nil, nil, reg, nil); err != nil || c.mode != ChainModeL1Only {
		t.Errorf("nil l2+senior: mode=%q err=%v, want l1_only/nil", modeOf(c), err)
	}
	if _, err := NewChain(l1, nil, sr, reg, nil); err == nil {
		t.Error("senior without L2: err = nil, want error")
	}
	if _, err := NewChain(nil, l2, sr, reg, nil); err == nil {
		t.Error("nil l1: err = nil, want error")
	}
}

func modeOf(c *Chain) string {
	if c == nil {
		return "<nil>"
	}
	return c.mode
}

// TestChainRunL1OnlyAblation: the assessment is built from the L1
// hypothesis, capped at the L1 provider's cap (25), and records only
// "l1" as available.
func TestChainRunL1OnlyAblation(t *testing.T) {
	l1fp := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: validVerdict}}
	chain, _ := newL1OnlyChain(t, l1fp)

	res, err := chain.Run(context.Background(), testPackage())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	a := res.Assessment
	if res.Mode != ChainModeL1Only {
		t.Errorf("mode = %q, want l1_only", res.Mode)
	}
	if got := strings.Join(a.AgentsAvailable, ","); got != "l1" {
		t.Errorf("agents_available = %q, want l1", got)
	}
	if a.RawConfidence != 70 {
		t.Errorf("raw = %d, want 70 (the L1 confidence)", a.RawConfidence)
	}
	if a.LLMCappedConfidence != 25 {
		t.Errorf("capped = %d, want 25 (L1 cap)", a.LLMCappedConfidence)
	}
	if a.Reasoning != "crypto miner launched" {
		t.Errorf("reasoning = %q, want the L1 hypothesis", a.Reasoning)
	}
	if res.L2 != nil {
		t.Error("L2 ran in an L1-only chain")
	}
}

// TestChainRunL1L2Ablation: the assessment is built from L2, capped at
// the L2 provider's cap, proving the BOUNDARY role's cap is used (L2 cap
// 30 here, not L1's 25).
func TestChainRunL1L2Ablation(t *testing.T) {
	l1fp := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: validVerdict}}
	l2fp := &fakeProvider{name: "fake", model: "m", capOverride: 30, resp: provider.Response{Raw: validL2Verdict}}
	chain, _ := newL1L2Chain(t, l1fp, l2fp)

	res, err := chain.Run(context.Background(), testPackage())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	a := res.Assessment
	if res.Mode != ChainModeL1L2 {
		t.Errorf("mode = %q, want l1_l2", res.Mode)
	}
	if got := strings.Join(a.AgentsAvailable, ","); got != "l1,l2" {
		t.Errorf("agents_available = %q, want l1,l2", got)
	}
	if a.RawConfidence != 66 {
		t.Errorf("raw = %d, want 66 (the L2 confidence)", a.RawConfidence)
	}
	if a.LLMCappedConfidence != 30 {
		t.Errorf("capped = %d, want 30 (the L2 cap, proving the boundary cap)", a.LLMCappedConfidence)
	}
	if len(a.NotedDisagreements) != 0 {
		t.Errorf("confirmed verdict should record no disagreements, got %v", a.NotedDisagreements)
	}
}

// TestChainRunL1L2AblationRefutedDisagreement: a refuted L2 verdict
// records the deterministic disagreement entry with the first
// contradictory finding (Story 3.7 phrasing reused).
func TestChainRunL1L2AblationRefutedDisagreement(t *testing.T) {
	l1fp := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: validVerdict}}
	l2fp := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: refutedL2Verdict}}
	chain, _ := newL1L2Chain(t, l1fp, l2fp)

	res, err := chain.Run(context.Background(), testPackage())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	a := res.Assessment
	if len(a.NotedDisagreements) != 1 {
		t.Fatalf("disagreements = %v, want 1", a.NotedDisagreements)
	}
	if !strings.Contains(a.NotedDisagreements[0], "L2 refuted the L1 hypothesis") {
		t.Errorf("disagreement entry wrong: %q", a.NotedDisagreements[0])
	}
	if !strings.Contains(a.NotedDisagreements[0], "fluent-bit") {
		t.Errorf("disagreement lost the first contradictory finding: %q", a.NotedDisagreements[0])
	}
}

// TestChainRunL1OnlyAbortsOnL1Failure: with no role below L1 to absorb
// the failure, an L1 provider error aborts the chain.
func TestChainRunL1OnlyAbortsOnL1Failure(t *testing.T) {
	l1fp := &fakeProvider{name: "fake", model: "m", err: context.DeadlineExceeded}
	chain, _ := newL1OnlyChain(t, l1fp)

	if _, err := chain.Run(context.Background(), testPackage()); err == nil {
		t.Fatal("L1-only chain with a failing L1 must abort, got nil error")
	}
}
