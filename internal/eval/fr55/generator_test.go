package fr55

import (
	"testing"

	"github.com/olokotoh/olaitan/internal/decision/score"
)

// TestBenignPackage_NoDeterministicSignal is the FR55 stimulus invariant
// (AC1, Task 2.2, BI-4): the benign package drives score.Score's rule and
// baseline terms to ZERO, so the ONLY non-zero ThreatScore term possible is
// the LLM term the trust-bound caps. It asserts against the REAL
// score.Calculator (consumed read-only), not a re-derivation.
func TestBenignPackage_NoDeterministicSignal(t *testing.T) {
	calc, err := score.New(nil, nil)
	if err != nil {
		t.Fatalf("score.New: %v", err)
	}
	pkg := BenignPackage(BenignPackageOptions{Index: 0})

	// llm_capped_confidence = 0: with no LLM contribution, the score must be
	// entirely zero (Rules == 0 AND Baseline == 0).
	got, err := calc.Score(&pkg, 0)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if got.Rules != 0 {
		t.Errorf("Rules = %v, want 0 (rule_severity must be 0 on a benign package)", got.Rules)
	}
	if got.Baseline != 0 {
		t.Errorf("Baseline = %v, want 0 (baseline_max_deviation must be 0 on a benign package)", got.Baseline)
	}
	if got.Total != 0 {
		t.Errorf("Total = %v, want 0 (no LLM term -> zero score)", got.Total)
	}

	// The package carries the empty deterministic-signal slices that force
	// the zero terms (BI-4): the invariant is structural, not incidental.
	if len(pkg.RuleMatches) != 0 {
		t.Errorf("RuleMatches len = %d, want 0", len(pkg.RuleMatches))
	}
	if len(pkg.BaselineDeviations) != 0 {
		t.Errorf("BaselineDeviations len = %d, want 0", len(pkg.BaselineDeviations))
	}
}

// TestBenignPackage_MaximalLLMHitsBound proves that even the MAXIMAL capped
// LLM confidence folds to exactly the bound on a benign package (the
// algebraic counterpart the harness exercises empirically): rules 0 +
// baseline 0 + LLMWeight * cap.
func TestBenignPackage_MaximalLLMHitsBound(t *testing.T) {
	calc, err := score.New(nil, nil)
	if err != nil {
		t.Fatalf("score.New: %v", err)
	}
	pkg := BenignPackage(BenignPackageOptions{Index: 7})

	// The Claude cap is 35; the capped LLM confidence can be at most 35.
	got, err := calc.Score(&pkg, 35)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	want := score.DefaultLLMWeight * 35.0 // 10.5
	if got.Total != want {
		t.Errorf("Total = %v, want %v (LLMWeight * cap on a benign package)", got.Total, want)
	}
}

// TestBenignPackage_Deterministic proves the generator is byte-reproducible
// for a fixed index (BI-2): the same index yields the same package, a
// different index yields a different (but still benign) package id.
func TestBenignPackage_Deterministic(t *testing.T) {
	a := BenignPackage(BenignPackageOptions{Index: 3})
	b := BenignPackage(BenignPackageOptions{Index: 3})
	if a.PackageID != b.PackageID {
		t.Errorf("PackageID drift: %q vs %q", a.PackageID, b.PackageID)
	}
	if len(a.Events) != len(b.Events) {
		t.Fatalf("event count drift: %d vs %d", len(a.Events), len(b.Events))
	}
	for i := range a.Events {
		if a.Events[i].ID != b.Events[i].ID || a.Events[i].Summary != b.Events[i].Summary {
			t.Errorf("event %d drift: %+v vs %+v", i, a.Events[i], b.Events[i])
		}
	}
	c := BenignPackage(BenignPackageOptions{Index: 4})
	if a.PackageID == c.PackageID {
		t.Errorf("distinct indices produced the same package id %q", a.PackageID)
	}
}
