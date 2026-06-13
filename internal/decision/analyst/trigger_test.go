package analyst

import (
	"math"
	"strconv"
	"testing"

	"github.com/olokotoh/olaitan/internal/schema"
)

func ruleMatchPkg(severity int) schema.EvidencePackage {
	return schema.EvidencePackage{
		RuleMatches: []schema.RuleMatch{{RuleID: "r1", Severity: strconv.Itoa(severity), EventID: "evt-1"}},
	}
}

func baselinePkg(sigma float64) schema.EvidencePackage {
	return schema.EvidencePackage{
		BaselineDeviations: []schema.BaselineDeviation{{Metric: "cpu", Sigma: sigma, PodUID: "pod-1"}},
	}
}

func TestShouldTriggerChainSeverity(t *testing.T) {
	cases := []struct {
		sev  int
		want bool
	}{
		{49, false}, {50, true}, {51, true}, {0, false}, {100, true},
	}
	for _, tc := range cases {
		if got := ShouldTriggerChain(ruleMatchPkg(tc.sev)); got != tc.want {
			t.Errorf("severity %d: got %v, want %v", tc.sev, got, tc.want)
		}
	}
}

func TestShouldTriggerChainSigma(t *testing.T) {
	cases := []struct {
		sigma float64
		want  bool
	}{
		{2.9, false}, {3.0, true}, {3.1, true}, {0.0, false}, {10.0, true},
	}
	for _, tc := range cases {
		if got := ShouldTriggerChain(baselinePkg(tc.sigma)); got != tc.want {
			t.Errorf("sigma %v: got %v, want %v", tc.sigma, got, tc.want)
		}
	}
}

func TestShouldTriggerChainMalformedSigmaNotCounted(t *testing.T) {
	// NaN/Inf/negative sigma is structurally invalid and must never
	// count toward the gate (parity with score.Calculator.Score).
	for _, bad := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), -5.0} {
		if ShouldTriggerChain(baselinePkg(bad)) {
			t.Errorf("malformed sigma %v should not trigger", bad)
		}
	}
}

func TestShouldTriggerChainNonNumericSeverityNotCounted(t *testing.T) {
	pkg := schema.EvidencePackage{
		RuleMatches: []schema.RuleMatch{{RuleID: "r1", Severity: "critical", EventID: "evt-1"}},
	}
	if ShouldTriggerChain(pkg) {
		t.Error("non-numeric severity must not trigger (Atoi, not keyword bucket)")
	}
}

func TestShouldTriggerChainEmptyPackage(t *testing.T) {
	if ShouldTriggerChain(schema.EvidencePackage{}) {
		t.Error("empty package must not trigger")
	}
}

func TestShouldTriggerChainMultiSignalOnlyDoesNotTrigger(t *testing.T) {
	// A multi-signal trigger carries neither a rule match nor a baseline
	// deviation (assembler.go); FR19 is a rule-or-baseline gate, so a
	// bare multi-signal correlation must not trip it.
	pkg := schema.EvidencePackage{
		Events: []schema.Event{{}, {}},
	}
	if ShouldTriggerChain(pkg) {
		t.Error("multi-signal-only package (no rule, no baseline) must not trigger")
	}
}

func TestShouldTriggerChainMultiElementFirstQualifies(t *testing.T) {
	// A qualifying element anywhere in the slice triggers, even behind
	// non-qualifying ones.
	pkg := schema.EvidencePackage{
		RuleMatches: []schema.RuleMatch{
			{RuleID: "low", Severity: "10", EventID: "evt-1"},
			{RuleID: "high", Severity: "80", EventID: "evt-2"},
		},
	}
	if !ShouldTriggerChain(pkg) {
		t.Error("a qualifying rule match behind a low one must still trigger")
	}
	pkg2 := schema.EvidencePackage{
		BaselineDeviations: []schema.BaselineDeviation{
			{Metric: "cpu", Sigma: 1.0, PodUID: "p1"},
			{Metric: "mem", Sigma: 4.0, PodUID: "p2"},
		},
	}
	if !ShouldTriggerChain(pkg2) {
		t.Error("a qualifying baseline deviation behind a low one must still trigger")
	}
}
