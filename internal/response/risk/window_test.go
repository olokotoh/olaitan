package risk

import (
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/schema"
)

func rulePkg(wl, sev string) schema.EvidencePackage {
	return schema.EvidencePackage{WorkloadID: wl, RuleMatches: []schema.RuleMatch{{RuleID: "r", Severity: sev}}}
}
func devPkg(wl string, sigma float64) schema.EvidencePackage {
	return schema.EvidencePackage{WorkloadID: wl, BaselineDeviations: []schema.BaselineDeviation{{Metric: "m", Sigma: sigma}}}
}

func TestObserve_DisabledIsPassThrough(t *testing.T) {
	var w *Window // nil is disabled
	r, d, llm := w.Observe("wl", rulePkg("wl", "critical"), 30, time.Now())
	if len(r) != 1 || len(d) != 0 || llm != 30 {
		t.Fatalf("nil window should pass through the package unchanged, got rules=%d devs=%d llm=%d", len(r), len(d), llm)
	}
	w0 := New(0)
	r, d, _ = w0.Observe("wl", devPkg("wl", 5), 0, time.Now())
	if len(r) != 0 || len(d) != 1 {
		t.Fatalf("zero-ttl window should pass through, got rules=%d devs=%d", len(r), len(d))
	}
}

func TestObserve_SumsRuleAndBaselineWithinWindow(t *testing.T) {
	w := New(60 * time.Second)
	now := time.Unix(1000, 0)
	// A rule-only package, then a baseline-only package for the SAME workload
	// arrive within the window (the two separate single-signal packages the
	// rules and baseline engines fire). The aggregate must carry BOTH.
	w.Observe("wl", rulePkg("wl", "critical"), 0, now)
	rules, devs, _ := w.Observe("wl", devPkg("wl", 6), 30, now.Add(2*time.Second))
	if len(rules) != 1 || len(devs) != 1 {
		t.Fatalf("aggregate must carry both signals, got rules=%d devs=%d", len(rules), len(devs))
	}
	if rules[0].Severity != "critical" || devs[0].Sigma != 6 {
		t.Fatalf("aggregate lost the strongest signals: %+v %+v", rules[0], devs[0])
	}
}

func TestObserve_KeepsStrongestAndDecays(t *testing.T) {
	w := New(30 * time.Second)
	now := time.Unix(2000, 0)
	w.Observe("wl", devPkg("wl", 4), 0, now)
	_, devs, _ := w.Observe("wl", devPkg("wl", 9), 0, now.Add(time.Second))
	if devs[0].Sigma != 9 {
		t.Fatalf("should keep the strongest sigma, got %v", devs[0].Sigma)
	}
	// After the TTL elapses the aggregate resets: a weaker later signal must not
	// still see the old strong one.
	_, devs, _ = w.Observe("wl", devPkg("wl", 4), 0, now.Add(40*time.Second))
	if devs[0].Sigma != 4 {
		t.Fatalf("aggregate should have decayed, got %v", devs[0].Sigma)
	}
}

func TestObserve_IsolatesWorkloads(t *testing.T) {
	w := New(60 * time.Second)
	now := time.Unix(3000, 0)
	w.Observe("a", rulePkg("a", "critical"), 0, now)
	rules, devs, _ := w.Observe("b", devPkg("b", 5), 0, now)
	if len(rules) != 0 || len(devs) != 1 {
		t.Fatalf("workload b must not inherit a's rule, got rules=%d devs=%d", len(rules), len(devs))
	}
}
