package risk

import (
	"math"
	"strconv"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/decision/score"
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
	w.Observe("wl", rulePkg("wl", "90"), 0, now)
	rules, devs, _ := w.Observe("wl", devPkg("wl", 6), 30, now.Add(2*time.Second))
	if len(rules) != 1 || len(devs) != 1 {
		t.Fatalf("aggregate must carry both signals, got rules=%d devs=%d", len(rules), len(devs))
	}
	if rules[0].Severity != "90" || devs[0].Sigma != 6 {
		t.Fatalf("aggregate lost the strongest signals: %+v %+v", rules[0], devs[0])
	}
}

// TestObserve_SustainedTrafficStillDecays pins the PR #92 review fix: a
// retained signal expires TTL after ITS OWN observation, even when unrelated
// packages keep arriving for the workload. Under the previous single
// updatedAt, every package refreshed the whole entry's TTL, so a critical rule
// never decayed while any traffic flowed and de-escalation was blocked.
func TestObserve_SustainedTrafficStillDecays(t *testing.T) {
	w := New(30 * time.Second)
	now := time.Unix(9000, 0)
	w.Observe("wl", rulePkg("wl", "90"), 0, now)
	// Signal-less packages keep arriving every 10s past the rule's TTL.
	for i := 1; i <= 4; i++ {
		rules, _, _ := w.Observe("wl", schema.EvidencePackage{WorkloadID: "wl"}, 0, now.Add(time.Duration(10*i)*time.Second))
		if i <= 3 && len(rules) != 1 {
			// At 10s/20s/30s the rule (age <= TTL) must still be present.
			t.Fatalf("t+%ds: rule should still be live, got %d", 10*i, len(rules))
		}
		if i == 4 && len(rules) != 0 {
			// At 40s the rule is older than TTL and must be gone despite the
			// intervening traffic.
			t.Fatalf("t+40s: rule should have decayed under sustained traffic, got %d", len(rules))
		}
	}
}

// TestObserve_KeywordSeverityNeverDisplacesNumeric pins the severity-semantics
// alignment with the score calculator: the calculator scores non-numeric
// severities as zero, so a keyword match must never displace a numeric match
// as "strongest" (that would zero the aggregate's rule term).
func TestObserve_KeywordSeverityNeverDisplacesNumeric(t *testing.T) {
	w := New(60 * time.Second)
	now := time.Unix(9500, 0)
	w.Observe("wl", rulePkg("wl", "75"), 0, now)
	rules, _, _ := w.Observe("wl", rulePkg("wl", "critical"), 0, now.Add(time.Second))
	if len(rules) != 1 || rules[0].Severity != "75" {
		t.Fatalf("numeric 75 must survive a keyword challenger, got %+v", rules)
	}
	// A keyword-only history stores nothing; the package's own matches pass
	// through so solo-scoring parity is preserved.
	rules, _, _ = w.Observe("wl2", rulePkg("wl2", "critical"), 0, now)
	if len(rules) != 1 || rules[0].Severity != "critical" {
		t.Fatalf("keyword-only package should pass through unchanged, got %+v", rules)
	}
}

// TestObserve_SignallessPackagesDoNotGrowMap pins the eviction fix: packages
// with no signals create no entries, and entries whose signals all expired are
// swept, so churned workload IDs cannot grow the map without bound.
func TestObserve_SignallessPackagesDoNotGrowMap(t *testing.T) {
	w := New(10 * time.Second)
	now := time.Unix(10000, 0)
	for i := 0; i < 100; i++ {
		wl := "churn-" + strconv.Itoa(i)
		w.Observe(wl, schema.EvidencePackage{WorkloadID: wl}, 0, now)
	}
	if n := len(w.m); n != 0 {
		t.Fatalf("signal-less packages must not create entries, map has %d", n)
	}
	// Real signals for churned workloads expire and are swept once TTL passes.
	for i := 0; i < 50; i++ {
		wl := "sig-" + strconv.Itoa(i)
		w.Observe(wl, rulePkg(wl, "75"), 0, now)
	}
	w.Observe("late", rulePkg("late", "50"), 0, now.Add(25*time.Second))
	if n := len(w.m); n != 1 {
		t.Fatalf("expired entries must be swept, map has %d (want 1)", n)
	}
}

// TestObserve_MalformedSigmaSkipped mirrors the score calculator's poisoned-
// sigma guard: NaN/Inf/negative sigmas must never become the retained
// strongest deviation.
func TestObserve_MalformedSigmaSkipped(t *testing.T) {
	w := New(60 * time.Second)
	now := time.Unix(11000, 0)
	w.Observe("wl", devPkg("wl", 4), 0, now)
	_, devs, _ := w.Observe("wl", devPkg("wl", math.Inf(1)), 0, now.Add(time.Second))
	if len(devs) != 1 || devs[0].Sigma != 4 {
		t.Fatalf("Inf sigma must not displace the real deviation, got %+v", devs)
	}
	_, devs, _ = w.Observe("wl", devPkg("wl", math.NaN()), 0, now.Add(2*time.Second))
	if len(devs) != 1 || devs[0].Sigma != 4 {
		t.Fatalf("NaN sigma must not displace the real deviation, got %+v", devs)
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
	w.Observe("a", rulePkg("a", "90"), 0, now)
	rules, devs, _ := w.Observe("b", devPkg("b", 5), 0, now)
	if len(rules) != 0 || len(devs) != 1 {
		t.Fatalf("workload b must not inherit a's rule, got rules=%d devs=%d", len(rules), len(devs))
	}
}

// TestWindow_SumsAcrossPackagesCrossesThresholds is the proof of the fix: a
// rule-only package then a baseline-only package for the SAME workload (the two
// separate single-signal packages the rules and baseline engines fire) score,
// through the risk window, as ONE aggregate that crosses the RESTRICTED and
// QUARANTINED bands, which no single package could. Deterministic, no cluster.
func TestWindow_SumsAcrossPackagesCrossesThresholds(t *testing.T) {
	calc, err := score.New(nil, nil) // FR30 defaults: 0.4/0.3/0.3, llm_cap 35, thresholds 20/40/70
	if err != nil {
		t.Fatalf("score.New: %v", err)
	}
	w := New(60 * time.Second)
	now := time.Unix(5000, 0)
	wl := "tenant/Deployment/web"

	score1 := func(pkg schema.EvidencePackage, llm int, at time.Time) float64 {
		r, d, l := w.Observe(wl, pkg, llm, at)
		agg := pkg
		agg.RuleMatches, agg.BaselineDeviations = r, d
		sc, serr := calc.Score(&agg, l)
		if serr != nil {
			t.Fatalf("Score: %v", serr)
		}
		return sc.Total
	}

	// 1) A high-severity rule alone: SUSPICIOUS band only (>=20, <40).
	ruleOnly := schema.EvidencePackage{WorkloadID: wl, RuleMatches: []schema.RuleMatch{{RuleID: "OLT-EXEC-001", Severity: "75"}}}
	s1 := score1(ruleOnly, 0, now)
	if s1 < 20 || s1 >= 40 {
		t.Fatalf("rule-only score = %.1f, want SUSPICIOUS band [20,40)", s1)
	}

	// 2) A baseline deviation (>=3 sigma) then arrives for the same workload,
	// plus the capped LLM term: the aggregate now sums rule + baseline + llm and
	// reaches RESTRICTED (>=40) which neither signal alone could.
	baseOnly := schema.EvidencePackage{WorkloadID: wl, BaselineDeviations: []schema.BaselineDeviation{{Metric: "outbound_unique_dst_ips", Sigma: 3.8}}}
	s2 := score1(baseOnly, 30, now.Add(2*time.Second))
	if s2 < 40 {
		t.Fatalf("rule+baseline+llm aggregate = %.1f, want >= RESTRICTED (40); the signals did not sum", s2)
	}
	if s2 <= s1 {
		t.Fatalf("aggregate %.1f must exceed the single-signal score %.1f", s2, s1)
	}

	// 3) A CRITICAL rule (severity 100) with the baseline + llm reaches
	// QUARANTINED (>=70): the graduated-response ceiling a severe sustained
	// multi-signal attack should hit.
	crit := schema.EvidencePackage{WorkloadID: wl, RuleMatches: []schema.RuleMatch{{RuleID: "OLT-PRIV-001", Severity: "100"}}}
	s3 := score1(crit, 30, now.Add(4*time.Second))
	if s3 < 70 {
		t.Fatalf("critical rule + baseline + llm aggregate = %.1f, want >= QUARANTINED (70)", s3)
	}
}
