package main

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/olokotoh/olaitan/internal/decision/analyst"
)

// TestApplyPromptVersionGauge proves the Story 3.15 info-gauge maintenance:
// seeding lights {role,hash}=1, and a reload retires the old series and lights
// the new one, so exactly ONE series per role is live (no cardinality creep).
func TestApplyPromptVersionGauge(t *testing.T) {
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "olaitan_llm_prompt_version", Help: "t"}, []string{"role", "hash"})

	// Seed l1, l2, senior (oldHash="" => pure set, no delete).
	applyPromptVersionGauge(g, "l1", "", "h1")
	applyPromptVersionGauge(g, "l2", "", "hL2")
	applyPromptVersionGauge(g, "senior", "", "hS")
	if n := testutil.CollectAndCount(g); n != 3 {
		t.Fatalf("after seed: %d series, want 3 (one per role)", n)
	}
	if v := testutil.ToFloat64(g.WithLabelValues("l1", "h1")); v != 1 {
		t.Errorf("l1/h1 = %v, want 1", v)
	}

	// Reload l1 h1 -> h2: old retired, new lit; still one series for l1.
	applyPromptVersionGauge(g, "l1", "h1", "h2")
	if n := testutil.CollectAndCount(g); n != 3 {
		t.Errorf("after l1 reload: %d series, want 3 (old l1 series retired)", n)
	}
	if v := testutil.ToFloat64(g.WithLabelValues("l1", "h2")); v != 1 {
		t.Errorf("l1/h2 = %v, want 1", v)
	}

	// A no-op reload (same hash) must not delete-then-recreate spuriously.
	applyPromptVersionGauge(g, "l2", "hL2", "hL2")
	if v := testutil.ToFloat64(g.WithLabelValues("l2", "hL2")); v != 1 {
		t.Errorf("l2/hL2 after no-op = %v, want 1", v)
	}
	if n := testutil.CollectAndCount(g); n != 3 {
		t.Errorf("after no-op: %d series, want 3", n)
	}
}

// TestCapViolationMetricIsFR50Name pins the Story 3.15 rename: the cap-violation
// counter is exposed under FR50's canonical olaitan_llm_cap_violation_total
// (not the old olaitan_decision_llm_cap_violation_total).
func TestCapViolationMetricIsFR50Name(t *testing.T) {
	if analyst.CapViolationMetricName != "olaitan_llm_cap_violation_total" {
		t.Errorf("CapViolationMetricName = %q, want olaitan_llm_cap_violation_total (FR50)", analyst.CapViolationMetricName)
	}
}
