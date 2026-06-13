package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/olokotoh/olaitan/internal/agent/prompts"
	"github.com/olokotoh/olaitan/internal/decision/analyst"
	"github.com/olokotoh/olaitan/internal/metrics"
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
// counter is exposed under FR50's canonical olaitan_llm_cap_violation_total and
// the old olaitan_decision_llm_cap_violation_total name is GONE from the
// registry (a gather-based guard, not just a const check).
func TestCapViolationMetricIsFR50Name(t *testing.T) {
	const oldName = "olaitan_decision_llm_cap_violation_total"
	if analyst.CapViolationMetricName != "olaitan_llm_cap_violation_total" {
		t.Errorf("CapViolationMetricName = %q, want olaitan_llm_cap_violation_total (FR50)", analyst.CapViolationMetricName)
	}
	reg := metrics.NewRegistry()
	vec, err := analyst.RegisterCapViolationMetric(reg)
	if err != nil {
		t.Fatalf("register cap-violation metric: %v", err)
	}
	// Materialise the labelless series so the family is emitted by Gather.
	vec.WithLabelValues().Inc()
	mfs, err := reg.Gatherer().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	var sawNew bool
	for _, mf := range mfs {
		if mf.GetName() == oldName {
			t.Errorf("the renamed-away metric %q is still registered", oldName)
		}
		if mf.GetName() == "olaitan_llm_cap_violation_total" {
			sawNew = true
		}
	}
	if !sawNew {
		t.Error("olaitan_llm_cap_violation_total not present in the registry")
	}
}

// TestPromptVersionGaugeReloadWiring exercises the Story 3.15 cmd wiring
// end-to-end: the seed loop lights one series per chain role, and a real
// prompt-store reload (driving the same Subscribe callback main.go installs)
// flips the gauge to the new {role,hash} while retiring the old, so exactly
// one series per role stays live.
func TestPromptVersionGaugeReloadWiring(t *testing.T) {
	dir := t.TempDir()
	for _, r := range prompts.Roles() {
		if err := os.WriteFile(filepath.Join(dir, string(r)+".txt"), []byte(string(r)+" v1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	store := prompts.New(dir, nil)
	if err := store.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "olaitan_llm_prompt_version", Help: "t"}, []string{"role", "hash"})

	// Replicate the production seed + reload wiring (main.go).
	chainRoles := []prompts.Role{prompts.RoleL1, prompts.RoleL2, prompts.RoleSenior}
	prev := store.Get()
	for _, role := range chainRoles {
		applyPromptVersionGauge(gauge, string(role), "", prev.Hash(role))
	}
	store.Subscribe(func(set *prompts.Set) {
		for _, role := range chainRoles {
			if oldH, newH := prev.Hash(role), set.Hash(role); oldH != newH {
				applyPromptVersionGauge(gauge, string(role), oldH, newH)
			}
		}
		prev = set
	})

	if n := testutil.CollectAndCount(gauge); n != 3 {
		t.Fatalf("after seed: %d series, want 3 (one per chain role)", n)
	}
	l1v1 := store.Get().Hash(prompts.RoleL1)
	if v := testutil.ToFloat64(gauge.WithLabelValues("l1", l1v1)); v != 1 {
		t.Errorf("seeded l1 series = %v, want 1", v)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- store.Watch(ctx) }()
	time.Sleep(50 * time.Millisecond)

	// Edit l1; the watcher reload must flip the gauge.
	if err := os.WriteFile(filepath.Join(dir, "l1.txt"), []byte("l1 v2 CHANGED\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(3 * time.Second)
	for {
		cur := store.Get().Hash(prompts.RoleL1)
		if cur != l1v1 && testutil.ToFloat64(gauge.WithLabelValues("l1", cur)) == 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("prompt-version gauge did not flip after reload")
		case <-time.After(25 * time.Millisecond):
		}
	}
	// Still exactly one series per role (old l1 retired).
	if n := testutil.CollectAndCount(gauge); n != 3 {
		t.Errorf("after reload: %d series, want 3 (old l1 series retired)", n)
	}
	cancel()
	if werr := <-done; werr != nil {
		t.Errorf("Watch: %v", werr)
	}
}
