package score

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"

	"github.com/olokotoh/olaitan/internal/config"
	"github.com/olokotoh/olaitan/internal/schema"
)

// pinnedParams returns gopter parameters with a fixed seed so property
// suites are flake-free across runs (Story 1.17 retrospective lesson:
// unseeded gopter runs flake on adversarial generators).
func pinnedParams() *gopter.TestParameters {
	p := gopter.DefaultTestParameters()
	p.Rng.Seed(42)
	p.MinSuccessfulTests = 200
	return p
}

// makePkg builds an EvidencePackage with the supplied severity ints and
// sigma floats. Used by the monotonicity properties that need to
// generate paired inputs deterministically.
func makePkg(sevs []int, sigmas []float64) *schema.EvidencePackage {
	pkg := &schema.EvidencePackage{}
	for _, s := range sevs {
		pkg.RuleMatches = append(pkg.RuleMatches, schema.RuleMatch{
			Severity: strconv.Itoa(s),
		})
	}
	for _, s := range sigmas {
		pkg.BaselineDeviations = append(pkg.BaselineDeviations, schema.BaselineDeviation{
			Sigma: s,
		})
	}
	return pkg
}

// TestProperty_ScoreInRange pins architecture.md:387 line (a): the
// computed Total never escapes [0, 100] for arbitrary in-range inputs.
func TestProperty_ScoreInRange(t *testing.T) {
	c := newCalcForTest(t, staticGetter(defaultScoreCfg()))

	props := gopter.NewProperties(pinnedParams())
	props.Property("0 <= Total <= 100 for any in-range package", prop.ForAll(
		func(sevs []int, sigmas []float64) bool {
			pkg := makePkg(sevs, sigmas)
			got, err := c.Score(pkg)
			if err != nil {
				return false
			}
			return got.Total >= 0 && got.Total <= 100
		},
		gen.SliceOf(gen.IntRange(0, 100)),
		gen.SliceOf(gen.Float64Range(0, 10)),
	))
	props.TestingRun(t)
}

// TestProperty_NoLLMOnlyEscalation is the algebraic trust-bound:
// max(LLM-only) = LLMWeight * LLMCap must stay below the SUSPICIOUS
// threshold (20, prd.md:294) so the LLM tier alone can never escalate a
// workload.
//
// Epic 2 hard-zeroes the runtime LLM term (score.go: llm = LLMWeight*0),
// so asserting on Score().Total alone is vacuous -- it is identically 0
// for an LLM-only package regardless of the cap, and the original
// assertion `Total < 20` therefore proved nothing (it passed even with
// llm_cap=100). This rewrite pins the real ceiling two ways:
//
//  1. The algebraic ceiling LLMWeight*LLMCap of the resolved config is
//     computed directly and asserted below the threshold -- this is the
//     value the runtime term will reach once Epic 3 (epics.md:1589)
//     populates it, so the test is non-vacuous and cap-sensitive.
//  2. The runtime LLM-only Score().Total never exceeds that ceiling
//     today (it is 0 <= ceiling), confirming the term is still zeroed.
//
// Enforcement of the ceiling across the whole operator-tunable config
// space lives in ScoreConfig.validate (config package:
// TestScoreValidateRejectsTrustBoundViolation). The FR55 empirical
// counterpart is the Epic 5 adversarial-LLM experiment.
func TestProperty_NoLLMOnlyEscalation(t *testing.T) {
	c := newCalcForTest(t, staticGetter(scoreCfg(0.4, 0.3, 0.3, 35)))

	snap := c.Snapshot()
	ceiling := snap.LLMWeight * snap.LLMCap
	if ceiling >= config.SuspiciousThreshold {
		t.Fatalf("trust-bound: LLMWeight*LLMCap = %v, want < %v (SUSPICIOUS)", ceiling, config.SuspiciousThreshold)
	}

	props := gopter.NewProperties(pinnedParams())
	props.Property("runtime LLM-only Total stays within the algebraic ceiling and below SUSPICIOUS", prop.ForAll(
		func(_ int) bool {
			got, err := c.Score(&schema.EvidencePackage{})
			if err != nil {
				return false
			}
			return got.Total <= ceiling && got.Total < config.SuspiciousThreshold
		},
		gen.IntRange(0, 1000),
	))
	props.TestingRun(t)
}

// TestProperty_MonotonicInRuleSeverity sanity-checks AC4: for two
// packages where set B's max rule severity dominates set A's max,
// Score(B).Total >= Score(A).Total when other inputs match.
func TestProperty_MonotonicInRuleSeverity(t *testing.T) {
	c := newCalcForTest(t, staticGetter(defaultScoreCfg()))

	props := gopter.NewProperties(pinnedParams())
	props.Property("higher max-severity rule set produces >= Total", prop.ForAll(
		func(a, b int) bool {
			if a > b {
				a, b = b, a
			}
			pkgA := makePkg([]int{a, a / 2}, []float64{})
			pkgB := makePkg([]int{b, b / 2}, []float64{})
			sA, errA := c.Score(pkgA)
			sB, errB := c.Score(pkgB)
			if errA != nil || errB != nil {
				return false
			}
			return sB.Total >= sA.Total
		},
		gen.IntRange(0, 100),
		gen.IntRange(0, 100),
	))
	props.TestingRun(t)
}

// TestProperty_MonotonicInBaselineSigma sanity-checks AC5: a higher
// max sigma produces a >= Total when other inputs match.
func TestProperty_MonotonicInBaselineSigma(t *testing.T) {
	c := newCalcForTest(t, staticGetter(defaultScoreCfg()))

	props := gopter.NewProperties(pinnedParams())
	props.Property("higher max-sigma deviation set produces >= Total", prop.ForAll(
		func(a, b float64) bool {
			if a > b {
				a, b = b, a
			}
			pkgA := makePkg([]int{}, []float64{a, a / 2})
			pkgB := makePkg([]int{}, []float64{b, b / 2})
			sA, errA := c.Score(pkgA)
			sB, errB := c.Score(pkgB)
			if errA != nil || errB != nil {
				return false
			}
			return sB.Total >= sA.Total
		},
		gen.Float64Range(0, 10),
		gen.Float64Range(0, 10),
	))
	props.TestingRun(t)
}

// TestProperty_DeterministicForFixedSnapshot pins Task 2.5: two
// invocations with a fixed config snapshot yield identical
// ConfidenceScore values for any in-range input.
func TestProperty_DeterministicForFixedSnapshot(t *testing.T) {
	c := newCalcForTest(t, staticGetter(defaultScoreCfg()))

	props := gopter.NewProperties(pinnedParams())
	props.Property("Score is referentially transparent for a fixed snapshot", prop.ForAll(
		func(sevs []int, sigmas []float64) bool {
			pkg := makePkg(sevs, sigmas)
			a, errA := c.Score(pkg)
			b, errB := c.Score(pkg)
			if errA != nil || errB != nil {
				return false
			}
			return a == b
		},
		gen.SliceOf(gen.IntRange(0, 100)),
		gen.SliceOf(gen.Float64Range(0, 10)),
	))
	props.TestingRun(t)
}

// TestProperty_HotReloadViaSubscribe exercises the full fsnotify hot-
// reload path against a real *config.Manager backed by a t.TempDir
// YAML file. AC2 production path: helm upgrade --set
// detection.score.ruleWeight=0.5 writes the file, fsnotify fires, the
// 50 ms debounce window expires (per internal/config/watcher.go:24),
// the atomic snapshot swaps, and the next Score() call observes the
// new weight.
//
// This is an integration-style test (no mocking per NFR36); the 50 ms
// debounce is the reason the polling deadline below is 2 s.
func TestProperty_HotReloadViaSubscribe(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "olaitan.yaml")

	writeCfg := func(rw, bw, lw float64) {
		body := minimalConfigYAML(rw, bw, lw)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
	}

	writeCfg(0.4, 0.3, 0.3)
	mgr, err := config.NewManager(path, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		_ = mgr.Watch(ctx)
		close(done)
	}()

	c, err := New(mgr, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	pkg := &schema.EvidencePackage{RuleMatches: []schema.RuleMatch{{Severity: "100"}}}
	got, err := c.Score(pkg)
	if err != nil {
		t.Fatalf("first Score: %v", err)
	}
	if got.Rules != 40 {
		t.Fatalf("initial Rules: want 40, got %v", got.Rules)
	}

	// Allow Watch goroutine to register its inotify watch on the
	// parent directory before we trigger the reload write; a race
	// here would have the rewrite fire before fsnotify is armed.
	time.Sleep(100 * time.Millisecond)
	writeCfg(0.5, 0.3, 0.2)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		s, err := c.Score(pkg)
		if err != nil {
			t.Fatalf("poll Score: %v", err)
		}
		if s.Rules == 50 {
			cancel()
			<-done
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	cancel()
	<-done
	t.Fatalf("hot-reload: Rules never reached 50 within 3s")
}

// minimalConfigYAML produces a valid Olaitan config with the supplied
// score weights, keeping every other detection/response/analyst/metrics
// block at production defaults so Load+Validate succeed. The caller
// must keep rw+bw+lw <= 1.0 to avoid the trust-bound rejection in
// ScoreConfig.validate.
func minimalConfigYAML(rw, bw, lw float64) string {
	return `detection:
  confidence_bands:
    watch: 10
    alert: 20
    act: 60
  baseline_window: "1h"
  correlator:
    window_duration: "60s"
  posture:
    enabled: false
  rules:
    enabled: false
  baselines:
    enabled: false
  score:
    rule_weight: ` + strconv.FormatFloat(rw, 'f', -1, 64) + `
    baseline_weight: ` + strconv.FormatFloat(bw, 'f', -1, 64) + `
    llm_weight: ` + strconv.FormatFloat(lw, 'f', -1, 64) + `
    llm_cap: 35
metrics:
  address: ":9090"
rate_limit:
  enabled: false
response:
  excluded_namespaces:
    - kube-system
analyst:
  provider: none
  timeout: 10s
  score_cap: 35
`
}
