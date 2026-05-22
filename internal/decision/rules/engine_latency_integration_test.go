//go:build integration

package rules

import (
	"io"
	"log/slog"
	"sort"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/decision/rules/loader"
)

// TestIntegration_RulesEngineLatencyBudget is the AC3 latency gate.
// Renamed from TestRulesEngineLatencyBudget (code-review P4) so the
// integration build tag actually isolates it from the default
// go-test sweep, matching the spec's AC3 phrasing. The gate drives
// the engine's real evaluatePackage entry point (code-review P5) so
// per-event resolver construction is included in the measured cost,
// rather than the prior shortcut that hoisted a single resolver
// outside the timed loop. Samples each fixture 1000 times and
// asserts p99 is within the NFR3 100 ms budget.
func TestIntegration_RulesEngineLatencyBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("latency gate skipped under -short")
	}

	dir := t.TempDir()
	build50RuleCorpus(t, dir)
	l := loader.New(dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := l.Load(); err != nil {
		t.Fatalf("loader.Load: %v", err)
	}
	corpus := l.Get()

	// Construct a minimal Engine: evaluatePackage only reaches
	// e.log and e.evalError, not NATS or the emitter, so a bare
	// struct with a discard logger is enough for the latency
	// measurement.
	eng := &Engine{
		loader: l,
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	const samples = 1000
	const budget = 100 * time.Millisecond

	for _, fx := range benchFixtures() {
		fx := fx
		t.Run(fx.name, func(t *testing.T) {
			pkg := loadFixture(t, fx.path)

			// Warm-up: 100 untimed iterations so steady-state branch
			// prediction and allocator behaviour stabilise.
			for i := 0; i < 100; i++ {
				_ = eng.evaluatePackage(pkg, corpus)
			}

			ts := make([]time.Duration, samples)
			for i := 0; i < samples; i++ {
				start := time.Now()
				_ = eng.evaluatePackage(pkg, corpus)
				ts[i] = time.Since(start)
			}
			sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
			p50 := ts[(samples-1)/2]
			p99 := ts[(samples-1)*99/100]

			t.Logf("[fixture=%s] p50=%s p99=%s (50 rules; NFR3 budget=%s; path: Engine.evaluatePackage)",
				fx.name, p50, p99, budget)
			if p99 > budget {
				t.Errorf("p99 %s exceeds NFR3 budget %s", p99, budget)
			}
		})
	}

	// Sanity: ensure the absolute path resolution did not silently
	// produce an empty corpus (otherwise the gate above is vacuous).
	if corpus == nil || corpus.Len() != 50 {
		t.Fatalf("corpus.Len = %d, want 50 (sanity check; latency gate is vacuous without a populated corpus)",
			corpus.Len())
	}
}
