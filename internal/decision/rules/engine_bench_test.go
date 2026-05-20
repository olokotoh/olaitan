package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	sigma "github.com/runreveal/sigmalite"

	"github.com/olokotoh/olaitan/internal/decision/rules/loader"
	"github.com/olokotoh/olaitan/internal/decision/rules/matcher"
	"github.com/olokotoh/olaitan/internal/decision/rules/parser"
	"github.com/olokotoh/olaitan/internal/schema"
)

// build50RuleCorpus mutates the spike POC's OLT-IMPACT-005 anchor
// 50 times to produce a 50-rule corpus, one per OLT-IMPACT-NNN ID in
// [100, 149]. Pattern matches the spike's mutateID (anchor "id:
// OLT-IMPACT-005"); the loader's by-ID index rejects duplicates so a
// mutation failure surfaces as a load error.
func build50RuleCorpus(b testing.TB, dir string) {
	b.Helper()
	src, err := os.ReadFile(filepath.Join("testdata", "positive", "OLT-IMPACT-005.yaml"))
	if err != nil {
		b.Fatalf("read source rule: %v", err)
	}
	const anchor = "id: OLT-IMPACT-005"
	if !strings.Contains(string(src), anchor) {
		b.Fatalf("anchor %q not present in source rule; bench cannot mutate", anchor)
	}
	for n := 0; n < 50; n++ {
		newID := fmt.Sprintf("id: OLT-IMPACT-%03d", 100+n)
		mutated := strings.Replace(string(src), anchor, newID, 1)
		out := filepath.Join(dir, fmt.Sprintf("olt-impact-%03d.yaml", 100+n))
		if err := os.WriteFile(out, []byte(mutated), 0o600); err != nil {
			b.Fatalf("write mutated rule %d: %v", n, err)
		}
	}
}

// loadFixture parses one of the four spike-inherited JSON fixtures
// (positive, negative_namespace, negative_process,
// negative_missing_process) into an EvidencePackage. We flatten the
// JSON into the package's first event's Raw blob so the engine's
// EventFields projection finds the streaming fields, and we route
// the k8s.* keys onto a synthesised WorkloadPosture so the matcher's
// posture half is exercised.
func loadFixture(b testing.TB, fixtureFile string) *schema.EvidencePackage {
	b.Helper()
	data, err := os.ReadFile(fixtureFile)
	if err != nil {
		b.Fatalf("read fixture %s: %v", fixtureFile, err)
	}
	var flat map[string]any
	if err := json.Unmarshal(data, &flat); err != nil {
		b.Fatalf("decode fixture: %v", err)
	}

	posture := &schema.WorkloadPosture{Identity: schema.WorkloadIdentity{}}
	streaming := map[string]any{}
	for k, v := range flat {
		if strings.HasPrefix(strings.ToLower(k), "k8s.") {
			switch strings.ToLower(k) {
			case "k8s.pod.namespace":
				posture.Identity.Namespace = fmt.Sprintf("%v", v)
			case "k8s.workload.owner_kind":
				posture.Identity.OwnerKind = fmt.Sprintf("%v", v)
			case "k8s.workload.owner_name":
				posture.Identity.OwnerName = fmt.Sprintf("%v", v)
			}
		} else {
			streaming[k] = v
		}
	}
	raw, _ := json.Marshal(streaming)
	return &schema.EvidencePackage{
		PackageID:       "bench-pkg",
		WorkloadID:      "bench/Deployment/bench",
		WorkloadPosture: posture,
		Events: []schema.Event{
			{ID: "bench-ev", Source: schema.SourceFalco, Category: schema.CategorySyscall, Raw: raw},
		},
	}
}

// evaluateOnceForBench reproduces the engine's hot-path evaluation
// without the JetStream consumer plumbing. opts is hoisted outside
// the timed loop per ADR-2026-04-28-01 Performance section.
func evaluateOnceForBench(rules []*parser.Rule, entry *sigma.LogEntry, opts *sigma.MatchOptions) int {
	hits := 0
	for _, r := range rules {
		if r.Detection == nil {
			continue
		}
		if r.Detection.Matches(entry, opts) {
			hits++
		}
	}
	return hits
}

type fixtureRef struct {
	name string
	path string
}

func bgnchFixtures() []fixtureRef {
	return []fixtureRef{
		{"positive", filepath.Join("testdata", "positive", "positive.json")},
		{"negative_namespace", filepath.Join("testdata", "negative", "negative_namespace.json")},
		{"negative_process", filepath.Join("testdata", "negative", "negative_process.json")},
		{"negative_missing_process", filepath.Join("testdata", "negative", "negative_missing_process.json")},
	}
}

// BenchmarkRulesEngine_PerPackageLatency runs the AC3 50-rule
// per-fixture latency rough cut. Per-fixture p50 and p99 are reported
// so match-path and short-circuit-miss-path latencies are not
// conflated (per the ADR's hand-off + the spike POC's runBench).
func BenchmarkRulesEngine_PerPackageLatency(b *testing.B) {
	dir := b.TempDir()
	build50RuleCorpus(b, dir)
	l := loader.New(dir, nil)
	if err := l.Load(); err != nil {
		b.Fatalf("loader.Load: %v", err)
	}
	rules := l.Get().Rules

	for _, fx := range bgnchFixtures() {
		fx := fx
		b.Run(fx.name, func(b *testing.B) {
			pkg := loadFixture(b, fx.path)
			ev := pkg.Events[0]
			resolver, entry, err := matcher.NewResolver(pkg.WorkloadPosture, matcher.EventFields(ev))
			if err != nil {
				b.Fatalf("NewResolver: %v", err)
			}
			// Hoist MatchOptions outside the timed loop per
			// ADR-2026-04-28-01 Performance.
			opts := &sigma.MatchOptions{FieldResolver: resolver}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = evaluateOnceForBench(rules, entry, opts)
			}
		})
	}
}

// TestRulesEngineLatencyBudget is the integration-tag latency gate
// for AC3. It samples each fixture 1000 times and asserts p99 is
// within the NFR3 100 ms budget. Per-fixture p50 / p99 are reported
// so the hand-off into Story 1.16 / 1.17 has fresh numbers.
func TestRulesEngineLatencyBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("latency gate skipped under -short")
	}

	dir := t.TempDir()
	build50RuleCorpus(t, dir)
	l := loader.New(dir, nil)
	if err := l.Load(); err != nil {
		t.Fatalf("loader.Load: %v", err)
	}
	rules := l.Get().Rules

	const samples = 1000
	const budget = 100 * time.Millisecond

	for _, fx := range bgnchFixtures() {
		fx := fx
		t.Run(fx.name, func(t *testing.T) {
			pkg := loadFixture(t, fx.path)
			ev := pkg.Events[0]
			resolver, entry, err := matcher.NewResolver(pkg.WorkloadPosture, matcher.EventFields(ev))
			if err != nil {
				t.Fatalf("NewResolver: %v", err)
			}
			opts := &sigma.MatchOptions{FieldResolver: resolver}

			// Warm-up: 100 untimed iterations so the JIT-equivalent
			// (constant folding + branch prediction) is steady.
			for i := 0; i < 100; i++ {
				_ = evaluateOnceForBench(rules, entry, opts)
			}

			ts := make([]time.Duration, samples)
			for i := 0; i < samples; i++ {
				start := time.Now()
				_ = evaluateOnceForBench(rules, entry, opts)
				ts[i] = time.Since(start)
			}
			sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
			p50 := ts[(samples-1)/2]
			p99 := ts[(samples-1)*99/100]

			t.Logf("[fixture=%s] p50=%s p99=%s (50 rules; NFR3 budget=%s)", fx.name, p50, p99, budget)
			if p99 > budget {
				t.Errorf("p99 %s exceeds NFR3 budget %s", p99, budget)
			}
		})
	}
}

// silence unused-import warnings when context is not used in this
// file. Kept handy because future bench additions may need it.
var _ = context.Background
