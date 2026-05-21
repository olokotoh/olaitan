package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

func benchFixtures() []fixtureRef {
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

	for _, fx := range benchFixtures() {
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

// silence unused-import warnings when context is not used in this
// file. Kept handy because future bench additions may need it.
var _ = context.Background
