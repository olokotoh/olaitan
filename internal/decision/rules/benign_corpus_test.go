package rules

import (
	"encoding/json"
	"io"
	"log/slog"
	"testing"
	"time"

	evalscenario "github.com/olokotoh/olaitan/internal/eval/scenario"
	"github.com/olokotoh/olaitan/internal/decision/rules/loader"
	"github.com/olokotoh/olaitan/internal/schema"
)

// TestBenignCorpus_MatchesNoRule is the load-bearing guard for the Story 7.3
// false-positive sweep: the benign event stream MUST match no rule in the
// shipped corpus, evaluated through the REAL parser+matcher engine (not a
// hand-maintained list), so a future rule that starts matching benign activity
// fails this test instead of silently corrupting the FPR baseline.
func TestBenignCorpus_MatchesNoRule(t *testing.T) {
	root := corpusRoot(t)
	l := loader.New(root, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := l.Load(); err != nil {
		t.Fatalf("loader.Load(%s): %v", root, err)
	}
	corpus := l.Get()
	if corpus == nil || corpus.Len() < 10 {
		t.Fatalf("corpus too small; want the full shipped corpus")
	}

	engine := &Engine{log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	// Build an EvidencePackage from the benign field maps, mirroring how the
	// correlator would assemble the two benign source events for one workload.
	maps := evalscenario.BenignRawFieldMaps()
	srcs := evalscenario.BenignEventSources()
	if len(maps) != len(srcs) {
		t.Fatalf("benign fixture mismatch: %d maps, %d sources", len(maps), len(srcs))
	}
	events := make([]schema.Event, len(maps))
	for i := range maps {
		raw, err := json.Marshal(maps[i])
		if err != nil {
			t.Fatalf("marshal benign map %d: %v", i, err)
		}
		events[i] = schema.Event{
			ID:        "benign-ev-" + srcs[i][0],
			Timestamp: time.Unix(1000, 0),
			Source:    schema.EventSource(srcs[i][0]),
			Category:  schema.EventCategory(srcs[i][1]),
			Pod:       schema.PodRef{Name: "web", Namespace: "tenant-acme"},
			Raw:       raw,
		}
	}
	pkg := &schema.EvidencePackage{
		PackageID: "benign-pkg",
		WorkloadID: "tenant-acme/Deployment/web",
		WorkloadPosture: &schema.WorkloadPosture{
			Identity: schema.WorkloadIdentity{
				Namespace: "tenant-acme",
				OwnerKind: "Deployment",
				OwnerName: "web",
			},
		},
		Events: events,
	}

	matches := engine.evaluatePackage(pkg, corpus)
	if len(matches) != 0 {
		ids := make([]string, 0, len(matches))
		for _, m := range matches {
			ids = append(ids, m.RuleID)
		}
		t.Fatalf("benign stream matched %d rule(s) %v; a benign sweep would then record false positives and the FPR baseline is corrupt. Narrow the offending rule or adjust the benign recipe.", len(matches), ids)
	}
}
