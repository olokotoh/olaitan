package rules

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"testing"

	"github.com/olokotoh/olaitan/internal/decision/rules/loader"
	"github.com/olokotoh/olaitan/internal/schema"
)

// TestIntegration_CorpusMatchesScenarioFixture verifies AC3: each of
// the five evaluation scenarios has exactly the expected pair of
// rules from the production corpus firing against a representative
// hand-built EvidencePackage fixture. The expected rule IDs per
// scenario are pinned in the §Dev Notes corpus inventory; this test
// is the AC3-bounded check that the corpus actually delivers them.
//
// The test loads the production corpus from the repo-root rules/
// directory via loader.New (the same code path the engine runs at
// startup), constructs a bare Engine to access the package-level
// evaluatePackage entry point without the JetStream consumer
// scaffolding, and table-walks the five scenario fixtures. The
// TestIntegration_* function-name prefix is semantic only (multiple
// components exercised together); no build tag is set because the
// test has no external dependencies and runs in milliseconds, so it
// belongs in the default `go test ./...` CI gate.
func TestIntegration_CorpusMatchesScenarioFixture(t *testing.T) {
	root := corpusRoot(t)
	l := loader.New(root, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := l.Load(); err != nil {
		t.Fatalf("loader.Load(%s): %v", root, err)
	}
	corpus := l.Get()
	if corpus == nil || corpus.Len() < 10 {
		got := 0
		if corpus != nil {
			got = corpus.Len()
		}
		t.Fatalf("corpus.Len() = %d, want >=10 (AC1)", got)
	}

	engine := &Engine{log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	cases := []struct {
		scenario string
		fixture  string
		wantIDs  []string
	}{
		{"S1", "testdata/scenarios/S1/package.json", []string{"OLT-PRIV-001", "OLT-EXEC-001"}},
		{"S2", "testdata/scenarios/S2/package.json", []string{"OLT-CRED-001", "OLT-CRED-002"}},
		{"S3", "testdata/scenarios/S3/package.json", []string{"OLT-RECON-001", "OLT-LATERAL-001"}},
		{"S4", "testdata/scenarios/S4/package.json", []string{"OLT-NET-001", "OLT-NET-002"}},
		{"S5", "testdata/scenarios/S5/package.json", []string{"OLT-IMPACT-005", "OLT-IMPACT-006"}},
	}

	for _, tc := range cases {
		t.Run(tc.scenario, func(t *testing.T) {
			pkg := loadScenarioFixture(t, tc.fixture)
			matches := engine.evaluatePackage(&pkg, corpus)
			got := make(map[string]bool, len(matches))
			for _, m := range matches {
				got[m.RuleID] = true
			}
			gotIDs := sortedRuleIDs(got)
			wantIDs := append([]string(nil), tc.wantIDs...)
			sort.Strings(wantIDs)
			// Exact match-set assertion: AC3 is satisfied iff the
			// expected pair fires AND no other rule fires. The earlier
			// "subset" form (only checking the wanted IDs are present)
			// admitted regressions where every rule misfired on every
			// fixture; the expected pair would still be in the set.
			if !reflect.DeepEqual(gotIDs, wantIDs) {
				t.Errorf("scenario %s: got rule IDs %v, want exactly %v",
					tc.scenario, gotIDs, wantIDs)
			}
		})
	}
}

// loadScenarioFixture deserialises a JSON-encoded schema.EvidencePackage
// fixture from <test-file-dir>/<rel>. Bails the test on any IO or
// unmarshal error so the table-driven caller can assume the returned
// package is well-formed.
func loadScenarioFixture(t *testing.T, rel string) schema.EvidencePackage {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller(0) failed; cannot resolve fixture path")
	}
	path := filepath.Join(filepath.Dir(thisFile), rel)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var pkg schema.EvidencePackage
	if err := json.Unmarshal(data, &pkg); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	return pkg
}

// sortedRuleIDs returns the keys of got in stable alphabetic order so
// failure diagnostics are reproducible across test reruns.
func sortedRuleIDs(got map[string]bool) []string {
	out := make([]string, 0, len(got))
	for id := range got {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
