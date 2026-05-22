package rules

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/olokotoh/olaitan/internal/decision/rules/parser"
)

// scenarioTechniques pins the AC1 scenario-to-technique mapping. A
// rule's scenario membership is computed from its attack: list using
// this table; the AC1 distribution invariants (>=10 rules, >=2 per
// scenario) are asserted against the resulting membership.
//
// Sub-techniques (T1552.005, T1071.001) count toward their parent
// scenario via the same table entry so a rule that pins only the
// sub-technique still satisfies AC1's per-scenario coverage gate.
var scenarioTechniques = map[string][]string{
	"S1": {"T1611"},
	"S2": {"T1552", "T1552.005"},
	"S3": {"T1613"},
	"S4": {"T1071", "T1071.001"},
	"S5": {"T1496"},
}

// TestCorpusLint_AllRulesParse walks the repo-root rules/ directory,
// parses every YAML via parser.ParseRule, and asserts the AC1
// distribution invariants. The test runs under the default build tag
// so the existing `go test ./...` CI job picks it up without any
// .github/workflows/ci.yml change (story Task 7).
func TestCorpusLint_AllRulesParse(t *testing.T) {
	root := corpusRoot(t)
	rules := walkAndParse(t, root)
	if len(rules) < 10 {
		t.Fatalf("corpus has %d rules; AC1 requires >=10", len(rules))
	}

	counts := map[string]int{}
	for _, r := range rules {
		hit := map[string]bool{}
		for _, attackID := range r.Attack {
			for scenario, techs := range scenarioTechniques {
				for _, want := range techs {
					if attackID == want {
						hit[scenario] = true
					}
				}
			}
		}
		for scenario := range hit {
			counts[scenario]++
		}
	}
	for scenario := range scenarioTechniques {
		if counts[scenario] < 2 {
			t.Errorf("scenario %s covered by %d rules; AC1 requires >=2", scenario, counts[scenario])
		}
	}

	// AC2 enforcement: every rule must declare a documented false-positive
	// characterisation. parser.ParseRule does not enforce this (sigmalite
	// stores the field but does not require it); Story 1.16's lint adds
	// the gate so a future contributor cannot land a rule without a
	// falsepositives entry. The severity 0-100 and attack.<technique>
	// halves of AC2 are already enforced by parser.ParseRule via
	// extractSeverity and extractAttack respectively.
	for _, r := range rules {
		if len(r.FalsePositives) == 0 {
			t.Errorf("rule %s missing falsepositives; AC2 requires a documented false-positive characterisation", r.ID)
		}
	}
}

// TestCorpusLint_FailsOnMissingAttackAnnotation locks the AC4 gate in
// by constructing an in-memory invalid rule (no attack: field) in a
// tempdir and asserting parser.ParseRule returns the exact error
// string the engine startup gate relies on. If a future contributor
// changes the parser's error string, this test breaks before a PR
// with a malformed rule could ever pass CI.
func TestCorpusLint_FailsOnMissingAttackAnnotation(t *testing.T) {
	dir := t.TempDir()
	bad := []byte(`title: missing attack field
id: OLT-IMPACT-999
detection:
  s:
    process.exe|endswith: 'xmrig'
  condition: s
`)
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, bad, 0o600); err != nil {
		t.Fatalf("write bad rule: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read bad rule: %v", err)
	}
	_, parseErr := parser.ParseRule(data)
	if parseErr == nil {
		t.Fatalf("parser accepted rule without attack: field; AC4 gate broken")
	}
	const want = "attack: required field is missing"
	if !strings.Contains(parseErr.Error(), want) {
		t.Errorf("got error %q, want substring %q", parseErr.Error(), want)
	}
}

// walkAndParse walks root recursively, parses every *.yaml / *.yml
// file via parser.ParseRule, and returns the parsed rules. On parse
// failure the test name surfaces the offending file path so a future
// contributor sees a clean diagnostic.
func walkAndParse(t *testing.T, root string) []*parser.Rule {
	t.Helper()
	var rules []*parser.Rule
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("read %s: %v", path, err)
			return nil
		}
		r, err := parser.ParseRule(data)
		if err != nil {
			t.Errorf("parse %s: %v", path, err)
			return nil
		}
		r.SourcePath = path
		rules = append(rules, r)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return rules
}

// corpusRoot resolves <this-test-file>/../../../rules so the lint
// test runs from any working directory. The path is computed via
// runtime.Caller because os.Getwd is not reliable under coverage-mode
// reruns or `go test -run` invocations from outside the package dir.
// Mirrors the chartDir(t) pattern at deploy/helm/helm_test.go:35.
func corpusRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller(0) failed; cannot resolve corpus root")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "rules")
}
