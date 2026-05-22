package rules

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/olokotoh/olaitan/internal/decision/rules/parser"
)

// countCorpusYAMLs counts every *.yaml / *.yml file under root by
// walking the tree, without touching the parser. Used as the on-disk
// authority for the AC1 ">=10 rules" check: if walkAndParse drops a
// file via t.Errorf on a parse failure, the count check below catches
// the divergence before the >=10 gate runs against the parsed subset.
func countCorpusYAMLs(t *testing.T, root string) int {
	t.Helper()
	n := 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		if ext == ".yaml" || ext == ".yml" {
			n++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("count corpus yamls under %s: %v", root, err)
	}
	return n
}

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
	onDisk := countCorpusYAMLs(t, root)
	rules := walkAndParse(t, root)
	if len(rules) != onDisk {
		t.Fatalf("parsed %d rules but %d *.yaml files on disk; parse failures hidden by walkAndParse", len(rules), onDisk)
	}
	if len(rules) < 10 {
		t.Fatalf("corpus has %d rules; AC1 requires >=10", len(rules))
	}

	counts := map[string]int{}
	rulesWithScenario := map[string]bool{}
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
		if len(hit) > 0 {
			rulesWithScenario[r.ID] = true
		}
	}
	for scenario := range scenarioTechniques {
		if counts[scenario] < 2 {
			t.Errorf("scenario %s covered by %d rules; AC1 requires >=2", scenario, counts[scenario])
		}
	}

	// AC1 reciprocal: every parsed rule must map to at least one
	// scenario via scenarioTechniques. An orphan-technique rule (e.g.
	// attack: [T9999]) would parse cleanly and satisfy AC2 but
	// contribute to no scenario, defeating the corpus inventory's
	// purpose. The reciprocal gate forces every future rule addition
	// to extend scenarioTechniques (or be removed) before lint passes.
	for _, r := range rules {
		if !rulesWithScenario[r.ID] {
			t.Errorf("rule %s attack:%v maps to no scenario in scenarioTechniques; either fix the rule's attack list or extend scenarioTechniques", r.ID, r.Attack)
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
// by table-driving three malformed-rule shapes (missing key, explicit
// null, empty list) through parser.ParseRule and asserting the EXACT
// parser error string the engine startup gate relies on. Equality
// (not Contains) is the deliberate contract: if the parser ever wraps
// or rephrases the error, the dev who made that change must update
// this test, which surfaces the breaking change at code-review time
// rather than letting CI silently accept the regression.
func TestCorpusLint_FailsOnMissingAttackAnnotation(t *testing.T) {
	const (
		titleAndDetection = `title: missing attack field
id: OLT-IMPACT-999
detection:
  s:
    process.exe|endswith: 'xmrig'
  condition: s
`
	)
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "missing_attack_key",
			yaml: titleAndDetection,
			want: "attack: required field is missing",
		},
		{
			name: "attack_explicit_null",
			yaml: "attack: null\n" + titleAndDetection,
			want: "attack: must be a non-empty list",
		},
		{
			name: "attack_empty_list",
			yaml: "attack: []\n" + titleAndDetection,
			want: "attack: must be a non-empty list",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "bad.yaml")
			if err := os.WriteFile(path, []byte(tc.yaml), 0o600); err != nil {
				t.Fatalf("write bad rule: %v", err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read bad rule: %v", err)
			}
			_, parseErr := parser.ParseRule(data)
			if parseErr == nil {
				t.Fatalf("parser accepted malformed rule; AC4 gate broken")
			}
			if got := parseErr.Error(); got != tc.want {
				t.Errorf("got error %q, want exact %q", got, tc.want)
			}
		})
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
