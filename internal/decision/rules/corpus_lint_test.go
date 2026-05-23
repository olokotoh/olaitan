package rules

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/olokotoh/olaitan/internal/decision/rules/parser"
)

// canonicalYAMLExt returns true for *.yaml / *.yml in any case. The
// chart's helm-prepare-rules Makefile glob `rules/*/*.yaml` is
// case-sensitive on Linux but case-insensitive on macOS; the lint
// walker matches the most permissive of the two so a rule named
// OLT-FOO.YAML or .Yml fails lint at PR-review time rather than
// silently slipping into divergent on-disk vs staged corpora across
// developer platforms.
func canonicalYAMLExt(path string) bool {
	ext := filepath.Ext(path)
	return strings.EqualFold(ext, ".yaml") || strings.EqualFold(ext, ".yml")
}

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
		if canonicalYAMLExt(path) {
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

	// AC1 unique-ID gate: two rules sharing an ID would silently
	// dedupe through any map keyed on r.ID, masking a real corpus
	// duplication. Fail lint at the first collision with both source
	// paths so the contributor sees which two files clash.
	idToPath := map[string]string{}
	for _, r := range rules {
		if prev, dup := idToPath[r.ID]; dup {
			t.Errorf("rule ID %q appears in two files: %s and %s", r.ID, prev, r.SourcePath)
		}
		idToPath[r.ID] = r.SourcePath
	}

	// AC1 attack-technique closed-world gate: every technique a rule
	// declares must be present in scenarioTechniques. An orphan ID
	// like T9999 (typo, unmapped technique, future ATT&CK revision)
	// would parse cleanly and pass the per-scenario count gate via a
	// sibling technique, but silently inflate the corpus with rules
	// that don't actually belong to any tracked scenario. Forcing the
	// extension of scenarioTechniques on every new technique keeps
	// the inventory and the lint table aligned.
	knownTechniques := map[string]bool{}
	for _, techs := range scenarioTechniques {
		for _, t := range techs {
			knownTechniques[t] = true
		}
	}

	// AC1 per-scenario distinct-rules gate. counts[scenario] is the
	// number of distinct rule SOURCE PATHS that hit each scenario, not
	// the number of attack-technique increments; a single multi
	// technique rule like attack:[T1611, T1552] contributes once to
	// S1 and once to S2 (one count per rule per scenario it hits),
	// not twice to one scenario. Keying on r.SourcePath (instead of
	// r.ID) plus the unique-ID gate above means the count is a true
	// distinct-rules-per-scenario tally even if a contributor
	// accidentally reuses an ID.
	counts := map[string]int{}
	rulesByPath := map[string]bool{}
	for _, r := range rules {
		hit := map[string]bool{}
		for _, attackID := range r.Attack {
			if !knownTechniques[attackID] {
				t.Errorf("rule %s declares unknown attack technique %q; either fix the typo or extend scenarioTechniques", r.ID, attackID)
				continue
			}
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
			rulesByPath[r.SourcePath] = true
		}
	}
	for scenario := range scenarioTechniques {
		if counts[scenario] < 2 {
			t.Errorf("scenario %s covered by %d distinct rules; AC1 requires >=2", scenario, counts[scenario])
		}
	}

	// AC1 reciprocal: every parsed rule must map to at least one
	// scenario via scenarioTechniques. Keyed on r.SourcePath (not
	// r.ID) so two rules sharing an ID are not silently collapsed
	// here before the unique-ID gate above flags them. The closed
	// world gate already catches unknown techniques; this gate
	// catches the rarer case of a rule whose entire attack list maps
	// outside scenarioTechniques' covered techniques.
	for _, r := range rules {
		if !rulesByPath[r.SourcePath] {
			t.Errorf("rule %s (%s) attack:%v maps to no scenario in scenarioTechniques; either fix the rule's attack list or extend scenarioTechniques", r.ID, r.SourcePath, r.Attack)
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
		if !canonicalYAMLExt(path) {
			return nil
		}
		// AC1 flatness gate: the chart's helm-prepare-rules Makefile
		// uses `wildcard rules/*/*.yaml` which does not recurse, so a
		// nested rule at rules/<cat>/sub/OLT-FOO.yaml would parse and
		// satisfy AC1 here but be silently absent from the staged
		// ConfigMap. Fail lint at the first nested file so the
		// divergence surfaces at PR-review time.
		if rel, relErr := filepath.Rel(root, path); relErr == nil {
			if depth := strings.Count(rel, string(filepath.Separator)); depth != 1 {
				t.Errorf("rule path %q is %d directories deep under rules/; must be exactly rules/<category>/<file>.yaml (the Makefile glob `rules/*/*.yaml` does not recurse)", rel, depth)
				return nil
			}
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
