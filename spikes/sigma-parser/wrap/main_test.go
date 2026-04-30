package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sigma "github.com/runreveal/sigmalite"
)

func loadOLTRule(t *testing.T) (*sigma.Rule, oltExtras) {
	t.Helper()
	yamlBytes, err := os.ReadFile(filepath.Join(sourceDir(), "..", "testdata", "OLT-IMPACT-005.yaml"))
	if err != nil {
		t.Fatalf("read rule: %v", err)
	}
	rule, err := sigma.ParseRule(yamlBytes)
	if err != nil {
		t.Fatalf("parse rule: %v", err)
	}
	extras, err := parseOLTExtras(rule)
	if err != nil {
		t.Fatalf("parse OLT extras: %v", err)
	}
	return rule, extras
}

// TestFixturesAgainstRule is a CI smoke that mirrors what main() prints.
// A passing run requires the parser to bind the OLT extras (attack,
// severity), the FieldResolver to route k8s.* lookups to the posture
// map, and the rule's modifiers (endswith, startswith, equality) to
// evaluate against the streaming-event field map.
func TestFixturesAgainstRule(t *testing.T) {
	rule, extras := loadOLTRule(t)
	if len(extras.Attack) != 1 || extras.Attack[0] != "T1496" {
		t.Fatalf("expected attack=[T1496], got %v", extras.Attack)
	}
	if extras.Severity != 75 {
		t.Fatalf("expected severity=75, got %d", extras.Severity)
	}

	cases := []struct {
		name string
		path string
		want bool
	}{
		{"positive", filepath.Join(sourceDir(), "..", "testdata", "fixtures", "positive.json"), true},
		{"negative_namespace", filepath.Join(sourceDir(), "..", "testdata", "fixtures", "negative_namespace.json"), false},
		{"negative_process", filepath.Join(sourceDir(), "..", "testdata", "fixtures", "negative_process.json"), false},
		{"negative_missing_process", filepath.Join(sourceDir(), "..", "testdata", "fixtures", "negative_missing_process.json"), false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			entry, resolver, err := loadFixture(tc.path)
			if err != nil {
				t.Fatalf("load fixture: %v", err)
			}
			got := evaluate(rule, entry, buildOpts(resolver))
			if got != tc.want {
				t.Fatalf("evaluate %s: want=%v got=%v", tc.name, tc.want, got)
			}
		})
	}
}

// TestRuleMatchShape pins the output struct to the production
// internal/schema.RuleMatch shape so Story 1.15 inherits the same JSON
// contract. It drives the runtime path (parse rule, build match) so a
// future rename of any field surfaces here, not just in a fabricated
// in-test struct.
func TestRuleMatchShape(t *testing.T) {
	rule, extras := loadOLTRule(t)
	match := buildRuleMatch(rule, extras, "positive")
	out, err := json.Marshal(match)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"rule_id":"OLT-IMPACT-005","rule_name":"Cryptominer process pattern in unprivileged Pod","severity":"75","mitre_tags":["T1496"],"event_id":"positive"}`
	if string(out) != want {
		t.Fatalf("ruleMatch JSON shape drift:\n want %s\n got  %s", want, string(out))
	}
}

// TestParseOLTExtrasRejectsViolations guards the dialect MUSTs in
// docs/sigma-extensions.md §4 (attack required, non-empty, ID format)
// and §8 (severity range [0,100]). A rule that violates any MUST must
// fail to load so Story 1.15 inherits a clean contract.
func TestParseOLTExtrasRejectsViolations(t *testing.T) {
	cases := []struct {
		name        string
		mutate      func(string) string
		errContains string
	}{
		{
			name:        "missing_attack",
			mutate:      func(s string) string { return strings.Replace(s, "attack:\n  - T1496\n", "", 1) },
			errContains: "attack",
		},
		{
			name:        "empty_attack_list",
			mutate:      func(s string) string { return strings.Replace(s, "  - T1496\n", "", 1) },
			errContains: "non-empty",
		},
		{
			name:        "malformed_attack_id",
			mutate:      func(s string) string { return strings.Replace(s, "T1496", "MITRE-1496", 1) },
			errContains: "does not match",
		},
		{
			name:        "severity_above_max",
			mutate:      func(s string) string { return strings.Replace(s, "severity: 75", "severity: 200", 1) },
			errContains: "[0, 100]",
		},
		{
			name:        "severity_below_min",
			mutate:      func(s string) string { return strings.Replace(s, "severity: 75", "severity: -1", 1) },
			errContains: "[0, 100]",
		},
		{
			name:        "severity_explicit_null",
			mutate:      func(s string) string { return strings.Replace(s, "severity: 75", "severity: null", 1) },
			errContains: "explicit null is not permitted",
		},
	}
	yamlBytes, err := os.ReadFile(filepath.Join(sourceDir(), "..", "testdata", "OLT-IMPACT-005.yaml"))
	if err != nil {
		t.Fatalf("read rule: %v", err)
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			mutated := tc.mutate(string(yamlBytes))
			rule, err := sigma.ParseRule([]byte(mutated))
			if err != nil {
				t.Fatalf("mutation %q produced a yaml-parse error before reaching parseOLTExtras (%v); rewrite the mutation so it tests the OLT-extras layer rather than the SIGMA-HQ parse layer", tc.name, err)
			}
			_, err = parseOLTExtras(rule)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.errContains)
			}
			if !strings.Contains(err.Error(), tc.errContains) {
				t.Fatalf("expected error containing %q, got: %v", tc.errContains, err)
			}
		})
	}
}

// TestSeverityFallbackFromLevel verifies the docs §8 level-table
// fallback: a rule with no `severity:` is resolved to the level-table
// number (medium → 50). Without this fallback the runtime would emit
// "0" for any rule that omits severity.
func TestSeverityFallbackFromLevel(t *testing.T) {
	// Build a minimal rule with level: high and no severity:.
	body := []byte(`title: Level fallback test
id: OLT-EXEC-000
attack:
  - T1059
level: high
detection:
  selection:
    process.exe: foo
  condition: selection
`)
	// sigmalite's ParseRule expects a YAML byte stream.
	rule, err := sigma.ParseRule(body)
	if err != nil {
		t.Fatalf("parse rule: %v", err)
	}
	extras, err := parseOLTExtras(rule)
	if err != nil {
		t.Fatalf("parse extras: %v", err)
	}
	if extras.Severity != 75 {
		t.Fatalf("level: high should map to severity 75, got %d", extras.Severity)
	}
	if extras.HasSeverity {
		t.Fatalf("HasSeverity should be false when the rule did not declare severity:")
	}
}

// TestBuildCorpusFailsOnAnchorDrift defends the AC5 corpus integrity:
// if the rule YAML's id-line ever drifts from the literal anchor,
// mutateID errors instead of silently producing ten copies of the same
// rule (which the bench would happily measure as "10-rule corpus").
func TestBuildCorpusFailsOnAnchorDrift(t *testing.T) {
	if _, err := buildCorpus([]byte("id: OLT-IMPACT-999\n")); err == nil {
		t.Fatalf("expected error when anchor is missing, got nil")
	}
}
