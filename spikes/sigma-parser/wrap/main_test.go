package main

import (
	"encoding/json"
	"os"
	"testing"

	sigma "github.com/runreveal/sigmalite"
)

// TestFixturesAgainstRule is a CI smoke that mirrors what main() prints.
// A passing run requires the parser to bind the OLT extras (attack,
// severity), the FieldResolver to route k8s.* lookups to the posture
// map, and the rule's modifiers (endswith, startswith, equality) to
// evaluate against the streaming-event field map.
func TestFixturesAgainstRule(t *testing.T) {
	yamlBytes, err := os.ReadFile("../testdata/OLT-IMPACT-005.yaml")
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
		{"positive", "../testdata/fixtures/positive.json", true},
		{"negative_namespace", "../testdata/fixtures/negative_namespace.json", false},
		{"negative_process", "../testdata/fixtures/negative_process.json", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			entry, posture, err := loadFixture(tc.path)
			if err != nil {
				t.Fatalf("load fixture: %v", err)
			}
			got := evaluate(rule, entry, posture)
			if got != tc.want {
				t.Fatalf("evaluate %s: want=%v got=%v", tc.name, tc.want, got)
			}
		})
	}
}

// TestRuleMatchShape pins the output struct to the production
// internal/schema.RuleMatch shape so Story 1.15 inherits the same
// JSON contract.
func TestRuleMatchShape(t *testing.T) {
	m := ruleMatch{
		RuleID:    "OLT-IMPACT-005",
		RuleName:  "x",
		Severity:  "75",
		MitreTags: []string{"T1496"},
		EventID:   "positive",
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"rule_id":"OLT-IMPACT-005","rule_name":"x","severity":"75","mitre_tags":["T1496"],"event_id":"positive"}`
	if string(out) != want {
		t.Fatalf("ruleMatch JSON shape drift: want %s got %s", want, string(out))
	}
}
