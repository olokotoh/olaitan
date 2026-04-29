package main

import (
	"testing"
)

// TestLintID guards the OLT rule-ID regex defined in
// docs/sigma-extensions.md and architecture.md:470.
func TestLintID(t *testing.T) {
	good := []string{"OLT-IMPACT-005", "OLT-EXEC-000", "OLT-LATERAL-999"}
	bad := []string{"OLT-FOO-005", "olt-impact-005", "OLT-IMPACT-5", "OLT-IMPACT-1234", "PROD-IMPACT-005"}
	for _, id := range good {
		if err := lintID(id); err != nil {
			t.Errorf("lintID(%q) = %v, want nil", id, err)
		}
	}
	for _, id := range bad {
		if err := lintID(id); err == nil {
			t.Errorf("lintID(%q) = nil, want error", id)
		}
	}
}

// TestPatternMatchesModifiers covers the five modifiers the POC
// implements, plus the bare-equality default.
func TestPatternMatchesModifiers(t *testing.T) {
	cases := []struct {
		name     string
		value    string
		pattern  string
		modifier string
		want     bool
	}{
		{"equality_match", "xmrig", "xmrig", "", true},
		{"equality_miss", "xmrig", "minerd", "", false},
		{"contains_match", "/usr/local/bin/xmrig", "xmrig", "contains", true},
		{"startswith_match", "tenant-acme", "tenant-", "startswith", true},
		{"startswith_miss", "kube-system", "tenant-", "startswith", false},
		{"endswith_match", "/usr/local/bin/xmrig", "xmrig", "endswith", true},
		{"re_match", "xmrig", "^xm.*g$", "re", true},
		{"re_miss", "redis-server", "^xm.*g$", "re", false},
		{"cidr_match", "10.1.2.3", "10.0.0.0/8", "cidr", true},
		{"cidr_miss", "192.168.1.1", "10.0.0.0/8", "cidr", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := patternMatches(tc.value, tc.pattern, tc.modifier)
			if err != nil {
				t.Fatalf("patternMatches(%q, %q, %q) unexpected error: %v", tc.value, tc.pattern, tc.modifier, err)
			}
			if got != tc.want {
				t.Fatalf("patternMatches(%q, %q, %q) = %v, want %v", tc.value, tc.pattern, tc.modifier, got, tc.want)
			}
		})
	}
}

// TestPatternMatchesErrors guards the three failure paths the POC
// surfaces: unknown modifier, malformed regex, and non-IP value fed to
// the cidr modifier. Story 1.15 must inherit these as loud errors, not
// silent no-match.
func TestPatternMatchesErrors(t *testing.T) {
	cases := []struct {
		name     string
		value    string
		pattern  string
		modifier string
	}{
		{"unknown_modifier", "x", "x", "bogus"},
		{"regex_compile_failure", "value", "[unterminated", "re"},
		{"cidr_bad_pattern", "10.1.2.3", "not-a-cidr", "cidr"},
		{"cidr_bad_value", "tenant-acme", "10.0.0.0/8", "cidr"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := patternMatches(tc.value, tc.pattern, tc.modifier)
			if err == nil {
				t.Fatalf("patternMatches(%q, %q, %q) expected error, got nil", tc.value, tc.pattern, tc.modifier)
			}
		})
	}
}

// TestEmptyPatternRejected ensures the POC refuses an empty pattern
// with substring-style modifiers, where strings.Contains("", x) and
// HasPrefix/HasSuffix would otherwise match every event silently.
func TestEmptyPatternRejected(t *testing.T) {
	for _, mod := range []string{"", "contains", "startswith", "endswith"} {
		_, err := anyPatternMatches("anything", []string{""}, mod)
		if err == nil {
			t.Errorf("anyPatternMatches with empty pattern and modifier %q expected error, got nil", mod)
		}
	}
}

// TestParseAndCondition rejects anything that is not a flat AND
// list. Documenting the POC's intentional limit; Story 1.15 will
// support full SIGMA-HQ condition grammar via sigmalite.
func TestParseAndCondition(t *testing.T) {
	if got := parseAndCondition("a and b and c"); len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Fatalf("parseAndCondition flat AND broken: %v", got)
	}
	if got := parseAndCondition("a AND b"); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("parseAndCondition should accept uppercase AND: %v", got)
	}
	if got := parseAndCondition("selection"); len(got) != 1 || got[0] != "selection" {
		t.Fatalf("parseAndCondition should accept a single identifier: %v", got)
	}
	if got := parseAndCondition(""); got != nil {
		t.Fatalf("parseAndCondition should reject empty input: %v", got)
	}
	if got := parseAndCondition("a or b"); got != nil {
		t.Fatalf("parseAndCondition should reject OR: %v", got)
	}
	if got := parseAndCondition("(a and b)"); got != nil {
		t.Fatalf("parseAndCondition should reject parentheses: %v", got)
	}
}

// TestEvaluateExercisesParseAndCondition drives the AND-condition
// path end-to-end: build an in-memory rule, evaluate against an event,
// and confirm the result. Without this, parseAndCondition could be
// removed and the existing fixture-based tests would still pass
// because evaluate() also has a single-block path; this test is the
// guard that the helper is actually wired into the pipeline.
func TestEvaluateExercisesParseAndCondition(t *testing.T) {
	r := rule{
		ID: "OLT-EXEC-000",
		Detection: map[string]any{
			"selection_a": map[string]any{"process.exe": "xmrig"},
			"selection_b": map[string]any{"k8s.pod.namespace": "tenant-acme"},
			"condition":   "selection_a AND selection_b",
		},
	}
	matchEvent := map[string]any{"process.exe": "xmrig", "k8s.pod.namespace": "tenant-acme"}
	missEvent := map[string]any{"process.exe": "xmrig", "k8s.pod.namespace": "kube-system"}

	got, err := evaluate(r, matchEvent)
	if err != nil {
		t.Fatalf("evaluate match: %v", err)
	}
	if !got {
		t.Fatalf("expected match for matchEvent, got false")
	}
	got, err = evaluate(r, missEvent)
	if err != nil {
		t.Fatalf("evaluate miss: %v", err)
	}
	if got {
		t.Fatalf("expected no-match for missEvent, got true")
	}
}
