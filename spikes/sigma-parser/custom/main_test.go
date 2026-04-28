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
		{"unknown_modifier", "x", "x", "bogus", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := patternMatches(tc.value, tc.pattern, tc.modifier)
			if got != tc.want {
				t.Fatalf("patternMatches(%q, %q, %q) = %v, want %v", tc.value, tc.pattern, tc.modifier, got, tc.want)
			}
		})
	}
}

// TestParseAndCondition rejects anything that is not a flat AND
// list. Documenting the POC's intentional limit; Story 1.15 will
// support full SIGMA-HQ condition grammar via sigmalite.
func TestParseAndCondition(t *testing.T) {
	if got := parseAndCondition("a and b and c"); len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Fatalf("parseAndCondition flat AND broken: %v", got)
	}
	if got := parseAndCondition("a or b"); got != nil {
		t.Fatalf("parseAndCondition should reject OR: %v", got)
	}
	if got := parseAndCondition("(a and b)"); got != nil {
		t.Fatalf("parseAndCondition should reject parentheses: %v", got)
	}
}
