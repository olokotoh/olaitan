package dfir

import (
	"strings"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/response/settling"
	"github.com/olokotoh/olaitan/internal/schema"
)

// TestParseForensicReport_ErrorBranches exercises the validation-pipeline error
// paths so a malformed reply always lands in a schema violation, never a
// half-decoded report.
func TestParseForensicReport_ErrorBranches(t *testing.T) {
	sch, err := reportSchema.compiled()
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	cases := []struct {
		name string
		raw  string
	}{
		{"empty", ""},
		{"whitespace-only", "   \n\t "},
		{"fence-only-single-line", "```json```"},
		{"not-json", "this is not json"},
		{"schema-violation-missing-required", `{"body":"x"}`},
		{"unterminated-fence", "```json\n{\"body\":\"x\"}"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if _, perr := parseForensicReport(sch, c.raw); perr == nil {
				t.Errorf("%s: expected a parse error, got nil", c.name)
			}
		})
	}
}

// TestStripWrappingFence covers the fence-stripping branches.
func TestStripWrappingFence(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"no fence", "no fence"},
		{"```\nbody\n```", "body"},
		{"```json\nbody\n```", "body"},
		{"```json\nbody", "```json\nbody"}, // unterminated: returned unchanged
		{"```nonl", "```nonl"},             // no newline after the fence
	}
	for _, c := range cases {
		if got := stripWrappingFence(c.in); got != c.want {
			t.Errorf("stripWrappingFence(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestQuoteYAML covers the escape branches (backslash, quote, newline, CR, tab,
// plain rune).
func TestQuoteYAML(t *testing.T) {
	got := quoteYAML("a\\b\"c\nd\re\tf g")
	want := `"a\\b\"c\nd\re\tf g"`
	if got != want {
		t.Errorf("quoteYAML = %q, want %q", got, want)
	}
}

// TestContainmentFromHistory covers the CLEAN/empty-state skip, the dedup, and
// the empty-history fallback.
func TestContainmentFromHistory(t *testing.T) {
	withHistory := settling.IncidentFinalised{
		FinalState: "QUARANTINED",
		History: []schema.StateTransition{
			{ToState: schema.PodSecurityState("CLEAN")},       // skipped
			{ToState: schema.PodSecurityState("")},            // skipped
			{ToState: schema.PodSecurityState("RESTRICTED")},  // kept
			{ToState: schema.PodSecurityState("RESTRICTED")},  // dedup'd
			{ToState: schema.PodSecurityState("QUARANTINED")}, // kept
		},
	}
	got := containmentFromHistory(withHistory)
	want := []string{"applied RESTRICTED", "applied QUARANTINED"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("containmentFromHistory = %v, want %v", got, want)
	}

	// Empty history falls back to the final state alone.
	empty := settling.IncidentFinalised{FinalState: "RESTRICTED"}
	if g := containmentFromHistory(empty); len(g) != 1 || g[0] != "applied RESTRICTED" {
		t.Errorf("empty-history fallback = %v, want [applied RESTRICTED]", g)
	}

	// No history and no final state yields nothing.
	if g := containmentFromHistory(settling.IncidentFinalised{}); len(g) != 0 {
		t.Errorf("no history + no final state must yield nothing, got %v", g)
	}
}

// TestContentAddressedKey pins the OA4 key layout.
func TestContentAddressedKey(t *testing.T) {
	got := contentAddressedKey(time.Date(2026, 6, 14, 23, 59, 0, 0, time.UTC), "deadbeef")
	if got != "reports/2026/06/14/deadbeef.md" {
		t.Errorf("contentAddressedKey = %q", got)
	}
}
