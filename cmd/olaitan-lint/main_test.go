package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestViolationFixtures asserts the linter flags each of the TEN representative
// violation fixtures (easy / hard / edge), so the tool genuinely catches a
// planted canonical-name literal. Each fixture carries exactly one violation.
func TestViolationFixtures(t *testing.T) {
	cases := []struct {
		file        string
		wantCat     string
		wantLiteral string
	}{
		{"v01_raw_subject_const.go.txt", "subject", "olaitan.events.raw.falco"},
		{"v02_audit_subject.go.txt", "subject", "AUDIT.transitions"},
		{"v03_investigations_prefix.go.txt", "subject", "INVESTIGATIONS.pkg-1.l1"},
		{"v04_reports_callarg.go.txt", "subject", "REPORTS.generated"},
		{"v05_fsm_key_workloadid.go.txt", "key", "fsm:default/Deployment/web"},
		{"v06_baseline_key.go.txt", "key", "baseline:tenant-acme:web-0:metrics"},
		{"v07_override_key.go.txt", "key", "override:{workload_id}"},
		{"v08_subject_in_map.go.txt", "subject", "olaitan.correlated.tenant-acme.web-0"},
		{"v09_overrides_applied.go.txt", "subject", "OVERRIDES.applied"},
		{"v10_incidents_finalised.go.txt", "subject", "INCIDENTS.finalised"},
	}
	if len(cases) != 10 {
		t.Fatalf("AC3 requires TEN violation fixtures, have %d", len(cases))
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			path := filepath.Join("testdata", "violations", c.file)
			findings, err := scanFile(path)
			if err != nil {
				t.Fatalf("scanFile(%s): %v", path, err)
			}
			var matched *finding
			for i := range findings {
				if findings[i].category == c.wantCat && findings[i].literal == c.wantLiteral {
					matched = &findings[i]
					break
				}
			}
			if matched == nil {
				t.Fatalf("fixture %s: want a %s finding for %q, got %+v", c.file, c.wantCat, c.wantLiteral, findings)
			}
			if matched.line == 0 || matched.col == 0 {
				t.Errorf("fixture %s: finding must carry a file:line:col (got line=%d col=%d)", c.file, matched.line, matched.col)
			}
			if len(findings) != 1 {
				t.Errorf("fixture %s: expected exactly one violation, got %d: %+v", c.file, len(findings), findings)
			}
		})
	}
}

// TestCompliantFixtures asserts the linter flags ZERO of the TEN representative
// compliant fixtures: the annotation domain, the envelope schema-version, the
// package:message error strings, the mid-string mention, the lowercase token,
// the comment-only mention, and the directive-suppressed literal.
func TestCompliantFixtures(t *testing.T) {
	files := []string{
		"c01_annotation_domain.go.txt",
		"c02_envelope_schema_version.go.txt",
		"c03_baseline_error_string.go.txt",
		"c04_health_error_string.go.txt",
		"c05_state_prose.go.txt",
		"c06_subject_in_comment.go.txt",
		"c07_subject_midstring.go.txt",
		"c08_lowercase_audit.go.txt",
		"c09_directive_suppressed.go.txt",
		"c10_evidence_error_string.go.txt",
	}
	if len(files) != 10 {
		t.Fatalf("AC3 requires TEN compliant fixtures, have %d", len(files))
	}
	for _, name := range files {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join("testdata", "compliant", name)
			findings, err := scanFile(path)
			if err != nil {
				t.Fatalf("scanFile(%s): %v", path, err)
			}
			if len(findings) != 0 {
				t.Errorf("compliant fixture %s must produce ZERO findings, got %+v", name, findings)
			}
		})
	}
}

// TestMatchesSubject unit-pins the subject heuristic, including the two
// false-positive guards that make AC4 (existing tree green) achievable.
func TestMatchesSubject(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		// Real subjects (all the families).
		{"olaitan.events.raw.falco", true},
		{"olaitan.events.normalised", true},
		{"olaitan.correlated.ns.pod", true},
		{"olaitan.state.ns.pod", true},
		{"olaitan.threats.alert", true},
		{"olaitan.evidence.packages", true},
		{"olaitan.health.heartbeat", true},
		{"AUDIT.transitions", true},
		{"OVERRIDES.applied", true},
		{"INCIDENTS.finalised", true},
		{"REPORTS.generated", true},
		{"INVESTIGATIONS.pkg-1.l1", true},
		{"INVESTIGATIONS.{id}.l1", true},
		{"THREATS.act", true},
		// FIX 2: a digit-first UPPER segment is a real subject (e.g. a numeric
		// package_id), so it must be flagged.
		{"INVESTIGATIONS.123abc.l1", true},
		// Guard 1: annotation domain + schema version are NOT subjects.
		{"olaitan.io/log-sidecar", false},
		{"olaitan.io/state-override", false},
		{"olaitan.eval.capture.envelope.v1", false},
		// Mid-string mention is not anchored at start.
		{"see olaitan.events docs", false},
		// Lowercase token is not the dotted-UPPER family.
		{"audit.local.scope", false},
		// FIX 1: a literal that EQUALS a known UPPER subject-family prefix is the
		// natural `"AUDIT." + verb` concatenation, so it is flagged.
		{"AUDIT.", true},
		// A bare UPPER word that is NOT a known prefix (no trailing dot match).
		{"AUDITED", false},
		{"REPORTSomething", false},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got := matchesSubject(c.in); got != c.want {
				t.Errorf("matchesSubject(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

// TestMatchesKey unit-pins the key heuristic, including the no-space-after-colon
// discriminator that separates a real key from the package:message error idiom.
func TestMatchesKey(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		// Real keys.
		{"baseline:ns:pod:metrics", true},
		{"checkpoint:correlator:stream_seq", true},
		{"state:ns:pod", true},
		{"evidence:incident:INC-1", true},
		{"health:ring", true},
		{"fsm:default/Deployment/web", true},
		{"fsm:{workload_id}", true},
		{"override:default/Deployment/web", true},
		// The package:message error idiom (space after the colon) is NOT a key.
		{"baseline: store: redis client is nil", false},
		{"baseline: store: %w", false},
		{"health: serve: %w", false},
		{"state: pending", false},
		{"evidence: incident not found", false},
		{"checkpoint: load failed", false},
		// FIX 1: a bare prefix that EQUALS a known key family (nothing after the
		// colon) is the natural `"fsm:" + id` concatenation, so it is flagged.
		// This is distinct from the space-led error idiom above, which passes.
		{"fsm:", true},
		{"override:", true},
		// Unrelated literal.
		{"some random string", false},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got := matchesKey(c.in); got != c.want {
				t.Errorf("matchesKey(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

// TestCanonicalPackagesAreExempt asserts a subject literal inside
// internal/subjects/ and a key literal inside internal/keys/ are exempt (the
// source of truth, not a violation), while the other category is still checked.
func TestCanonicalPackagesAreExempt(t *testing.T) {
	if !withinDir("internal/subjects/subjects.go", subjectsPkgDir) {
		t.Error("internal/subjects/subjects.go should be within the subjects package dir")
	}
	if !withinDir("internal/keys/keys.go", keysPkgDir) {
		t.Error("internal/keys/keys.go should be within the keys package dir")
	}
	if withinDir("internal/eval/scenario/recipes.go", subjectsPkgDir) {
		t.Error("a non-subjects file must NOT be treated as within the subjects package dir")
	}
}

// TestDirectiveSuppression proves the escape hatch suppresses a genuine match
// and that it is line-scoped (own line and the line below), for BOTH categories.
func TestDirectiveSuppression(t *testing.T) {
	const src = `package x
const a = "olaitan.events.raw.falco" //olaitan-lint:allow subject trailing directive
//olaitan-lint:allow key leading directive above the literal
const b = "fsm:default/Deployment/web"
const c = "AUDIT.transitions"
`
	findings := scanSource(t, "suppress.go", src)
	// Only the un-suppressed AUDIT.transitions on the last line survives.
	if len(findings) != 1 {
		t.Fatalf("want exactly one surviving finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].literal != "AUDIT.transitions" {
		t.Errorf("surviving finding = %q, want AUDIT.transitions", findings[0].literal)
	}
}

// TestTrailingDirectiveDoesNotLeakToNextLine asserts FIX 3: a TRAILING
// directive (a comment sharing a code line) suppresses ONLY that line, so it
// cannot silently mute a real violation on the immediately following line. The
// old "own line AND next line" rule created that blind spot.
func TestTrailingDirectiveDoesNotLeakToNextLine(t *testing.T) {
	const src = `package x
const a = "olaitan.events.raw.falco" //olaitan-lint:allow subject ok
const b = "AUDIT.transitions"
`
	findings := scanSource(t, "trailing.go", src)
	if len(findings) != 1 {
		t.Fatalf("trailing directive must not suppress line+1; want exactly one surviving finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].literal != "AUDIT.transitions" || findings[0].line != 3 {
		t.Errorf("surviving finding = %q on line %d, want AUDIT.transitions on line 3", findings[0].literal, findings[0].line)
	}
}

// TestExistingTreeIsClean pins AC4 inside `go test`: the linter must report
// ZERO findings over the real repository tree (not only in the CI step). If a
// future change hard-codes a canonical subject or key, this fails locally.
func TestExistingTreeIsClean(t *testing.T) {
	findings, err := run([]string{"../.."}, false)
	if err != nil {
		t.Fatalf("run over repo root: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("AC4: existing tree must be clean, got %d finding(s): %+v", len(findings), findings)
	}
}

// TestDirectiveRequiresReason asserts a directive without a reason is itself a
// hard error, so the hatch cannot be used to silently mute a finding.
func TestDirectiveRequiresReason(t *testing.T) {
	const src = `package x
const a = "olaitan.events.raw.falco" //olaitan-lint:allow subject
`
	dir := t.TempDir()
	path := filepath.Join(dir, "noreason.go")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := scanFile(path); err == nil {
		t.Error("a directive missing a reason must be a hard error, got nil")
	}
}

// TestDirectiveUnknownCategory asserts a directive naming an unknown category
// is a hard error (a typo cannot silently disable enforcement).
func TestDirectiveUnknownCategory(t *testing.T) {
	const src = `package x
const a = "olaitan.events.raw.falco" //olaitan-lint:allow subjekt typo
`
	dir := t.TempDir()
	path := filepath.Join(dir, "typo.go")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := scanFile(path); err == nil {
		t.Error("a directive with an unknown category must be a hard error, got nil")
	}
}

// TestFindingFormatStable asserts the printed finding format carries
// file:line:col, the category, and the offending literal (the AC2 output
// contract CI relies on).
func TestFindingFormatStable(t *testing.T) {
	findings := scanSource(t, "fmt.go", "package x\nconst a = \"AUDIT.transitions\"\n")
	if len(findings) != 1 {
		t.Fatalf("want one finding, got %d", len(findings))
	}
	f := findings[0]
	if f.line != 2 {
		t.Errorf("line = %d, want 2", f.line)
	}
	if f.category != "subject" || f.literal != "AUDIT.transitions" {
		t.Errorf("got category=%q literal=%q", f.category, f.literal)
	}
}

// TestRunDeterministicOrder asserts run() emits findings in stable
// file:line:col order across the violation fixtures, so the CI exit and output
// are reproducible (the drift-free-gate prerequisite).
func TestRunDeterministicOrder(t *testing.T) {
	root := filepath.Join("testdata", "violations")
	// scanFile per file in directory order is not what run() does; run() walks
	// and sorts. Drive run() over a temp tree of real .go files to exercise the
	// sort path deterministically.
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "b.go"), "package x\nconst a = \"AUDIT.transitions\"\nconst b = \"REPORTS.generated\"\n")
	mustWrite(t, filepath.Join(dir, "a.go"), "package x\nconst a = \"fsm:default/Deployment/web\"\n")

	first, err := run([]string{dir}, false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := run([]string{dir}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != len(second) {
		t.Fatalf("non-deterministic count: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("non-deterministic order at %d: %+v vs %+v", i, first[i], second[i])
		}
	}
	// a.go must sort before b.go.
	if len(first) < 2 || !strings.HasSuffix(first[0].file, "a.go") {
		t.Errorf("findings not sorted by file (a.go first): %+v", first)
	}
	_ = root
}

// TestTestFilesSkippedByDefault asserts a *_test.go file is out of default
// scope (NFR35 integration tests legitimately drive real subjects), but is
// scanned with includeTests=true.
func TestTestFilesSkippedByDefault(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "x_test.go"), "package x\nconst a = \"olaitan.events.raw.falco\"\n")

	def, err := run([]string{dir}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(def) != 0 {
		t.Errorf("default scope must skip *_test.go, got %+v", def)
	}
	withTests, err := run([]string{dir}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(withTests) != 1 {
		t.Errorf("includeTests must scan *_test.go, got %d findings", len(withTests))
	}
}

// scanSource writes src to a temp .go file and scans it.
func scanSource(t *testing.T, name, src string) []finding {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	mustWrite(t, path, src)
	findings, err := scanFile(path)
	if err != nil {
		t.Fatalf("scanFile: %v", err)
	}
	return findings
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
