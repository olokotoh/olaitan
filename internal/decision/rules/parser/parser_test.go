package parser

import (
	"strings"
	"testing"
)

const validOLTRule = `
title: Cryptominer pattern
id: OLT-IMPACT-005
attack:
  - T1496
severity: 75
detection:
  sel:
    process.exe|endswith: 'xmrig'
  condition: sel
`

func TestParseRule_ValidOLTRule(t *testing.T) {
	r, err := ParseRule([]byte(validOLTRule))
	if err != nil {
		t.Fatalf("ParseRule: unexpected error: %v", err)
	}
	if r.ID != "OLT-IMPACT-005" {
		t.Errorf("ID = %q, want OLT-IMPACT-005", r.ID)
	}
	if r.Title != "Cryptominer pattern" {
		t.Errorf("Title = %q, want %q", r.Title, "Cryptominer pattern")
	}
	if len(r.Attack) != 1 || r.Attack[0] != "T1496" {
		t.Errorf("Attack = %v, want [T1496]", r.Attack)
	}
	if r.Severity != 75 {
		t.Errorf("Severity = %d, want 75", r.Severity)
	}
	if !r.HasSeverity {
		t.Errorf("HasSeverity = false, want true (severity was explicit)")
	}
	if r.SeverityString() != "75" {
		t.Errorf("SeverityString() = %q, want %q", r.SeverityString(), "75")
	}
}

func TestParseRule_MissingAttack(t *testing.T) {
	const ruleYAML = `
title: t
id: OLT-IMPACT-006
detection:
  sel:
    a: b
  condition: sel
`
	_, err := ParseRule([]byte(ruleYAML))
	if err == nil {
		t.Fatalf("ParseRule: expected error, got nil")
	}
	if got, want := err.Error(), "attack: required field is missing"; got != want {
		t.Errorf("error = %q, want %q", got, want)
	}
}

func TestParseRule_EmptyAttackList(t *testing.T) {
	const ruleYAML = `
title: t
id: OLT-IMPACT-007
attack: []
detection:
  sel:
    a: b
  condition: sel
`
	_, err := ParseRule([]byte(ruleYAML))
	if err == nil {
		t.Fatalf("ParseRule: expected error, got nil")
	}
	if got, want := err.Error(), "attack: must be a non-empty list"; got != want {
		t.Errorf("error = %q, want %q", got, want)
	}
}

func TestParseRule_NilAttack(t *testing.T) {
	const ruleYAML = `
title: t
id: OLT-IMPACT-008
attack: ~
detection:
  sel:
    a: b
  condition: sel
`
	_, err := ParseRule([]byte(ruleYAML))
	if err == nil {
		t.Fatalf("ParseRule: expected error, got nil")
	}
	if got, want := err.Error(), "attack: must be a non-empty list"; got != want {
		t.Errorf("error = %q, want %q", got, want)
	}
}

func TestParseRule_InvalidTechniqueFormat(t *testing.T) {
	for _, bad := range []string{"T12", "T12345", "T1234.12", "T1234.1234", "X1234", "t1234"} {
		t.Run(bad, func(t *testing.T) {
			ruleYAML := "title: t\nid: OLT-IMPACT-009\nattack:\n  - " + bad + "\ndetection:\n  sel:\n    a: b\n  condition: sel\n"
			_, err := ParseRule([]byte(ruleYAML))
			if err == nil {
				t.Fatalf("expected rejection for %q, got nil", bad)
			}
			if !strings.HasPrefix(err.Error(), "attack: ") || !strings.Contains(err.Error(), "does not match") {
				t.Errorf("unexpected error shape for %q: %v", bad, err)
			}
		})
	}
}

func TestParseRule_ValidTechniqueVariants(t *testing.T) {
	for _, ok := range []string{"T1234", "T9999", "T1234.001", "T1234.999"} {
		t.Run(ok, func(t *testing.T) {
			ruleYAML := "title: t\nid: OLT-IMPACT-010\nattack:\n  - " + ok + "\ndetection:\n  sel:\n    a: b\n  condition: sel\n"
			if _, err := ParseRule([]byte(ruleYAML)); err != nil {
				t.Errorf("expected accept for %q, got %v", ok, err)
			}
		})
	}
}

func TestParseRule_ExplicitSeverityNull(t *testing.T) {
	const ruleYAML = `
title: t
id: OLT-IMPACT-011
attack:
  - T1496
severity: null
detection:
  sel:
    a: b
  condition: sel
`
	_, err := ParseRule([]byte(ruleYAML))
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	const want = "severity: explicit null is not permitted; omit the key to use the level fallback, or supply an integer 0-100"
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
}

func TestParseRule_OutOfRangeSeverity(t *testing.T) {
	for _, sev := range []int{-1, 101, 200, -100} {
		t.Run("sev", func(t *testing.T) {
			ruleYAML := "title: t\nid: OLT-IMPACT-012\nattack:\n  - T1496\nseverity: " + itoa(sev) + "\ndetection:\n  sel:\n    a: b\n  condition: sel\n"
			_, err := ParseRule([]byte(ruleYAML))
			if err == nil {
				t.Fatalf("expected rejection for severity=%d", sev)
			}
			if !strings.HasPrefix(err.Error(), "severity:") || !strings.Contains(err.Error(), "is outside [0, 100]") {
				t.Errorf("unexpected error for severity=%d: %v", sev, err)
			}
		})
	}
}

func TestParseRule_SeverityWinsOverLevel(t *testing.T) {
	const ruleYAML = `
title: t
id: OLT-IMPACT-013
attack:
  - T1496
severity: 42
level: critical
detection:
  sel:
    a: b
  condition: sel
`
	r, err := ParseRule([]byte(ruleYAML))
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}
	if r.Severity != 42 {
		t.Errorf("Severity = %d, want 42 (explicit severity must win over level)", r.Severity)
	}
	if !r.HasSeverity {
		t.Errorf("HasSeverity = false, want true (explicit severity was provided)")
	}
}

func TestParseRule_LevelOnlyFallback(t *testing.T) {
	cases := []struct {
		level string
		want  int
	}{
		{"informational", 10},
		{"low", 30},
		{"medium", 50},
		{"high", 75},
		{"critical", 90},
	}
	for _, c := range cases {
		t.Run(c.level, func(t *testing.T) {
			ruleYAML := "title: t\nid: OLT-IMPACT-014\nattack:\n  - T1496\nlevel: " + c.level + "\ndetection:\n  sel:\n    a: b\n  condition: sel\n"
			r, err := ParseRule([]byte(ruleYAML))
			if err != nil {
				t.Fatalf("ParseRule(%s): %v", c.level, err)
			}
			if r.Severity != c.want {
				t.Errorf("level=%s: Severity = %d, want %d", c.level, r.Severity, c.want)
			}
			if r.HasSeverity {
				t.Errorf("level=%s: HasSeverity = true, want false (severity was not explicit)", c.level)
			}
		})
	}
}

func TestParseRule_UnknownLevel(t *testing.T) {
	const ruleYAML = `
title: t
id: OLT-IMPACT-015
attack:
  - T1496
level: catastrophic
detection:
  sel:
    a: b
  condition: sel
`
	_, err := ParseRule([]byte(ruleYAML))
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	const want = `level: "catastrophic" is not a SIGMA-HQ level (informational, low, medium, high, critical)`
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
}

func TestParseRule_DefaultSeverityWhenAbsent(t *testing.T) {
	const ruleYAML = `
title: t
id: OLT-IMPACT-016
attack:
  - T1496
detection:
  sel:
    a: b
  condition: sel
`
	r, err := ParseRule([]byte(ruleYAML))
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}
	if r.Severity != 50 {
		t.Errorf("Severity = %d, want 50 (default when neither severity nor level present)", r.Severity)
	}
	if r.HasSeverity {
		t.Errorf("HasSeverity = true, want false (no explicit severity)")
	}
}

func TestParseRule_SeverityExplicitZero(t *testing.T) {
	const ruleYAML = `
title: t
id: OLT-IMPACT-017
attack:
  - T1496
severity: 0
detection:
  sel:
    a: b
  condition: sel
`
	r, err := ParseRule([]byte(ruleYAML))
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}
	if r.Severity != 0 {
		t.Errorf("Severity = %d, want 0", r.Severity)
	}
	if !r.HasSeverity {
		t.Errorf("HasSeverity = false, want true (operator explicitly set severity to 0)")
	}
}

func TestParseRule_RuleIDGrammar(t *testing.T) {
	cases := []struct {
		id      string
		wantErr bool
	}{
		{"OLT-EXEC-001", false},
		{"OLT-NET-999", false},
		{"OLT-FILE-100", false},
		{"OLT-PRIV-042", false},
		{"OLT-IMPACT-005", false},
		{"OLT-RECON-010", false},
		{"OLT-PERSIST-001", false},
		{"OLT-EXFIL-001", false},
		{"OLT-CRED-001", false},
		{"OLT-LATERAL-001", false},
		{"OLT-OTHER-001", true},      // unknown category
		{"OLT-EXEC-1", true},         // wrong sequence width
		{"OLT-EXEC-1000", true},      // sequence too wide
		{"olt-exec-001", true},       // lowercase
		{"OLT_EXEC_001", true},       // underscores
		{"SIGMA-EXEC-001", true},     // wrong prefix
		{"OLT-EXEC-001-extra", true}, // trailing garbage
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			ruleYAML := "title: t\nid: " + c.id + "\nattack:\n  - T1234\ndetection:\n  sel:\n    a: b\n  condition: sel\n"
			_, err := ParseRule([]byte(ruleYAML))
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected rejection for id=%q", c.id)
				}
				if !strings.HasPrefix(err.Error(), "id: ") || !strings.Contains(err.Error(), "does not match") {
					t.Errorf("unexpected error for id=%q: %v", c.id, err)
				}
			} else {
				if err != nil {
					t.Errorf("expected accept for id=%q, got %v", c.id, err)
				}
			}
		})
	}
}

// TestParseRule_MissingTitle asserts a rule without the required
// title key fails parse. sigmalite delegates the requirement; the
// OLT parser propagates the error verbatim (code-review P14 /
// AC5(b)).
func TestParseRule_MissingTitle(t *testing.T) {
	body := `
id: OLT-EXEC-001
attack: [T1234]
detection:
  sel:
    process.exe|contains: 'curl'
  condition: sel
`
	_, err := ParseRule([]byte(body))
	if err == nil {
		t.Fatal("expected error for missing title, got nil")
	}
}

// TestParseRule_MissingDetection asserts a rule without the detection
// key fails parse. sigmalite enforces the requirement (code-review
// P14 / AC5(b)).
func TestParseRule_MissingDetection(t *testing.T) {
	body := `
title: t
id: OLT-EXEC-001
attack: [T1234]
`
	_, err := ParseRule([]byte(body))
	if err == nil {
		t.Fatal("expected error for missing detection, got nil")
	}
}

// TestParseRule_EmptyDetectionClause asserts a rule with detection
// declared but containing zero selection clauses (i.e. only the
// `condition:` key) fails parse. A rule with no clauses cannot
// produce matches and its evaluation behaviour under sigmalite is
// undefined; reject at parse time so operators get a clear error
// rather than a silently never-matching rule (code-review P20).
func TestParseRule_EmptyDetectionClause(t *testing.T) {
	body := `
title: t
id: OLT-EXEC-001
attack: [T1234]
detection:
  condition: sel
`
	_, err := ParseRule([]byte(body))
	if err == nil {
		t.Fatal("expected error for detection containing only a condition (no selection clauses)")
	}
}

func TestParseRule_MalformedYAML(t *testing.T) {
	cases := []string{
		"   not valid: yaml: at: all:",
		"title: t\nid: OLT-EXEC-001\nattack:\n  - T1234\ndetection: not-a-map\n",
		"\x00\x01\x02",
	}
	for _, raw := range cases {
		_, err := ParseRule([]byte(raw))
		if err == nil {
			t.Errorf("expected error for malformed YAML: %q", raw)
		}
	}
}

// itoa returns the decimal representation of i. Tests use this rather
// than strconv so the test file does not introduce an import strictly
// for compose-into-yaml usage.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
