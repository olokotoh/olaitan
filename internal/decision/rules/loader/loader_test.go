package loader

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const ruleOLT005 = `
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

const ruleOLT006 = `
title: Privileged container
id: OLT-PRIV-001
attack:
  - T1611
severity: 90
detection:
  sel:
    process.privileged: 'true'
  condition: sel
`

const ruleBadAttack = `
title: t
id: OLT-NET-001
attack: []
detection:
  sel:
    a: b
  condition: sel
`

func writeRule(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write rule %s: %v", name, err)
	}
	return p
}

func TestLoad_EmptyDirEmptyCorpus(t *testing.T) {
	dir := t.TempDir()
	l := New(dir, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	if err := l.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if l.Get().Len() != 0 {
		t.Errorf("Len = %d, want 0", l.Get().Len())
	}
}

func TestLoad_SingleValidRule(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "olt-impact-005.yaml", ruleOLT005)
	l := New(dir, nil)
	if err := l.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	c := l.Get()
	if c.Len() != 1 {
		t.Fatalf("Len = %d, want 1", c.Len())
	}
	r := c.ByID["OLT-IMPACT-005"]
	if r == nil {
		t.Fatalf("ByID missing OLT-IMPACT-005")
	}
	if r.SourcePath == "" {
		t.Errorf("SourcePath empty; loader should populate it")
	}
}

func TestLoad_MultipleRulesAcrossCategories(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "olt-impact-005.yaml", ruleOLT005)
	writeRule(t, dir, "olt-priv-001.yml", ruleOLT006)
	l := New(dir, nil)
	if err := l.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if l.Get().Len() != 2 {
		t.Fatalf("Len = %d, want 2", l.Get().Len())
	}
	if l.Get().ByID["OLT-IMPACT-005"] == nil || l.Get().ByID["OLT-PRIV-001"] == nil {
		t.Errorf("ByID missing expected rules: %v", l.Get().ByID)
	}
}

func TestLoad_RejectsMalformedYAML(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "bad.yaml", "not: a: rule:")
	l := New(dir, nil)
	err := l.Load()
	if err == nil {
		t.Fatalf("expected error on malformed YAML")
	}
	if !strings.Contains(err.Error(), "parse") || !strings.Contains(err.Error(), "bad.yaml") {
		t.Errorf("error = %q, want substring 'parse' and the file name", err.Error())
	}
	if l.Get() != nil {
		t.Errorf("Get() != nil on failed initial Load")
	}
}

func TestLoad_RejectsMissingAttack(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "bad.yaml", ruleBadAttack)
	l := New(dir, nil)
	err := l.Load()
	if err == nil {
		t.Fatalf("expected error on empty attack list")
	}
	if !strings.Contains(err.Error(), "attack: must be a non-empty list") {
		t.Errorf("error = %q, want substring 'attack: must be a non-empty list'", err.Error())
	}
}

func TestLoad_DuplicateIDRejected(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "a.yaml", ruleOLT005)
	writeRule(t, dir, "b.yaml", ruleOLT005)
	l := New(dir, nil)
	err := l.Load()
	if err == nil {
		t.Fatalf("expected duplicate-id error")
	}
	if !strings.Contains(err.Error(), "duplicate id") {
		t.Errorf("error = %q, want substring 'duplicate id'", err.Error())
	}
}

func TestLoad_StableOrderByPath(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "z.yaml", ruleOLT006) // OLT-PRIV-001
	writeRule(t, dir, "a.yaml", ruleOLT005) // OLT-IMPACT-005
	l := New(dir, nil)
	if err := l.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if l.Get().Rules[0].ID != "OLT-IMPACT-005" {
		t.Errorf("first rule ID = %q, want OLT-IMPACT-005 (lexicographic file sort)", l.Get().Rules[0].ID)
	}
	if l.Get().Rules[1].ID != "OLT-PRIV-001" {
		t.Errorf("second rule ID = %q, want OLT-PRIV-001", l.Get().Rules[1].ID)
	}
}

func TestLoad_FailureRetainsPreviousCorpusOnSecondCall(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "good.yaml", ruleOLT005)
	l := New(dir, nil)
	if err := l.Load(); err != nil {
		t.Fatalf("first Load: %v", err)
	}
	prev := l.Get()

	// Add a broken rule and call Load again. The loader's contract
	// is: only the atomic swap is gated by success, so a failed
	// loadOnce returns the error and leaves the active pointer
	// alone.
	writeRule(t, dir, "bad.yaml", ruleBadAttack)
	if err := l.Load(); err == nil {
		t.Fatalf("expected error from second Load with a broken rule")
	}
	if l.Get() != prev {
		t.Errorf("active corpus changed after failed Load; want previous pointer retained")
	}
}

func TestLoad_IgnoresNonYAMLFiles(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "olt-impact-005.yaml", ruleOLT005)
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hello"), 0o600); err != nil {
		t.Fatalf("write README: %v", err)
	}
	l := New(dir, nil)
	if err := l.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if l.Get().Len() != 1 {
		t.Errorf("Len = %d, want 1 (README.md must be ignored)", l.Get().Len())
	}
}
