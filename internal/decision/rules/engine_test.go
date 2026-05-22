package rules

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/olokotoh/olaitan/internal/correlator/trigger"
	"github.com/olokotoh/olaitan/internal/decision/rules/loader"
	"github.com/olokotoh/olaitan/internal/schema"
)

const ruleEventID = `
title: Match if event has any event.id
id: OLT-EXEC-001
attack:
  - T1059
detection:
  sel:
    event.id|re: '.+'
  condition: sel
`

const ruleProcExe = `
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

const rulePostureNS = `
title: Tenant namespace gate
id: OLT-NET-001
attack:
  - T1071
severity: 40
detection:
  sel:
    k8s.pod.namespace|startswith: 'tenant-'
  condition: sel
`

func writeRule(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatalf("write rule: %v", err)
	}
}

func TestEvaluatePackage_MatchesProcessExeRule(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "olt-impact-005.yaml", ruleProcExe)
	l := loader.New(dir, nil)
	if err := l.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	e := &Engine{loader: l}

	raw, _ := json.Marshal(map[string]any{"process.exe": "/usr/local/bin/xmrig"})
	pkg := &schema.EvidencePackage{
		PackageID:  "pkg-1",
		WorkloadID: "ns/Deployment/web",
		Events: []schema.Event{
			{ID: "ev-1", Source: schema.SourceFalco, Category: schema.CategorySyscall, Raw: raw},
		},
	}

	matches := e.evaluatePackage(pkg, l.Get())
	if len(matches) != 1 {
		t.Fatalf("matches = %d, want 1", len(matches))
	}
	got := matches[0]
	if got.RuleID != "OLT-IMPACT-005" {
		t.Errorf("RuleID = %q, want OLT-IMPACT-005", got.RuleID)
	}
	if got.Severity != "75" {
		t.Errorf("Severity = %q, want 75", got.Severity)
	}
	if got.EventID != "ev-1" {
		t.Errorf("EventID = %q, want ev-1", got.EventID)
	}
	if len(got.MitreTags) != 1 || got.MitreTags[0] != "T1496" {
		t.Errorf("MitreTags = %v, want [T1496]", got.MitreTags)
	}
}

func TestEvaluatePackage_NoMatchesProducesEmpty(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "olt-impact-005.yaml", ruleProcExe)
	l := loader.New(dir, nil)
	if err := l.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	e := &Engine{loader: l}

	raw, _ := json.Marshal(map[string]any{"process.exe": "/usr/bin/redis-server"})
	pkg := &schema.EvidencePackage{
		PackageID: "pkg-2",
		Events:    []schema.Event{{ID: "ev-1", Raw: raw}},
	}
	if matches := e.evaluatePackage(pkg, l.Get()); len(matches) != 0 {
		t.Errorf("matches = %v, want empty", matches)
	}
}

func TestEvaluatePackage_PerEventFanOut(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "olt-impact-005.yaml", ruleProcExe)
	l := loader.New(dir, nil)
	if err := l.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	e := &Engine{loader: l}

	raw1, _ := json.Marshal(map[string]any{"process.exe": "/usr/local/bin/xmrig"})
	raw2, _ := json.Marshal(map[string]any{"process.exe": "/usr/local/bin/xmrig"})
	pkg := &schema.EvidencePackage{
		PackageID: "pkg-3",
		Events: []schema.Event{
			{ID: "ev-1", Raw: raw1},
			{ID: "ev-2", Raw: raw2},
		},
	}
	matches := e.evaluatePackage(pkg, l.Get())
	if len(matches) != 2 {
		t.Fatalf("matches = %d, want 2 (one per event)", len(matches))
	}
	if matches[0].EventID != "ev-1" || matches[1].EventID != "ev-2" {
		t.Errorf("EventIDs = [%q, %q], want [ev-1, ev-2]", matches[0].EventID, matches[1].EventID)
	}
}

func TestEvaluatePackage_K8sFieldsResolvedFromPosture(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "olt-net-001.yaml", rulePostureNS)
	l := loader.New(dir, nil)
	if err := l.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	e := &Engine{loader: l}

	pkg := &schema.EvidencePackage{
		PackageID: "pkg-4",
		WorkloadPosture: &schema.WorkloadPosture{
			Identity: schema.WorkloadIdentity{
				Namespace: "tenant-acme",
				OwnerKind: "Deployment",
				OwnerName: "web",
			},
		},
		Events: []schema.Event{{ID: "ev-1"}},
	}
	if matches := e.evaluatePackage(pkg, l.Get()); len(matches) != 1 {
		t.Errorf("matches = %d, want 1 (rule references k8s.pod.namespace only)", len(matches))
	}
}

func TestEvaluatePackage_NoEventsFallsBackToPackageID(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "olt-net-001.yaml", rulePostureNS)
	l := loader.New(dir, nil)
	if err := l.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	e := &Engine{loader: l}

	pkg := &schema.EvidencePackage{
		PackageID: "pkg-fallback",
		WorkloadPosture: &schema.WorkloadPosture{
			Identity: schema.WorkloadIdentity{Namespace: "tenant-x"},
		},
	}
	matches := e.evaluatePackage(pkg, l.Get())
	if len(matches) != 1 {
		t.Fatalf("matches = %d, want 1", len(matches))
	}
	if matches[0].EventID != "pkg-fallback" {
		t.Errorf("EventID = %q, want pkg-fallback (fallback to PackageID)", matches[0].EventID)
	}
}

func TestEvaluatePackage_NoLoadedRulesEmpty(t *testing.T) {
	dir := t.TempDir()
	l := loader.New(dir, nil)
	if err := l.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	e := &Engine{loader: l}

	pkg := &schema.EvidencePackage{PackageID: "pkg-empty", Events: []schema.Event{{ID: "ev-1"}}}
	if matches := e.evaluatePackage(pkg, l.Get()); len(matches) != 0 {
		t.Errorf("matches = %v on empty corpus, want empty", matches)
	}
}

func TestChooseEventID(t *testing.T) {
	if got := chooseEventID("ev", "pkg"); got != "ev" {
		t.Errorf("chooseEventID(ev, pkg) = %q, want ev", got)
	}
	if got := chooseEventID("", "pkg"); got != "pkg" {
		t.Errorf("chooseEventID(, pkg) = %q, want pkg", got)
	}
}

// TestReEntrancyGuard_ContractStability pins the constant so a
// future refactor of trigger.TypeRuleMatch surfaces here rather than
// silently breaking the engine guard.
func TestReEntrancyGuard_ContractStability(t *testing.T) {
	if trigger.TypeRuleMatch != "rule_match" {
		t.Errorf("trigger.TypeRuleMatch = %q, want %q (engine.handle() relies on this)",
			trigger.TypeRuleMatch, "rule_match")
	}
}

// TestApplyReEntrancyGuard_SkipsRuleMatchPackages exercises the
// guard logic directly: a rule_match-triggered package must be
// skipped and the skippedSelf counter must bump; any other trigger
// type must pass through (code-review P8). The integration test
// TestIntegration_ReEntrancyGuardSkipsRuleMatchPackages still
// covers the full handle() pipeline end-to-end.
// TestEvaluatePackage_ZeroEvents_EventIDIsUnsetInSynthetic exercises
// code-review D4: when pkg.Events is empty, evaluatePackage now
// synthesises schema.Event{} (no ID), so a rule referencing
// event.id resolves to nil and fails-open as a miss. Posture-only
// rules still fire via the resolver's k8s.* half (covered by
// TestEvaluatePackage_PostureOnlyRule).
func TestEvaluatePackage_ZeroEvents_EventIDIsUnsetInSynthetic(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "olt-exec-001.yaml", ruleEventID)
	l := loader.New(dir, nil)
	if err := l.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	e := &Engine{loader: l}

	pkg := &schema.EvidencePackage{
		PackageID:  "pkg-1",
		WorkloadID: "ns/Deployment/web",
		// Events deliberately empty
	}
	matches := e.evaluatePackage(pkg, l.Get())
	if len(matches) != 0 {
		t.Errorf("matches = %d, want 0 (event.id should be unset in the synthetic event)", len(matches))
	}
}

func TestApplyReEntrancyGuard_SkipsRuleMatchPackages(t *testing.T) {
	e := &Engine{}
	pkg := schema.EvidencePackage{
		PackageID: "pkg-1",
		Trigger:   schema.EvidenceTrigger{Type: trigger.TypeRuleMatch},
	}
	if !e.applyReEntrancyGuard(&pkg) {
		t.Errorf("applyReEntrancyGuard(rule_match): got false, want true")
	}
	if got := e.skippedSelf.Load(); got != 1 {
		t.Errorf("skippedSelf after rule_match guard: got %d, want 1", got)
	}
}

func TestApplyReEntrancyGuard_PassesThroughOtherTriggers(t *testing.T) {
	e := &Engine{}
	for _, ty := range []string{
		"", // zero value
		trigger.TypeMultiSignal,
		trigger.TypeBaselineDeviation,
	} {
		pkg := schema.EvidencePackage{
			PackageID: "pkg-1",
			Trigger:   schema.EvidenceTrigger{Type: ty},
		}
		if e.applyReEntrancyGuard(&pkg) {
			t.Errorf("applyReEntrancyGuard(%q): got true, want false (only rule_match should skip)", ty)
		}
	}
	if got := e.skippedSelf.Load(); got != 0 {
		t.Errorf("skippedSelf after non-rule_match guards: got %d, want 0", got)
	}
}

func TestNoteReloadRejected_BumpsCounter(t *testing.T) {
	e := &Engine{}
	if e.reloadRejected.Load() != 0 {
		t.Errorf("reloadRejected: initial = %d, want 0", e.reloadRejected.Load())
	}
	e.NoteReloadRejected()
	e.NoteReloadRejected()
	if got := e.reloadRejected.Load(); got != 2 {
		t.Errorf("reloadRejected after 2 calls = %d, want 2", got)
	}
}

func TestIsExpectedFetchTimeout(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errStub("nats: no messages"), true},
		{errStub("foo"), false},
	}
	for _, c := range cases {
		if got := isExpectedFetchTimeout(c.err); got != c.want {
			t.Errorf("isExpectedFetchTimeout(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

type errStub string

func (e errStub) Error() string { return string(e) }
