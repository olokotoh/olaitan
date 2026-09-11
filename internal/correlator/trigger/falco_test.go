package trigger

import (
	"encoding/json"
	"testing"

	"github.com/olokotoh/olaitan/internal/schema"
)

func falcoEvent(t *testing.T, rule, priority string, tags []string, source string) schema.Event {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"rule": rule, "priority": priority, "tags": tags, "source": source})
	if err != nil {
		t.Fatal(err)
	}
	return schema.Event{
		ID:     "ev-1",
		Source: schema.SourceFalco,
		Pod:    schema.PodRef{Name: "web-1", Namespace: "victim"},
		Raw:    raw,
	}
}

// Story 10.3 decision (2026-09-11): a Falco alert at Warning or above on a
// real pod starts an investigation by itself, as a rule_match. Falco is a
// rules engine; its verdict was being thrown away.
func TestFalcoRuleMatch(t *testing.T) {
	tags := []string{"T1555", "container", "filesystem", "maturity_stable", "mitre_credential_access"}
	m, ok := FalcoRuleMatch(falcoEvent(t, "Read sensitive file untrusted", "WARNING", tags, "syscall"), "warning")
	if !ok {
		t.Fatal("a Warning alert on a pod did not produce a rule match")
	}
	if m.RuleID != "falco:Read sensitive file untrusted" || m.RuleName != "Read sensitive file untrusted" || m.EventID != "ev-1" {
		t.Errorf("rule match = %+v", m)
	}
	if m.Severity != "50" {
		t.Errorf("Warning severity = %q, want 50 (the OLT scale: SUSPICIOUS on its own, not RESTRICTED)", m.Severity)
	}
	if len(m.MitreTags) != 1 || m.MitreTags[0] != "T1555" {
		t.Errorf("mitre tags = %v, want only the technique IDs", m.MitreTags)
	}

	for prio, want := range map[string]string{"ERROR": "75", "CRITICAL": "90", "ALERT": "100", "EMERGENCY": "100"} {
		if m, ok := FalcoRuleMatch(falcoEvent(t, "r", prio, nil, "syscall"), "warning"); !ok || m.Severity != want {
			t.Errorf("%s -> %q ok=%v, want %s", prio, m.Severity, ok, want)
		}
	}
}

func TestFalcoRuleMatchStaysQuiet(t *testing.T) {
	cases := map[string]struct {
		ev    schema.Event
		floor string
	}{
		"notice below the default floor":  {falcoEvent(t, "Terminal shell in container", "NOTICE", nil, "syscall"), "warning"},
		"warning below a critical floor":  {falcoEvent(t, "Read sensitive file untrusted", "WARNING", nil, "syscall"), "critical"},
		"trigger switched off":            {falcoEvent(t, "Read sensitive file untrusted", "CRITICAL", nil, "syscall"), "off"},
		"falco's own internal event":      {falcoEvent(t, "Falco internal: syscall event drop", "CRITICAL", nil, "internal"), "warning"},
		"unknown priority is not a floor": {falcoEvent(t, "r", "UNKNOWN(-1)", nil, "syscall"), "warning"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if m, ok := FalcoRuleMatch(tc.ev, tc.floor); ok {
				t.Errorf("fired: %+v", m)
			}
		})
	}
	host := falcoEvent(t, "Read sensitive file untrusted", "WARNING", nil, "syscall")
	host.Pod = schema.PodRef{Node: "n1"}
	if _, ok := FalcoRuleMatch(host, "warning"); ok {
		t.Error("a host event (no pod) fired a trigger")
	}
	audit := falcoEvent(t, "Read sensitive file untrusted", "WARNING", nil, "syscall")
	audit.Source = schema.SourceAudit
	if _, ok := FalcoRuleMatch(audit, "warning"); ok {
		t.Error("a non-Falco event fired the Falco trigger")
	}
	bad := falcoEvent(t, "r", "WARNING", nil, "syscall")
	bad.Raw = json.RawMessage(`not json`)
	if _, ok := FalcoRuleMatch(bad, "warning"); ok {
		t.Error("an undecodable Raw fired a trigger")
	}
}

func TestValidFalcoTriggerFloor(t *testing.T) {
	for _, ok := range []string{"", "off", "warning", "Warning", "error", "critical", "alert", "emergency"} {
		if err := ValidateFalcoTriggerFloor(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"notice", "informational", "debug", "high"} {
		if ValidateFalcoTriggerFloor(bad) == nil {
			t.Errorf("%q accepted; a floor below warning would let a plain kubectl exec start investigations", bad)
		}
	}
}
