package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/eval/capture"
)

// scenariosTreeRoot resolves the committed deploy/demo/scenarios/ tree from
// the cmd/olaitan-eval/ test working directory (two levels up).
func scenariosTreeRoot() string {
	return filepath.Join("..", "..", "deploy", "demo", "scenarios")
}

// TestCaptureTarget_ProjectsResolvedTarget asserts captureTarget projects the
// resolved scenarioTarget onto the capture.Target the Story-5.4 metadata
// measurement consumes (BI-9, the cross-story seam; 5.2 declares, 5.4
// measures), and that a non-harness Scenario yields the zero Target.
func TestCaptureTarget_ProjectsResolvedTarget(t *testing.T) {
	sc, err := newScenario("s2", scenariosTreeRoot(), testLogger())
	if err != nil {
		t.Fatalf("newScenario: %v", err)
	}
	tgt := captureTarget(sc)
	if tgt.FSMState != "RESTRICTED" || tgt.TimeToDetectSeconds != 60 || !tgt.Floor {
		t.Errorf("captureTarget(s2) = %+v; want RESTRICTED/60/floor=true", tgt)
	}

	// A non-harness Scenario (no resolved target) yields the zero Target,
	// which the measurement treats as never-met.
	zero := captureTarget(scenarioFunc(func(context.Context) error { return nil }))
	if zero != (capture.Target{}) {
		t.Errorf("captureTarget(non-harness) = %+v; want the zero Target", zero)
	}
}

// scenarioFunc adapts a func to the Scenario interface for the non-harness
// captureTarget case.
type scenarioFunc func(context.Context) error

func (f scenarioFunc) Run(ctx context.Context) error { return f(ctx) }

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
}

// TestNewScenario_DispatchAllFive asserts the factory maps every s1..s5 id to
// the matching descriptive-slug harness (BI-1) and that --scenario s3
// resolves the S3 harness (NOT a hardwired rsScenario). It also pins the
// AC2-AC6 target.yaml values (Task 1.3) read off the committed tree.
func TestNewScenario_DispatchAllFive(t *testing.T) {
	root := scenariosTreeRoot()
	cases := []struct {
		id        string
		slug      string
		technique string
		state     string
		ttd       int
		floor     bool
		rules     []string
	}{
		{"s1", "s1-container-escape", "T1611", "QUARANTINED", 30, false, []string{"OLT-PRIV-001"}},
		{"s2", "s2-credential-exfil", "T1552", "RESTRICTED", 60, true, []string{"OLT-CRED-001", "OLT-CRED-002"}},
		{"s3", "s3-lateral-movement", "T1613", "QUARANTINED", 90, false, []string{"OLT-LATERAL-001"}},
		{"s4", "s4-c2-beaconing", "T1071", "SUSPICIOUS", 300, true, []string{"OLT-NET-001", "OLT-NET-002"}},
		{"s5", "s5-cryptomining", "T1496", "RESTRICTED", 120, false, []string{"OLT-IMPACT-005", "OLT-IMPACT-006"}},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			sc, err := newScenario(tc.id, root, testLogger())
			if err != nil {
				t.Fatalf("newScenario(%q): %v", tc.id, err)
			}
			h, ok := sc.(*scenarioHarness)
			if !ok {
				t.Fatalf("scenario %q is %T; want *scenarioHarness", tc.id, sc)
			}
			if h.id != tc.id {
				t.Errorf("harness id = %q; want %q", h.id, tc.id)
			}
			if filepath.Base(h.dir) != tc.slug {
				t.Errorf("harness dir = %q; want slug %q", h.dir, tc.slug)
			}
			if h.target.MitreTechnique != tc.technique {
				t.Errorf("mitre_technique = %q; want %q", h.target.MitreTechnique, tc.technique)
			}
			if h.target.TargetFSMState != tc.state {
				t.Errorf("target_fsm_state = %q; want %q", h.target.TargetFSMState, tc.state)
			}
			if h.target.TargetTimeToDetectSeconds != tc.ttd {
				t.Errorf("target_time_to_detect_seconds = %d; want %d", h.target.TargetTimeToDetectSeconds, tc.ttd)
			}
			if h.target.Floor != tc.floor {
				t.Errorf("floor = %v; want %v", h.target.Floor, tc.floor)
			}
			if len(h.target.TriggeringRules) != len(tc.rules) {
				t.Fatalf("triggering_rules = %v; want %v", h.target.TriggeringRules, tc.rules)
			}
			for i, r := range tc.rules {
				if h.target.TriggeringRules[i] != r {
					t.Errorf("triggering_rules[%d] = %q; want %q", i, h.target.TriggeringRules[i], r)
				}
			}
			// Run must dispatch without error (the honest in-process
			// log-and-resolve path; the injection lives in the e2e test).
			if err := sc.Run(context.Background()); err != nil {
				t.Errorf("Run(%q): %v", tc.id, err)
			}
		})
	}
}

// TestNewScenario_RejectsUnknownID asserts an id with no harness mapping is a
// hard error (no silent no-op).
func TestNewScenario_RejectsUnknownID(t *testing.T) {
	if _, err := newScenario("s99", scenariosTreeRoot(), testLogger()); err == nil {
		t.Fatalf("expected an error for an unmapped scenario id, got nil")
	}
}

// TestNewScenario_MissingHarnessFailsLoudly asserts a missing harness
// directory (bad scenariosRoot) is a hard error so a mis-wired tree cannot
// silently no-op.
func TestNewScenario_MissingHarnessFailsLoudly(t *testing.T) {
	if _, err := newScenario("s1", t.TempDir(), testLogger()); err == nil {
		t.Fatalf("expected an error for a missing harness dir, got nil")
	}
}

// TestLoadScenarioTarget_FailFast asserts the target.yaml validator rejects a
// missing/invalid field rather than passing a malformed contract through to
// Story 5.4's metadata writer (BI-2).
func TestLoadScenarioTarget_FailFast(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"missing scenario_id": "mitre_technique: T1611\ntarget_fsm_state: QUARANTINED\ntarget_time_to_detect_seconds: 30\ntriggering_rules: [OLT-PRIV-001]\n",
		"missing technique":   "scenario_id: s1\ntarget_fsm_state: QUARANTINED\ntarget_time_to_detect_seconds: 30\ntriggering_rules: [OLT-PRIV-001]\n",
		"invalid state":       "scenario_id: s1\nmitre_technique: T1611\ntarget_fsm_state: CLEAN\ntarget_time_to_detect_seconds: 30\ntriggering_rules: [OLT-PRIV-001]\n",
		"zero ttd":            "scenario_id: s1\nmitre_technique: T1611\ntarget_fsm_state: QUARANTINED\ntarget_time_to_detect_seconds: 0\ntriggering_rules: [OLT-PRIV-001]\n",
		"no rules":            "scenario_id: s1\nmitre_technique: T1611\ntarget_fsm_state: QUARANTINED\ntarget_time_to_detect_seconds: 30\ntriggering_rules: []\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, "target.yaml")
			if err := writeFile(path, body); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			if _, err := loadScenarioTarget(path); err == nil {
				t.Errorf("expected a fail-fast error for %q, got nil", name)
			}
		})
	}
}

// TestScenarioEvents_Deterministic asserts AC7: the emitted event set is
// byte-stable across two invocations modulo the injection timestamp. With a
// FIXED timestamp the two batches are byte-identical; with two DIFFERENT
// timestamps they differ ONLY in the timestamp field (so re-running the
// stimulus is deterministic by construction: no rand, no clock-keyed
// branching).
func TestScenarioEvents_Deterministic(t *testing.T) {
	ts := time.Date(2026, 6, 15, 9, 30, 0, 0, time.UTC)
	for _, id := range []string{"s1", "s2", "s3", "s4", "s5"} {
		t.Run(id, func(t *testing.T) {
			a := scenarioEvents(id, "web-pod-abc", ts)
			b := scenarioEvents(id, "web-pod-abc", ts)
			if len(a) == 0 {
				t.Fatalf("scenario %q produced no events", id)
			}
			if len(a) != len(b) {
				t.Fatalf("event count differs across invocations: %d vs %d", len(a), len(b))
			}
			for i := range a {
				if a[i].Subject != b[i].Subject {
					t.Errorf("event[%d] subject differs: %q vs %q", i, a[i].Subject, b[i].Subject)
				}
				if !bytes.Equal(a[i].Payload, b[i].Payload) {
					t.Errorf("event[%d] payload not byte-stable across two invocations:\n a=%s\n b=%s", i, a[i].Payload, b[i].Payload)
				}
			}

			// A different injection timestamp changes ONLY the timestamp
			// field (the AC7 "modulo injection timestamp" clause): blanking
			// the timestamp out of both batches yields byte-identical events.
			c := scenarioEvents(id, "web-pod-abc", ts.Add(7*time.Hour))
			for i := range a {
				if !bytes.Equal(stripTimestamp(t, a[i].Payload), stripTimestamp(t, c[i].Payload)) {
					t.Errorf("event[%d] differs beyond the timestamp across two timestamps:\n a=%s\n c=%s", i, a[i].Payload, c[i].Payload)
				}
			}
		})
	}
}

// TestScenarioEvents_MatchTheRuleFieldShapes pins the load-bearing field
// shapes each scenario's stimulus must carry so the OLT rule fires (a drift
// guard against the Dev Notes mapping). It does not run the rule engine (that
// is the e2e proof); it asserts the synthetic events carry the exact fields
// the rule detection blocks key on.
func TestScenarioEvents_MatchTheRuleFieldShapes(t *testing.T) {
	ts := time.Now().UTC()
	pod := "web-pod-abc"

	// S1: a falco event whose process.cap_effective contains CAP_SYS_ADMIN.
	if got := rawField(t, scenarioEvents("s1", pod, ts), rawFalcoSubject, "process.cap_effective"); !strings.Contains(got, "CAP_SYS_ADMIN") {
		t.Errorf("s1 process.cap_effective = %q; want it to contain CAP_SYS_ADMIN", got)
	}
	// S2: a falco event whose file.path is the SA-token path, by a non-system process.
	if got := rawField(t, scenarioEvents("s2", pod, ts), rawFalcoSubject, "file.path"); got != "/run/secrets/kubernetes.io/serviceaccount/token" {
		t.Errorf("s2 file.path = %q; want the SA-token path", got)
	}
	if got := rawField(t, scenarioEvents("s2", pod, ts), rawNetworkSubject, "network.dst_ip"); got != "169.254.169.254" {
		t.Errorf("s2 network.dst_ip = %q; want the metadata IP", got)
	}
	// S3: a falco event whose process.exe ends /kubectl.
	if got := rawField(t, scenarioEvents("s3", pod, ts), rawFalcoSubject, "process.exe"); got != "/usr/local/bin/kubectl" {
		t.Errorf("s3 process.exe = %q; want a /kubectl path", got)
	}
	// S4: a small non-RFC1918 flow to a C2 port. dst_port is an integer.
	s4 := scenarioEvents("s4", pod, ts)
	if got := rawField(t, s4, rawNetworkSubject, "network.dst_ip"); got != "203.0.113.10" {
		t.Errorf("s4 network.dst_ip = %q; want the TEST-NET-3 (non-RFC1918) address", got)
	}
	if got := rawFieldNumber(t, s4, rawNetworkSubject, "network.dst_port"); got != 8443 {
		t.Errorf("s4 network.dst_port = %v; want a C2 port", got)
	}
	if got := rawField(t, s4, rawNetworkSubject, "network.bytes_out"); got != "512" {
		t.Errorf("s4 network.bytes_out = %q; want a <1000-byte payload", got)
	}
	// S5: a miner process to a pool port + a stratum flow with WARNING severity.
	s5 := scenarioEvents("s5", pod, ts)
	if got := rawField(t, s5, rawFalcoSubject, "process.exe"); got != "/tmp/xmrig" {
		t.Errorf("s5 process.exe = %q; want a miner binary", got)
	}
	if got := topField(t, s5, rawNetworkSubject, "severity"); got != "WARNING" {
		t.Errorf("s5 network event severity = %q; want WARNING (OLT-IMPACT-006)", got)
	}
}

// TestScenarioEvents_TwoDistinctSources asserts every scenario's stimulus
// carries at least TWO distinct event sources so the correlator's
// rising-edge (MultiSignalMinSources=2) fires and assembles the EvidencePackage
// the rules engine evaluates.
func TestScenarioEvents_TwoDistinctSources(t *testing.T) {
	for _, id := range []string{"s1", "s2", "s3", "s4", "s5"} {
		evs := scenarioEvents(id, "web-pod-abc", time.Now().UTC())
		sources := map[string]bool{}
		for _, e := range evs {
			var ev map[string]any
			if err := json.Unmarshal(e.Payload, &ev); err != nil {
				t.Fatalf("%s: unmarshal: %v", id, err)
			}
			sources[ev["source"].(string)] = true
		}
		if len(sources) < 2 {
			t.Errorf("scenario %q has %d distinct source(s) %v; want >= 2 for the rising edge", id, len(sources), sources)
		}
	}
}

// TestScenarioBaselinePreseed asserts only S4 rests (partly) on a baseline
// deviation (BI-4); the others fire on a rule match alone.
func TestScenarioBaselinePreseed(t *testing.T) {
	for _, id := range []string{"s1", "s2", "s3", "s5"} {
		if scenarioBaselinePreseed(id) {
			t.Errorf("scenario %q should not require a baseline pre-seed", id)
		}
	}
	if !scenarioBaselinePreseed("s4") {
		t.Errorf("scenario s4 should require a baseline pre-seed (BI-4)")
	}
}

// --- test helpers -------------------------------------------------------

func writeFile(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o644)
}

func stripTimestamp(t *testing.T, payload []byte) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	delete(m, "timestamp")
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("re-marshal payload: %v", err)
	}
	return out
}

// rawField returns the string value of a flattened raw-field key on the FIRST
// event in evs whose subject matches.
func rawField(t *testing.T, evs []scenarioEvent, subject, key string) string {
	t.Helper()
	raw := rawMap(t, evs, subject)
	if raw == nil {
		return ""
	}
	v, _ := raw[key].(string)
	return v
}

func rawFieldNumber(t *testing.T, evs []scenarioEvent, subject, key string) float64 {
	t.Helper()
	raw := rawMap(t, evs, subject)
	if raw == nil {
		return 0
	}
	v, _ := raw[key].(float64)
	return v
}

// topField returns the top-level (non-raw) string value on the FIRST event in
// evs whose subject matches and which carries the key.
func topField(t *testing.T, evs []scenarioEvent, subject, key string) string {
	t.Helper()
	for _, e := range evs {
		if e.Subject != subject {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal(e.Payload, &ev); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if v, ok := ev[key].(string); ok {
			return v
		}
	}
	return ""
}

// rawMap returns the parsed `raw` object of the LAST event on the subject
// (the match event; the priming/extra events come first).
func rawMap(t *testing.T, evs []scenarioEvent, subject string) map[string]any {
	t.Helper()
	var found map[string]any
	for _, e := range evs {
		if e.Subject != subject {
			continue
		}
		var ev struct {
			Raw json.RawMessage `json:"raw"`
		}
		if err := json.Unmarshal(e.Payload, &ev); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		var raw map[string]any
		if err := json.Unmarshal(ev.Raw, &raw); err != nil {
			t.Fatalf("unmarshal raw: %v", err)
		}
		found = raw
	}
	return found
}
