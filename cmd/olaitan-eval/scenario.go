package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

// Story 5.2 fills the FROZEN Scenario seam (runner.go) WITHOUT reshaping the
// interface or the Runner loop (the Story 5.1 PO-Ratification-1 freeze). It
// supplies the five MITRE-annotated S1-S5 harnesses under
// deploy/demo/scenarios/ and a factory that maps the short --scenario sN id
// to the matching descriptive-slug harness directory.

// scenarioSlugs maps the short --scenario id (validateScenario accepts
// s1..s5) to the architecture's descriptive directory slug under
// deploy/demo/scenarios/ (BI-1: the architecture names the same directories
// with self-documenting slugs; each is resolvable from the short id via this
// deterministic map). This is the ONE deviation from the verbatim epic
// `{s1..s5}` shorthand, surfaced in the PR body.
var scenarioSlugs = map[string]string{
	"s1": "s1-container-escape",
	"s2": "s2-credential-exfil",
	"s3": "s3-lateral-movement",
	"s4": "s4-c2-beaconing",
	"s5": "s5-cryptomining",
}

// defaultScenariosRoot is the committed harness root the factory resolves
// scenario directories under. It is relative to the repository root (the
// olaitan-eval binary is run from the repo root, the eval-smoke / scenarios
// -smoke precedent).
const defaultScenariosRoot = "deploy/demo/scenarios"

// validFSMStates is the set of target_fsm_state values target.yaml may
// declare. It mirrors the escalation-capable FSM states an attack scenario
// can target (internal/schema/state.go); CLEAN is excluded because no attack
// targets the clean baseline.
var validFSMStates = map[string]bool{
	"SUSPICIOUS":       true,
	"RESTRICTED":       true,
	"QUARANTINED":      true,
	"PRESERVED_KILLED": true,
}

// scenarioTarget is the machine-readable target.yaml contract Story 5.2 OWNS
// and Story 5.4's metadata writer CONSUMES (BI-2). It declares the target
// FSM state + time-to-detect the run's measured outcome is scored against.
type scenarioTarget struct {
	ScenarioID                string   `yaml:"scenario_id"`
	MitreTechnique            string   `yaml:"mitre_technique"`
	TargetFSMState            string   `yaml:"target_fsm_state"`
	TargetTimeToDetectSeconds int      `yaml:"target_time_to_detect_seconds"`
	Floor                     bool     `yaml:"floor"`
	TriggeringRules           []string `yaml:"triggering_rules"`
}

// scenarioHarness is the rich Scenario impl Story 5.2 wires behind the frozen
// seam, one per S1-S5. It carries the resolved harness directory and the
// parsed target.yaml so the in-process Run can dispatch the matching harness
// honestly (BI-1, BI-2).
type scenarioHarness struct {
	id     string
	dir    string
	target scenarioTarget
	logger *slog.Logger
}

// newScenario is the scenario FACTORY (Story 5.2, Task 3.2). It maps the
// short --scenario id (s1..s5) to the matching descriptive-slug harness under
// scenariosRoot (BI-1), loads + validates that harness's target.yaml, and
// returns the rich Scenario impl. A nil scenarioSlugs entry, a missing
// harness directory, or an invalid target.yaml is a hard error so a
// mis-wired scenario fails loudly rather than silently no-opping (the BI-3
// "no silent no-op" discipline). scenariosRoot is a parameter so tests can
// point it at the committed tree from any working directory.
func newScenario(scenarioID, scenariosRoot string, logger *slog.Logger) (Scenario, error) {
	slug, ok := scenarioSlugs[scenarioID]
	if !ok {
		return nil, fmt.Errorf("scenario %q has no harness mapping (want one of %s)", scenarioID, knownScenarioIDs())
	}
	dir := filepath.Join(scenariosRoot, slug)
	target, err := loadScenarioTarget(filepath.Join(dir, "target.yaml"))
	if err != nil {
		return nil, fmt.Errorf("scenario %q (%s): %w", scenarioID, slug, err)
	}
	if target.ScenarioID != scenarioID {
		return nil, fmt.Errorf("scenario %q harness %s declares scenario_id %q; the id and the harness must agree", scenarioID, slug, target.ScenarioID)
	}
	return &scenarioHarness{id: scenarioID, dir: dir, target: target, logger: logger}, nil
}

// knownScenarioIDs returns the sorted s1..s5 ids the factory maps, for error
// messages.
func knownScenarioIDs() string {
	ids := make([]string, 0, len(scenarioSlugs))
	for id := range scenarioSlugs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := ""
	for i, id := range ids {
		if i > 0 {
			out += ", "
		}
		out += id
	}
	return out
}

// loadScenarioTarget parses + validates a harness target.yaml (BI-2). It
// fails fast on a missing file or any required field that is empty / invalid
// so a malformed contract cannot reach Story 5.4's metadata writer.
func loadScenarioTarget(path string) (scenarioTarget, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return scenarioTarget{}, fmt.Errorf("read target.yaml %q: %w", path, err)
	}
	var t scenarioTarget
	if err := yaml.Unmarshal(raw, &t); err != nil {
		return scenarioTarget{}, fmt.Errorf("parse target.yaml %q: %w", path, err)
	}
	if t.ScenarioID == "" {
		return scenarioTarget{}, fmt.Errorf("target.yaml %q: scenario_id is required", path)
	}
	if t.MitreTechnique == "" {
		return scenarioTarget{}, fmt.Errorf("target.yaml %q: mitre_technique is required", path)
	}
	if !validFSMStates[t.TargetFSMState] {
		return scenarioTarget{}, fmt.Errorf("target.yaml %q: target_fsm_state %q is not a valid escalation state (want one of SUSPICIOUS, RESTRICTED, QUARANTINED, PRESERVED_KILLED)", path, t.TargetFSMState)
	}
	if t.TargetTimeToDetectSeconds <= 0 {
		return scenarioTarget{}, fmt.Errorf("target.yaml %q: target_time_to_detect_seconds must be > 0 (got %d)", path, t.TargetTimeToDetectSeconds)
	}
	if len(t.TriggeringRules) == 0 {
		return scenarioTarget{}, fmt.Errorf("target.yaml %q: triggering_rules must list at least one OLT rule id", path)
	}
	return t, nil
}

// Run drives the scenario harness against the warmed cluster (Story 5.2,
// Task 3.3). HONEST in-process-vs-test-driven split (BI-3, the rs_smoke
// precedent): the synthetic-event INJECTION lives in the e2e test
// (tests/e2e/scenarios_smoke_test.go) for the same reason rs_smoke kept it
// there (it needs the kind port-forward + a JetStream connection the
// in-process binary does not hold on a host with no cluster). Run therefore
// resolves + validates the harness contract and logs the resolved harness +
// triggering rules so `olaitan-eval --scenario s3` honestly dispatches the
// S3 harness (NOT the 5.1 rsScenario no-op marker), and the e2e test invokes
// the matching injectScenario(scenarioID) helper against the same harness
// contract. This is a deliberate, documented split, not a silent no-op.
func (s *scenarioHarness) Run(ctx context.Context) error {
	s.logger.Info("scenario harness dispatched",
		"scenario", s.id,
		"harness_dir", s.dir,
		"mitre_technique", s.target.MitreTechnique,
		"target_fsm_state", s.target.TargetFSMState,
		"target_time_to_detect_seconds", s.target.TargetTimeToDetectSeconds,
		"triggering_rules", s.target.TriggeringRules,
		"stimulus", "synthetic-event injection driven by tests/e2e/scenarios_smoke_test.go on kind (BI-3)")
	return nil
}

// --- deterministic synthetic-event recipes (BI-3, AC7) -----------------
//
// The kind stimulus for each scenario is a fixed sequence of synthetic raw
// events published directly to olaitan.events.raw.{falco,network} (the
// rs_smoke precedent: Falco's eBPF probe cannot load inside a kind node, so
// the harness publishes the JSON events the production source would emit).
// scenarioEvents is the SINGLE SOURCE OF TRUTH for those recipes, shared by
// the determinism unit test (which asserts byte-stability across two
// invocations modulo the injection timestamp) and mirrored by the e2e
// injector. The event CONTENT and the script's BRANCHING are fixed; only the
// injection timestamp varies (AC7). No rand, no time.Now()-keyed branching,
// no outbound network.

// The raw-event subjects the synthetic injection targets (the subjects the
// production Falco / CNI exporters publish to). Held as local constants so
// scenario.go does not couple cmd/olaitan-eval to internal/subjects.
const (
	rawFalcoSubject   = "olaitan.events.raw.falco"
	rawNetworkSubject = "olaitan.events.raw.network"
)

// scenarioEvent is one synthetic raw event in a scenario's deterministic
// stimulus: the NATS subject to publish to and the JSON payload (the shape
// the production source would emit, flattened by the rule resolver's
// EventFields path).
type scenarioEvent struct {
	Subject string
	Payload []byte
}

// scenarioBaselinePreseed reports whether the scenario's AC8 detection rests
// (partly) on a baseline deviation that must be pre-seeded with the rs_smoke
// 10-priming-plus-1-spike EvidencePackage pattern (BI-4). Only S4 (C2
// beaconing) does; the others fire on a rule match alone.
func scenarioBaselinePreseed(scenarioID string) bool {
	return scenarioID == "s4"
}

// scenarioEvents returns the ordered deterministic raw-event stimulus for a
// scenario (AC7). podName is the resolved tenant-acme/web pod; ts is the
// single injection timestamp shared by every event in the batch (so the
// correlator's 60s window cannot straddle a boundary, the rs_smoke
// precedent). The recipe field shapes EXACTLY match each scenario's OLT rule
// detection block (the Dev Notes mapping table). An unknown scenarioID
// returns a nil slice (the factory rejects unknown ids upstream).
func scenarioEvents(scenarioID, podName string, ts time.Time) []scenarioEvent {
	stamp := ts.UTC().Format(time.RFC3339Nano)
	pod := map[string]any{
		"name":      podName,
		"namespace": "tenant-acme",
		"uid":       "scenario-" + scenarioID + "-uid-1",
	}
	// A priming event drives the correlator window from 0 to 1 source so
	// the scenario's match event makes the window cross
	// MultiSignalMinSources=2 (the rising edge) and the correlator
	// assembles a package onto EVIDENCE.packages carrying every window
	// event for the rules/baseline engines to evaluate. The priming source
	// is chosen to DIFFER from the match event's source so the two events
	// are two DISTINCT sources (the rs_smoke network+falco precedent):
	// scenarios whose match is a falco event prime with a benign network
	// flow; scenarios whose match is a network flow (S4) prime with a
	// benign falco event.
	primingNetwork := func() scenarioEvent {
		raw, _ := json.Marshal(map[string]any{"dst_ip": "10.0.0.1"})
		ev := map[string]any{
			"id":        "scenario-" + scenarioID + "-priming",
			"timestamp": stamp,
			"source":    "network",
			"category":  "flow",
			"summary":   "scenario " + scenarioID + " priming flow",
			"raw":       json.RawMessage(raw),
			"pod":       pod,
		}
		b, _ := json.Marshal(ev)
		return scenarioEvent{Subject: rawNetworkSubject, Payload: b}
	}
	primingFalco := func() scenarioEvent {
		raw, _ := json.Marshal(map[string]any{"process.exe": "/usr/bin/true"})
		ev := map[string]any{
			"id":        "scenario-" + scenarioID + "-priming",
			"timestamp": stamp,
			"source":    "falco",
			"category":  "process",
			"summary":   "scenario " + scenarioID + " priming process",
			"raw":       json.RawMessage(raw),
			"pod":       pod,
		}
		b, _ := json.Marshal(ev)
		return scenarioEvent{Subject: rawFalcoSubject, Payload: b}
	}
	mk := func(id, subject, source, category, severity string, raw map[string]any) scenarioEvent {
		rawJSON, _ := json.Marshal(raw)
		ev := map[string]any{
			"id":        id,
			"timestamp": stamp,
			"source":    source,
			"category":  category,
			"raw":       json.RawMessage(rawJSON),
			"pod":       pod,
		}
		if severity != "" {
			ev["severity"] = severity
		}
		b, _ := json.Marshal(ev)
		return scenarioEvent{Subject: subject, Payload: b}
	}

	switch scenarioID {
	case "s1": // T1611 -> OLT-PRIV-001: CAP_SYS_ADMIN in cap_effective.
		return []scenarioEvent{
			primingNetwork(),
			mk("scenario-s1-falco-1", rawFalcoSubject, "falco", "syscall", "CRITICAL", map[string]any{
				"process.exe":           "/host/bin/sh",
				"process.cap_effective": "CAP_NET_BIND_SERVICE CAP_SYS_ADMIN CAP_SETUID",
			}),
		}
	case "s2": // T1552 -> OLT-CRED-001 (SA-token read) + OLT-CRED-002 (metadata IP).
		return []scenarioEvent{
			primingNetwork(),
			mk("scenario-s2-falco-1", rawFalcoSubject, "falco", "file", "WARNING", map[string]any{
				"file.path":   "/run/secrets/kubernetes.io/serviceaccount/token",
				"process.exe": "/usr/bin/curl",
			}),
			mk("scenario-s2-net-1", rawNetworkSubject, "network", "flow", "", map[string]any{
				"dst_ip":         "169.254.169.254",
				"network.dst_ip": "169.254.169.254",
			}),
		}
	case "s3": // T1613 -> OLT-LATERAL-001: kubectl exec in tenant Deployment pod.
		return []scenarioEvent{
			primingNetwork(),
			mk("scenario-s3-falco-1", rawFalcoSubject, "falco", "process", "WARNING", map[string]any{
				"process.exe": "/usr/local/bin/kubectl",
			}),
		}
	case "s4": // T1071 -> OLT-NET-001 (small non-RFC1918 flow) + OLT-NET-002 (C2 port).
		// The match is a network flow, so prime with a benign FALCO event
		// (so the window carries two distinct sources and the rising edge
		// fires). The baseline-deviation half (BI-4) is pre-seeded
		// separately via the EvidencePackage 10-priming-plus-1-spike
		// pattern in the e2e injector.
		return []scenarioEvent{
			primingFalco(),
			mk("scenario-s4-net-1", rawNetworkSubject, "network", "flow", "", map[string]any{
				"dst_ip":            "203.0.113.10",
				"network.dst_ip":    "203.0.113.10",
				"network.bytes_out": "512",
				"network.dst_port":  8443,
				"network.protocol":  "TCP",
			}),
		}
	case "s5": // T1496 -> OLT-IMPACT-005 (miner proc + pool port) + OLT-IMPACT-006 (stratum flow).
		return []scenarioEvent{
			primingNetwork(),
			mk("scenario-s5-falco-1", rawFalcoSubject, "falco", "process", "WARNING", map[string]any{
				"process.exe":      "/tmp/xmrig",
				"network.dst_port": 3333,
			}),
			mk("scenario-s5-net-1", rawNetworkSubject, "network", "flow", "WARNING", map[string]any{
				"network.dst_port": 4444,
			}),
		}
	}
	return nil
}
