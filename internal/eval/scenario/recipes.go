// Package scenario is the SINGLE SOURCE OF TRUTH for the deterministic
// synthetic-event recipes that drive the Story 5.2 attack-scenario harnesses
// (S1-S5) on kind.
//
// The kind stimulus for each scenario is a fixed sequence of synthetic raw
// events published directly to olaitan.events.raw.{falco,network} (the
// rs_smoke precedent: Falco's eBPF probe cannot load inside a kind node, so
// the harness publishes the JSON events the production source would emit).
// Both the in-process olaitan-eval binary (cmd/olaitan-eval) and the e2e kind
// injector (tests/e2e, which cannot import package main) import THIS package,
// so there is exactly one real recipe definition and no hand-copy to drift
// against. The event CONTENT and the recipe's BRANCHING are fixed; only the
// injection timestamp varies (AC7). No rand, no time.Now()-keyed branching, no
// outbound network.
package scenario

import (
	"encoding/json"
	"time"

	"github.com/olokotoh/olaitan/internal/subjects"
)

// The raw-event subjects the synthetic injection targets (the subjects the
// production Falco / CNI exporters publish to). Sourced from the canonical
// internal/subjects package (no import cycle: subjects has no internal deps),
// so the recipe stimulus cannot drift from the production subject contract.
const (
	RawFalcoSubject   = subjects.RawFalco
	RawNetworkSubject = subjects.RawNetwork
)

// Event is one synthetic raw event in a scenario's deterministic stimulus: the
// NATS subject to publish to and the JSON payload (the shape the production
// source would emit, flattened by the rule resolver's EventFields path).
type Event struct {
	Subject string
	Payload []byte
}

// BaselinePreseed reports whether the scenario's AC8 detection rests (partly)
// on a baseline deviation that must be pre-seeded with the rs_smoke
// 10-priming-plus-1-spike EvidencePackage pattern (BI-4). Only S4 (C2
// beaconing) does; the others fire on a rule match alone.
func BaselinePreseed(scenarioID string) bool {
	return scenarioID == "s4"
}

// Events returns the ordered deterministic raw-event stimulus for a scenario
// (AC7). podName is the resolved tenant-acme/web pod; ts is the single
// injection timestamp shared by every event in the batch (so the correlator's
// 60s window cannot straddle a boundary, the rs_smoke precedent). The recipe
// field shapes EXACTLY match each scenario's OLT rule detection block (the Dev
// Notes mapping table). An unknown scenarioID returns a nil slice (the factory
// rejects unknown ids upstream).
func Events(scenarioID, podName string, ts time.Time) []Event {
	stamp := ts.UTC().Format(time.RFC3339Nano)
	pod := map[string]any{
		"name":      podName,
		"namespace": "tenant-acme",
		"uid":       "scenario-" + scenarioID + "-uid-1",
	}
	// A priming event drives the correlator window from 0 to 1 source so the
	// scenario's match event makes the window cross MultiSignalMinSources=2
	// (the rising edge) and the correlator assembles a package onto
	// EVIDENCE.packages carrying every window event for the rules/baseline
	// engines to evaluate. The priming source is chosen to DIFFER from the
	// match event's source so the two events are two DISTINCT sources (the
	// rs_smoke network+falco precedent): scenarios whose match is a falco event
	// prime with a benign network flow; scenarios whose match is a network flow
	// (S4) prime with a benign falco event.
	primingNetwork := func() Event {
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
		return Event{Subject: RawNetworkSubject, Payload: b}
	}
	primingFalco := func() Event {
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
		return Event{Subject: RawFalcoSubject, Payload: b}
	}
	mk := func(id, subject, source, category, severity string, raw map[string]any) Event {
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
		return Event{Subject: subject, Payload: b}
	}

	switch scenarioID {
	case "s1": // T1611 -> OLT-PRIV-001: CAP_SYS_ADMIN in cap_effective.
		return []Event{
			primingNetwork(),
			mk("scenario-s1-falco-1", RawFalcoSubject, "falco", "syscall", "CRITICAL", map[string]any{
				"process.exe":           "/host/bin/sh",
				"process.cap_effective": "CAP_NET_BIND_SERVICE CAP_SYS_ADMIN CAP_SETUID",
			}),
		}
	case "s2": // T1552 -> OLT-CRED-001 (SA-token read) + OLT-CRED-002 (metadata IP).
		return []Event{
			primingNetwork(),
			mk("scenario-s2-falco-1", RawFalcoSubject, "falco", "file", "WARNING", map[string]any{
				"file.path":   "/run/secrets/kubernetes.io/serviceaccount/token",
				"process.exe": "/usr/bin/curl",
			}),
			mk("scenario-s2-net-1", RawNetworkSubject, "network", "flow", "", map[string]any{
				"dst_ip":         "169.254.169.254",
				"network.dst_ip": "169.254.169.254",
			}),
		}
	case "s3": // T1613 -> OLT-LATERAL-001: kubectl exec in tenant Deployment pod.
		return []Event{
			primingNetwork(),
			mk("scenario-s3-falco-1", RawFalcoSubject, "falco", "process", "WARNING", map[string]any{
				"process.exe": "/usr/local/bin/kubectl",
			}),
		}
	case "s4": // T1071 -> OLT-NET-001 (small non-RFC1918 flow) + OLT-NET-002 (C2 port).
		// The match is a network flow, so prime with a benign FALCO event (so
		// the window carries two distinct sources and the rising edge fires).
		// The baseline-deviation half (BI-4) is pre-seeded separately via the
		// EvidencePackage 10-priming-plus-1-spike pattern in the e2e injector.
		return []Event{
			primingFalco(),
			mk("scenario-s4-net-1", RawNetworkSubject, "network", "flow", "", map[string]any{
				"dst_ip":            "203.0.113.10",
				"network.dst_ip":    "203.0.113.10",
				"network.bytes_out": "512",
				"network.dst_port":  8443,
				"network.protocol":  "TCP",
			}),
		}
	case "s5": // T1496 -> OLT-IMPACT-005 (miner proc + pool port) + OLT-IMPACT-006 (stratum flow).
		return []Event{
			primingNetwork(),
			mk("scenario-s5-falco-1", RawFalcoSubject, "falco", "process", "WARNING", map[string]any{
				"process.exe":      "/tmp/xmrig",
				"network.dst_port": 3333,
			}),
			mk("scenario-s5-net-1", RawNetworkSubject, "network", "flow", "WARNING", map[string]any{
				"network.dst_port": 4444,
			}),
		}
	}
	return nil
}
