// Benign sweep (Story 7.3): a deterministic stream of NORMAL-behaviour events
// that matches NO rule in the shipped corpus and, after baseline priming,
// stays inside the 3-sigma envelope. Injected at a steady rate for a
// wall-clock window, it measures the false-positive rate (escalations per
// hour on a workload doing nothing wrong). Like the attack recipes, content is
// byte-deterministic; only the per-tick id and timestamp advance.
package scenario

import (
	"encoding/json"
	"fmt"
	"time"
)

// BenignScenarioID is the reserved scenario id the analysis pipeline treats as
// the false-positive sweep (an escalation here is a FALSE positive, never a
// true one). Attack scenarios are s1..s5; this is "benign".
const BenignScenarioID = "benign"

// BenignEvents returns one tick of the benign stream for a workload: a pair of
// normal events from two distinct sources (so the correlator assembles a
// package and the detection tiers actually run, giving the FSM a chance to
// mis-escalate if it were buggy), each shaped to match NO OLT rule:
//
//   - a benign process event: an allowlisted interpreter launch with NO
//     dangerous capability, NO miner name, NO kubectl;
//   - a benign network flow: an intra-cluster RFC1918 destination on a normal
//     service port, NOT a C2 port and NOT a non-RFC1918 address.
//
// tick advances the event ids and timestamps so a steady-rate sweep publishes
// distinct events; the field CONTENT is fixed. ts is the tick's wall time.
func BenignEvents(podName string, ts time.Time, tick int) []Event {
	stamp := ts.UTC().Format(time.RFC3339Nano)
	pod := map[string]any{
		"name":      podName,
		"namespace": "tenant-acme",
		"uid":       "benign-uid-1",
	}
	mk := func(idSuffix, subject, source, category string, raw map[string]any) Event {
		rawJSON, _ := json.Marshal(raw)
		ev := map[string]any{
			"id":        fmt.Sprintf("benign-%s-%d", idSuffix, tick),
			"timestamp": stamp,
			"source":    source,
			"category":  category,
			"summary":   "benign " + idSuffix,
			"raw":       json.RawMessage(rawJSON),
			"pod":       pod,
		}
		b, _ := json.Marshal(ev)
		return Event{Subject: subject, Payload: b}
	}
	return []Event{
		// Normal application process: node serving traffic. Allowlisted-shape
		// exe, no cap_effective, no miner/kubectl markers.
		mk("proc", RawFalcoSubject, "falco", "process", map[string]any{
			"process.exe":           "/usr/local/bin/node",
			"process.cap_effective": "",
		}),
		// Normal intra-cluster flow: RFC1918 destination, HTTPS to a peer
		// service. FRAGILITY NOTE (PR #93 review): OLT-NET-001 fires on an
		// outbound flow in a tenant namespace to a NON-RFC1918 address with a
		// SMALL payload (bytes_out matching ^[0-9]{1,3}$). This benign flow
		// already satisfies the outbound/tenant clauses, so it must fail on
		// BOTH remaining axes, not one, to stay robustly benign: the
		// destination is RFC1918 (10.0.0.42) AND the payload is 4+ digits
		// (40960 bytes), so neither the dst_ip negation nor the small-payload
		// clause matches. Do NOT make this destination public or shrink the
		// payload below 4 digits "for realism" without re-checking the corpus
		// (the benign_corpus_test rule-miss property guards the build).
		mk("flow", RawNetworkSubject, "network", "flow", map[string]any{
			"dst_ip":            "10.0.0.42",
			"network.dst_ip":    "10.0.0.42",
			"network.dst_port":  443,
			"network.protocol":  "TCP",
			"network.bytes_out": "40960",
		}),
	}
}

// BenignRawFieldMaps returns the two benign events' raw field maps (the
// process map, then the flow map) as the rule engine's field resolver sees
// them. Exposed for the rule-miss property test so it can build an
// EvidencePackage without re-decoding the JSON payloads. Content matches
// BenignEvents exactly.
func BenignRawFieldMaps() []map[string]any {
	return []map[string]any{
		{"process.exe": "/usr/local/bin/node", "process.cap_effective": ""},
		{"dst_ip": "10.0.0.42", "network.dst_ip": "10.0.0.42", "network.dst_port": 443, "network.protocol": "TCP", "network.bytes_out": "40960"},
	}
}

// BenignEventSources returns the (source, category) of each benign event in
// BenignRawFieldMaps order, so the property test can build schema.Events with
// the correct source routing.
func BenignEventSources() [][2]string {
	return [][2]string{
		{"falco", "process"},
		{"network", "flow"},
	}
}
