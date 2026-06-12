package schema

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestL1HypothesisJSON(t *testing.T) {
	original := L1Hypothesis{
		SchemaVersion: L1HypothesisSchemaVersion,
		Hypothesis:    "crypto-miner launched from a compromised web pod",
		CitedEvidence: []EvidenceCitation{
			{EventID: "evt-1", Note: "execve of xmrig"},
			{EventID: "evt-2"},
		},
		FollowUpProbes: []string{"list outbound connections from pod web-0"},
		Confidence:     72,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Verify snake_case keys in JSON.
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	for _, key := range []string{"schema_version", "hypothesis", "cited_evidence", "follow_up_probes", "confidence"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q not found", key)
		}
	}

	var decoded L1Hypothesis
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Hypothesis != original.Hypothesis {
		t.Errorf("Hypothesis: got %q, want %q", decoded.Hypothesis, original.Hypothesis)
	}
	if len(decoded.CitedEvidence) != 2 || decoded.CitedEvidence[0].EventID != "evt-1" || decoded.CitedEvidence[0].Note != "execve of xmrig" {
		t.Errorf("CitedEvidence round-trip mismatch: %+v", decoded.CitedEvidence)
	}
	if decoded.Confidence != 72 {
		t.Errorf("Confidence: got %d, want 72", decoded.Confidence)
	}
}

func TestL1HypothesisOptionalFieldsOmitted(t *testing.T) {
	minimal := L1Hypothesis{
		Hypothesis:    "benign log rotation",
		CitedEvidence: []EvidenceCitation{{EventID: "evt-9"}},
		Confidence:    5,
	}
	data, err := json.Marshal(minimal)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(data)
	for _, absent := range []string{"schema_version", "follow_up_probes", `"note"`} {
		if strings.Contains(got, absent) {
			t.Errorf("zero-value optional field %s rendered into JSON: %s", absent, got)
		}
	}
}
