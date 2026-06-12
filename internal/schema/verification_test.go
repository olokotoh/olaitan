package schema

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestL2VerificationJSON(t *testing.T) {
	original := L2Verification{
		SchemaVersion: L2VerificationSchemaVersion,
		Verdict:       VerdictRefuted,
		VerifiedEvidence: []EvidenceVerification{
			{EventID: "evt-1", Finding: "the binary is a known log shipper, not a miner"},
			{EventID: "evt-2", Finding: "secret read matches the documented startup path"},
		},
		ContradictoryFindings: []string{"L1 cited evt-1 as a miner launch; the hash matches fluent-bit"},
		Confidence:            81,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	for _, key := range []string{"schema_version", "verdict", "verified_evidence", "contradictory_findings", "confidence"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q not found", key)
		}
	}

	var decoded L2Verification
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Verdict != VerdictRefuted {
		t.Errorf("Verdict: got %q", decoded.Verdict)
	}
	if len(decoded.VerifiedEvidence) != 2 || decoded.VerifiedEvidence[0].EventID != "evt-1" || decoded.VerifiedEvidence[0].Finding == "" {
		t.Errorf("VerifiedEvidence round-trip mismatch: %+v", decoded.VerifiedEvidence)
	}
	if len(decoded.ContradictoryFindings) != 1 {
		t.Errorf("ContradictoryFindings round-trip mismatch: %+v", decoded.ContradictoryFindings)
	}
	if decoded.Confidence != 81 {
		t.Errorf("Confidence: got %d, want 81", decoded.Confidence)
	}
}

func TestL2VerificationOptionalFieldsOmitted(t *testing.T) {
	minimal := L2Verification{
		Verdict:          VerdictConfirmed,
		VerifiedEvidence: []EvidenceVerification{{EventID: "evt-9", Finding: "confirmed by process tree"}},
		Confidence:       64,
	}
	data, err := json.Marshal(minimal)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(data)
	for _, absent := range []string{"schema_version", "contradictory_findings"} {
		if strings.Contains(got, absent) {
			t.Errorf("zero-value optional field %s rendered into JSON: %s", absent, got)
		}
	}
}
