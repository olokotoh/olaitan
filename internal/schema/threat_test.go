package schema

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestThreatAssessmentStory37FieldsJSON(t *testing.T) {
	original := ThreatAssessment{
		ThreatType:          "crypto_miner",
		Reasoning:           "challenged L1 and L2; evidence supports the miner hypothesis",
		MitreTechniques:     []string{"T1496"},
		Mode:                ModeLLM,
		NotedDisagreements:  []string{"L2 refuted the miner claim on evt-1"},
		RawConfidence:       90,
		LLMCappedConfidence: 35,
		AgentsAvailable:     []string{"l1", "l2", "senior"},
	}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	for _, key := range []string{"noted_disagreements", "raw_confidence", "llm_capped_confidence", "agents_available"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q not found", key)
		}
	}
	var decoded ThreatAssessment
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.RawConfidence != 90 || decoded.LLMCappedConfidence != 35 {
		t.Errorf("confidence pair round-trip mismatch: raw=%d capped=%d", decoded.RawConfidence, decoded.LLMCappedConfidence)
	}
	if len(decoded.AgentsAvailable) != 3 || decoded.AgentsAvailable[0] != "l1" {
		t.Errorf("agents_available round-trip mismatch: %+v", decoded.AgentsAvailable)
	}
}

// TestThreatAssessmentPre37WireFormUnchanged pins the BI-4 MINOR-bump
// guarantee: a pre-3.7 assessment (all new fields zero) marshals to a
// byte-identical wire form with none of the new keys present.
func TestThreatAssessmentPre37WireFormUnchanged(t *testing.T) {
	pre := ThreatAssessment{
		ThreatType: "benign_operations",
		Reasoning:  "rules only",
		Mode:       ModeRulesOnly,
	}
	data, err := json.Marshal(pre)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(data)
	for _, absent := range []string{"noted_disagreements", "raw_confidence", "llm_capped_confidence", "agents_available", "llm_unavailable"} {
		if strings.Contains(got, absent) {
			t.Errorf("zero-value additive field %s rendered into JSON: %s", absent, got)
		}
	}
}

// TestThreatAssessmentLLMUnavailableWireForm pins the Story 3.10 BI-4
// additive field: false omits the key (byte-compat), true renders it.
func TestThreatAssessmentLLMUnavailableWireForm(t *testing.T) {
	off, _ := json.Marshal(ThreatAssessment{Mode: ModeLLM})
	if strings.Contains(string(off), "llm_unavailable") {
		t.Errorf("false LLMUnavailable must omit the key, got %s", off)
	}
	on, _ := json.Marshal(ThreatAssessment{Mode: ModeLLM, LLMUnavailable: true})
	if !strings.Contains(string(on), "\"llm_unavailable\":true") {
		t.Errorf("true LLMUnavailable must render, got %s", on)
	}
}
