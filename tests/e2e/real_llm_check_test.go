//go:build e2e

package e2e_test

import (
	"encoding/json"
	"strings"
	"testing"
)

// Story 10.6: the live test can only prove what its checker refuses, so the
// checker is pinned here without a cluster, the same way the Story 10.5 AC2
// matcher is (full_profile_match_test.go).

// goodRealLLMRecord is an AUDIT.assessments v2 record shaped like the one a
// real full-mode chain run on the ollama family publishes: three roles
// contributed, every role recorded the configured provider and model, the
// model reported 85, and the ollama cap of 25 was applied.
const goodRealLLMRecord = `{
  "schema_version": "audit.assessments.v2",
  "package_id": "pkg-1",
  "workload_id": "ns/Deployment/victim",
  "mode": "full",
  "agents_available": ["l1", "l2", "senior"],
  "prompt_versions": {"l1": "aa", "l2": "bb", "senior": "cc"},
  "providers": {"l1": "ollama", "l2": "ollama", "senior": "ollama"},
  "models": {"l1": "qwen2.5:3b-instruct", "l2": "qwen2.5:3b-instruct", "senior": "qwen2.5:3b-instruct"},
  "threat_type": "credential_access",
  "raw_confidence": 85,
  "llm_capped_confidence": 25,
  "l1_hypothesis": {
    "schema_version": "l1_hypothesis.v1",
    "hypothesis": "A shell in the container read /etc/shadow.",
    "cited_evidence": [{"event_id": "ev-1", "note": "the read"}],
    "follow_up_probes": ["who ran the shell"],
    "confidence": 80
  },
  "l2_verification": {
    "schema_version": "l2_verification.v1",
    "verdict": "confirmed",
    "verified_evidence": [{"event_id": "ev-1", "finding": "the read is in the Falco event"}],
    "confidence": 82
  },
  "threat_assessment": {
    "threat_type": "credential_access",
    "confidence": 25,
    "recommended_state": "",
    "reasoning": "The read of /etc/shadow is a credential access attempt.",
    "mitre_techniques": ["T1003.008"],
    "kill_chain_stage": "credential-access",
    "mode": "llm",
    "raw_confidence": 85,
    "llm_capped_confidence": 25,
    "agents_available": ["l1", "l2", "senior"]
  },
  "redacted_evidence": {"package_id": "pkg-1", "events": [{"id": "ev-1", "source": "falco"}]},
  "redaction_applied": true
}`

var realLLMWantForTest = realLLMWant{Provider: "ollama", Model: "qwen2.5:3b-instruct", Cap: 25}

// mutate applies f to the decoded good record and re-encodes it.
func mutate(t *testing.T, f func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(goodRealLLMRecord), &m); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	f(m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRealLLMCheckAcceptsAGoodRecord(t *testing.T) {
	schemas := loadModelSchemas(t)
	if problems := checkRealLLMAssessment([]byte(goodRealLLMRecord), realLLMWantForTest, schemas); len(problems) != 0 {
		t.Fatalf("good record rejected:\n%s", strings.Join(problems, "\n"))
	}
}

func TestRealLLMCheckRejects(t *testing.T) {
	schemas := loadModelSchemas(t)
	cases := []struct {
		name string
		f    func(m map[string]any)
		want string
	}{
		{"not the full chain", func(m map[string]any) { m["mode"] = "l1_l2" }, "mode"},
		{"senior degraded out of the chain", func(m map[string]any) {
			m["agents_available"] = []any{"l1", "l2"}
		}, "agents_available"},
		{"provider not the configured one", func(m map[string]any) {
			m["providers"].(map[string]any)["l2"] = "openai"
		}, "providers[l2]"},
		{"model not the configured one", func(m map[string]any) {
			m["models"].(map[string]any)["senior"] = "fake"
		}, "models[senior]"},
		{"prompt version missing", func(m map[string]any) {
			delete(m["prompt_versions"].(map[string]any), "l1")
		}, "prompt_versions[l1]"},
		{"L1 output not schema-valid", func(m map[string]any) {
			m["l1_hypothesis"].(map[string]any)["verdict"] = "extra key"
		}, "l1_hypothesis"},
		{"L1 output missing", func(m map[string]any) { delete(m, "l1_hypothesis") }, "l1_hypothesis"},
		{"L2 output not schema-valid", func(m map[string]any) {
			m["l2_verification"].(map[string]any)["confidence"] = 400
		}, "l2_verification"},
		{"Senior output not schema-valid", func(m map[string]any) {
			m["threat_assessment"].(map[string]any)["reasoning"] = ""
		}, "threat_assessment"},
		{"Senior fell back to the unavailable degrade", func(m map[string]any) {
			m["threat_assessment"].(map[string]any)["llm_unavailable"] = true
		}, "llm_unavailable"},
		{"model confidence not above the cap, so the cap was never exercised", func(m map[string]any) {
			m["raw_confidence"] = 20
			m["llm_capped_confidence"] = 20
			m["threat_assessment"].(map[string]any)["raw_confidence"] = 20
			m["threat_assessment"].(map[string]any)["llm_capped_confidence"] = 20
		}, "raw_confidence"},
		{"cap not applied in the audit record", func(m map[string]any) {
			m["llm_capped_confidence"] = 85
		}, "llm_capped_confidence"},
		{"redaction not applied", func(m map[string]any) { m["redaction_applied"] = false }, "redaction_applied"},
		{"no Falco event in the evidence", func(m map[string]any) {
			m["redacted_evidence"] = map[string]any{"events": []any{map[string]any{"id": "ev-1", "source": "audit"}}}
		}, "falco"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			problems := checkRealLLMAssessment(mutate(t, tc.f), realLLMWantForTest, schemas)
			if len(problems) == 0 {
				t.Fatalf("record accepted; want a problem naming %q", tc.want)
			}
			if !strings.Contains(strings.Join(problems, "\n"), tc.want) {
				t.Errorf("problems do not name %q:\n%s", tc.want, strings.Join(problems, "\n"))
			}
		})
	}
}

// TestRealLLMCheckRejectsGarbage: a record that is not JSON is a problem,
// not a panic.
func TestRealLLMCheckRejectsGarbage(t *testing.T) {
	if problems := checkRealLLMAssessment([]byte("not json"), realLLMWantForTest, loadModelSchemas(t)); len(problems) == 0 {
		t.Fatal("garbage accepted")
	}
}
