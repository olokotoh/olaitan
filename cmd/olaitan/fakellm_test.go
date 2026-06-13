package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/olokotoh/olaitan/internal/schema"
)

// chatResp mirrors the slice of the OpenAI chat-completion response the
// fake-llm server emits, so the test can extract the verdict content.
type chatResp struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

func postFakeLLM(t *testing.T, srv *httptest.Server, userContent string) string {
	t.Helper()
	body := `{"model":"x","messages":[{"role":"system","content":"sys"},{"role":"user","content":` + mustJSON(t, userContent) + `}]}`
	resp, err := http.Post(srv.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var cr chatResp
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(cr.Choices) != 1 {
		t.Fatalf("choices = %d, want 1", len(cr.Choices))
	}
	return cr.Choices[0].Message.Content
}

func mustJSON(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestFakeLLMVerdictsAreRoleValid proves the fake server returns a
// schema-shaped verdict per role, citing an event id lifted from the request
// so the runner's referential gate passes.
func TestFakeLLMVerdictsAreRoleValid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(fakeLLMChatHandler))
	defer srv.Close()

	// L1: triage instruction + an evidence package carrying event "evt-42".
	l1 := postFakeLLM(t, srv, `Triage the following... {"id":"evt-42","summary":"secret read"}`)
	var hyp schema.L1Hypothesis
	if err := json.Unmarshal([]byte(l1), &hyp); err != nil {
		t.Fatalf("L1 verdict not L1Hypothesis-shaped: %v\n%s", err, l1)
	}
	if hyp.Hypothesis == "" || len(hyp.CitedEvidence) == 0 || hyp.CitedEvidence[0].EventID != "evt-42" {
		t.Errorf("L1 must cite the request's event id, got %+v", hyp)
	}

	// L2: the real verify instruction phrase.
	l2 := postFakeLLM(t, srv, `Verify the L1 analyst's hypothesis (provided in the l1_hypothesis block)... {"id":"evt-42"}`)
	var ver schema.L2Verification
	if err := json.Unmarshal([]byte(l2), &ver); err != nil {
		t.Fatalf("L2 verdict not L2Verification-shaped: %v\n%s", err, l2)
	}
	if ver.Verdict == "" {
		t.Errorf("L2 verdict empty: %+v", ver)
	}

	// Senior: the real finalising instruction phrase -> credential-theft.
	sr := postFakeLLM(t, srv, `You are the Senior analyst finalising the verdict on the following...`)
	var ta struct {
		ThreatType string `json:"threat_type"`
		Confidence int    `json:"confidence"`
	}
	if err := json.Unmarshal([]byte(sr), &ta); err != nil {
		t.Fatalf("Senior verdict not assessment-shaped: %v\n%s", err, sr)
	}
	if ta.ThreatType != "credential_theft" || ta.Confidence <= 0 {
		t.Errorf("Senior verdict = %+v, want credential_theft with confidence>0", ta)
	}
}

// TestFakeLLMHealthz proves the readiness endpoint the e2e probes.
func TestFakeLLMHealthz(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthz = %d, want 200", resp.StatusCode)
	}
}
