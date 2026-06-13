package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// fake-llm is a self-contained OpenAI-compatible canned-verdict server used
// by the Story 3.16 RSLT-full kind e2e smoke (AC7). It ships in the olaitan
// binary so the e2e needs no external image pull and stays air-gap-clean. It
// is NOT a production component: it returns deterministic, schema-valid L1 /
// L2 / Senior verdicts so the deployed chain can be exercised end to end
// against a real provider transport without calling a paid LLM.
//
// The openai_compat provider POSTs {base}/chat/completions with a system +
// user message; the role is inferred from the instruction text, and a cited
// event id is lifted from the (redacted) evidence in the request so the
// returned verdict passes the runner's referential-integrity gate.

// fakeLLMEventIDRe lifts an event id from the request body. The evidence
// package serialises event ids as "id":"evt-..."; we cite the first one so
// the verdict's cited_evidence references a real event (the L1/L2 runners
// reject a citation that is not present in the package).
var fakeLLMEventIDRe = regexp.MustCompile(`"id"\s*:\s*"([^"]+)"`)

// runFakeLLM serves the canned-verdict endpoint. Flags: --addr (default
// :8080). Blocks until ctx is cancelled (SIGINT/SIGTERM).
func runFakeLLM(ctx context.Context, args []string, stderr io.Writer) int {
	addr := ":8080"
	for i := 0; i < len(args); i++ {
		if args[i] == "--addr" && i+1 < len(args) {
			addr = args[i+1]
			i++
		} else if strings.HasPrefix(args[i], "--addr=") {
			addr = strings.TrimPrefix(args[i], "--addr=")
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/v1/chat/completions", fakeLLMChatHandler)

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	_, _ = fmt.Fprintf(stderr, "fake-llm: listening on %s\n", addr)

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		return 0
	case err := <-errc:
		if err != nil && err != http.ErrServerClosed {
			_, _ = fmt.Fprintf(stderr, "fake-llm: serve: %v\n", err)
			return 1
		}
		return 0
	}
}

// fakeLLMChatHandler returns an OpenAI chat-completion whose message content
// is the role-appropriate verdict JSON.
func fakeLLMChatHandler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	role := fakeLLMRole(string(body))
	eventID := fakeLLMEventID(string(body))
	verdict := fakeLLMVerdict(role, eventID)

	resp := map[string]any{
		"id":      "fakecmpl-1",
		"object":  "chat.completion",
		"model":   "fake-llm",
		"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": verdict}, "finish_reason": "stop"}},
		"usage":   map[string]any{"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// fakeLLMRole infers the analyst role from the instruction text the provider
// composes into the request.
func fakeLLMRole(body string) string {
	b := strings.ToLower(body)
	// Match the exact analyst user-instruction phrases (l1.go/l2.go/senior.go),
	// most-specific first. The Senior and L2 requests both carry the L1
	// hypothesis block, so generic "l2"/"l1_hypothesis" substrings are NOT
	// reliable -- only the instruction phrase identifies the role.
	switch {
	case strings.Contains(b, "senior analyst finalising"):
		return "senior"
	case strings.Contains(b, "verify the l1 analyst's hypothesis"):
		return "l2"
	default:
		return "l1"
	}
}

// fakeLLMEventID returns the first event id found in the request, or a
// fallback that callers must ensure exists in the package (the e2e package
// always carries at least one event so the regex hits).
func fakeLLMEventID(body string) string {
	// The evidence is JSON embedded as a string value inside the request's
	// messages array, so its quotes arrive backslash-escaped on the wire.
	// Unescape first so the id regex matches both the escaped wire form and a
	// plain test body.
	unescaped := strings.ReplaceAll(body, `\"`, `"`)
	if m := fakeLLMEventIDRe.FindStringSubmatch(unescaped); len(m) == 2 {
		return m[1]
	}
	return "evt-1"
}

// fakeLLMVerdict returns a schema-valid verdict for the role, citing eventID.
// The Senior verdict is a high-confidence credential-theft assessment so the
// S2 cred-exfil scenario produces a capped LLM contribution that moves the
// FSM ThreatScore (AC7).
func fakeLLMVerdict(role, eventID string) string {
	switch role {
	case "l2":
		return fmt.Sprintf(`{"verdict":"confirmed","verified_evidence":[{"event_id":%q,"finding":"credential read confirmed by ancestry"}],"confidence":78}`, eventID)
	case "senior":
		return `{"threat_type":"credential_theft","reasoning":"L1 and L2 agree the workload read a ServiceAccount token then opened an external connection; challenged and upheld","mitre_techniques":["T1552"],"noted_disagreements":[],"confidence":85}`
	default: // l1
		return fmt.Sprintf(`{"hypothesis":"workload exfiltrating a ServiceAccount credential","cited_evidence":[{"event_id":%q,"note":"secret read"}],"follow_up_probes":["check egress destinations"],"confidence":72}`, eventID)
	}
}
