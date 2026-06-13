// Real-wire-format integration suite (Story 3.2 AC5 / BI-7, NFR36): the
// SDK's full encode/decode path crosses a real HTTP round-trip against an
// httptest.Server speaking the Anthropic /v1/messages wire format. The only
// stand-in is the upstream server; attempt counts are proven by a
// request-counting handler, never by wall-clock.
package claude

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/agent/provider"
	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/schema"
)

const testAPIKey = "test-key"

const successBody = `{
  "id": "msg_01TestFixture",
  "type": "message",
  "role": "assistant",
  "model": "claude-opus-4-8",
  "content": [{"type": "text", "text": "{\"verdict\":\"benign\",\"confidence\":12}"}],
  "stop_reason": "end_turn",
  "stop_sequence": null,
  "usage": {"input_tokens": 42, "output_tokens": 7}
}`

func apiErrorBody(typ, msg string) string {
	return fmt.Sprintf(`{"type":"error","error":{"type":%q,"message":%q}}`, typ, msg)
}

// capturingHandler counts attempts, records request bodies and serves the
// scripted per-attempt status codes (the last entry repeats).
type capturingHandler struct {
	mu       sync.Mutex
	bodies   [][]byte
	attempts atomic.Int64
	// script is the per-attempt plan: status code + body. The last entry
	// repeats for any further attempt.
	script []scriptedResponse
	// delay, when non-zero, is slept before answering (timeout tests).
	delay time.Duration
}

type scriptedResponse struct {
	status int
	body   string
}

func (h *capturingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n := h.attempts.Add(1)
	body, _ := io.ReadAll(r.Body)
	h.mu.Lock()
	h.bodies = append(h.bodies, body)
	h.mu.Unlock()

	if h.delay > 0 {
		time.Sleep(h.delay)
	}

	idx := int(n) - 1
	if idx >= len(h.script) {
		idx = len(h.script) - 1
	}
	resp := h.script[idx]
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.status)
	_, _ = io.WriteString(w, resp.body)
}

func (h *capturingHandler) lastBody() []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.bodies) == 0 {
		return nil
	}
	return h.bodies[len(h.bodies)-1]
}

// newTestProvider builds a provider against the httptest server with the
// retry backoff shrunk to milliseconds (the attempt COUNT, not wall-clock,
// is the assertion surface per BI-7.2; Strategy semantics are untouched).
func newTestProvider(t *testing.T, baseURL string, logSink io.Writer) (*Provider, *metrics.Registry) {
	t.Helper()
	if logSink == nil {
		logSink = io.Discard
	}
	reg := metrics.NewRegistry()
	p, err := New(Config{BaseURL: baseURL}, testAPIKey, reg, nil, slog.New(slog.NewJSONHandler(logSink, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p.strategy.Min = time.Millisecond
	p.strategy.Max = 4 * time.Millisecond
	return p, reg
}

func analyseRequest(role provider.Role) provider.Request {
	return provider.Request{
		Role: role,
		Package: schema.EvidencePackage{
			SchemaVersion: "v1",
			PackageID:     "pkg-it-1",
			WorkloadID:    "default/nginx-abc",
		},
		Prompt: provider.Prompt{System: "analyst system prompt", User: "triage this evidence"},
		Schema: provider.JSONSchema(`{"type":"object"}`),
	}
}

// counterValue returns the olaitan_llm_calls_total sample for the given
// label values, plus the total number of series in the family.
func counterValue(t *testing.T, reg *metrics.Registry, prov, role, status string) (float64, int) {
	t.Helper()
	mfs, err := reg.Gatherer().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != metricName {
			continue
		}
		var val float64
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, lp := range m.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			// AC4: the label set is exactly {provider, role, status}; a
			// workload_id or pod_uid label is a cardinality violation.
			for name := range labels {
				if name != "provider" && name != "role" && name != "status" {
					t.Errorf("unexpected metric label %q (bounded set is provider/role/status)", name)
				}
			}
			if labels["provider"] == prov && labels["role"] == role && labels["status"] == status {
				val = m.GetCounter().GetValue()
			}
		}
		return val, len(mf.GetMetric())
	}
	return 0, 0
}

func TestAnalyseSuccessSingleAttempt(t *testing.T) {
	h := &capturingHandler{script: []scriptedResponse{{200, successBody}}}
	ts := httptest.NewServer(h)
	defer ts.Close()

	p, reg := newTestProvider(t, ts.URL, nil)
	resp, err := p.Analyse(context.Background(), analyseRequest(provider.RoleL1))
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if got := h.attempts.Load(); got != 1 {
		t.Errorf("attempts = %d, want 1", got)
	}
	if want := `{"verdict":"benign","confidence":12}`; resp.Raw != want {
		t.Errorf("Raw = %q, want %q", resp.Raw, want)
	}
	if resp.StopReason != "end_turn" {
		t.Errorf("StopReason = %q, want end_turn", resp.StopReason)
	}
	if resp.Model != "claude-opus-4-8" {
		t.Errorf("Model = %q", resp.Model)
	}
	if resp.InputTokens != 42 || resp.OutputTokens != 7 {
		t.Errorf("usage = %d/%d, want 42/7", resp.InputTokens, resp.OutputTokens)
	}
	if v, _ := counterValue(t, reg, "claude", "l1", statusSuccess); v != 1 {
		t.Errorf("metric {claude,l1,success} = %v, want 1", v)
	}
	// Story 3.15 (FR50): the call observed one latency sample on
	// olaitan_llm_call_duration_seconds{claude,l1}.
	if n := durationSampleCount(t, reg, "claude", "l1"); n != 1 {
		t.Errorf("olaitan_llm_call_duration_seconds{claude,l1} count = %d, want 1", n)
	}
}

// durationSampleCount returns the olaitan_llm_call_duration_seconds histogram
// observation count for {provider,role} (Story 3.15).
func durationSampleCount(t *testing.T, reg *metrics.Registry, prov, role string) uint64 {
	t.Helper()
	mfs, err := reg.Gatherer().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != provider.CallDurationMetricName {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, lp := range m.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			if labels["provider"] == prov && labels["role"] == role {
				return m.GetHistogram().GetSampleCount()
			}
		}
	}
	return 0
}

func TestAnalyseWirePayloadContract(t *testing.T) {
	h := &capturingHandler{script: []scriptedResponse{{200, successBody}}}
	ts := httptest.NewServer(h)
	defer ts.Close()

	p, _ := newTestProvider(t, ts.URL, nil)
	if _, err := p.Analyse(context.Background(), analyseRequest(provider.RoleL1)); err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	body := h.lastBody()
	var wire map[string]any
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatalf("request body is not JSON: %v", err)
	}
	// Removed Opus 4.8 params must never cross the wire (BI-2.4/BI-9).
	for _, forbidden := range []string{"temperature", "top_p", "top_k", "budget_tokens"} {
		if _, ok := wire[forbidden]; ok {
			t.Errorf("wire payload carries removed param %q (400 on Opus 4.8)", forbidden)
		}
	}
	thinking, ok := wire["thinking"].(map[string]any)
	if !ok || thinking["type"] != "disabled" {
		t.Errorf("thinking = %v, want explicit {type: disabled} (BI-9)", wire["thinking"])
	}
	if wire["model"] != "claude-opus-4-8" {
		t.Errorf("model = %v", wire["model"])
	}
	if wire["max_tokens"] != float64(DefaultMaxTokens) {
		t.Errorf("max_tokens = %v, want %d", wire["max_tokens"], DefaultMaxTokens)
	}
	// The API key travels ONLY in the x-api-key header, never the body.
	if strings.Contains(string(body), testAPIKey) {
		t.Error("request body contains the API key")
	}
}

func TestAnalyseRetriesTransientThenSucceeds(t *testing.T) {
	h := &capturingHandler{script: []scriptedResponse{
		{500, apiErrorBody("api_error", "upstream hiccup")},
		{200, successBody},
	}}
	ts := httptest.NewServer(h)
	defer ts.Close()

	p, reg := newTestProvider(t, ts.URL, nil)
	if _, err := p.Analyse(context.Background(), analyseRequest(provider.RoleL1)); err != nil {
		t.Fatalf("Analyse after 500-then-200: %v", err)
	}
	if got := h.attempts.Load(); got != 2 {
		t.Errorf("attempts = %d, want 2 (retry once then succeed)", got)
	}
	if v, _ := counterValue(t, reg, "claude", "l1", statusSuccess); v != 1 {
		t.Errorf("metric {claude,l1,success} = %v, want 1 (final outcome only)", v)
	}
}

func TestAnalyseTransientExhaustsThreeAttempts(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		errType string
	}{
		{"429 rate limit", 429, "rate_limit_error"},
		{"500 api error", 500, "api_error"},
		{"529 overloaded", 529, "overloaded_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &capturingHandler{script: []scriptedResponse{{tc.status, apiErrorBody(tc.errType, "still failing")}}}
			ts := httptest.NewServer(h)
			defer ts.Close()

			p, reg := newTestProvider(t, ts.URL, nil)
			_, err := p.Analyse(context.Background(), analyseRequest(provider.RoleSenior))
			if err == nil {
				t.Fatal("Analyse: err = nil, want exhaustion error")
			}
			if !strings.Contains(err.Error(), "max attempts (3) exhausted") {
				t.Errorf("err = %v, want max-attempts exhaustion", err)
			}
			if got := h.attempts.Load(); got != 3 {
				t.Errorf("attempts = %d, want 3", got)
			}
			if v, _ := counterValue(t, reg, "claude", "senior", statusTransient); v != 1 {
				t.Errorf("metric {claude,senior,transient_failure} = %v, want 1", v)
			}
		})
	}
}

func TestAnalysePermanentAbortsFirstAttempt(t *testing.T) {
	cases := []struct {
		status  int
		errType string
	}{
		{400, "invalid_request_error"},
		{401, "authentication_error"},
		{403, "permission_error"},
		{404, "not_found_error"},
		{413, "request_too_large"},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%d %s", tc.status, tc.errType), func(t *testing.T) {
			h := &capturingHandler{script: []scriptedResponse{{tc.status, apiErrorBody(tc.errType, "permanent")}}}
			ts := httptest.NewServer(h)
			defer ts.Close()

			p, reg := newTestProvider(t, ts.URL, nil)
			_, err := p.Analyse(context.Background(), analyseRequest(provider.RoleL1))
			if err == nil {
				t.Fatal("Analyse: err = nil, want permanent error")
			}
			if got := h.attempts.Load(); got != 1 {
				t.Errorf("attempts = %d, want exactly 1 (no retry on permanent)", got)
			}
			if v, _ := counterValue(t, reg, "claude", "l1", statusPermanent); v != 1 {
				t.Errorf("metric {claude,l1,permanent_failure} = %v, want 1", v)
			}
		})
	}
}

func TestAnalyseRoleTimeoutRecordsTimeoutStatus(t *testing.T) {
	h := &capturingHandler{
		script: []scriptedResponse{{200, successBody}},
		delay:  300 * time.Millisecond,
	}
	ts := httptest.NewServer(h)
	defer ts.Close()

	p, reg := newTestProvider(t, ts.URL, nil)
	// Shrink the senior budget so the sleeping handler exceeds it. The
	// production constants are asserted by TestRoleTimeoutContract; here
	// the seam proves the deadline -> status=timeout mapping (BI-5.2).
	p.timeouts = map[provider.Role]time.Duration{provider.RoleSenior: 50 * time.Millisecond}

	_, err := p.Analyse(context.Background(), analyseRequest(provider.RoleSenior))
	if err == nil {
		t.Fatal("Analyse: err = nil, want deadline error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want context.DeadlineExceeded in chain", err)
	}
	if v, _ := counterValue(t, reg, "claude", "senior", statusTimeout); v != 1 {
		t.Errorf("metric {claude,senior,timeout} = %v, want 1", v)
	}
	if v, _ := counterValue(t, reg, "claude", "senior", statusTransient); v != 0 {
		t.Errorf("metric {claude,senior,transient_failure} = %v, want 0 (deadline is timeout, not transient)", v)
	}
}

func TestAnalyseParentCancellationIsNotTimeout(t *testing.T) {
	h := &capturingHandler{
		script: []scriptedResponse{{200, successBody}},
		delay:  300 * time.Millisecond,
	}
	ts := httptest.NewServer(h)
	defer ts.Close()

	p, reg := newTestProvider(t, ts.URL, nil)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	_, err := p.Analyse(ctx, analyseRequest(provider.RoleL2))
	if err == nil {
		t.Fatal("Analyse: err = nil, want cancellation error")
	}
	if v, _ := counterValue(t, reg, "claude", "l2", statusTimeout); v != 0 {
		t.Errorf("parent cancellation recorded as timeout, want transient (BI-5.2 shutdown path)")
	}
	if v, _ := counterValue(t, reg, "claude", "l2", statusTransient); v != 1 {
		t.Errorf("metric {claude,l2,transient_failure} = %v, want 1", v)
	}
}

// TestAnalyseRedactsEvidenceBeforeSend is the Story 3.2 extension of the
// Story 3.1 boundary harness (3.1 AC5): a secret-bearing package crosses a
// REAL provider wire boundary and the captured body must carry the
// redaction placeholders, never the raw secret (AC3).
func TestAnalyseRedactsEvidenceBeforeSend(t *testing.T) {
	const rawSecret = "raw-secret-value-zJ8kQ"
	h := &capturingHandler{script: []scriptedResponse{{200, successBody}}}
	ts := httptest.NewServer(h)
	defer ts.Close()

	p, _ := newTestProvider(t, ts.URL, nil)
	req := analyseRequest(provider.RoleL1)
	req.Package.Events = []schema.Event{{
		ID:       "ev-1",
		Source:   schema.SourceAudit,
		Category: schema.CategoryAPI,
		Summary:  "secret create observed",
		Raw:      json.RawMessage(fmt.Sprintf(`{"spec":{"containers":[{"env":{"API_KEY":%q}}]}}`, rawSecret)),
	}}

	if _, err := p.Analyse(context.Background(), req); err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	// The raw secret has no JSON-escapable characters, so checking the raw
	// bytes is exact at every encoding level.
	if strings.Contains(string(h.lastBody()), rawSecret) {
		t.Fatal("outgoing wire payload contains the RAW secret (AC3/NFR18 violation)")
	}
	text := wireText(t, h.lastBody())
	if strings.Contains(text, rawSecret) {
		t.Fatal("decoded wire text contains the RAW secret (AC3/NFR18 violation)")
	}

	// Strongest form: decode the evidence package exactly as the model
	// would and assert the secret-keyed value IS the redaction token.
	// (The token's < and > survive two JSON encodings as < escapes,
	// so a substring check on the text would be encoding-dependent.)
	start := strings.Index(text, "<evidence_package>\n")
	end := strings.Index(text, "\n</evidence_package>")
	if start < 0 || end < 0 {
		t.Fatalf("wire text missing the evidence_package block:\n%s", text)
	}
	var sent schema.EvidencePackage
	if err := json.Unmarshal([]byte(text[start+len("<evidence_package>\n"):end]), &sent); err != nil {
		t.Fatalf("unmarshal transported evidence package: %v", err)
	}
	if len(sent.Events) != 1 {
		t.Fatalf("transported package has %d events, want 1", len(sent.Events))
	}
	var raw struct {
		Spec struct {
			Containers []struct {
				Env map[string]string `json:"env"`
			} `json:"containers"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(sent.Events[0].Raw, &raw); err != nil {
		t.Fatalf("unmarshal transported event raw: %v", err)
	}
	got := raw.Spec.Containers[0].Env["API_KEY"]
	if got != "<REDACTED>" {
		t.Errorf("transported API_KEY = %q, want the <REDACTED> placeholder (redaction-before-send, AC3)", got)
	}
}

// TestAnalyseAPIKeyNeverInErrorOrLogs forces a 401 with a sentinel key and
// proves the sentinel appears in no error string and no log line (NFR18,
// BI-6.2). The key's only legitimate location is the x-api-key header.
func TestAnalyseAPIKeyNeverInErrorOrLogs(t *testing.T) {
	const sentinel = "SENTINEL-KEY-aGlnaGx5LXNlY3JldA"
	var seenHeader string
	h := &capturingHandler{script: []scriptedResponse{{401, apiErrorBody("authentication_error", "invalid x-api-key")}}}
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHeader = r.Header.Get("x-api-key")
		h.ServeHTTP(w, r)
	})
	ts := httptest.NewServer(wrapped)
	defer ts.Close()

	var logBuf bytes.Buffer
	reg := metrics.NewRegistry()
	p, err := New(Config{BaseURL: ts.URL}, sentinel, reg, nil, slog.New(slog.NewJSONHandler(&logBuf, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p.strategy.Min = time.Millisecond
	p.strategy.Max = 4 * time.Millisecond

	_, err = p.Analyse(context.Background(), analyseRequest(provider.RoleL1))
	if err == nil {
		t.Fatal("Analyse: err = nil, want 401")
	}
	if strings.Contains(err.Error(), sentinel) {
		t.Error("error string contains the API key (NFR18 violation)")
	}
	if strings.Contains(logBuf.String(), sentinel) {
		t.Error("log output contains the API key (NFR18 violation)")
	}
	if seenHeader != sentinel {
		t.Errorf("x-api-key header = %q, want the sentinel (the one legitimate location)", seenHeader)
	}
	if body := string(h.lastBody()); strings.Contains(body, sentinel) {
		t.Error("request body contains the API key")
	}
}

// Story 3.2 round-1 review HIGH: a 200 response whose body is JSON `null`
// decodes into a nil *Message with no error in the SDK. That must degrade
// to a retryable transport error and a transient_failure outcome, never a
// nil-pointer panic recorded as success.
func TestAnalyseNullResponseBodyIsTransientNotPanic(t *testing.T) {
	h := &capturingHandler{script: []scriptedResponse{{200, "null"}}}
	ts := httptest.NewServer(h)
	defer ts.Close()

	p, reg := newTestProvider(t, ts.URL, nil)
	_, err := p.Analyse(context.Background(), analyseRequest(provider.RoleL1))
	if err == nil {
		t.Fatal("Analyse on 200 null body: err = nil, want transport error")
	}
	if !strings.Contains(err.Error(), "empty message") {
		t.Errorf("err = %v, want empty-message transport error", err)
	}
	if got := h.attempts.Load(); got != 3 {
		t.Errorf("attempts = %d, want 3 (transient, retried)", got)
	}
	if v, _ := counterValue(t, reg, "claude", "l1", statusTransient); v != 1 {
		t.Errorf("metric {claude,l1,transient_failure} = %v, want 1", v)
	}
	if v, _ := counterValue(t, reg, "claude", "l1", statusSuccess); v != 0 {
		t.Errorf("metric {claude,l1,success} = %v, want 0 (a null body is not a success)", v)
	}
}

func TestHealthNullResponseBodyReturnsError(t *testing.T) {
	h := &capturingHandler{script: []scriptedResponse{{200, "null"}}}
	ts := httptest.NewServer(h)
	defer ts.Close()

	p, _ := newTestProvider(t, ts.URL, nil)
	if err := p.Health(context.Background()); err == nil {
		t.Fatal("Health on 200 null body: err = nil, want unhealthy")
	}
}

func TestHealthSuccessAndFailure(t *testing.T) {
	h := &capturingHandler{script: []scriptedResponse{{200, successBody}}}
	ts := httptest.NewServer(h)
	defer ts.Close()

	p, reg := newTestProvider(t, ts.URL, nil)
	if err := p.Health(context.Background()); err != nil {
		t.Fatalf("Health: %v", err)
	}

	hFail := &capturingHandler{script: []scriptedResponse{{529, apiErrorBody("overloaded_error", "overloaded")}}}
	tsFail := httptest.NewServer(hFail)
	defer tsFail.Close()
	pFail, _ := newTestProvider(t, tsFail.URL, nil)
	if err := pFail.Health(context.Background()); err == nil {
		t.Fatal("Health against 529: err = nil, want error")
	}
	if got := hFail.attempts.Load(); got != 1 {
		t.Errorf("health attempts = %d, want 1 (no retry on health probe)", got)
	}
	// AC4 scopes olaitan_llm_calls_total to Analyse outcomes.
	mfs, err := reg.Gatherer().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == metricName && len(mf.GetMetric()) != 0 {
			t.Error("Health incremented olaitan_llm_calls_total; the metric is Analyse-scoped")
		}
	}
}

func TestMetricSingleIncrementPerCall(t *testing.T) {
	h := &capturingHandler{script: []scriptedResponse{{200, successBody}}}
	ts := httptest.NewServer(h)
	defer ts.Close()

	p, reg := newTestProvider(t, ts.URL, nil)
	for i := 0; i < 3; i++ {
		if _, err := p.Analyse(context.Background(), analyseRequest(provider.RoleL1)); err != nil {
			t.Fatalf("Analyse #%d: %v", i, err)
		}
	}
	v, series := counterValue(t, reg, "claude", "l1", statusSuccess)
	if v != 3 {
		t.Errorf("metric {claude,l1,success} = %v after 3 calls, want 3", v)
	}
	if series != 1 {
		t.Errorf("family has %d series, want 1 (one outcome per call, no extra labels)", series)
	}
}
