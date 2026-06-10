// Real-wire-format integration suite (Story 3.3 AC3 / BI-7, NFR36): the
// Chat Completions HTTP boundary crosses a real round trip against an
// httptest.Server; attempt counts are proven by a request-counting
// handler, never wall-clock. The matrix mirrors Story 3.2's, plus the
// dual-provider shared-registry coexistence proof (BI-3).
package openaicompat

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
	"github.com/olokotoh/olaitan/internal/agent/provider/claude"
	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/schema"
)

const testAPIKey = "test-key"

const successBody = `{
  "id": "cmpl-test-1",
  "model": "test-model",
  "choices": [{
    "index": 0,
    "message": {"role": "assistant", "content": "{\"verdict\":\"benign\",\"confidence\":12}"},
    "finish_reason": "stop"
  }],
  "usage": {"prompt_tokens": 42, "completion_tokens": 7}
}`

func apiErrorBody(typ, msg string) string {
	return fmt.Sprintf(`{"error":{"type":%q,"message":%q}}`, typ, msg)
}

type scriptedResponse struct {
	status int
	body   string
}

// capturingHandler counts attempts, records bodies/paths/headers and
// serves the scripted per-attempt responses (last entry repeats).
type capturingHandler struct {
	mu       sync.Mutex
	bodies   [][]byte
	paths    []string
	auths    []string
	attempts atomic.Int64
	script   []scriptedResponse
	delay    time.Duration
}

func (h *capturingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n := h.attempts.Add(1)
	body, _ := io.ReadAll(r.Body)
	h.mu.Lock()
	h.bodies = append(h.bodies, body)
	h.paths = append(h.paths, r.URL.Path)
	h.auths = append(h.auths, r.Header.Get("Authorization"))
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

func (h *capturingHandler) lastPath() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.paths) == 0 {
		return ""
	}
	return h.paths[len(h.paths)-1]
}

func (h *capturingHandler) lastAuth() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.auths) == 0 {
		return ""
	}
	return h.auths[len(h.auths)-1]
}

func newTestProvider(t *testing.T, baseURL string, logSink io.Writer) (*Provider, *metrics.Registry) {
	t.Helper()
	if logSink == nil {
		logSink = io.Discard
	}
	reg := metrics.NewRegistry()
	p, err := New(Config{Model: "test-model", BaseURL: baseURL}, testAPIKey, reg, nil, slog.New(slog.NewJSONHandler(logSink, nil)))
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
			PackageID:     "pkg-oa-1",
			WorkloadID:    "default/nginx-abc",
		},
		Prompt: provider.Prompt{System: "analyst system prompt", User: "triage this evidence"},
		Schema: provider.JSONSchema(`{"type":"object"}`),
	}
}

func counterValue(t *testing.T, reg *metrics.Registry, prov, role, status string) (float64, int) {
	t.Helper()
	mfs, err := reg.Gatherer().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != provider.CallsMetricName {
			continue
		}
		var val float64
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, lp := range m.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
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
	if resp.StopReason != "stop" {
		t.Errorf("StopReason = %q, want stop (finish_reason verbatim)", resp.StopReason)
	}
	if resp.Model != "test-model" {
		t.Errorf("Model = %q", resp.Model)
	}
	if resp.InputTokens != 42 || resp.OutputTokens != 7 {
		t.Errorf("usage = %d/%d, want 42/7", resp.InputTokens, resp.OutputTokens)
	}
	if v, _ := counterValue(t, reg, "openai", "l1", provider.StatusSuccess); v != 1 {
		t.Errorf("metric {openai,l1,success} = %v, want 1", v)
	}
}

func TestAnalyseWirePayloadContract(t *testing.T) {
	h := &capturingHandler{script: []scriptedResponse{{200, successBody}}}
	ts := httptest.NewServer(h)
	defer ts.Close()

	p, _ := newTestProvider(t, ts.URL, nil)
	if _, err := p.Analyse(context.Background(), analyseRequest(provider.RoleL1)); err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	if got := h.lastPath(); got != "/chat/completions" {
		t.Errorf("path = %q, want /chat/completions", got)
	}
	if got := h.lastAuth(); got != "Bearer "+testAPIKey {
		t.Errorf("Authorization = %q, want Bearer token (the one legitimate key location)", got)
	}

	body := h.lastBody()
	var wire map[string]any
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatalf("request body is not JSON: %v", err)
	}
	// Lowest common denominator only: no sampling params, no
	// max_completion_tokens, no vendor extension (BI-2.1).
	for _, forbidden := range []string{"temperature", "top_p", "top_k", "max_completion_tokens", "budget_tokens", "thinking"} {
		if _, ok := wire[forbidden]; ok {
			t.Errorf("wire payload carries non-LCD field %q", forbidden)
		}
	}
	if wire["model"] != "test-model" {
		t.Errorf("model = %v", wire["model"])
	}
	if wire["max_tokens"] != float64(DefaultMaxTokens) {
		t.Errorf("max_tokens = %v, want %d", wire["max_tokens"], DefaultMaxTokens)
	}
	if stream, ok := wire["stream"].(bool); !ok || stream {
		t.Errorf("stream = %v, want explicit false", wire["stream"])
	}
	msgs, ok := wire["messages"].([]any)
	if !ok || len(msgs) != 2 {
		t.Fatalf("messages = %v, want [system, user]", wire["messages"])
	}
	if strings.Contains(string(body), testAPIKey) {
		t.Error("request body contains the API key")
	}
}

func TestAnalyseRetriesTransientThenSucceeds(t *testing.T) {
	h := &capturingHandler{script: []scriptedResponse{
		{500, apiErrorBody("server_error", "upstream hiccup")},
		{200, successBody},
	}}
	ts := httptest.NewServer(h)
	defer ts.Close()

	p, reg := newTestProvider(t, ts.URL, nil)
	if _, err := p.Analyse(context.Background(), analyseRequest(provider.RoleL1)); err != nil {
		t.Fatalf("Analyse after 500-then-200: %v", err)
	}
	if got := h.attempts.Load(); got != 2 {
		t.Errorf("attempts = %d, want 2", got)
	}
	if v, _ := counterValue(t, reg, "openai", "l1", provider.StatusSuccess); v != 1 {
		t.Errorf("metric {openai,l1,success} = %v, want 1 (final outcome only)", v)
	}
}

func TestAnalyseTransientExhaustsThreeAttempts(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		errType string
	}{
		{"429 rate limit", 429, "rate_limit_exceeded"},
		{"500 server error", 500, "server_error"},
		{"503 unavailable", 503, "service_unavailable"},
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
			if v, _ := counterValue(t, reg, "openai", "senior", provider.StatusTransient); v != 1 {
				t.Errorf("metric {openai,senior,transient_failure} = %v, want 1", v)
			}
		})
	}
}

func TestAnalysePermanentAbortsFirstAttempt(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 413} {
		t.Run(fmt.Sprintf("%d", status), func(t *testing.T) {
			h := &capturingHandler{script: []scriptedResponse{{status, apiErrorBody("invalid_request_error", "permanent")}}}
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
			if v, _ := counterValue(t, reg, "openai", "l1", provider.StatusPermanent); v != 1 {
				t.Errorf("metric {openai,l1,permanent_failure} = %v, want 1", v)
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
	p.timeouts = map[provider.Role]time.Duration{provider.RoleSenior: 50 * time.Millisecond}

	_, err := p.Analyse(context.Background(), analyseRequest(provider.RoleSenior))
	if err == nil {
		t.Fatal("Analyse: err = nil, want deadline error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want context.DeadlineExceeded in chain", err)
	}
	if v, _ := counterValue(t, reg, "openai", "senior", provider.StatusTimeout); v != 1 {
		t.Errorf("metric {openai,senior,timeout} = %v, want 1", v)
	}
	if v, _ := counterValue(t, reg, "openai", "senior", provider.StatusTransient); v != 0 {
		t.Errorf("deadline misrecorded as transient_failure")
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
	if _, err := p.Analyse(ctx, analyseRequest(provider.RoleL2)); err == nil {
		t.Fatal("Analyse: err = nil, want cancellation error")
	}
	if v, _ := counterValue(t, reg, "openai", "l2", provider.StatusTimeout); v != 0 {
		t.Errorf("parent cancellation recorded as timeout, want transient (shutdown path)")
	}
	if v, _ := counterValue(t, reg, "openai", "l2", provider.StatusTransient); v != 1 {
		t.Errorf("metric {openai,l2,transient_failure} = %v, want 1", v)
	}
}

// TestAnalyseRedactsEvidenceBeforeSend: the Story 3.1/3.2 boundary proof
// on the Chat Completions wire shape (decode the transported evidence
// exactly as the model would and assert the secret-keyed value IS the
// redaction placeholder).
func TestAnalyseRedactsEvidenceBeforeSend(t *testing.T) {
	const rawSecret = "raw-secret-value-qP7xT"
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

	if strings.Contains(string(h.lastBody()), rawSecret) {
		t.Fatal("outgoing wire payload contains the RAW secret (AC2/NFR18 violation)")
	}
	text := chatWireText(t, h.lastBody())
	if strings.Contains(text, rawSecret) {
		t.Fatal("decoded wire text contains the RAW secret")
	}
	start := strings.Index(text, "<evidence_package>\n")
	end := strings.Index(text, "\n</evidence_package>")
	if start < 0 || end < 0 {
		t.Fatalf("wire text missing the evidence_package block:\n%s", text)
	}
	var sent schema.EvidencePackage
	if err := json.Unmarshal([]byte(text[start+len("<evidence_package>\n"):end]), &sent); err != nil {
		t.Fatalf("unmarshal transported evidence package: %v", err)
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
	if got := raw.Spec.Containers[0].Env["API_KEY"]; got != "<REDACTED>" {
		t.Errorf("transported API_KEY = %q, want the <REDACTED> placeholder", got)
	}
}

func TestAnalyseAPIKeyNeverInErrorOrLogs(t *testing.T) {
	const sentinel = "SENTINEL-KEY-b3BlbmFpLXNlY3JldA"
	h := &capturingHandler{script: []scriptedResponse{{401, apiErrorBody("invalid_api_key", "bad key")}}}
	ts := httptest.NewServer(h)
	defer ts.Close()

	var logBuf bytes.Buffer
	reg := metrics.NewRegistry()
	p, err := New(Config{Model: "test-model", BaseURL: ts.URL}, sentinel, reg, nil, slog.New(slog.NewJSONHandler(&logBuf, nil)))
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
	if got := h.lastAuth(); got != "Bearer "+sentinel {
		t.Errorf("Authorization = %q, want the sentinel Bearer token", got)
	}
	if strings.Contains(string(h.lastBody()), sentinel) {
		t.Error("request body contains the API key")
	}
}

// TestAnalyseKeyEchoedInErrorBodyIsScrubbed: round-1 review finding.
// OpenAI itself echoes key material in 401 bodies ("Incorrect API key
// provided: sk-...") and arbitrary compatible proxies may echo the
// Authorization value; the snippet scrub must keep an echoed key out of
// error strings and logs (NFR18).
func TestAnalyseKeyEchoedInErrorBodyIsScrubbed(t *testing.T) {
	const sentinel = "SENTINEL-KEY-ZWNoby1pbi1ib2R5"
	h := &capturingHandler{script: []scriptedResponse{{401, apiErrorBody("invalid_api_key", "Incorrect API key provided: "+sentinel)}}}
	ts := httptest.NewServer(h)
	defer ts.Close()

	var logBuf bytes.Buffer
	reg := metrics.NewRegistry()
	p, err := New(Config{Model: "test-model", BaseURL: ts.URL}, sentinel, reg, nil, slog.New(slog.NewJSONHandler(&logBuf, nil)))
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
		t.Error("error string contains the API key echoed by the upstream error body (NFR18 violation)")
	}
	if !strings.Contains(err.Error(), "<redacted>") {
		t.Errorf("err = %v, want the echoed key replaced with <redacted>", err)
	}
	if strings.Contains(logBuf.String(), sentinel) {
		t.Error("log output contains the echoed API key (NFR18 violation)")
	}
}

// TestAnalyseDoesNotFollowRedirects: round-1 review finding. A 3xx from
// a misconfigured endpoint must surface as a typed transient apiError;
// following it would convert the POST to a GET (301/302/303) and re-send
// the bearer token to the redirect target.
func TestAnalyseDoesNotFollowRedirects(t *testing.T) {
	target := &capturingHandler{script: []scriptedResponse{{200, successBody}}}
	tsTarget := httptest.NewServer(target)
	defer tsTarget.Close()

	var redirects atomic.Int64
	tsRedir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirects.Add(1)
		http.Redirect(w, r, tsTarget.URL+"/chat/completions", http.StatusMovedPermanently)
	}))
	defer tsRedir.Close()

	p, reg := newTestProvider(t, tsRedir.URL, nil)
	_, err := p.Analyse(context.Background(), analyseRequest(provider.RoleL1))
	if err == nil {
		t.Fatal("Analyse via 301: err = nil, want typed apiError")
	}
	var apiErr *apiError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusMovedPermanently {
		t.Errorf("err = %v, want typed apiError with status 301", err)
	}
	if got := redirects.Load(); got != 3 {
		t.Errorf("redirecting endpoint attempts = %d, want 3 (transient, retried)", got)
	}
	if got := target.attempts.Load(); got != 0 {
		t.Errorf("redirect target received %d requests, want 0 (no follow, no key forward)", got)
	}
	if v, _ := counterValue(t, reg, "openai", "l1", provider.StatusTransient); v != 1 {
		t.Errorf("metric {openai,l1,transient_failure} = %v, want 1", v)
	}
}

// TestAnalyseEmptyContentIn200IsSuccess pins the documented contract
// (runbook limitation c): a well-formed 200 whose first choice carries an
// empty content string is SUCCESS with Raw == ""; treating an empty
// verdict as failed is the Story 3.5-3.7 caller's contract, not the
// transport's (round-1 review: previously documented but unpinned).
func TestAnalyseEmptyContentIn200IsSuccess(t *testing.T) {
	h := &capturingHandler{script: []scriptedResponse{{200, `{"model":"test-model","choices":[{"index":0,"message":{"role":"assistant","content":""},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":0}}`}}}
	ts := httptest.NewServer(h)
	defer ts.Close()

	p, reg := newTestProvider(t, ts.URL, nil)
	resp, err := p.Analyse(context.Background(), analyseRequest(provider.RoleL1))
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if resp.Raw != "" {
		t.Errorf("Raw = %q, want empty string", resp.Raw)
	}
	if got := h.attempts.Load(); got != 1 {
		t.Errorf("attempts = %d, want 1 (empty content is not retryable)", got)
	}
	if v, _ := counterValue(t, reg, "openai", "l1", provider.StatusSuccess); v != 1 {
		t.Errorf("metric {openai,l1,success} = %v, want 1", v)
	}
}

// The Story 3.2 round-1 lesson, binding here per BI-4: degenerate 200
// bodies must degrade to retryable transport errors, never a panic or a
// falsified success.
func TestAnalyseNullResponseBodyIsTransientNotPanic(t *testing.T) {
	h := &capturingHandler{script: []scriptedResponse{{200, "null"}}}
	ts := httptest.NewServer(h)
	defer ts.Close()

	p, reg := newTestProvider(t, ts.URL, nil)
	_, err := p.Analyse(context.Background(), analyseRequest(provider.RoleL1))
	if err == nil {
		t.Fatal("Analyse on 200 null body: err = nil, want transport error")
	}
	if !strings.Contains(err.Error(), "empty choices") {
		t.Errorf("err = %v, want empty-choices transport error", err)
	}
	if got := h.attempts.Load(); got != 3 {
		t.Errorf("attempts = %d, want 3 (transient, retried)", got)
	}
	if v, _ := counterValue(t, reg, "openai", "l1", provider.StatusTransient); v != 1 {
		t.Errorf("metric {openai,l1,transient_failure} = %v, want 1", v)
	}
	if v, _ := counterValue(t, reg, "openai", "l1", provider.StatusSuccess); v != 0 {
		t.Errorf("a null body must never record success")
	}
}

func TestAnalyseEmptyChoicesIsTransient(t *testing.T) {
	h := &capturingHandler{script: []scriptedResponse{{200, `{"model":"test-model","choices":[]}`}}}
	ts := httptest.NewServer(h)
	defer ts.Close()

	p, reg := newTestProvider(t, ts.URL, nil)
	if _, err := p.Analyse(context.Background(), analyseRequest(provider.RoleL1)); err == nil {
		t.Fatal("Analyse on empty choices: err = nil, want transport error")
	}
	if v, _ := counterValue(t, reg, "openai", "l1", provider.StatusTransient); v != 1 {
		t.Errorf("metric {openai,l1,transient_failure} = %v, want 1", v)
	}
}

func TestHealthSuccessFailureAndGuards(t *testing.T) {
	h := &capturingHandler{script: []scriptedResponse{{200, successBody}}}
	ts := httptest.NewServer(h)
	defer ts.Close()
	p, reg := newTestProvider(t, ts.URL, nil)
	if err := p.Health(context.Background()); err != nil {
		t.Fatalf("Health: %v", err)
	}

	hFail := &capturingHandler{script: []scriptedResponse{{503, apiErrorBody("service_unavailable", "down")}}}
	tsFail := httptest.NewServer(hFail)
	defer tsFail.Close()
	pFail, regFail := newTestProvider(t, tsFail.URL, nil)
	if err := pFail.Health(context.Background()); err == nil {
		t.Fatal("Health against 503: err = nil, want error")
	}
	if got := hFail.attempts.Load(); got != 1 {
		t.Errorf("health attempts = %d, want 1 (no retry on health probe)", got)
	}

	hNull := &capturingHandler{script: []scriptedResponse{{200, "null"}}}
	tsNull := httptest.NewServer(hNull)
	defer tsNull.Close()
	pNull, regNull := newTestProvider(t, tsNull.URL, nil)
	if err := pNull.Health(context.Background()); err == nil {
		t.Fatal("Health on 200 null body: err = nil, want unhealthy")
	}

	// The metric is Analyse-scoped; Health must not touch it on the
	// success path NOR the failure paths (round-1 review: the failure
	// paths are the ones most likely to share code with Analyse).
	for name, r := range map[string]*metrics.Registry{"success": reg, "fail-503": regFail, "null-body": regNull} {
		mfs, err := r.Gatherer().Gather()
		if err != nil {
			t.Fatalf("gather %s: %v", name, err)
		}
		for _, mf := range mfs {
			if mf.GetName() == provider.CallsMetricName && len(mf.GetMetric()) != 0 {
				t.Errorf("Health (%s path) incremented olaitan_llm_calls_total; the metric is Analyse-scoped", name)
			}
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
	v, series := counterValue(t, reg, "openai", "l1", provider.StatusSuccess)
	if v != 3 {
		t.Errorf("metric {openai,l1,success} = %v after 3 calls, want 3", v)
	}
	if series != 1 {
		t.Errorf("family has %d series, want 1", series)
	}
}

// TestBaseURLForms: trailing-slash and path-prefixed endpoints must all
// resolve to <prefix>/chat/completions (BI-2.5).
func TestBaseURLForms(t *testing.T) {
	cases := []struct {
		suffix   string
		wantPath string
	}{
		{"", "/chat/completions"},
		{"/", "/chat/completions"},
		{"/proxy/v1", "/proxy/v1/chat/completions"},
		{"/proxy/v1/", "/proxy/v1/chat/completions"},
	}
	for _, tc := range cases {
		t.Run("base"+tc.suffix, func(t *testing.T) {
			h := &capturingHandler{script: []scriptedResponse{{200, successBody}}}
			ts := httptest.NewServer(h)
			defer ts.Close()

			p, _ := newTestProvider(t, ts.URL+tc.suffix, nil)
			if _, err := p.Analyse(context.Background(), analyseRequest(provider.RoleL1)); err != nil {
				t.Fatalf("Analyse: %v", err)
			}
			if got := h.lastPath(); got != tc.wantPath {
				t.Errorf("path = %q, want %q", got, tc.wantPath)
			}
		})
	}
}

// TestDualProviderSharedRegistry is the BI-3 coexistence proof: the
// Claude and OpenAI-compatible providers construct against the SAME
// registry (no duplicate-registration error) and increment side-by-side
// series of the one shared family (the Story 3.8 routing prerequisite).
// Both providers drive a REAL Analyse increment (round-1 review: the
// BI-7 clause demands increment, not just registration).
func TestDualProviderSharedRegistry(t *testing.T) {
	reg := metrics.NewRegistry()
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))

	hOA := &capturingHandler{script: []scriptedResponse{{200, successBody}}}
	tsOA := httptest.NewServer(hOA)
	defer tsOA.Close()
	oa, err := New(Config{Model: "test-model", BaseURL: tsOA.URL}, testAPIKey, reg, nil, log)
	if err != nil {
		t.Fatalf("openai New: %v", err)
	}

	// A minimal Anthropic Messages success body so the claude provider can
	// complete a real call against its own httptest endpoint.
	const claudeSuccessBody = `{
	  "id": "msg_01DualProvider",
	  "type": "message",
	  "role": "assistant",
	  "model": "claude-opus-4-8",
	  "content": [{"type": "text", "text": "{\"verdict\":\"benign\"}"}],
	  "stop_reason": "end_turn",
	  "stop_sequence": null,
	  "usage": {"input_tokens": 1, "output_tokens": 1}
	}`
	hCL := &capturingHandler{script: []scriptedResponse{{200, claudeSuccessBody}}}
	tsCL := httptest.NewServer(hCL)
	defer tsCL.Close()
	cl, err := claude.New(claude.Config{BaseURL: tsCL.URL}, testAPIKey, reg, nil, log)
	if err != nil {
		t.Fatalf("claude.New on the same registry: %v (BI-3 idempotent registration broken)", err)
	}

	if _, err := oa.Analyse(context.Background(), analyseRequest(provider.RoleL1)); err != nil {
		t.Fatalf("openai Analyse: %v", err)
	}
	if _, err := cl.Analyse(context.Background(), analyseRequest(provider.RoleL1)); err != nil {
		t.Fatalf("claude Analyse: %v", err)
	}

	if v, _ := counterValue(t, reg, "openai", "l1", provider.StatusSuccess); v != 1 {
		t.Errorf("metric {openai,l1,success} = %v, want 1", v)
	}
	if v, series := counterValue(t, reg, "claude", "l1", provider.StatusSuccess); v != 1 || series != 2 {
		t.Errorf("metric {claude,l1,success} = %v (family series = %d), want 1 with 2 side-by-side series", v, series)
	}
}
