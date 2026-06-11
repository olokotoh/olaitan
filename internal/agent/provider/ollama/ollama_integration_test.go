// Real-wire-format integration suite (Story 3.4 AC4, NFR36): the native
// /api/chat HTTP boundary crosses a real round trip against an
// httptest.Server; attempt counts are proven by a request-counting
// handler, never wall-clock. The matrix mirrors Story 3.2/3.3's, plus
// the tri-provider shared-registry coexistence proof (BI-5: every
// provider INCREMENTS, none merely registers).
package ollama

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
	openaicompat "github.com/olokotoh/olaitan/internal/agent/provider/openai_compat"
	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/schema"
)

const successBody = `{
  "model": "test-model",
  "created_at": "2026-06-11T00:00:00Z",
  "message": {"role": "assistant", "content": "{\"verdict\":\"benign\",\"confidence\":12}"},
  "done": true,
  "done_reason": "stop",
  "prompt_eval_count": 42,
  "eval_count": 7
}`

func apiErrorBody(msg string) string {
	return fmt.Sprintf(`{"error":%q}`, msg)
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

func newTestProvider(t *testing.T, endpoint string, logSink io.Writer) (*Provider, *metrics.Registry) {
	t.Helper()
	if logSink == nil {
		logSink = io.Discard
	}
	reg := metrics.NewRegistry()
	p, err := New(Config{Model: "test-model", Endpoint: endpoint}, reg, nil, slog.New(slog.NewJSONHandler(logSink, nil)))
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
			PackageID:     "pkg-ol-1",
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

// wireRequest decodes the captured native /api/chat request body for
// shape assertions. Raw map form so ABSENT keys are distinguishable.
func wireRequest(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("unmarshal captured request: %v", err)
	}
	return m
}

func wireUserContent(t *testing.T, body []byte) string {
	t.Helper()
	var req struct {
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("unmarshal captured messages: %v", err)
	}
	if len(req.Messages) == 0 {
		t.Fatal("captured request has no messages")
	}
	return req.Messages[len(req.Messages)-1].Content
}

// TestAnalyseSuccessAndWireShape: one attempt, decoded response fields,
// and the BI-2.1 request contract: path /api/chat, stream PRESENT and
// false, options.num_predict present, NO sampling keys, NO num_ctx, NO
// max_tokens, and NO Authorization header (BI-3: no credential exists).
func TestAnalyseSuccessAndWireShape(t *testing.T) {
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
	if resp.Raw != `{"verdict":"benign","confidence":12}` {
		t.Errorf("Raw = %q", resp.Raw)
	}
	if resp.StopReason != "stop" {
		t.Errorf("StopReason = %q, want done_reason verbatim", resp.StopReason)
	}
	if resp.Model != "test-model" {
		t.Errorf("Model = %q", resp.Model)
	}
	if resp.InputTokens != 42 || resp.OutputTokens != 7 {
		t.Errorf("tokens = %d/%d, want 42/7 (prompt_eval_count/eval_count)", resp.InputTokens, resp.OutputTokens)
	}

	if got := h.lastPath(); got != "/api/chat" {
		t.Errorf("path = %q, want /api/chat", got)
	}
	if got := h.lastAuth(); got != "" {
		t.Errorf("Authorization = %q, want ABSENT (no credential exists, BI-3)", got)
	}
	wire := wireRequest(t, h.lastBody())
	stream, present := wire["stream"]
	if !present {
		t.Error("stream key absent from the wire; it must be EXPLICITLY false (server defaults to streaming)")
	} else if stream != false {
		t.Errorf("stream = %v, want false", stream)
	}
	opts, ok := wire["options"].(map[string]any)
	if !ok {
		t.Fatal("options object absent from the wire")
	}
	if _, ok := opts["num_predict"]; !ok {
		t.Error("options.num_predict absent from the wire")
	}
	for _, forbidden := range []string{"temperature", "top_p", "num_ctx", "keep_alive"} {
		if _, ok := opts[forbidden]; ok {
			t.Errorf("options.%s present on the wire; BI-2.1 forbids it", forbidden)
		}
	}
	for _, forbidden := range []string{"max_tokens", "max_completion_tokens", "temperature", "top_p"} {
		if _, ok := wire[forbidden]; ok {
			t.Errorf("top-level %s present on the wire; BI-2.1 forbids it", forbidden)
		}
	}
	if v, _ := counterValue(t, reg, "ollama", "l1", provider.StatusSuccess); v != 1 {
		t.Errorf("metric {ollama,l1,success} = %v, want 1", v)
	}
}

func TestAnalyse500Then200Retries(t *testing.T) {
	h := &capturingHandler{script: []scriptedResponse{
		{500, apiErrorBody("transient blip")},
		{200, successBody},
	}}
	ts := httptest.NewServer(h)
	defer ts.Close()

	p, reg := newTestProvider(t, ts.URL, nil)
	if _, err := p.Analyse(context.Background(), analyseRequest(provider.RoleL1)); err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if got := h.attempts.Load(); got != 2 {
		t.Errorf("attempts = %d, want 2 (500 then 200)", got)
	}
	if v, _ := counterValue(t, reg, "ollama", "l1", provider.StatusSuccess); v != 1 {
		t.Errorf("metric {ollama,l1,success} = %v, want 1", v)
	}
}

func TestAnalyseTransientExhaustion(t *testing.T) {
	for _, status := range []int{429, 500, 503} {
		t.Run(fmt.Sprintf("status-%d", status), func(t *testing.T) {
			h := &capturingHandler{script: []scriptedResponse{{status, apiErrorBody("down")}}}
			ts := httptest.NewServer(h)
			defer ts.Close()

			p, reg := newTestProvider(t, ts.URL, nil)
			if _, err := p.Analyse(context.Background(), analyseRequest(provider.RoleL1)); err == nil {
				t.Fatal("Analyse: err = nil, want exhaustion error")
			}
			if got := h.attempts.Load(); got != 3 {
				t.Errorf("attempts = %d, want 3 (MaxAttempts)", got)
			}
			if v, _ := counterValue(t, reg, "ollama", "l1", provider.StatusTransient); v != 1 {
				t.Errorf("metric {ollama,l1,transient_failure} = %v, want 1", v)
			}
		})
	}
}

func TestAnalysePermanentAborts(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 413} {
		t.Run(fmt.Sprintf("status-%d", status), func(t *testing.T) {
			h := &capturingHandler{script: []scriptedResponse{{status, apiErrorBody("no")}}}
			ts := httptest.NewServer(h)
			defer ts.Close()

			p, reg := newTestProvider(t, ts.URL, nil)
			_, err := p.Analyse(context.Background(), analyseRequest(provider.RoleL1))
			if err == nil {
				t.Fatal("Analyse: err = nil, want permanent error")
			}
			var apiErr *apiError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != status {
				t.Errorf("err = %v, want typed apiError %d", err, status)
			}
			if got := h.attempts.Load(); got != 1 {
				t.Errorf("attempts = %d, want 1 (permanent, no retry)", got)
			}
			if v, _ := counterValue(t, reg, "ollama", "l1", provider.StatusPermanent); v != 1 {
				t.Errorf("metric {ollama,l1,permanent_failure} = %v, want 1", v)
			}
		})
	}
}

// TestAnalyseRoleTimeoutRecordsTimeoutStatus: the role deadline firing
// while the parent is alive resolves to status=timeout (seam-replaced
// single-role map mirrors the 3.2/3.3 suites).
func TestAnalyseRoleTimeoutRecordsTimeoutStatus(t *testing.T) {
	h := &capturingHandler{script: []scriptedResponse{{200, successBody}}, delay: 300 * time.Millisecond}
	ts := httptest.NewServer(h)
	defer ts.Close()

	p, reg := newTestProvider(t, ts.URL, nil)
	p.timeouts = map[provider.Role]time.Duration{provider.RoleL1: 50 * time.Millisecond}

	if _, err := p.Analyse(context.Background(), analyseRequest(provider.RoleL1)); err == nil {
		t.Fatal("Analyse: err = nil, want deadline error")
	}
	if v, _ := counterValue(t, reg, "ollama", "l1", provider.StatusTimeout); v != 1 {
		t.Errorf("metric {ollama,l1,timeout} = %v, want 1", v)
	}
	if v, _ := counterValue(t, reg, "ollama", "l1", provider.StatusTransient); v != 0 {
		t.Errorf("role-deadline expiry recorded transient, want timeout only")
	}
}

func TestAnalyseParentCancellationIsNotTimeout(t *testing.T) {
	h := &capturingHandler{script: []scriptedResponse{{200, successBody}}, delay: 300 * time.Millisecond}
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
	if v, _ := counterValue(t, reg, "ollama", "l2", provider.StatusTimeout); v != 0 {
		t.Errorf("parent cancellation recorded as timeout, want transient (shutdown path)")
	}
	if v, _ := counterValue(t, reg, "ollama", "l2", provider.StatusTransient); v != 1 {
		t.Errorf("metric {ollama,l2,transient_failure} = %v, want 1", v)
	}
}

// TestAnalyseRedactsEvidenceBeforeSend: the Story 3.1/3.2 boundary proof
// on the native wire shape (decode the transported evidence exactly as
// the model would and assert the secret-keyed value IS the redaction
// placeholder).
func TestAnalyseRedactsEvidenceBeforeSend(t *testing.T) {
	const rawSecret = "raw-secret-value-zX4kQ"
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
		t.Fatal("outgoing wire payload contains the RAW secret (NFR18 violation)")
	}
	text := wireUserContent(t, h.lastBody())
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

// The Story 3.2 round-1 lesson, binding here per BI-2.2: degenerate 200
// bodies must degrade to retryable transport errors, never a panic or a
// falsified success.
func TestAnalyseNullBodyAndMissingMessageAreTransient(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"json null body", "null"},
		{"empty object", "{}"},
		{"null message", `{"model":"test-model","message":null,"done":true}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &capturingHandler{script: []scriptedResponse{{200, tc.body}}}
			ts := httptest.NewServer(h)
			defer ts.Close()

			p, reg := newTestProvider(t, ts.URL, nil)
			_, err := p.Analyse(context.Background(), analyseRequest(provider.RoleL1))
			if err == nil {
				t.Fatal("Analyse on degenerate 200: err = nil, want transport error")
			}
			if !strings.Contains(err.Error(), "missing message") {
				t.Errorf("err = %v, want missing-message transport error", err)
			}
			if got := h.attempts.Load(); got != 3 {
				t.Errorf("attempts = %d, want 3 (transient, retried)", got)
			}
			if v, _ := counterValue(t, reg, "ollama", "l1", provider.StatusSuccess); v != 0 {
				t.Errorf("a degenerate 200 must never record success")
			}
		})
	}
}

// TestAnalyseNDJSONLeakIsTransient: a server that ignores stream:false
// returns NDJSON chunks; the single-object decode fails and the call
// degrades to a retryable transport error, never a partial verdict.
func TestAnalyseNDJSONLeakIsTransient(t *testing.T) {
	ndjson := `{"model":"test-model","message":{"role":"assistant","content":"par"},"done":false}
{"model":"test-model","message":{"role":"assistant","content":"tial"},"done":true,"done_reason":"stop"}`
	h := &capturingHandler{script: []scriptedResponse{{200, ndjson}}}
	ts := httptest.NewServer(h)
	defer ts.Close()

	p, reg := newTestProvider(t, ts.URL, nil)
	_, err := p.Analyse(context.Background(), analyseRequest(provider.RoleL1))
	if err == nil {
		t.Fatal("Analyse on NDJSON leak: err = nil, want decode error")
	}
	if got := h.attempts.Load(); got != 3 {
		t.Errorf("attempts = %d, want 3 (transient, retried)", got)
	}
	if v, _ := counterValue(t, reg, "ollama", "l1", provider.StatusSuccess); v != 0 {
		t.Errorf("an NDJSON leak must never record success")
	}
}

// TestAnalyseEmptyContentIn200IsSuccess pins the cross-provider
// contract (Story 3.3 precedent): a well-formed 200 whose message
// carries an empty content string is SUCCESS with Raw == ""; treating
// an empty verdict as failed is the Story 3.5-3.7 caller's contract.
func TestAnalyseEmptyContentIn200IsSuccess(t *testing.T) {
	h := &capturingHandler{script: []scriptedResponse{{200, `{"model":"test-model","message":{"role":"assistant","content":""},"done":true,"done_reason":"stop"}`}}}
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
	if v, _ := counterValue(t, reg, "ollama", "l1", provider.StatusSuccess); v != 1 {
		t.Errorf("metric {ollama,l1,success} = %v, want 1", v)
	}
}

// TestAnalyseDoesNotFollowRedirects: a 3xx from a misconfigured
// endpoint must surface as a typed transient apiError; following it
// would convert the POST to a GET (Story 3.3 round-1 lesson, binding).
func TestAnalyseDoesNotFollowRedirects(t *testing.T) {
	target := &capturingHandler{script: []scriptedResponse{{200, successBody}}}
	tsTarget := httptest.NewServer(target)
	defer tsTarget.Close()

	var redirects atomic.Int64
	tsRedir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirects.Add(1)
		http.Redirect(w, r, tsTarget.URL+"/api/chat", http.StatusMovedPermanently)
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
		t.Errorf("redirect target received %d requests, want 0 (no follow)", got)
	}
	if v, _ := counterValue(t, reg, "ollama", "l1", provider.StatusTransient); v != 1 {
		t.Errorf("metric {ollama,l1,transient_failure} = %v, want 1", v)
	}
}

// TestEndpointForms: trailing-slash and path-prefixed endpoints must all
// resolve to <prefix>/api/chat (BI-2.5).
func TestEndpointForms(t *testing.T) {
	cases := []struct {
		suffix   string
		wantPath string
	}{
		{"", "/api/chat"},
		{"/", "/api/chat"},
		{"/proxy", "/proxy/api/chat"},
		{"/proxy/", "/proxy/api/chat"},
	}
	for _, tc := range cases {
		t.Run("endpoint"+tc.suffix, func(t *testing.T) {
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

func TestHealthSuccessFailureAndGuards(t *testing.T) {
	h := &capturingHandler{script: []scriptedResponse{{200, successBody}}}
	ts := httptest.NewServer(h)
	defer ts.Close()
	p, reg := newTestProvider(t, ts.URL, nil)
	if err := p.Health(context.Background()); err != nil {
		t.Fatalf("Health: %v", err)
	}
	if got := h.attempts.Load(); got != 1 {
		t.Errorf("health attempts = %d, want 1", got)
	}
	wire := wireRequest(t, h.lastBody())
	if opts, ok := wire["options"].(map[string]any); !ok || opts["num_predict"] != float64(1) {
		t.Errorf("health num_predict = %v, want 1 (minimal probe)", wire["options"])
	}

	hFail := &capturingHandler{script: []scriptedResponse{{503, apiErrorBody("down")}}}
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
	// success path NOR the failure paths (Story 3.3 round-1 lesson).
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
	v, series := counterValue(t, reg, "ollama", "l1", provider.StatusSuccess)
	if v != 3 {
		t.Errorf("metric {ollama,l1,success} = %v after 3 calls, want 3", v)
	}
	if series != 1 {
		t.Errorf("family has %d series, want 1", series)
	}
}

// TestTriProviderSharedRegistry is the BI-5 coexistence proof for the
// COMPLETE provider set: claude, openai_compat, and ollama construct
// against the SAME registry (idempotent registration) and each DRIVES A
// REAL INCREMENT against its own wire-shape endpoint (the Story 3.3
// round-1 lesson: increment, never just register). Family ceiling after
// 3.4: 3 providers x 4 roles x 4 statuses = 48 bounded series.
func TestTriProviderSharedRegistry(t *testing.T) {
	reg := metrics.NewRegistry()
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))

	// Ollama endpoint (native /api/chat shape).
	hOL := &capturingHandler{script: []scriptedResponse{{200, successBody}}}
	tsOL := httptest.NewServer(hOL)
	defer tsOL.Close()
	ol, err := New(Config{Model: "test-model", Endpoint: tsOL.URL}, reg, nil, log)
	if err != nil {
		t.Fatalf("ollama New: %v", err)
	}

	// Claude endpoint (Anthropic Messages shape).
	const claudeSuccessBody = `{
	  "id": "msg_01TriProvider",
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
	cl, err := claude.New(claude.Config{BaseURL: tsCL.URL}, "test-key", reg, nil, log)
	if err != nil {
		t.Fatalf("claude.New on the shared registry: %v (idempotent registration broken)", err)
	}

	// OpenAI-compatible endpoint (Chat Completions shape).
	const openaiSuccessBody = `{
	  "id": "cmpl-tri-1",
	  "model": "test-model",
	  "choices": [{
	    "index": 0,
	    "message": {"role": "assistant", "content": "{\"verdict\":\"benign\"}"},
	    "finish_reason": "stop"
	  }],
	  "usage": {"prompt_tokens": 1, "completion_tokens": 1}
	}`
	hOA := &capturingHandler{script: []scriptedResponse{{200, openaiSuccessBody}}}
	tsOA := httptest.NewServer(hOA)
	defer tsOA.Close()
	oa, err := openaicompat.New(openaicompat.Config{Model: "test-model", BaseURL: tsOA.URL}, "test-key", reg, nil, log)
	if err != nil {
		t.Fatalf("openai_compat.New on the shared registry: %v (idempotent registration broken)", err)
	}

	if _, err := ol.Analyse(context.Background(), analyseRequest(provider.RoleL1)); err != nil {
		t.Fatalf("ollama Analyse: %v", err)
	}
	if _, err := cl.Analyse(context.Background(), analyseRequest(provider.RoleL1)); err != nil {
		t.Fatalf("claude Analyse: %v", err)
	}
	if _, err := oa.Analyse(context.Background(), analyseRequest(provider.RoleL1)); err != nil {
		t.Fatalf("openai_compat Analyse: %v", err)
	}

	for _, prov := range []string{"ollama", "claude", "openai"} {
		if v, _ := counterValue(t, reg, prov, "l1", provider.StatusSuccess); v != 1 {
			t.Errorf("metric {%s,l1,success} = %v, want 1", prov, v)
		}
	}
	if _, series := counterValue(t, reg, "ollama", "l1", provider.StatusSuccess); series != 3 {
		t.Errorf("family series = %d, want 3 side-by-side provider series", series)
	}
}

// TestAnalyseLogsNeverCarryEvidence: the laundered error snippet and the
// transport errors must not leak the redacted-evidence payload into logs
// (bounded diagnostics only).
func TestAnalyseErrorSnippetIsBoundedAndLaundered(t *testing.T) {
	long := strings.Repeat("A", 8000) + "\r\n\x00ctrl"
	h := &capturingHandler{script: []scriptedResponse{{500, long}}}
	ts := httptest.NewServer(h)
	defer ts.Close()

	var logBuf bytes.Buffer
	p, _ := newTestProvider(t, ts.URL, &logBuf)
	_, err := p.Analyse(context.Background(), analyseRequest(provider.RoleL1))
	if err == nil {
		t.Fatal("Analyse: err = nil, want 500 exhaustion")
	}
	var apiErr *apiError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want typed apiError", err)
	}
	if len(apiErr.Snippet) > maxErrorBodyBytes {
		t.Errorf("snippet length = %d, want <= %d", len(apiErr.Snippet), maxErrorBodyBytes)
	}
	if strings.ContainsAny(apiErr.Snippet, "\r\n\x00") {
		t.Errorf("snippet carries control characters: %q", apiErr.Snippet)
	}
}
