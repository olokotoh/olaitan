// Package ollama implements the internal/agent/provider Provider
// interface over the NATIVE Ollama HTTP API (Story 3.4,
// architecture.md:381: "Ollama HTTP API ({ollama-endpoint}/api/chat)"),
// the third and final concrete provider and the FR48 air-gapped path.
//
// # Why the native /api/chat, not Ollama's OpenAI-compat shim
//
// The architecture binds the native endpoint verbatim. The native shape
// carries Ollama's own fields (done_reason, prompt_eval_count,
// eval_count) and avoids tracking the compat shim's drift; routing
// through the Story 3.3 openai_compat provider would also make the
// dedicated package the architecture file tree mandates pointless.
//
// # Why there is no API key anywhere in this package
//
// architecture.md:263: "Ollama treated as an in-cluster service;
// protected by NetworkPolicy from external reach; no API-key auth
// needed." The constructor takes no key, no Authorization header is
// ever set, and the NFR18 construction log carries no api_key_set
// field (a vacuous false would imply a missing credential). This is
// the one documented divergence from the claude/openai_compat
// constructor shape; the NetworkPolicy rendered by the chart is the
// auth boundary.
//
// # Transport semantics
//
// Identical to the Claude and OpenAI-compatible providers by
// construction (Story 3.4 BI-4): the shared internal/agent/provider
// helpers own the per-role timeout table, the final-outcome status
// mapping, and the analyst user-turn composition; internal/retry owns
// ALL retries; redact.RedactAndAudit runs BEFORE the wire payload is
// built; and exactly one olaitan_llm_calls_total{provider="ollama",
// role,status} outcome is recorded per Analyse call on the SHARED
// family (48 bounded series across the three providers).
//
// # Ollama-specific honesty notes (Story 3.4 BI-2/BI-3)
//
// stream:false is EXPLICIT on every request: the server defaults to
// streaming for /api/chat, and an NDJSON stream fails a single-object
// decode. The provider never sends options.num_ctx: the EFFECTIVE
// context window is the server-side num_ctx (small by default
// regardless of model capability), so MaxContextTokens defaults to a
// conservative 4096 and the operator who raises num_ctx server-side
// raises the knob to match (docs/runbook.md air-gapped section).
// Health is one real 1-token chat call; a cold model load exceeds the
// 10s bound, so Health honestly reports unhealthy until the model is
// warm.
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
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/olokotoh/olaitan/internal/agent/provider"
	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/report/redact"
	"github.com/olokotoh/olaitan/internal/retry"
)

// ErrNoModel is returned by New when cfg.Model is empty. There is no
// defensible default model for an air-gapped deployment: the operator
// must pin the model they actually provisioned, or every call fails at
// runtime as a confusing permanent 404 (Story 3.4 BI-3.2; mirrors the
// openai_compat reasoning).
var ErrNoModel = errors.New("ollama: no model configured")

// ErrBadEndpoint is returned by New when a non-empty cfg.Endpoint is not
// an absolute http(s) URL or carries userinfo credentials. Failing fast
// turns a permanent misconfiguration into a construction error instead
// of an endlessly retried transient, and keeps credentials out of the
// construction log and url.Error strings. The error deliberately does
// not echo the offending value (Story 3.3 round-1 lesson, binding here).
var ErrBadEndpoint = errors.New("ollama: endpoint must be an absolute http(s) URL without userinfo")

const (
	providerName = "ollama"

	// DefaultEndpoint is used when cfg.Endpoint is empty: the in-cluster
	// Service URL the epic mandates (Story 3.4 AC1). Plain http is the
	// expected in-cluster scheme; the NetworkPolicy is the boundary.
	DefaultEndpoint = "http://ollama.olaitan.svc.cluster.local:11434"

	// DefaultNumPredict bounds the analyst verdict via options.num_predict
	// (the native name for the output ceiling; never max_tokens). Parity
	// with the claude/openai_compat 4096 default.
	DefaultNumPredict int64 = 4096

	// DefaultScoreCap is the Ollama-tier trust cap (Story 3.4 AC2 / PRD
	// per-provider ladder 35 Claude / 30 OpenAI-class / 25 local Ollama).
	// Enforcement of the cap on assessments is Story 3.7 scope; this
	// package ships the default and the accessor only.
	DefaultScoreCap = 25

	// DefaultMaxContextTokens is deliberately the server-side num_ctx
	// scale, NOT the model's theoretical window (Story 3.4 BI-3.4
	// honesty binding): Ollama clamps prompts to num_ctx (small by
	// default) regardless of what the model could address, and this
	// provider never sends options.num_ctx. Operators who raise num_ctx
	// server-side raise this knob to match.
	DefaultMaxContextTokens = 4096

	// healthTimeout bounds the Health probe (one real 1-token chat call;
	// callers gate the cadence). A cold model load exceeds this on
	// purpose: unhealthy-until-warm is signal, not noise (BI-3.5).
	healthTimeout = 10 * time.Second

	// maxErrorBodyBytes bounds how much of an upstream error body is
	// carried on the typed error (diagnostics only; the body is laundered
	// by sanitizeSnippet before it can reach an error string or log).
	maxErrorBodyBytes = 256

	// errorBodyReadBytes bounds how much of a non-200 body is read off
	// the wire at all (Story 3.3 round-1 lesson, binding here).
	errorBodyReadBytes = 4 << 10

	// maxResponseBodyBytes bounds how much of a 200 body is read; analyst
	// verdicts are KB-scale, so 10 MiB is generous headroom against a
	// misbehaving upstream streaming garbage.
	maxResponseBodyBytes = 10 << 20
)

// Config carries the construction-time knobs. cmd/olaitan maps
// analyst.local.{endpoint,model} plus analyst.score_cap onto this
// (Story 3.4 BI-6); tests construct it directly.
type Config struct {
	// Model is REQUIRED: the Ollama model id sent verbatim (the model the
	// operator actually pulled/baked, e.g. llama3.1:70b).
	Model string
	// Endpoint is the Ollama service root; empty selects DefaultEndpoint.
	// Trailing slashes are normalised away.
	Endpoint string
	// NumPredict is the per-response output ceiling (options.num_predict);
	// <=0 selects DefaultNumPredict.
	NumPredict int64
	// ScoreCap is the per-provider anti-hallucination cap; <=0 selects
	// DefaultScoreCap (25). Enforcement is Story 3.7 scope.
	ScoreCap int
	// MaxContextTokens is the prompt-budgeting window; <=0 selects
	// DefaultMaxContextTokens. Pair it with the server-side num_ctx
	// (BI-3.4); the provider never sends options.num_ctx itself.
	MaxContextTokens int
}

// Provider is the Ollama implementation of provider.Provider.
type Provider struct {
	httpc      *http.Client
	endpoint   string
	model      string
	numPredict int64
	scoreCap   int
	maxCtx     int
	calls      *prometheus.CounterVec
	sink       *redact.RedactionAuditSink
	log        *slog.Logger
	timeouts   map[provider.Role]time.Duration
	strategy   retry.Strategy
}

// Compile-time interface conformance.
var _ provider.Provider = (*Provider)(nil)

// New constructs the Ollama provider. There is NO apiKey parameter: the
// in-cluster Ollama service uses no credential and the NetworkPolicy is
// the auth boundary (architecture.md:263; the documented divergence from
// the claude/openai_compat constructor shape). An empty model returns
// ErrNoModel ("skip wiring" signal at the cmd layer); a malformed
// endpoint returns ErrBadEndpoint (fail-fast, never echoed). sink is the
// off-by-default Story 3.1 redaction audit sink; redaction itself always
// runs.
func New(cfg Config, reg *metrics.Registry, sink *redact.RedactionAuditSink, log *slog.Logger) (*Provider, error) {
	if cfg.Model == "" {
		return nil, ErrNoModel
	}
	if log == nil {
		log = slog.Default()
	}

	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	endpoint = strings.TrimRight(endpoint, "/")
	if u, err := url.Parse(endpoint); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return nil, ErrBadEndpoint
	}

	numPredict := cfg.NumPredict
	if numPredict <= 0 {
		numPredict = DefaultNumPredict
	}
	scoreCap := cfg.ScoreCap
	if scoreCap <= 0 {
		scoreCap = DefaultScoreCap
	}
	maxCtx := cfg.MaxContextTokens
	if maxCtx <= 0 {
		maxCtx = DefaultMaxContextTokens
	}

	calls, err := provider.RegisterCallsMetric(reg)
	if err != nil {
		return nil, fmt.Errorf("ollama: %w", err)
	}

	p := &Provider{
		// No client-level timeout: the per-role context is the sole,
		// sufficient bound (claude/openai_compat parity). Redirects are
		// never followed: nothing in-cluster legitimately redirects
		// /api/chat, and a followed 301/302/303 would convert the POST
		// to a GET; the 3xx surfaces as a typed *apiError instead
		// (Story 3.3 round-1 lesson, binding here).
		httpc: &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		endpoint:   endpoint,
		model:      cfg.Model,
		numPredict: numPredict,
		scoreCap:   scoreCap,
		maxCtx:     maxCtx,
		calls:      calls,
		sink:       sink,
		log:        log,
		timeouts:   provider.DefaultRoleTimeouts(),
		strategy: retry.Strategy{
			Min:         1 * time.Second,
			Max:         16 * time.Second,
			Multiplier:  4,
			Jitter:      1,
			MaxAttempts: 3,
		},
	}

	// NFR18 construction log. There is deliberately NO api_key_set field:
	// no credential exists for this provider (BI-3.1, documented
	// divergence). endpoint is validated userinfo-free above.
	log.Info("ollama provider constructed",
		"provider", providerName,
		"model", cfg.Model,
		"endpoint", endpoint,
		"num_predict", numPredict,
		"audit_sink_wired", sink != nil)
	return p, nil
}

// Name implements provider.Provider. "ollama" is the family identity for
// the metric label and the Story 3.8 routing key.
func (p *Provider) Name() string { return providerName }

// Model implements provider.Provider.
func (p *Provider) Model() string { return p.model }

// MaxContextTokens implements provider.Provider (config knob paired with
// the server-side num_ctx; see the package doc honesty note).
func (p *Provider) MaxContextTokens() int { return p.maxCtx }

// ScoreCap implements provider.Provider (Ollama-tier default 25; Story
// 3.7 owns enforcement).
func (p *Provider) ScoreCap() int { return p.scoreCap }

// SupportsStreaming implements provider.Provider (Phase 3 feature flag).
func (p *Provider) SupportsStreaming() bool { return false }

// chatRequest is the native /api/chat request. stream:false is EXPLICIT
// and load-bearing (the server defaults to streaming); options carries
// num_predict ONLY (no sampling, no num_ctx, no keep_alive - Story 3.4
// BI-2.1).
type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
	Stream   bool          `json:"stream"`
	Options  chatOptions   `json:"options"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatOptions struct {
	NumPredict int64 `json:"num_predict"`
}

// chatResponse is the native /api/chat single-object success shape.
// Message is a POINTER so a JSON null body, an empty body, or a missing
// message object decodes to nil and degrades to a retryable transport
// error (the Story 3.2 nil-message lesson) instead of masquerading as an
// empty-but-successful verdict. Duration fields and extensions
// (thinking, tool_calls, logprobs) are deliberately not modelled.
type chatResponse struct {
	Model   string `json:"model"`
	Message *struct {
		Content string `json:"content"`
	} `json:"message"`
	Done            bool   `json:"done"`
	DoneReason      string `json:"done_reason"`
	PromptEvalCount int64  `json:"prompt_eval_count"`
	EvalCount       int64  `json:"eval_count"`
}

// apiError is the typed HTTP-status error the BI-2.4 classification
// switches on; NEVER classified by substring. Snippet is a bounded,
// laundered body excerpt for diagnostics.
type apiError struct {
	StatusCode int
	Snippet    string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("ollama: api status %d: %s", e.StatusCode, e.Snippet)
}

// Analyse implements provider.Provider. The control flow is structurally
// identical to the Claude and OpenAI-compatible providers (Story 3.4
// BI-4): validate role -> single deferred outcome metric -> per-role
// total budget -> redact -> build the wire payload from the REDACTED
// copy only -> retried POST -> shared status resolution.
func (p *Provider) Analyse(ctx context.Context, req provider.Request) (provider.Response, error) {
	if !req.Role.Valid() {
		// Rejected before the metric defer: the role is a label and must
		// stay within the bounded enum.
		return provider.Response{}, fmt.Errorf("ollama: invalid analyst role %q (allowed: l1, l2, senior, dfir)", req.Role)
	}

	status := provider.StatusTransient
	defer func() {
		p.calls.WithLabelValues(providerName, string(req.Role), status).Inc()
	}()

	cctx, cancel := context.WithTimeout(ctx, p.timeouts[req.Role])
	defer cancel()

	// AC-mandated ordering: redaction BEFORE the outgoing payload exists;
	// the redacted copy is the only evidence the wire body is built from.
	redacted, _ := redact.RedactAndAudit(req.Package, p.sink)

	content, err := provider.BuildAnalystContent(redacted, req)
	if err != nil {
		status = provider.StatusPermanent
		return provider.Response{}, fmt.Errorf("ollama: %w", err)
	}

	var msgs []chatMessage
	if req.Prompt.System != "" {
		msgs = append(msgs, chatMessage{Role: "system", Content: req.Prompt.System})
	}
	msgs = append(msgs, chatMessage{Role: "user", Content: content})

	body, err := json.Marshal(chatRequest{
		Model:    p.model,
		Messages: msgs,
		Stream:   false,
		Options:  chatOptions{NumPredict: p.numPredict},
	})
	if err != nil {
		status = provider.StatusPermanent
		return provider.Response{}, fmt.Errorf("ollama: marshal request: %w", err)
	}

	var result provider.Response
	op := func(opCtx context.Context) error {
		resp, callErr := p.post(opCtx, body)
		if callErr != nil {
			if isPermanent(callErr) {
				return retry.Permanent(callErr)
			}
			// A transport-level timeout that did NOT consume the role
			// budget stays retryable; Strategy.Do treats raw context
			// sentinels as terminal, so the sentinel is stripped from
			// the chain on purpose while the role context is alive
			// (Story 3.2 pattern; string concat, not %w).
			if opCtx.Err() == nil &&
				(errors.Is(callErr, context.DeadlineExceeded) || errors.Is(callErr, context.Canceled)) {
				return errors.New("ollama: transient transport timeout: " + callErr.Error())
			}
			return callErr
		}
		result = resp
		return nil
	}

	err = p.strategy.Do(cctx, op)
	status = provider.ResolveStatus(err, isPermanent, cctx, ctx)
	if err != nil {
		return provider.Response{}, fmt.Errorf("ollama: analyse role=%s: %w", req.Role, err)
	}
	return result, nil
}

// Health implements provider.Provider: a minimal 1-token chat call,
// single attempt, bounded by healthTimeout, no retry (a probe wants the
// current answer) and no olaitan_llm_calls_total increment (the metric
// is Analyse-scoped). The nil/missing-message guards in post apply
// identically. A cold model load exceeds the bound by design: unhealthy
// until the model is warm is the honest answer (BI-3.5; runbook
// documents warm-up guidance).
func (p *Provider) Health(ctx context.Context) error {
	hctx, cancel := context.WithTimeout(ctx, healthTimeout)
	defer cancel()

	body, err := json.Marshal(chatRequest{
		Model:    p.model,
		Messages: []chatMessage{{Role: "user", Content: "ping"}},
		Stream:   false,
		Options:  chatOptions{NumPredict: 1},
	})
	if err != nil {
		return fmt.Errorf("ollama: health: marshal: %w", err)
	}
	if _, err := p.post(hctx, body); err != nil {
		return fmt.Errorf("ollama: health: %w", err)
	}
	return nil
}

// post executes one native /api/chat round trip and decodes the
// single-object response. Non-200 statuses become the typed *apiError;
// a 200 with a null/empty body or a missing message object is a plain
// (retryable) error per the Story 3.2 nil-message lesson. An NDJSON
// stream from a server that ignored stream:false fails the
// single-object decode and is likewise retryable.
func (p *Provider) post(ctx context.Context, body []byte) (provider.Response, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return provider.Response{}, fmt.Errorf("ollama: build request: %w", err)
	}
	// Content-Type is the ONLY header: no credential exists for this
	// provider (BI-3), so there is no Authorization header to set.
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := p.httpc.Do(httpReq)
	if err != nil {
		return provider.Response{}, fmt.Errorf("ollama: transport: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	if httpResp.StatusCode != http.StatusOK {
		// Error bodies are upstream-controlled: read only a bounded
		// prefix, and drop the snippet entirely on a mid-read failure
		// (the status code alone carries the classification - Story 3.3
		// rounds 1+2, binding here).
		raw, err := io.ReadAll(io.LimitReader(httpResp.Body, errorBodyReadBytes))
		if err != nil {
			raw = nil
		}
		return provider.Response{}, &apiError{StatusCode: httpResp.StatusCode, Snippet: sanitizeSnippet(raw)}
	}

	raw, err := io.ReadAll(io.LimitReader(httpResp.Body, maxResponseBodyBytes))
	if err != nil {
		return provider.Response{}, fmt.Errorf("ollama: read response: %w", err)
	}

	var decoded chatResponse
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return provider.Response{}, fmt.Errorf("ollama: decode response: %w", err)
	}
	if decoded.Message == nil {
		// A JSON null body or a response without a message object
		// decodes with no error; it must degrade to a retryable
		// transport error, never a falsified success (Story 3.2
		// round-1 lesson, binding per Story 3.4 BI-2.2).
		return provider.Response{}, errors.New("ollama: missing message in 200 response")
	}

	return provider.Response{
		Raw:          decoded.Message.Content,
		StopReason:   decoded.DoneReason,
		Model:        decoded.Model,
		InputTokens:  decoded.PromptEvalCount,
		OutputTokens: decoded.EvalCount,
	}, nil
}

// sanitizeSnippet launders an upstream error body before it can reach an
// error string or a log line: control characters are flattened
// (log-injection) and the length cut lands on a rune boundary. There is
// no API key to scrub for this provider (BI-3); the laundering itself is
// the Story 3.3 round-1 lesson and stays.
func sanitizeSnippet(raw []byte) string {
	s := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, string(raw))
	if len(s) > maxErrorBodyBytes {
		s = s[:maxErrorBodyBytes]
	}
	return strings.ToValidUTF8(s, "")
}

// isPermanent classifies err against the shared BI-2.4 table using the
// typed *apiError status code, NEVER substring matching. Permanent: the
// 4xx client-error family minus 408 (request timeout) and 429 (rate
// limit) - which makes Ollama's 404 for an un-provisioned model
// permanent, correctly (runbook: 404 means the model was never pulled).
// Transient: 429, every 5xx, and any non-API transport error.
func isPermanent(err error) bool {
	var apiErr *apiError
	if !errors.As(err, &apiErr) {
		return false
	}
	sc := apiErr.StatusCode
	if sc == 408 || sc == 429 {
		return false
	}
	return sc >= 400 && sc < 500
}
