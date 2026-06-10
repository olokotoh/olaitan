// Package openaicompat implements the internal/agent/provider Provider
// interface over the OpenAI Chat Completions wire shape (Story 3.3,
// architecture.md:309: "a generic OpenAI-compatible HTTPS client").
//
// # Why a hand-rolled stdlib client, not the openai-go SDK
//
// The target is the COMPATIBLE-server ecosystem (OpenAI, Together, Groq,
// LiteLLM, vLLM, and any future endpoint speaking the Chat Completions
// shape). Those servers implement a SUBSET of the official OpenAI
// surface, so this client speaks the lowest common denominator only:
// POST {base}/chat/completions with model/messages/max_tokens/stream
// (never max_completion_tokens, never sampling parameters, never vendor
// extensions), Authorization Bearer auth, and HTTP-status-typed errors.
// Adding the official SDK would buy nothing the common denominator needs
// and would couple the package to OpenAI-proper field evolution.
//
// # Transport semantics
//
// Identical to the Claude provider by construction (Story 3.3 AC2): the
// shared internal/agent/provider helpers own the per-role timeout table,
// the final-outcome status mapping, and the analyst user-turn
// composition; internal/retry owns ALL retries (Strategy{Min:1s, Max:16s,
// Multiplier:4, Jitter:1, MaxAttempts:3}); redact.RedactAndAudit runs
// BEFORE the wire payload is built; the API key is constructor-injected
// and never logged, metricised, or error-embedded (NFR18); and exactly
// one olaitan_llm_calls_total{provider="openai",role,status} outcome is
// recorded per Analyse call on the SHARED family (Story 3.3 BI-3).
//
// # Story 3.2 review lessons applied here by construction
//
// A 200 response with a JSON null body, an empty body, or an empty
// choices array degrades to a retryable transport error (never a nil
// dereference, never a falsified success); Health applies the same
// guards. The provider name is "openai" (the family identity for the
// metric label and the Story 3.8 routing key); the ENDPOINT distinguishes
// the vendor, not the name.
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

// ErrNoAPIKey is returned by New when the injected key is empty; the
// (future, Story 3.8) wiring treats it as "skip and stay rules-only",
// identical to the Claude provider (Story 3.2 BI-6.3).
var ErrNoAPIKey = errors.New("openai: no API key configured")

// ErrNoModel is returned by New when cfg.Model is empty. Unlike the
// Claude provider there is no defensible cross-vendor default model for
// a generic compatible endpoint, so the operator must pin one (Story 3.3
// BI-4.1, the one documented divergence from claude.New).
var ErrNoModel = errors.New("openai: no model configured")

// ErrBadBaseURL is returned by New when a non-empty cfg.BaseURL is not an
// absolute http(s) URL or carries userinfo credentials. Failing fast here
// turns a permanent misconfiguration into a construction error instead of
// an endlessly retried transient, and keeps credentials out of the
// construction log and url.Error strings. The error deliberately does not
// echo the offending value.
var ErrBadBaseURL = errors.New("openai: base URL must be an absolute http(s) URL without userinfo")

const (
	providerName = "openai"

	// DefaultBaseURL is used when cfg.BaseURL is empty. Compatible
	// vendors are selected by pointing BaseURL at their endpoint
	// (e.g. https://api.together.xyz/v1, https://api.groq.com/openai/v1).
	DefaultBaseURL = "https://api.openai.com/v1"

	// DefaultMaxTokens bounds the analyst verdict, mirroring the Claude
	// provider (schema-bounded JSON, a few KB at most).
	DefaultMaxTokens int64 = 4096

	// DefaultScoreCap mirrors analyst.score_cap's shipped default (the
	// algebraic trust bound, Story 3.2). The 0-vs-unset limitation note
	// in docs/runbook.md applies here identically.
	DefaultScoreCap = 35

	// DefaultMaxContextTokens is the conservative window assumed when the
	// operator does not supply one. Compatible vendors are unenumerable,
	// so the window is a config knob, not a model map (Story 3.3 BI-4.1).
	DefaultMaxContextTokens = 128_000

	// healthTimeout bounds the Health probe (one real 1-token call;
	// callers gate the cadence, identical to the Claude provider).
	healthTimeout = 10 * time.Second

	// maxErrorBodyBytes bounds how much of an upstream error body is
	// carried on the typed error (diagnostics only; the body is laundered
	// by sanitizeSnippet before it can reach an error string or log).
	maxErrorBodyBytes = 256

	// errorBodyReadBytes bounds how much of a non-200 body is read off the
	// wire at all. Error bodies are upstream-controlled; only a snippet is
	// kept, so reading the 200-path ceiling would be wasted exposure. Kept
	// larger than maxErrorBodyBytes so the key scrub sees past the cut.
	errorBodyReadBytes = 4 << 10

	// maxResponseBodyBytes bounds how much of a 200 body is read; analyst
	// verdicts are KB-scale, so 10 MiB is generous headroom against a
	// misbehaving upstream streaming garbage.
	maxResponseBodyBytes = 10 << 20
)

// Config carries the construction-time knobs (the Story 3.8 routing
// config maps operator values onto this; until then tests construct it
// directly).
type Config struct {
	// Model is REQUIRED: the Chat Completions model id sent verbatim.
	Model string
	// BaseURL is the compatible endpoint root; empty selects
	// DefaultBaseURL. Trailing slashes are normalised away.
	BaseURL string
	// MaxTokens is the per-response output ceiling; <=0 selects
	// DefaultMaxTokens.
	MaxTokens int64
	// ScoreCap is the per-provider anti-hallucination cap; <=0 selects
	// DefaultScoreCap. Enforcement is Story 3.11/3.7 scope.
	ScoreCap int
	// MaxContextTokens is the model's context window for prompt
	// budgeting; <=0 selects DefaultMaxContextTokens.
	MaxContextTokens int
}

// Provider is the OpenAI-compatible implementation of provider.Provider.
type Provider struct {
	httpc     *http.Client
	baseURL   string
	key       string
	model     string
	maxTokens int64
	scoreCap  int
	maxCtx    int
	calls     *prometheus.CounterVec
	sink      *redact.RedactionAuditSink
	log       *slog.Logger
	timeouts  map[provider.Role]time.Duration
	strategy  retry.Strategy
}

// Compile-time interface conformance.
var _ provider.Provider = (*Provider)(nil)

// New constructs the OpenAI-compatible provider. apiKey is injected by
// the composition root (a projected Kubernetes Secret value, trimmed at
// the wiring layer); an empty key returns ErrNoAPIKey and an empty model
// returns ErrNoModel, both treated as "skip wiring" signals. The key is
// held only for the Authorization header and is never logged, metricised
// or embedded in errors (NFR18). sink is the off-by-default Story 3.1
// redaction audit sink (nil unless report.redact.audit_enabled);
// redaction itself always runs.
func New(cfg Config, apiKey string, reg *metrics.Registry, sink *redact.RedactionAuditSink, log *slog.Logger) (*Provider, error) {
	if apiKey == "" {
		return nil, ErrNoAPIKey
	}
	if cfg.Model == "" {
		return nil, ErrNoModel
	}
	if log == nil {
		log = slog.Default()
	}

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")
	// Round-1 review: validate the endpoint at construction. A relative or
	// scheme-less URL would fail on every attempt as a retried transient,
	// masking a permanent misconfiguration; userinfo would leak into the
	// construction log below and into url.Error strings.
	if u, err := url.Parse(baseURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return nil, ErrBadBaseURL
	}

	maxTokens := cfg.MaxTokens
	if maxTokens <= 0 {
		maxTokens = DefaultMaxTokens
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
		return nil, fmt.Errorf("openai: %w", err)
	}

	p := &Provider{
		// No client-level timeout: the per-role context is the sole,
		// sufficient bound (mirrors the Claude provider, where the SDK
		// adds no timeout of its own). Redirects are never followed: no
		// compatible endpoint legitimately redirects /chat/completions,
		// and following one would convert the POST to a GET (301/302/303)
		// and re-send the bearer token to the redirect target. The 3xx
		// surfaces as a typed *apiError instead (transient class).
		httpc: &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		baseURL:   baseURL,
		key:       apiKey,
		model:     cfg.Model,
		maxTokens: maxTokens,
		scoreCap:  scoreCap,
		maxCtx:    maxCtx,
		calls:     calls,
		sink:      sink,
		log:       log,
		timeouts:  provider.DefaultRoleTimeouts(),
		strategy: retry.Strategy{
			Min:         1 * time.Second,
			Max:         16 * time.Second,
			Multiplier:  4,
			Jitter:      1,
			MaxAttempts: 3,
		},
	}

	// NFR18: the BOOLEAN presence flag only, never the key value.
	// base_url is a documented addition to the Story 3.2 construction-log
	// field set (BI-4 amendment, round-1 review): the endpoint is the one
	// knob that distinguishes compat vendors, and the validation above
	// guarantees it carries no userinfo credentials.
	log.Info("openai-compatible provider constructed",
		"provider", providerName,
		"model", cfg.Model,
		"base_url", baseURL,
		"max_tokens", maxTokens,
		"api_key_set", true,
		"audit_sink_wired", sink != nil)
	return p, nil
}

// Name implements provider.Provider. "openai" is the family identity for
// the metric label and the Story 3.8 routing key; the endpoint
// distinguishes the vendor (Together/Groq/LiteLLM all answer to it).
func (p *Provider) Name() string { return providerName }

// Model implements provider.Provider.
func (p *Provider) Model() string { return p.model }

// MaxContextTokens implements provider.Provider (config knob; compatible
// vendors are unenumerable so there is no model map).
func (p *Provider) MaxContextTokens() int { return p.maxCtx }

// ScoreCap implements provider.Provider.
func (p *Provider) ScoreCap() int { return p.scoreCap }

// SupportsStreaming implements provider.Provider (Phase 3 feature flag).
func (p *Provider) SupportsStreaming() bool { return false }

// chatRequest is the lowest-common-denominator Chat Completions request.
// max_tokens (NOT max_completion_tokens) is the compat-universal field;
// no sampling parameter is ever sent (Story 3.3 BI-2.1).
type chatRequest struct {
	Model     string        `json:"model"`
	Messages  []chatMessage `json:"messages"`
	MaxTokens int64         `json:"max_tokens"`
	Stream    bool          `json:"stream"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatResponse is the lowest-common-denominator success shape. Vendor
// extensions (system_fingerprint, logprobs, tool fields) are ignored.
type chatResponse struct {
	Model   string `json:"model"`
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int64 `json:"prompt_tokens"`
		CompletionTokens int64 `json:"completion_tokens"`
	} `json:"usage"`
}

// apiError is the typed HTTP-status error the BI-2.4 classification
// switches on; NEVER classified by substring. Snippet is a bounded body
// excerpt for diagnostics (response bodies never carry the API key).
type apiError struct {
	StatusCode int
	Snippet    string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("openai: api status %d: %s", e.StatusCode, e.Snippet)
}

// Analyse implements provider.Provider. The control flow is structurally
// identical to the Claude provider (Story 3.3 BI-5): validate role ->
// single deferred outcome metric -> per-role total budget -> redact ->
// build the wire payload from the REDACTED copy only -> retried POST ->
// shared status resolution.
func (p *Provider) Analyse(ctx context.Context, req provider.Request) (provider.Response, error) {
	if !req.Role.Valid() {
		// Rejected before the metric defer: the role is a label and must
		// stay within the bounded enum.
		return provider.Response{}, fmt.Errorf("openai: invalid analyst role %q (allowed: l1, l2, senior, dfir)", req.Role)
	}

	status := provider.StatusTransient
	defer func() {
		p.calls.WithLabelValues(providerName, string(req.Role), status).Inc()
	}()

	cctx, cancel := context.WithTimeout(ctx, p.timeouts[req.Role])
	defer cancel()

	// AC2: redaction BEFORE the outgoing payload exists; the redacted
	// copy is the only evidence the wire body is built from.
	redacted, _ := redact.RedactAndAudit(req.Package, p.sink)

	content, err := provider.BuildAnalystContent(redacted, req)
	if err != nil {
		status = provider.StatusPermanent
		return provider.Response{}, fmt.Errorf("openai: %w", err)
	}

	var msgs []chatMessage
	if req.Prompt.System != "" {
		msgs = append(msgs, chatMessage{Role: "system", Content: req.Prompt.System})
	}
	msgs = append(msgs, chatMessage{Role: "user", Content: content})

	body, err := json.Marshal(chatRequest{
		Model:     p.model,
		Messages:  msgs,
		MaxTokens: p.maxTokens,
		Stream:    false,
	})
	if err != nil {
		status = provider.StatusPermanent
		return provider.Response{}, fmt.Errorf("openai: marshal request: %w", err)
	}

	var result provider.Response
	op := func(opCtx context.Context) error {
		resp, callErr := p.post(opCtx, "/chat/completions", body)
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
				return errors.New("openai: transient transport timeout: " + callErr.Error())
			}
			return callErr
		}
		result = resp
		return nil
	}

	err = p.strategy.Do(cctx, op)
	status = provider.ResolveStatus(err, isPermanent, cctx, ctx)
	if err != nil {
		return provider.Response{}, fmt.Errorf("openai: analyse role=%s: %w", req.Role, err)
	}
	return result, nil
}

// Health implements provider.Provider: a minimal 1-token chat call,
// single attempt, bounded by healthTimeout, no retry (a probe wants the
// current answer) and no olaitan_llm_calls_total increment (the metric is
// Analyse-scoped). The nil/empty guards in post apply identically.
func (p *Provider) Health(ctx context.Context) error {
	hctx, cancel := context.WithTimeout(ctx, healthTimeout)
	defer cancel()

	body, err := json.Marshal(chatRequest{
		Model:     p.model,
		Messages:  []chatMessage{{Role: "user", Content: "ping"}},
		MaxTokens: 1,
		Stream:    false,
	})
	if err != nil {
		return fmt.Errorf("openai: health: marshal: %w", err)
	}
	if _, err := p.post(hctx, "/chat/completions", body); err != nil {
		return fmt.Errorf("openai: health: %w", err)
	}
	return nil
}

// post executes one Chat Completions round trip and decodes the
// lowest-common-denominator response. Non-2xx statuses become the typed
// *apiError; a 200 with a null/empty body or an empty choices array is a
// plain (retryable) error per the Story 3.2 nil-message lesson.
func (p *Provider) post(ctx context.Context, path string, body []byte) (provider.Response, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return provider.Response{}, fmt.Errorf("openai: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	// The Authorization header is the API key's ONE legitimate location
	// (NFR18); compatible servers reject unknown headers inconsistently,
	// so nothing else is set.
	httpReq.Header.Set("Authorization", "Bearer "+p.key)

	httpResp, err := p.httpc.Do(httpReq)
	if err != nil {
		// Transport error (dial, TLS, ctx). Never carries the key: Go
		// redacts header values from URL-level errors.
		return provider.Response{}, fmt.Errorf("openai: transport: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	if httpResp.StatusCode != http.StatusOK {
		// Error bodies are upstream-controlled: read only a bounded
		// prefix (round-1 review; the 200-path ceiling would be wasted
		// exposure) and tolerate a mid-read failure, since the status
		// code alone carries the classification.
		raw, _ := io.ReadAll(io.LimitReader(httpResp.Body, errorBodyReadBytes))
		return provider.Response{}, &apiError{StatusCode: httpResp.StatusCode, Snippet: p.sanitizeSnippet(raw)}
	}

	raw, err := io.ReadAll(io.LimitReader(httpResp.Body, maxResponseBodyBytes))
	if err != nil {
		return provider.Response{}, fmt.Errorf("openai: read response: %w", err)
	}

	var decoded chatResponse
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return provider.Response{}, fmt.Errorf("openai: decode response: %w", err)
	}
	if len(decoded.Choices) == 0 {
		// A JSON `null` body decodes to the zero chatResponse with no
		// error; an upstream proxy returning it must degrade to a
		// retryable transport error, never a falsified success (Story
		// 3.2 round-1 lesson, binding per Story 3.3 BI-4).
		return provider.Response{}, errors.New("openai: empty choices in 200 response")
	}

	return provider.Response{
		Raw:          decoded.Choices[0].Message.Content,
		StopReason:   decoded.Choices[0].FinishReason,
		Model:        decoded.Model,
		InputTokens:  decoded.Usage.PromptTokens,
		OutputTokens: decoded.Usage.CompletionTokens,
	}, nil
}

// sanitizeSnippet launders an upstream error body before it can reach an
// error string or a log line (round-1 review). Response bodies SHOULD
// never carry the API key, but OpenAI itself echoes key material in 401
// bodies and arbitrary compatible proxies may echo the Authorization
// value, so the key is scrubbed defensively; control characters are
// flattened (log-injection); and the length cut lands on a rune boundary.
func (p *Provider) sanitizeSnippet(raw []byte) string {
	s := strings.ReplaceAll(string(raw), p.key, "<redacted>")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	if len(s) > maxErrorBodyBytes {
		s = s[:maxErrorBodyBytes]
	}
	return strings.ToValidUTF8(s, "")
}

// isPermanent classifies err against the shared BI-2.4 table using the
// typed *apiError status code, NEVER substring matching. Permanent: the
// 4xx client-error family minus 408 (request timeout) and 429 (rate
// limit). Transient: 429, every 5xx, and any non-API transport error.
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
