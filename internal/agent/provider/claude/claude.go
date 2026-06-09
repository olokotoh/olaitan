// Package claude implements the internal/agent/provider Provider interface
// over the Anthropic Messages API using the official anthropic-sdk-go
// (Story 3.2, architecture.md:308 deferral resolved in favour of the SDK).
//
// # Transport semantics owned here
//
//   - Retry: internal/retry owns ALL retries (Strategy{Min:1s, Max:16s,
//     Multiplier:4, Jitter:1, MaxAttempts:3}; base delays 1s and 4s are
//     slept across the 3 attempts, the 16s Max caps any future
//     MaxAttempts tune). The SDK's built-in auto-retry is DISABLED via
//     option.WithMaxRetries(0) so the attempt count and backoff stay
//     single-source-of-truth and the olaitan_llm_calls_total accounting
//     cannot be corrupted by hidden SDK attempts.
//   - Timeouts: the per-role context deadline (30s l1, 30s l2, 60s senior,
//     120s dfir-reserved) is the TOTAL budget for all attempts including
//     backoff, not per-attempt. The worst-case backoff across 3 attempts is
//     1s+4s = 5s, which cannot pathologically starve even the tightest 30s
//     budget. Strategy.Do honours context cancellation mid-call and
//     mid-backoff, so an expired budget aborts cleanly.
//   - Redaction: redact.RedactAndAudit runs BEFORE the outgoing payload is
//     built; the redacted EvidencePackage is the only evidence serialised
//     into the wire request (Story 3.1 AC5 / Story 3.2 AC3).
//   - API key: injected as a constructor argument (read from the projected
//     Kubernetes Secret env var by cmd/olaitan), never logged, never put in
//     an error, never used as a metric or audit label (NFR18).
//   - Metric: olaitan_llm_calls_total{provider="claude", role, status} is
//     registered once at construction and incremented exactly once per
//     Analyse call in a defer with the resolved final outcome. An
//     invalid-role request is rejected before the transport path and is
//     deliberately NOT metricised: minting a series for an unbounded
//     caller-supplied role string would violate the bounded-label rule.
//
// # Opus 4.8 request surface
//
// Thinking is explicitly disabled for analyst calls and the call is
// non-streaming with a bounded MaxTokens (Story 3.2 BI-9): the analyst
// verdict is small, schema-bounded, latency-sensitive, and cost-sensitive.
// No sampling parameter (temperature, top_p, top_k) and no budget_tokens
// is ever sent; all four are removed on Opus 4.8 and return HTTP 400.
// SupportsStreaming() reports false (Phase 3 feature flag).
package claude

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/olokotoh/olaitan/internal/agent/provider"
	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/report/redact"
	"github.com/olokotoh/olaitan/internal/retry"
	"github.com/olokotoh/olaitan/internal/schema"
)

// ErrNoAPIKey is returned by New when the projected Secret env var was
// empty. cmd/olaitan treats it as "skip Claude wiring and run rules-only"
// (clean degradation, Story 3.2 BI-6.3): startup must not crash or block
// when no key is configured.
var ErrNoAPIKey = errors.New("claude: no API key configured")

const (
	providerName = "claude"

	// DefaultModel is the model used when analyst.api.model is empty.
	// Exact model id only; never append a date suffix.
	DefaultModel = string(anthropic.ModelClaudeOpus4_8)

	// DefaultMaxTokens bounds the analyst verdict (schema-bounded JSON, a
	// few KB at most). Well under the non-streaming SDK timeout threshold.
	DefaultMaxTokens int64 = 4096

	// DefaultScoreCap mirrors analyst.score_cap's shipped default: the
	// algebraic trust bound 0.3 * 35 = 10.5 < SUSPICIOUS threshold 20.
	DefaultScoreCap = 35

	// healthTimeout bounds the Health probe. Health issues a real (1
	// output token) Messages call, so callers must gate its frequency to
	// avoid steady-state cost; the kubelet-style once-per-period probe is
	// the intended cadence.
	healthTimeout = 10 * time.Second

	metricName = "olaitan_llm_calls_total"
	metricHelp = "LLM transport calls by provider, analyst role and final outcome " +
		"(success, transient_failure, permanent_failure, timeout). One increment " +
		"per Analyse call; bounded 16-series label set (Story 3.2 BI-4)."
)

// Metric status label values (the bounded outcome enum).
const (
	statusSuccess   = "success"
	statusTransient = "transient_failure"
	statusPermanent = "permanent_failure"
	statusTimeout   = "timeout"
)

// roleTimeouts is the AC2-mandated per-role total retry budget. Story 3.8
// makes these config-routable; for Story 3.2 the constants are the contract.
var roleTimeouts = map[provider.Role]time.Duration{
	provider.RoleL1:     30 * time.Second,
	provider.RoleL2:     30 * time.Second,
	provider.RoleSenior: 60 * time.Second,
	provider.RoleDFIR:   120 * time.Second,
}

// contextWindows maps the supported model ids to their context window for
// MaxContextTokens(). Unknown ids fall back to the conservative 200K so a
// future model pin can never over-budget a prompt.
var contextWindows = map[string]int{
	"claude-opus-4-8":   1_000_000,
	"claude-opus-4-7":   1_000_000,
	"claude-opus-4-6":   1_000_000,
	"claude-sonnet-4-6": 1_000_000,
	"claude-haiku-4-5":  200_000,
}

const fallbackContextWindow = 200_000

// Config carries the construction-time knobs the provider consumes from the
// operator's analyst config block (internal/config AnalystConfig).
type Config struct {
	// Model is analyst.api.model; empty selects DefaultModel.
	Model string
	// BaseURL is analyst.api.endpoint; empty selects the SDK's production
	// default. Integration tests point this at an httptest.Server.
	BaseURL string
	// MaxTokens is the per-response output ceiling; 0 selects
	// DefaultMaxTokens.
	MaxTokens int64
	// ScoreCap is analyst.score_cap; 0 selects DefaultScoreCap. Exposed via
	// ScoreCap(); enforcement is Story 3.11/3.7 scope.
	ScoreCap int
}

// Provider is the Claude implementation of provider.Provider.
type Provider struct {
	client    anthropic.Client
	model     string
	maxTokens int64
	scoreCap  int
	calls     *prometheus.CounterVec
	sink      *redact.RedactionAuditSink
	log       *slog.Logger
	timeouts  map[provider.Role]time.Duration
	strategy  retry.Strategy
}

// Compile-time interface conformance (Story 3.2 Task 2.2).
var _ provider.Provider = (*Provider)(nil)

// New constructs the Claude provider. apiKey is the projected Kubernetes
// Secret value read from the environment by cmd/olaitan; an empty key
// returns ErrNoAPIKey so the caller can skip wiring and stay rules-only.
// The key is held only inside the SDK client and is never logged,
// metricised or embedded in errors (NFR18). sink is the off-by-default
// Story 3.1 redaction audit sink (nil when report.redact.audit_enabled is
// false); redaction itself always runs regardless.
func New(cfg Config, apiKey string, reg *metrics.Registry, sink *redact.RedactionAuditSink, log *slog.Logger) (*Provider, error) {
	if apiKey == "" {
		return nil, ErrNoAPIKey
	}
	if log == nil {
		log = slog.Default()
	}

	model := cfg.Model
	if model == "" {
		model = DefaultModel
	}
	maxTokens := cfg.MaxTokens
	if maxTokens <= 0 {
		maxTokens = DefaultMaxTokens
	}
	scoreCap := cfg.ScoreCap
	if scoreCap <= 0 {
		scoreCap = DefaultScoreCap
	}

	calls, err := reg.RegisterCounterVec(metricName, metricHelp, []string{"provider", "role", "status"})
	if err != nil {
		return nil, fmt.Errorf("claude: register %s: %w", metricName, err)
	}

	// WithoutEnvironmentDefaults keeps construction deterministic: a stray
	// ANTHROPIC_API_KEY or ANTHROPIC_BASE_URL on the host can neither
	// override the injected Secret key nor silently redirect traffic.
	// WithMaxRetries(0) disables the SDK auto-retry (default 2 on 429/5xx)
	// so internal/retry is the single observable source of truth (BI-2.2).
	opts := []option.RequestOption{
		option.WithoutEnvironmentDefaults(),
		option.WithAPIKey(apiKey),
		option.WithMaxRetries(0),
	}
	if cfg.BaseURL != "" {
		opts = append(opts, option.WithBaseURL(cfg.BaseURL))
	}

	p := &Provider{
		client:    anthropic.NewClient(opts...),
		model:     model,
		maxTokens: maxTokens,
		scoreCap:  scoreCap,
		calls:     calls,
		sink:      sink,
		log:       log,
		timeouts:  roleTimeouts,
		strategy: retry.Strategy{
			Min:         1 * time.Second,
			Max:         16 * time.Second,
			Multiplier:  4,
			Jitter:      1,
			MaxAttempts: 3,
		},
	}

	// api_key_set is the BOOLEAN presence flag; the value itself is never
	// logged (NFR18). New is only reachable with a non-empty key, so the
	// flag is always true here; the false branch is logged by cmd/olaitan
	// at the skip site.
	log.Info("claude provider constructed",
		"provider", providerName,
		"model", model,
		"max_tokens", maxTokens,
		"api_key_set", true,
		"audit_sink_wired", sink != nil)
	return p, nil
}

// Name implements provider.Provider.
func (p *Provider) Name() string { return providerName }

// Model implements provider.Provider.
func (p *Provider) Model() string { return p.model }

// MaxContextTokens implements provider.Provider.
func (p *Provider) MaxContextTokens() int {
	if w, ok := contextWindows[p.model]; ok {
		return w
	}
	return fallbackContextWindow
}

// ScoreCap implements provider.Provider.
func (p *Provider) ScoreCap() int { return p.scoreCap }

// SupportsStreaming implements provider.Provider. Streaming is the Phase 3
// feature flag (architecture.md:300); Story 3.2 is non-streaming only.
func (p *Provider) SupportsStreaming() bool { return false }

// Analyse implements provider.Provider. See the package doc for the
// transport semantics; the call sequence is: validate role -> derive the
// per-role total budget -> redact the evidence package -> build the wire
// payload from the REDACTED copy only -> run the SDK call under
// internal/retry -> record exactly one outcome metric.
func (p *Provider) Analyse(ctx context.Context, req provider.Request) (provider.Response, error) {
	// Reject unbounded roles before the metric defer is installed: the
	// role is a metric label and must stay within the 4-value enum.
	if !req.Role.Valid() {
		return provider.Response{}, fmt.Errorf("claude: invalid analyst role %q (allowed: l1, l2, senior, dfir)", req.Role)
	}

	status := statusTransient
	defer func() {
		p.calls.WithLabelValues(providerName, string(req.Role), status).Inc()
	}()

	cctx, cancel := context.WithTimeout(ctx, p.timeouts[req.Role])
	defer cancel()

	// AC3: redaction happens BEFORE the outgoing payload exists. The
	// redacted copy is the only evidence the wire request is built from;
	// the audit enqueue (nil-sink tolerant) never blocks or fails it.
	redacted, _ := redact.RedactAndAudit(req.Package, p.sink)

	params, err := p.buildParams(redacted, req)
	if err != nil {
		status = statusPermanent
		return provider.Response{}, err
	}

	var msg *anthropic.Message
	op := func(opCtx context.Context) error {
		m, callErr := p.client.Messages.New(opCtx, params)
		if callErr != nil {
			if isPermanent(callErr) {
				// Permanent classes (BI-3 table) short-circuit Strategy.Do
				// without sleeping.
				return retry.Permanent(callErr)
			}
			// A transport-level timeout that did NOT consume the role
			// budget stays retryable. Strategy.Do treats raw context
			// sentinel errors as terminal, so while the role context is
			// still alive the sentinel is stripped from the chain on
			// purpose (string concatenation, not %w) to keep the retry
			// row of the BI-3 table honest.
			if opCtx.Err() == nil &&
				(errors.Is(callErr, context.DeadlineExceeded) || errors.Is(callErr, context.Canceled)) {
				return errors.New("claude: transient transport timeout: " + callErr.Error())
			}
			return callErr
		}
		msg = m
		return nil
	}

	err = p.strategy.Do(cctx, op)
	status = p.resolveStatus(err, cctx, ctx)
	if err != nil {
		return provider.Response{}, fmt.Errorf("claude: analyse role=%s: %w", req.Role, err)
	}
	return toResponse(msg), nil
}

// Health implements provider.Provider: a minimal real Messages call (1
// output token) against the configured endpoint, single attempt, bounded
// by healthTimeout. It deliberately bypasses internal/retry (a health
// probe wants the current answer, not a 5s-backoff smoothed one) and does
// NOT touch olaitan_llm_calls_total (AC4 scopes the metric to Analyse
// outcomes). Callers gate the cadence to keep steady-state cost near zero.
func (p *Provider) Health(ctx context.Context) error {
	hctx, cancel := context.WithTimeout(ctx, healthTimeout)
	defer cancel()

	_, err := p.client.Messages.New(hctx, anthropic.MessageNewParams{
		Model:     anthropic.Model(p.model),
		MaxTokens: 1,
		Messages:  []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock("ping"))},
		Thinking:  disabledThinking(),
	})
	if err != nil {
		return fmt.Errorf("claude: health: %w", err)
	}
	return nil
}

// buildParams serialises the REDACTED evidence package plus the
// orchestrator's prompt pair into the Messages API request. The evidence
// and the optional prior assessment travel in tagged blocks inside the
// user turn; the expected output schema travels as an output-contract
// instruction (Stories 3.5-3.7 own prompt composition and verdict
// parsing). No sampling parameter and no budget_tokens is set: all are
// removed on Opus 4.8 and return HTTP 400 (BI-2.4); thinking is the
// explicit disabled union (BI-9).
func (p *Provider) buildParams(redacted schema.EvidencePackage, req provider.Request) (anthropic.MessageNewParams, error) {
	evidence, err := marshalEvidence(redacted)
	if err != nil {
		return anthropic.MessageNewParams{}, err
	}

	var sb strings.Builder
	sb.WriteString(req.Prompt.User)
	sb.WriteString("\n\n<evidence_package>\n")
	sb.Write(evidence)
	sb.WriteString("\n</evidence_package>")
	if req.PriorAssessment != nil {
		prior, perr := json.Marshal(req.PriorAssessment)
		if perr != nil {
			return anthropic.MessageNewParams{}, fmt.Errorf("claude: marshal prior assessment: %w", perr)
		}
		sb.WriteString("\n\n<prior_assessment>\n")
		sb.Write(prior)
		sb.WriteString("\n</prior_assessment>")
	}
	if len(req.Schema) > 0 {
		sb.WriteString("\n\nRespond with a single JSON document conforming to this JSON Schema and nothing else:\n")
		sb.Write(req.Schema)
	}

	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(p.model),
		MaxTokens: p.maxTokens,
		Messages:  []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock(sb.String()))},
		Thinking:  disabledThinking(),
	}
	if req.Prompt.System != "" {
		params.System = []anthropic.TextBlockParam{{Text: req.Prompt.System}}
	}
	return params, nil
}

// resolveStatus maps the final Strategy.Do outcome onto the bounded metric
// status enum (BI-3.2): success when err is nil; timeout when the per-role
// deadline itself fired (parent context still alive, so a process shutdown
// is never misreported as a role timeout); permanent_failure when a BI-3
// permanent class aborted the attempt loop; transient_failure otherwise
// (exhausted retries, transport errors, parent-context cancellation).
func (p *Provider) resolveStatus(err error, callCtx, parentCtx context.Context) string {
	switch {
	case err == nil:
		return statusSuccess
	case errors.Is(err, context.DeadlineExceeded) &&
		callCtx.Err() != nil && parentCtx.Err() == nil:
		return statusTimeout
	case isPermanent(err):
		return statusPermanent
	default:
		return statusTransient
	}
}

// isPermanent classifies err against the BI-3 table using the SDK's typed
// *anthropic.Error (StatusCode + Type()), NEVER substring matching.
// Permanent: the 4xx client-error family minus 408 (request timeout) and
// 429 (rate limit), which covers the table's 400/401/403/404/413 rows and
// extends the same non-retryable intent to any other 4xx. Transient:
// 429, every 5xx (500/529 rows), and any non-API transport error.
func isPermanent(err error) bool {
	var apiErr *anthropic.Error
	if !errors.As(err, &apiErr) {
		return false
	}
	sc := apiErr.StatusCode
	if sc == 408 || sc == 429 {
		return false
	}
	return sc >= 400 && sc < 500
}

// disabledThinking returns the explicit thinking-disabled union (BI-9):
// analyst calls are latency- and cost-bounded structured-verdict calls, so
// adaptive thinking stays off in 3.2. Story 3.7 may promote the Senior
// role to adaptive thinking via a per-role option without changing this
// default.
func disabledThinking() anthropic.ThinkingConfigParamUnion {
	return anthropic.ThinkingConfigParamUnion{
		OfDisabled: &anthropic.ThinkingConfigDisabledParam{},
	}
}

// toResponse flattens the Message into the transport-level Response: the
// concatenated text blocks, the stop reason, the serving model and the
// token usage. Parsing the verdict JSON is the caller's job (BI-1.3).
func toResponse(msg *anthropic.Message) provider.Response {
	var sb strings.Builder
	for _, block := range msg.Content {
		if block.Type == "text" {
			sb.WriteString(block.Text)
		}
	}
	return provider.Response{
		Raw:          sb.String(),
		StopReason:   string(msg.StopReason),
		Model:        string(msg.Model),
		InputTokens:  msg.Usage.InputTokens,
		OutputTokens: msg.Usage.OutputTokens,
	}
}

// marshalEvidence renders the redacted package as the canonical JSON the
// model receives. A marshal failure is a permanent (caller-data) error.
func marshalEvidence(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("claude: marshal redacted evidence: %w", err)
	}
	return b, nil
}
