// Package analyst hosts the Layer-3 investigation-chain sub-agents
// (Stories 3.5-3.7): the L1 first-pass triage analyst (this file), the
// L2 verifier (Story 3.6), and the Senior orchestrator (Story 3.7). It
// is the internal/decision-side consumer of the shared LLM transport at
// internal/agent/provider; this directory is the one the Story 3.2
// provider package doc reserved for the L1/L2/Senior agent code (the
// architecture tree's internal/decision/agent/ spelling is recorded as a
// variance in the Story 3.5 traceability provenance).
//
// Division of labour (Story 3.5 BI-2/BI-10): the provider owns
// redaction, transport retries, the per-role timeout budget (30s for
// L1) and the olaitan_llm_calls_total transport metric. The runners in
// this package own prompt composition, response validation against the
// role schema, the decision-level outcome metric
// (olaitan_decision_llm_calls_total) and the audit capture record.
// Chain triggering and per-role provider routing are Story 3.8; the
// three-strike retry policy on schema violations is Story 3.10; NATS
// checkpointing is Story 3.9; prompt ConfigMap loading and hot reload
// are Story 3.13; audit publishing is Story 3.14.
package analyst

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/olokotoh/olaitan/internal/agent/provider"
	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/schema"
)

// l1SchemaJSON is the embedded runtime copy of the authoritative
// L1Hypothesis JSON schema. It MUST stay byte-identical to
// docs/schemas/l1_hypothesis.json (guarded by
// TestEmbeddedSchemaMatchesDocs); go:embed cannot reference the docs
// tree across package boundaries, hence the copy (Story 3.5 BI-5).
//
//go:embed l1_hypothesis_schema.json
var l1SchemaJSON []byte

// Typed sentinels (Story 3.5 BI-6) consumed by the Story 3.10 retry
// policy. Errors returned by Run wrap exactly one of these; callers
// branch with errors.Is.
var (
	// ErrSchemaViolation marks a response that failed the L1Hypothesis
	// contract: empty body, undecodable JSON, JSON-schema validation
	// failure, or a cited event_id absent from the input package (AC3).
	ErrSchemaViolation = errors.New("analyst: response violates the L1Hypothesis contract")
	// ErrProviderUnavailable marks a provider.Analyse failure of any
	// kind, including the per-role timeout (the transport metric
	// distinguishes timeouts; the decision level does not), a reply
	// truncated by the output-token ceiling (stop reason max_tokens or
	// length: a transport/configuration condition, not model
	// misbehaviour), and caller-context cancellation (mirroring the
	// transport's transient classification; discriminate with
	// errors.Is(err, context.Canceled) through the wrap when needed).
	ErrProviderUnavailable = errors.New("analyst: provider unavailable")
	// ErrNoCitableEvents marks an EvidencePackage whose citable id set
	// is empty (no Events and no trigger event id): the schema demands
	// at least one citation from that set, so a conformant reply is
	// impossible and no provider call is spent. This is a caller-input
	// precondition failure, not a model or provider outcome: Run
	// returns BEFORE the provider call and records NO decision metric
	// (the olaitan_decision_llm_calls_total family counts
	// provider-reaching runs; round-1 review amendment to BI-8).
	ErrNoCitableEvents = errors.New("analyst: evidence package has no citable event ids")
)

// Decision-outcome status label values for
// olaitan_decision_llm_calls_total (Story 3.5 BI-8; the architecture B7
// llm_status enum, architecture.md:318). The label set is bounded:
// runners must never mint a value outside these four constants.
const (
	// StatusSuccess: the response parsed, validated and passed the
	// referential checks.
	StatusSuccess = "success"
	// StatusUnavailable: provider.Analyse returned an error (transport
	// failure, exhausted retries, the per-role timeout, or
	// caller-context cancellation), or the reply was truncated by the
	// output-token ceiling before it could carry a complete verdict.
	StatusUnavailable = "unavailable"
	// StatusSchemaViolation: the response failed the L1Hypothesis
	// contract (see ErrSchemaViolation).
	StatusSchemaViolation = "schema_violation"
	// StatusSuccessLowConfidence is RESERVED for the Story 3.7 Senior
	// (a validated assessment whose confidence falls below the acting
	// threshold). Defined here so the bounded enum is complete from day
	// one; no 3.5 path emits it.
	StatusSuccessLowConfidence = "success_low_confidence"
)

// l1UserInstruction is the fixed user-turn task statement (Story 3.5
// BI-3). The per-provider SYSTEM prompts are the Story 3.13
// ConfigMap-mounted manifests; the user turn is code-owned and stable.
// provider.BuildAnalystContent appends the redacted evidence package and
// the output-contract instruction after this text.
const l1UserInstruction = "Triage the following Kubernetes runtime evidence package as the L1 analyst. " +
	"State your single most plausible hypothesis about the observed activity, cite the event ids " +
	"from the package that support it, list any follow-up probes you would request, and give an " +
	"integer confidence between 0 and 100."

// PromptSpec is the L1 prompt seam (Story 3.5 BI-3): the caller supplies
// the system prompt text and its version identifier. Story 3.13 owns
// loading both from the ConfigMap (and hot reload, and the content-hash
// audit); until then callers pass whatever they loaded themselves.
type PromptSpec struct {
	// System is the L1 system prompt, passed to the provider VERBATIM.
	// Per the provider REDACTION CONTRACT it must never contain raw
	// event excerpts; evidence travels exclusively on Request.Package.
	System string
	// Version identifies the prompt revision for the audit record
	// (AC4); Story 3.13 supplies the ConfigMap revision here.
	Version string
}

// L1Result is the audit capture record of one L1 invocation (Story 3.5
// BI-9, AC4): everything Story 3.14 needs to publish to
// AUDIT.assessments. It is populated as far as known on failure paths
// too (status, latency, provider), so the audit trail covers failures;
// the error return of Run stays authoritative for control flow.
// L1Result is in-memory only; persistence (and any pre-persistence
// redaction) is Story 3.14 scope.
type L1Result struct {
	// Hypothesis is the validated, schema_version-stamped verdict (zero
	// value when Status is not success).
	Hypothesis schema.L1Hypothesis
	// PromptVersion echoes PromptSpec.Version (AC4 "prompt version").
	PromptVersion string
	// System and User are the full input prompt pair as sent (clean by
	// the REDACTION CONTRACT: evidence never enters prompt text).
	System string
	User   string
	// Provider is the provider's metric label (e.g. "claude").
	Provider string
	// Model is the model id that served the call: Response.Model when
	// the provider echoed one. On failure paths (or when the provider
	// does not echo a model) it carries the pinned constructor model,
	// so audit consumers should read it together with Status.
	Model string
	// RawOutput is the unparsed model reply (empty when the provider
	// call itself failed).
	RawOutput string
	// Latency is the wall-clock duration of the provider call.
	Latency time.Duration
	// Status is the BI-8 decision-outcome enum value recorded on the
	// metric for this invocation.
	Status string
}

// L1 is the first-pass triage analyst runner (FR20/FR21). Construct
// with NewL1; issue calls with Run.
type L1 struct {
	provider provider.Provider
	spec     PromptSpec
	calls    *prometheus.CounterVec
	log      *slog.Logger
	schema   *jsonschema.Schema
}

// NewL1 builds an L1 runner on top of an already-constructed provider
// (per-role provider selection is Story 3.8). It registers (or re-uses)
// the decision-outcome metric family on reg.
func NewL1(p provider.Provider, spec PromptSpec, reg *metrics.Registry, log *slog.Logger) (*L1, error) {
	if p == nil {
		return nil, errors.New("analyst: nil provider")
	}
	if log == nil {
		log = slog.Default()
	}
	sch, err := compiledL1Schema()
	if err != nil {
		return nil, err
	}
	calls, err := RegisterDecisionCallsMetric(reg)
	if err != nil {
		return nil, err
	}
	return &L1{provider: p, spec: spec, calls: calls, log: log, schema: sch}, nil
}

// schemaCompiler compiles one embedded role schema exactly once per
// process (Story 3.6 BI-4 generalization of the Story 3.5 L1-only
// helper); a compile failure is a build-artifact corruption and fails
// every runner constructor with the same error.
type schemaCompiler struct {
	name string
	doc  []byte
	once sync.Once
	sch  *jsonschema.Schema
	err  error
}

func (c *schemaCompiler) compiled() (*jsonschema.Schema, error) {
	c.once.Do(func() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(c.doc))
		if err != nil {
			c.err = fmt.Errorf("analyst: unmarshal embedded %s: %w", c.name, err)
			return
		}
		comp := jsonschema.NewCompiler()
		if err := comp.AddResource(c.name, doc); err != nil {
			c.err = fmt.Errorf("analyst: add %s resource: %w", c.name, err)
			return
		}
		sch, err := comp.Compile(c.name)
		if err != nil {
			c.err = fmt.Errorf("analyst: compile %s: %w", c.name, err)
			return
		}
		c.sch = sch
	})
	return c.sch, c.err
}

var l1Schema = &schemaCompiler{name: "l1_hypothesis_schema.json", doc: l1SchemaJSON}

// compiledL1Schema preserves the Story 3.5 accessor.
func compiledL1Schema() (*jsonschema.Schema, error) { return l1Schema.compiled() }

// Run issues one L1 analyst call for pkg and returns the audit record
// plus the control-flow error. Exactly one outcome is recorded on
// olaitan_decision_llm_calls_total per call (AC4). The 30-second L1
// budget is enforced by the provider via Request.Role (Story 3.5
// BI-10); Run makes exactly ONE provider attempt (the Story 3.10
// three-strike policy sits above this, transport-level retries below).
func (a *L1) Run(ctx context.Context, pkg schema.EvidencePackage) (L1Result, error) {
	res := L1Result{
		PromptVersion: a.spec.Version,
		System:        a.spec.System,
		User:          l1UserInstruction,
		Provider:      a.provider.Name(),
		Model:         a.provider.Model(),
	}

	// Precondition (round-1 review): an empty citable set makes a
	// conformant reply impossible (the schema demands >= 1 citation
	// from it), so fail before spending the provider call. No decision
	// metric is recorded: the family counts provider-reaching runs.
	known := citableEventIDs(pkg)
	if len(known) == 0 {
		return res, fmt.Errorf("%w: package %s carries no events and no trigger event id, so a schema-conformant reply is impossible", ErrNoCitableEvents, pkg.PackageID)
	}

	req := provider.Request{
		Role:    provider.RoleL1,
		Package: pkg,
		Prompt:  provider.Prompt{System: a.spec.System, User: l1UserInstruction},
		// Defensive copy: the embedded backing array is shared with the
		// compiled validator; a misbehaving Provider mutating req.Schema
		// in place must not corrupt every later Run.
		Schema: provider.JSONSchema(bytes.Clone(l1SchemaJSON)),
	}

	start := time.Now()
	resp, err := a.provider.Analyse(ctx, req)
	res.Latency = time.Since(start)
	if err != nil {
		res.Status = StatusUnavailable
		a.record(res, pkg.PackageID)
		return res, fmt.Errorf("%w: %w", ErrProviderUnavailable, err)
	}
	if resp.Model != "" {
		res.Model = resp.Model
	}
	res.RawOutput = resp.Raw

	// A reply cut off by the output-token ceiling is a transport or
	// configuration condition, not model misbehaviour: classifying it
	// as unavailable keeps the Story 3.10 strike policy from re-issuing
	// an identically over-budget call as a schema-violation retry.
	// Stop-reason values pass through the providers verbatim:
	// "max_tokens" (claude), "length" (openai_compat finish_reason and
	// ollama done_reason).
	if isTruncated(resp.StopReason) {
		res.Status = StatusUnavailable
		a.record(res, pkg.PackageID)
		return res, fmt.Errorf("%w: response truncated by the output-token ceiling (stop_reason=%q)", ErrProviderUnavailable, resp.StopReason)
	}

	hyp, perr := parseL1Hypothesis(a.schema, resp.Raw, known, pkg.PackageID)
	if perr != nil {
		res.Status = StatusSchemaViolation
		a.record(res, pkg.PackageID)
		return res, fmt.Errorf("%w: %w", ErrSchemaViolation, perr)
	}
	hyp.SchemaVersion = schema.L1HypothesisSchemaVersion
	res.Hypothesis = hyp
	res.Status = StatusSuccess
	a.record(res, pkg.PackageID)
	return res, nil
}

// isTruncated reports whether the provider stop reason marks an
// output-token-ceiling truncation. Comparison is case-insensitive
// (Story 3.3 binding lesson: string gates are case-insensitive).
func isTruncated(stopReason string) bool {
	return strings.EqualFold(stopReason, "max_tokens") || strings.EqualFold(stopReason, "length")
}

// citableEventIDs builds the AC3 referential set: every non-empty
// Events[].ID plus a non-empty Trigger.EventID (the trigger event may
// have been dropped by the Story 1.14 overflow cap, so trigger
// membership avoids a false violation; BI-6.5). Empty ids are excluded
// on both sides: the schema's event_id minLength 1 means "" can never
// be cited, so counting it would defeat the ErrNoCitableEvents
// impossibility guard (round-2 review).
func citableEventIDs(pkg schema.EvidencePackage) map[string]struct{} {
	known := make(map[string]struct{}, len(pkg.Events)+1)
	for _, ev := range pkg.Events {
		if ev.ID != "" {
			known[ev.ID] = struct{}{}
		}
	}
	if pkg.Trigger.EventID != "" {
		known[pkg.Trigger.EventID] = struct{}{}
	}
	return known
}

// record increments the decision metric and emits the one structured
// log line per invocation.
func (a *L1) record(res L1Result, packageID string) {
	recordDecisionCall(a.calls, a.log, provider.RoleL1, packageID,
		res.Provider, res.Model, res.Status, res.PromptVersion, res.Latency)
}

// recordDecisionCall is the shared per-invocation outcome recorder for
// every chain runner (Story 3.6 BI-4 hoist; no payload bytes,
// NFR18-safe fields only). Failure outcomes log at Warn so operators
// can filter on level. The log message renders as
// "<role> analyst call", byte-identical to the Story 3.5 L1 line.
func recordDecisionCall(calls *prometheus.CounterVec, log *slog.Logger, role provider.Role, packageID, providerName, model, status, promptVersion string, latency time.Duration) {
	calls.WithLabelValues(providerName, string(role), status).Inc()
	level := slog.LevelInfo
	if status != StatusSuccess {
		level = slog.LevelWarn
	}
	log.Log(context.Background(), level, string(role)+" analyst call",
		"package_id", packageID,
		"provider", providerName,
		"model", model,
		"status", status,
		"latency_ms", latency.Milliseconds(),
		"prompt_version", promptVersion,
	)
}

// parseL1Hypothesis runs the Story 3.5 BI-6 validation pipeline: trim,
// fence-strip, JSON-schema validation, decode, then the AC3 referential
// check that every cited event_id is a member of the known set built by
// citableEventIDs.
//
// Decode detail (round-1 review): draft 2020-12 "type":"integer"
// accepts any number with a zero fractional part (70.0, 1e2), which Go
// cannot unmarshal into int. The published schema is the authoritative
// contract the model is instructed to follow, so a conformant reply
// must not burn a Story 3.10 strike: confidence decodes through a
// float64 wire field and converts exactly (validation already bounded
// it to an integral value in [0,100], where float64 is exact).
func parseL1Hypothesis(sch *jsonschema.Schema, raw string, known map[string]struct{}, packageID string) (schema.L1Hypothesis, error) {
	var zero schema.L1Hypothesis
	body := strings.TrimSpace(raw)
	if body == "" {
		return zero, errors.New("empty response body")
	}
	body = stripWrappingFence(body)
	if body == "" {
		return zero, errors.New("empty response body after stripping the code fence")
	}

	inst, err := jsonschema.UnmarshalJSON(strings.NewReader(body))
	if err != nil {
		return zero, fmt.Errorf("decode response JSON: %w", err)
	}
	if err := sch.Validate(inst); err != nil {
		return zero, fmt.Errorf("validate against %s: %w", schema.L1HypothesisSchemaVersion, err)
	}
	var wire struct {
		SchemaVersion  string                    `json:"schema_version"`
		Hypothesis     string                    `json:"hypothesis"`
		CitedEvidence  []schema.EvidenceCitation `json:"cited_evidence"`
		FollowUpProbes []string                  `json:"follow_up_probes"`
		Confidence     float64                   `json:"confidence"`
	}
	if err := json.Unmarshal([]byte(body), &wire); err != nil {
		return zero, fmt.Errorf("decode into schema.L1Hypothesis: %w", err)
	}
	hyp := schema.L1Hypothesis{
		SchemaVersion:  wire.SchemaVersion,
		Hypothesis:     wire.Hypothesis,
		CitedEvidence:  wire.CitedEvidence,
		FollowUpProbes: wire.FollowUpProbes,
		Confidence:     int(wire.Confidence),
	}

	// minLength counts code points, so a whitespace-only hypothesis
	// passes the schema; reject it here (round-1 review): a blank
	// verdict must not reach the Story 3.7 Senior as a success.
	if strings.TrimSpace(hyp.Hypothesis) == "" {
		return zero, errors.New("hypothesis is whitespace-only")
	}

	for _, c := range hyp.CitedEvidence {
		if _, ok := known[c.EventID]; !ok {
			return zero, fmt.Errorf("cited event_id %q is not present in package %s", boundForLog(c.EventID), packageID)
		}
	}
	return hyp, nil
}

// boundForLog caps a model-controlled string at 64 bytes and launders
// the cut to valid UTF-8 before it is interpolated into an error that
// callers will log (the byte cut can bite a multibyte rune; same
// standard as the provider snippet sanitizers, Story 3.3 round-2
// lesson).
func boundForLog(s string) string {
	const maxLen = 64
	if len(s) > maxLen {
		return strings.ToValidUTF8(s[:maxLen], "") + "..."
	}
	return s
}

// stripWrappingFence removes ONE wrapping markdown code fence if and
// only if the trimmed body starts with a fence line and ends with a
// closing fence (Story 3.5 BI-6.2). The entire first line (the fence
// and any language tag or other content sharing it) is discarded: a
// payload crammed entirely onto a single fence line therefore strips
// to "" and lands in the empty-after-fence violation branch, while a
// multi-line crammed payload reaches the JSON decoder and fails there;
// both classify as schema violations. Partial or unclosed fences are
// returned unchanged and fail JSON decoding. Both LF and bare-CR line
// endings terminate the fence line (round-1 review: a CR-only reply
// must not retain its fence).
func stripWrappingFence(body string) string {
	if !strings.HasPrefix(body, "```") {
		return body
	}
	nl := strings.IndexAny(body, "\r\n")
	if nl < 0 {
		return body
	}
	rest := strings.TrimSpace(body[nl+1:])
	if !strings.HasSuffix(rest, "```") {
		return body
	}
	return strings.TrimSpace(strings.TrimSuffix(rest, "```"))
}
