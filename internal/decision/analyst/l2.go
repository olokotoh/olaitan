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
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/olokotoh/olaitan/internal/agent/provider"
	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/schema"
)

// l2SchemaJSON is the embedded runtime copy of the authoritative
// L2Verification JSON schema. It MUST stay byte-identical to
// docs/schemas/l2_verification.json (guarded by
// TestEmbeddedL2SchemaMatchesDocs; Story 3.6 BI-3).
//
//go:embed l2_verification_schema.json
var l2SchemaJSON []byte

var l2Schema = &schemaCompiler{name: "l2_verification_schema.json", doc: l2SchemaJSON}

// l2UserInstruction is the fixed user-turn task statement (Story 3.6
// BI-4). The per-provider SYSTEM prompts are the Story 3.13
// ConfigMap-mounted manifests. provider.BuildAnalystContent appends the
// redacted evidence package, the framed L1 hypothesis
// (Request.PriorHypothesis, Story 3.6 BI-2) and the output-contract
// instruction after this text.
const l2UserInstruction = "Verify the L1 analyst's hypothesis (provided in the l1_hypothesis block) against the " +
	"following Kubernetes runtime evidence package, evidence by evidence. State your verdict as exactly one of " +
	"confirmed, refuted, or inconclusive; give one finding per examined event (at most the 50 most relevant events, " +
	"one entry per event id), citing its event id from the package; list any findings that contradict the L1 " +
	"hypothesis; and give an integer confidence between 0 and 100."

// L2SkipReasonL1Unavailable is the bounded reason label recorded when
// the chain skips L2 because L1 was unavailable (AC4).
const L2SkipReasonL1Unavailable = "l1_unavailable"

// ShouldSkipL2 is the AC4 chain gate, exported for the Story 3.7
// orchestrator: L2 is skipped if and only if L1 failed with provider
// unavailability (the Story 3.10 three-strike policy routes its
// post-retry llm_unavailable exhaustion through the same sentinel). The
// sentinel inherits the full unavailable classification, so transport
// failures, exhausted retries, the per-role timeout, output-token
// truncation and caller-context cancellation all skip under the same
// l1_unavailable label (Story 3.10 may split the reason set). A
// schema violation does NOT skip L2 at this level: before Story 3.10 a
// single violation is not yet llm_unavailable, and 3.10 owns that
// escalation. ErrNoCitableEvents is a chain-level concern (no L1 ran at
// all) owned by Story 3.8. The returned reason is the bounded metric
// label value for olaitan_decision_llm_l2_skipped_total; on the
// no-skip path it is "" and must never be recorded (RecordL2Skip
// refuses it).
func ShouldSkipL2(l1Err error) (bool, string) {
	if errors.Is(l1Err, ErrProviderUnavailable) {
		return true, L2SkipReasonL1Unavailable
	}
	return false, ""
}

// L2Result is the audit capture record of one L2 invocation (Story 3.6
// BI-5): everything Story 3.14 needs to publish to AUDIT.assessments.
// AC3's contradiction preservation is satisfied here: a refuted verdict
// and its contradictory_findings survive into Verification verbatim.
// Populated as far as known on failure paths; in-memory only
// (persistence and pre-persistence redaction are Story 3.14 scope).
type L2Result struct {
	// Verification is the validated, schema_version-stamped verdict
	// (zero value when Status is not success).
	Verification schema.L2Verification
	// PromptVersion echoes PromptSpec.Version.
	PromptVersion string
	// System and User are the prompt-pair INPUTS (the ConfigMap system
	// prompt and the fixed user instruction; clean by the REDACTION
	// CONTRACT). The full user turn that crossed the wire is composed
	// provider-side by BuildAnalystContent (instruction + framed
	// evidence + framed hypothesis + output contract) and is
	// deterministic from these inputs plus the package; Story 3.13/3.14
	// own the prompt-content hash that pins the composed form.
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
	// metric for this invocation; empty on the precondition-failure
	// paths (ErrNoHypothesis, ErrNoCitableEvents), where no provider
	// call was made and nothing was recorded.
	Status string
}

// L2 is the verification analyst runner (FR22/FR23). Construct with
// NewL2; issue calls with Run.
type L2 struct {
	provider provider.Provider
	spec     PromptSpec
	calls    *prometheus.CounterVec
	log      *slog.Logger
	schema   *jsonschema.Schema
}

// ScoreCap exposes the L2 provider's per-provider anti-hallucination cap
// so the orchestrator can cap an L1+L2 ablation assessment at the
// boundary role's cap (Story 3.8 BI-5; mirrors Senior.ScoreCap).
func (a *L2) ScoreCap() int { return a.provider.ScoreCap() }

// NewL2 builds an L2 runner on top of an already-constructed provider
// (per-role provider selection is Story 3.8). It registers (or re-uses)
// the shared decision-outcome metric family on reg.
func NewL2(p provider.Provider, spec PromptSpec, reg *metrics.Registry, log *slog.Logger) (*L2, error) {
	if p == nil {
		return nil, errors.New("analyst: nil provider")
	}
	if log == nil {
		log = slog.Default()
	}
	sch, err := l2Schema.compiled()
	if err != nil {
		return nil, err
	}
	calls, err := RegisterDecisionCallsMetric(reg)
	if err != nil {
		return nil, err
	}
	return &L2{provider: p, spec: spec, calls: calls, log: log, schema: sch}, nil
}

// Run issues one L2 analyst call for pkg plus the L1 hypothesis and
// returns the audit record plus the control-flow error. Exactly one
// outcome is recorded on olaitan_decision_llm_calls_total per
// provider-reaching call (Story 3.5 BI-8 as amended). The 30-second L2
// budget is enforced by the provider via Request.Role; Run makes
// exactly ONE provider attempt (Story 3.10 retries sit above,
// transport-level retries below).
func (a *L2) Run(ctx context.Context, pkg schema.EvidencePackage, hyp schema.L1Hypothesis) (L2Result, error) {
	res := L2Result{
		PromptVersion: a.spec.Version,
		System:        a.spec.System,
		User:          l2UserInstruction,
		Provider:      a.provider.Name(),
		Model:         a.provider.Model(),
	}

	if strings.TrimSpace(hyp.Hypothesis) == "" {
		return res, fmt.Errorf("%w: package %s arrived with an empty hypothesis (a failed L1 run yields a zero value; consult ShouldSkipL2 before spawning L2)", ErrNoHypothesis, pkg.PackageID)
	}

	known := citableEventIDs(pkg)
	if len(known) == 0 {
		return res, fmt.Errorf("%w: package %s carries no events and no trigger event id, so a schema-conformant reply is impossible", ErrNoCitableEvents, pkg.PackageID)
	}

	req := provider.Request{
		Role:            provider.RoleL2,
		Package:         pkg,
		Prompt:          provider.Prompt{System: a.spec.System, User: l2UserInstruction},
		Schema:          provider.JSONSchema(bytes.Clone(l2SchemaJSON)),
		PriorHypothesis: &hyp,
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

	if isTruncated(resp.StopReason) {
		res.Status = StatusUnavailable
		a.record(res, pkg.PackageID)
		return res, fmt.Errorf("%w: response truncated by the output-token ceiling (stop_reason=%q)", ErrProviderUnavailable, resp.StopReason)
	}

	verification, perr := parseL2Verification(a.schema, resp.Raw, known, pkg.PackageID)
	if perr != nil {
		res.Status = StatusSchemaViolation
		a.record(res, pkg.PackageID)
		return res, fmt.Errorf("%w: %w", ErrSchemaViolation, perr)
	}
	verification.SchemaVersion = schema.L2VerificationSchemaVersion
	res.Verification = verification
	res.Status = StatusSuccess
	a.record(res, pkg.PackageID)
	return res, nil
}

func (a *L2) record(res L2Result, packageID string) {
	recordDecisionCall(a.calls, a.log, provider.RoleL2, packageID,
		res.Provider, res.Model, res.Status, res.PromptVersion, res.Latency)
}

// parseL2Verification runs the Story 3.6 BI-4 validation pipeline
// (same shape as parseL1Hypothesis): trim, fence-strip, JSON-schema
// validation, wire-struct decode (float64 confidence; validation
// before decode protects the int conversion), then the programmatic
// rules JSON Schema cannot express: whitespace-only finding and
// contradictory entries are rejected, and every verified event_id must
// be a member of the known set.
func parseL2Verification(sch *jsonschema.Schema, raw string, known map[string]struct{}, packageID string) (schema.L2Verification, error) {
	var zero schema.L2Verification
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
		return zero, fmt.Errorf("validate against %s: %w", schema.L2VerificationSchemaVersion, err)
	}
	var wire struct {
		SchemaVersion         string                        `json:"schema_version"`
		Verdict               string                        `json:"verdict"`
		VerifiedEvidence      []schema.EvidenceVerification `json:"verified_evidence"`
		ContradictoryFindings []string                      `json:"contradictory_findings"`
		Confidence            float64                       `json:"confidence"`
	}
	if err := json.Unmarshal([]byte(body), &wire); err != nil {
		return zero, fmt.Errorf("decode into schema.L2Verification: %w", err)
	}
	verification := schema.L2Verification{
		SchemaVersion:         wire.SchemaVersion,
		Verdict:               wire.Verdict,
		VerifiedEvidence:      wire.VerifiedEvidence,
		ContradictoryFindings: wire.ContradictoryFindings,
		Confidence:            int(wire.Confidence),
	}

	// One narrative entry per event: duplicate event_ids would let a
	// reply spend every slot restating (or contradicting) one event,
	// and two verdicts for the same event would reach the Senior as one
	// clean success (round-1 review). uniqueItems only rejects
	// whole-object duplicates, so the per-id rule lives here.
	seen := make(map[string]struct{}, len(verification.VerifiedEvidence))
	for i, v := range verification.VerifiedEvidence {
		if strings.TrimSpace(v.Finding) == "" {
			return zero, fmt.Errorf("verified_evidence[%d].finding is whitespace-only", i)
		}
		if _, ok := known[v.EventID]; !ok {
			return zero, fmt.Errorf("verified event_id %q is not present in package %s", boundForLog(v.EventID), packageID)
		}
		if _, dup := seen[v.EventID]; dup {
			return zero, fmt.Errorf("verified_evidence[%d] repeats event_id %q; the narrative is one entry per event", i, boundForLog(v.EventID))
		}
		seen[v.EventID] = struct{}{}
	}
	for i, c := range verification.ContradictoryFindings {
		if strings.TrimSpace(c) == "" {
			return zero, fmt.Errorf("contradictory_findings[%d] is whitespace-only", i)
		}
	}
	return verification, nil
}
