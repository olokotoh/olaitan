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

// seniorSchemaJSON is the embedded runtime copy of the authoritative
// Senior verdict schema. It MUST stay byte-identical to
// docs/schemas/threat_assessment.json (guarded by
// TestEmbeddedSeniorSchemaMatchesDocs; Story 3.7 BI-2).
//
//go:embed threat_assessment_schema.json
var seniorSchemaJSON []byte

var seniorSchema = &schemaCompiler{name: "threat_assessment_schema.json", doc: seniorSchemaJSON}

// seniorUserInstruction is the fixed user-turn task statement (Story
// 3.7 BI-5). provider.BuildAnalystContent appends the redacted evidence
// package, the framed L1 hypothesis and L2 verification where present,
// and the output-contract instruction after this text.
const seniorUserInstruction = "You are the Senior analyst finalising the verdict on the following Kubernetes " +
	"runtime evidence package. Explicitly challenge the L1 hypothesis and the L2 verification where the " +
	"l1_hypothesis and l2_verification blocks are present; if they are absent, assess the evidence directly with " +
	"appropriately reduced confidence. State a short threat_type classification and your reasoning; annotate " +
	"applicable ATT&CK technique ids (form T#### or T####.###, at most 20); record any explicit disagreements " +
	"between the L1 and L2 analyses; optionally name the kill-chain stage; and give an integer raw confidence " +
	"between 0 and 100."

// SeniorVerdict is the validated model-facing Senior output
// (threat_assessment.v1). The orchestrator combines it with the cap
// arithmetic and chain availability into the persisted
// schema.ThreatAssessment.
type SeniorVerdict struct {
	SchemaVersion      string   `json:"schema_version,omitempty"`
	ThreatType         string   `json:"threat_type"`
	Reasoning          string   `json:"reasoning"`
	MitreTechniques    []string `json:"mitre_techniques,omitempty"`
	NotedDisagreements []string `json:"noted_disagreements,omitempty"`
	KillChainStage     string   `json:"kill_chain_stage,omitempty"`
	Confidence         int      `json:"confidence"`
}

// SeniorResult is the audit capture record of one Senior invocation
// (Story 3.7 BI-5), mirroring L1Result/L2Result. Populated as far as
// known on failure paths; Status is empty on the precondition path
// (ErrNoCitableEvents), where no provider call was made.
type SeniorResult struct {
	Verdict       SeniorVerdict
	PromptVersion string
	// System and User are the prompt-pair INPUTS; the composed user
	// turn is provider-side (BuildAnalystContent) and deterministic
	// from these plus the package and prior blocks.
	System string
	User   string
	// Provider is the provider's metric label; Model is the served
	// model (Response echo, pinned fallback on failure paths).
	Provider  string
	Model     string
	RawOutput string
	Latency   time.Duration
	Status    string
}

// Senior is the orchestrating senior analyst runner (FR24). Construct
// with NewSenior; issue calls with Run.
type Senior struct {
	provider provider.Provider
	spec     PromptSpec
	calls    *prometheus.CounterVec
	log      *slog.Logger
	schema   *jsonschema.Schema
}

// NewSenior builds a Senior runner on top of an already-constructed
// provider (per-role provider selection is Story 3.8).
func NewSenior(p provider.Provider, spec PromptSpec, reg *metrics.Registry, log *slog.Logger) (*Senior, error) {
	if p == nil {
		return nil, errors.New("analyst: nil provider")
	}
	if log == nil {
		log = slog.Default()
	}
	sch, err := seniorSchema.compiled()
	if err != nil {
		return nil, err
	}
	calls, err := RegisterDecisionCallsMetric(reg)
	if err != nil {
		return nil, err
	}
	return &Senior{provider: p, spec: spec, calls: calls, log: log, schema: sch}, nil
}

// ScoreCap exposes the Senior provider's per-provider anti-hallucination
// cap for the orchestrator's AC2 arithmetic.
func (a *Senior) ScoreCap() int { return a.provider.ScoreCap() }

// Run issues one Senior analyst call. hyp and ver are NIL in degraded
// modes (both nil = Senior-on-evidence-only, AC4; ver nil = L2-failed
// hypothesis-only mode); nil is a legal input here, unlike the L2
// runner's ErrNoHypothesis contract. The 60-second Senior budget is
// enforced by the provider via Request.Role. Exactly one outcome is
// recorded on olaitan_decision_llm_calls_total per provider-reaching
// call; the ErrNoCitableEvents precondition records nothing.
func (a *Senior) Run(ctx context.Context, pkg schema.EvidencePackage, hyp *schema.L1Hypothesis, ver *schema.L2Verification) (SeniorResult, error) {
	res := SeniorResult{
		PromptVersion: a.spec.Version,
		System:        a.spec.System,
		User:          seniorUserInstruction,
		Provider:      a.provider.Name(),
		Model:         a.provider.Model(),
	}

	known := citableEventIDs(pkg)
	if len(known) == 0 {
		return res, fmt.Errorf("%w: package %s carries no events and no trigger event id", ErrNoCitableEvents, pkg.PackageID)
	}

	req := provider.Request{
		Role:              provider.RoleSenior,
		Package:           pkg,
		Prompt:            provider.Prompt{System: a.spec.System, User: seniorUserInstruction},
		Schema:            provider.JSONSchema(bytes.Clone(seniorSchemaJSON)),
		PriorHypothesis:   hyp,
		PriorVerification: ver,
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

	verdict, perr := parseSeniorVerdict(a.schema, resp.Raw)
	if perr != nil {
		res.Status = StatusSchemaViolation
		a.record(res, pkg.PackageID)
		return res, fmt.Errorf("%w: %w", ErrSchemaViolation, perr)
	}
	verdict.SchemaVersion = schema.ThreatAssessmentSchemaVersion
	res.Verdict = verdict
	res.Status = StatusSuccess
	a.record(res, pkg.PackageID)
	return res, nil
}

func (a *Senior) record(res SeniorResult, packageID string) {
	recordDecisionCall(a.calls, a.log, provider.RoleSenior, packageID,
		res.Provider, res.Model, res.Status, res.PromptVersion, res.Latency)
}

// parseSeniorVerdict runs the shared validation pipeline for the Senior
// verdict. There is NO event referential check: the Senior does not
// cite events (L1 citations and the L2 narrative carry the referential
// guarantees); programmatic rules cover the whitespace classes JSON
// Schema cannot express.
func parseSeniorVerdict(sch *jsonschema.Schema, raw string) (SeniorVerdict, error) {
	var zero SeniorVerdict
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
		return zero, fmt.Errorf("validate against %s: %w", schema.ThreatAssessmentSchemaVersion, err)
	}
	var wire struct {
		SchemaVersion      string   `json:"schema_version"`
		ThreatType         string   `json:"threat_type"`
		Reasoning          string   `json:"reasoning"`
		MitreTechniques    []string `json:"mitre_techniques"`
		NotedDisagreements []string `json:"noted_disagreements"`
		KillChainStage     string   `json:"kill_chain_stage"`
		Confidence         float64  `json:"confidence"`
	}
	if err := json.Unmarshal([]byte(body), &wire); err != nil {
		return zero, fmt.Errorf("decode into SeniorVerdict: %w", err)
	}
	verdict := SeniorVerdict{
		SchemaVersion:      wire.SchemaVersion,
		ThreatType:         wire.ThreatType,
		Reasoning:          wire.Reasoning,
		MitreTechniques:    wire.MitreTechniques,
		NotedDisagreements: wire.NotedDisagreements,
		KillChainStage:     wire.KillChainStage,
		Confidence:         int(wire.Confidence),
	}

	if strings.TrimSpace(verdict.ThreatType) == "" {
		return zero, errors.New("threat_type is whitespace-only")
	}
	if strings.TrimSpace(verdict.Reasoning) == "" {
		return zero, errors.New("reasoning is whitespace-only")
	}
	for i, d := range verdict.NotedDisagreements {
		if strings.TrimSpace(d) == "" {
			return zero, fmt.Errorf("noted_disagreements[%d] is whitespace-only", i)
		}
	}
	return verdict, nil
}
