// Package provider defines the shared LLM transport abstraction for the
// olaitan analyst tier (Story 3.2, architecture.md:290-312).
//
// # Ring placement and importers
//
// The package lives at internal/agent/provider/ rather than under
// internal/decision/ so the Layer-5 DFIR agent (internal/report/dfir/,
// Epic 4) can share the same interface as the Layer-3 orchestrator
// (internal/decision/agent/, Stories 3.5-3.7). Those two packages are the
// ONLY intended importers (architecture.md:927). The empty
// internal/decision/analyst/ directory is a placeholder reserved for the
// L1/L2/Senior agent code, not for transport code.
//
// # Import-direction allow-set (NFR38)
//
// This package and its implementations may import only the substrate they
// operate over: internal/schema (EvidencePackage, ThreatAssessment),
// internal/report/redact (the mandatory pre-send redaction entry point,
// a leaf package with no upward imports), internal/config,
// internal/retry, internal/metrics, and the official provider SDKs.
// Importing internal/decision/*, internal/report/dfir, internal/response/*,
// internal/correlator/*, or internal/collector/* is forbidden: those are
// consumers or peers, never dependencies.
//
// # Analyse versus the epics' "Call"
//
// epics.md describes the surface as "Call(ctx, request) (response, error)
// with role-typed request/response"; architecture.md:295-303 names the
// method Analyse with positional (Prompt, JSONSchema) arguments and the
// orchestrator sample at architecture.md:637 calls p.Analyse(...). This
// package implements the architecture's named surface and folds the
// positional arguments into a role-carrying Request, satisfying the epics'
// role-typed requirement: same inputs, role-typed envelope.
//
// # Why Role is provider-local, not internal/schema
//
// The analyst role is a transport concern (it selects the per-call timeout
// and the metric label) and is never persisted in evidence or assessments,
// so it lives here instead of widening internal/schema for a non-persisted
// concept.
package provider

import (
	"context"
	"encoding/json"

	"github.com/olokotoh/olaitan/internal/schema"
)

// Role identifies which analyst tier is issuing the call. It selects the
// per-call timeout budget and the role label on
// olaitan_llm_calls_total{provider,role,status}. The label set is bounded:
// implementations must reject any Role outside the four constants below
// rather than mint a new metric series.
type Role string

const (
	// RoleL1 is the first-pass triage analyst (Story 3.5). Budget: 30s.
	RoleL1 Role = "l1"
	// RoleL2 is the verification analyst (Story 3.6). Budget: 30s.
	RoleL2 Role = "l2"
	// RoleSenior is the orchestrating senior analyst (Story 3.7). Budget: 60s.
	RoleSenior Role = "senior"
	// RoleDFIR is RESERVED for the Epic 4 forensic reporting agent. It is
	// defined here so the 120s timeout row and the metric label exist from
	// day one; no DFIR agent ships in Epic 3.
	RoleDFIR Role = "dfir"
)

// Valid reports whether r is one of the four bounded role constants.
func (r Role) Valid() bool {
	switch r {
	case RoleL1, RoleL2, RoleSenior, RoleDFIR:
		return true
	}
	return false
}

// Prompt is the role-specific instruction pair built by the orchestrator
// (Stories 3.5-3.7). The provider only transports it; it never composes
// analyst instructions itself.
//
// Callers that surface model output to operators should include a
// final-answer-only instruction in System: with thinking disabled
// (the Story 3.2 default) Opus 4.8 may otherwise write reasoning
// prose into the visible response.
type Prompt struct {
	// System is the system prompt (may be empty).
	System string
	// User is the user-turn instruction the evidence is appended to.
	User string
}

// JSONSchema is the JSON-schema document the caller expects the structured
// verdict to conform to. The provider transports it as an output-contract
// instruction; decoding and validating the verdict against it is the
// caller's job (parseL1Hypothesis and friends, Stories 3.5-3.7).
type JSONSchema = json.RawMessage

// Request is the role-typed call envelope. It carries everything one
// analyst call needs: the role (timeout + metric label), the evidence
// package (redacted by the provider before any byte leaves the process),
// the prompt pair, the expected output schema, and the optional prior
// assessment for L2/Senior re-evaluation.
type Request struct {
	Role            Role
	Package         schema.EvidencePackage
	Prompt          Prompt
	Schema          JSONSchema
	PriorAssessment *schema.ThreatAssessment
}

// Response is the transport-level result of one analyst call. The provider
// returns the structured payload; it does not parse it into
// schema.ThreatAssessment (that is the orchestrator's job).
type Response struct {
	// Raw is the concatenated text content of the model reply.
	Raw string
	// StopReason is the provider's stop reason (e.g. "end_turn",
	// "max_tokens") for caller-side truncation handling.
	StopReason string
	// Model is the model id that actually served the call, echoed for the
	// reproducibility manifest.
	Model string
	// InputTokens and OutputTokens are the provider-reported usage for
	// cost observability.
	InputTokens  int64
	OutputTokens int64
}

// Provider is the single LLM transport interface every analyst call goes
// through (architecture.md:295-303, enforcement guideline
// architecture.md:662). Implementations own retry (via internal/retry),
// per-role timeouts, pre-send redaction (via internal/report/redact), and
// the olaitan_llm_calls_total outcome metric.
type Provider interface {
	// Name returns the provider's metric label (e.g. "claude").
	Name() string
	// Model returns the pinned model id for the reproducibility manifest.
	Model() string
	// MaxContextTokens returns the model's context window for prompt
	// budgeting.
	MaxContextTokens() int
	// ScoreCap returns the per-provider anti-hallucination cap consumed by
	// the Story 3.11 capped ThreatScore contribution. The accessor only
	// exposes the configured value; enforcement is Story 3.11/3.7 scope.
	ScoreCap() int
	// SupportsStreaming reports whether the implementation streams
	// responses (Phase 3 feature flag, architecture.md:300).
	SupportsStreaming() bool
	// Analyse issues one analyst call. Implementations must redact
	// req.Package before building the wire payload, derive the timeout
	// from req.Role, and record exactly one outcome on
	// olaitan_llm_calls_total.
	Analyse(ctx context.Context, req Request) (Response, error)
	// Health reports whether the provider can currently serve calls.
	Health(ctx context.Context) error
}
