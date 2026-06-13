package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// SchemaVersionAssessments is the audit.assessments.v2 wire version. v2
// (Story 3.14) extends the Story 3.8 MINIMAL v1 payload with the full
// SIEM trail: per-role prompt versions / providers / models, the L1/L2/
// Senior verdicts, the REDACTED evidence inputs, and the redaction flag.
// The addition is MINOR-additive per NFR29 (older consumers ignore the
// new fields); it versions independently of the other audit subjects
// (docs/schema-versioning.md).
const SchemaVersionAssessments = "audit.assessments.v2"

// AssessmentInput is the ring-clean projection seam (Story 3.14 BI-2a):
// the audit package (ring layer 4) must NOT import internal/decision/
// analyst (ring layer 3, NFR38), so the cmd caller (which imports both)
// flattens an analyst.ChainResult onto these schema-typed fields. Every
// field is a schema type or a plain value; nothing here references the
// analyst package. Per-role maps are keyed by "l1"/"l2"/"senior" and omit
// a role the ablation mode did not run.
type AssessmentInput struct {
	PackageID       string
	WorkloadID      string
	Mode            string
	AgentsAvailable []string
	// PromptVersions / Providers / Models are keyed by role ("l1","l2",
	// "senior"); a role absent from the map did not run in this mode.
	PromptVersions map[string]string
	Providers      map[string]string
	Models         map[string]string
	// RawConfidence is the boundary role's model-reported confidence;
	// CappedConfidence is min(raw, boundary-provider cap).
	RawConfidence    int
	CappedConfidence int
	// The structured per-role verdicts (nil when that role did not run).
	L1Hypothesis     *schema.L1Hypothesis
	L2Verification   *schema.L2Verification
	ThreatAssessment *schema.ThreatAssessment
	// RedactedEvidence is the EvidencePackage AFTER redact.Redact — the
	// exact bytes the LLM saw. The RAW package must never be passed here.
	RedactedEvidence schema.EvidencePackage
	// RedactionApplied records that the redaction layer ran for these
	// inputs (NFR15/NFR18). A production path must always pass true; a
	// false in any non-test path is a CI-enforced violation (AC3).
	RedactionApplied bool
	// Now is the chain decision time (decided_at == published_at in the
	// synchronous publish path).
	Now time.Time
}

// AuditAssessment is the AUDIT.assessments wire event: the full SIEM
// projection of one investigation-chain run (Story 3.14, FR41). It carries
// the prompt versions, redacted inputs, the L1/L2/Senior verdicts, per-role
// provider attribution, and the raw + capped confidences, so every LLM
// verdict is traceable and a Senior's challenge of L1/L2 is preserved.
type AuditAssessment struct {
	SchemaVersion string `json:"schema_version"`
	PackageID     string `json:"package_id"`
	WorkloadID    string `json:"workload_id"`
	// Mode is the chain mode: "full", "l1_l2", or "l1_only".
	Mode string `json:"mode"`
	// AgentsAvailable lists the roles that contributed; the complement is
	// the skipped set the ablation produced.
	AgentsAvailable []string `json:"agents_available,omitempty"`
	// PromptVersions/Providers/Models are role-keyed; a role absent from
	// the map did not run in this mode (Story 3.13 hashes, FR25 routing).
	PromptVersions map[string]string `json:"prompt_versions,omitempty"`
	Providers      map[string]string `json:"providers,omitempty"`
	Models         map[string]string `json:"models,omitempty"`
	// ThreatType is the Senior verdict's threat type; empty in an ablation
	// mode where no Senior ran.
	ThreatType string `json:"threat_type,omitempty"`
	// RawConfidence is the model-reported confidence of the boundary role;
	// LLMCappedConfidence is min(raw, boundary-provider cap).
	RawConfidence       int `json:"raw_confidence"`
	LLMCappedConfidence int `json:"llm_capped_confidence"`
	// The structured per-role verdicts (omitted when the role did not run).
	L1Hypothesis     *schema.L1Hypothesis     `json:"l1_hypothesis,omitempty"`
	L2Verification   *schema.L2Verification   `json:"l2_verification,omitempty"`
	ThreatAssessment *schema.ThreatAssessment `json:"threat_assessment,omitempty"`
	// RedactedEvidence is the EvidencePackage AFTER redaction — the exact
	// inputs the LLM saw, safe to ship to a SIEM (NFR15/NFR18).
	RedactedEvidence schema.EvidencePackage `json:"redacted_evidence"`
	// RedactionApplied: true on every production path (the chain always
	// redacts before the LLM); a false is a CI-enforced violation (AC3).
	RedactionApplied bool `json:"redaction_applied"`
	// DecidedAt is when the chain produced the assessment; PublishedAt is
	// the audit-emission time (== DecidedAt in the synchronous publish).
	DecidedAt   time.Time `json:"decided_at"`
	PublishedAt time.Time `json:"published_at"`
}

// AssessmentFromChain projects a chain run (flattened to AssessmentInput by
// the cmd caller) onto the AUDIT.assessments v2 wire event. It serialises
// the REDACTED evidence only; the raw package never reaches this function.
func AssessmentFromChain(in AssessmentInput) AuditAssessment {
	return AuditAssessment{
		SchemaVersion:       SchemaVersionAssessments,
		PackageID:           in.PackageID,
		WorkloadID:          in.WorkloadID,
		Mode:                in.Mode,
		AgentsAvailable:     in.AgentsAvailable,
		PromptVersions:      in.PromptVersions,
		Providers:           in.Providers,
		Models:              in.Models,
		ThreatType:          threatType(in.ThreatAssessment),
		RawConfidence:       in.RawConfidence,
		LLMCappedConfidence: in.CappedConfidence,
		L1Hypothesis:        in.L1Hypothesis,
		L2Verification:      in.L2Verification,
		ThreatAssessment:    in.ThreatAssessment,
		RedactedEvidence:    in.RedactedEvidence,
		RedactionApplied:    in.RedactionApplied,
		DecidedAt:           in.Now,
		PublishedAt:         in.Now,
	}
}

// threatType returns the assessment's threat type, or "" when no Senior ran.
func threatType(a *schema.ThreatAssessment) string {
	if a == nil {
		return ""
	}
	return a.ThreatType
}

// AssessmentAuditPublisher is the one-method publish seam (mirroring
// AuditTransitionPublisher) so the chain consumer's tests inject a
// capturing fake without a real NATS connection.
type AssessmentAuditPublisher interface {
	PublishAuditAssessment(ctx context.Context, evt AuditAssessment) error
}

// natsAssessmentPublisher publishes AuditAssessment events to
// subjects.AuditAssessments. Unlike the transition sink, this is a
// SYNCHRONOUS publish: the investigation-chain consumer runs off its own
// JetStream goroutine (already decoupled from the FSM hot path), so a
// bounded synchronous PublishJS is acceptable. The msgID is the
// package_id, so a chain re-run of the same package is deduplicated
// inside the AUDIT_ASSESSMENTS stream's dedup window.
type natsAssessmentPublisher struct {
	nc *natsclient.Client
}

// NewNATSAssessmentPublisher returns an AssessmentAuditPublisher backed
// by the shared NATS client. A nil client is a construction error.
func NewNATSAssessmentPublisher(nc *natsclient.Client) (AssessmentAuditPublisher, error) {
	if nc == nil {
		return nil, fmt.Errorf("audit: nil nats client for assessment publisher")
	}
	return &natsAssessmentPublisher{nc: nc}, nil
}

// PublishAuditAssessment publishes evt to AUDIT.assessments with
// WithMsgID dedup keyed on the package_id.
func (p *natsAssessmentPublisher) PublishAuditAssessment(ctx context.Context, evt AuditAssessment) error {
	if _, err := p.nc.PublishJS(ctx, subjects.AuditAssessments, evt, jetstream.WithMsgID(evt.PackageID)); err != nil {
		return fmt.Errorf("audit: publish assessment: %w", err)
	}
	return nil
}
