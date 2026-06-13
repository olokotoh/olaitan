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

// SchemaVersionAssessments is the audit.assessments.v1 wire version
// (Story 3.8 AC4). It versions independently of the other audit subjects
// (docs/schema-versioning.md); Story 3.14 may extend the payload under a
// new version.
const SchemaVersionAssessments = "audit.assessments.v1"

// AuditAssessment is the AUDIT.assessments wire event: the SIEM
// projection of one investigation-chain run (Story 3.8 BI-8). It is the
// MINIMAL payload that makes the chain's ablation auditable (AC4):
// agents_available records which roles ran (its complement is which were
// skipped) and mode records the configured boundary. The confidence
// fields carry the raw and per-provider-capped LLM confidence for audit
// traceability; the score fold into the FSM ThreatScore is Story 3.11.
//
// Story 3.14 owns the broader audit pipeline and may supersede or extend
// this payload under a new schema_version.
type AuditAssessment struct {
	SchemaVersion string `json:"schema_version"`
	PackageID     string `json:"package_id"`
	WorkloadID    string `json:"workload_id"`
	// Mode is the chain mode: "full", "l1_l2", or "l1_only".
	Mode string `json:"mode"`
	// AgentsAvailable lists the roles that contributed (e.g. ["l1"],
	// ["l1","l2"], ["l1","l2","senior"]); the complement is the skipped
	// set the ablation produced.
	AgentsAvailable []string `json:"agents_available,omitempty"`
	// ThreatType is the Senior verdict's threat type; empty in an
	// ablation mode where no Senior ran.
	ThreatType string `json:"threat_type,omitempty"`
	// RawConfidence is the model-reported confidence of the boundary
	// role; LLMCappedConfidence is min(raw, boundary-provider cap).
	RawConfidence       int `json:"raw_confidence"`
	LLMCappedConfidence int `json:"llm_capped_confidence"`
	// DecidedAt is when the chain produced the assessment.
	DecidedAt time.Time `json:"decided_at"`
}

// AssessmentFromChain projects a chain run onto the AUDIT.assessments
// wire event, stamping schema_version and decided_at.
func AssessmentFromChain(packageID, workloadID, mode string, a schema.ThreatAssessment, now time.Time) AuditAssessment {
	return AuditAssessment{
		SchemaVersion:       SchemaVersionAssessments,
		PackageID:           packageID,
		WorkloadID:          workloadID,
		Mode:                mode,
		AgentsAvailable:     a.AgentsAvailable,
		ThreatType:          a.ThreatType,
		RawConfidence:       a.RawConfidence,
		LLMCappedConfidence: a.LLMCappedConfidence,
		DecidedAt:           now,
	}
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
