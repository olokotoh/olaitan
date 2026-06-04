package override

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// SchemaVersionAuditOverride is stamped on every AUDIT.overrides SIEM event
// (Story 2.8, BI-4.2). It versions INDEPENDENTLY of the operational
// SchemaVersionOverride ("override.v1") so the append-only SIEM audit copy and
// the operational OVERRIDES.applied subject can evolve separately
// (docs/schema-versioning.md).
const SchemaVersionAuditOverride = "audit.overrides.v1"

// AuditOverride is the AUDIT.overrides wire event (schema_version
// audit.overrides.v1): the append-only SIEM copy of an operator override
// application or rejection (Story 2.8, BI-2/BI-4.2). It deliberately mirrors the
// operational OverrideApplied JSON shape (publisher.go) - the same full FR40
// attribution set (operator_id, before_state, requested_state, ttl_seconds,
// source, rejected, reason) - but carries its OWN schema_version so the two
// subjects version independently. An SIEM correlates AUDIT.overrides with
// AUDIT.transitions on workload_id (BI-10): an applied override emits BOTH (the
// state change and this application record); a rejected override emits ONLY
// this event (a rejection changes no state).
//
// Authoritative validation source: docs/schemas/audit/overrides.json.
type AuditOverride struct {
	SchemaVersion  string    `json:"schema_version"`
	WorkloadID     string    `json:"workload_id"`
	RequestedState string    `json:"requested_state"`
	BeforeState    string    `json:"before_state"`
	TTLSeconds     int       `json:"ttl_seconds"`
	OperatorID     string    `json:"operator_id,omitempty"`
	Source         string    `json:"source"`
	Rejected       bool      `json:"rejected"`
	Reason         string    `json:"reason,omitempty"`
	PublishedAt    time.Time `json:"published_at"`
	// AppliedAtNs is the override's applied-at nanosecond timestamp, used in the
	// dedup message id so a poll re-emit is server-side deduplicated. Zero on a
	// rejection (no applied-at), matching the operational subject.
	AppliedAtNs int64 `json:"applied_at_ns"`
}

// auditOverrideFromApplied projects an operational OverrideApplied event onto
// the SIEM AuditOverride event, swapping in the independent audit
// schema_version (BI-2.2). The two events are built from the SAME in-memory
// OverrideApplied at the controller's existing publish points, so the SIEM copy
// can never drift from the operational record.
func auditOverrideFromApplied(evt OverrideApplied) AuditOverride {
	return AuditOverride{
		SchemaVersion:  SchemaVersionAuditOverride,
		WorkloadID:     evt.WorkloadID,
		RequestedState: evt.RequestedState,
		BeforeState:    evt.BeforeState,
		TTLSeconds:     evt.TTLSeconds,
		OperatorID:     evt.OperatorID,
		Source:         evt.Source,
		Rejected:       evt.Rejected,
		Reason:         evt.Reason,
		PublishedAt:    evt.PublishedAt,
		AppliedAtNs:    evt.AppliedAtNs,
	}
}

// AuditOverridePublisher is the Story 2.8 one-method audit-publish seam (BI-2),
// the SIEM sibling of OverridePublisher. The controller's tests inject a fake
// without a real NATS connection; a nil publisher on the controller means no
// audit (off-by-default, BI-8).
type AuditOverridePublisher interface {
	PublishAuditOverride(ctx context.Context, evt AuditOverride) error
}

// natsAuditOverridePublisher publishes AuditOverride events to
// subjects.AuditOverrides via PublishJS, reusing the EXACT msgID derivation of
// the operational natsOverridePublisher (publisher.go) so an idempotent poll
// re-publish does not inflate the SIEM record either (BI-2.3).
type natsAuditOverridePublisher struct {
	nc *natsclient.Client
}

// NewNATSAuditPublisher returns an AuditOverridePublisher backed by the shared
// NATS client. A nil client is a construction error.
func NewNATSAuditPublisher(nc *natsclient.Client) (AuditOverridePublisher, error) {
	if nc == nil {
		return nil, fmt.Errorf("override: nil nats client for audit publisher")
	}
	return &natsAuditOverridePublisher{nc: nc}, nil
}

// PublishAuditOverride publishes evt to AUDIT.overrides with the SAME WithMsgID
// derivation as the operational publisher (BI-2.3): an applied event keys on
// (workload, applied_at) and a rejection keys on (workload, reason, requested
// state), so the audit dedup is never looser than the operational one.
func (p *natsAuditOverridePublisher) PublishAuditOverride(ctx context.Context, evt AuditOverride) error {
	evt, msgID := prepareAuditOverride(evt, time.Now().UTC())
	if _, err := p.nc.PublishJS(ctx, subjects.AuditOverrides, evt, jetstream.WithMsgID(msgID)); err != nil {
		return fmt.Errorf("override: publish audit override: %w", err)
	}
	return nil
}

// prepareAuditOverride defaults the schema_version/published_at and derives the
// dedup message id, reusing the EXACT operational derivation (BI-2.3): an
// applied event keys on (workload, applied_at) and a rejection keys on
// (workload, reason, requested state), so the audit dedup is never looser than
// the operational one. Split out from PublishAuditOverride so the
// defaulting/dedup logic is unit-testable without a live NATS client.
func prepareAuditOverride(evt AuditOverride, now time.Time) (AuditOverride, string) {
	if evt.SchemaVersion == "" {
		evt.SchemaVersion = SchemaVersionAuditOverride
	}
	if evt.PublishedAt.IsZero() {
		evt.PublishedAt = now
	}
	msgID := evt.WorkloadID + ":" + strconv.FormatInt(evt.AppliedAtNs, 10)
	if evt.Rejected {
		msgID = evt.WorkloadID + ":rejected:" + evt.Reason + ":" + evt.RequestedState
	}
	return evt, msgID
}
