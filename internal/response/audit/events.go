// Package audit hosts the Story 2.8 append-only SIEM audit seams (FR40/NFR16).
// It is the Ring-4 (response) home for the three audit-publishing adapters that
// project the shipped FSM/override/netpol activity onto the three append-only
// NATS AUDIT subjects:
//
//   - AUDIT.transitions: a non-blocking fsm.TransitionSink (TransitionAuditSink)
//     appended to the existing fsm.MultiSink, so every actual FSM state change
//     (including operator-pin transitions, captured for free) is audited.
//   - AUDIT.overrides:   published by the override controller's own
//     AuditOverridePublisher seam (defined in internal/response/override), NOT
//     here; this package provides no override adapter.
//   - AUDIT.policies:    a PolicyAuditSink adapter satisfying the
//     netpol.PolicyAuditPublisher interface (defined IN internal/response/netpol
//     so netpol gains no NATS dependency, BI-3/BI-12). The NATS publish lands
//     here, keeping netpol Ring-clean and NATS-free.
//
// Ring discipline (BI-12): this package may import substrate (internal/schema,
// internal/nats, internal/subjects, internal/metrics) and same-ring sibling
// TYPES (internal/response/fsm, internal/response/netpol). It MUST NOT import
// internal/collector/* (Ring 1) or internal/decision/*. netpol does NOT import
// this package: the adapter is wired at cmd/olaitan, so the dependency points
// the right way.
//
// All publishing is best-effort and never blocks or fails enforcement (BI-5):
// the transitions sink and the policy adapter both mirror the shipped RedisSink
// shape (a bounded in-memory buffer + a background Run drainer + a dropped
// counter on overflow), so a NATS outage drops audit events with a warning
// rather than stalling the FSM goroutine or the netpol apply worker.
package audit

import (
	"time"

	"github.com/olokotoh/olaitan/internal/response/netpol"
	"github.com/olokotoh/olaitan/internal/schema"
)

// Schema version constants per the architecture's schema-versioning ADR
// (architecture.md:244). Each audit subject versions independently
// (docs/schema-versioning.md), mirroring the override.v1 precedent.
const (
	SchemaVersionTransitions = "audit.transitions.v1"
	SchemaVersionPolicies    = "audit.policies.v1"
)

// AuditTransition is the AUDIT.transitions wire event (schema_version
// audit.transitions.v1): the SIEM projection of schema.StateTransition (BI-4.1).
// The AC4-of-Story-2.2 field-name normalisation is made LITERAL on the wire so a
// SIEM ingest needs no rename map: before_state=FromState, after_state=ToState,
// triggering_threat_score=Confidence. Both decided_at (the FSM injected-clock
// decision time) and published_at (the audit-emission time) are carried,
// deliberately distinct (BI-1.3). An override-driven transition arrives here
// like any automated one, carrying trigger_type=override and operator_id
// (BI-1.1/BI-10); it is NOT special-cased and NOT deduplicated against the
// AUDIT.overrides event.
//
// Authoritative validation source: docs/schemas/audit/transitions.json.
type AuditTransition struct {
	SchemaVersion string `json:"schema_version"`
	// BeforeState is StateTransition.FromState (AC1 before_state).
	BeforeState string `json:"before_state"`
	// AfterState is StateTransition.ToState (AC1 after_state).
	AfterState string `json:"after_state"`
	// TriggeringThreatScore is StateTransition.Confidence (AC1
	// triggering_threat_score), the score that drove the transition.
	TriggeringThreatScore float64 `json:"triggering_threat_score"`
	PackageID             string  `json:"package_id"`
	WorkloadID            string  `json:"workload_id"`
	// TriggerType is "automated" or "override".
	TriggerType string `json:"trigger_type"`
	// Reason is one of the schema.Reason* constants or the override
	// operator_override reason.
	Reason string `json:"reason"`
	// OperatorID is populated on override transitions only.
	OperatorID string `json:"operator_id,omitempty"`
	// DecidedAt is StateTransition.Timestamp, the FSM injected-clock decision
	// time (BI-1.3), distinct from PublishedAt.
	DecidedAt time.Time `json:"decided_at"`
	// PublishedAt is when the audit event was emitted onto NATS (BI-1.3).
	PublishedAt time.Time `json:"published_at"`
}

// transitionFromState builds the AuditTransition wire event from a
// schema.StateTransition, stamping decided_at from the FSM Timestamp and
// published_at from now (BI-1.3). The Confidence field carries the
// triggering threat score.
func transitionFromState(st schema.StateTransition, now time.Time) AuditTransition {
	return AuditTransition{
		SchemaVersion:         SchemaVersionTransitions,
		BeforeState:           string(st.FromState),
		AfterState:            string(st.ToState),
		TriggeringThreatScore: st.Confidence,
		PackageID:             st.PackageID,
		WorkloadID:            st.WorkloadID,
		TriggerType:           st.TriggerType,
		Reason:                st.Reason,
		OperatorID:            st.OperatorID,
		DecidedAt:             st.Timestamp,
		PublishedAt:           now,
	}
}

// AuditPolicy is the AUDIT.policies wire event (schema_version
// audit.policies.v1): the SIEM projection of a single netpol mutation (BI-4.3).
// action is one of the documented netpol mutation actions (BI-9); fsm_state is
// the FSM state that caused the mutation (BI-3.4); spec_summary is a compact,
// closed-enum rendering of the policy shape (egress_allowlist / deny_all /
// removed, BI-4.3/BI-11), NOT a full NetworkPolicy diff. published_at is
// stamped by the adapter at emit time.
//
// Authoritative validation source: docs/schemas/audit/policies.json.
type AuditPolicy struct {
	SchemaVersion string `json:"schema_version"`
	// Action is one of the netpol.AuditAction* values (apply / supersede_delete
	// / deescalation_remove / gc_delete).
	Action string `json:"action"`
	// WorkloadID, Namespace identify the workload whose policy was mutated.
	WorkloadID string `json:"workload_id"`
	Namespace  string `json:"namespace"`
	// PolicyName and PolicyKind identify a single mutated policy object. Both
	// are omitempty because a deescalation_remove records the removal of a
	// workload's managed SET (BI-9), which has no single name/kind; apply,
	// supersede_delete and gc_delete carry both.
	PolicyName  string    `json:"policy_name,omitempty"`
	PolicyKind  string    `json:"policy_kind,omitempty"` // restricted / quarantined
	FSMState    string    `json:"fsm_state"`
	Result      string    `json:"result"`
	SpecSummary string    `json:"spec_summary"` // egress_allowlist / deny_all / removed
	PackageID   string    `json:"package_id,omitempty"`
	PublishedAt time.Time `json:"published_at"`
}

// policyFromEvent builds the AuditPolicy wire event from the netpol-package
// PolicyAuditEvent, stamping published_at from now. netpol owns the mutation
// facts; this adapter owns the wire framing + schema version, keeping netpol
// NATS-free (BI-3/BI-12).
func policyFromEvent(evt netpol.PolicyAuditEvent, now time.Time) AuditPolicy {
	return AuditPolicy{
		SchemaVersion: SchemaVersionPolicies,
		Action:        evt.Action,
		WorkloadID:    evt.WorkloadID,
		Namespace:     evt.Namespace,
		PolicyName:    evt.PolicyName,
		PolicyKind:    evt.PolicyKind,
		FSMState:      evt.FSMState,
		Result:        evt.Result,
		SpecSummary:   evt.SpecSummary,
		PackageID:     evt.PackageID,
		PublishedAt:   now,
	}
}
