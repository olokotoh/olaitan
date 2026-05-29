package schema

import "time"

// PodSecurityState represents the isolation state of a pod.
type PodSecurityState string

const (
	StateClean           PodSecurityState = "CLEAN"
	StateSuspicious      PodSecurityState = "SUSPICIOUS"
	StateRestricted      PodSecurityState = "RESTRICTED"
	StateQuarantined     PodSecurityState = "QUARANTINED"
	StatePreservedKilled PodSecurityState = "PRESERVED_KILLED"
)

// stateOrderMap is the static ordering of security states for transition validation.
var stateOrderMap = map[PodSecurityState]int{
	StateClean:           0,
	StateSuspicious:      1,
	StateRestricted:      2,
	StateQuarantined:     3,
	StatePreservedKilled: 4,
}

// ValidTransition returns true if moving from one state to the next is allowed.
// The FSM enforces sequential escalation and allows de-escalation to any lower state.
func ValidTransition(from, to PodSecurityState) bool {
	fromIdx, fromOk := stateOrderMap[from]
	toIdx, toOk := stateOrderMap[to]
	if !fromOk || !toOk {
		return false
	}
	// Escalation: must be exactly one step up
	if toIdx > fromIdx {
		return toIdx == fromIdx+1
	}
	// De-escalation: can drop to any lower state
	return toIdx < fromIdx
}

// StateTransition records a pod moving between security states.
//
// Story 2.2 (FSM) extends this struct with WorkloadID, PackageID, and
// Reason without renaming any existing field, so the Story 1.x
// consumers (schema.Incident embeds a []StateTransition) keep compiling
// unchanged. The Story 2.2 acceptance-criteria field names map onto
// this struct as follows (BI-2):
//
//	AC4 before_state            -> FromState
//	AC4 after_state             -> ToState
//	AC4 triggering_threat_score -> Confidence (carries ConfidenceScore.Total)
//	AC4 reason                  -> Reason (new; see the Reason* constants)
//	AC4 workload_id             -> WorkloadID (new; WorkloadIdentity canonical string)
//	AC4 package_id              -> PackageID (new; the EvidencePackage idempotency key)
//
// The schema version is tracked in docs/schema-versioning.md and the
// on-wire shape in docs/schemas/state_transition.yaml.
type StateTransition struct {
	Timestamp     time.Time        `json:"timestamp"`
	Pod           PodRef           `json:"pod"`
	FromState     PodSecurityState `json:"from_state"`
	ToState       PodSecurityState `json:"to_state"`
	TriggerType   string           `json:"trigger_type"` // "automated" or "override"
	Confidence    float64          `json:"confidence"`
	TriggerEvents []string         `json:"trigger_events,omitempty"`
	OperatorID    string           `json:"operator_id,omitempty"`
	// WorkloadID is the schema.WorkloadIdentity canonical string
	// (namespace/owner-kind/owner-name, pod-name fallback) the FSM
	// keyed this transition on (Story 2.2, AC4 workload_id).
	WorkloadID string `json:"workload_id,omitempty"`
	// PackageID is the EvidencePackage that triggered the evaluation;
	// it is the FSM idempotency key (Story 2.2, AC4 package_id, BI-5).
	PackageID string `json:"package_id,omitempty"`
	// Reason is one of the Reason* constants below and explains why the
	// FSM produced this transition (Story 2.2, AC4 reason).
	Reason string `json:"reason,omitempty"`
}

// Reason constants enumerate why the FSM (Story 2.2) produced a
// StateTransition. ReasonNoTransition is set on the record returned
// when an Evaluate call left the workload's state unchanged; it is not
// emitted to a TransitionSink (BI-5).
const (
	ReasonEscalationThresholdCrossed  = "escalation_threshold_crossed"
	ReasonDwellGuardElapsed           = "dwell_guard_elapsed"
	ReasonDeescalationCooldownExpired = "de_escalation_cooldown_expired"
	ReasonNoTransition                = "no_transition"
)
