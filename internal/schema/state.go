package schema

import "time"

// PodSecurityState represents the isolation state of a pod.
type PodSecurityState string

const (
	StateClean            PodSecurityState = "CLEAN"
	StateSuspicious       PodSecurityState = "SUSPICIOUS"
	StateRestricted       PodSecurityState = "RESTRICTED"
	StateQuarantined      PodSecurityState = "QUARANTINED"
	StatePreservedKilled  PodSecurityState = "PRESERVED_KILLED"
)

// ValidTransition returns true if moving from one state to the next is allowed.
// The FSM enforces sequential escalation and allows de-escalation to any lower state.
func ValidTransition(from, to PodSecurityState) bool {
	order := stateOrder()
	fromIdx, fromOk := order[from]
	toIdx, toOk := order[to]
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

func stateOrder() map[PodSecurityState]int {
	return map[PodSecurityState]int{
		StateClean:           0,
		StateSuspicious:      1,
		StateRestricted:      2,
		StateQuarantined:     3,
		StatePreservedKilled: 4,
	}
}

// StateTransition records a pod moving between security states.
type StateTransition struct {
	Timestamp      time.Time        `json:"timestamp"`
	Pod            PodRef           `json:"pod"`
	FromState      PodSecurityState `json:"from_state"`
	ToState        PodSecurityState `json:"to_state"`
	TriggerType    string           `json:"trigger_type"` // "automated" or "override"
	Confidence     float64          `json:"confidence"`
	TriggerEvents  []string         `json:"trigger_events,omitempty"`
	OperatorID     string           `json:"operator_id,omitempty"`
}
