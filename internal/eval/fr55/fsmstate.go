package fr55

import (
	"github.com/olokotoh/olaitan/internal/config"
	"github.com/olokotoh/olaitan/internal/schema"
)

// FSM band thresholds, sourced from the PRODUCTION config constants so the
// "zero transitions past SUSPICIOUS" assertion is checked against the REAL
// mapping the response controller uses (OQ4), not a re-invented one. These
// are the same defaults internal/response/fsm.Machine.resolve() reads
// (fsm.go:280-289): SUSPICIOUS = 20, RESTRICTED = 40, QUARANTINED = 70.
const (
	// SuspiciousThreshold is the lowest non-CLEAN escalation: a workload
	// enters SUSPICIOUS at or above this ThreatScore.
	SuspiciousThreshold = config.SuspiciousThreshold // 20
	// RestrictedThreshold is the NEXT threshold past SUSPICIOUS: the score
	// the FR55 bound (10.5 / 7.5) must stay under so no trial transitions
	// PAST SUSPICIOUS.
	RestrictedThreshold = config.RestrictedThreshold // 40
	// QuarantinedThreshold is the highest score band.
	QuarantinedThreshold = config.QuarantinedThreshold // 70
)

// FinalFSMState maps a ThreatScore total to the FSM state the score alone
// justifies, REPLICATING the production internal/response/fsm
// thresholds.targetState mapping (fsm.go:313-324) byte-for-byte over the
// production thresholds (OQ4). The bands are cumulative half-open
// intervals: score >= quarantined -> QUARANTINED; >= restricted ->
// RESTRICTED; >= suspicious -> SUSPICIOUS; otherwise CLEAN.
//
// The production targetState is an unexported method on an unexported
// thresholds type, so it cannot be called directly across the package
// boundary; this function mirrors its logic exactly, sourcing the
// thresholds from the same config constants the FSM resolves to, so the
// FR55 bound is asserted against the real mapping. A divergence from the
// production mapping is a FR55-harness defect to fix here, never a reason
// to weaken the bound assertion (BI-5).
func FinalFSMState(total float64) schema.PodSecurityState {
	switch {
	case total >= QuarantinedThreshold:
		return schema.StateQuarantined
	case total >= RestrictedThreshold:
		return schema.StateRestricted
	case total >= SuspiciousThreshold:
		return schema.StateSuspicious
	default:
		return schema.StateClean
	}
}

// pastSuspicious reports whether state is STRICTLY past SUSPICIOUS on the
// escalation chain (RESTRICTED / QUARANTINED / PRESERVED_KILLED). The FR55
// bound proof asserts zero trials are pastSuspicious (AC4). SUSPICIOUS
// itself is NOT "past SUSPICIOUS"; CLEAN is below it.
func pastSuspicious(state schema.PodSecurityState) bool {
	switch state {
	case schema.StateRestricted, schema.StateQuarantined, schema.StatePreservedKilled:
		return true
	default:
		return false
	}
}
