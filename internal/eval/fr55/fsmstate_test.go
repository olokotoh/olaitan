package fr55

import (
	"testing"

	"github.com/olokotoh/olaitan/internal/config"
	"github.com/olokotoh/olaitan/internal/schema"
)

// TestThresholds_MatchProductionConstants pins the FR55 thresholds to the
// production config constants (OQ4): the "zero past SUSPICIOUS" assertion
// is checked against the REAL FSM mapping, not a guess. If the production
// thresholds change, this test fails and the harness must follow.
func TestThresholds_MatchProductionConstants(t *testing.T) {
	if SuspiciousThreshold != config.SuspiciousThreshold {
		t.Errorf("SuspiciousThreshold = %v, want production %v", SuspiciousThreshold, config.SuspiciousThreshold)
	}
	if RestrictedThreshold != config.RestrictedThreshold {
		t.Errorf("RestrictedThreshold = %v, want production %v", RestrictedThreshold, config.RestrictedThreshold)
	}
	if QuarantinedThreshold != config.QuarantinedThreshold {
		t.Errorf("QuarantinedThreshold = %v, want production %v", QuarantinedThreshold, config.QuarantinedThreshold)
	}
	// The bound (10.5 / 7.5) must stay strictly below the SUSPICIOUS
	// threshold, so it never even reaches SUSPICIOUS, let alone past it.
	if SuspiciousThreshold <= 10.5 {
		t.Errorf("SUSPICIOUS threshold %v must exceed the Claude bound 10.5", SuspiciousThreshold)
	}
	if RestrictedThreshold <= SuspiciousThreshold {
		t.Errorf("RESTRICTED %v must exceed SUSPICIOUS %v (the next threshold past SUSPICIOUS)", RestrictedThreshold, SuspiciousThreshold)
	}
}

// TestFinalFSMState_BandMapping pins the score->state mapping to the
// production cumulative-band logic (fsm.go:targetState, OQ4), including the
// FR55 bounds themselves.
func TestFinalFSMState_BandMapping(t *testing.T) {
	cases := []struct {
		score float64
		want  schema.PodSecurityState
	}{
		{0, schema.StateClean},
		{7.5, schema.StateClean},  // Ollama bound -> CLEAN (below SUSPICIOUS)
		{10.5, schema.StateClean}, // Claude bound -> CLEAN (below SUSPICIOUS)
		{19.999, schema.StateClean},
		{20, schema.StateSuspicious},
		{39.999, schema.StateSuspicious},
		{40, schema.StateRestricted},
		{69.999, schema.StateRestricted},
		{70, schema.StateQuarantined},
		{100, schema.StateQuarantined},
	}
	for _, tc := range cases {
		if got := FinalFSMState(tc.score); got != tc.want {
			t.Errorf("FinalFSMState(%v) = %s, want %s", tc.score, got, tc.want)
		}
	}
}

// TestPastSuspicious pins which states count as "past SUSPICIOUS" for the
// AC4 bound assertion: SUSPICIOUS and CLEAN are NOT past it; RESTRICTED and
// above are.
func TestPastSuspicious(t *testing.T) {
	cases := []struct {
		state schema.PodSecurityState
		want  bool
	}{
		{schema.StateClean, false},
		{schema.StateSuspicious, false},
		{schema.StateRestricted, true},
		{schema.StateQuarantined, true},
		{schema.StatePreservedKilled, true},
	}
	for _, tc := range cases {
		if got := pastSuspicious(tc.state); got != tc.want {
			t.Errorf("pastSuspicious(%s) = %t, want %t", tc.state, got, tc.want)
		}
	}
}
