package fsm

import (
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"

	"github.com/olokotoh/olaitan/internal/config"
	"github.com/olokotoh/olaitan/internal/schema"
)

// pinnedParams returns gopter parameters with a fixed seed so property
// suites are flake-free across runs (the Story 2.1 score_property_test.go
// precedent). MinSuccessfulTests is 1000 so AC5's ">= 1000 randomised
// event sequences" is satisfied per property: each successful run drives a
// fresh randomised sequence through the FSM.
func pinnedParams() *gopter.TestParameters {
	p := gopter.DefaultTestParameters()
	p.Rng.Seed(2222)
	p.MinSuccessfulTests = 1000
	return p
}

// propMachine builds a Machine for the property suite: AC1 thresholds, the
// AC2/AC3 default dwell/cooldown, a fake clock, and a NopSink. The clock
// is returned so a property can advance it deterministically.
func propMachine() (*Machine, *fakeClock) {
	clock := newFakeClock()
	cfg := testConfig(
		config.DefaultSuspiciousDwellSeconds,
		config.DefaultRestrictedDwellSeconds,
		config.DefaultQuarantinedDwellSeconds,
		config.DefaultDeescalationCooldownSeconds,
	)
	m, _ := newWithGetter(func() *config.Config { return cfg }, nil, NopSink{}, clock)
	return m, clock
}

func order(s schema.PodSecurityState) int { return stateOrder(s) }

// climbTo escalates "w" to target by feeding a maximal score and
// advancing the clock past each state's dwell guard between steps. It
// returns once the workload reaches target.
func climbTo(m *Machine, clock *fakeClock, target schema.PodSecurityState) {
	for order(m.State("w")) < order(target) {
		m.Evaluate("w", 100, "p")
		if order(m.State("w")) >= order(target) {
			return
		}
		// Advance past the longest dwell so the next step is permitted.
		clock.advance(time.Duration(config.DefaultRestrictedDwellSeconds+config.DefaultQuarantinedDwellSeconds+1) * time.Second)
	}
}

// TestProperty_MonotonicEscalation pins AC1: a single Evaluate never moves
// a workload more than one step in either direction, and never reaches an
// out-of-chain state.
func TestProperty_MonotonicEscalation(t *testing.T) {
	m, clock := propMachine()
	props := gopter.NewProperties(pinnedParams())
	props.Property("at most one state step per Evaluate", prop.ForAll(
		func(score float64, advanceSec uint16) bool {
			clock.advance(time.Duration(advanceSec) * time.Second)
			before := m.State("w")
			st := m.Evaluate("w", score, "p")
			after := st.ToState
			if after == schema.StatePreservedKilled {
				return false
			}
			diff := order(after) - order(before)
			if diff < -1 || diff > 1 {
				return false
			}
			// The returned record's FromState must equal the prior state.
			return st.FromState == before
		},
		gen.Float64Range(-50, 200),
		gen.UInt16(),
	))
	props.TestingRun(t)
}

// TestProperty_NoEscalationPastSuspiciousForBenign pins FR55 empirically:
// a workload whose score never exceeds the SUSPICIOUS threshold (20) never
// reaches RESTRICTED or beyond, no matter how the clock advances.
func TestProperty_NoEscalationPastSuspiciousForBenign(t *testing.T) {
	m, clock := propMachine()
	props := gopter.NewProperties(pinnedParams())
	props.Property("score <= 20 never reaches RESTRICTED+", prop.ForAll(
		func(score float64, advanceSec uint16) bool {
			clock.advance(time.Duration(advanceSec) * time.Second)
			// Constrain to the benign band [0, 20].
			st := m.Evaluate("benign", score, "p")
			return order(st.ToState) <= order(schema.StateSuspicious)
		},
		gen.Float64Range(0, 20),
		gen.UInt16(),
	))
	props.TestingRun(t)
}

// TestProperty_DeescalationOneStepPerCooldown pins AC3: starting from
// QUARANTINED, a sustained sub-threshold score de-escalates exactly one
// step per full cooldown window and never more than one step at a time.
func TestProperty_DeescalationOneStepPerCooldown(t *testing.T) {
	props := gopter.NewProperties(pinnedParams())
	props.Property("one de-escalation step per cooldown", prop.ForAll(
		func(extraSec uint16) bool {
			m, clock := propMachine()
			climbTo(m, clock, schema.StateQuarantined)
			if m.State("w") != schema.StateQuarantined {
				return false
			}
			// Advance exactly one cooldown (plus arbitrary slack) with a
			// sub-threshold score: de-escalate exactly one step.
			clock.advance(time.Duration(config.DefaultDeescalationCooldownSeconds)*time.Second + time.Duration(extraSec)*time.Second)
			st := m.Evaluate("w", 0, "p")
			return st.FromState == schema.StateQuarantined && st.ToState == schema.StateRestricted
		},
		gen.UInt16(),
	))
	props.TestingRun(t)
}

// TestProperty_DwellGuardDefersEscalation pins AC2: while the per-state
// dwell guard has not elapsed, a higher score does not escalate.
func TestProperty_DwellGuardDefersEscalation(t *testing.T) {
	props := gopter.NewProperties(pinnedParams())
	props.Property("escalation deferred within the dwell window", prop.ForAll(
		func(withinSec uint16) bool {
			m, clock := propMachine()
			// Climb to RESTRICTED. SUSPICIOUS dwell is 0 so both steps land
			// at the same instant; RESTRICTED was just entered.
			m.Evaluate("w", 100, "p")
			m.Evaluate("w", 100, "p")
			if m.State("w") != schema.StateRestricted {
				return false
			}
			dwell := config.DefaultRestrictedDwellSeconds
			// Advance strictly less than the dwell.
			within := int(withinSec) % dwell // [0, dwell)
			clock.advance(time.Duration(within) * time.Second)
			st := m.Evaluate("w", 100, "p")
			// Still RESTRICTED: escalation deferred.
			return st.FromState == st.ToState && st.ToState == schema.StateRestricted
		},
		gen.UInt16(),
	))
	props.TestingRun(t)
}

// TestProperty_Idempotent pins BI-5: re-evaluating the same workload with
// the same score at the same clock instant after the first call leaves the
// state unchanged and reports no_transition.
func TestProperty_Idempotent(t *testing.T) {
	props := gopter.NewProperties(pinnedParams())
	props.Property("repeated identical Evaluate is a no-op", prop.ForAll(
		func(score float64) bool {
			m, _ := propMachine()
			// Evaluate at a fixed instant until the state stabilises (the
			// score-justified target reached, gated only by dwell which is
			// 0 between CLEAN and SUSPICIOUS). At most three steps are
			// possible on the CLEAN..QUARANTINED chain.
			var last schema.StateTransition
			for i := 0; i < 4; i++ {
				last = m.Evaluate("w", score, "p")
			}
			stable := last.ToState
			// One more identical call at the same instant must be a no-op:
			// idempotent by construction (BI-5).
			again := m.Evaluate("w", score, "p")
			return again.FromState == stable && again.ToState == stable && again.Reason == schema.ReasonNoTransition
		},
		gen.Float64Range(-50, 200),
	))
	props.TestingRun(t)
}

// TestProperty_PreservedKilledUnreachable pins BI-7: no sequence of
// arbitrary scores and clock advances can ever drive a workload into
// PRESERVED_KILLED.
func TestProperty_PreservedKilledUnreachable(t *testing.T) {
	props := gopter.NewProperties(pinnedParams())
	props.Property("PRESERVED_KILLED is never entered", prop.ForAll(
		func(scores []float64, advances []uint16) bool {
			m, clock := propMachine()
			for i, s := range scores {
				if i < len(advances) {
					clock.advance(time.Duration(advances[i]) * time.Second)
				}
				st := m.Evaluate("w", s, "p")
				if st.ToState == schema.StatePreservedKilled {
					return false
				}
				if m.State("w") == schema.StatePreservedKilled {
					return false
				}
			}
			return true
		},
		gen.SliceOf(gen.Float64Range(-50, 200)),
		gen.SliceOf(gen.UInt16()),
	))
	props.TestingRun(t)
}
