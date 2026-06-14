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

// TestProperty_MonotonicEscalation pins AC1/AC4: a single Evaluate never moves
// a workload more than one state step in either direction, and never reaches an
// out-of-chain state. Story 4.1 relaxes it (BI-10): PRESERVED_KILLED is now a
// reachable terminal at ordinal 4, but it may be reached ONLY as a one-step
// escalation from QUARANTINED. Because stateOrder now returns 4 for
// PRESERVED_KILLED, the |order(after)-order(before)| <= 1 bound itself rejects
// a RESTRICTED(2) -> PRESERVED_KILLED(4) skip (diff 2); the explicit
// before==QUARANTINED check below pins the single-legal-predecessor invariant
// directly so the property cannot pass on a skip even if stateOrder drifted.
func TestProperty_MonotonicEscalation(t *testing.T) {
	m, clock := propMachine()
	props := gopter.NewProperties(pinnedParams())
	props.Property("at most one state step per Evaluate", prop.ForAll(
		func(score float64, advanceSec uint16) bool {
			clock.advance(time.Duration(advanceSec) * time.Second)
			before := m.State("w")
			st := m.Evaluate("w", score, "p")
			after := st.ToState
			if after == schema.StatePreservedKilled && st.FromState != st.ToState && before != schema.StateQuarantined {
				// An ACTUAL entry into PRESERVED_KILLED (from != to) may only
				// originate from QUARANTINED (AC4); a PK -> PK no-op is fine.
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

// TestProperty_PreservedKilledOnlyFromQuarantined pins AC4/BI-2 (the
// reframing of the Story 2.2 "PRESERVED_KILLED unreachable" property): across
// any sequence of arbitrary scores and clock advances, a workload may enter
// PRESERVED_KILLED ONLY via the single legal QUARANTINED -> PRESERVED_KILLED
// edge under the kill condition, and NEVER from any non-QUARANTINED state.
// Once in PRESERVED_KILLED it never escalates out (there is no state above
// ordinal 4). The property records the from-state on every actual transition
// into PRESERVED_KILLED and fails if any such transition originated anywhere
// but QUARANTINED, or if PRESERVED_KILLED is ever the from-state of a later
// transition (escalate-out, BI-2.2).
func TestProperty_PreservedKilledOnlyFromQuarantined(t *testing.T) {
	props := gopter.NewProperties(pinnedParams())
	props.Property("PRESERVED_KILLED entered only from QUARANTINED, never escaped", prop.ForAll(
		func(scores []float64, advances []uint16) bool {
			m, clock := propMachine()
			for i, s := range scores {
				if i < len(advances) {
					clock.advance(time.Duration(advances[i]) * time.Second)
				}
				before := m.State("w")
				st := m.Evaluate("w", s, "p")
				// An ACTUAL entry into PRESERVED_KILLED (from != to) must
				// originate from QUARANTINED on BOTH the recorded transition and
				// the observed prior state; a PK -> PK no-op is fine.
				if st.ToState == schema.StatePreservedKilled && st.FromState != st.ToState {
					if st.FromState != schema.StateQuarantined || before != schema.StateQuarantined {
						return false
					}
				}
				// Escalate-out: PRESERVED_KILLED must never be the source of an
				// actual onward transition (no state sits above ordinal 4).
				if st.FromState == schema.StatePreservedKilled && st.FromState != st.ToState {
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

// TestProperty_PreservedKilledReachableUnderKillCondition complements the
// only-from-QUARANTINED property with a liveness witness (AC4): a workload held
// at a kill-scoring level long enough genuinely DOES reach PRESERVED_KILLED, so
// the only-from-QUARANTINED property above is not vacuously true on a kill edge
// that can never fire.
func TestProperty_PreservedKilledReachableUnderKillCondition(t *testing.T) {
	props := gopter.NewProperties(pinnedParams())
	props.Property("a sustained kill-level score from QUARANTINED reaches PRESERVED_KILLED", prop.ForAll(
		func(extraSec uint16) bool {
			m, clock := propMachine()
			climbTo(m, clock, schema.StateQuarantined)
			if m.State("w") != schema.StateQuarantined {
				return false
			}
			// Hold a kill-level score (>= default 90) for the kill-sustain
			// window plus arbitrary slack; the QUARANTINED dwell also elapses.
			sustain := config.DefaultKillSustainSeconds
			// First a kill-level sample to start the at-or-above-kill window.
			m.Evaluate("w", 95, "p")
			clock.advance(time.Duration(sustain)*time.Second + time.Duration(extraSec)*time.Second)
			st := m.Evaluate("w", 95, "p")
			return st.FromState == schema.StateQuarantined && st.ToState == schema.StatePreservedKilled && st.Reason == schema.ReasonKillConditionMet
		},
		gen.UInt16(),
	))
	props.TestingRun(t)
}
