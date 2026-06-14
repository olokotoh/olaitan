package fsm

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/config"
	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/schema"
)

// fakeClock is a controllable Clock for dwell/cooldown tests (no real
// sleeps, BI-5).
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// RecordingSink records every published transition for assertions. It is
// the test counterpart to NopSink (Task 4.1).
type RecordingSink struct {
	mu          sync.Mutex
	transitions []schema.StateTransition
}

func (s *RecordingSink) Publish(st schema.StateTransition) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.transitions = append(s.transitions, st)
}

func (s *RecordingSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.transitions)
}

// testConfig builds a *config.Config with the AC1 thresholds (20/40/70)
// and the supplied dwell/cooldown seconds. A negative value leaves the
// pointer nil so OrDefault applies.
func testConfig(suspiciousDwell, restrictedDwell, quarantinedDwell, cooldown int) *config.Config {
	cfg := &config.Config{}
	cfg.Detection.ConfidenceBands = config.ConfidenceBands{Watch: 20, Alert: 40, Act: 70}
	fc := config.FSMConfig{}
	// A negative value leaves the corresponding pointer nil so the
	// FSMConfig OrDefault accessors apply, letting tests exercise the
	// default path. Non-negative values are set explicitly.
	if suspiciousDwell >= 0 {
		fc.SuspiciousDwellSeconds = &suspiciousDwell
	}
	if restrictedDwell >= 0 {
		fc.RestrictedDwellSeconds = &restrictedDwell
	}
	if quarantinedDwell >= 0 {
		fc.QuarantinedDwellSeconds = &quarantinedDwell
	}
	if cooldown >= 0 {
		fc.DeescalationCooldownSeconds = &cooldown
	}
	cfg.Detection.FSM = fc
	return cfg
}

// newMachineForTest builds a Machine with a static config snapshot, the
// supplied fake clock, and a recording sink (no metrics registry).
func newMachineForTest(t *testing.T, cfg *config.Config, clock Clock) (*Machine, *RecordingSink) {
	t.Helper()
	sink := &RecordingSink{}
	get := func() *config.Config { return cfg }
	m, err := newWithGetter(get, nil, sink, clock)
	if err != nil {
		t.Fatalf("newWithGetter: %v", err)
	}
	return m, sink
}

func TestNew_NilSinkRejected(t *testing.T) {
	get := func() *config.Config { return nil }
	if _, err := newWithGetter(get, nil, nil, nil); err == nil {
		t.Fatal("newWithGetter with nil sink: want error, got nil")
	}
}

func TestNopSink_Publish(t *testing.T) {
	// NopSink must accept any transition without panicking (the Epic 2
	// default; Stories 2.3/2.8 wire real sinks).
	NopSink{}.Publish(schema.StateTransition{ToState: schema.StateSuspicious})
}

// TestMetricsRegistered_AndUpdated pins Task 5: the three FSM metrics
// register against a real registry and update on Evaluate. It exercises
// registerMetrics, recordMetrics, the dwell histogram, and the
// active-workloads gauge that the nil-registry tests skip.
func TestMetricsRegistered_AndUpdated(t *testing.T) {
	clock := newFakeClock()
	reg := metrics.NewRegistry()
	cfg := testConfig(0, 120, 120, 600)
	m, err := newWithGetter(func() *config.Config { return cfg }, reg, NopSink{}, clock)
	if err != nil {
		t.Fatalf("newWithGetter with registry: %v", err)
	}

	// Drive two workloads through transitions so the gauge has multiple
	// states populated and the dwell histogram observes a real dwell.
	m.Evaluate("a", 100, "p") // CLEAN -> SUSPICIOUS (escalation)
	clock.advance(5 * time.Second)
	m.Evaluate("a", 100, "p") // SUSPICIOUS -> RESTRICTED, dwell ~5s observed
	m.Evaluate("b", 25, "p")  // CLEAN -> SUSPICIOUS
	m.Evaluate("a", 100, "p") // RESTRICTED self (dwell guard) -> no_transition

	mfs, gerr := reg.Gatherer().Gather()
	if gerr != nil {
		t.Fatalf("gather: %v", gerr)
	}
	seen := map[string]bool{}
	for _, mf := range mfs {
		seen[mf.GetName()] = true
	}
	for _, name := range []string{
		"olaitan_response_fsm_transitions_total",
		"olaitan_response_fsm_dwell_seconds",
		"olaitan_response_fsm_active_workloads",
	} {
		if !seen[name] {
			t.Errorf("metric %q not registered/exported", name)
		}
	}

	// active_workloads gauge for SUSPICIOUS must be >= 1 (workload "b").
	for _, mf := range mfs {
		if mf.GetName() != "olaitan_response_fsm_active_workloads" {
			continue
		}
		var foundSuspicious bool
		for _, mtr := range mf.GetMetric() {
			for _, lp := range mtr.GetLabel() {
				if lp.GetName() == "state" && lp.GetValue() == string(schema.StateSuspicious) {
					foundSuspicious = true
					if mtr.GetGauge().GetValue() < 1 {
						t.Errorf("active_workloads{state=SUSPICIOUS} = %v, want >= 1", mtr.GetGauge().GetValue())
					}
				}
			}
		}
		if !foundSuspicious {
			t.Error("active_workloads gauge missing the SUSPICIOUS state series")
		}
	}
}

// TestNew_RegisterMetricsTwiceFails pins that a duplicate registration
// (same registry, same metric names) surfaces an error rather than
// panicking, matching the score package contract.
func TestNew_RegisterMetricsTwiceFails(t *testing.T) {
	reg := metrics.NewRegistry()
	get := func() *config.Config { return nil }
	if _, err := newWithGetter(get, reg, NopSink{}, newFakeClock()); err != nil {
		t.Fatalf("first registration: %v", err)
	}
	if _, err := newWithGetter(get, reg, NopSink{}, newFakeClock()); err == nil {
		t.Fatal("second registration on the same registry: want error, got nil")
	}
}

// TestEscalation_SingleStepAtBoundaries pins AC1: each threshold crossing
// escalates exactly one state, never skipping. SUSPICIOUS dwell is 0 so a
// single high score walks CLEAN -> SUSPICIOUS -> RESTRICTED ... only one
// step per Evaluate.
func TestEscalation_SingleStepAtBoundaries(t *testing.T) {
	clock := newFakeClock()
	// All dwell guards 0 so escalation is purely score-driven; isolates
	// the one-step invariant from the dwell logic (covered separately).
	m, sink := newMachineForTest(t, testConfig(0, 0, 0, 600), clock)

	// A score of 100 justifies QUARANTINED but the FSM must step up one
	// state at a time: SUSPICIOUS, then RESTRICTED, then QUARANTINED.
	wantSteps := []struct {
		from, to schema.PodSecurityState
	}{
		{schema.StateClean, schema.StateSuspicious},
		{schema.StateSuspicious, schema.StateRestricted},
		{schema.StateRestricted, schema.StateQuarantined},
	}
	for i, step := range wantSteps {
		st := m.Evaluate("w", 100, "pkg")
		if st.FromState != step.from || st.ToState != step.to {
			t.Fatalf("step %d: got %s->%s, want %s->%s", i, st.FromState, st.ToState, step.from, step.to)
		}
		if st.Confidence != 100 {
			t.Fatalf("step %d: confidence = %v, want 100", i, st.Confidence)
		}
	}
	// Already QUARANTINED (terminal): a further high score is no_transition.
	st := m.Evaluate("w", 100, "pkg")
	if st.FromState != st.ToState {
		t.Fatalf("terminal: got %s->%s, want no transition", st.FromState, st.ToState)
	}
	if st.ToState != schema.StateQuarantined {
		t.Fatalf("terminal: state = %s, want QUARANTINED", st.ToState)
	}
	if st.Reason != schema.ReasonNoTransition {
		t.Fatalf("terminal: reason = %q, want no_transition", st.Reason)
	}
	if got := sink.count(); got != 3 {
		t.Fatalf("sink emissions = %d, want 3 (one per actual change)", got)
	}
}

// climbToQuarantinedForKill drives "w" to QUARANTINED with all dwell guards 0
// (so the three escalation steps land at the same clock instant, fixing
// stateEnteredAt to now) and returns the machine + sink. The default kill
// knobs (90 / 300 s) apply via testConfig leaving them nil.
func climbToQuarantinedForKill(t *testing.T, clock *fakeClock) (*Machine, *RecordingSink) {
	t.Helper()
	m, sink := newMachineForTest(t, testConfig(0, 0, 0, 600), clock)
	for i := 0; i < 3; i++ {
		m.Evaluate("w", 100, "pkg")
	}
	if s := m.State("w"); s != schema.StateQuarantined {
		t.Fatalf("setup: state = %s, want QUARANTINED", s)
	}
	return m, sink
}

// TestKill_FiresAfterSustainedFromQuarantined pins Story 4.1 AC1/BI-5: a
// QUARANTINED workload whose score holds at or above the kill threshold (90)
// for the kill-sustain window (300 s), with at least that long since the
// QUARANTINED apply, escalates to PRESERVED_KILLED with reason kill_condition_met.
func TestKill_FiresAfterSustainedFromQuarantined(t *testing.T) {
	clock := newFakeClock()
	m, sink := climbToQuarantinedForKill(t, clock)
	before := sink.count()

	// Start the at-or-above-kill window with a kill-level sample, then advance
	// past both the sustain window AND the QUARANTINED dwell-since-apply.
	m.Evaluate("w", 95, "pkg") // no kill yet (window just opened)
	clock.advance(time.Duration(config.DefaultKillSustainSeconds+1) * time.Second)
	st := m.Evaluate("w", 95, "pkg")

	if st.FromState != schema.StateQuarantined || st.ToState != schema.StatePreservedKilled {
		t.Fatalf("kill: got %s->%s, want QUARANTINED->PRESERVED_KILLED", st.FromState, st.ToState)
	}
	if st.Reason != schema.ReasonKillConditionMet {
		t.Errorf("kill reason = %q, want kill_condition_met", st.Reason)
	}
	if st.TriggerType != "automated" {
		t.Errorf("kill trigger = %q, want automated", st.TriggerType)
	}
	if sink.count() != before+1 {
		t.Errorf("kill emitted %d transitions, want 1", sink.count()-before)
	}
}

// TestKill_DoesNotFireBeforeSustainElapsed pins BI-5: a QUARANTINED workload
// whose score is at kill level but for LESS than the sustain window is not
// killed (neither the at-or-above-kill window nor the QUARANTINED dwell has
// elapsed).
func TestKill_DoesNotFireBeforeSustainElapsed(t *testing.T) {
	clock := newFakeClock()
	m, _ := climbToQuarantinedForKill(t, clock)

	m.Evaluate("w", 95, "pkg")
	clock.advance(time.Duration(config.DefaultKillSustainSeconds-10) * time.Second) // just short
	st := m.Evaluate("w", 95, "pkg")
	if st.ToState == schema.StatePreservedKilled {
		t.Fatalf("kill fired before the sustain window elapsed: %s->%s", st.FromState, st.ToState)
	}
	if st.FromState != schema.StateQuarantined || st.ToState != schema.StateQuarantined {
		t.Fatalf("expected no transition (stay QUARANTINED), got %s->%s", st.FromState, st.ToState)
	}
}

// TestKill_ScoreDipResetsSustainWindow pins BI-5: a dip below the kill
// threshold resets the at-or-above-kill window, so the kill clock restarts even
// though the QUARANTINED dwell continues to accrue.
func TestKill_ScoreDipResetsSustainWindow(t *testing.T) {
	clock := newFakeClock()
	m, _ := climbToQuarantinedForKill(t, clock)

	// Hold kill-level for almost the whole window, then dip below 90 (but stay
	// at or above the QUARANTINED entry threshold 70 so we do not de-escalate).
	m.Evaluate("w", 95, "pkg")
	clock.advance(time.Duration(config.DefaultKillSustainSeconds-5) * time.Second)
	dip := m.Evaluate("w", 80, "pkg") // resets the at-or-above-kill window
	if dip.ToState != schema.StateQuarantined {
		t.Fatalf("dip should not change state, got %s->%s", dip.FromState, dip.ToState)
	}

	// Advance just past where the kill WOULD have fired without the dip; it must
	// NOT fire because the dip reset the window.
	clock.advance(10 * time.Second)
	st := m.Evaluate("w", 95, "pkg")
	if st.ToState == schema.StatePreservedKilled {
		t.Fatal("kill fired even though a sub-90 dip reset the sustain window (BI-5)")
	}

	// Now hold kill-level for a full fresh window: the kill fires.
	clock.advance(time.Duration(config.DefaultKillSustainSeconds+1) * time.Second)
	st = m.Evaluate("w", 95, "pkg")
	if st.ToState != schema.StatePreservedKilled {
		t.Fatalf("kill did not fire after a fresh full sustain window, got %s->%s", st.FromState, st.ToState)
	}
}

// TestKill_BenignNeverKills pins BI-12/FR55 at the unit level: a QUARANTINED
// workload whose score sits in the benign band can never be killed (and indeed
// de-escalates), since the kill threshold 90 is far above the benign band.
func TestKill_DwellSinceQuarantineRequired(t *testing.T) {
	clock := newFakeClock()
	m, _ := climbToQuarantinedForKill(t, clock)

	// Immediately feed kill-level scores at the SAME instant QUARANTINED was
	// applied: the QUARANTINED dwell-since-apply is zero, so even a high score
	// cannot kill on the first post-quarantine evaluation.
	st := m.Evaluate("w", 100, "pkg")
	if st.ToState == schema.StatePreservedKilled {
		t.Fatal("kill fired with zero dwell since the QUARANTINED apply (BI-5.1)")
	}
}

// TestEscalation_BoundaryScores pins the band edges: a score exactly at a
// threshold is inclusive (>=). 19 stays CLEAN, 20 reaches SUSPICIOUS.
func TestEscalation_BoundaryScores(t *testing.T) {
	clock := newFakeClock()
	m, _ := newMachineForTest(t, testConfig(0, 0, 0, 600), clock)

	if st := m.Evaluate("a", 19, "p"); st.ToState != schema.StateClean {
		t.Fatalf("score 19: state = %s, want CLEAN", st.ToState)
	}
	if st := m.Evaluate("b", 20, "p"); st.ToState != schema.StateSuspicious {
		t.Fatalf("score 20: state = %s, want SUSPICIOUS", st.ToState)
	}
}

// TestDwellGuard_DefersThenAllows pins AC2: in RESTRICTED with a 120 s
// dwell, a QUARANTINED-level score is held until the dwell elapses.
func TestDwellGuard_DefersThenAllows(t *testing.T) {
	clock := newFakeClock()
	// SUSPICIOUS dwell 0 so we can climb to RESTRICTED quickly; RESTRICTED
	// dwell 120 s is the guard under test (the escalation OUT of RESTRICTED
	// is gated by RESTRICTED's own dwell, AC2).
	m, sink := newMachineForTest(t, testConfig(0, 120, 120, 600), clock)

	// Climb to RESTRICTED (two single steps).
	m.Evaluate("w", 100, "p")       // CLEAN -> SUSPICIOUS
	st := m.Evaluate("w", 100, "p") // SUSPICIOUS -> RESTRICTED
	if st.ToState != schema.StateRestricted {
		t.Fatalf("setup: state = %s, want RESTRICTED", st.ToState)
	}
	// Entered RESTRICTED at the current clock. Quarantined-level score now
	// must be deferred: dwell not elapsed.
	clock.advance(119 * time.Second)
	st = m.Evaluate("w", 100, "p")
	if st.FromState != st.ToState {
		t.Fatalf("within dwell: got %s->%s, want deferred (no transition)", st.FromState, st.ToState)
	}
	if m.State("w") != schema.StateRestricted {
		t.Fatalf("within dwell: state = %s, want RESTRICTED", m.State("w"))
	}
	// Advance past the 120 s dwell; now the escalation is allowed.
	clock.advance(2 * time.Second)
	st = m.Evaluate("w", 100, "p")
	if st.ToState != schema.StateQuarantined {
		t.Fatalf("after dwell: state = %s, want QUARANTINED", st.ToState)
	}
	if st.Reason != schema.ReasonDwellGuardElapsed {
		t.Fatalf("after dwell: reason = %q, want dwell_guard_elapsed", st.Reason)
	}
	// Two actual escalations to RESTRICTED + one to QUARANTINED = 3.
	if got := sink.count(); got != 3 {
		t.Fatalf("sink emissions = %d, want 3", got)
	}
}

// TestDeescalation_OneStepPerCooldown pins AC3: a sustained sub-threshold
// score de-escalates one step per cooldown elapse, and a single low
// sample does not de-escalate.
func TestDeescalation_OneStepPerCooldown(t *testing.T) {
	clock := newFakeClock()
	m, _ := newMachineForTest(t, testConfig(0, 0, 0, 600), clock)

	// Climb to QUARANTINED.
	m.Evaluate("w", 100, "p")
	m.Evaluate("w", 100, "p")
	st := m.Evaluate("w", 100, "p")
	if st.ToState != schema.StateQuarantined {
		t.Fatalf("setup: state = %s, want QUARANTINED", st.ToState)
	}

	// A single low sample must NOT de-escalate (cooldown not elapsed).
	st = m.Evaluate("w", 0, "p")
	if st.FromState != st.ToState {
		t.Fatalf("single low sample: got %s->%s, want no de-escalation", st.FromState, st.ToState)
	}

	// Sustain sub-threshold for the full cooldown: de-escalate one step.
	clock.advance(600 * time.Second)
	st = m.Evaluate("w", 0, "p")
	if st.ToState != schema.StateRestricted {
		t.Fatalf("after cooldown: state = %s, want RESTRICTED", st.ToState)
	}
	if st.Reason != schema.ReasonDeescalationCooldownExpired {
		t.Fatalf("after cooldown: reason = %q, want de_escalation_cooldown_expired", st.Reason)
	}
	// Next step requires a fresh full cooldown window (anchor reset).
	st = m.Evaluate("w", 0, "p")
	if st.FromState != st.ToState {
		t.Fatalf("immediately after step: got %s->%s, want no further de-escalation", st.FromState, st.ToState)
	}
	clock.advance(600 * time.Second)
	st = m.Evaluate("w", 0, "p")
	if st.ToState != schema.StateSuspicious {
		t.Fatalf("second cooldown: state = %s, want SUSPICIOUS", st.ToState)
	}
	clock.advance(600 * time.Second)
	st = m.Evaluate("w", 0, "p")
	if st.ToState != schema.StateClean {
		t.Fatalf("third cooldown: state = %s, want CLEAN", st.ToState)
	}
}

// TestDeescalation_RollingResetsOnSpike pins the rolling semantics: a
// mid-window score back at or above the threshold restarts the cooldown
// so de-escalation is deferred.
func TestDeescalation_RollingResetsOnSpike(t *testing.T) {
	clock := newFakeClock()
	m, _ := newMachineForTest(t, testConfig(0, 0, 0, 600), clock)

	m.Evaluate("w", 50, "p") // CLEAN -> SUSPICIOUS
	if m.State("w") != schema.StateSuspicious {
		t.Fatalf("setup: state = %s, want SUSPICIOUS", m.State("w"))
	}
	// Sub-threshold for 599 s, then one at-threshold sample resets the
	// anchor.
	clock.advance(599 * time.Second)
	m.Evaluate("w", 0, "p")
	clock.advance(1 * time.Second)
	m.Evaluate("w", 25, "p") // at/above SUSPICIOUS threshold -> resets anchor
	// Now even after 599 more seconds, the window is short.
	clock.advance(599 * time.Second)
	st := m.Evaluate("w", 0, "p")
	if st.FromState != st.ToState {
		t.Fatalf("after spike reset: got %s->%s, want no de-escalation", st.FromState, st.ToState)
	}
	clock.advance(1 * time.Second)
	st = m.Evaluate("w", 0, "p")
	if st.ToState != schema.StateClean {
		t.Fatalf("after full window: state = %s, want CLEAN", st.ToState)
	}
}

// TestIdempotency_RepeatedSameInputs pins BI-5: re-evaluating the same
// (workload, score, time) yields the same result and emits no duplicate.
func TestIdempotency_RepeatedSameInputs(t *testing.T) {
	clock := newFakeClock()
	m, sink := newMachineForTest(t, testConfig(0, 0, 0, 600), clock)

	// Score 25 justifies only SUSPICIOUS, so once there the FSM self-loops
	// (target == current), which is the steady state idempotency exercises.
	first := m.Evaluate("w", 25, "pkg-1") // CLEAN -> SUSPICIOUS, one emission
	if first.FromState != schema.StateClean || first.ToState != schema.StateSuspicious {
		t.Fatalf("first: got %s->%s", first.FromState, first.ToState)
	}
	for i := 0; i < 5; i++ {
		st := m.Evaluate("w", 25, "pkg-1") // same inputs, same clock
		if st.FromState != schema.StateSuspicious || st.ToState != schema.StateSuspicious {
			t.Fatalf("repeat %d: got %s->%s, want SUSPICIOUS self-loop", i, st.FromState, st.ToState)
		}
		if st.Reason != schema.ReasonNoTransition {
			t.Fatalf("repeat %d: reason = %q, want no_transition", i, st.Reason)
		}
	}
	if got := sink.count(); got != 1 {
		t.Fatalf("sink emissions = %d, want 1 (no duplicate on idempotent repeats)", got)
	}
}

// TestState_UnknownWorkloadIsCleanAndNotInserted pins AC6/BI-6: State is a
// read-only query; an unseen workload reports CLEAN without being inserted.
func TestState_UnknownWorkloadIsCleanAndNotInserted(t *testing.T) {
	clock := newFakeClock()
	m, _ := newMachineForTest(t, testConfig(0, 0, 0, 600), clock)

	if got := m.State("never-seen"); got != schema.StateClean {
		t.Fatalf("unknown workload: state = %s, want CLEAN", got)
	}
	m.mu.RLock()
	_, present := m.states["never-seen"]
	m.mu.RUnlock()
	if present {
		t.Fatal("State inserted an entry for an unseen workload; it must be read-only")
	}
}

// TestCurrentState_TrackedFlag pins Story 2.6 BI-2c: CurrentState reports ok=true
// only for a tracked workload and (CLEAN, false) for a never-seen one, without
// inserting it. The netpol StateOracle keys the de-escalation reconcile on this.
func TestCurrentState_TrackedFlag(t *testing.T) {
	clock := newFakeClock()
	m, _ := newMachineForTest(t, testConfig(0, 0, 0, 600), clock)

	// Unknown workload: (CLEAN, false), not inserted.
	if s, ok := m.CurrentState("never-seen"); ok || s != schema.StateClean {
		t.Fatalf("CurrentState(unknown) = (%s, %v), want (CLEAN, false)", s, ok)
	}
	m.mu.RLock()
	_, present := m.states["never-seen"]
	m.mu.RUnlock()
	if present {
		t.Fatal("CurrentState inserted an entry for an unseen workload; it must be read-only")
	}

	// A tracked workload at RESTRICTED reports (RESTRICTED, true).
	m.Evaluate("w", 50, "pkg-1") // CLEAN -> SUSPICIOUS (zero dwell)
	m.Evaluate("w", 50, "pkg-2") // SUSPICIOUS -> RESTRICTED
	if s, ok := m.CurrentState("w"); !ok || s != schema.StateRestricted {
		t.Fatalf("CurrentState(w) = (%s, %v), want (RESTRICTED, true)", s, ok)
	}
}

// TestEncapsulation_EvaluateIsSoleMutator pins AC6: at runtime Evaluate is
// the only exported method that mutates per-workload state. State is
// read-only. Story 2.3 adds Restore as the single sanctioned startup-only
// rehydration mutator (it seeds the map from durable Redis before the
// consumer starts and is in-package, so external code still cannot touch
// workloadState directly). This is an API-shape assertion.
func TestEncapsulation_EvaluateIsSoleMutator(t *testing.T) {
	allowed := map[string]bool{
		"Evaluate":        true, // sole AUTOMATED (score-driven) mutator (AC6)
		"State":           true, // read-only query (BI-6)
		"CurrentState":    true, // read-only query with tracked flag (Story 2.6 BI-2c)
		"Restore":         true, // startup-only rehydration mutator (Story 2.3 BI-5)
		"Pin":             true, // operator-override mutator (Story 2.7 BI-2)
		"ReleasePin":      true, // operator-override release mutator (Story 2.7 BI-2)
		"IsPinned":        true, // read-only override-pin query (Story 2.7 BI-8)
		"PinnedWorkloads": true, // read-only override-pin set query (Story 2.7 BI-4)
	}
	mt := reflect.TypeOf(&Machine{})
	for i := 0; i < mt.NumMethod(); i++ {
		name := mt.Method(i).Name
		if !allowed[name] {
			t.Errorf("unexpected exported Machine method %q: only Evaluate (runtime mutator), State (read-only), and Restore (startup rehydration) may be exported (AC6 + Story 2.3 BI-5)", name)
		}
	}
}

// TestEdge_ScoreClampingBoundaries pins the clamp at the band edges and
// out-of-range inputs (Task 7.6). PRESERVED_KILLED is never produced.
func TestEdge_ScoreClampingBoundaries(t *testing.T) {
	clock := newFakeClock()
	cases := []struct {
		score float64
		want  schema.PodSecurityState
	}{
		{-50, schema.StateClean},
		{0, schema.StateClean},
		{20, schema.StateSuspicious},
		{40, schema.StateSuspicious}, // one step up from CLEAN even though 40 justifies RESTRICTED
		{70, schema.StateSuspicious}, // one step up from CLEAN
		{200, schema.StateSuspicious},
	}
	for _, tc := range cases {
		m, _ := newMachineForTest(t, testConfig(0, 0, 0, 600), clock)
		st := m.Evaluate("w", tc.score, "p")
		if st.ToState != tc.want {
			t.Errorf("score %v: state = %s, want %s", tc.score, st.ToState, tc.want)
		}
		if st.ToState == schema.StatePreservedKilled {
			t.Errorf("score %v: reached PRESERVED_KILLED (must be unreachable, BI-7)", tc.score)
		}
	}
}

// TestEvaluate_NilConfigUsesDefaults pins the fall-through: a nil snapshot
// yields the Story 2.2 defaults so the machine is always well-defined.
func TestEvaluate_NilConfigUsesDefaults(t *testing.T) {
	clock := newFakeClock()
	sink := &RecordingSink{}
	m, err := newWithGetter(func() *config.Config { return nil }, nil, sink, clock)
	if err != nil {
		t.Fatalf("newWithGetter: %v", err)
	}
	// Default SUSPICIOUS threshold is 20; a score of 25 escalates one step.
	st := m.Evaluate("w", 25, "p")
	if st.ToState != schema.StateSuspicious {
		t.Fatalf("nil config: state = %s, want SUSPICIOUS (default thresholds)", st.ToState)
	}
}

// TestNew_RealClockDefault pins that New defaults a nil clock to the real
// wall clock and does not panic.
func TestNew_RealClockDefault(t *testing.T) {
	m, err := New(nil, nil, NopSink{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if m.clock == nil {
		t.Fatal("New left clock nil; want real-clock default")
	}
	// A real-clock Evaluate must still work end-to-end.
	if st := m.Evaluate("w", 50, "p"); st.ToState != schema.StateSuspicious {
		t.Fatalf("real clock evaluate: state = %s, want SUSPICIOUS", st.ToState)
	}
}

// --- Story 2.7 operator override (Pin/ReleasePin/Evaluate defer) ---

// TestPin_EmitsOverrideTransition pins Task 2.5: a Pin to a different state
// emits exactly one transition through the sink with TriggerType "override"
// and Reason operator_override (BI-7, the override's authoritative entry).
func TestPin_EmitsOverrideTransition(t *testing.T) {
	clock := newFakeClock()
	m, sink := newMachineForTest(t, testConfig(0, 0, 0, 600), clock)

	if err := m.Pin("w", schema.StateRestricted, "alice"); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	if sink.count() != 1 {
		t.Fatalf("Pin emitted %d transitions, want exactly 1", sink.count())
	}
	st := sink.transitions[0]
	if st.ToState != schema.StateRestricted || st.FromState != schema.StateClean {
		t.Errorf("pin transition = %s->%s, want CLEAN->RESTRICTED", st.FromState, st.ToState)
	}
	if st.TriggerType != "override" {
		t.Errorf("pin TriggerType = %q, want override", st.TriggerType)
	}
	if st.Reason != schema.ReasonOperatorOverride {
		t.Errorf("pin Reason = %q, want operator_override", st.Reason)
	}
	if st.OperatorID != "alice" {
		t.Errorf("pin OperatorID = %q, want alice", st.OperatorID)
	}
	if s, pinned := m.IsPinned("w"); !pinned || s != schema.StateRestricted {
		t.Errorf("IsPinned(w) = (%s, %v), want (RESTRICTED, true)", s, pinned)
	}
}

// TestPin_RejectsInvalidTarget pins the Story 4.1 reframing of Story 2.7 BI-5:
// an unknown state returns ErrInvalidOverrideState and mutates nothing.
// PRESERVED_KILLED is no longer unconditionally rejected (Story 4.1 admits it
// as an override target from QUARANTINED, BI-6); from a non-QUARANTINED current
// state it is still rejected, but that is exercised in
// TestPin_RejectsPreservedKilledFromNonQuarantined below.
func TestPin_RejectsInvalidTarget(t *testing.T) {
	clock := newFakeClock()
	m, sink := newMachineForTest(t, testConfig(0, 0, 0, 600), clock)

	for _, bad := range []schema.PodSecurityState{"BOGUS", "preserved_killed", ""} {
		if err := m.Pin("w", bad, ""); !errors.Is(err, ErrInvalidOverrideState) {
			t.Errorf("Pin(%q) = %v, want ErrInvalidOverrideState", bad, err)
		}
	}
	if sink.count() != 0 {
		t.Fatalf("invalid pin emitted %d transitions, want 0", sink.count())
	}
	if _, pinned := m.IsPinned("w"); pinned {
		t.Error("invalid pin left the workload pinned")
	}
}

// TestPin_AcceptsPreservedKilledFromQuarantined pins Story 4.1 AC2/BI-6: an
// operator may pin a QUARANTINED workload to PRESERVED_KILLED; the override
// emits one transition with TriggerType "override" and Reason operator_override.
func TestPin_AcceptsPreservedKilledFromQuarantined(t *testing.T) {
	clock := newFakeClock()
	m, sink := newMachineForTest(t, testConfig(0, 0, 0, 600), clock)

	// Pin to QUARANTINED first (an operator may multi-step pin), then to PK.
	if err := m.Pin("w", schema.StateQuarantined, "alice"); err != nil {
		t.Fatalf("Pin QUARANTINED: %v", err)
	}
	if err := m.Pin("w", schema.StatePreservedKilled, "alice"); err != nil {
		t.Fatalf("Pin PRESERVED_KILLED from QUARANTINED: %v, want nil", err)
	}
	if s := m.State("w"); s != schema.StatePreservedKilled {
		t.Fatalf("after pin, state = %s, want PRESERVED_KILLED", s)
	}
	// Two pins => two transitions; the second is the kill override.
	if sink.count() != 2 {
		t.Fatalf("emitted %d transitions, want 2 (QUARANTINED then PRESERVED_KILLED)", sink.count())
	}
	last := sink.transitions[1]
	if last.FromState != schema.StateQuarantined || last.ToState != schema.StatePreservedKilled {
		t.Errorf("kill override = %s->%s, want QUARANTINED->PRESERVED_KILLED", last.FromState, last.ToState)
	}
	if last.TriggerType != "override" || last.Reason != schema.ReasonOperatorOverride {
		t.Errorf("kill override trigger=%q reason=%q, want override/operator_override", last.TriggerType, last.Reason)
	}
	if last.OperatorID != "alice" {
		t.Errorf("kill override OperatorID = %q, want alice", last.OperatorID)
	}
}

// TestPin_RejectsPreservedKilledFromNonQuarantined pins the BI-6.3 only-from-
// QUARANTINED guard: an operator may NOT skip a RESTRICTED (or any non-
// QUARANTINED) workload straight to PRESERVED_KILLED via Pin's multi-step
// latitude. The reject mutates nothing.
func TestPin_RejectsPreservedKilledFromNonQuarantined(t *testing.T) {
	clock := newFakeClock()
	for _, from := range []schema.PodSecurityState{
		schema.StateClean, schema.StateSuspicious, schema.StateRestricted,
	} {
		m, sink := newMachineForTest(t, testConfig(0, 0, 0, 600), clock)
		if from != schema.StateClean {
			if err := m.Pin("w", from, "alice"); err != nil {
				t.Fatalf("setup pin to %s: %v", from, err)
			}
		}
		baseline := sink.count()
		if err := m.Pin("w", schema.StatePreservedKilled, "mallory"); !errors.Is(err, ErrInvalidOverrideState) {
			t.Errorf("Pin PRESERVED_KILLED from %s = %v, want ErrInvalidOverrideState", from, err)
		}
		if s := m.State("w"); s == schema.StatePreservedKilled {
			t.Errorf("rejected skip-into left workload at PRESERVED_KILLED (from %s)", from)
		}
		if sink.count() != baseline {
			t.Errorf("rejected skip-into emitted a transition (from %s)", from)
		}
	}
}

// TestPin_IdempotentSameState pins BI-8: re-pinning to the SAME state emits
// no further transition but keeps the workload pinned.
func TestPin_IdempotentSameState(t *testing.T) {
	clock := newFakeClock()
	m, sink := newMachineForTest(t, testConfig(0, 0, 0, 600), clock)

	if err := m.Pin("w", schema.StateRestricted, ""); err != nil {
		t.Fatalf("first Pin: %v", err)
	}
	if err := m.Pin("w", schema.StateRestricted, ""); err != nil {
		t.Fatalf("second Pin: %v", err)
	}
	if sink.count() != 1 {
		t.Fatalf("idempotent re-pin emitted %d transitions, want 1 (only the first)", sink.count())
	}
	if _, pinned := m.IsPinned("w"); !pinned {
		t.Error("re-pin cleared the pin flag")
	}
}

// TestEvaluate_NoOpWhilePinned pins the FR38 defer (BI-2): a pinned workload
// returns no_transition for ANY score and never escalates/de-escalates, and
// the dwell/cooldown timers are not advanced.
func TestEvaluate_NoOpWhilePinned(t *testing.T) {
	clock := newFakeClock()
	m, sink := newMachineForTest(t, testConfig(0, 0, 0, 600), clock)

	if err := m.Pin("w", schema.StateSuspicious, ""); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	sinkBefore := sink.count()

	// A maximal score would normally drive escalation; while pinned it must not.
	for i := 0; i < 5; i++ {
		clock.advance(time.Hour)
		st := m.Evaluate("w", 100, "p")
		if st.FromState != schema.StateSuspicious || st.ToState != schema.StateSuspicious {
			t.Fatalf("pinned Evaluate = %s->%s, want SUSPICIOUS->SUSPICIOUS", st.FromState, st.ToState)
		}
		if st.Reason != schema.ReasonNoTransition {
			t.Errorf("pinned Evaluate Reason = %q, want no_transition", st.Reason)
		}
	}
	if sink.count() != sinkBefore {
		t.Errorf("pinned Evaluate fired the sink %d extra times, want 0", sink.count()-sinkBefore)
	}
	if m.State("w") != schema.StateSuspicious {
		t.Errorf("pinned workload drifted to %s, want SUSPICIOUS", m.State("w"))
	}
}

// TestReleasePin_ResumesScoreDrivenControl pins BI-6: after release the next
// Evaluate runs the normal escalation logic from the released state.
func TestReleasePin_ResumesScoreDrivenControl(t *testing.T) {
	clock := newFakeClock()
	m, _ := newMachineForTest(t, testConfig(0, 0, 0, 600), clock)

	if err := m.Pin("w", schema.StateSuspicious, ""); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	resumed, ok := m.ReleasePin("w")
	if !ok || resumed != schema.StateSuspicious {
		t.Fatalf("ReleasePin = (%s, %v), want (SUSPICIOUS, true)", resumed, ok)
	}
	if _, pinned := m.IsPinned("w"); pinned {
		t.Fatal("ReleasePin did not clear the pin flag")
	}
	// A high score now escalates one step from the released SUSPICIOUS state.
	st := m.Evaluate("w", 100, "p")
	if st.FromState != schema.StateSuspicious || st.ToState != schema.StateRestricted {
		t.Fatalf("post-release Evaluate = %s->%s, want SUSPICIOUS->RESTRICTED (score-driven re-evaluation)", st.FromState, st.ToState)
	}
}

// TestReleasePin_UnknownWorkload pins the ok=false branch.
func TestReleasePin_UnknownWorkload(t *testing.T) {
	clock := newFakeClock()
	m, _ := newMachineForTest(t, testConfig(0, 0, 0, 600), clock)
	if _, ok := m.ReleasePin("never-seen"); ok {
		t.Error("ReleasePin(unknown) ok = true, want false")
	}
}

// TestPin_CleanRoutesRemoval pins BI-7: a pin to CLEAN from a higher state
// emits a transition INTO CLEAN (which the netpol manager treats as a removal
// of all managed policies). We assert the sink sees the CLEAN transition.
func TestPin_CleanRoutesRemoval(t *testing.T) {
	clock := newFakeClock()
	m, sink := newMachineForTest(t, testConfig(0, 0, 0, 600), clock)

	if err := m.Pin("w", schema.StateQuarantined, ""); err != nil {
		t.Fatalf("Pin QUARANTINED: %v", err)
	}
	if err := m.Pin("w", schema.StateClean, ""); err != nil {
		t.Fatalf("Pin CLEAN: %v", err)
	}
	last := sink.transitions[len(sink.transitions)-1]
	if last.ToState != schema.StateClean || last.FromState != schema.StateQuarantined {
		t.Errorf("re-pin transition = %s->%s, want QUARANTINED->CLEAN (removal path)", last.FromState, last.ToState)
	}
	if last.TriggerType != "override" {
		t.Errorf("re-pin TriggerType = %q, want override", last.TriggerType)
	}
}
