package fsm

import (
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

func (s *RecordingSink) all() []schema.StateTransition {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]schema.StateTransition, len(s.transitions))
	copy(out, s.transitions)
	return out
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
	fc.SuspiciousDwellSeconds = &suspiciousDwell
	fc.RestrictedDwellSeconds = &restrictedDwell
	fc.QuarantinedDwellSeconds = &quarantinedDwell
	fc.DeescalationCooldownSeconds = &cooldown
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

// TestEncapsulation_EvaluateIsSoleMutator pins AC6: Evaluate is the only
// exported method that mutates per-workload state. State is read-only;
// there is no other exported mutator. This is an API-shape assertion.
func TestEncapsulation_EvaluateIsSoleMutator(t *testing.T) {
	allowed := map[string]bool{
		"Evaluate": true, // sole mutator (AC6)
		"State":    true, // read-only query (BI-6)
	}
	mt := reflect.TypeOf(&Machine{})
	for i := 0; i < mt.NumMethod(); i++ {
		name := mt.Method(i).Name
		if !allowed[name] {
			t.Errorf("unexpected exported Machine method %q: only Evaluate (mutator) and State (read-only) may be exported (AC6)", name)
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
