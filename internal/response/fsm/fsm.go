// Package fsm implements the Story 2.2 deterministic response-ring
// finite state machine (FR31/FR32).
//
// The FSM consumes ThreatScores and drives a workload one step at a time
// along the ordered chain
//
//	CLEAN -> SUSPICIOUS -> RESTRICTED -> QUARANTINED
//
// QUARANTINED is the terminal escalation in this epic; PRESERVED_KILLED
// exists in the enum but is unreachable until Epic 4 (BI-7). Escalation
// is gated by a per-state minimum dwell guard (AC2) so a hallucinating
// future LLM (Epic 3) cannot rapidly oscillate a workload; de-escalation
// is gated by a rolling sub-threshold cooldown (AC3) so a single low
// sample never de-escalates.
//
// Determinism and side-effect freedom (BI-5): Evaluate is a pure
// function over (current per-workload state, dwell/cooldown timers,
// incoming score, injected Clock). It performs NO NATS publish, NO Redis
// write, NO NetworkPolicy apply; emission of actual transitions is via
// an injected TransitionSink seam that Stories 2.3 (Redis) and 2.8 (NATS
// audit) wire later. Re-evaluating the same (workload, state, score,
// time) yields the same StateTransition.
//
// Encapsulation (AC6, BI-6): Evaluate is the SOLE exported mutator. All
// per-workload state lives in an in-memory map guarded by a sync.RWMutex
// (Redis persistence and restart recovery are Story 2.3, not here). The
// only other exported surface is the read-only State query and the
// TransitionSink seam.
//
// Dependency-ring direction (BI-1): this package is Ring 4
// (response/isolation) and imports only substrate: internal/schema,
// internal/config, internal/metrics. It does NOT import
// internal/decision/ or internal/collector/.
package fsm

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/olokotoh/olaitan/internal/config"
	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/schema"
)

// Clock abstracts the wall clock so dwell and cooldown timers are
// testable without real sleeps (BI-5). Production passes a clock backed
// by time.Now; tests inject a controllable fake.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// TransitionSink is the output seam (BI-5). Evaluate pushes a
// StateTransition to the sink ONLY on an actual state change; a
// no_transition result is never published. Story 2.3 wires a
// Redis-backed sink and Story 2.8 wires a NATS audit sink; this story
// ships only the no-op default (NopSink) and a test recorder
// (RecordingSink in fsm_test.go).
type TransitionSink interface {
	Publish(schema.StateTransition)
}

// NopSink is the default sink: it discards every transition. main.go
// wires this until Stories 2.3/2.8 land real sinks.
type NopSink struct{}

// Publish discards the transition.
func (NopSink) Publish(schema.StateTransition) {}

// thresholds is the resolved snapshot of the three escalation thresholds
// (from ConfidenceBands, BI-3) and the dwell/cooldown durations (from
// FSMConfig, BI-4) that Evaluate reads on each call.
type thresholds struct {
	suspicious       float64 // ConfidenceBands.Watch
	restricted       float64 // ConfidenceBands.Alert
	quarantined      float64 // ConfidenceBands.Act
	suspiciousDwell  time.Duration
	restrictedDwell  time.Duration
	quarantinedDwell time.Duration
	cooldown         time.Duration
}

// workloadState is the per-workload FSM state held in memory (BI-6).
type workloadState struct {
	current PodState
	// stateEnteredAt is when the workload last entered current; the
	// escalation dwell guard measures from here (AC2).
	stateEnteredAt time.Time
	// lastAtOrAboveThresholdAt is the most recent time the score was at
	// or above the entry threshold of current. The de-escalation
	// cooldown measures the continuous sub-threshold window from here so
	// a single low sample does not de-escalate (AC3).
	lastAtOrAboveThresholdAt time.Time
}

// PodState aliases schema.PodSecurityState so callers can reference the
// FSM state type through this package without a second import.
type PodState = schema.PodSecurityState

// Machine is the in-memory FSM. Construct it with New. Evaluate is the
// sole mutator; State is a read-only query.
type Machine struct {
	snapshot func() *config.Config
	clock    Clock
	sink     TransitionSink

	mu     sync.RWMutex
	states map[string]*workloadState

	metrics *fsmMetrics

	// recovered counts workloads rehydrated from Redis on restart
	// (Story 2.3 AC5). Read by the olaitan_response_fsm_state_recovered_total
	// CounterFunc; written only by Restore.
	recovered atomic.Int64
}

// fsmMetrics owns the three Story 2.2 instruments.
type fsmMetrics struct {
	transitions *prometheus.CounterVec   // olaitan_response_fsm_transitions_total{from_state,to_state,reason}
	dwell       *prometheus.HistogramVec // olaitan_response_fsm_dwell_seconds{state}
	active      *prometheus.GaugeVec     // olaitan_response_fsm_active_workloads{state}
}

// ErrNilSink is returned by New when sink is nil. The caller must pass
// an explicit sink (NopSink{} in Epic 2) so the emission seam is never
// silently dropped.
var ErrNilSink = errors.New("fsm: nil transition sink")

// New constructs a Machine bound to the supplied config manager, metrics
// registry, and sink, mirroring score.New ergonomics. A nil mgr degrades
// the machine to the AC1/AC2/AC3 defaults (the test-only fall-through; a
// nil snapshot getter is treated as "no config"). A nil registry skips
// metric registration (test fixtures). clock may be nil to default to
// the real wall clock. sink must not be nil.
func New(mgr *config.Manager, registry *metrics.Registry, sink TransitionSink, clock Clock) (*Machine, error) {
	var get func() *config.Config
	if mgr == nil {
		get = func() *config.Config { return nil }
	} else {
		get = mgr.Get
	}
	return newWithGetter(get, registry, sink, clock)
}

// newWithGetter is the test-friendly constructor: it accepts an arbitrary
// snapshot getter so unit tests can swap the active *config.Config
// without going through the file watcher (the score package precedent).
func newWithGetter(get func() *config.Config, registry *metrics.Registry, sink TransitionSink, clock Clock) (*Machine, error) {
	if get == nil {
		return nil, errors.New("fsm: nil snapshot getter")
	}
	if sink == nil {
		return nil, ErrNilSink
	}
	if clock == nil {
		clock = realClock{}
	}
	m := &Machine{
		snapshot: get,
		clock:    clock,
		sink:     sink,
		states:   make(map[string]*workloadState),
		metrics:  &fsmMetrics{},
	}
	if registry != nil {
		if err := m.registerMetrics(registry); err != nil {
			return nil, fmt.Errorf("fsm: register metrics: %w", err)
		}
	}
	return m, nil
}

func (m *Machine) registerMetrics(r *metrics.Registry) error {
	tv, err := r.RegisterCounterVec(
		"olaitan_response_fsm_transitions_total",
		"Cumulative number of actual FSM state changes labelled by from_state, to_state, and reason. no_transition evaluations are NOT counted (Story 2.2, FR31/FR32).",
		[]string{"from_state", "to_state", "reason"},
	)
	if err != nil {
		return err
	}
	m.metrics.transitions = tv

	dv, err := r.RegisterHistogramVec(
		"olaitan_response_fsm_dwell_seconds",
		"Observed residence time a workload spent in a state before the FSM left it (recorded on any state change, escalation or de-escalation), labelled by the state being left (Story 2.2, AC2).",
		[]string{"state"},
		[]float64{1, 10, 30, 60, 120, 300, 600},
	)
	if err != nil {
		return err
	}
	m.metrics.dwell = dv

	av, err := r.RegisterGaugeVec(
		"olaitan_response_fsm_active_workloads",
		"Current number of workloads the FSM is tracking in each state (Story 2.2).",
		[]string{"state"},
	)
	if err != nil {
		return err
	}
	m.metrics.active = av

	// Story 2.3 AC5: count workloads rehydrated from Redis on restart.
	if err := r.RegisterCounter(
		"olaitan_response_fsm_state_recovered_total",
		"",
		"Cumulative number of workloads whose FSM state was recovered from Redis on controller restart (Story 2.3, FR37/NFR24).",
		nil,
		func() int64 { return m.recovered.Load() },
	); err != nil {
		return err
	}
	return nil
}

// resolve reads the active config snapshot and returns the resolved
// thresholds. A nil snapshot (test fall-through or teardown) yields the
// Story 2.1/2.2 defaults so the machine is always well-defined.
func (m *Machine) resolve() thresholds {
	t := thresholds{
		suspicious:       float64(config.SuspiciousThreshold),  // 20
		restricted:       float64(config.RestrictedThreshold),  // 40
		quarantined:      float64(config.QuarantinedThreshold), // 70
		suspiciousDwell:  time.Duration(config.DefaultSuspiciousDwellSeconds) * time.Second,
		restrictedDwell:  time.Duration(config.DefaultRestrictedDwellSeconds) * time.Second,
		quarantinedDwell: time.Duration(config.DefaultQuarantinedDwellSeconds) * time.Second,
		cooldown:         time.Duration(config.DefaultDeescalationCooldownSeconds) * time.Second,
	}
	cur := m.snapshot()
	if cur == nil {
		return t
	}
	b := cur.Detection.ConfidenceBands
	t.suspicious = float64(b.Watch)
	t.restricted = float64(b.Alert)
	t.quarantined = float64(b.Act)
	f := cur.Detection.FSM
	t.suspiciousDwell = time.Duration(f.SuspiciousDwellSecondsOrDefault()) * time.Second
	t.restrictedDwell = time.Duration(f.RestrictedDwellSecondsOrDefault()) * time.Second
	t.quarantinedDwell = time.Duration(f.QuarantinedDwellSecondsOrDefault()) * time.Second
	t.cooldown = time.Duration(f.DeescalationCooldownSecondsOrDefault()) * time.Second
	return t
}

// targetState returns the highest state the score alone justifies under
// the resolved thresholds. The bands are cumulative half-open intervals:
// score >= quarantined -> QUARANTINED; >= restricted -> RESTRICTED;
// >= suspicious -> SUSPICIOUS; otherwise CLEAN.
func (t thresholds) targetState(score float64) PodState {
	switch {
	case score >= t.quarantined:
		return schema.StateQuarantined
	case score >= t.restricted:
		return schema.StateRestricted
	case score >= t.suspicious:
		return schema.StateSuspicious
	default:
		return schema.StateClean
	}
}

// entryThreshold returns the score threshold at or above which a workload
// belongs in state s. CLEAN has an entry threshold of 0 (always
// satisfied). This is the threshold the de-escalation cooldown watches
// (AC3): while the score stays below it, the sub-threshold window grows.
func (t thresholds) entryThreshold(s PodState) float64 {
	switch s {
	case schema.StateSuspicious:
		return t.suspicious
	case schema.StateRestricted:
		return t.restricted
	case schema.StateQuarantined:
		return t.quarantined
	default:
		return 0
	}
}

// dwell returns the minimum dwell guard for state s (the escalation gate,
// AC2). CLEAN has no dwell guard.
func (t thresholds) dwell(s PodState) time.Duration {
	switch s {
	case schema.StateSuspicious:
		return t.suspiciousDwell
	case schema.StateRestricted:
		return t.restrictedDwell
	case schema.StateQuarantined:
		return t.quarantinedDwell
	default:
		return 0
	}
}

// stateOrder returns the ordinal of a state on the CLEAN..QUARANTINED
// chain. PRESERVED_KILLED is never produced by Evaluate (BI-7).
func stateOrder(s PodState) int {
	switch s {
	case schema.StateClean:
		return 0
	case schema.StateSuspicious:
		return 1
	case schema.StateRestricted:
		return 2
	case schema.StateQuarantined:
		return 3
	default:
		return 0
	}
}

// nextUp returns the state one step above s on the escalation chain, or s
// itself when s is already QUARANTINED (the terminal escalation, BI-7).
func nextUp(s PodState) PodState {
	switch s {
	case schema.StateClean:
		return schema.StateSuspicious
	case schema.StateSuspicious:
		return schema.StateRestricted
	case schema.StateRestricted:
		return schema.StateQuarantined
	default:
		return s
	}
}

// nextDown returns the state one step below s on the escalation chain, or
// s itself when s is already CLEAN.
func nextDown(s PodState) PodState {
	switch s {
	case schema.StateQuarantined:
		return schema.StateRestricted
	case schema.StateRestricted:
		return schema.StateSuspicious
	case schema.StateSuspicious:
		return schema.StateClean
	default:
		return s
	}
}

// Evaluate is the SOLE mutation entry point (AC6, BI-6). It folds one
// ThreatScore observation for workloadID into the in-memory FSM and
// returns the resulting StateTransition.
//
// Algorithm (pinned by the property tests for determinism):
//
//  1. An unknown workload initialises to CLEAN with stateEnteredAt and
//     lastAtOrAboveThresholdAt set to now (AC1, edge case).
//  2. The score is clamped to [0, 100].
//  3. The cooldown anchor lastAtOrAboveThresholdAt is refreshed to now
//     whenever the clamped score is at or above the current state's entry
//     threshold; this is what makes the de-escalation window "rolling" so
//     a single low sample does not de-escalate (AC3).
//  4. ESCALATION (one step up, AC1): if the score justifies a higher
//     state, the machine steps up exactly one state, but only once the
//     current state's minimum dwell guard has elapsed (AC2). The reason
//     is escalation_threshold_crossed when the dwell was already zero or
//     satisfied on entry, dwell_guard_elapsed otherwise. QUARANTINED is
//     terminal (BI-7).
//  5. DE-ESCALATION (one step down, AC3): otherwise, if the score has
//     stayed continuously below the current state's entry threshold for
//     at least the cooldown, the machine steps down exactly one state
//     (reason de_escalation_cooldown_expired) and the cooldown anchor is
//     reset so the next step requires a fresh full window.
//  6. Otherwise the state is unchanged (reason no_transition).
//
// The returned StateTransition always carries the reason; it is pushed to
// the TransitionSink ONLY when From != To (an actual change, BI-5). The
// transition counter is likewise incremented only on an actual change, so
// it reflects state-change rate rather than evaluation volume (Task 5.2).
func (m *Machine) Evaluate(workloadID string, score float64, packageID string) schema.StateTransition {
	now := m.clock.Now()
	t := m.resolve()
	score = clamp(score, 0, 100)

	m.mu.Lock()
	ws, known := m.states[workloadID]
	if !known {
		ws = &workloadState{
			current:                  schema.StateClean,
			stateEnteredAt:           now,
			lastAtOrAboveThresholdAt: now,
		}
		m.states[workloadID] = ws
	}

	from := ws.current

	// Refresh the rolling cooldown anchor: as long as the score is at or
	// above the current state's entry threshold, the sub-threshold window
	// restarts from now (AC3 "rolling ThreatScore").
	if score >= t.entryThreshold(ws.current) {
		ws.lastAtOrAboveThresholdAt = now
	}

	target := t.targetState(score)
	reason := schema.ReasonNoTransition
	to := ws.current

	switch {
	case stateOrder(target) > stateOrder(ws.current):
		// Escalation candidate. Gate on the current state's dwell guard
		// (AC2). CLEAN has a zero dwell guard so it escalates immediately.
		dwell := t.dwell(ws.current)
		elapsed := now.Sub(ws.stateEnteredAt)
		if elapsed >= dwell {
			to = nextUp(ws.current)
			if dwell > 0 {
				reason = schema.ReasonDwellGuardElapsed
			} else {
				reason = schema.ReasonEscalationThresholdCrossed
			}
		}
	case stateOrder(target) < stateOrder(ws.current):
		// De-escalation candidate. Gate on the continuous sub-threshold
		// cooldown (AC3): the score must have stayed below the current
		// state's entry threshold for at least the cooldown.
		subThreshold := now.Sub(ws.lastAtOrAboveThresholdAt)
		if subThreshold >= t.cooldown {
			to = nextDown(ws.current)
			reason = schema.ReasonDeescalationCooldownExpired
		}
	}

	// Apply the transition, if any, through the validated table.
	if to != from {
		if !schema.ValidTransition(from, to) {
			// Defensive: the one-step helpers above can only ever produce
			// a valid neighbour, so this branch is unreachable. Keeping it
			// makes the encapsulation guarantee (AC6) explicit: every
			// mutation passes ValidTransition.
			to = from
			reason = schema.ReasonNoTransition
		} else {
			if m.metrics != nil && m.metrics.dwell != nil {
				// Record how long the workload dwelled in the state it is
				// leaving (escalation only carries a meaningful dwell; on
				// de-escalation we still record the residence time).
				m.metrics.dwell.WithLabelValues(string(from)).Observe(now.Sub(ws.stateEnteredAt).Seconds())
			}
			ws.current = to
			ws.stateEnteredAt = now
			// Reset the cooldown anchor on every actual change so the next
			// de-escalation requires a fresh full sub-threshold window and
			// an escalation does not carry a stale anchor.
			ws.lastAtOrAboveThresholdAt = now
		}
	}

	st := schema.StateTransition{
		Timestamp:   now,
		FromState:   from,
		ToState:     to,
		TriggerType: "automated",
		Confidence:  score,
		WorkloadID:  workloadID,
		PackageID:   packageID,
		Reason:      reason,
	}

	m.recordMetrics(st)
	m.mu.Unlock()

	if st.FromState != st.ToState {
		m.sink.Publish(st)
	}
	return st
}

// recordMetrics increments the transition counter on actual state changes
// and refreshes the active-workloads gauge. Called with m.mu held.
func (m *Machine) recordMetrics(st schema.StateTransition) {
	if m.metrics == nil {
		return
	}
	// Count only actual state changes. A counter named ..._transitions_total
	// must not tick on no_transition evaluations, or rate(transitions_total)
	// would track inbound evidence volume on the hot path rather than the
	// state-change rate the metric name promises.
	if m.metrics.transitions != nil && st.FromState != st.ToState {
		m.metrics.transitions.WithLabelValues(string(st.FromState), string(st.ToState), st.Reason).Inc()
	}
	// Refresh the gauge on every evaluation, not only on transitions: a
	// first-seen workload that stays CLEAN is inserted into m.states without
	// a transition and must still be counted. Recompute is cheap (the map is
	// small relative to the evaluation cadence).
	if m.metrics.active != nil {
		m.refreshActiveGaugeLocked()
	}
}

// refreshActiveGaugeLocked recomputes the per-state workload counts.
// Called with m.mu held. Recomputed (rather than incrementally adjusted)
// so the gauge cannot drift; the workload map is small relative to the
// evaluation cadence.
func (m *Machine) refreshActiveGaugeLocked() {
	counts := map[PodState]int{
		schema.StateClean:       0,
		schema.StateSuspicious:  0,
		schema.StateRestricted:  0,
		schema.StateQuarantined: 0,
	}
	for _, ws := range m.states {
		counts[ws.current]++
	}
	for state, n := range counts {
		m.metrics.active.WithLabelValues(string(state)).Set(float64(n))
	}
}

// State returns the current FSM state for workloadID, or CLEAN if the
// workload has never been evaluated. Read-only query for Stories
// 2.4-2.7/2.9 (BI-6). It is NOT a mutator: an unseen workload is reported
// as CLEAN without being inserted into the map.
func (m *Machine) State(workloadID string) PodState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if ws, ok := m.states[workloadID]; ok {
		return ws.current
	}
	return schema.StateClean
}

// Restore rehydrates the in-memory FSM map from durable Redis state on
// controller startup (Story 2.3 AC2). It MUST run before the FSM consumer
// begins so a recovered workload is never re-initialised to CLEAN by
// Evaluate's first-seen path. For each recovered workload it seeds current
// and stateEnteredAt (clamped so a future-dated persisted timestamp yields
// zero, never negative, dwell elapsed; BI-6) and resets the de-escalation
// cooldown anchor to now so a stale persisted anchor can never trigger a
// premature de-escalation on restart. Returns the count recovered and the
// count of malformed entries skipped. Safe to call once at startup.
func (m *Machine) Restore(ctx context.Context, store *Store) (recovered int, skipped int, err error) {
	if store == nil {
		return 0, 0, errors.New("fsm: restore with nil store")
	}
	loaded, skipped, err := store.LoadAll(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("fsm: restore load: %w", err)
	}
	now := m.clock.Now()
	m.mu.Lock()
	for _, rw := range loaded {
		entered := rw.state.stateEnteredAt
		if now.Before(entered) {
			// A backward clock step lost the monotonic reading; clamp the
			// persisted timestamp to now so dwell elapsed is zero rather
			// than negative (BI-6).
			entered = now
		}
		m.states[rw.workloadID] = &workloadState{
			current:                  rw.state.current,
			stateEnteredAt:           entered,
			lastAtOrAboveThresholdAt: now,
		}
	}
	recovered = len(loaded)
	if m.metrics != nil && m.metrics.active != nil {
		m.refreshActiveGaugeLocked()
	}
	m.mu.Unlock()
	if recovered > 0 {
		m.recovered.Add(int64(recovered))
	}
	return recovered, skipped, nil
}

func clamp(v, lo, hi float64) float64 {
	// A NaN score (e.g. a 0/0 sigma normalisation upstream) compares false
	// against every bound, so without this guard it would pass through
	// unclamped and be classed as fully benign (CLEAN). Floor it to lo.
	if math.IsNaN(v) {
		return lo
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
