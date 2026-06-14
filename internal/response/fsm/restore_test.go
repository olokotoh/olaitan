package fsm

import (
	"context"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/config"
	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/schema"
)

func seedState(t *testing.T, store *Store, workloadID string, cur schema.PodSecurityState, at time.Time) {
	t.Helper()
	_, err := store.Save(context.Background(), workloadID, string(schema.StateClean),
		persistedState{current: cur, stateEnteredAt: at, cooldownAnchorAt: at, updatedAt: at}, nil)
	if err != nil {
		t.Fatalf("seed %s: %v", workloadID, err)
	}
}

// TestRestore_SeedsStatesBeforeConsumer pins AC2 + the "never silently
// de-escalate to CLEAN on restart" goal: a persisted QUARANTINED workload
// is restored, and a first post-restart low-score Evaluate does not reset
// it to CLEAN.
func TestRestore_SeedsStatesBeforeConsumer(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	store, _ := NewStore(newRedisClient(t, mr.Addr()))
	clock := newFakeClock()
	seedState(t, store, testWorkloadID, schema.StateQuarantined, clock.Now().Add(-time.Hour))

	m, _ := newMachineForTest(t, testConfig(0, 120, 120, 600), clock)
	n, skipped, err := m.Restore(ctx, store)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if n != 1 || skipped != 0 {
		t.Fatalf("Restore = (%d,%d), want (1,0)", n, skipped)
	}
	if got := m.State(testWorkloadID); got != schema.StateQuarantined {
		t.Errorf("State after restore = %q, want QUARANTINED", got)
	}
	st := m.Evaluate(testWorkloadID, 0, "p-after")
	if st.ToState == schema.StateClean {
		t.Error("restored workload de-escalated to CLEAN on first post-restart evaluate")
	}
}

// TestRestore_ClockClampOnFutureTimestamp pins BI-6: a persisted timestamp
// in the future relative to the restore clock (a backward NTP step that
// lost the monotonic reading) is clamped so dwell elapsed is never
// negative, and the cooldown anchor restarts at restore-now.
func TestRestore_ClockClampOnFutureTimestamp(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	store, _ := NewStore(newRedisClient(t, mr.Addr()))
	clock := newFakeClock()
	future := clock.Now().Add(time.Hour)
	seedState(t, store, testWorkloadID, schema.StateRestricted, future)

	m, _ := newMachineForTest(t, testConfig(0, 120, 120, 600), clock)
	if _, _, err := m.Restore(ctx, store); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	m.mu.RLock()
	ws := m.states[testWorkloadID]
	m.mu.RUnlock()
	if ws == nil {
		t.Fatal("workload not restored")
	}
	if ws.stateEnteredAt.After(clock.Now()) {
		t.Errorf("stateEnteredAt %v not clamped to restore-now %v (would yield negative dwell)", ws.stateEnteredAt, clock.Now())
	}
	if !ws.lastAtOrAboveThresholdAt.Equal(clock.Now()) {
		t.Errorf("cooldown anchor = %v, want restore-now %v", ws.lastAtOrAboveThresholdAt, clock.Now())
	}
}

// TestKill_RestorePreventsImmediateKill pins Story 4.1 round-1 Finding 3 and the
// dev-handoff risk #2 (the Restore kill-anchor reseed): a workload restored as
// QUARANTINED with a FAR-PAST stateEnteredAt (clock 3 / the QUARANTINED-dwell
// clock is already satisfied) is NOT killed on the first post-restart sustained
// kill score. Restore reseeds lastBelowKillThresholdAt to restart-now (the kill
// anchor is in-memory only and cannot be recovered), so clock 2 (the
// at-or-above-kill window) restarts from zero and dominates: the kill defers
// until a fresh post-restart sustain window elapses, then fires. This isolates
// clock 3's independent binding after Restore (which steady-state operation
// masks) and exercises clock 2's restart-now reseed dominance.
func TestKill_RestorePreventsImmediateKill(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	store, _ := NewStore(newRedisClient(t, mr.Addr()))
	clock := newFakeClock()
	// Seed QUARANTINED with stateEnteredAt far in the past: the QUARANTINED-dwell
	// clock (clock 3) is already satisfied at restore-now.
	farPast := clock.Now().Add(-time.Duration(config.DefaultKillSustainSeconds+1_000) * time.Second)
	seedState(t, store, testWorkloadID, schema.StateQuarantined, farPast)

	m, _ := newMachineForTest(t, testConfig(0, 0, 0, 600), clock)
	if _, _, err := m.Restore(ctx, store); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if got := m.State(testWorkloadID); got != schema.StateQuarantined {
		t.Fatalf("State after restore = %q, want QUARANTINED", got)
	}

	// Open the at-or-above-kill window at restart-now with a kill-level score.
	// Despite clock 3 already being satisfied (far-past stateEnteredAt), no kill:
	// clock 2 (lastBelowKillThresholdAt) was reseeded to restart-now.
	st := m.Evaluate(testWorkloadID, 95, "pkg")
	if st.ToState == schema.StatePreservedKilled {
		t.Fatal("kill fired immediately after restore despite the in-memory kill anchor reseed (Finding 3)")
	}

	// Just short of a fresh post-restart sustain window: still no kill.
	clock.advance(time.Duration(config.DefaultKillSustainSeconds-10) * time.Second)
	st = m.Evaluate(testWorkloadID, 95, "pkg")
	if st.ToState == schema.StatePreservedKilled {
		t.Fatalf("kill fired before a fresh post-restart sustain window elapsed: %s->%s", st.FromState, st.ToState)
	}

	// A fresh full post-restart sustain window has now elapsed: the kill fires.
	clock.advance(20 * time.Second)
	st = m.Evaluate(testWorkloadID, 95, "pkg")
	if st.FromState != schema.StateQuarantined || st.ToState != schema.StatePreservedKilled {
		t.Fatalf("kill did not fire after a fresh post-restart sustain window, got %s->%s", st.FromState, st.ToState)
	}
	if st.Reason != schema.ReasonKillConditionMet {
		t.Errorf("kill reason = %q, want kill_condition_met", st.Reason)
	}
}

// TestRestore_RecoveredMetric pins AC5: state_recovered_total counts the
// workloads rehydrated from Redis.
func TestRestore_RecoveredMetric(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	store, _ := NewStore(newRedisClient(t, mr.Addr()))
	clock := newFakeClock()
	seedState(t, store, "default/Deployment/web", schema.StateSuspicious, clock.Now())
	seedState(t, store, "default/Deployment/api", schema.StateRestricted, clock.Now())

	reg := metrics.NewRegistry()
	cfg := testConfig(0, 120, 120, 600)
	m, err := newWithGetter(func() *config.Config { return cfg }, reg, NopSink{}, clock)
	if err != nil {
		t.Fatalf("newWithGetter: %v", err)
	}
	n, _, err := m.Restore(ctx, store)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if n != 2 {
		t.Fatalf("recovered = %d, want 2", n)
	}
	mfs, gerr := reg.Gatherer().Gather()
	if gerr != nil {
		t.Fatalf("gather: %v", gerr)
	}
	found := false
	var val float64
	for _, mf := range mfs {
		if mf.GetName() == "olaitan_response_fsm_state_recovered_total" {
			found = true
			val = mf.GetMetric()[0].GetCounter().GetValue()
		}
	}
	if !found {
		t.Fatal("olaitan_response_fsm_state_recovered_total not registered")
	}
	if val != 2 {
		t.Errorf("state_recovered_total = %v, want 2", val)
	}
}
