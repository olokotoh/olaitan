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
