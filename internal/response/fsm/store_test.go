package fsm

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	redisclient "github.com/olokotoh/olaitan/internal/redis"
	"github.com/olokotoh/olaitan/internal/schema"
)

// startMiniredis launches an in-process miniredis (the real Redis
// boundary per NFR36) and registers cleanup. Shared by the fsm package
// store/sink/restore tests.
func startMiniredis(t *testing.T) *miniredis.Miniredis {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("start miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	return mr
}

func newRedisClient(t *testing.T, addr string) *redisclient.Client {
	t.Helper()
	cfg := redisclient.DefaultConfig()
	cfg.Addr = addr
	c, err := redisclient.NewClient(cfg)
	if err != nil {
		t.Fatalf("new redis client: %v", err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

const testWorkloadID = "default/Deployment/web"

func mkState(cur schema.PodSecurityState, at time.Time) persistedState {
	return persistedState{current: cur, stateEnteredAt: at, cooldownAnchorAt: at, updatedAt: at}
}

func TestStore_SaveAndLoadAll(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	store, err := NewStore(newRedisClient(t, mr.Addr()))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	at := time.Unix(1700000000, 0).UTC()
	swapped, err := store.Save(ctx, testWorkloadID, string(schema.StateClean), mkState(schema.StateSuspicious, at), []byte(`{"to_state":"SUSPICIOUS"}`))
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if !swapped {
		t.Fatal("Save: expected swapped=true on first write")
	}
	recovered, skipped, err := store.LoadAll(ctx)
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if skipped != 0 {
		t.Fatalf("LoadAll skipped = %d, want 0", skipped)
	}
	if len(recovered) != 1 {
		t.Fatalf("LoadAll recovered = %d, want 1", len(recovered))
	}
	got := recovered[0]
	if got.workloadID != testWorkloadID {
		t.Errorf("workloadID = %q, want %q", got.workloadID, testWorkloadID)
	}
	if got.state.current != schema.StateSuspicious {
		t.Errorf("current = %q, want SUSPICIOUS", got.state.current)
	}
	if !got.state.stateEnteredAt.Equal(at) {
		t.Errorf("stateEnteredAt = %v, want %v", got.state.stateEnteredAt, at)
	}
}

func TestStore_SaveCASRejectsStaleWrite(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	store, _ := NewStore(newRedisClient(t, mr.Addr()))
	at := time.Unix(1700000000, 0).UTC()
	// First land SUSPICIOUS (from CLEAN).
	if _, err := store.Save(ctx, testWorkloadID, string(schema.StateClean), mkState(schema.StateSuspicious, at), nil); err != nil {
		t.Fatalf("Save 1: %v", err)
	}
	// Then land RESTRICTED (from SUSPICIOUS).
	if _, err := store.Save(ctx, testWorkloadID, string(schema.StateSuspicious), mkState(schema.StateRestricted, at), nil); err != nil {
		t.Fatalf("Save 2: %v", err)
	}
	// A replay of the first transition (expects CLEAN) must be rejected:
	// the persisted current is now RESTRICTED.
	swapped, err := store.Save(ctx, testWorkloadID, string(schema.StateClean), mkState(schema.StateSuspicious, at), nil)
	if err != nil {
		t.Fatalf("Save stale: %v", err)
	}
	if swapped {
		t.Fatal("stale replay should not swap (CAS must reject)")
	}
	recovered, _, _ := store.LoadAll(ctx)
	if len(recovered) != 1 || recovered[0].state.current != schema.StateRestricted {
		t.Fatalf("persisted state should remain RESTRICTED, got %+v", recovered)
	}
}

func TestStore_NoTTLOnFSMKeys(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	cli := newRedisClient(t, mr.Addr())
	store, _ := NewStore(cli)
	at := time.Unix(1700000000, 0).UTC()
	if _, err := store.Save(ctx, testWorkloadID, string(schema.StateClean), mkState(schema.StateSuspicious, at), []byte(`{}`)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// FSM state must be durable: no positive TTL on the state key.
	d, err := cli.Raw().TTL(ctx, "fsm:"+testWorkloadID).Result()
	if err != nil {
		t.Fatalf("TTL: %v", err)
	}
	if d > 0 {
		t.Errorf("fsm state key has positive TTL %v, want no expiry (durable)", d)
	}
}

func TestStore_HistoryAppendAndCap(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	cli := newRedisClient(t, mr.Addr())
	store, _ := NewStore(cli)
	at := time.Unix(1700000000, 0).UTC()
	// One applied transition appends exactly one history entry.
	if _, err := store.Save(ctx, testWorkloadID, string(schema.StateClean), mkState(schema.StateSuspicious, at), []byte(`{"n":1}`)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	n, err := cli.Raw().LLen(ctx, "fsm:"+testWorkloadID+":history").Result()
	if err != nil {
		t.Fatalf("LLen: %v", err)
	}
	if n != 1 {
		t.Errorf("history length = %d, want 1", n)
	}
}

func TestStore_LoadAllSkipsMalformed(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	cli := newRedisClient(t, mr.Addr())
	store, _ := NewStore(cli)
	// Write a malformed hash directly (bad schema version) under a valid key.
	if err := cli.Raw().HSet(ctx, "fsm:"+testWorkloadID, map[string]any{"schema_version": "bogus", "current_state": "SUSPICIOUS"}).Err(); err != nil {
		t.Fatalf("seed malformed: %v", err)
	}
	recovered, skipped, err := store.LoadAll(ctx)
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(recovered) != 0 {
		t.Errorf("recovered = %d, want 0", len(recovered))
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1", skipped)
	}
}

// TestStore_RestartSimulation persists state, closes the client (simulating
// a controller kill), reopens against the SAME miniredis, and verifies the
// state survives (AC4).
func TestStore_RestartSimulation(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	at := time.Unix(1700000000, 0).UTC()

	cli1 := newRedisClient(t, mr.Addr())
	store1, _ := NewStore(cli1)
	if _, err := store1.Save(ctx, testWorkloadID, string(schema.StateClean), mkState(schema.StateQuarantined, at), []byte(`{}`)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	_ = cli1.Close(ctx)

	// New client against the same miniredis = a fresh controller process.
	cli2 := newRedisClient(t, mr.Addr())
	store2, _ := NewStore(cli2)
	recovered, _, err := store2.LoadAll(ctx)
	if err != nil {
		t.Fatalf("LoadAll after restart: %v", err)
	}
	if len(recovered) != 1 || recovered[0].state.current != schema.StateQuarantined {
		t.Fatalf("state did not survive restart: %+v", recovered)
	}
}
