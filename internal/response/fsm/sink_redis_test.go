package fsm

import (
	"context"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/schema"
)

func mkTransition(from, to schema.PodSecurityState, pkgID string) schema.StateTransition {
	return schema.StateTransition{
		Timestamp:  time.Unix(1700000000, 0).UTC(),
		FromState:  from,
		ToState:    to,
		WorkloadID: testWorkloadID,
		PackageID:  pkgID,
		Reason:     "escalation_threshold_crossed",
	}
}

func TestRedisSink_PublishPersists(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	store, _ := NewStore(newRedisClient(t, mr.Addr()))
	sink, err := NewRedisSink(store, nil, RedisSinkConfig{})
	if err != nil {
		t.Fatalf("NewRedisSink: %v", err)
	}
	sink.Publish(mkTransition(schema.StateClean, schema.StateSuspicious, "p1"))
	recovered, _, _ := store.LoadAll(ctx)
	if len(recovered) != 1 || recovered[0].state.current != schema.StateSuspicious {
		t.Fatalf("transition not persisted: %+v", recovered)
	}
}

func TestRedisSink_IdempotentReplay(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	cli := newRedisClient(t, mr.Addr())
	store, _ := NewStore(cli)
	sink, _ := NewRedisSink(store, nil, RedisSinkConfig{})
	st := mkTransition(schema.StateClean, schema.StateSuspicious, "p1")
	sink.Publish(st)
	sink.Publish(st) // replay: CAS rejects (persisted SUSPICIOUS != FromState CLEAN)
	n, err := cli.Raw().LLen(ctx, "fsm:"+testWorkloadID+":history").Result()
	if err != nil {
		t.Fatalf("LLen: %v", err)
	}
	if n != 1 {
		t.Errorf("history length = %d, want 1 (replay must not double-append)", n)
	}
}

// TestRedisSink_BuffersOnOutageAndReplays drives AC3: a transition that
// fails because Redis is unreachable is buffered, and the background
// replayer drains it once Redis recovers, with no loss.
func TestRedisSink_BuffersOnOutageAndReplays(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	store, _ := NewStore(newRedisClient(t, mr.Addr()))
	sink, _ := NewRedisSink(store, nil, RedisSinkConfig{ReplayEvery: 50 * time.Millisecond, WriteTimeout: 500 * time.Millisecond})

	mr.SetError("simulated outage")
	sink.Publish(mkTransition(schema.StateClean, schema.StateSuspicious, "p1"))
	if d := sink.Dropped(); d != 0 {
		t.Fatalf("dropped = %d during a single buffered transition, want 0", d)
	}
	mr.SetError("") // outage clears

	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- sink.Run(rctx) }()

	deadline := time.Now().Add(3 * time.Second)
	recoveredLen := 0
	for time.Now().Before(deadline) {
		recovered, _, _ := store.LoadAll(ctx)
		recoveredLen = len(recovered)
		if recoveredLen == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	if recoveredLen != 1 {
		t.Fatalf("buffered transition not replayed after outage cleared (recovered=%d)", recoveredLen)
	}
}
