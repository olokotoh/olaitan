package window

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/schema"
)

func TestStoreAddEvictsByWindowPerWorkload(t *testing.T) {
	now := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	store := NewStore(60 * time.Second)
	store.SetNow(func() time.Time { return now })

	old := event("old", now.Add(-61*time.Second), schema.SourceFalco)
	kept := event("kept", now.Add(-30*time.Second), schema.SourceAudit)
	latest := event("latest", now, schema.SourceRuntime)

	if _, err := store.Add("payments/Deployment/api", old); err != nil {
		t.Fatalf("add old: %v", err)
	}
	if _, err := store.Add("payments/Deployment/api", kept); err != nil {
		t.Fatalf("add kept: %v", err)
	}
	got, err := store.Add("payments/Deployment/api", latest)
	if err != nil {
		t.Fatalf("add latest: %v", err)
	}

	if len(got.Events) != 2 {
		t.Fatalf("events after eviction: got %d, want 2 (%+v)", len(got.Events), got.Events)
	}
	if got.Events[0].ID != "kept" || got.Events[1].ID != "latest" {
		t.Errorf("order/events: got %v", ids(got.Events))
	}
}

func TestStoreSetWindowDurationAffectsFutureAdds(t *testing.T) {
	now := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	store := NewStore(60 * time.Second)
	store.SetNow(func() time.Time { return now })
	_, _ = store.Add("ns/Deployment/app", event("stale", now.Add(-20*time.Second), schema.SourceFalco))
	store.SetWindowDuration(10 * time.Second)

	got, err := store.Add("ns/Deployment/app", event("fresh", now, schema.SourceAudit))
	if err != nil {
		t.Fatalf("add fresh: %v", err)
	}
	if len(got.Events) != 1 || got.Events[0].ID != "fresh" {
		t.Errorf("window update did not evict stale event: %v", ids(got.Events))
	}
}

func TestStoreConcurrentAdds(t *testing.T) {
	store := NewStore(time.Hour)
	// Concurrent adds use real-time timestamps so the real-time clock
	// keeps every event inside the one-hour cutoff.
	store.SetNow(func() time.Time { return time.Now().UTC() })
	var wg sync.WaitGroup
	now := time.Now().UTC()
	for i := 0; i < 128; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := store.Add("ns/Deployment/app", event(fmt.Sprintf("evt-%03d", i), now.Add(time.Duration(i)*time.Microsecond), schema.SourceFalco))
			if err != nil {
				t.Errorf("add %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	got := store.Snapshot("ns/Deployment/app")
	if len(got.Events) != 128 {
		t.Fatalf("events: got %d, want 128", len(got.Events))
	}
}

// TestStoreFutureDatedEventDoesNotRewindCutoff guards the P9 closure:
// a single event whose timestamp is far in the future must not erase
// existing in-window events. The cutoff is computed from the store's
// clock, not the event's timestamp, so a clock-skewed sensor cannot
// poison the buffer.
func TestStoreFutureDatedEventDoesNotRewindCutoff(t *testing.T) {
	now := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	store := NewStore(60 * time.Second)
	store.SetNow(func() time.Time { return now })

	if _, err := store.Add("ns/Deployment/app", event("first", now.Add(-1*time.Second), schema.SourceFalco)); err != nil {
		t.Fatalf("add first: %v", err)
	}
	if _, err := store.Add("ns/Deployment/app", event("second", now, schema.SourceAudit)); err != nil {
		t.Fatalf("add second: %v", err)
	}
	got, err := store.Add("ns/Deployment/app", event("future", now.Add(time.Hour), schema.SourceRuntime))
	if err != nil {
		t.Fatalf("add future: %v", err)
	}
	if len(got.Events) != 3 {
		t.Fatalf("future-dated event evicted prior events: got %d, want 3 (%v)", len(got.Events), ids(got.Events))
	}
}

// TestStoreMapKeyDeletedWhenBufferEmpties covers P7: a workload whose
// buffer fully evicts must have its map key removed so a Store
// running over many short-lived workloads cannot grow unbounded.
func TestStoreMapKeyDeletedWhenBufferEmpties(t *testing.T) {
	now := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	store := NewStore(time.Second)
	store.SetNow(func() time.Time { return now })

	if _, err := store.Add("ns/Deployment/app", event("first", now, schema.SourceFalco)); err != nil {
		t.Fatalf("add first: %v", err)
	}
	if got := storeKeyCount(store); got != 1 {
		t.Fatalf("after first add: map size = %d, want 1", got)
	}
	// Advance the store's clock past the cutoff for the existing
	// event; the next Add to a DIFFERENT workload would inherit the
	// same advance. To test eviction-driven delete we simply re-add
	// to the same workload at a later time; the prior event falls
	// behind the cutoff but the freshly-added event survives. To
	// observe the delete, expire BOTH by re-setting the clock and
	// re-adding so the cutoff lands strictly after every previous
	// event timestamp.
	store.SetNow(func() time.Time { return now.Add(2 * time.Second) })
	store.SetWindowDuration(time.Second) // re-trigger the retroactive sweep
	if got := storeKeyCount(store); got != 0 {
		t.Fatalf("after window sweep with no fresh events: map size = %d, want 0", got)
	}
}

// TestStoreSetWindowDurationRetroactivelyEvicts covers P19: a window
// shrink applied at hot-reload time must evict entries that no longer
// fit, not wait for the next Add per workload.
func TestStoreSetWindowDurationRetroactivelyEvicts(t *testing.T) {
	now := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	store := NewStore(60 * time.Second)
	store.SetNow(func() time.Time { return now })

	if _, err := store.Add("ns/Deployment/app", event("old", now.Add(-45*time.Second), schema.SourceFalco)); err != nil {
		t.Fatalf("add old: %v", err)
	}
	if _, err := store.Add("ns/Deployment/app", event("recent", now.Add(-2*time.Second), schema.SourceAudit)); err != nil {
		t.Fatalf("add recent: %v", err)
	}

	store.SetWindowDuration(5 * time.Second)

	got := store.Snapshot("ns/Deployment/app")
	if len(got.Events) != 1 || got.Events[0].ID != "recent" {
		t.Fatalf("retro-eviction: got %v, want [recent]", ids(got.Events))
	}
}

// TestStoreAddAndCheckRisingEdge covers the P23 rising-edge contract:
// AddAndCheckRisingEdge signals transitioned=true only on the
// false-to-true edge; subsequent adds while the predicate stays true
// must return transitioned=false (no re-fire); after the buffer
// fully evicts and re-climbs, transitioned=true must fire again.
func TestStoreAddAndCheckRisingEdge(t *testing.T) {
	now := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	clock := &atomicTime{}
	clock.Store(now)
	store := NewStore(60 * time.Second)
	store.SetNow(clock.Load)

	// Step 1: first event from one source. Predicate not met yet.
	_, transitioned, err := store.AddAndCheckRisingEdge("ns/Deployment/app", event("e1", now, schema.SourceFalco), 2)
	if err != nil {
		t.Fatalf("step1: %v", err)
	}
	if transitioned {
		t.Fatalf("step1: expected no transition with single source")
	}

	// Step 2: second source enters the window. Rising edge fires.
	_, transitioned, err = store.AddAndCheckRisingEdge("ns/Deployment/app", event("e2", now, schema.SourceAudit), 2)
	if err != nil {
		t.Fatalf("step2: %v", err)
	}
	if !transitioned {
		t.Fatalf("step2: expected rising-edge transition")
	}

	// Step 3: additional events while predicate stays true. No re-fire.
	_, transitioned, err = store.AddAndCheckRisingEdge("ns/Deployment/app", event("e3", now, schema.SourceRuntime), 2)
	if err != nil {
		t.Fatalf("step3: %v", err)
	}
	if transitioned {
		t.Fatalf("step3: expected no re-fire while predicate stays true")
	}

	// Step 4: advance the clock past the window so all prior events
	// expire; the next add re-establishes the buffer and must NOT
	// fire (only one source).
	clock.Store(now.Add(2 * time.Minute))
	_, transitioned, err = store.AddAndCheckRisingEdge("ns/Deployment/app", event("e4", clock.Load(), schema.SourceFalco), 2)
	if err != nil {
		t.Fatalf("step4: %v", err)
	}
	if transitioned {
		t.Fatalf("step4: expected no transition with single source post-rearm")
	}

	// Step 5: second source arrives again. Re-armed rising edge fires.
	_, transitioned, err = store.AddAndCheckRisingEdge("ns/Deployment/app", event("e5", clock.Load(), schema.SourceAudit), 2)
	if err != nil {
		t.Fatalf("step5: %v", err)
	}
	if !transitioned {
		t.Fatalf("step5: expected rising-edge transition after window roll")
	}
}

type atomicTime struct {
	v atomic.Value
}

func (a *atomicTime) Store(t time.Time) { a.v.Store(t) }
func (a *atomicTime) Load() time.Time {
	t, _ := a.v.Load().(time.Time)
	return t
}

func event(id string, ts time.Time, source schema.EventSource) schema.Event {
	return schema.Event{
		ID:        id,
		Timestamp: ts,
		Source:    source,
		Pod:       schema.PodRef{Name: "api-pod", Namespace: "payments", UID: "pod-uid"},
		Category:  schema.CategorySyscall,
		Summary:   id,
	}
}

func ids(events []schema.Event) []string {
	out := make([]string, len(events))
	for i := range events {
		out[i] = events[i].ID
	}
	return out
}

func storeKeyCount(s *Store) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.workload)
}
