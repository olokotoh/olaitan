package posture

import (
	"sync"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/schema"
)

// fixedClock returns a clock function that always returns t.
func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func TestCache_HitWithinTTL(t *testing.T) {
	c := newCache()
	t0 := time.Date(2026, 5, 12, 22, 0, 0, 0, time.UTC)
	posture := &schema.WorkloadPosture{
		Identity:   schema.WorkloadIdentity{Namespace: "ns", OwnerKind: "Deployment", OwnerName: "app"},
		CapturedAt: t0,
	}

	c.Put("ns/Deployment/app", posture, 60*time.Second, fixedClock(t0))

	// Read at t0+30s -> hit.
	got, ok := c.Get("ns/Deployment/app", fixedClock(t0.Add(30*time.Second)))
	if !ok {
		t.Fatalf("Get within TTL: ok=false; want true")
	}
	if got != posture {
		t.Errorf("Get returned a different pointer; pointer-equality required for hot-path")
	}
}

func TestCache_MissAfterTTL(t *testing.T) {
	c := newCache()
	t0 := time.Date(2026, 5, 12, 22, 0, 0, 0, time.UTC)
	posture := &schema.WorkloadPosture{
		Identity:   schema.WorkloadIdentity{Namespace: "ns", OwnerKind: "Deployment", OwnerName: "app"},
		CapturedAt: t0,
	}

	c.Put("ns/Deployment/app", posture, 60*time.Second, fixedClock(t0))

	// Read at t0+61s -> miss + lazy delete.
	got, ok := c.Get("ns/Deployment/app", fixedClock(t0.Add(61*time.Second)))
	if ok {
		t.Fatalf("Get after TTL: ok=true; want false")
	}
	if got != nil {
		t.Errorf("Get after TTL: posture=%v; want nil", got)
	}
	if c.Len() != 0 {
		t.Errorf("Len after stale-evict: got %d, want 0", c.Len())
	}
}

func TestCache_MissOnUnknownKey(t *testing.T) {
	c := newCache()
	now := fixedClock(time.Date(2026, 5, 12, 22, 0, 0, 0, time.UTC))
	got, ok := c.Get("nonexistent", now)
	if ok || got != nil {
		t.Errorf("Get on unknown key: got (%v,%v); want (nil,false)", got, ok)
	}
}

func TestCache_PutRefreshesExistingEntry(t *testing.T) {
	c := newCache()
	t0 := time.Date(2026, 5, 12, 22, 0, 0, 0, time.UTC)
	first := &schema.WorkloadPosture{Identity: schema.WorkloadIdentity{Namespace: "ns", OwnerKind: "Deployment", OwnerName: "app"}, ServiceAccount: "first"}
	second := &schema.WorkloadPosture{Identity: schema.WorkloadIdentity{Namespace: "ns", OwnerKind: "Deployment", OwnerName: "app"}, ServiceAccount: "second"}

	c.Put("k", first, 60*time.Second, fixedClock(t0))
	c.Put("k", second, 60*time.Second, fixedClock(t0.Add(10*time.Second)))

	got, ok := c.Get("k", fixedClock(t0.Add(20*time.Second)))
	if !ok || got.ServiceAccount != "second" {
		t.Errorf("Put did not refresh: got %+v ok=%v; want second/true", got, ok)
	}
	if c.Len() != 1 {
		t.Errorf("Len after refresh: got %d, want 1", c.Len())
	}
}

func TestCache_Reset(t *testing.T) {
	c := newCache()
	t0 := time.Date(2026, 5, 12, 22, 0, 0, 0, time.UTC)
	c.Put("a", &schema.WorkloadPosture{}, 60*time.Second, fixedClock(t0))
	c.Put("b", &schema.WorkloadPosture{}, 60*time.Second, fixedClock(t0))
	_, _ = c.Get("a", fixedClock(t0))
	if c.Len() != 2 {
		t.Fatalf("precondition: Len=%d", c.Len())
	}

	c.Reset()
	if c.Len() != 0 {
		t.Errorf("Len after Reset: got %d, want 0", c.Len())
	}
}

func TestCache_ConcurrentGetPutRaceClean(t *testing.T) {
	c := newCache()
	t0 := time.Date(2026, 5, 12, 22, 0, 0, 0, time.UTC)
	now := fixedClock(t0)

	c.Put("hot-key", &schema.WorkloadPosture{Identity: schema.WorkloadIdentity{Namespace: "ns", OwnerKind: "Deployment", OwnerName: "app"}}, 60*time.Second, now)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%5 == 0 {
				c.Put("hot-key", &schema.WorkloadPosture{}, 60*time.Second, now)
			}
			_, _ = c.Get("hot-key", now)
		}(i)
	}
	wg.Wait()
}

func TestCache_StaleEvictionUnderConcurrentRefresh(t *testing.T) {
	c := newCache()
	t0 := time.Date(2026, 5, 12, 22, 0, 0, 0, time.UTC)
	c.Put("k", &schema.WorkloadPosture{}, 60*time.Second, fixedClock(t0))

	// Concurrent Get at expired-time and Put at refreshed-time. The
	// upgrade-on-hit branch must not evict the freshly-refreshed
	// entry.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = c.Get("k", fixedClock(t0.Add(120*time.Second))) // would evict
	}()
	go func() {
		defer wg.Done()
		c.Put("k", &schema.WorkloadPosture{}, 60*time.Second, fixedClock(t0.Add(125*time.Second)))
	}()
	wg.Wait()

	// After both goroutines, the entry should be present (the Put
	// refreshed it past the Get's eviction view). We assert no panic
	// and Len <= 1.
	if c.Len() > 1 {
		t.Errorf("Len: got %d, want <= 1", c.Len())
	}
}

func TestCache_ZeroTTLImmediatelyExpired(t *testing.T) {
	c := newCache()
	t0 := time.Date(2026, 5, 12, 22, 0, 0, 0, time.UTC)
	c.Put("k", &schema.WorkloadPosture{}, 0, fixedClock(t0))
	got, ok := c.Get("k", fixedClock(t0))
	if ok || got != nil {
		t.Errorf("zero-TTL: got (%v,%v); want (nil,false)", got, ok)
	}
}
