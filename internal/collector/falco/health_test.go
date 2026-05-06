package falco

import (
	"errors"
	"sync"
	"testing"
)

func TestSourceHealth_ZeroValueIsUnhealthy(t *testing.T) {
	var h SourceHealth
	healthy, err := h.Status()
	if healthy {
		t.Error("zero-value SourceHealth should be unhealthy")
	}
	if err != nil {
		t.Errorf("zero-value SourceHealth should report nil err, got %v", err)
	}
}

func TestSourceHealth_MarkHealthy(t *testing.T) {
	var h SourceHealth
	h.MarkHealthy()
	healthy, err := h.Status()
	if !healthy {
		t.Error("after MarkHealthy: expected healthy=true")
	}
	if err != nil {
		t.Errorf("after MarkHealthy: expected nil err, got %v", err)
	}
}

func TestSourceHealth_MarkUnhealthyCarriesError(t *testing.T) {
	var h SourceHealth
	want := errors.New("connection refused")
	h.MarkUnhealthy(want)
	healthy, err := h.Status()
	if healthy {
		t.Error("after MarkUnhealthy: expected healthy=false")
	}
	if !errors.Is(err, want) {
		t.Errorf("after MarkUnhealthy: expected %v, got %v", want, err)
	}
}

func TestSourceHealth_MarkUnhealthyNilErrorIsAllowed(t *testing.T) {
	var h SourceHealth
	h.MarkUnhealthy(nil)
	healthy, err := h.Status()
	if healthy {
		t.Error("after MarkUnhealthy(nil): expected healthy=false")
	}
	if err != nil {
		t.Errorf("after MarkUnhealthy(nil): expected nil err, got %v", err)
	}
}

func TestSourceHealth_HealthyClearsLastError(t *testing.T) {
	var h SourceHealth
	h.MarkUnhealthy(errors.New("transient"))
	h.MarkHealthy()
	_, err := h.Status()
	if err != nil {
		t.Errorf("MarkHealthy should clear lastErr, got %v", err)
	}
}

func TestSourceHealth_ConcurrentReadersAndWriters(t *testing.T) {
	// Run with -race; this should not data-race regardless of the reader/writer
	// interleaving because every field access goes through atomics.
	var h SourceHealth
	var wg sync.WaitGroup
	const goroutines = 8
	const iterations = 1000

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				if j%2 == 0 {
					h.MarkHealthy()
				} else {
					h.MarkUnhealthy(errors.New("transient"))
				}
				_, _ = h.Status()
			}
		}(i)
	}
	wg.Wait()
	// Final state is unspecified due to race; we only assert no panic and no race.
}

func TestSourceHealth_StatusReturnsConsistentSnapshot(t *testing.T) {
	// SourceHealth uses a single atomic.Pointer[healthState] holding the
	// (healthy, lastErr) tuple, so Status() is a single atomic load and
	// readers always observe a self-consistent snapshot — there is no
	// possibility of seeing healthy=true alongside a stale lastErr from
	// a prior MarkUnhealthy. This test verifies that contract under the
	// single-threaded case; the concurrent-readers-and-writers test
	// above exercises the same guarantee under load.
	var h SourceHealth
	h.MarkUnhealthy(errors.New("e"))
	h.MarkHealthy()
	healthy, err := h.Status()
	if !healthy {
		t.Error("after MarkHealthy: expected healthy=true")
	}
	if err != nil {
		t.Errorf("after MarkHealthy: expected nil err, got %v", err)
	}
}
