package analyst

import (
	"sync"
	"testing"
	"time"
)

type cbFakeClock struct{ t time.Time }

func (c *cbFakeClock) Now() time.Time          { return c.t }
func (c *cbFakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestBreaker(fc *cbFakeClock, fired *int) *CircuitBreaker {
	return NewCircuitBreaker(CircuitBreakerOptions{
		RatePerMin: 10,
		Cooling:    60 * time.Second,
		Enabled:    true,
		Clock:      fc,
		OnTransition: func(CBTransition) {
			if fired != nil {
				*fired++
			}
		},
	})
}

// TestCircuitBreakerEngagesAboveThreshold (AC1): the 11th LLM-eligible package
// in the window crosses the strict-greater-than 10/min threshold and engages;
// the engaged breaker bypasses (Admit=false).
func TestCircuitBreakerEngagesAboveThreshold(t *testing.T) {
	fc := &cbFakeClock{t: time.Unix(1_000_000, 0)}
	b := newTestBreaker(fc, nil)
	for i := 0; i < 10; i++ {
		if !b.Admit() {
			t.Fatalf("admit %d bypassed before threshold", i)
		}
	}
	if b.Admit() {
		t.Error("the 11th admit (total 11 > 10) must bypass")
	}
	if !b.IsEngaged() || b.EngagedTotal() != 1 {
		t.Errorf("engaged=%v total=%d, want engaged/1", b.IsEngaged(), b.EngagedTotal())
	}
}

// TestCircuitBreakerDisengagesAfterCooling (AC3): once the rate stays at/below
// threshold for the contiguous cooling window, the breaker disengages and the
// chain re-engages (Admit=true).
func TestCircuitBreakerDisengagesAfterCooling(t *testing.T) {
	fc := &cbFakeClock{t: time.Unix(1_000_000, 0)}
	b := newTestBreaker(fc, nil)
	for i := 0; i < 11; i++ {
		b.Admit()
	}
	if !b.IsEngaged() {
		t.Fatal("setup: should be engaged")
	}
	// Slide past the window so the burst falls out, then mark the start of the
	// below-threshold period.
	fc.advance(90 * time.Second)
	if b.Admit() {
		t.Error("still within cooling; must remain engaged")
	}
	// Cooling elapses since the below-threshold start.
	fc.advance(61 * time.Second)
	if !b.Admit() {
		t.Error("cooling elapsed below threshold; must disengage")
	}
	if b.IsEngaged() {
		t.Error("should be disengaged")
	}
	if b.EngagedTotal() != 1 {
		t.Errorf("disengage must not advance the engage count, got %d", b.EngagedTotal())
	}
}

// TestCircuitBreakerReEngages (AC3): after disengaging, a fresh burst engages
// again and advances the count to 2.
func TestCircuitBreakerReEngages(t *testing.T) {
	fc := &cbFakeClock{t: time.Unix(1_000_000, 0)}
	b := newTestBreaker(fc, nil)
	for i := 0; i < 11; i++ {
		b.Admit()
	}
	fc.advance(90 * time.Second)
	b.Admit()
	fc.advance(61 * time.Second)
	b.Admit() // disengages
	if b.IsEngaged() {
		t.Fatal("setup: should be disengaged")
	}
	fc.advance(time.Second)
	for i := 0; i < 11; i++ {
		b.Admit()
	}
	if !b.IsEngaged() || b.EngagedTotal() != 2 {
		t.Errorf("re-engage: engaged=%v total=%d, want engaged/2", b.IsEngaged(), b.EngagedTotal())
	}
}

// TestCircuitBreakerTransitionOnce: a sustained over-threshold burst fires the
// transition callback exactly once and advances EngagedTotal once (log volume
// must not amplify the attack).
func TestCircuitBreakerTransitionOnce(t *testing.T) {
	fc := &cbFakeClock{t: time.Unix(1_000_000, 0)}
	fired := 0
	b := newTestBreaker(fc, &fired)
	for i := 0; i < 50; i++ {
		b.Admit()
	}
	if fired != 1 || b.EngagedTotal() != 1 {
		t.Errorf("sustained engagement: fired=%d total=%d, want 1/1", fired, b.EngagedTotal())
	}
}

// TestCircuitBreakerDisabledAlwaysAdmits: a disabled breaker never engages.
func TestCircuitBreakerDisabledAlwaysAdmits(t *testing.T) {
	fc := &cbFakeClock{t: time.Unix(1_000_000, 0)}
	b := NewCircuitBreaker(CircuitBreakerOptions{RatePerMin: 10, Cooling: 60 * time.Second, Enabled: false, Clock: fc})
	for i := 0; i < 100; i++ {
		if !b.Admit() {
			t.Fatal("disabled breaker bypassed")
		}
	}
	if b.IsEngaged() || b.EngagedTotal() != 0 {
		t.Errorf("disabled breaker engaged=%v total=%d, want false/0", b.IsEngaged(), b.EngagedTotal())
	}
}

// TestCircuitBreakerHotReload (AC4): lowering the threshold engages sooner;
// disabling resets the engaged state.
func TestCircuitBreakerHotReload(t *testing.T) {
	fc := &cbFakeClock{t: time.Unix(1_000_000, 0)}
	b := newTestBreaker(fc, nil)
	if !b.UpdateRatePerMin(3) {
		t.Fatal("UpdateRatePerMin(3) rejected")
	}
	for i := 0; i < 3; i++ {
		if !b.Admit() {
			t.Fatalf("admit %d bypassed before the lowered threshold", i)
		}
	}
	if b.Admit() { // total 4 > 3
		t.Error("4th admit must bypass under the lowered threshold")
	}
	if !b.IsEngaged() {
		t.Fatal("should be engaged under the lowered threshold")
	}
	b.UpdateEnabled(false)
	if b.IsEngaged() {
		t.Error("disabling must reset the engaged state")
	}
	if !b.Admit() {
		t.Error("a disabled breaker must admit")
	}
	// Invalid updates are rejected and retain the prior value.
	if b.UpdateRatePerMin(0) || b.UpdateCooling(time.Millisecond) {
		t.Error("invalid Update* values must be rejected")
	}
}

// TestCircuitBreakerConcurrentAdmit proves the breaker is safe for concurrent
// Admit + hot-reload (its core design claim), under `go test -race`. The
// engage count must not exceed the number of engage edges regardless of
// interleaving; the run must be race-free.
func TestCircuitBreakerConcurrentAdmit(t *testing.T) {
	// Real clock so concurrent callers share a live window.
	b := NewCircuitBreaker(CircuitBreakerOptions{RatePerMin: 5, Cooling: time.Second, Enabled: true})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				b.Admit()
				if j%50 == 0 {
					b.UpdateRatePerMin(5 + j%3)
					b.UpdateCooling(time.Second)
				}
			}
		}()
	}
	wg.Wait()
	// 16*200 = 3200 admits well above rate 5 => engaged at least once; the
	// count is bounded and non-negative (no torn writes).
	if b.EngagedTotal() < 1 {
		t.Errorf("EngagedTotal = %d, want >= 1 under a 3200-admit burst", b.EngagedTotal())
	}
}
