package analyst

import (
	"sync"
	"sync/atomic"
	"time"
)

// CircuitBreaker is the global LLM-tier backpressure breaker (Story 3.12,
// FR51 LLM half / NFR23). It protects against attack-driven LLM cost
// amplification: when LLM-eligible packages (those past the FR19 trigger gate)
// arrive faster than RatePerMin globally, the breaker engages and the chain is
// BYPASSED (packages proceed deterministic-only) until the rate stays at or
// below threshold for a contiguous Cooling window.
//
// Unlike internal/ratelimit.Limiter (the per-source, per-second, sampling
// sensing breaker), this is GLOBAL, measures over a sliding 1-MINUTE window,
// and is BINARY (engaged => bypass all, no sampling). The hysteresis,
// transition-once semantics, atomic mutators, and injectable clock mirror the
// proven Limiter design.
type CircuitBreaker struct {
	ratePerMin   atomic.Int64
	coolingNanos atomic.Int64
	enabled      atomic.Bool
	clock        CBClock
	onTransition CBTransitionFn
	engagedTotal atomic.Int64

	mu                sync.Mutex
	buckets           [cbNumBuckets]cbBucket
	engaged           bool
	engagedSinceNanos int64
	belowSinceNanos   int64
}

// CBClock is the breaker's time source; tests inject a fake to drive
// engage/disengage deterministically.
type CBClock interface{ Now() time.Time }

type cbRealClock struct{}

func (cbRealClock) Now() time.Time { return time.Now() }

// CBRealClock returns the wall-clock implementation.
func CBRealClock() CBClock { return cbRealClock{} }

// CBTransition carries the engage/disengage edge context to the callback.
// EngagedFor is meaningful only when Engaged=false.
type CBTransition struct {
	Engaged        bool
	PackagesPerMin int64
	RatePerMin     int64
	EngagedFor     time.Duration
}

// CBTransitionFn fires once per engage and once per disengage edge (never for
// a re-engage during cooldown). It runs outside the breaker lock and must not
// block.
type CBTransitionFn func(CBTransition)

// CircuitBreakerOptions configures a CircuitBreaker.
type CircuitBreakerOptions struct {
	RatePerMin   int            // engagement threshold (strict >). Default 10.
	Cooling      time.Duration  // contiguous below-threshold duration to disengage. Default 60s.
	Enabled      bool           // false => Admit always permits, never engages.
	Clock        CBClock        // nil => wall clock.
	OnTransition CBTransitionFn // nil => no callback (EngagedTotal still advances).
}

// Defaults (FR51/NFR23: 10 LLM-eligible packages/min, 60s cooling window).
const (
	DefaultCBRatePerMin = 10
	DefaultCBCooling    = 60 * time.Second
)

// cbNumBuckets x cbBucketDuration = a sliding 1-minute window (60 x 1s).
const (
	cbNumBuckets     = 60
	cbBucketDuration = time.Second
	cbWindow         = time.Minute
)

type cbBucket struct {
	startNanos int64
	count      int64
}

// NewCircuitBreaker constructs a breaker from options, applying defaults for
// zero-valued fields.
func NewCircuitBreaker(opts CircuitBreakerOptions) *CircuitBreaker {
	rate := opts.RatePerMin
	if rate <= 0 {
		rate = DefaultCBRatePerMin
	}
	cooling := opts.Cooling
	if cooling <= 0 {
		cooling = DefaultCBCooling
	}
	clock := opts.Clock
	if clock == nil {
		clock = cbRealClock{}
	}
	b := &CircuitBreaker{clock: clock, onTransition: opts.OnTransition}
	b.ratePerMin.Store(int64(rate))
	b.coolingNanos.Store(int64(cooling))
	b.enabled.Store(opts.Enabled)
	return b
}

// EngagedTotal returns the cumulative engage-transition count (bound to
// olaitan_llm_circuit_breaker_engaged_total via NewCounterFunc).
func (b *CircuitBreaker) EngagedTotal() int64 { return b.engagedTotal.Load() }

// IsEngaged reports the current engaged state (for tests).
func (b *CircuitBreaker) IsEngaged() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.engaged
}

// Enabled reports whether the breaker is active.
func (b *CircuitBreaker) Enabled() bool { return b.enabled.Load() }

// RatePerMin / Cooling expose the current thresholds.
func (b *CircuitBreaker) RatePerMin() int        { return int(b.ratePerMin.Load()) }
func (b *CircuitBreaker) Cooling() time.Duration { return time.Duration(b.coolingNanos.Load()) }

// UpdateRatePerMin / UpdateCooling / UpdateEnabled mutate the breaker at
// runtime (FR49 hot-reload). Invalid values are ignored and reported false.
func (b *CircuitBreaker) UpdateRatePerMin(rate int) bool {
	if rate < 1 {
		return false
	}
	b.ratePerMin.Store(int64(rate))
	return true
}

func (b *CircuitBreaker) UpdateCooling(cooling time.Duration) bool {
	if cooling < time.Second {
		return false
	}
	b.coolingNanos.Store(int64(cooling))
	return true
}

func (b *CircuitBreaker) UpdateEnabled(enabled bool) {
	prev := b.enabled.Swap(enabled)
	if prev && !enabled {
		b.mu.Lock()
		b.engaged = false
		b.engagedSinceNanos = 0
		b.belowSinceNanos = 0
		b.mu.Unlock()
	}
}

// Admit records one LLM-eligible package in the sliding window and reports
// whether the chain should run. It returns false while the breaker is engaged
// (bypass => deterministic-only). A disabled breaker always returns true.
func (b *CircuitBreaker) Admit() bool {
	if !b.enabled.Load() {
		return true
	}

	nowNanos := b.clock.Now().UnixNano()
	threshold := b.ratePerMin.Load()
	cooling := b.coolingNanos.Load()

	var (
		fire bool
		tr   CBTransition
	)

	b.mu.Lock()

	bucketStart := (nowNanos / int64(cbBucketDuration)) * int64(cbBucketDuration)
	idx := (nowNanos / int64(cbBucketDuration)) % cbNumBuckets
	if idx < 0 {
		idx += cbNumBuckets
	}
	bk := &b.buckets[idx]
	if bk.startNanos != bucketStart {
		bk.startNanos = bucketStart
		bk.count = 0
	}
	bk.count++

	cutoff := nowNanos - int64(cbWindow)
	var total int64
	for i := range b.buckets {
		if b.buckets[i].startNanos > cutoff {
			total += b.buckets[i].count
		}
	}

	switch {
	case !b.engaged && total > threshold:
		b.engaged = true
		b.engagedSinceNanos = nowNanos
		b.belowSinceNanos = 0
		b.engagedTotal.Add(1)
		fire = true
		tr = CBTransition{Engaged: true, PackagesPerMin: total, RatePerMin: threshold}
	case b.engaged && total > threshold:
		b.belowSinceNanos = 0
	case b.engaged && total <= threshold:
		if b.belowSinceNanos == 0 {
			b.belowSinceNanos = nowNanos
		}
		if nowNanos-b.belowSinceNanos >= cooling {
			engagedFor := time.Duration(nowNanos - b.engagedSinceNanos)
			b.engaged = false
			b.engagedSinceNanos = 0
			b.belowSinceNanos = 0
			fire = true
			tr = CBTransition{Engaged: false, PackagesPerMin: total, RatePerMin: threshold, EngagedFor: engagedFor}
		}
	}

	engaged := b.engaged
	b.mu.Unlock()

	if fire && b.onTransition != nil {
		b.onTransition(tr)
	}
	return !engaged
}
