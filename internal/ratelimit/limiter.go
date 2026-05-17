// Package ratelimit implements the per-source per-node rate-limit
// circuit breaker that protects the Olaitan sensing layer from
// attack-driven event amplification (FR51 sensing half; NFR22). When a
// source exceeds the configured events-per-second threshold on a single
// node, the limiter engages and switches to deterministic hash-based
// sampling at the configured rate; surviving events are annotated with
// Sampled=true and SamplingRate so the downstream correlator and DFIR
// report writer can honestly disclose the degradation rather than
// silently miss attack signal.
//
// Design choices (see _bmad-output/implementation-artifacts/1-13-...md
// for full binding interpretations):
//
//   - The breaker lives at the sensing boundary, not the correlator.
//     Architecture.md:966 names internal/correlator/trigger/sampler.go,
//     but the sensing-layer half is applied on each adapter's publish
//     path so the dependency direction stays sensing -> correlator.
//     The LLM-tier breaker (internal/decision/agent/circuitbreaker.go)
//     is out of scope here; it lands in a future Story 3.x.
//
//   - Sliding 1-second window via a 10x100ms ring buffer. O(1) per
//     Allow call; no per-instance goroutine. Engage/disengage is
//     evaluated lazily on the hot path (guardrail 30).
//
//   - Deterministic FNV-1a hash sampling. The decision is reproducible
//     across evaluation re-runs at the same event sequence (NFR42).
//     math/rand is intentionally avoided (guardrail 28).
//
//   - Engage/disengage transitions log and increment the engagement
//     counter exactly once. Sustained engagement does NOT emit periodic
//     logs (guardrail 29; otherwise log volume amplifies the very
//     attack the breaker mitigates).
//
//   - All Update* mutators are atomic so a config reload during
//     steady-state traffic does not pause the hot path.
package ratelimit

import (
	"errors"
	"fmt"
	"hash/fnv"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// Clock is the time source the Limiter consults. The real-clock
// implementation is the package default; tests inject a fake clock to
// drive engage/disengage transitions deterministically.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

// Now satisfies Clock with time.Now.
func (realClock) Now() time.Time { return time.Now() }

// RealClock returns the wall-clock implementation. Exported so tests
// that exercise both real and fake clocks can name the production one.
func RealClock() Clock { return realClock{} }

// Transition carries the context the OnTransition callback receives on
// every engage/disengage edge. Engaged distinguishes the two cases;
// EngagedFor is meaningful only when Engaged=false (it carries the
// engage->disengage duration so the caller can log "engaged_for_seconds"
// per AC3).
type Transition struct {
	Source          string
	Node            string
	Engaged         bool
	EventsPerSecond float64
	Threshold       int
	SamplingRate    float64
	EngagedFor      time.Duration
}

// TransitionFn is the engage/disengage callback the caller wires for
// structured logging plus per-source counter increments. Called once
// per engage and once per disengage transition; never called for
// re-engage-during-cooldown (treated as a continuous engagement).
//
// The callback runs outside the limiter's internal lock so subscribers
// may call back into Limiter methods without deadlocking; the callback
// MUST NOT block.
type TransitionFn func(Transition)

// Options configures a Limiter at construction time. Zero-value Options
// with Enabled=false constructs a disabled limiter (Allow always
// permits, never engages).
type Options struct {
	// Source labels the adapter family (falco, audit, runtime,
	// network, applog) for metric and log context. Required.
	Source string

	// Node labels the Kubernetes node the agent pod runs on, sourced
	// from the K8S_NODE_NAME downward-API env var by the caller.
	// Required when Enabled=true; treated as the per-node dimension of
	// FR51's "per-source per-node" contract.
	Node string

	// Threshold is the events-per-second strict-greater-than threshold
	// for engagement. Below or at threshold => not engaged. Default
	// 1000 per NFR22 and PRD line 439. Must be >= 1 when Enabled.
	Threshold int

	// Cooldown is the contiguous below-threshold duration required for
	// disengagement. Default 60s per AC3. Must be >= 1s when Enabled.
	Cooldown time.Duration

	// SamplingRate is the fraction in (0, 1] of events that survive the
	// sampling roll while engaged. Default 0.1. samplingRate*100 must
	// be an integer-comparable bound; values that don't land on a
	// whole percent are accepted but the sampling decision uses the
	// nearest integer threshold.
	SamplingRate float64

	// Enabled short-circuits the limiter when false: Allow always
	// returns Publish=true, Sampled=false, SamplingRate=1.0. The
	// engagement counter never advances; the OnTransition callback
	// never fires. Mutator UpdateEnabled flips the runtime state.
	Enabled bool

	// Clock injects the time source. Nil means the wall clock.
	Clock Clock

	// OnTransition is the engage/disengage callback. Nil means no
	// callback (the engagement counter still advances internally).
	OnTransition TransitionFn
}

// Defaults applied at New time when the corresponding option field is
// zero. Threshold and Cooldown carry NFR22 / PRD line 439 values;
// SamplingRate carries the 10% AC1 figure.
const (
	DefaultThreshold    = 1000
	DefaultCooldown     = 60 * time.Second
	DefaultSamplingRate = 0.1
)

// numBuckets fixes the 10x100ms ring buffer covering a sliding 1s
// window. Changing this constant requires updating bucketDuration so
// numBuckets * bucketDuration stays equal to one second.
const numBuckets = 10

// bucketDuration is each ring bucket's width. 100ms means at most a
// 10% measurement granularity error on the 1s rate; well below the
// engagement hysteresis the cooldown already provides.
const bucketDuration = 100 * time.Millisecond

// windowDuration is the total sliding-window length the limiter measures
// rate over. Equal to numBuckets * bucketDuration by construction.
const windowDuration = time.Second

// Decision is the per-event verdict the Limiter returns from Allow.
// Adapters use this to decide whether to publish the event and whether
// to annotate it with Sampled / SamplingRate before publishing.
//
//   - Publish=true,  Sampled=false, SamplingRate=1.0 : not engaged,
//     publish unmodified (the steady-state hot path).
//   - Publish=true,  Sampled=true,  SamplingRate=rate : engaged, this
//     event survived the sampling roll; annotate and publish.
//   - Publish=false, Sampled=false, SamplingRate=rate : engaged, this
//     event was dropped by the sampling roll; do not publish.
type Decision struct {
	Publish      bool
	Sampled      bool
	SamplingRate float64
}

// bucket is one slot of the sliding-window ring. startNanos pins the
// bucket to a specific 100ms-aligned wall-clock interval so a stale
// bucket from one second ago is recognised and reset before being
// counted.
type bucket struct {
	startNanos int64
	count      int64
}

// Limiter is a per-(source, node) rate-limit circuit breaker. Construct
// with New; call Allow on the publish hot path; observe engage-count
// via EngagedTotal for the Story 1.12 Prometheus binding.
//
// Concurrent safety: Allow is safe for concurrent callers; the internal
// state is protected by a mutex on the hot path. The mutex is held only
// over the bucket-increment + transition-evaluation arithmetic, which
// is sub-microsecond on production hardware; the OnTransition callback
// is invoked after the mutex is released so subscribers cannot deadlock
// by calling back into the limiter.
type Limiter struct {
	source string
	node   string

	threshold        atomic.Int64
	cooldownNanos    atomic.Int64
	samplingRateBits atomic.Uint64
	enabled          atomic.Bool

	clock        Clock
	onTransition TransitionFn

	mu                sync.Mutex
	buckets           [numBuckets]bucket
	engaged           bool
	engagedSinceNanos int64
	belowSinceNanos   int64

	engagedTotal atomic.Int64
}

// New constructs a Limiter from Options. Source must be non-empty;
// when Enabled=true Node must be non-empty and Threshold / Cooldown /
// SamplingRate must satisfy the documented ranges. Returns a wrapped
// error if any field is out of bounds so a misconfiguration fails
// loudly at construction rather than crash-looping later.
func New(opts Options) (*Limiter, error) {
	if opts.Source == "" {
		return nil, errors.New("ratelimit: source is empty")
	}
	if opts.Enabled && opts.Node == "" {
		return nil, errors.New("ratelimit: node is empty (required when enabled=true)")
	}

	threshold := opts.Threshold
	if threshold == 0 {
		threshold = DefaultThreshold
	}
	cooldown := opts.Cooldown
	if cooldown == 0 {
		cooldown = DefaultCooldown
	}
	samplingRate := opts.SamplingRate
	if samplingRate == 0 {
		samplingRate = DefaultSamplingRate
	}

	if opts.Enabled {
		if threshold < 1 {
			return nil, fmt.Errorf("ratelimit: threshold must be >= 1 (got %d)", threshold)
		}
		if cooldown < time.Second {
			return nil, fmt.Errorf("ratelimit: cooldown must be >= 1s (got %s)", cooldown)
		}
		if samplingRate <= 0 || samplingRate > 1 {
			return nil, fmt.Errorf("ratelimit: sampling_rate must be in (0, 1] (got %v)", samplingRate)
		}
	}

	clock := opts.Clock
	if clock == nil {
		clock = realClock{}
	}

	l := &Limiter{
		source:       opts.Source,
		node:         opts.Node,
		clock:        clock,
		onTransition: opts.OnTransition,
	}
	l.threshold.Store(int64(threshold))
	l.cooldownNanos.Store(int64(cooldown))
	l.samplingRateBits.Store(math.Float64bits(samplingRate))
	l.enabled.Store(opts.Enabled)
	return l, nil
}

// Source returns the source label this Limiter was constructed with.
// Used by per-adapter wiring code that needs to surface the same label
// to slog / metrics without re-deriving it.
func (l *Limiter) Source() string { return l.source }

// Node returns the node label this Limiter was constructed with.
func (l *Limiter) Node() string { return l.node }

// Enabled reports whether the breaker is currently active. UpdateEnabled
// changes this value at runtime per FR49 hot-reload.
func (l *Limiter) Enabled() bool { return l.enabled.Load() }

// Threshold returns the current events-per-second engagement threshold.
func (l *Limiter) Threshold() int { return int(l.threshold.Load()) }

// Cooldown returns the current below-threshold duration required for
// disengagement.
func (l *Limiter) Cooldown() time.Duration {
	return time.Duration(l.cooldownNanos.Load())
}

// SamplingRate returns the current sampling rate fraction.
func (l *Limiter) SamplingRate() float64 {
	return math.Float64frombits(l.samplingRateBits.Load())
}

// EngagedTotal returns the cumulative count of engage transitions since
// the Limiter was constructed. Story 1.12's metrics.Registry.RegisterCounter
// reads this via prometheus.NewCounterFunc to bind
// olaitan_sensor_circuit_breaker_engaged_total{source, node}.
//
// A re-engage-during-cooldown is treated as a continuous engagement and
// does NOT advance the counter (guardrail 29).
func (l *Limiter) EngagedTotal() int64 { return l.engagedTotal.Load() }

// IsEngaged reports whether the breaker is currently in the engaged
// state. Used by integration tests to verify the engage transition
// without polling the counter.
func (l *Limiter) IsEngaged() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.engaged
}

// UpdateThreshold mutates the engagement threshold at runtime. Invalid
// values (less than 1) are rejected and the previous value is retained;
// the returned error names the offending value so the caller can log it.
func (l *Limiter) UpdateThreshold(newThreshold int) error {
	if newThreshold < 1 {
		return fmt.Errorf("ratelimit: threshold must be >= 1 (got %d)", newThreshold)
	}
	l.threshold.Store(int64(newThreshold))
	return nil
}

// UpdateCooldown mutates the cooldown duration at runtime. Values
// below one second are rejected and the previous value is retained.
func (l *Limiter) UpdateCooldown(newCooldown time.Duration) error {
	if newCooldown < time.Second {
		return fmt.Errorf("ratelimit: cooldown must be >= 1s (got %s)", newCooldown)
	}
	l.cooldownNanos.Store(int64(newCooldown))
	return nil
}

// UpdateSamplingRate mutates the sampling rate at runtime. Values
// outside (0, 1] are rejected and the previous value is retained.
func (l *Limiter) UpdateSamplingRate(newRate float64) error {
	if newRate <= 0 || newRate > 1 {
		return fmt.Errorf("ratelimit: sampling_rate must be in (0, 1] (got %v)", newRate)
	}
	l.samplingRateBits.Store(math.Float64bits(newRate))
	return nil
}

// UpdateEnabled flips the limiter on or off at runtime. The breaker's
// internal state (engaged, engagedTotal) is preserved across disable
// so a re-enable resumes from the prior engagement count; the engaged
// flag is reset to false on disable to keep IsEngaged honest.
func (l *Limiter) UpdateEnabled(enabled bool) {
	prev := l.enabled.Swap(enabled)
	if prev && !enabled {
		l.mu.Lock()
		l.engaged = false
		l.engagedSinceNanos = 0
		l.belowSinceNanos = 0
		l.mu.Unlock()
	}
}

// Allow is the publish hot path. The caller passes the event ID for
// the deterministic sampling decision; the returned Decision tells the
// caller whether to publish and whether to annotate.
//
// When the limiter is disabled or below threshold, Allow returns
// {Publish: true, Sampled: false, SamplingRate: 1.0} -- the steady-state
// no-overhead path.
//
// When the limiter is engaged, Allow rolls FNV-1a(eventID) mod 100
// against the current samplingRate*100; events that win the roll are
// annotated, those that lose are dropped.
func (l *Limiter) Allow(eventID string) Decision {
	if !l.enabled.Load() {
		return Decision{Publish: true, Sampled: false, SamplingRate: 1.0}
	}

	now := l.clock.Now()
	nowNanos := now.UnixNano()

	threshold := l.threshold.Load()
	cooldown := l.cooldownNanos.Load()
	samplingRate := math.Float64frombits(l.samplingRateBits.Load())

	var (
		fireTransition bool
		transition     Transition
	)

	l.mu.Lock()

	bucketStart := (nowNanos / int64(bucketDuration)) * int64(bucketDuration)
	idx := (nowNanos / int64(bucketDuration)) % numBuckets
	if idx < 0 {
		idx += numBuckets
	}
	b := &l.buckets[idx]
	if b.startNanos != bucketStart {
		b.startNanos = bucketStart
		b.count = 0
	}
	b.count++

	windowCutoff := nowNanos - int64(windowDuration)
	var total int64
	for i := range l.buckets {
		if l.buckets[i].startNanos > windowCutoff {
			total += l.buckets[i].count
		}
	}

	switch {
	case !l.engaged && total > threshold:
		l.engaged = true
		l.engagedSinceNanos = nowNanos
		l.belowSinceNanos = 0
		l.engagedTotal.Add(1)
		fireTransition = true
		transition = Transition{
			Source:          l.source,
			Node:            l.node,
			Engaged:         true,
			EventsPerSecond: float64(total),
			Threshold:       int(threshold),
			SamplingRate:    samplingRate,
		}

	case l.engaged && total > threshold:
		l.belowSinceNanos = 0

	case l.engaged && total <= threshold:
		if l.belowSinceNanos == 0 {
			l.belowSinceNanos = nowNanos
		}
		if nowNanos-l.belowSinceNanos >= cooldown {
			engagedFor := time.Duration(nowNanos - l.engagedSinceNanos)
			l.engaged = false
			l.engagedSinceNanos = 0
			l.belowSinceNanos = 0
			fireTransition = true
			transition = Transition{
				Source:          l.source,
				Node:            l.node,
				Engaged:         false,
				EventsPerSecond: float64(total),
				Threshold:       int(threshold),
				SamplingRate:    samplingRate,
				EngagedFor:      engagedFor,
			}
		}
	}

	currentlyEngaged := l.engaged
	l.mu.Unlock()

	if fireTransition && l.onTransition != nil {
		l.onTransition(transition)
	}

	if !currentlyEngaged {
		return Decision{Publish: true, Sampled: false, SamplingRate: 1.0}
	}

	const samplingScale = 1_000_000
	bound := uint64(math.Ceil(samplingRate * samplingScale))
	if bound > samplingScale {
		bound = samplingScale
	}
	if hashEventID(eventID)%samplingScale < bound {
		return Decision{Publish: true, Sampled: true, SamplingRate: samplingRate}
	}
	return Decision{Publish: false, Sampled: false, SamplingRate: samplingRate}
}

// hashEventID computes FNV-1a(id) over the UTF-8 bytes of the event ID.
// FNV-1a was chosen over crypto/sha256 for speed (the limiter sits on
// the publish hot path) and over math/rand for reproducibility across
// Epic 5 evaluation re-runs (guardrail 28; NFR42).
func hashEventID(id string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(id))
	return h.Sum64()
}
