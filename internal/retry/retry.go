// Package retry provides an exponential-backoff helper for connect-loop
// patterns. Single purpose: keep callers like the Falco gRPC adapter
// (internal/collector/falco) free from the timer-context-randomness
// boilerplate that retry loops invariably grow when written inline.
//
// The package depends only on the standard library, including
// math/rand/v2 (Go 1.22+; project pin is 1.25). v2 is goroutine-safe by
// default so callers do not need their own synchronisation around random
// jitter draws.
//
// Equal-jitter is the chosen anti-thundering-herd algorithm. Per the AWS
// Architecture Blog convention: half of the computed delay is fixed,
// the other half is uniform-random in [0, half), giving a final sleep in
// [computed/2, computed) at full jitter. The Strategy.Jitter knob in
// [0, 1] linearly scales how much randomness is applied: Jitter=0 is
// fully deterministic; Jitter=1 is full equal-jitter.
//
// Validation runs on the first call to Do, not at struct-construction
// time, so callers do not need a separate New constructor. A zero-value
// Strategy{} therefore returns a config error from Do rather than
// spinning at zero delay.
package retry

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"
)

// Strategy describes an exponential-backoff retry policy.
//
// Min is the initial delay; Max caps the per-attempt delay. Multiplier
// (must be >= 1.0) governs how aggressively the delay grows per attempt.
// Jitter (must be in [0, 1]) controls how much equal-jitter randomness
// is mixed in: 0 is fully deterministic, 1 is full equal-jitter.
//
// MaxAttempts caps the total number of op invocations. 0 means unlimited
// (retry until ctx is cancelled or op succeeds). Negative values are a
// configuration error.
type Strategy struct {
	Min         time.Duration
	Max         time.Duration
	Multiplier  float64
	Jitter      float64
	MaxAttempts int

	// sleepFn is an unexported test seam: when non-nil, used instead of
	// the default timer-and-context sleep. Production callers cannot set
	// this field (no exported constructor takes it); tests in this
	// package set it via a composite literal.
	sleepFn func(ctx context.Context, d time.Duration) error

	// randFn is an unexported test seam for the jitter draw. When
	// non-nil it is used instead of math/rand/v2.Float64. Production
	// callers cannot set this; tests inject a deterministic source so
	// jitter-bound assertions are provable rather than statistical.
	randFn func() float64
}

// IsZero reports whether s is the Go zero value (no fields set). Useful
// at construction sites that want to substitute a default Strategy when
// the caller did not supply one. The check excludes the unexported test
// seams; production callers cannot set those.
func (s Strategy) IsZero() bool {
	return s.Min == 0 &&
		s.Max == 0 &&
		s.Multiplier == 0 &&
		s.Jitter == 0 &&
		s.MaxAttempts == 0
}

// Validate runs every config invariant. Exported so callers (e.g. the
// Falco adapter constructor) can fail fast on a partial misconfiguration
// rather than discover it on the first retry attempt.
func (s Strategy) Validate() error {
	return s.validate()
}

// Do invokes op with backoff between failed attempts.
//
// Returns nil on success. Returns ctx.Err() (wrapped via fmt.Errorf so
// errors.Is(err, context.Canceled) still works) when ctx is cancelled
// before or during the loop. Returns a "retry: max attempts exhausted"
// error wrapping the last attempt's error when MaxAttempts > 0 is hit.
// Returns a "retry: <field>" config error if the strategy is invalid.
//
// If op returns an error wrapped in *PermanentError (via Permanent),
// Do returns the underlying error immediately without sleeping or
// re-trying. This is the standard pattern from cenkalti/backoff and
// lets callers signal "this error is a configuration mistake; retrying
// will never help" without modifying the Strategy struct.
func (s Strategy) Do(ctx context.Context, op func(ctx context.Context) error) error {
	if err := s.validate(); err != nil {
		return err
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("retry: ctx already done: %w", err)
	}

	attempt := 0
	var lastErr error
	for {
		attempt++
		err := op(ctx)
		if err == nil {
			return nil
		}
		// Treat ctx errors as terminal; do not retry past a cancelled context.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("retry: ctx cancelled during op: %w", err)
		}
		// Caller-signalled permanent error: bail out without retrying.
		var perm *PermanentError
		if errors.As(err, &perm) {
			return perm.Unwrap()
		}
		lastErr = err

		if s.MaxAttempts > 0 && attempt >= s.MaxAttempts {
			return fmt.Errorf("retry: max attempts (%d) exhausted: %w", s.MaxAttempts, lastErr)
		}

		delay := s.computeDelay(attempt)

		sleeper := s.sleepFn
		if sleeper == nil {
			sleeper = realSleep
		}
		if serr := sleeper(ctx, delay); serr != nil {
			return fmt.Errorf("retry: ctx cancelled during backoff: %w", serr)
		}
	}
}

// computeDelay returns the per-attempt sleep duration with jitter applied.
// The deterministic component grows as Min * Multiplier^(attempt-1),
// capped at Max. With Jitter > 0, equal-jitter scales the random portion
// in [0, computed*Jitter); the deterministic portion is the remainder.
func (s Strategy) computeDelay(attempt int) time.Duration {
	// Compute the deterministic exponential: Min * Multiplier^(attempt-1).
	// Use float64 in the loop and convert at the end so the time.Duration
	// scale (nanoseconds) does not overflow on long retry chains.
	computed := float64(s.Min)
	for i := 1; i < attempt; i++ {
		computed *= s.Multiplier
		if computed >= float64(s.Max) {
			computed = float64(s.Max)
			break
		}
	}

	if s.Jitter == 0 {
		return time.Duration(computed)
	}

	// Equal-jitter scaled by Jitter: take a `spread = computed * Jitter / 2`
	// chunk off the top, replace it with `rand[0, spread)`. The result lies
	// in `[computed - spread, computed)`. At Jitter=1 this collapses to
	// `[computed/2, computed)`, the canonical equal-jitter form.
	spread := computed * s.Jitter / 2
	rng := s.randFn
	if rng == nil {
		rng = rand.Float64
	}
	r := rng() * spread
	return time.Duration((computed - spread) + r)
}

// validate runs every config invariant; returns the first violation as
// a "retry: <field>" error so the caller can grep logs.
func (s Strategy) validate() error {
	if s.Min <= 0 {
		return fmt.Errorf("retry: min must be > 0 (got %v)", s.Min)
	}
	if s.Max < s.Min {
		return fmt.Errorf("retry: max must be >= min (got min=%v, max=%v)", s.Min, s.Max)
	}
	if s.Multiplier < 1.0 {
		return fmt.Errorf("retry: multiplier must be >= 1.0 (got %v)", s.Multiplier)
	}
	if s.Jitter < 0 || s.Jitter > 1 {
		return fmt.Errorf("retry: jitter must be in [0, 1] (got %v)", s.Jitter)
	}
	if s.MaxAttempts < 0 {
		return fmt.Errorf("retry: max-attempts must be >= 0 (got %d, where 0 means unlimited)", s.MaxAttempts)
	}
	return nil
}

// PermanentError marks an error as non-retryable so Strategy.Do bails
// out without backoff or further attempts. Construct via Permanent.
// Errors wrapped this way are typically configuration mistakes
// (permission denied on a Unix socket, gRPC Unauthenticated) where the
// next attempt cannot succeed without operator intervention; loud,
// fast failure is the right signal so the parent process can crash and
// kubelet can restart the pod.
type PermanentError struct {
	err error
}

// Error returns the underlying error message.
func (p *PermanentError) Error() string { return p.err.Error() }

// Unwrap returns the wrapped error so errors.Is/As reach through.
func (p *PermanentError) Unwrap() error { return p.err }

// Permanent wraps err so Strategy.Do treats it as terminal. A nil err
// returns nil (unchanged behaviour: no error means no retry).
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return &PermanentError{err: err}
}

// realSleep blocks for d unless ctx is cancelled first; in the latter
// case it returns ctx.Err() promptly. Allocating a new timer per
// invocation is fine because retry loops are not on a hot path.
func realSleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
