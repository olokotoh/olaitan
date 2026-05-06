package retry

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Helper: a recording sleepFn that captures requested durations and
// returns immediately. The clock argument is the elapsed simulated time,
// useful for asserting jitter / Multiplier progressions. The mutex
// guards `durations` so future tests that drive Strategy.Do from
// multiple goroutines do not race silently; the bench-shaped tests in
// this file already rely on the recording being consistent.
type recordedSleep struct {
	mu        sync.Mutex
	durations []time.Duration
}

func (r *recordedSleep) fn(ctx context.Context, d time.Duration) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	r.mu.Lock()
	r.durations = append(r.durations, d)
	r.mu.Unlock()
	return nil
}

// snapshot returns a copy of the recorded durations safe to read without
// the lock held. Tests should call this rather than touching r.durations
// directly to avoid the race detector flagging concurrent access.
func (r *recordedSleep) snapshot() []time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]time.Duration, len(r.durations))
	copy(out, r.durations)
	return out
}

func TestStrategyDo_SuccessOnFirstAttempt(t *testing.T) {
	rec := &recordedSleep{}
	s := Strategy{
		Min:         10 * time.Millisecond,
		Max:         100 * time.Millisecond,
		Multiplier:  2.0,
		Jitter:      0,
		MaxAttempts: 3,
		sleepFn:     rec.fn,
	}
	calls := 0
	err := s.Do(context.Background(), func(ctx context.Context) error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("Do: unexpected error: %v", err)
	}
	if calls != 1 {
		t.Errorf("op invocations: got %d, want 1", calls)
	}
	if len(rec.durations) != 0 {
		t.Errorf("expected zero sleeps on first-attempt success, got %d", len(rec.durations))
	}
}

func TestStrategyDo_SuccessAfterTransientFailures(t *testing.T) {
	rec := &recordedSleep{}
	s := Strategy{
		Min:         10 * time.Millisecond,
		Max:         100 * time.Millisecond,
		Multiplier:  2.0,
		Jitter:      0,
		MaxAttempts: 5,
		sleepFn:     rec.fn,
	}
	calls := 0
	transient := errors.New("transient")
	err := s.Do(context.Background(), func(ctx context.Context) error {
		calls++
		if calls < 3 {
			return transient
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Do: unexpected error: %v", err)
	}
	if calls != 3 {
		t.Errorf("op invocations: got %d, want 3", calls)
	}
	if len(rec.durations) != 2 {
		t.Errorf("sleeps: got %d, want 2 (one between each retry pair)", len(rec.durations))
	}
}

func TestStrategyDo_MaxAttemptsExhaustionReturnsLastErrorWrapped(t *testing.T) {
	rec := &recordedSleep{}
	s := Strategy{
		Min:         10 * time.Millisecond,
		Max:         100 * time.Millisecond,
		Multiplier:  2.0,
		Jitter:      0,
		MaxAttempts: 3,
		sleepFn:     rec.fn,
	}
	last := errors.New("last")
	calls := 0
	err := s.Do(context.Background(), func(ctx context.Context) error {
		calls++
		return last
	})
	if err == nil {
		t.Fatal("Do: expected error on exhaustion, got nil")
	}
	if !errors.Is(err, last) {
		t.Errorf("Do: error chain does not wrap last attempt error: %v", err)
	}
	if !strings.Contains(err.Error(), "retry:") {
		t.Errorf("Do: error message missing retry: prefix: %q", err.Error())
	}
	if calls != 3 {
		t.Errorf("op invocations: got %d, want 3", calls)
	}
	// Sleeps are inserted BETWEEN attempts: 3 attempts -> 2 sleeps.
	if len(rec.durations) != 2 {
		t.Errorf("sleeps: got %d, want 2", len(rec.durations))
	}
}

func TestStrategyDo_ContextCancelMidBackoff(t *testing.T) {
	// sleepFn returns ctx.Err() when ctx is already cancelled.
	cancellingSleep := func(ctx context.Context, d time.Duration) error {
		<-ctx.Done()
		return ctx.Err()
	}
	s := Strategy{
		Min:         10 * time.Millisecond,
		Max:         100 * time.Millisecond,
		Multiplier:  2.0,
		Jitter:      0,
		MaxAttempts: 0, // unlimited
		sleepFn:     cancellingSleep,
	}
	ctx, cancel := context.WithCancel(context.Background())
	transient := errors.New("transient")
	calls := int32(0)
	go func() {
		// Cancel after the first failure -> first sleep starts -> ctx cancel hits sleepFn.
		// The op runs once and returns transient; we then enter sleepFn which blocks
		// on ctx.Done(); cancel() unblocks it.
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	err := s.Do(ctx, func(ctx context.Context) error {
		atomic.AddInt32(&calls, 1)
		return transient
	})
	if err == nil {
		t.Fatal("Do: expected ctx error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Do: expected context.Canceled, got %v", err)
	}
	if c := atomic.LoadInt32(&calls); c != 1 {
		t.Errorf("op invocations during cancelled retry: got %d, want 1", c)
	}
}

func TestStrategyDo_ContextAlreadyCancelled(t *testing.T) {
	rec := &recordedSleep{}
	s := Strategy{
		Min: 10 * time.Millisecond, Max: 100 * time.Millisecond, Multiplier: 2.0,
		MaxAttempts: 0, sleepFn: rec.fn,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := s.Do(ctx, func(ctx context.Context) error { return errors.New("never reached") })
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Do on pre-cancelled ctx: got %v, want context.Canceled", err)
	}
}

func TestStrategyDo_ZeroValueReturnsConfigError(t *testing.T) {
	var s Strategy
	err := s.Do(context.Background(), func(ctx context.Context) error { return nil })
	if err == nil {
		t.Fatal("zero-value Strategy: expected config error, got nil")
	}
	if !strings.Contains(err.Error(), "retry:") {
		t.Errorf("config error missing retry: prefix: %q", err.Error())
	}
}

func TestStrategyDo_InvalidConfigVariants(t *testing.T) {
	cases := []struct {
		name string
		s    Strategy
	}{
		{"min-zero", Strategy{Min: 0, Max: 100 * time.Millisecond, Multiplier: 2}},
		{"min-negative", Strategy{Min: -1 * time.Millisecond, Max: 100 * time.Millisecond, Multiplier: 2}},
		{"min-greater-than-max", Strategy{Min: 200 * time.Millisecond, Max: 100 * time.Millisecond, Multiplier: 2}},
		{"multiplier-below-one", Strategy{Min: 10 * time.Millisecond, Max: 100 * time.Millisecond, Multiplier: 0.5}},
		{"jitter-negative", Strategy{Min: 10 * time.Millisecond, Max: 100 * time.Millisecond, Multiplier: 2, Jitter: -0.1}},
		{"jitter-above-one", Strategy{Min: 10 * time.Millisecond, Max: 100 * time.Millisecond, Multiplier: 2, Jitter: 1.5}},
		{"max-attempts-negative", Strategy{Min: 10 * time.Millisecond, Max: 100 * time.Millisecond, Multiplier: 2, MaxAttempts: -1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.s.Do(context.Background(), func(ctx context.Context) error { return nil })
			if err == nil {
				t.Fatalf("expected config error for %s, got nil", tc.name)
			}
			if !strings.Contains(err.Error(), "retry:") {
				t.Errorf("expected retry: prefixed error, got %q", err.Error())
			}
		})
	}
}

func TestStrategyDo_BackoffProgressionRespectsMultiplier(t *testing.T) {
	// Jitter=0 makes backoff fully deterministic so we can assert exact values.
	rec := &recordedSleep{}
	s := Strategy{
		Min:         10 * time.Millisecond,
		Max:         1 * time.Second,
		Multiplier:  2.0,
		Jitter:      0,
		MaxAttempts: 5,
		sleepFn:     rec.fn,
	}
	transient := errors.New("transient")
	_ = s.Do(context.Background(), func(ctx context.Context) error { return transient })
	// 5 attempts -> 4 sleeps. Min*Multiplier^k for k=0..3:
	want := []time.Duration{
		10 * time.Millisecond,
		20 * time.Millisecond,
		40 * time.Millisecond,
		80 * time.Millisecond,
	}
	if len(rec.durations) != len(want) {
		t.Fatalf("sleeps: got %d, want %d", len(rec.durations), len(want))
	}
	for i, w := range want {
		if rec.durations[i] != w {
			t.Errorf("sleeps[%d]: got %v, want %v", i, rec.durations[i], w)
		}
	}
}

func TestStrategyDo_BackoffCappedAtMax(t *testing.T) {
	rec := &recordedSleep{}
	s := Strategy{
		Min:         10 * time.Millisecond,
		Max:         50 * time.Millisecond,
		Multiplier:  2.0,
		Jitter:      0,
		MaxAttempts: 6,
		sleepFn:     rec.fn,
	}
	transient := errors.New("transient")
	_ = s.Do(context.Background(), func(ctx context.Context) error { return transient })
	// 6 attempts -> 5 sleeps. Progression: 10, 20, 40, 50 (capped), 50 (capped).
	want := []time.Duration{10, 20, 40, 50, 50}
	if len(rec.durations) != len(want) {
		t.Fatalf("sleeps: got %d, want %d", len(rec.durations), len(want))
	}
	for i, w := range want {
		expected := time.Duration(w) * time.Millisecond
		if rec.durations[i] != expected {
			t.Errorf("sleeps[%d]: got %v, want %v", i, rec.durations[i], expected)
		}
	}
}

func TestStrategyDo_JitterBoundsRespected(t *testing.T) {
	// At Jitter=1, equal-jitter places each sleep in [computed/2, computed).
	// Inject a deterministic randFn that walks the documented [0, 1)
	// boundary so the band assertion is provable rather than statistical;
	// the previous reliance on math/rand/v2.Float64()'s [0, 1) contract
	// would silently flake if a future Go release ever changed it.
	rec := &recordedSleep{}
	// drawSequence walks 0.0, 0.25, 0.5, 0.75, 0.9999... cycling, which
	// covers both the lower-edge (0.0 → sleep == computed/2) and
	// upper-edge (0.9999... → sleep just below computed) cases.
	draws := []float64{0.0, 0.25, 0.5, 0.75, 0.9999999}
	var idx int
	deterministicRand := func() float64 {
		v := draws[idx%len(draws)]
		idx++
		return v
	}
	s := Strategy{
		Min:         100 * time.Millisecond,
		Max:         100 * time.Millisecond, // pin so the band is fixed at [50ms, 100ms)
		Multiplier:  2.0,
		Jitter:      1.0,
		MaxAttempts: 50,
		sleepFn:     rec.fn,
		randFn:      deterministicRand,
	}
	transient := errors.New("transient")
	_ = s.Do(context.Background(), func(ctx context.Context) error { return transient })
	durations := rec.snapshot()
	if len(durations) < 40 {
		t.Fatalf("expected ~49 sleeps, got %d", len(durations))
	}
	for i, d := range durations {
		if d < 50*time.Millisecond || d >= 100*time.Millisecond {
			t.Errorf("sleeps[%d]: %v outside [50ms, 100ms)", i, d)
		}
	}
}

func TestRealSleep_RespectsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := realSleep(ctx, 100*time.Millisecond); !errors.Is(err, context.Canceled) {
		t.Errorf("realSleep on cancelled ctx: got %v, want context.Canceled", err)
	}
}

func TestRealSleep_BlocksUntilTimer(t *testing.T) {
	start := time.Now()
	if err := realSleep(context.Background(), 5*time.Millisecond); err != nil {
		t.Fatalf("realSleep: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 5*time.Millisecond {
		t.Errorf("realSleep returned too early: %v", elapsed)
	}
}

func TestRealSleep_ZeroDurationIsNoOp(t *testing.T) {
	if err := realSleep(context.Background(), 0); err != nil {
		t.Errorf("realSleep(0): unexpected error %v", err)
	}
}

func TestStrategyDo_UnlimitedAttemptsTerminateOnSuccess(t *testing.T) {
	rec := &recordedSleep{}
	s := Strategy{
		Min:         1 * time.Millisecond,
		Max:         10 * time.Millisecond,
		Multiplier:  2.0,
		Jitter:      0,
		MaxAttempts: 0, // unlimited
		sleepFn:     rec.fn,
	}
	calls := 0
	transient := errors.New("transient")
	err := s.Do(context.Background(), func(ctx context.Context) error {
		calls++
		if calls < 7 {
			return transient
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Do: unexpected error: %v", err)
	}
	if calls != 7 {
		t.Errorf("op invocations: got %d, want 7", calls)
	}
}
