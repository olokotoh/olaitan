package ratelimit

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock is an atomic-pointer-backed wall-clock substitute that
// tests advance manually. Unlike time.Now, repeated reads return the
// same value until Advance is called, so engagement transitions land
// at fixtures-known nanoseconds and assertions can name an exact
// engagement boundary.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{now: t} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

// origin is a deterministic absolute time so fake-clock arithmetic
// reads identically across test runs. Picked far from any
// time.Time{} zero so bucket-start nanoseconds never collide with the
// uninitialised-bucket sentinel.
var origin = time.Date(2026, 5, 15, 10, 0, 0, 0, time.UTC)

func newTestLimiter(t *testing.T, clock Clock, onTransition TransitionFn, mutate func(*Options)) *Limiter {
	t.Helper()
	opts := Options{
		Source:       "falco",
		Node:         "node-a",
		Threshold:    DefaultThreshold,
		Cooldown:     DefaultCooldown,
		SamplingRate: DefaultSamplingRate,
		Enabled:      true,
		Clock:        clock,
		OnTransition: onTransition,
	}
	if mutate != nil {
		mutate(&opts)
	}
	l, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return l
}

func TestNew_DefaultsApplied(t *testing.T) {
	l, err := New(Options{Source: "falco", Node: "node-a", Enabled: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if l.Threshold() != DefaultThreshold {
		t.Fatalf("threshold: got %d, want %d", l.Threshold(), DefaultThreshold)
	}
	if l.Cooldown() != DefaultCooldown {
		t.Fatalf("cooldown: got %s, want %s", l.Cooldown(), DefaultCooldown)
	}
	if l.SamplingRate() != DefaultSamplingRate {
		t.Fatalf("samplingRate: got %v, want %v", l.SamplingRate(), DefaultSamplingRate)
	}
	if !l.Enabled() {
		t.Fatalf("enabled: got false, want true")
	}
}

func TestNew_RejectsBadOptions(t *testing.T) {
	cases := []struct {
		name string
		opts Options
	}{
		{"empty source", Options{Source: "", Enabled: true, Node: "node-a"}},
		{"enabled no node", Options{Source: "falco", Enabled: true}},
		{"threshold below 1", Options{Source: "falco", Node: "node-a", Threshold: -1, Enabled: true}},
		{"cooldown below 1s", Options{Source: "falco", Node: "node-a", Threshold: 1000, Cooldown: 500 * time.Millisecond, Enabled: true}},
		{"samplingRate above 1", Options{Source: "falco", Node: "node-a", Threshold: 1000, Cooldown: time.Minute, SamplingRate: 1.5, Enabled: true}},
		{"samplingRate at 0 disallowed", Options{Source: "falco", Node: "node-a", Threshold: 1000, Cooldown: time.Minute, SamplingRate: -0.0001, Enabled: true}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.opts); err == nil {
				t.Fatalf("New: want error, got nil")
			}
		})
	}
}

func TestAllow_DisabledShortCircuit(t *testing.T) {
	l := newTestLimiter(t, newFakeClock(origin), nil, func(o *Options) {
		o.Enabled = false
	})
	for i := 0; i < 5000; i++ {
		d := l.Allow(fmt.Sprintf("evt-%d", i))
		if !d.Publish || d.Sampled || d.SamplingRate != 1.0 {
			t.Fatalf("disabled Allow: got %+v, want Publish=true Sampled=false rate=1.0", d)
		}
	}
	if l.EngagedTotal() != 0 {
		t.Fatalf("engagedTotal: got %d, want 0", l.EngagedTotal())
	}
}

func TestAllow_BelowThresholdNotEngaged(t *testing.T) {
	clock := newFakeClock(origin)
	l := newTestLimiter(t, clock, nil, nil)

	// 500 events spread evenly across 1 second is well below 1000/sec.
	for i := 0; i < 500; i++ {
		d := l.Allow(fmt.Sprintf("evt-%d", i))
		if !d.Publish || d.Sampled {
			t.Fatalf("below-threshold Allow[%d]: got %+v", i, d)
		}
		clock.Advance(2 * time.Millisecond)
	}
	if l.IsEngaged() {
		t.Fatal("limiter engaged at 500 events over 1 second")
	}
	if l.EngagedTotal() != 0 {
		t.Fatalf("engagedTotal: got %d, want 0", l.EngagedTotal())
	}
}

func TestAllow_AboveThresholdEngages(t *testing.T) {
	clock := newFakeClock(origin)

	var transitions []Transition
	var mu sync.Mutex
	onT := func(tr Transition) {
		mu.Lock()
		defer mu.Unlock()
		transitions = append(transitions, tr)
	}

	l := newTestLimiter(t, clock, onT, nil)

	// 1500 events with no clock advance => 1500 events in one bucket
	// at one instant, which simulates a burst that exceeds 1000/sec.
	for i := 0; i < 1500; i++ {
		l.Allow(fmt.Sprintf("evt-%d", i))
	}

	if !l.IsEngaged() {
		t.Fatal("limiter not engaged after 1500 events in one tick")
	}
	if l.EngagedTotal() != 1 {
		t.Fatalf("engagedTotal: got %d, want 1", l.EngagedTotal())
	}

	mu.Lock()
	defer mu.Unlock()
	if len(transitions) != 1 {
		t.Fatalf("transitions: got %d, want 1; got %+v", len(transitions), transitions)
	}
	if !transitions[0].Engaged {
		t.Fatalf("transitions[0].Engaged: got false, want true")
	}
	if transitions[0].Source != "falco" || transitions[0].Node != "node-a" {
		t.Fatalf("transition labels: got %+v", transitions[0])
	}
}

func TestAllow_SustainedEngagementOneTransition(t *testing.T) {
	clock := newFakeClock(origin)

	var engageCount, disengageCount int32
	onT := func(tr Transition) {
		if tr.Engaged {
			atomic.AddInt32(&engageCount, 1)
		} else {
			atomic.AddInt32(&disengageCount, 1)
		}
	}

	l := newTestLimiter(t, clock, onT, nil)

	// Run 5000 events at 2000/sec for 2.5s: well above 1000/sec.
	for i := 0; i < 5000; i++ {
		l.Allow(fmt.Sprintf("evt-%d", i))
		clock.Advance(500 * time.Microsecond)
	}

	if got := atomic.LoadInt32(&engageCount); got != 1 {
		t.Fatalf("engageCount: got %d, want 1 (sustained engagement must not re-fire)", got)
	}
	if got := atomic.LoadInt32(&disengageCount); got != 0 {
		t.Fatalf("disengageCount: got %d, want 0", got)
	}
	if l.EngagedTotal() != 1 {
		t.Fatalf("engagedTotal: got %d, want 1", l.EngagedTotal())
	}
}

func TestAllow_CooldownDisengagement(t *testing.T) {
	clock := newFakeClock(origin)

	var disengaged []Transition
	var mu sync.Mutex
	onT := func(tr Transition) {
		if !tr.Engaged {
			mu.Lock()
			disengaged = append(disengaged, tr)
			mu.Unlock()
		}
	}

	l := newTestLimiter(t, clock, onT, func(o *Options) {
		o.Cooldown = 2 * time.Second
	})

	// Burst above threshold to engage.
	for i := 0; i < 1500; i++ {
		l.Allow(fmt.Sprintf("burst-%d", i))
	}
	if !l.IsEngaged() {
		t.Fatal("setup: limiter not engaged after burst")
	}

	// Advance past the sliding window so the burst's contribution
	// expires; the limiter still sees engaged=true until cooldown.
	clock.Advance(2 * time.Second)

	// Send a few events well below threshold; the first one should
	// see total <= threshold and arm the cooldown timer at belowSince.
	l.Allow("calm-0")
	if !l.IsEngaged() {
		t.Fatal("limiter disengaged before cooldown elapsed")
	}

	// Advance cooldown duration so the next Allow trips disengagement.
	clock.Advance(2 * time.Second)
	l.Allow("calm-1")

	if l.IsEngaged() {
		t.Fatal("limiter still engaged after cooldown elapsed")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(disengaged) != 1 {
		t.Fatalf("disengaged transitions: got %d, want 1; got %+v", len(disengaged), disengaged)
	}
	if disengaged[0].EngagedFor <= 0 {
		t.Fatalf("disengaged[0].EngagedFor: got %s, want > 0", disengaged[0].EngagedFor)
	}
}

func TestAllow_CooldownResetsOnReengage(t *testing.T) {
	clock := newFakeClock(origin)

	var transitions []Transition
	var mu sync.Mutex
	onT := func(tr Transition) {
		mu.Lock()
		defer mu.Unlock()
		transitions = append(transitions, tr)
	}

	l := newTestLimiter(t, clock, onT, func(o *Options) {
		o.Cooldown = 2 * time.Second
	})

	// Engage.
	for i := 0; i < 1500; i++ {
		l.Allow(fmt.Sprintf("burst-%d", i))
	}
	if !l.IsEngaged() {
		t.Fatal("limiter not engaged")
	}

	// Advance past the window so old burst counts roll off.
	clock.Advance(2 * time.Second)

	// One calm tick arms cooldown.
	l.Allow("calm-0")

	// Advance just under cooldown, then burst again above threshold:
	// cooldown timer should reset, limiter stays engaged.
	clock.Advance(1500 * time.Millisecond)
	for i := 0; i < 1500; i++ {
		l.Allow(fmt.Sprintf("burst2-%d", i))
	}
	if !l.IsEngaged() {
		t.Fatal("limiter disengaged across re-burst")
	}

	mu.Lock()
	defer mu.Unlock()
	for _, tr := range transitions {
		if !tr.Engaged {
			t.Fatalf("unexpected disengage transition: %+v", tr)
		}
	}
	if l.EngagedTotal() != 1 {
		t.Fatalf("engagedTotal: got %d, want 1 (re-burst within cooldown must be continuous)", l.EngagedTotal())
	}
}

func TestAllow_SampledFractionWithinTolerance(t *testing.T) {
	clock := newFakeClock(origin)
	l := newTestLimiter(t, clock, nil, nil)

	// Burst to engage the breaker so the sampling path runs.
	for i := 0; i < 1500; i++ {
		l.Allow(fmt.Sprintf("burst-%d", i))
	}
	if !l.IsEngaged() {
		t.Fatal("limiter not engaged before sampling test")
	}

	// 1000 follow-up events while engaged; count how many publish.
	var sampled, dropped int
	for i := 0; i < 1000; i++ {
		d := l.Allow(fmt.Sprintf("sample-%d", i))
		switch {
		case d.Publish && d.Sampled:
			sampled++
		case !d.Publish:
			dropped++
		}
	}
	total := sampled + dropped
	if total != 1000 {
		t.Fatalf("partition: sampled=%d dropped=%d total=%d", sampled, dropped, total)
	}

	// AC5: sampling fraction within ±2 percent absolute of 0.1.
	if sampled < 80 || sampled > 120 {
		t.Fatalf("sampled fraction: got %d/1000, want 80..120", sampled)
	}
}

func TestAllow_SamplingDeterministic(t *testing.T) {
	run := func() []bool {
		clock := newFakeClock(origin)
		l := newTestLimiter(t, clock, nil, nil)
		for i := 0; i < 1500; i++ {
			l.Allow(fmt.Sprintf("burst-%d", i))
		}
		decisions := make([]bool, 200)
		for i := 0; i < 200; i++ {
			d := l.Allow(fmt.Sprintf("sample-%d", i))
			decisions[i] = d.Publish && d.Sampled
		}
		return decisions
	}
	first := run()
	second := run()
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("sampling decisions diverge at i=%d: first=%v second=%v", i, first[i], second[i])
		}
	}
}

func TestUpdate_AcceptsAndRejects(t *testing.T) {
	l := newTestLimiter(t, newFakeClock(origin), nil, nil)

	if err := l.UpdateThreshold(500); err != nil {
		t.Fatalf("UpdateThreshold(500): %v", err)
	}
	if l.Threshold() != 500 {
		t.Fatalf("threshold after update: got %d, want 500", l.Threshold())
	}
	if err := l.UpdateThreshold(0); err == nil {
		t.Fatal("UpdateThreshold(0): want error, got nil")
	}
	if l.Threshold() != 500 {
		t.Fatalf("threshold preserved after invalid update: got %d, want 500", l.Threshold())
	}

	if err := l.UpdateCooldown(30 * time.Second); err != nil {
		t.Fatalf("UpdateCooldown: %v", err)
	}
	if l.Cooldown() != 30*time.Second {
		t.Fatalf("cooldown after update: got %s, want 30s", l.Cooldown())
	}
	if err := l.UpdateCooldown(500 * time.Millisecond); err == nil {
		t.Fatal("UpdateCooldown(500ms): want error, got nil")
	}

	if err := l.UpdateSamplingRate(0.25); err != nil {
		t.Fatalf("UpdateSamplingRate: %v", err)
	}
	if l.SamplingRate() != 0.25 {
		t.Fatalf("samplingRate after update: got %v, want 0.25", l.SamplingRate())
	}
	if err := l.UpdateSamplingRate(2.0); err == nil {
		t.Fatal("UpdateSamplingRate(2.0): want error, got nil")
	}
	if err := l.UpdateSamplingRate(0); err == nil {
		t.Fatal("UpdateSamplingRate(0): want error, got nil")
	}
}

func TestUpdateThreshold_TakesEffectWithinOneBucket(t *testing.T) {
	clock := newFakeClock(origin)
	l := newTestLimiter(t, clock, nil, func(o *Options) {
		o.Threshold = 1000
	})

	// 200 events: below the 1000 threshold, not engaged.
	for i := 0; i < 200; i++ {
		l.Allow(fmt.Sprintf("evt-%d", i))
	}
	if l.IsEngaged() {
		t.Fatal("limiter engaged at 200 events with threshold 1000")
	}

	// Drop the threshold and run 200 more in the same bucket: the
	// sliding-window count is now ~400 over the last second, which
	// exceeds the new threshold of 100.
	if err := l.UpdateThreshold(100); err != nil {
		t.Fatalf("UpdateThreshold: %v", err)
	}
	clock.Advance(50 * time.Millisecond)
	for i := 200; i < 400; i++ {
		l.Allow(fmt.Sprintf("evt-%d", i))
	}
	if !l.IsEngaged() {
		t.Fatal("limiter not engaged after threshold dropped to 100")
	}
}

func TestUpdateEnabled_FalseShortCircuitsImmediately(t *testing.T) {
	clock := newFakeClock(origin)
	l := newTestLimiter(t, clock, nil, nil)

	// Engage first.
	for i := 0; i < 1500; i++ {
		l.Allow(fmt.Sprintf("burst-%d", i))
	}
	if !l.IsEngaged() {
		t.Fatal("limiter not engaged")
	}

	// Disable: subsequent Allows should publish unsampled regardless
	// of the prior engagement state, and IsEngaged should report false.
	l.UpdateEnabled(false)
	if l.IsEngaged() {
		t.Fatal("UpdateEnabled(false) did not clear engagement")
	}
	for i := 0; i < 100; i++ {
		d := l.Allow(fmt.Sprintf("post-%d", i))
		if !d.Publish || d.Sampled || d.SamplingRate != 1.0 {
			t.Fatalf("post-disable Allow[%d]: %+v", i, d)
		}
	}

	// Re-enable: starts fresh but the engagedTotal counter survives.
	l.UpdateEnabled(true)
	for i := 0; i < 1500; i++ {
		l.Allow(fmt.Sprintf("burst2-%d", i))
	}
	if !l.IsEngaged() {
		t.Fatal("re-enabled limiter did not engage on second burst")
	}
	if l.EngagedTotal() != 2 {
		t.Fatalf("engagedTotal across enable cycle: got %d, want 2", l.EngagedTotal())
	}
}

// TestAllow_ConcurrentRace fires 100 goroutines doing 10000 Allow calls
// each against a single Limiter under -race. The expectation is no data
// race and a single engagement count regardless of scheduling.
func TestAllow_ConcurrentRace(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping concurrent race test in -short mode")
	}

	clock := newFakeClock(origin)
	l := newTestLimiter(t, clock, nil, nil)

	const goroutines = 100
	const iter = 10000

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		g := g
		go func() {
			defer wg.Done()
			for i := 0; i < iter; i++ {
				l.Allow(fmt.Sprintf("g%d-i%d", g, i))
			}
		}()
	}
	wg.Wait()

	if !l.IsEngaged() {
		t.Fatal("limiter not engaged after 1M concurrent Allow calls")
	}
	if l.EngagedTotal() != 1 {
		t.Fatalf("engagedTotal: got %d, want exactly 1 across the burst", l.EngagedTotal())
	}
}

// TestAllow_NotEngagedSteadyState confirms the no-overhead path: when
// Enabled=true and the rate stays well below threshold for several
// seconds, the limiter never engages and every event publishes
// unmodified.
func TestAllow_NotEngagedSteadyState(t *testing.T) {
	clock := newFakeClock(origin)

	var transitions int32
	onT := func(_ Transition) { atomic.AddInt32(&transitions, 1) }

	l := newTestLimiter(t, clock, onT, nil)

	// 100 events/sec for 3 seconds: well below threshold.
	for sec := 0; sec < 3; sec++ {
		for i := 0; i < 100; i++ {
			d := l.Allow(fmt.Sprintf("evt-%d-%d", sec, i))
			if !d.Publish || d.Sampled {
				t.Fatalf("steady-state Allow: %+v", d)
			}
			clock.Advance(10 * time.Millisecond)
		}
	}
	if got := atomic.LoadInt32(&transitions); got != 0 {
		t.Fatalf("transitions in steady state: got %d, want 0", got)
	}
}

// TestNew_DisabledDoesNotRequireNode confirms an Enabled=false limiter
// is constructable without a node label so adapters can pass through a
// zero-value Options when rate limiting is off cluster-wide.
func TestNew_DisabledDoesNotRequireNode(t *testing.T) {
	l, err := New(Options{Source: "falco", Enabled: false})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 5000; i++ {
		d := l.Allow(fmt.Sprintf("evt-%d", i))
		if !d.Publish || d.Sampled {
			t.Fatalf("disabled Allow: %+v", d)
		}
	}
}
