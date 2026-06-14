package settling

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/schema"
)

func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakePublisher captures published events for assertion and optionally fails a
// configurable number of times first (to exercise the publish-retry path).
type fakePublisher struct {
	mu        sync.Mutex
	events    []IncidentFinalised
	failFirst int
	err       error
}

func (f *fakePublisher) PublishIncidentFinalised(_ context.Context, evt IncidentFinalised) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failFirst > 0 {
		f.failFirst--
		if f.err != nil {
			return f.err
		}
		return errors.New("nats down")
	}
	f.events = append(f.events, evt)
	return nil
}

func (f *fakePublisher) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.events)
}

func (f *fakePublisher) snapshot() []IncidentFinalised {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]IncidentFinalised, len(f.events))
	copy(out, f.events)
	return out
}

// fakeHistory is a HistoryReader returning a fixed history (or an error).
type fakeHistory struct {
	hist []schema.StateTransition
	err  error
}

func (f *fakeHistory) LoadHistory(_ context.Context, _ string) ([]schema.StateTransition, error) {
	return f.hist, f.err
}

func nonClean(wid string, to schema.PodSecurityState, score float64) schema.StateTransition {
	return schema.StateTransition{
		Timestamp:   time.Now(),
		FromState:   schema.StateClean,
		ToState:     to,
		TriggerType: "automated",
		Confidence:  score,
		WorkloadID:  wid,
		PackageID:   "pkg-" + wid,
		Reason:      schema.ReasonEscalationThresholdCrossed,
	}
}

// runController starts a controller with a short window on a cancellable
// goroutine and returns the controller plus a stop func.
func runController(t *testing.T, cfg Config, pub Publisher, hist HistoryReader) (*Controller, func()) {
	t.Helper()
	c, err := New(cfg, pub, hist, discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = c.Run(ctx)
	}()
	return c, func() {
		cancel()
		<-done
	}
}

// waitForCount polls until pub has at least n events or the deadline passes.
func waitForCount(t *testing.T, pub *fakePublisher, n int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if pub.count() >= n {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestStableFinalisesOnce: a workload that stays non-CLEAN past the window
// produces exactly one IncidentFinalised carrying the surviving final state and
// the score on the transition that established it (AC1/AC3, BI-7).
func TestStableFinalisesOnce(t *testing.T) {
	pub := &fakePublisher{}
	c, stop := runController(t, Config{Window: 30 * time.Millisecond}, pub, nil)
	defer stop()

	c.Publish(nonClean("w1", schema.StateQuarantined, 88.5))

	waitForCount(t, pub, 1, time.Second)
	if got := pub.count(); got != 1 {
		t.Fatalf("event count = %d, want exactly 1", got)
	}
	evt := pub.snapshot()[0]
	if evt.FinalState != string(schema.StateQuarantined) {
		t.Errorf("final_state = %q, want QUARANTINED", evt.FinalState)
	}
	if evt.ThreatScore != 88.5 {
		t.Errorf("threat_score = %v, want 88.5 (captured from the transition)", evt.ThreatScore)
	}
	if evt.PackageID != "pkg-w1" || evt.WorkloadID != "w1" {
		t.Errorf("package/workload = %q/%q, want pkg-w1/w1", evt.PackageID, evt.WorkloadID)
	}
	if evt.SchemaVersion != SchemaVersionIncidentFinalised {
		t.Errorf("schema_version = %q", evt.SchemaVersion)
	}

	// Give the loop time to (not) double-fire.
	time.Sleep(60 * time.Millisecond)
	if got := pub.count(); got != 1 {
		t.Fatalf("event count after settle = %d, want still 1 (once-only)", got)
	}
}

// TestOscillatingResetsTimer: repeated non-CLEAN edges inside the window reset
// the timer so the window only completes after the last edge, and the surviving
// candidate is the final state (AC2). At most one finalisation results.
func TestOscillatingResetsTimer(t *testing.T) {
	pub := &fakePublisher{}
	window := 40 * time.Millisecond
	c, stop := runController(t, Config{Window: window}, pub, nil)
	defer stop()

	// Three edges spaced inside the window; each resets the timer.
	c.Publish(nonClean("w1", schema.StateSuspicious, 30))
	time.Sleep(15 * time.Millisecond)
	c.Publish(nonClean("w1", schema.StateRestricted, 55))
	time.Sleep(15 * time.Millisecond)
	c.Publish(nonClean("w1", schema.StateQuarantined, 91))

	// Before the full window since the LAST edge, no finalisation yet.
	time.Sleep(20 * time.Millisecond)
	if got := pub.count(); got != 0 {
		t.Fatalf("finalised %d before the reset window elapsed, want 0", got)
	}

	waitForCount(t, pub, 1, time.Second)
	if got := pub.count(); got != 1 {
		t.Fatalf("event count = %d, want exactly 1 after stabilisation", got)
	}
	if evt := pub.snapshot()[0]; evt.FinalState != string(schema.StateQuarantined) || evt.ThreatScore != 91 {
		t.Errorf("surviving candidate = %q/%v, want QUARANTINED/91", evt.FinalState, evt.ThreatScore)
	}
}

// TestDeescalationToCleanCancels: a CLEAN transition during the window cancels
// the timer; no IncidentFinalised is published (AC4).
func TestDeescalationToCleanCancels(t *testing.T) {
	pub := &fakePublisher{}
	c, stop := runController(t, Config{Window: 40 * time.Millisecond}, pub, nil)
	defer stop()

	c.Publish(nonClean("w1", schema.StateQuarantined, 91))
	time.Sleep(15 * time.Millisecond)
	clean := nonClean("w1", schema.StateClean, 0)
	clean.FromState = schema.StateQuarantined
	c.Publish(clean)

	time.Sleep(80 * time.Millisecond)
	if got := pub.count(); got != 0 {
		t.Fatalf("event count = %d, want 0 (CLEAN cancels finalisation, AC4)", got)
	}
}

// TestCleanThenNewIncidentReFinalises: after a CLEAN cycle clears the finalised
// marker, a NEW non-CLEAN incident for the same workload finalises again, and
// the two events carry DISTINCT dedup msg ids so the second is not suppressed
// by the JetStream dedup window (BI-8, Open Assumption 5).
func TestCleanThenNewIncidentReFinalises(t *testing.T) {
	pub := &fakePublisher{}
	c, stop := runController(t, Config{Window: 25 * time.Millisecond}, pub, nil)
	defer stop()

	// First incident.
	c.Publish(nonClean("w1", schema.StateRestricted, 60))
	waitForCount(t, pub, 1, time.Second)

	// De-escalate to CLEAN (clears the finalised marker).
	clean := nonClean("w1", schema.StateClean, 0)
	clean.FromState = schema.StateRestricted
	c.Publish(clean)
	time.Sleep(10 * time.Millisecond)

	// A genuinely new incident finalises again.
	second := nonClean("w1", schema.StateQuarantined, 95)
	second.PackageID = "pkg-w1-second"
	c.Publish(second)
	waitForCount(t, pub, 2, time.Second)

	if got := pub.count(); got != 2 {
		t.Fatalf("event count = %d, want 2 (a new incident after CLEAN re-finalises)", got)
	}
	evs := pub.snapshot()
	id0, id1 := FinalisedMsgID(evs[0]), FinalisedMsgID(evs[1])
	if id0 == id1 {
		t.Fatalf("dedup msg ids must differ across incidents, both = %q", id0)
	}
}

// TestRestartReplayDeduped: two finalisations of the SAME incident (same
// package_id + same finalised_at) yield the SAME dedup msg id, so a restart-
// replay is server-side suppressed; the in-memory once-only guard already
// prevents a double publish within one process lifetime.
func TestRestartReplayDeduped(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	a := IncidentFinalised{PackageID: "pkg-1", FinalisedAt: now}
	b := IncidentFinalised{PackageID: "pkg-1", FinalisedAt: now}
	if FinalisedMsgID(a) != FinalisedMsgID(b) {
		t.Fatalf("same incident must dedup to the same msg id: %q vs %q", FinalisedMsgID(a), FinalisedMsgID(b))
	}
	// A different finalised_at (a new incident instance) must differ.
	bDiff := IncidentFinalised{PackageID: "pkg-1", FinalisedAt: now.Add(time.Second)}
	if FinalisedMsgID(a) == FinalisedMsgID(bDiff) {
		t.Fatal("a distinct finalisation instant must yield a distinct dedup id")
	}
}

// TestDropNeverBlocks: Publish on a full queue does not block the caller (the
// FSM hot path). We fill the queue (no Run draining) and assert Publish returns
// promptly.
func TestDropNeverBlocks(t *testing.T) {
	c, err := New(Config{Window: time.Second, QueueSize: 2}, &fakePublisher{}, nil, discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// No Run goroutine: the queue fills and then Publish must drop, never block.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			c.Publish(nonClean("w1", schema.StateSuspicious, 10))
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on a full queue (must drop, not block the FSM goroutine)")
	}
}

// TestPinnedWorkloadFinalises: a workload pinned non-CLEAN by an operator
// override (TriggerType=override) finalises identically to an automated one
// (Open Assumption 3).
func TestPinnedWorkloadFinalises(t *testing.T) {
	pub := &fakePublisher{}
	c, stop := runController(t, Config{Window: 25 * time.Millisecond}, pub, nil)
	defer stop()

	pinned := nonClean("w-pinned", schema.StateQuarantined, 50)
	pinned.TriggerType = "override"
	pinned.Reason = schema.ReasonOperatorOverride
	pinned.OperatorID = "alice"
	c.Publish(pinned)

	waitForCount(t, pub, 1, time.Second)
	if got := pub.count(); got != 1 {
		t.Fatalf("pinned workload finalisation count = %d, want 1", got)
	}
	if evt := pub.snapshot()[0]; evt.FinalState != string(schema.StateQuarantined) {
		t.Errorf("pinned final_state = %q, want QUARANTINED", evt.FinalState)
	}
}

// TestHistoryPrefersPersisted: when a HistoryReader returns a non-empty history,
// the event carries the persisted history (restart-safe), not the in-process
// accumulation (Open Assumption 2).
func TestHistoryPrefersPersisted(t *testing.T) {
	persisted := []schema.StateTransition{
		{FromState: schema.StateClean, ToState: schema.StateSuspicious, Confidence: 30},
		{FromState: schema.StateSuspicious, ToState: schema.StateRestricted, Confidence: 55},
		{FromState: schema.StateRestricted, ToState: schema.StateQuarantined, Confidence: 91},
	}
	pub := &fakePublisher{}
	c, stop := runController(t, Config{Window: 25 * time.Millisecond}, pub, &fakeHistory{hist: persisted})
	defer stop()

	c.Publish(nonClean("w1", schema.StateQuarantined, 91))
	waitForCount(t, pub, 1, time.Second)
	evt := pub.snapshot()[0]
	if len(evt.History) != 3 {
		t.Fatalf("history len = %d, want 3 (persisted preferred)", len(evt.History))
	}
}

// TestHistoryFallsBackToInProcess: when no HistoryReader is wired (or it errors/
// returns empty), the event carries the in-process accumulation.
func TestHistoryFallsBackToInProcess(t *testing.T) {
	pub := &fakePublisher{}
	// HistoryReader errors -> fall back to in-process.
	c, stop := runController(t, Config{Window: 30 * time.Millisecond}, pub, &fakeHistory{err: errors.New("redis down")})
	defer stop()

	c.Publish(nonClean("w1", schema.StateSuspicious, 30))
	time.Sleep(10 * time.Millisecond)
	c.Publish(nonClean("w1", schema.StateRestricted, 55))
	waitForCount(t, pub, 1, time.Second)
	evt := pub.snapshot()[0]
	if len(evt.History) != 2 {
		t.Fatalf("in-process history len = %d, want 2 (both observed edges)", len(evt.History))
	}
}

// TestPublishFailureDoesNotMarkFinalised: a failed publish does not mark the
// incident finalised, so a subsequent re-arm retries and eventually succeeds.
func TestPublishFailureDoesNotMarkFinalised(t *testing.T) {
	pub := &fakePublisher{failFirst: 1}
	c, stop := runController(t, Config{Window: 20 * time.Millisecond}, pub, nil)
	defer stop()

	// First edge -> timer fires -> publish FAILS (failFirst consumes it).
	c.Publish(nonClean("w1", schema.StateQuarantined, 80))
	time.Sleep(60 * time.Millisecond)
	if got := pub.count(); got != 0 {
		t.Fatalf("event count = %d after a failing publish, want 0", got)
	}
	// A new edge re-arms; this time the publish succeeds.
	c.Publish(nonClean("w1", schema.StateQuarantined, 82))
	waitForCount(t, pub, 1, time.Second)
	if got := pub.count(); got != 1 {
		t.Fatalf("event count = %d after retry, want 1", got)
	}
}

// TestNewNilPublisher rejects a nil publisher at construction.
func TestNewNilPublisher(t *testing.T) {
	if _, err := New(Config{}, nil, nil, discardLog()); err == nil {
		t.Fatal("New must reject a nil publisher")
	}
}

// TestRunReturnsNilOnContextCancel: Run returns nil on graceful cancellation
// (errgroup discipline).
func TestRunReturnsNilOnContextCancel(t *testing.T) {
	c, err := New(Config{Window: time.Second}, &fakePublisher{}, nil, discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- c.Run(ctx) }()
	cancel()
	select {
	case e := <-errc:
		if e != nil {
			t.Fatalf("Run returned %v, want nil on context cancel", e)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not return on context cancel")
	}
}
