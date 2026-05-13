package applog

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	natsjs "github.com/nats-io/nats.go/jetstream"

	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// stubPublisher is a minimal natsPublisher that records every publish
// and lets tests programme failure scenarios. Concurrency-safe via a
// sync.Mutex; the adapter's consume loop is single-goroutine but
// multiple test goroutines (the adapter goroutine + the test driver)
// observe the publisher state, so a mutex is the correct primitive
// here despite the apparent simplicity.
type stubPublisher struct {
	mu          sync.Mutex
	subjects    []string
	failAlways  error
	failOnce    error
	totalCalls  int64
	totalOK     int64
	publishedEv []schema.Event
}

func newStubPublisher() *stubPublisher {
	return &stubPublisher{}
}

func (s *stubPublisher) PublishJS(ctx context.Context, subject string, data any, opts ...natsjs.PublishOpt) (*natsjs.PubAck, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.totalCalls++
	if s.failAlways != nil {
		return nil, s.failAlways
	}
	if s.failOnce != nil {
		err := s.failOnce
		s.failOnce = nil
		return nil, err
	}
	s.totalOK++
	if ev, ok := data.(schema.Event); ok {
		s.publishedEv = append(s.publishedEv, ev)
	}
	s.subjects = append(s.subjects, subject)
	return &natsjs.PubAck{Stream: "EVENTS_RAW", Sequence: uint64(s.totalOK)}, nil
}

func (s *stubPublisher) successes() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.totalOK
}

func (s *stubPublisher) setFailAlways(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failAlways = err
}

func newTestAdapter(t *testing.T, pub natsPublisher) *Adapter {
	t.Helper()
	cfg := Config{
		StdoutPath:       "/tmp/test/stdout.log",
		StderrPath:       "/tmp/test/stderr.log",
		Pod:              schema.PodRef{Name: "p", Namespace: "ns", UID: "u", Node: "n"},
		Container:        "app",
		ChannelBuffer:    32,
		StalenessTimeout: 10 * time.Second,
	}
	a, err := New(cfg, pub, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func TestNew_RejectsEmptyStdoutPath(t *testing.T) {
	cfg := Config{StderrPath: "/x", Container: "c"}
	_, err := New(cfg, newStubPublisher(), nil)
	if err == nil {
		t.Fatal("expected error for empty stdout path")
	}
}

func TestNew_RejectsEmptyStderrPath(t *testing.T) {
	cfg := Config{StdoutPath: "/x", Container: "c"}
	_, err := New(cfg, newStubPublisher(), nil)
	if err == nil {
		t.Fatal("expected error for empty stderr path")
	}
}

func TestNew_RejectsIdenticalPaths(t *testing.T) {
	cfg := Config{StdoutPath: "/x", StderrPath: "/x", Container: "c"}
	_, err := New(cfg, newStubPublisher(), nil)
	if err == nil {
		t.Fatal("expected error for identical paths")
	}
}

func TestNew_RejectsEmptyContainer(t *testing.T) {
	cfg := Config{StdoutPath: "/a", StderrPath: "/b"}
	_, err := New(cfg, newStubPublisher(), nil)
	if err == nil {
		t.Fatal("expected error for empty container")
	}
}

func TestNew_RejectsNonPositiveChannelBuffer(t *testing.T) {
	cfg := Config{StdoutPath: "/a", StderrPath: "/b", Container: "c", ChannelBuffer: -1}
	_, err := New(cfg, newStubPublisher(), nil)
	if err == nil {
		t.Fatal("expected error for negative channel buffer")
	}
}

func TestNew_RejectsTinyMaxLineBytes(t *testing.T) {
	cfg := Config{StdoutPath: "/a", StderrPath: "/b", Container: "c", MaxLineBytesOverride: 100}
	_, err := New(cfg, newStubPublisher(), nil)
	if err == nil {
		t.Fatal("expected error for tiny max line bytes")
	}
}

func TestNew_RejectsNilPublisher(t *testing.T) {
	cfg := Config{StdoutPath: "/a", StderrPath: "/b", Container: "c"}
	_, err := New(cfg, nil, nil)
	if err == nil {
		t.Fatal("expected error for nil publisher")
	}
}

// pipeTailFn returns a stdout/stderr-tail closure backed by an
// os.Pipe; the test writes lines into the writer end and the adapter's
// consume goroutine drains them as if they had come from a real log
// file. Mirrors the test substrate used in tail_test.go but at the
// adapter scope so we exercise the full Translate-and-publish path.
//
// The closure spawns a context-watcher goroutine that closes the
// pipe's read end on ctx.Done(); without it, the blocking syscall
// inside bufio.Reader.ReadSlice would not honour ctx cancellation and
// the test would deadlock on Adapter.Run shutdown.
func pipeTailFn(t *testing.T, a *Adapter, stream string) (*os.File, func(ctx context.Context, sink chan<- LineRecord) error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	t.Cleanup(func() { _ = w.Close() })
	off := &atomic.Int64{}
	rb := a.recBuilder()
	fn := func(ctx context.Context, sink chan<- LineRecord) error {
		closeDone := make(chan struct{})
		go func() {
			defer close(closeDone)
			<-ctx.Done()
			_ = r.Close()
		}()
		err := runReaderTail(ctx, r, stream, sink, a.shed, off, a.nowFn, rb, a.log)
		<-closeDone
		if err != nil {
			a.recordReaderErr()
		}
		return err
	}
	return w, fn
}

func TestRun_PublishesLinesToRawAppLogSubject(t *testing.T) {
	pub := newStubPublisher()
	a := newTestAdapter(t, pub)

	wOut, stdoutFn := pipeTailFn(t, a, "stdout")
	wErr, stderrFn := pipeTailFn(t, a, "stderr")
	a.stdoutTailFn = stdoutFn
	a.stderrTailFn = stderrFn

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- a.Run(ctx) }()

	if _, err := wOut.Write([]byte("hello stdout\n")); err != nil {
		t.Fatalf("write stdout: %v", err)
	}
	if _, err := wErr.Write([]byte("hello stderr\n")); err != nil {
		t.Fatalf("write stderr: %v", err)
	}

	// Wait for both publishes to land.
	deadline := time.After(5 * time.Second)
	for pub.successes() < 2 {
		select {
		case <-deadline:
			cancel()
			<-runDone
			t.Fatalf("publishes: got %d want >= 2", pub.successes())
		case <-time.After(20 * time.Millisecond):
		}
	}

	// Verify subject pinning.
	for _, subj := range pub.subjects {
		if subj != subjects.RawAppLog {
			t.Errorf("publish subject: got %q want %q", subj, subjects.RawAppLog)
		}
	}

	cancel()
	<-runDone
}

func TestRun_ContextCancelExitsCleanly(t *testing.T) {
	pub := newStubPublisher()
	a := newTestAdapter(t, pub)
	_, stdoutFn := pipeTailFn(t, a, "stdout")
	_, stderrFn := pipeTailFn(t, a, "stderr")
	a.stdoutTailFn = stdoutFn
	a.stderrTailFn = stderrFn

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- a.Run(ctx) }()
	cancel()

	select {
	case err := <-runDone:
		if err != nil {
			t.Errorf("expected nil on cancel, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return on cancel")
	}
}

func TestRun_DropsTranslateError_NoCrash(t *testing.T) {
	pub := newStubPublisher()
	a := newTestAdapter(t, pub)

	// Build a tail closure that emits a malformed LineRecord (zero
	// timestamp) followed by a well-formed one.
	a.stdoutTailFn = func(ctx context.Context, sink chan<- LineRecord) error {
		bad := LineRecord{
			Line:      []byte("bad"),
			Stream:    "stdout",
			Timestamp: time.Time{}, // zero -> ErrInvalidTimestamp
			Pod:       a.cfg.Pod,
			Container: a.cfg.Container,
			Offset:    1,
		}
		good := LineRecord{
			Line:      []byte("good"),
			Stream:    "stdout",
			Timestamp: time.Now(),
			Pod:       a.cfg.Pod,
			Container: a.cfg.Container,
			Offset:    2,
		}
		select {
		case sink <- bad:
		case <-ctx.Done():
			return nil
		}
		select {
		case sink <- good:
		case <-ctx.Done():
			return nil
		}
		<-ctx.Done()
		return nil
	}
	a.stderrTailFn = func(ctx context.Context, sink chan<- LineRecord) error {
		<-ctx.Done()
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- a.Run(ctx) }()

	// Wait for the good line to publish.
	deadline := time.After(2 * time.Second)
	for pub.successes() < 1 {
		select {
		case <-deadline:
			cancel()
			<-runDone
			t.Fatalf("good publish never happened (translate_errors=%d)", a.TranslateErrors())
		case <-time.After(20 * time.Millisecond):
		}
	}

	if a.TranslateErrors() < 1 {
		t.Errorf("translate_errors: got %d want >= 1", a.TranslateErrors())
	}
	cancel()
	<-runDone
}

func TestRun_TerminalPublishErrorIsDropped(t *testing.T) {
	pub := newStubPublisher()
	pub.setFailAlways(nats.ErrMaxPayload)
	a := newTestAdapter(t, pub)

	w, stdoutFn := pipeTailFn(t, a, "stdout")
	a.stdoutTailFn = stdoutFn
	a.stderrTailFn = func(ctx context.Context, sink chan<- LineRecord) error {
		<-ctx.Done()
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- a.Run(ctx) }()

	if _, err := w.Write([]byte("oversize-emulated\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	deadline := time.After(3 * time.Second)
	for a.PublishDrops() < 1 {
		select {
		case <-deadline:
			cancel()
			<-runDone
			t.Fatalf("publish_drops never incremented")
		case <-time.After(20 * time.Millisecond):
		}
	}

	cancel()
	<-runDone
}

func TestRun_StalenessWatchdog_QuietButHealthy_DoesNotFlipUnhealthy(t *testing.T) {
	pub := newStubPublisher()
	cfg := Config{
		StdoutPath:       "/x",
		StderrPath:       "/y",
		Pod:              schema.PodRef{Name: "p", Namespace: "ns", UID: "u"},
		Container:        "app",
		ChannelBuffer:    8,
		StalenessTimeout: 50 * time.Millisecond, // tight for test speed
	}
	a, err := New(cfg, pub, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Simulate a successful past event but no reader error -- the
	// watchdog must NOT flip unhealthy on staleness alone.
	past := time.Now().Add(-10 * time.Second)
	a.lastEventTime.Store(&past)
	// readerErrAt remains nil (zero pointer).

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wdDone := make(chan struct{})
	go func() {
		defer close(wdDone)
		a.runStalenessWatchdog(ctx)
	}()

	// Health begins at zero-value (false, nil). Mark healthy first so
	// we can verify the watchdog does not unmark it.
	a.health.MarkHealthy()
	time.Sleep(200 * time.Millisecond) // > 4 watchdog ticks

	healthy, _ := a.health.Status()
	if !healthy {
		t.Errorf("watchdog falsely flipped unhealthy on quiet-but-healthy stream")
	}
	cancel()
	<-wdDone
}

func TestRun_StalenessWatchdog_StaleAndReaderError_FlipsUnhealthy(t *testing.T) {
	pub := newStubPublisher()
	cfg := Config{
		StdoutPath:    "/x",
		StderrPath:    "/y",
		Pod:           schema.PodRef{Name: "p", Namespace: "ns", UID: "u"},
		Container:     "app",
		ChannelBuffer: 8,
		// Above the watchdog period's 100ms floor so the ticker fires
		// inside the test deadline AND the readerErrAt set at t=0 is
		// still inside the StalenessTimeout window when the first
		// tick reads it.
		StalenessTimeout: 400 * time.Millisecond,
	}
	a, err := New(cfg, pub, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	past := time.Now().Add(-10 * time.Second)
	a.lastEventTime.Store(&past)
	now := time.Now()
	a.readerErrAt.Store(&now)

	a.health.MarkHealthy()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wdDone := make(chan struct{})
	go func() {
		defer close(wdDone)
		a.runStalenessWatchdog(ctx)
	}()

	// Wait up to 2s for the watchdog to flip the source unhealthy.
	deadline := time.After(2 * time.Second)
	for {
		healthy, _ := a.health.Status()
		if !healthy {
			break
		}
		select {
		case <-deadline:
			cancel()
			<-wdDone
			t.Fatal("watchdog did not flip unhealthy under stale + reader-error")
		case <-time.After(20 * time.Millisecond):
		}
	}

	cancel()
	<-wdDone
}

func TestRun_TopLevelPanic_MarksUnhealthy_DoesNotPropagate(t *testing.T) {
	pub := newStubPublisher()
	a := newTestAdapter(t, pub)
	a.stdoutTailFn = func(ctx context.Context, sink chan<- LineRecord) error {
		panic("synthetic")
	}
	a.stderrTailFn = func(ctx context.Context, sink chan<- LineRecord) error {
		<-ctx.Done()
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- a.Run(ctx) }()

	select {
	case err := <-runDone:
		if err != nil {
			t.Errorf("Run propagated panic instead of recovering: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after panic")
	}
	healthy, herr := a.health.Status()
	if healthy {
		t.Errorf("expected unhealthy after panic")
	}
	if herr == nil {
		t.Errorf("expected non-nil panic error in health, got nil")
	}
}

// TestRun_HealthFlipsOnAllScannerFailure asserts that when both tail
// goroutines return errors, Adapter.Run wraps the error, surfaces it
// to the errgroup, and Health() reports unhealthy with that error.
// Mirrors the Story 1.7 P29 / Story 1.8 P27 health-on-scanner-failure
// guarantees the Acceptance Auditor flagged as missing.
func TestRun_HealthFlipsOnAllScannerFailure(t *testing.T) {
	pub := newStubPublisher()
	a := newTestAdapter(t, pub)

	scannerErr := errors.New("synthetic scanner failure")
	a.stdoutTailFn = func(ctx context.Context, sink chan<- LineRecord) error {
		a.recordReaderErr()
		return scannerErr
	}
	a.stderrTailFn = func(ctx context.Context, sink chan<- LineRecord) error {
		a.recordReaderErr()
		return scannerErr
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- a.Run(ctx) }()

	select {
	case err := <-runDone:
		if err == nil {
			t.Fatalf("Run returned nil; expected wrapped scanner error")
		}
		if !errors.Is(err, scannerErr) {
			t.Errorf("Run err = %v; want chain containing %v", err, scannerErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of scanner failure")
	}

	healthy, herr := a.health.Status()
	if healthy {
		t.Errorf("expected unhealthy after scanner failure")
	}
	if herr == nil {
		t.Errorf("expected non-nil health error after scanner failure")
	}
}

// TestRun_HealthRestoresOnReconnect drives the adapter through an
// initial scanner-error window (health unhealthy due to the
// readerErrAt stamp + zero published events) and then a successful
// publish path which must flip health back to healthy. Mirrors the
// Story 1.8 reconnect-and-resume coverage that the Acceptance Auditor
// listed as required.
func TestRun_HealthRestoresOnReconnect(t *testing.T) {
	pub := newStubPublisher()
	a := newTestAdapter(t, pub)

	// First start: stamp an early reader error then send a line. The
	// successful publish that follows should flip health back to
	// healthy.
	a.recordReaderErr()
	healthy, _ := a.health.Status()
	if healthy {
		t.Fatal("expected initial unhealthy state from recordReaderErr precondition")
	}

	wOut, stdoutFn := pipeTailFn(t, a, "stdout")
	a.stdoutTailFn = stdoutFn
	a.stderrTailFn = func(ctx context.Context, sink chan<- LineRecord) error {
		<-ctx.Done()
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- a.Run(ctx) }()

	if _, err := wOut.Write([]byte("recovery line\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	deadline := time.After(3 * time.Second)
	for {
		h, _ := a.health.Status()
		if h && pub.successes() > 0 {
			break
		}
		select {
		case <-deadline:
			cancel()
			<-runDone
			t.Fatalf("health did not restore after successful publish (healthy=%v, successes=%d)", h, pub.successes())
		case <-time.After(20 * time.Millisecond):
		}
	}
	cancel()
	<-runDone
}

func TestRun_BackpressureShedding_SignalsViaCounter(t *testing.T) {
	// Smallest channel + a publisher that is artificially slow forces
	// the shed-state high-water trigger to fire and the LinesShed
	// counter to increment.
	pub := &slowPublisher{delay: 100 * time.Millisecond}
	cfg := Config{
		StdoutPath:    "/x",
		StderrPath:    "/y",
		Pod:           schema.PodRef{Name: "p", Namespace: "ns", UID: "u"},
		Container:     "app",
		ChannelBuffer: 4,
	}
	a, err := New(cfg, pub, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	w, stdoutFn := pipeTailFn(t, a, "stdout")
	a.stdoutTailFn = stdoutFn
	a.stderrTailFn = func(ctx context.Context, sink chan<- LineRecord) error {
		<-ctx.Done()
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- a.Run(ctx) }()

	// Pump a burst.
	go func() {
		for i := 0; i < 1024; i++ {
			_, _ = w.Write([]byte("line\n"))
		}
		_ = w.Close()
	}()

	deadline := time.After(3 * time.Second)
	for a.LinesShed() == 0 {
		select {
		case <-deadline:
			cancel()
			<-runDone
			t.Fatalf("LinesShed: got 0 want > 0")
		case <-time.After(20 * time.Millisecond):
		}
	}
	cancel()
	<-runDone
}

// slowPublisher is a publisher that sleeps for delay before returning
// success on every PublishJS. Used to force back-pressure.
type slowPublisher struct {
	delay time.Duration
	calls atomic.Int64
}

func (s *slowPublisher) PublishJS(ctx context.Context, subject string, data any, opts ...natsjs.PublishOpt) (*natsjs.PubAck, error) {
	s.calls.Add(1)
	select {
	case <-time.After(s.delay):
		return &natsjs.PubAck{Stream: "EVENTS_RAW"}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestEventsTotal_ZeroOnConstruct(t *testing.T) {
	a := newTestAdapter(t, newStubPublisher())
	if got := a.EventsTotal(); got != 0 {
		t.Errorf("EventsTotal on fresh Adapter: got %d, want 0", got)
	}
	if got := a.DroppedEvents(); got != 0 {
		t.Errorf("DroppedEvents on fresh Adapter: got %d, want 0", got)
	}
}

func TestEventsTotal_ReflectsIncrement(t *testing.T) {
	a := newTestAdapter(t, newStubPublisher())
	a.eventsPublished.Add(7)
	if got := a.EventsTotal(); got != 7 {
		t.Errorf("EventsTotal after Add(7): got %d, want 7", got)
	}
}

func TestIsPermanentPublishError_RecognisesTypedErrors(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"transient", errors.New("transient"), false},
		{"max payload", nats.ErrMaxPayload, true},
		{"no responders", nats.ErrNoResponders, true},
		{"stream not found", natsjs.ErrStreamNotFound, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isPermanentPublishError(tc.err)
			if got != tc.want {
				t.Errorf("got %v want %v for %v", got, tc.want, tc.err)
			}
		})
	}
}
