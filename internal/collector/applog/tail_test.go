package applog

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/schema"
)

// silentLogger discards log output for tests so the -v output is
// readable.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testRecBuilder returns a recBuilder closure that produces a
// LineRecord with a fixed PodRef and Container; tests vary only the
// stream, line, timestamp, and offset.
func testRecBuilder() func(stream string, line []byte, ts time.Time, offset int64) LineRecord {
	pod := schema.PodRef{Name: "test-pod", Namespace: "default", UID: "uid-1", Node: "node-1"}
	return func(stream string, line []byte, ts time.Time, offset int64) LineRecord {
		return LineRecord{
			Line:      append([]byte(nil), line...),
			Stream:    stream,
			Timestamp: ts,
			Pod:       pod,
			Container: "test-app",
			Offset:    offset,
		}
	}
}

// drainCh collects up to want LineRecords from sink within timeout.
// Returns whatever it received (may be fewer than want on timeout).
func drainCh(sink <-chan LineRecord, want int, timeout time.Duration) []LineRecord {
	out := make([]LineRecord, 0, want)
	deadline := time.After(timeout)
	for len(out) < want {
		select {
		case rec := <-sink:
			out = append(out, rec)
		case <-deadline:
			return out
		}
	}
	return out
}

func TestTail_LFLineEnding(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	sink := make(chan LineRecord, 16)
	shed := newShedState(16)
	off := &atomic.Int64{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- runReaderTail(ctx, r, "stdout", sink, shed, off, time.Now, testRecBuilder(), silentLogger())
	}()

	if _, err := w.Write([]byte("line one\nline two\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = w.Close()

	got := drainCh(sink, 2, 2*time.Second)
	if len(got) != 2 {
		t.Fatalf("got %d lines want 2", len(got))
	}
	if string(got[0].Line) != "line one" {
		t.Errorf("line[0]: got %q", got[0].Line)
	}
	if string(got[1].Line) != "line two" {
		t.Errorf("line[1]: got %q", got[1].Line)
	}
	if got[0].Offset == got[1].Offset {
		t.Errorf("offsets must differ: both=%d", got[0].Offset)
	}

	cancel()
	<-done
}

func TestTail_CRLFLineEnding(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	sink := make(chan LineRecord, 8)
	shed := newShedState(8)
	off := &atomic.Int64{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- runReaderTail(ctx, r, "stdout", sink, shed, off, time.Now, testRecBuilder(), silentLogger())
	}()

	if _, err := w.Write([]byte("windows-line\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = w.Close()

	got := drainCh(sink, 1, 2*time.Second)
	if len(got) != 1 {
		t.Fatalf("got %d lines want 1", len(got))
	}
	if string(got[0].Line) != "windows-line" {
		t.Errorf("line stripping CR: got %q want %q", got[0].Line, "windows-line")
	}

	cancel()
	<-done
}

func TestTail_NoTrailingNewline_EmittedOnReaderClose(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	sink := make(chan LineRecord, 8)
	shed := newShedState(8)
	off := &atomic.Int64{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- runReaderTail(ctx, r, "stdout", sink, shed, off, time.Now, testRecBuilder(), silentLogger())
	}()

	if _, err := w.Write([]byte("partial-no-newline")); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Closing the writer flushes EOF; the partial line must surface
	// before runReaderTail returns nil.
	_ = w.Close()

	got := drainCh(sink, 1, 2*time.Second)
	if len(got) != 1 {
		t.Fatalf("got %d records want 1", len(got))
	}
	if string(got[0].Line) != "partial-no-newline" {
		t.Errorf("partial line: got %q", got[0].Line)
	}

	cancel()
	<-done
}

func TestTail_LineLongerThan1MiB_TruncatedAtBoundary(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	sink := make(chan LineRecord, 4)
	shed := newShedState(4)
	off := &atomic.Int64{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- runReaderTail(ctx, r, "stdout", sink, shed, off, time.Now, testRecBuilder(), silentLogger())
	}()

	// Write a line of 1.5 MiB followed by a normal line.
	bigLine := make([]byte, scannerBufferLimit+512*1024)
	for i := range bigLine {
		bigLine[i] = 'x'
	}
	go func() {
		_, _ = w.Write(bigLine)
		_, _ = w.Write([]byte("\nshort line\n"))
		_ = w.Close()
	}()

	got := drainCh(sink, 2, 4*time.Second)
	if len(got) != 2 {
		t.Fatalf("got %d records want 2", len(got))
	}
	if len(got[0].Line) != scannerBufferLimit {
		t.Errorf("first line truncation: got %d want %d", len(got[0].Line), scannerBufferLimit)
	}
	if string(got[1].Line) != "short line" {
		t.Errorf("second line: got %q want %q", got[1].Line, "short line")
	}

	cancel()
	<-done
}

func TestTail_ReaderEOF_ReturnsCleanly(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	sink := make(chan LineRecord, 4)
	shed := newShedState(4)
	off := &atomic.Int64{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- runReaderTail(ctx, r, "stdout", sink, shed, off, time.Now, testRecBuilder(), silentLogger())
	}()

	_ = w.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil on clean EOF, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runReaderTail did not return on EOF")
	}
	cancel()
}

func TestTail_BackpressureSheddingTriggers_AtChannelFull(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	// Tiny channel forces shedding under load.
	sink := make(chan LineRecord, 16)
	shed := newShedState(16)
	off := &atomic.Int64{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- runReaderTail(ctx, r, "stdout", sink, shed, off, time.Now, testRecBuilder(), silentLogger())
	}()

	// Pump 4096 lines without draining the channel (only the first
	// 16 fit in the buffer; the rest must be shed).
	go func() {
		// Build a single buffer of 4096 short lines so write does not
		// block on os.Pipe's internal buffer mid-write. os.Pipe has a
		// ~64 KiB kernel buffer; 4096 short lines easily exceed that,
		// so we write in chunks.
		var batch strings.Builder
		for i := 0; i < 4096; i++ {
			batch.WriteString("line\n")
		}
		_, _ = w.Write([]byte(batch.String()))
		_ = w.Close()
	}()

	// Wait long enough for shed-mode to engage and drops to accumulate.
	deadline := time.After(3 * time.Second)
	for shed.LinesShed() == 0 {
		select {
		case <-deadline:
			t.Fatalf("expected dropped > 0, got 0; chan len=%d", len(sink))
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	cancel()
	<-done

	if shed.LinesShed() == 0 {
		t.Errorf("LinesShed: got 0 want > 0")
	}
	// The bounded channel must NEVER exceed its capacity.
	if len(sink) > 16 {
		t.Errorf("channel overshot capacity: len=%d cap=16", len(sink))
	}
}

func TestTail_BackpressureRecoversAtLowWaterMark(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	sink := make(chan LineRecord, 16)
	shed := newShedState(16)
	off := &atomic.Int64{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- runReaderTail(ctx, r, "stdout", sink, shed, off, time.Now, testRecBuilder(), silentLogger())
	}()

	// Phase 1: fill the channel to trigger shedding.
	var phase1 strings.Builder
	for i := 0; i < 256; i++ {
		phase1.WriteString("p1\n")
	}
	_, _ = w.Write([]byte(phase1.String()))

	// Wait for shed-mode to engage.
	for i := 0; i < 100; i++ {
		if shed.Shedding() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !shed.Shedding() {
		_ = w.Close()
		cancel()
		<-done
		t.Fatalf("shed-mode did not engage")
	}

	// Phase 2: drain the channel below the low-water mark.
	for len(sink) > 0 {
		<-sink
	}

	// Phase 3: write one more line so the next send observes the
	// drained channel and flips shed-mode off.
	if _, err := w.Write([]byte("p3\n")); err != nil {
		t.Fatalf("phase3 write: %v", err)
	}

	// Wait for the shed flag to clear.
	cleared := false
	for i := 0; i < 200; i++ {
		if !shed.Shedding() {
			cleared = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !cleared {
		t.Errorf("shed-mode did not clear after drain")
	}

	_ = w.Close()
	cancel()
	<-done
}

func TestTail_ContextCancelExitsCleanly(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	sink := make(chan LineRecord, 8)
	shed := newShedState(8)
	off := &atomic.Int64{}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- runReaderTail(ctx, r, "stdout", sink, shed, off, time.Now, testRecBuilder(), silentLogger())
	}()

	cancel()
	// Close the writer so the underlying read unblocks; runReaderTail
	// observes either ctx.Err or io.EOF and returns.
	_ = w.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil on cancel, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runReaderTail did not return on cancel")
	}
}

// TestTail_FileTail_ReadsBasicFileLines exercises runFileTail against
// a real file (not os.Pipe) to verify the nxadm/tail bridge wiring.
// File rotation behaviour itself (move-and-recreate, truncate-in-
// place) is the responsibility of nxadm/tail and is covered by the
// upstream library's own test suite; reproducing those tests here is
// scope-creep and the inotify timing under the race detector makes
// the assertion flaky. The adapter's delegate-to-nxadm wiring is what
// this test validates.
func TestTail_FileTail_ReadsBasicFileLines(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/log.txt"
	if err := os.WriteFile(path, []byte("first\nsecond\n"), 0o644); err != nil {
		t.Fatalf("write initial: %v", err)
	}

	sink := make(chan LineRecord, 32)
	shed := newShedState(32)
	off := &atomic.Int64{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = runFileTail(ctx, path, "stdout", sink, shed, off, time.Now, testRecBuilder(), silentLogger())
	}()

	got := drainCh(sink, 2, 5*time.Second)
	if len(got) != 2 {
		cancel()
		wg.Wait()
		t.Fatalf("got %d lines want 2", len(got))
	}
	if string(got[0].Line) != "first" || string(got[1].Line) != "second" {
		cancel()
		wg.Wait()
		t.Fatalf("got lines %q %q", got[0].Line, got[1].Line)
	}

	cancel()
	wg.Wait()
}
