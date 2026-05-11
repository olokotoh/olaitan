package applog

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nxadm/tail"
)

// scannerBufferLimit is the bufio.Scanner buffer cap used by the
// reader-based line iterator. 1 MiB is generous for application logs;
// lines longer than this trip the long-line policy which emits the
// 1 MiB-truncated prefix with a "truncated:true" tag and resumes after
// the next newline. Note: this 1 MiB cap is the per-scanner buffer
// limit, distinct from the per-event MaxLineBytes (64 KiB) cap that
// Translate applies to the published Raw payload.
const scannerBufferLimit = 1 * 1024 * 1024

// shedHighWaterRatio is the channel-fill threshold above which the
// tailer enters shed-mode. 75 percent (channel.Len > capacity*3/4) is
// the entry condition. Recovery happens at 25 percent (channel.Len <
// capacity/4).
const (
	shedHighWaterRatio = 4 // entry: len*4 > cap*3 (i.e. len > cap*3/4)
	shedLowWaterRatio  = 4 // exit: len*4 < cap (i.e. len < cap/4)
)

// shedState is the back-pressure shedding state machine for one
// LineRecord channel. The tailer goroutines consult it on every send;
// once the channel is full enough to justify shedding (high-water
// triggered), subsequent sends use a non-blocking select with a default
// case that drops the line and increments LinesShed. The shed flag
// flips back off when the channel drains below the low-water mark.
//
// Concurrency: a single shedState is shared across both tail
// goroutines (stdout, stderr) because shed-mode is a property of the
// shared sink channel, not the per-stream reader. Both goroutines may
// race on `shedding.Load`/`Store` and on the `len(sink)` peek; the
// flip is best-effort and may oscillate briefly under contention. The
// `dropped` counter is atomic and aggregates across both streams.
type shedState struct {
	shedding atomic.Bool
	dropped  atomic.Int64
	cap      int

	// stallTimeout, when > 0, enables the stall-time gate: when the
	// non-shedding send path observes the channel-fill ratio AT OR ABOVE
	// the high-water mark for longer than stallTimeout since the last
	// successful send, the tracker flips into shed-mode independent of
	// the strict-greater-than channel-fill condition. Zero disables the
	// gate (channel-fill is the only trigger).
	stallTimeout time.Duration

	// lastSendAt is the wall-clock time of the most recent successful
	// send. The stall-time gate compares against this. Stored as a
	// monotonic-preserving *time.Time so a forward NTP step does not
	// trip a spurious flip.
	lastSendAt atomic.Pointer[time.Time]

	// log surfaces WARN messages on shed-mode entry and exit (Task 4.3
	// of Story 1.9). nil is treated as slog.Default by the call sites
	// so a zero-value shedState in tests does not panic.
	log *slog.Logger

	// nowFn is a test seam for the stall-time gate.
	nowFn func() time.Time
}

// newShedState returns a fresh shed-state tracker for a channel of
// the given capacity. Panics on cap < 1: a zero-cap channel is an
// always-shedding configuration and a negative cap is a producer bug.
func newShedState(channelCap int) *shedState {
	if channelCap < 1 {
		panic(fmt.Sprintf("applog: newShedState: capacity must be >= 1 (got %d)", channelCap))
	}
	return &shedState{cap: channelCap, nowFn: time.Now}
}

// withLogger installs the logger used for shed-mode entry/exit WARN
// emission. Returns s for fluent setup.
func (s *shedState) withLogger(log *slog.Logger) *shedState {
	s.log = log
	return s
}

// withStallTimeout installs the stall-time gate threshold. Zero disables
// the gate (channel-fill is the only trigger). Returns s for fluent
// setup.
func (s *shedState) withStallTimeout(d time.Duration) *shedState {
	s.stallTimeout = d
	return s
}

// LinesShed returns the cumulative count of LineRecords dropped due
// to back-pressure shedding. Exposed for adapter tests and Story 1.12
// Prometheus binding.
func (s *shedState) LinesShed() int64 { return s.dropped.Load() }

// Shedding returns true when the back-pressure tracker is currently in
// shed-mode. Exposed for tests; production code reads this implicitly
// via the send path.
func (s *shedState) Shedding() bool { return s.shedding.Load() }

// send attempts to push rec onto sink. The control flow:
//
//   - If currently in shed-mode: non-blocking send. On default-case
//     drop, increment dropped counter and check the low-water mark to
//     flip shedding off; otherwise stay in shed-mode.
//   - If not in shed-mode: blocking send. Before each send, peek the
//     channel-length-vs-capacity ratio; if at or above the high-water
//     mark, flip into shed-mode and convert this send to non-blocking
//     so the line that triggered the threshold is itself dropped (the
//     consumer is already drowning).
//
// Returns ctx.Err() when ctx is cancelled mid-send. Returns nil on a
// successful send, a successful drop, or a successful state-transition
// drop. The caller does not distinguish these because shed-mode
// behaviour is deliberately quiet at the per-line level (the WARN log
// is emitted on shed-mode entry/exit, not on every dropped line).
func (s *shedState) send(ctx context.Context, sink chan<- LineRecord, rec LineRecord) error {
	if s.shedding.Load() {
		select {
		case sink <- rec:
			s.recordSendTime()
			// Drained below the low-water mark: clear shed-mode.
			if len(sink)*shedLowWaterRatio < s.cap {
				if s.shedding.CompareAndSwap(true, false) {
					s.logShedExit("channel drained below low-water mark")
				}
			}
			return nil
		case <-ctx.Done():
			return ctx.Err()
		default:
			s.dropped.Add(1)
			return nil
		}
	}

	// Non-shedding fast path. Check whether the channel is approaching
	// full and flip into shed-mode if so. The high-water condition is
	// `len*4 > cap*3` -- i.e. len > cap * 3/4. Entering shed-mode here
	// also drops the current rec (the consumer is already drowning).
	if len(sink)*shedHighWaterRatio > s.cap*3 {
		if s.shedding.CompareAndSwap(false, true) {
			s.logShedEntry("channel-fill above high-water mark", len(sink))
		}
		s.dropped.Add(1)
		return nil
	}

	// Stall-time gate: when the channel is AT-OR-ABOVE the high-water
	// mark and the last successful send is older than stallTimeout, the
	// consumer is moving but at a rate that does not drain the buffer.
	// Flip into shed-mode preemptively. The strict >-greater channel-
	// fill check above will not fire in this case (the buffer is not
	// quite over the threshold) so without this gate a slow-but-not-
	// stopped consumer would leave the tailer blocked at full capacity
	// for arbitrary periods.
	if s.stallTimeout > 0 && len(sink)*shedHighWaterRatio >= s.cap*3 {
		if lastPtr := s.lastSendAt.Load(); lastPtr != nil {
			if s.nowFn != nil && s.nowFn().Sub(*lastPtr) > s.stallTimeout {
				if s.shedding.CompareAndSwap(false, true) {
					s.logShedEntry("stall-time gate fired", len(sink))
				}
				s.dropped.Add(1)
				return nil
			}
		}
	}

	select {
	case sink <- rec:
		s.recordSendTime()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// recordSendTime stamps lastSendAt for the stall-time gate. Captures
// the time on the goroutine that did the send so a forward NTP step
// does not poison the staleness math.
func (s *shedState) recordSendTime() {
	if s.nowFn == nil {
		return
	}
	t := s.nowFn()
	s.lastSendAt.Store(&t)
}

// logShedEntry / logShedExit emit a WARN log at the shed-mode
// transition boundaries. Per Task 4.3 of Story 1.9 the WARN log is the
// operator-visible signal that the line tailer is dropping events; the
// dropped counter is reported at exit so operators can quantify the
// stall.
func (s *shedState) logShedEntry(reason string, chanLen int) {
	if s.log == nil {
		return
	}
	s.log.Warn("applog: tail entered shed mode",
		"reason", reason,
		"channel_len", chanLen,
		"channel_cap", s.cap,
		"dropped_before", s.dropped.Load())
}

func (s *shedState) logShedExit(reason string) {
	if s.log == nil {
		return
	}
	s.log.Warn("applog: tail exited shed mode",
		"reason", reason,
		"dropped_total", s.dropped.Load())
}

// runReaderTail drains lines from r using a bufio.Scanner with the
// long-line policy and emits LineRecords onto sink with back-pressure
// shedding via shed.
//
// Long-line policy: lines up to scannerBufferLimit (1 MiB) are scanned
// as a single token. When bufio.ErrTooLong is reported, the loop
// switches to a manual byte-by-byte read that emits at the 1 MiB
// boundary with the truncated suffix dropped and a "truncated:true"
// tag added downstream by Translate, then resumes reading from the
// next newline. This avoids the silent-drop-on-overlong-line failure
// mode bufio.Scanner defaults to.
//
// On ctx cancellation, runReaderTail returns nil immediately without
// flushing any in-flight partial bytes; the next-line read is
// abandoned. Any unterminated final line buffered inside
// readLineWithLongLinePolicy is dropped at shutdown. Callers must not
// rely on a partial-line flush. On unrecoverable read error other
// than io.EOF, runReaderTail
// logs and returns the wrapped error so the parent goroutine can
// decide whether to fail the adapter or restart this stream.
//
// offsetSeq is the per-stream monotonic offset counter; runReaderTail
// increments it once per LineRecord produced. Pass a fresh
// atomic.Int64 per stream so the stdout and stderr streams have
// independent counters.
//
// recBuilder is a closure that wraps the line bytes into a LineRecord
// (capturing PodRef, Container, Labels, and the timestamp source). The
// adapter constructs the closure once and reuses it for the lifetime
// of the stream.
//
// runReaderTail does NOT close sink on exit -- the adapter owns the
// channel's lifecycle.
func runReaderTail(
	ctx context.Context,
	r io.Reader,
	stream string,
	sink chan<- LineRecord,
	shed *shedState,
	offsetSeq *atomic.Int64,
	now func() time.Time,
	recBuilder func(stream string, line []byte, ts time.Time, offset int64) LineRecord,
	log *slog.Logger,
) error {
	br := bufio.NewReaderSize(r, scannerBufferLimit)
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		line, err := readLineWithLongLinePolicy(br, scannerBufferLimit)
		// Emit when we either have line bytes (including a legitimate
		// empty line, which arrives as a non-nil zero-length slice from
		// readLineWithLongLinePolicy) or the read completed cleanly with
		// a non-nil slice. The explicit line != nil guard skips the
		// pathological (nil, nil) case where a misbehaving reader signals
		// no progress and no error; without this guard the loop would
		// emit a phantom LineRecord and bump the offset counter.
		if line != nil && (len(line) > 0 || err == nil) {
			ts := now()
			off := offsetSeq.Add(1)
			rec := recBuilder(stream, line, ts, off)
			if serr := shed.send(ctx, sink, rec); serr != nil {
				return nil
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				// EOF: clean writer-closed condition. Returning nil
				// lets the adapter decide whether to restart (the
				// errgroup unwinds the parent context if every reader
				// returns).
				return nil
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil
			}
			// During shutdown the underlying pipe / file descriptor may
			// have been closed mid-read; surface as graceful nil rather
			// than a wrapped error so the errgroup unwinds cleanly.
			if ctx.Err() != nil && (errors.Is(err, os.ErrClosed) || errors.Is(err, io.ErrClosedPipe)) {
				return nil
			}
			log.Warn("applog: reader error", "stream", stream, "err", err)
			return fmt.Errorf("applog: reader (%s): %w", stream, err)
		}
	}
}

// readLineWithLongLinePolicy reads up to maxLine bytes from br,
// stopping at the first newline. Returns the line bytes (without the
// trailing newline) plus any read error. The line slice is freshly
// allocated; it does not alias br's internal buffer.
//
// If the line is longer than maxLine, the first maxLine bytes are
// returned and the remainder up to the next newline is silently
// discarded.
//
// maxLine here is scannerBufferLimit (1 MiB). Translate then applies a
// second, per-record cap from Config.MaxLineBytesOverride which
// Config.Validate bounds at MaxLineBytesAbsoluteCap (192 KiB). Because
// the translate-side cap is always strictly less than scannerBufferLimit,
// any reader-side truncation here would already have been preempted by
// the translate-side truncation, which is what sets the truncated:true
// tag. No separate reader-truncated flag is needed.
//
// Returns (nil, io.EOF) when the underlying reader is fully drained
// with no trailing partial line. Returns (partial, nil) when br
// returns a partial line followed by EOF on the next read; the caller
// then loops once more to receive the EOF.
func readLineWithLongLinePolicy(br *bufio.Reader, maxLine int) ([]byte, error) {
	out := make([]byte, 0, 256)
	for {
		chunk, err := br.ReadSlice('\n')
		if len(chunk) > 0 {
			// Strip trailing \n and \r\n.
			n := len(chunk)
			if chunk[n-1] == '\n' {
				n--
				if n > 0 && chunk[n-1] == '\r' {
					n--
				}
				if len(out) == 0 {
					return append([]byte(nil), chunk[:n]...), nil
				}
				out = append(out, chunk[:n]...)
				if len(out) > maxLine {
					out = out[:maxLine]
				}
				return out, nil
			}
			// No newline yet: chunk is a buffer-full prefix of a
			// long line. Append, then loop. If we are already at
			// maxLine, switch to discard mode for the remainder of
			// this line.
			out = append(out, chunk...)
			if len(out) > maxLine {
				out = out[:maxLine]
			}
		}
		if err == nil {
			// ReadSlice returned a buffer-full but no error: keep
			// looping to consume the rest of this long line. If we
			// are at maxLine, switch to discard mode.
			if len(out) >= maxLine {
				if derr := discardToNewline(br); derr != nil {
					if errors.Is(derr, io.EOF) && len(out) > 0 {
						return out, nil
					}
					return out, derr
				}
				return out, nil
			}
			continue
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			// buffer full but ReadSlice returned err == ErrBufferFull
			// rather than nil. Same disposition as above.
			if len(out) >= maxLine {
				if derr := discardToNewline(br); derr != nil {
					if errors.Is(derr, io.EOF) && len(out) > 0 {
						return out, nil
					}
					return out, derr
				}
				return out, nil
			}
			continue
		}
		// EOF or other error: surface, returning any in-flight bytes.
		if len(out) > 0 {
			return out, err
		}
		return nil, err
	}
}

// discardToNewline reads from br until the next '\n' or until io.EOF.
// Used by readLineWithLongLinePolicy when a line exceeds the maxLine
// cap and the suffix must be dropped before resuming on the next line.
func discardToNewline(br *bufio.Reader) error {
	for {
		_, err := br.ReadSlice('\n')
		if err == nil {
			return nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return err
	}
}

// runFileTail tails the file at path using nxadm/tail (rotation-aware,
// inotify-driven on Linux, polling fallback elsewhere) and emits
// LineRecords onto sink with back-pressure shedding via shed.
//
// Configuration: ReOpen=true (handle move-and-recreate rotation),
// MustExist=false (sidecar may start before the application has
// written its first line; nxadm/tail polls for the file to appear),
// Follow=true (long-running tail), Poll=false (use inotify on Linux).
// MaxLineSize is 0 (unlimited at the nxadm/tail layer; Translate caps
// at MaxLineBytes downstream).
//
// On ctx cancellation, runFileTail calls Stop on the underlying
// tail.Tail and returns. On unrecoverable error from nxadm/tail
// (rare; most rotation/errno cases are absorbed internally), the
// wrapped error is returned so the adapter's errgroup unwinds.
func runFileTail(
	ctx context.Context,
	path string,
	stream string,
	sink chan<- LineRecord,
	shed *shedState,
	offsetSeq *atomic.Int64,
	now func() time.Time,
	recBuilder func(stream string, line []byte, ts time.Time, offset int64) LineRecord,
	log *slog.Logger,
	recordReaderErr func(),
) error {
	cfg := tail.Config{
		ReOpen:    true,
		MustExist: false,
		Follow:    true,
		Poll:      false,
		Logger:    tail.DiscardingLogger,
	}
	t, err := tail.TailFile(path, cfg)
	if err != nil {
		return fmt.Errorf("applog: tail-file %q: %w", path, err)
	}

	// Stop the tailer once. The async stop goroutine fires on
	// ctx.Done; the function-exit defer fires unconditionally so a
	// fast-exit (ctx already cancelled at entry, error mid-loop, etc.)
	// does not leak the underlying file descriptor / inotify watcher.
	// sync.Once guards against the double-Stop race.
	var stopOnce sync.Once
	stopTail := func() {
		stopOnce.Do(func() {
			if serr := t.Stop(); serr != nil {
				log.Warn("applog: tail-file stop", "path", path, "err", serr)
			}
		})
	}
	stopDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			stopTail()
		case <-stopDone:
		}
	}()
	defer close(stopDone)
	defer stopTail()

	for {
		select {
		case <-ctx.Done():
			return nil
		case line, ok := <-t.Lines:
			if !ok {
				return nil
			}
			if line.Err != nil {
				// Stamp readerErrAt so the staleness watchdog can
				// combine a recent reader-side error with the
				// staleness window when deciding to flip unhealthy.
				// Without this stamp, per-line errors are invisible
				// to the watchdog (the function-return-only stamp on
				// defaultFileTail never fires while t.Lines is still
				// open) and a stream-broken-but-channel-still-open
				// scenario would never flip the source unhealthy.
				if recordReaderErr != nil {
					recordReaderErr()
				}
				log.Warn("applog: tail-file line error", "path", path, "err", line.Err)
				continue
			}
			ts := now()
			off := offsetSeq.Add(1)
			// nxadm/tail strips the trailing newline; pass the bytes
			// to the recBuilder which forwards through Translate's
			// MaxLineBytes cap.
			rec := recBuilder(stream, []byte(line.Text), ts, off)
			if serr := shed.send(ctx, sink, rec); serr != nil {
				return nil
			}
		}
	}
}
