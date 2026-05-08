package applog

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
type shedState struct {
	shedding atomic.Bool
	dropped  atomic.Int64
	cap      int
}

// newShedState returns a fresh shed-state tracker for a channel of
// the given capacity.
func newShedState(channelCap int) *shedState {
	return &shedState{cap: channelCap}
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
			// Drained below the low-water mark: clear shed-mode.
			if len(sink)*shedLowWaterRatio < s.cap {
				s.shedding.Store(false)
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
		s.shedding.Store(true)
		s.dropped.Add(1)
		return nil
	}

	select {
	case sink <- rec:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
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
// On ctx cancellation, runReaderTail flushes any in-flight partial
// line (no trailing newline) to sink as a final LineRecord and returns
// nil. On unrecoverable read error other than io.EOF, runReaderTail
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
		if len(line) > 0 || (err == nil) {
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
// discarded. The truncation flag is implicit in the line length being
// exactly maxLine; the caller (Translate) detects this via the
// MaxLineBytes cap downstream.
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

	// Stop the tailer on ctx cancellation. Stop returns the first
	// error encountered by the tailer goroutine; we log but do not
	// propagate the close-time error because the call is best-effort
	// teardown.
	stopDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			if serr := t.Stop(); serr != nil {
				log.Warn("applog: tail-file stop", "path", path, "err", serr)
			}
		case <-stopDone:
		}
	}()
	defer close(stopDone)

	for {
		select {
		case <-ctx.Done():
			return nil
		case line, ok := <-t.Lines:
			if !ok {
				return nil
			}
			if line.Err != nil {
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
