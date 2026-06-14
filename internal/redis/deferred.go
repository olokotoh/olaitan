package redis

// Story 4.7 deferred-report queue helpers. The deferred queue is a plain Redis
// LIST at the literal key reports:deferred (NOT a Redis Stream: the evidence:
// prefix Streams fence in validateStreamKey would reject it anyway, and a LIST
// is the right primitive for a bounded FIFO work queue). FIFO ordering is RPUSH
// (tail enqueue) + LPOP (head drain), so the OLDEST deferred report drains first
// (mirroring the RPush + LTrim bounded FSM-history precedent in setters.go).
//
// The bytes the helpers move are an opaque JSON envelope owned by the caller
// (internal/report/deferq): this package neither encodes nor decodes it, it only
// provides the typed RPUSH / LRANGE-peek / LPOP-commit / LLEN list operations on
// the one well-known key.

import (
	"context"
	"errors"
	"fmt"

	goredis "github.com/redis/go-redis/v9"
)

// DeferredReportsKey is the literal Redis LIST key the Story 4.7 deferred-report
// queue lives under (AC2). It is a plain LIST, not a key-family-validated key,
// so the helpers below operate on conn() directly rather than through the
// key-family validator the FSM/baseline setters use.
const DeferredReportsKey = "reports:deferred"

// EnqueueDeferredReport RPUSHes envelope onto the tail of reports:deferred
// (FIFO: the oldest item is at the head, drained first). When maxLen > 0 the
// list is bounded: if the RPUSH would exceed maxLen, the OLDEST entries are
// trimmed from the head via LTRIM so the list keeps only the most-recent maxLen
// reports (BI-6 / PO ratification 7: drop-oldest, keeping the freshest forensic
// records). It returns the number of OLDEST entries dropped to honour the cap so
// the caller can count + log them loudly. The RPUSH + LTRIM run in one pipelined
// round-trip (the AppendFSMHistory precedent).
//
// A non-positive maxLen leaves the list unbounded (drops nothing).
func (c *Client) EnqueueDeferredReport(ctx context.Context, envelope []byte, maxLen int64) (dropped int64, err error) {
	rdb := c.conn()
	if rdb == nil {
		return 0, ErrClientClosed
	}
	if len(envelope) == 0 {
		return 0, fmt.Errorf("redis: enqueue-deferred-report: envelope is empty")
	}
	pipe := rdb.TxPipeline()
	pushCmd := pipe.RPush(ctx, DeferredReportsKey, envelope)
	if maxLen > 0 {
		// Keep only the last maxLen entries (the newest), dropping the oldest from
		// the head. LTRIM is idempotent when the list is already within the cap.
		pipe.LTrim(ctx, DeferredReportsKey, -maxLen, -1)
	}
	if _, perr := pipe.Exec(ctx); perr != nil {
		return 0, fmt.Errorf("redis: enqueue-deferred-report: %w", perr)
	}
	if maxLen > 0 {
		// The RPUSH return value is the list length BEFORE the trim; anything over
		// the cap was dropped from the head.
		if over := pushCmd.Val() - maxLen; over > 0 {
			dropped = over
		}
	}
	return dropped, nil
}

// PeekDeferredReport returns the envelope at the HEAD of reports:deferred
// (LRANGE 0 0) WITHOUT removing it, so the drain worker can re-PUT the head and
// only commit the LPOP after a confirmed write (the crash-safe BI-9 discipline:
// a crash after the re-PUT but before the LPOP re-attempts the same
// content-addressed key, which the archive dedups). ok is false (with a nil
// envelope and a nil error) when the list is empty.
func (c *Client) PeekDeferredReport(ctx context.Context) (envelope []byte, ok bool, err error) {
	rdb := c.conn()
	if rdb == nil {
		return nil, false, ErrClientClosed
	}
	vals, lerr := rdb.LRange(ctx, DeferredReportsKey, 0, 0).Result()
	if lerr != nil {
		return nil, false, fmt.Errorf("redis: peek-deferred-report: %w", lerr)
	}
	if len(vals) == 0 {
		return nil, false, nil
	}
	return []byte(vals[0]), true, nil
}

// CommitDeferredReport LPOPs (removes) the HEAD of reports:deferred. The drain
// worker calls it ONLY after a successful (or HEAD-deduped) re-PUT of the peeked
// head, so the LPOP is committed AFTER the durable write lands (BI-9). An empty
// list is not an error (a concurrent drain may have already removed the head).
func (c *Client) CommitDeferredReport(ctx context.Context) error {
	rdb := c.conn()
	if rdb == nil {
		return ErrClientClosed
	}
	if err := rdb.LPop(ctx, DeferredReportsKey).Err(); err != nil && !errors.Is(err, goredis.Nil) {
		return fmt.Errorf("redis: commit-deferred-report: %w", err)
	}
	return nil
}

// DeferredReportLen returns the current depth of reports:deferred (LLEN), used
// to seed the olaitan_report_writes_deferred_count gauge on startup so a
// process restart with a non-empty backlog reports the true depth (AC4).
func (c *Client) DeferredReportLen(ctx context.Context) (int64, error) {
	rdb := c.conn()
	if rdb == nil {
		return 0, ErrClientClosed
	}
	n, err := rdb.LLen(ctx, DeferredReportsKey).Result()
	if err != nil {
		return 0, fmt.Errorf("redis: deferred-report-len: %w", err)
	}
	return n, nil
}
