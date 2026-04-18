package redis

// Redis Streams helpers. (Parallel to internal/nats/streams.go for
// JetStream — different package, same filename on purpose to keep the
// "streams" name obvious inside each wrapper.)

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/olokotoh/olaitan/internal/keys"
)

// StreamEntry is a single message read from a Redis Stream. Fields is a
// map of the stream entry's k/v pairs — callers marshal structured data
// into/out of it themselves (no JSON is enforced by this package).
type StreamEntry struct {
	ID     string
	Fields map[string]string
}

// Append publishes a message to a Redis Stream, trimming the stream to
// approximately StreamMaxLen entries. Only streams under the evidence:
// prefix are allowed — state:/health:/baseline: should never be Redis
// Streams in this architecture.
func (c *Client) Append(ctx context.Context, stream string, fields map[string]any) (string, error) {
	if c == nil || c.rdb == nil {
		return "", ErrClientClosed
	}
	if err := validateStreamKey(stream); err != nil {
		return "", err
	}
	if len(fields) == 0 {
		return "", fmt.Errorf("redis: append %q: fields is empty", stream)
	}
	args := &goredis.XAddArgs{
		Stream: stream,
		ID:     "*",
		Values: fields,
	}
	if c.cfg.StreamMaxLen > 0 {
		args.MaxLen = c.cfg.StreamMaxLen
		args.Approx = true
	}
	id, err := c.rdb.XAdd(ctx, args).Result()
	if err != nil {
		return "", fmt.Errorf("redis: append %q: %w", stream, err)
	}
	return id, nil
}

// Read is a thin wrapper over XREAD. lastID == "" defaults to "$" (only
// new messages arriving after this call). A non-positive block returns
// immediately if nothing is available; a positive block waits up to that
// duration for new entries. (Note: go-redis v9's XReadArgs.Block sends
// BLOCK 0 — "wait forever" — on zero, so we explicitly pass -1 to
// suppress the BLOCK option when the caller wants no blocking.)
func (c *Client) Read(ctx context.Context, stream, lastID string, count int64, block time.Duration) ([]StreamEntry, error) {
	if c == nil || c.rdb == nil {
		return nil, ErrClientClosed
	}
	if err := validateStreamKey(stream); err != nil {
		return nil, err
	}
	if lastID == "" {
		lastID = "$"
	}
	if block <= 0 {
		block = -1
	}
	args := &goredis.XReadArgs{
		Streams: []string{stream, lastID},
		Count:   count,
		Block:   block,
	}
	res, err := c.rdb.XRead(ctx, args).Result()
	if errors.Is(err, goredis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("redis: read %q: %w", stream, err)
	}
	var out []StreamEntry
	for _, s := range res {
		for _, m := range s.Messages {
			out = append(out, messageToEntry(m))
		}
	}
	return out, nil
}

// Range is a thin wrapper over XRANGE. Pass "-" / "+" for the full stream.
func (c *Client) Range(ctx context.Context, stream, start, stop string) ([]StreamEntry, error) {
	if c == nil || c.rdb == nil {
		return nil, ErrClientClosed
	}
	if err := validateStreamKey(stream); err != nil {
		return nil, err
	}
	msgs, err := c.rdb.XRange(ctx, stream, start, stop).Result()
	if err != nil {
		return nil, fmt.Errorf("redis: range %q: %w", stream, err)
	}
	out := make([]StreamEntry, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, messageToEntry(m))
	}
	return out, nil
}

// Len returns the stream's current length.
func (c *Client) Len(ctx context.Context, stream string) (int64, error) {
	if c == nil || c.rdb == nil {
		return 0, ErrClientClosed
	}
	if err := validateStreamKey(stream); err != nil {
		return 0, err
	}
	n, err := c.rdb.XLen(ctx, stream).Result()
	if err != nil {
		return 0, fmt.Errorf("redis: len %q: %w", stream, err)
	}
	return n, nil
}

// validateStreamKey rejects any key that is not in the evidence family.
// Redis Streams is used only for evidence/transitions in this epic; a
// state: or health: stream is almost certainly a caller mistake.
func validateStreamKey(stream string) error {
	if stream == "" {
		return fmt.Errorf("redis: stream key is empty")
	}
	if !strings.HasPrefix(stream, keys.EvidencePrefix) {
		return fmt.Errorf("redis: stream %q: only evidence: streams are allowed", stream)
	}
	return nil
}

func messageToEntry(m goredis.XMessage) StreamEntry {
	fields := make(map[string]string, len(m.Values))
	for k, v := range m.Values {
		if s, ok := v.(string); ok {
			fields[k] = s
			continue
		}
		fields[k] = fmt.Sprint(v)
	}
	return StreamEntry{ID: m.ID, Fields: fields}
}
