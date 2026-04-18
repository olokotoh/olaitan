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
//
// Non-string values returned by Redis are stringified via fmt.Sprint, so
// numeric fields written via Append come back as their string form.
// Callers that need typed round-trip should marshal to JSON before
// Append and unmarshal after Read.
type StreamEntry struct {
	ID     string
	Fields map[string]string
}

// BlockForever is the sentinel for an XREAD that should wait indefinitely
// for new entries. Pass this to Read's block argument to request
// go-redis's native BLOCK 0 semantics. Any other non-positive value is
// treated as "return immediately" (non-blocking).
const BlockForever = time.Duration(-1 << 62)

// Append publishes a message to a Redis Stream, trimming the stream to
// approximately StreamMaxLen entries. Only streams under the evidence:
// prefix are allowed — state:/health:/baseline: should never be Redis
// Streams in this architecture.
func (c *Client) Append(ctx context.Context, stream string, fields map[string]any) (string, error) {
	rdb := c.conn()
	if rdb == nil {
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
	id, err := rdb.XAdd(ctx, args).Result()
	if err != nil {
		return "", fmt.Errorf("redis: append %q: %w", stream, err)
	}
	return id, nil
}

// Read is a thin wrapper over XREAD. An empty lastID is rejected —
// callers must pass an explicit sentinel: "$" for "new messages only",
// "0" to replay from the start, or a prior entry ID to resume. For the
// block argument: a positive duration sets a block timeout; any
// non-positive value other than BlockForever maps to "return
// immediately"; BlockForever maps to go-redis's BLOCK 0 (wait forever).
func (c *Client) Read(ctx context.Context, stream, lastID string, count int64, block time.Duration) ([]StreamEntry, error) {
	rdb := c.conn()
	if rdb == nil {
		return nil, ErrClientClosed
	}
	if err := validateStreamKey(stream); err != nil {
		return nil, err
	}
	if lastID == "" {
		return nil, fmt.Errorf("redis: read %q: lastID is empty (use \"$\", \"0\", or a prior entry ID)", stream)
	}
	if count < 0 {
		return nil, fmt.Errorf("redis: read %q: count must be non-negative", stream)
	}
	var blockArg time.Duration
	switch {
	case block == BlockForever:
		blockArg = 0 // go-redis sends BLOCK 0 = wait forever
	case block <= 0:
		blockArg = -1 // go-redis suppresses BLOCK — non-blocking
	default:
		blockArg = block
	}
	args := &goredis.XReadArgs{
		Streams: []string{stream, lastID},
		Count:   count,
		Block:   blockArg,
	}
	res, err := rdb.XRead(ctx, args).Result()
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
	rdb := c.conn()
	if rdb == nil {
		return nil, ErrClientClosed
	}
	if err := validateStreamKey(stream); err != nil {
		return nil, err
	}
	msgs, err := rdb.XRange(ctx, stream, start, stop).Result()
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
	rdb := c.conn()
	if rdb == nil {
		return 0, ErrClientClosed
	}
	if err := validateStreamKey(stream); err != nil {
		return 0, err
	}
	n, err := rdb.XLen(ctx, stream).Result()
	if err != nil {
		return 0, fmt.Errorf("redis: len %q: %w", stream, err)
	}
	return n, nil
}

// validateStreamKey rejects any key that is not in the evidence family.
// Redis Streams is used only for evidence/transitions in this epic; a
// state: or health: stream is almost certainly a caller mistake. The
// check also requires at least one non-empty token after the prefix
// and rejects glob metacharacters that could turn an argv string into
// a pattern at the driver level.
func validateStreamKey(stream string) error {
	if stream == "" {
		return fmt.Errorf("redis: stream key is empty")
	}
	if !strings.HasPrefix(stream, keys.EvidencePrefix) {
		return fmt.Errorf("redis: stream %q: only evidence: streams are allowed", stream)
	}
	suffix := stream[len(keys.EvidencePrefix):]
	if suffix == "" {
		return fmt.Errorf("redis: stream %q: missing token after prefix", stream)
	}
	if strings.ContainsAny(suffix, "*?[") {
		return fmt.Errorf("redis: stream %q: contains glob metacharacter", stream)
	}
	return nil
}

func messageToEntry(m goredis.XMessage) StreamEntry {
	fields := make(map[string]string, len(m.Values))
	for k, v := range m.Values {
		switch x := v.(type) {
		case nil:
			fields[k] = ""
		case string:
			fields[k] = x
		default:
			fields[k] = fmt.Sprint(v)
		}
	}
	return StreamEntry{ID: m.ID, Fields: fields}
}
