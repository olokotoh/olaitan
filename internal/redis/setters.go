package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/olokotoh/olaitan/internal/keys"
)

// TTL policy per key family. These match the architecture contract
// (baselines 48h, state 1h, health 30s) and must not drift without a
// corresponding architecture change.
const (
	ttlBaseline = 48 * time.Hour
	ttlState    = 1 * time.Hour
	ttlHealth   = 30 * time.Second
)

// SetBaselineMetrics writes a baseline metrics hash with a 48h TTL.
// Key must be in the baseline family — pass the output of
// keys.BaselineMetrics or keys.BaselineWindow, never a raw string.
func (c *Client) SetBaselineMetrics(ctx context.Context, key string, fields map[string]any) error {
	if c == nil || c.rdb == nil {
		return ErrClientClosed
	}
	if keys.FamilyOf(key) != keys.FamilyBaseline {
		return fmt.Errorf("redis: set-baseline-metrics %q: key is not in baseline family", key)
	}
	if len(fields) == 0 {
		return fmt.Errorf("redis: set-baseline-metrics %q: fields is empty", key)
	}
	if err := c.rdb.HSet(ctx, key, fields).Err(); err != nil {
		return fmt.Errorf("redis: set-baseline-metrics %q: %w", key, err)
	}
	if err := c.rdb.Expire(ctx, key, ttlBaseline).Err(); err != nil {
		return fmt.Errorf("redis: set-baseline-metrics-ttl %q: %w", key, err)
	}
	return nil
}

// SetBaselineWindow appends a (timestamp, event-count) sample into the
// baseline rolling-window sorted-set and refreshes the 48h TTL.
func (c *Client) SetBaselineWindow(ctx context.Context, key string, ts time.Time, eventCount int64) error {
	if c == nil || c.rdb == nil {
		return ErrClientClosed
	}
	if keys.FamilyOf(key) != keys.FamilyBaseline {
		return fmt.Errorf("redis: set-baseline-window %q: key is not in baseline family", key)
	}
	member := fmt.Sprintf("%d:%d", ts.UnixNano(), eventCount)
	if err := c.rdb.ZAdd(ctx, key, goredis.Z{Score: float64(ts.UnixNano()), Member: member}).Err(); err != nil {
		return fmt.Errorf("redis: set-baseline-window %q: %w", key, err)
	}
	if err := c.rdb.Expire(ctx, key, ttlBaseline).Err(); err != nil {
		return fmt.Errorf("redis: set-baseline-window-ttl %q: %w", key, err)
	}
	return nil
}

// SetCheckpoint stores a checkpoint value. Checkpoints survive
// indefinitely — no TTL is applied.
func (c *Client) SetCheckpoint(ctx context.Context, key, value string) error {
	if c == nil || c.rdb == nil {
		return ErrClientClosed
	}
	if keys.FamilyOf(key) != keys.FamilyCheckpoint {
		return fmt.Errorf("redis: set-checkpoint %q: key is not in checkpoint family", key)
	}
	if err := c.rdb.Set(ctx, key, value, 0).Err(); err != nil {
		return fmt.Errorf("redis: set-checkpoint %q: %w", key, err)
	}
	return nil
}

// GetCheckpoint returns a checkpoint value or ErrKeyMissing when unset.
func (c *Client) GetCheckpoint(ctx context.Context, key string) (string, error) {
	if c == nil || c.rdb == nil {
		return "", ErrClientClosed
	}
	if keys.FamilyOf(key) != keys.FamilyCheckpoint {
		return "", fmt.Errorf("redis: get-checkpoint %q: key is not in checkpoint family", key)
	}
	val, err := c.rdb.Get(ctx, key).Result()
	if errors.Is(err, goredis.Nil) {
		return "", ErrKeyMissing
	}
	if err != nil {
		return "", fmt.Errorf("redis: get-checkpoint %q: %w", key, err)
	}
	return val, nil
}

// SetState writes a state hash with a 1h TTL.
func (c *Client) SetState(ctx context.Context, key string, fields map[string]any) error {
	if c == nil || c.rdb == nil {
		return ErrClientClosed
	}
	if keys.FamilyOf(key) != keys.FamilyState {
		return fmt.Errorf("redis: set-state %q: key is not in state family", key)
	}
	if len(fields) == 0 {
		return fmt.Errorf("redis: set-state %q: fields is empty", key)
	}
	if err := c.rdb.HSet(ctx, key, fields).Err(); err != nil {
		return fmt.Errorf("redis: set-state %q: %w", key, err)
	}
	if err := c.rdb.Expire(ctx, key, ttlState).Err(); err != nil {
		return fmt.Errorf("redis: set-state-ttl %q: %w", key, err)
	}
	return nil
}

// GetState returns the state hash. Returns ErrKeyMissing when the key
// does not exist or its TTL expired. The returned map is nil when the
// hash exists but has no fields.
func (c *Client) GetState(ctx context.Context, key string) (map[string]string, error) {
	if c == nil || c.rdb == nil {
		return nil, ErrClientClosed
	}
	if keys.FamilyOf(key) != keys.FamilyState {
		return nil, fmt.Errorf("redis: get-state %q: key is not in state family", key)
	}
	// Disambiguate "no hash" from "empty hash" with EXISTS — HGetAll returns
	// an empty map for both.
	n, err := c.rdb.Exists(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("redis: get-state-exists %q: %w", key, err)
	}
	if n == 0 {
		return nil, ErrKeyMissing
	}
	out, err := c.rdb.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("redis: get-state %q: %w", key, err)
	}
	return out, nil
}

// SetHealth writes the ring's health status string with a 30s TTL.
func (c *Client) SetHealth(ctx context.Context, key, statusJSON string) error {
	if c == nil || c.rdb == nil {
		return ErrClientClosed
	}
	if keys.FamilyOf(key) != keys.FamilyHealth {
		return fmt.Errorf("redis: set-health %q: key is not in health family", key)
	}
	if err := c.rdb.Set(ctx, key, statusJSON, ttlHealth).Err(); err != nil {
		return fmt.Errorf("redis: set-health %q: %w", key, err)
	}
	return nil
}

// GetHealth returns the ring's last reported health status, a presence
// flag (false when the key is absent — distinguishing expired TTL from
// never-set), and any error.
func (c *Client) GetHealth(ctx context.Context, key string) (string, bool, error) {
	if c == nil || c.rdb == nil {
		return "", false, ErrClientClosed
	}
	if keys.FamilyOf(key) != keys.FamilyHealth {
		return "", false, fmt.Errorf("redis: get-health %q: key is not in health family", key)
	}
	val, err := c.rdb.Get(ctx, key).Result()
	if errors.Is(err, goredis.Nil) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("redis: get-health %q: %w", key, err)
	}
	return val, true, nil
}
