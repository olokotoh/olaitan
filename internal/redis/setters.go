package redis

import (
	"context"
	"errors"
	"fmt"
	"strings"
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

// setHashWithTTL runs HSET + EXPIRE in a single pipelined round-trip so a
// process crash or ctx cancel between the two commands cannot leave a
// hash without its family TTL.
func (c *Client) setHashWithTTL(ctx context.Context, rdb *goredis.Client, action, key string, fields map[string]any, ttl time.Duration) error {
	pipe := rdb.TxPipeline()
	pipe.HSet(ctx, key, fields)
	pipe.Expire(ctx, key, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redis: %s %q: %w", action, key, err)
	}
	return nil
}

// SetBaselineMetrics writes a baseline metrics hash with a 48h TTL.
// Key must be in the baseline family — pass the output of
// keys.BaselineMetrics or keys.BaselineWindow, never a raw string.
func (c *Client) SetBaselineMetrics(ctx context.Context, key string, fields map[string]any) error {
	rdb := c.conn()
	if rdb == nil {
		return ErrClientClosed
	}
	if keys.FamilyOf(key) != keys.FamilyBaseline {
		return fmt.Errorf("redis: set-baseline-metrics %q: key is not in baseline family", key)
	}
	if len(fields) == 0 {
		return fmt.Errorf("redis: set-baseline-metrics %q: fields is empty", key)
	}
	return c.setHashWithTTL(ctx, rdb, "set-baseline-metrics", key, fields, ttlBaseline)
}

// SetBaselineWindow appends a (timestamp, event-count) sample into the
// baseline rolling-window sorted-set and refreshes the 48h TTL in a
// single pipelined round-trip. The score is the nanosecond Unix
// timestamp cast to int64 then stored as a float64 — safe for dates up
// to ~year 2255; the member embeds the nanosecond+count pair so two
// samples sharing the same score resolve to distinct sorted-set
// members.
func (c *Client) SetBaselineWindow(ctx context.Context, key string, ts time.Time, eventCount int64) error {
	rdb := c.conn()
	if rdb == nil {
		return ErrClientClosed
	}
	if keys.FamilyOf(key) != keys.FamilyBaseline {
		return fmt.Errorf("redis: set-baseline-window %q: key is not in baseline family", key)
	}
	if ts.IsZero() {
		return fmt.Errorf("redis: set-baseline-window %q: timestamp is zero", key)
	}
	member := fmt.Sprintf("%d:%d", ts.UnixNano(), eventCount)
	pipe := rdb.TxPipeline()
	pipe.ZAdd(ctx, key, goredis.Z{Score: float64(ts.UnixNano()), Member: member})
	pipe.Expire(ctx, key, ttlBaseline)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redis: set-baseline-window %q: %w", key, err)
	}
	return nil
}

// SetCheckpoint stores a checkpoint value. Checkpoints survive
// indefinitely — no TTL is applied.
func (c *Client) SetCheckpoint(ctx context.Context, key, value string) error {
	rdb := c.conn()
	if rdb == nil {
		return ErrClientClosed
	}
	if keys.FamilyOf(key) != keys.FamilyCheckpoint {
		return fmt.Errorf("redis: set-checkpoint %q: key is not in checkpoint family", key)
	}
	if err := rdb.Set(ctx, key, value, 0).Err(); err != nil {
		return fmt.Errorf("redis: set-checkpoint %q: %w", key, err)
	}
	return nil
}

// GetCheckpoint returns a checkpoint value or ErrKeyMissing when unset.
func (c *Client) GetCheckpoint(ctx context.Context, key string) (string, error) {
	rdb := c.conn()
	if rdb == nil {
		return "", ErrClientClosed
	}
	if keys.FamilyOf(key) != keys.FamilyCheckpoint {
		return "", fmt.Errorf("redis: get-checkpoint %q: key is not in checkpoint family", key)
	}
	val, err := rdb.Get(ctx, key).Result()
	if errors.Is(err, goredis.Nil) {
		return "", ErrKeyMissing
	}
	if err != nil {
		return "", fmt.Errorf("redis: get-checkpoint %q: %w", key, err)
	}
	return val, nil
}

// SetState writes a state hash with a 1h TTL in a single pipelined
// round-trip so a ctx cancel between HSET and EXPIRE cannot leave an
// untimed state key.
func (c *Client) SetState(ctx context.Context, key string, fields map[string]any) error {
	rdb := c.conn()
	if rdb == nil {
		return ErrClientClosed
	}
	if keys.FamilyOf(key) != keys.FamilyState {
		return fmt.Errorf("redis: set-state %q: key is not in state family", key)
	}
	if len(fields) == 0 {
		return fmt.Errorf("redis: set-state %q: fields is empty", key)
	}
	return c.setHashWithTTL(ctx, rdb, "set-state", key, fields, ttlState)
}

// GetState returns the state hash. Returns ErrKeyMissing when the key
// does not exist or its TTL expired. The returned map is always
// non-nil but may be empty if the hash exists with no fields — which
// should not happen through this package's SetState (we reject empty
// field maps at write time).
func (c *Client) GetState(ctx context.Context, key string) (map[string]string, error) {
	rdb := c.conn()
	if rdb == nil {
		return nil, ErrClientClosed
	}
	if keys.FamilyOf(key) != keys.FamilyState {
		return nil, fmt.Errorf("redis: get-state %q: key is not in state family", key)
	}
	// Single HGETALL is atomic — no TOCTOU gap against TTL expiry. An
	// empty result map means the key does not exist (or expired); any
	// non-empty map means the hash is present. This relies on SetState
	// rejecting empty field writes above.
	out, err := rdb.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("redis: get-state %q: %w", key, err)
	}
	if len(out) == 0 {
		return nil, ErrKeyMissing
	}
	return out, nil
}

// SetHealth writes the ring's health status string with a 30s TTL.
func (c *Client) SetHealth(ctx context.Context, key, statusJSON string) error {
	rdb := c.conn()
	if rdb == nil {
		return ErrClientClosed
	}
	if keys.FamilyOf(key) != keys.FamilyHealth {
		return fmt.Errorf("redis: set-health %q: key is not in health family", key)
	}
	if statusJSON == "" {
		return fmt.Errorf("redis: set-health %q: status is empty", key)
	}
	if err := rdb.Set(ctx, key, statusJSON, ttlHealth).Err(); err != nil {
		return fmt.Errorf("redis: set-health %q: %w", key, err)
	}
	return nil
}

// GetHealth returns the ring's last reported health status, a presence
// flag (false when the key is absent — distinguishing expired TTL from
// never-set), and any error.
func (c *Client) GetHealth(ctx context.Context, key string) (string, bool, error) {
	rdb := c.conn()
	if rdb == nil {
		return "", false, ErrClientClosed
	}
	if keys.FamilyOf(key) != keys.FamilyHealth {
		return "", false, fmt.Errorf("redis: get-health %q: key is not in health family", key)
	}
	val, err := rdb.Get(ctx, key).Result()
	if errors.Is(err, goredis.Nil) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("redis: get-health %q: %w", key, err)
	}
	return val, true, nil
}

// SetFSMStateCAS writes the durable FSM-state hash for a workload using a
// compare-and-swap on casField (Story 2.3 AC1). The fsm: family carries
// NO TTL: FSM state must survive an arbitrary restart gap (BI-2), so a
// process crash must never let the state silently expire to absent.
//
// CAS semantics: the write lands when the persisted casField equals
// expectedPrior, OR when the key is absent (the workload was never
// persisted, so the first transition can always land and a lost earlier
// write can never strand a workload at CLEAN on restart). A present key
// whose casField differs from expectedPrior means a newer state already
// won; the stale write is dropped and (false, nil) is returned. A
// concurrent modification of the watched key also returns (false, nil)
// so the caller may retry. This makes replays idempotent: re-applying a
// transition whose target already landed is a no-op CAS (BI-7).
func (c *Client) SetFSMStateCAS(ctx context.Context, key, casField, expectedPrior string, fields map[string]any) (bool, error) {
	rdb := c.conn()
	if rdb == nil {
		return false, ErrClientClosed
	}
	if keys.FamilyOf(key) != keys.FamilyFSM {
		return false, fmt.Errorf("redis: set-fsm-state %q: key is not in fsm family", key)
	}
	if casField == "" {
		return false, fmt.Errorf("redis: set-fsm-state %q: cas field is empty", key)
	}
	if len(fields) == 0 {
		return false, fmt.Errorf("redis: set-fsm-state %q: fields is empty", key)
	}
	swapped := false
	txf := func(tx *goredis.Tx) error {
		prior, gerr := tx.HGet(ctx, key, casField).Result()
		absent := errors.Is(gerr, goredis.Nil)
		if gerr != nil && !absent {
			return gerr
		}
		if !absent && prior != expectedPrior {
			// A newer state already won; drop the stale/replayed write.
			return nil
		}
		_, perr := tx.TxPipelined(ctx, func(pipe goredis.Pipeliner) error {
			pipe.HSet(ctx, key, fields)
			return nil
		})
		if perr != nil {
			return perr
		}
		swapped = true
		return nil
	}
	if err := rdb.Watch(ctx, txf, key); err != nil {
		if errors.Is(err, goredis.TxFailedErr) {
			// The watched key changed between WATCH and EXEC; not swapped.
			return false, nil
		}
		return false, fmt.Errorf("redis: set-fsm-state %q: %w", key, err)
	}
	return swapped, nil
}

// GetFSMState returns the durable FSM-state hash for a workload, or
// ErrKeyMissing when the key does not exist. Used on restart recovery.
func (c *Client) GetFSMState(ctx context.Context, key string) (map[string]string, error) {
	rdb := c.conn()
	if rdb == nil {
		return nil, ErrClientClosed
	}
	if keys.FamilyOf(key) != keys.FamilyFSM {
		return nil, fmt.Errorf("redis: get-fsm-state %q: key is not in fsm family", key)
	}
	out, err := rdb.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("redis: get-fsm-state %q: %w", key, err)
	}
	if len(out) == 0 {
		return nil, ErrKeyMissing
	}
	return out, nil
}

// AppendFSMHistory appends a marshalled transition record to the
// workload's fsm:{workload_id}:history list and trims it to the last
// capN entries in one pipelined round-trip (Story 2.3 AC1). When capN
// is <= 0 the list is unbounded. No TTL is applied.
func (c *Client) AppendFSMHistory(ctx context.Context, key string, entry []byte, capN int) error {
	rdb := c.conn()
	if rdb == nil {
		return ErrClientClosed
	}
	if keys.FamilyOf(key) != keys.FamilyFSM {
		return fmt.Errorf("redis: append-fsm-history %q: key is not in fsm family", key)
	}
	if len(entry) == 0 {
		return fmt.Errorf("redis: append-fsm-history %q: entry is empty", key)
	}
	pipe := rdb.TxPipeline()
	pipe.RPush(ctx, key, entry)
	if capN > 0 {
		pipe.LTrim(ctx, key, int64(-capN), -1)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redis: append-fsm-history %q: %w", key, err)
	}
	return nil
}

// ScanFSMStateKeys returns every durable FSM-state key (fsm:{workload_id})
// currently in Redis, excluding the fsm:{workload_id}:history lists. Used
// on restart to rehydrate the in-memory FSM map (Story 2.3 AC2).
func (c *Client) ScanFSMStateKeys(ctx context.Context) ([]string, error) {
	rdb := c.conn()
	if rdb == nil {
		return nil, ErrClientClosed
	}
	var out []string
	var cursor uint64
	for {
		batch, next, err := rdb.Scan(ctx, cursor, keys.FSMStatePrefix+"*", 256).Result()
		if err != nil {
			return nil, fmt.Errorf("redis: scan-fsm-state: %w", err)
		}
		for _, k := range batch {
			if strings.HasSuffix(k, ":history") {
				continue
			}
			out = append(out, k)
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return out, nil
}
