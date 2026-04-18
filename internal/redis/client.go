// Package redis wraps the go-redis driver with connection pooling, retry
// wiring, TTL-per-key-family typed setters, and a Redis Streams helper
// surface. Key constants and builders live in internal/keys/; everything
// here is the transport-layer wrapper.
package redis

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// ErrClientClosed is returned when a method is called on a Client whose
// underlying connection is nil or already closed. Masks the driver's
// redis.ErrClosed so callers never have to import go-redis just to
// identify a closed client.
var ErrClientClosed = errors.New("redis: client is closed")

// ErrKeyMissing is returned when a Get-style method targets a key that
// does not exist (or whose TTL expired). Masks go-redis's redis.Nil so
// callers do not need to import the driver for a common sentinel.
var ErrKeyMissing = errors.New("redis: key missing")

// ClientConfig holds Redis connection settings. TLS plumbing is wired but
// cert-rotation / CA-bundle handling is out of scope for Story 1.5 (see
// deferred-work.md). Callers that want TLS populate TLSConfig themselves.
type ClientConfig struct {
	Addr                  string
	Username              string
	Password              string
	DB                    int
	PoolSize              int
	MinIdleConns          int
	DialTimeout           time.Duration
	ReadTimeout           time.Duration
	WriteTimeout          time.Duration
	MaxRetries            int
	MinRetryBackoff       time.Duration
	MaxRetryBackoff       time.Duration
	ContextTimeoutEnabled bool
	// StreamMaxLen caps each Redis Streams key at this approximate length
	// (MAXLEN ~). Enforced by Append in streams.go. 0 disables trimming.
	StreamMaxLen int64
	// TLSConfig, when non-nil, enables TLS to Redis. Certificate rotation
	// and CA-bundle discovery are owned by a future security story.
	TLSConfig *tls.Config
}

// DefaultConfig returns sensible defaults: local plaintext Redis, pool
// size 10, retry 6× with go-redis's exponential-with-equal-jitter backoff
// clamped between 100 ms and 5 s (not a literal 100 → 200 → 400 schedule).
func DefaultConfig() ClientConfig {
	return ClientConfig{
		Addr:                  "localhost:6379",
		PoolSize:              10,
		MinIdleConns:          2,
		DialTimeout:           5 * time.Second,
		ReadTimeout:           3 * time.Second,
		WriteTimeout:          3 * time.Second,
		MaxRetries:            6,
		MinRetryBackoff:       100 * time.Millisecond,
		MaxRetryBackoff:       5 * time.Second,
		ContextTimeoutEnabled: true,
		StreamMaxLen:          100_000,
	}
}

// Client wraps *goredis.Client with the package's error-wrapping contract
// and the key-family validator enforced by typed setters.
//
// The mu/closeOnce pair protects rdb from the Close-vs-in-flight race:
// callers resolve rdb under RLock, Close takes the write lock, nils rdb,
// and the sync.Once ensures the underlying pool is closed exactly once
// even under concurrent Close callers.
type Client struct {
	mu        sync.RWMutex
	closeOnce sync.Once
	rdb       *goredis.Client
	cfg       ClientConfig
}

// conn returns the underlying *goredis.Client under RLock, or nil if
// the Client is closed. All method call sites use this helper instead
// of touching c.rdb directly so Close is race-safe.
func (c *Client) conn() *goredis.Client {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rdb
}

// NewClient validates cfg, opens the pool, and issues a short-deadline
// PING so a bad Addr fails fast at construction time rather than deep
// in a hot path.
func NewClient(cfg ClientConfig) (*Client, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	opts := &goredis.Options{
		Addr:                  cfg.Addr,
		Username:              cfg.Username,
		Password:              cfg.Password,
		DB:                    cfg.DB,
		PoolSize:              cfg.PoolSize,
		MinIdleConns:          cfg.MinIdleConns,
		DialTimeout:           cfg.DialTimeout,
		ReadTimeout:           cfg.ReadTimeout,
		WriteTimeout:          cfg.WriteTimeout,
		MaxRetries:            cfg.MaxRetries,
		MinRetryBackoff:       cfg.MinRetryBackoff,
		MaxRetryBackoff:       cfg.MaxRetryBackoff,
		ContextTimeoutEnabled: cfg.ContextTimeoutEnabled,
		TLSConfig:             cfg.TLSConfig,
	}

	rdb := goredis.NewClient(opts)

	pingCtx, cancel := context.WithTimeout(context.Background(), cfg.DialTimeout)
	defer cancel()
	if err := rdb.Ping(pingCtx).Err(); err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("redis: ping %s: %w", cfg.Addr, err)
	}

	return &Client{rdb: rdb, cfg: cfg}, nil
}

func validateConfig(cfg ClientConfig) error {
	if cfg.Addr == "" {
		return errors.New("redis: config: addr is empty")
	}
	if cfg.DB < 0 || cfg.DB > 15 {
		return errors.New("redis: config: db must be in [0, 15]")
	}
	if cfg.PoolSize < 0 {
		return errors.New("redis: config: pool-size must be non-negative")
	}
	if cfg.MinIdleConns < 0 {
		return errors.New("redis: config: min-idle-conns must be non-negative")
	}
	if cfg.MaxRetries < 0 {
		return errors.New("redis: config: max-retries must be non-negative")
	}
	if cfg.MinRetryBackoff < 0 {
		return errors.New("redis: config: min-retry-backoff must be non-negative")
	}
	if cfg.MaxRetryBackoff < 0 {
		return errors.New("redis: config: max-retry-backoff must be non-negative")
	}
	if cfg.MinRetryBackoff > cfg.MaxRetryBackoff {
		return errors.New("redis: config: min-retry-backoff must be ≤ max-retry-backoff")
	}
	if cfg.StreamMaxLen < 0 {
		return errors.New("redis: config: stream-max-len must be non-negative")
	}
	if cfg.DialTimeout <= 0 {
		return errors.New("redis: config: dial-timeout must be positive")
	}
	if cfg.ReadTimeout < 0 {
		return errors.New("redis: config: read-timeout must be non-negative")
	}
	if cfg.WriteTimeout < 0 {
		return errors.New("redis: config: write-timeout must be non-negative")
	}
	return nil
}

// Raw returns the underlying *goredis.Client for escape-hatch operations.
// Callers using Raw must uphold the "redis: action: %w" wrap contract
// themselves. Prefer the typed setters/getters in the same package.
func (c *Client) Raw() *goredis.Client {
	return c.conn()
}

// Close flushes any pending commands and closes the underlying pool.
// Safe to call on a nil or already-closed Client, and safe to call
// concurrently — only the first caller drives the actual pool close
// via sync.Once; subsequent callers return nil immediately once rdb
// has been cleared under the write lock. The context deadline bounds
// the close wait; a deadline that expires before close finishes
// returns a wrapped context error. The spawned goroutine will finish
// once the pool drains even if this call returns on ctx.Done — it
// cannot be cancelled, but it is bounded by the go-redis pool's own
// lifecycle.
func (c *Client) Close(ctx context.Context) error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	rdb := c.rdb
	c.rdb = nil
	c.mu.Unlock()
	if rdb == nil {
		return nil
	}

	var closeErr error
	c.closeOnce.Do(func() {
		done := make(chan error, 1)
		go func() {
			done <- rdb.Close()
		}()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, goredis.ErrClosed) {
				closeErr = fmt.Errorf("redis: close: %w", err)
			}
		case <-ctx.Done():
			closeErr = fmt.Errorf("redis: close: %w", ctx.Err())
		}
	})
	return closeErr
}
