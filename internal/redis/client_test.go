package redis_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	redisclient "github.com/olokotoh/olaitan/internal/redis"
)

// startMiniredis spins up an in-process Redis substitute.
func startMiniredis(t *testing.T) *miniredis.Miniredis {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("start miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	return mr
}

// newTestClient constructs a Client pointed at mr with auth-aware config.
func newTestClient(t *testing.T, mr *miniredis.Miniredis) *redisclient.Client {
	t.Helper()
	cfg := redisclient.DefaultConfig()
	cfg.Addr = mr.Addr()
	c, err := redisclient.NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

func TestNewClientValidation(t *testing.T) {
	base := redisclient.DefaultConfig()

	tests := []struct {
		name    string
		mutate  func(*redisclient.ClientConfig)
		wantSub string
	}{
		{"empty-addr", func(c *redisclient.ClientConfig) { c.Addr = "" }, "addr is empty"},
		{"negative-pool", func(c *redisclient.ClientConfig) { c.PoolSize = -1 }, "pool-size"},
		{"negative-min-idle", func(c *redisclient.ClientConfig) { c.MinIdleConns = -1 }, "min-idle-conns"},
		{"negative-max-retries", func(c *redisclient.ClientConfig) { c.MaxRetries = -1 }, "max-retries"},
		{"negative-min-backoff", func(c *redisclient.ClientConfig) { c.MinRetryBackoff = -time.Millisecond }, "min-retry-backoff"},
		{"negative-max-backoff", func(c *redisclient.ClientConfig) { c.MaxRetryBackoff = -time.Millisecond }, "max-retry-backoff"},
		{"backoff-ordering", func(c *redisclient.ClientConfig) {
			c.MinRetryBackoff = 10 * time.Second
			c.MaxRetryBackoff = 1 * time.Second
		}, "min-retry-backoff must be ≤"},
		{"backoff-ordering-max-zero", func(c *redisclient.ClientConfig) {
			c.MinRetryBackoff = 10 * time.Second
			c.MaxRetryBackoff = 0
		}, "min-retry-backoff must be ≤"},
		{"negative-stream-maxlen", func(c *redisclient.ClientConfig) { c.StreamMaxLen = -1 }, "stream-max-len"},
		{"zero-dial-timeout", func(c *redisclient.ClientConfig) { c.DialTimeout = 0 }, "dial-timeout"},
		{"negative-dial-timeout", func(c *redisclient.ClientConfig) { c.DialTimeout = -time.Millisecond }, "dial-timeout"},
		{"negative-read-timeout", func(c *redisclient.ClientConfig) { c.ReadTimeout = -time.Millisecond }, "read-timeout"},
		{"negative-write-timeout", func(c *redisclient.ClientConfig) { c.WriteTimeout = -time.Millisecond }, "write-timeout"},
		{"db-negative", func(c *redisclient.ClientConfig) { c.DB = -1 }, "db must be in"},
		{"db-too-large", func(c *redisclient.ClientConfig) { c.DB = 16 }, "db must be in"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			tt.mutate(&cfg)
			_, err := redisclient.NewClient(cfg)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantSub)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("err %q does not contain %q", err, tt.wantSub)
			}
			if !strings.HasPrefix(err.Error(), "redis:") {
				t.Errorf("err %q does not start with %q", err, "redis:")
			}
		})
	}
}

func TestNewClientAuthRejected(t *testing.T) {
	mr := startMiniredis(t)
	mr.RequireAuth("hunter2")

	cfg := redisclient.DefaultConfig()
	cfg.Addr = mr.Addr()
	cfg.Password = "wrong"
	_, err := redisclient.NewClient(cfg)
	if err == nil {
		t.Fatal("expected AUTH error, got nil")
	}
	if !strings.HasPrefix(err.Error(), "redis:") {
		t.Errorf("err %q missing redis: prefix", err)
	}
}

func TestNewClientAuthAccepted(t *testing.T) {
	mr := startMiniredis(t)
	mr.RequireAuth("hunter2")

	cfg := redisclient.DefaultConfig()
	cfg.Addr = mr.Addr()
	cfg.Password = "hunter2"
	c, err := redisclient.NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
}

func TestSetBaselineMetricsTTL48h(t *testing.T) {
	mr := startMiniredis(t)
	c := newTestClient(t, mr)
	ctx := context.Background()

	key := "baseline:default:nginx:metrics"
	if err := c.SetBaselineMetrics(ctx, key, map[string]any{"p50": "12", "p99": "40"}); err != nil {
		t.Fatalf("set: %v", err)
	}
	ttl := mr.TTL(key)
	if ttl < 47*time.Hour || ttl > 48*time.Hour+time.Second {
		t.Errorf("TTL = %v, want ~48h", ttl)
	}
	mr.FastForward(48*time.Hour + time.Second)
	if mr.Exists(key) {
		t.Error("expected key to be expired after 48h FastForward")
	}
}

func TestSetBaselineWindowTTL48h(t *testing.T) {
	mr := startMiniredis(t)
	c := newTestClient(t, mr)
	ctx := context.Background()

	key := "baseline:default:nginx:window"
	if err := c.SetBaselineWindow(ctx, key, time.Unix(100, 0), 5); err != nil {
		t.Fatalf("set: %v", err)
	}
	ttl := mr.TTL(key)
	if ttl < 47*time.Hour || ttl > 48*time.Hour+time.Second {
		t.Errorf("TTL = %v, want ~48h", ttl)
	}
}

func TestSetCheckpointNoTTL(t *testing.T) {
	mr := startMiniredis(t)
	c := newTestClient(t, mr)
	ctx := context.Background()

	key := "checkpoint:correlator:stream_seq"
	if err := c.SetCheckpoint(ctx, key, "42"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if ttl := mr.TTL(key); ttl != 0 {
		t.Errorf("TTL = %v, want 0 (no TTL)", ttl)
	}
	mr.FastForward(72 * time.Hour)
	got, err := c.GetCheckpoint(ctx, key)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != "42" {
		t.Errorf("value = %q, want %q", got, "42")
	}
}

func TestGetCheckpointMissing(t *testing.T) {
	mr := startMiniredis(t)
	c := newTestClient(t, mr)
	ctx := context.Background()

	_, err := c.GetCheckpoint(ctx, "checkpoint:correlator:stream_seq")
	if !errors.Is(err, redisclient.ErrKeyMissing) {
		t.Errorf("err = %v, want ErrKeyMissing", err)
	}
}

func TestSetStateTTL1h(t *testing.T) {
	mr := startMiniredis(t)
	c := newTestClient(t, mr)
	ctx := context.Background()

	key := "state:default:nginx"
	if err := c.SetState(ctx, key, map[string]any{"fsm": "clean"}); err != nil {
		t.Fatalf("set: %v", err)
	}
	ttl := mr.TTL(key)
	if ttl < 59*time.Minute || ttl > time.Hour+time.Second {
		t.Errorf("TTL = %v, want ~1h", ttl)
	}

	got, err := c.GetState(ctx, key)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got["fsm"] != "clean" {
		t.Errorf("fsm = %q, want clean", got["fsm"])
	}

	mr.FastForward(time.Hour + time.Second)
	if _, err := c.GetState(ctx, key); !errors.Is(err, redisclient.ErrKeyMissing) {
		t.Errorf("post-TTL err = %v, want ErrKeyMissing", err)
	}
}

func TestSetHealthTTL30s(t *testing.T) {
	mr := startMiniredis(t)
	c := newTestClient(t, mr)
	ctx := context.Background()

	key := "health:ring-1"
	if err := c.SetHealth(ctx, key, `{"ok":true}`); err != nil {
		t.Fatalf("set: %v", err)
	}
	ttl := mr.TTL(key)
	if ttl < 29*time.Second || ttl > 30*time.Second+100*time.Millisecond {
		t.Errorf("TTL = %v, want ~30s", ttl)
	}

	val, present, err := c.GetHealth(ctx, key)
	if err != nil || !present || val != `{"ok":true}` {
		t.Errorf("GetHealth = %q,%v,%v", val, present, err)
	}

	mr.FastForward(31 * time.Second)
	_, present, err = c.GetHealth(ctx, key)
	if err != nil {
		t.Fatalf("post-TTL err: %v", err)
	}
	if present {
		t.Error("expected present=false after TTL expiry")
	}
}

func TestSetterFamilyMismatchRejected(t *testing.T) {
	mr := startMiniredis(t)
	c := newTestClient(t, mr)
	ctx := context.Background()

	cases := []struct {
		name string
		call func() error
	}{
		{"set-baseline-wrong-family", func() error {
			return c.SetBaselineMetrics(ctx, "state:default:nginx", map[string]any{"x": 1})
		}},
		{"set-state-wrong-family", func() error {
			return c.SetState(ctx, "baseline:default:nginx:metrics", map[string]any{"x": 1})
		}},
		{"set-health-wrong-family", func() error {
			return c.SetHealth(ctx, "state:default:nginx", "ok")
		}},
		{"set-checkpoint-wrong-family", func() error {
			return c.SetCheckpoint(ctx, "state:default:nginx", "ok")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if err == nil {
				t.Fatal("expected family-mismatch error, got nil")
			}
			if !strings.HasPrefix(err.Error(), "redis:") {
				t.Errorf("err %q missing redis: prefix", err)
			}
		})
	}
}

func TestErrorWrapPattern(t *testing.T) {
	mr := startMiniredis(t)
	c := newTestClient(t, mr)
	ctx := context.Background()

	// Force every subsequent command to error.
	mr.SetError("BOOM")

	calls := []struct {
		name string
		run  func() error
	}{
		{"set-baseline-metrics", func() error {
			return c.SetBaselineMetrics(ctx, "baseline:default:nginx:metrics", map[string]any{"x": 1})
		}},
		{"set-baseline-window", func() error {
			return c.SetBaselineWindow(ctx, "baseline:default:nginx:window", time.Now(), 1)
		}},
		{"set-checkpoint", func() error {
			return c.SetCheckpoint(ctx, "checkpoint:correlator:stream_seq", "1")
		}},
		{"get-checkpoint", func() error {
			_, err := c.GetCheckpoint(ctx, "checkpoint:correlator:stream_seq")
			return err
		}},
		{"set-state", func() error { return c.SetState(ctx, "state:default:nginx", map[string]any{"x": 1}) }},
		{"get-state", func() error { _, err := c.GetState(ctx, "state:default:nginx"); return err }},
		{"set-health", func() error { return c.SetHealth(ctx, "health:ring-1", "ok") }},
		{"get-health", func() error { _, _, err := c.GetHealth(ctx, "health:ring-1"); return err }},
		{"append", func() error {
			_, err := c.Append(ctx, "evidence:incident:INC-1", map[string]any{"k": "v"})
			return err
		}},
		{"range", func() error { _, err := c.Range(ctx, "evidence:incident:INC-1", "-", "+"); return err }},
		{"len", func() error { _, err := c.Len(ctx, "evidence:incident:INC-1"); return err }},
	}
	for _, tc := range calls {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.HasPrefix(err.Error(), "redis:") {
				t.Errorf("err %q does not start with %q", err, "redis:")
			}
		})
	}
}

func TestNilReceiverGuards(t *testing.T) {
	var c *redisclient.Client
	ctx := context.Background()

	checks := []struct {
		name string
		run  func() error
	}{
		{"set-baseline-metrics", func() error { return c.SetBaselineMetrics(ctx, "baseline:x:y:metrics", map[string]any{"k": 1}) }},
		{"set-baseline-window", func() error { return c.SetBaselineWindow(ctx, "baseline:x:y:window", time.Now(), 1) }},
		{"set-checkpoint", func() error { return c.SetCheckpoint(ctx, "checkpoint:x", "v") }},
		{"get-checkpoint", func() error { _, err := c.GetCheckpoint(ctx, "checkpoint:x"); return err }},
		{"set-state", func() error { return c.SetState(ctx, "state:x:y", map[string]any{"k": 1}) }},
		{"get-state", func() error { _, err := c.GetState(ctx, "state:x:y"); return err }},
		{"set-health", func() error { return c.SetHealth(ctx, "health:r", "ok") }},
		{"get-health", func() error { _, _, err := c.GetHealth(ctx, "health:r"); return err }},
		{"append", func() error { _, err := c.Append(ctx, "evidence:incident:x", map[string]any{"k": "v"}); return err }},
		{"read", func() error { _, err := c.Read(ctx, "evidence:incident:x", "", 0, 0); return err }},
		{"range", func() error { _, err := c.Range(ctx, "evidence:incident:x", "-", "+"); return err }},
		{"len", func() error { _, err := c.Len(ctx, "evidence:incident:x"); return err }},
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(); !errors.Is(err, redisclient.ErrClientClosed) {
				t.Errorf("got %v, want ErrClientClosed", err)
			}
		})
	}

	if raw := c.Raw(); raw != nil {
		t.Errorf("Raw on nil = %v, want nil", raw)
	}
	if err := c.Close(ctx); err != nil {
		t.Errorf("Close on nil = %v, want nil", err)
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	mr := startMiniredis(t)
	cfg := redisclient.DefaultConfig()
	cfg.Addr = mr.Addr()
	c, err := redisclient.NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	if err := c.Close(context.Background()); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := c.Close(context.Background()); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

func TestConcurrentAppend(t *testing.T) {
	mr := startMiniredis(t)
	c := newTestClient(t, mr)
	ctx := context.Background()

	const (
		workers = 50
		per     = 100
	)
	stream := "evidence:incident:concurrent"

	var wg sync.WaitGroup
	errs := make(chan error, workers*per)
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				if _, err := c.Append(ctx, stream, map[string]any{"w": id, "i": i}); err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("append: %v", err)
	}

	n, err := c.Len(ctx, stream)
	if err != nil {
		t.Fatalf("len: %v", err)
	}
	if n != workers*per {
		t.Errorf("len = %d, want %d", n, workers*per)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := redisclient.DefaultConfig()
	if cfg.Addr == "" {
		t.Error("Addr should not be empty")
	}
	if cfg.PoolSize != 10 {
		t.Errorf("PoolSize = %d, want 10", cfg.PoolSize)
	}
	if cfg.MinIdleConns != 2 {
		t.Errorf("MinIdleConns = %d, want 2", cfg.MinIdleConns)
	}
	if cfg.DialTimeout != 5*time.Second {
		t.Errorf("DialTimeout = %v, want 5s", cfg.DialTimeout)
	}
	if cfg.ReadTimeout != 3*time.Second {
		t.Errorf("ReadTimeout = %v, want 3s", cfg.ReadTimeout)
	}
	if cfg.WriteTimeout != 3*time.Second {
		t.Errorf("WriteTimeout = %v, want 3s", cfg.WriteTimeout)
	}
	if cfg.MaxRetries != 6 {
		t.Errorf("MaxRetries = %d, want 6", cfg.MaxRetries)
	}
	if cfg.MinRetryBackoff != 100*time.Millisecond {
		t.Errorf("MinRetryBackoff = %v, want 100ms", cfg.MinRetryBackoff)
	}
	if cfg.MaxRetryBackoff != 5*time.Second {
		t.Errorf("MaxRetryBackoff = %v, want 5s", cfg.MaxRetryBackoff)
	}
	if cfg.StreamMaxLen != 100_000 {
		t.Errorf("StreamMaxLen = %d, want 100000", cfg.StreamMaxLen)
	}
	if !cfg.ContextTimeoutEnabled {
		t.Error("ContextTimeoutEnabled should default true")
	}

	mr := startMiniredis(t)
	cfg.Addr = mr.Addr()
	c, err := redisclient.NewClient(cfg)
	if err != nil {
		t.Fatalf("new client with DefaultConfig overrides: %v", err)
	}
	_ = c.Close(context.Background())
}

func TestContextCancelReturnsWrappedError(t *testing.T) {
	mr := startMiniredis(t)
	c := newTestClient(t, mr)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := c.SetCheckpoint(ctx, "checkpoint:correlator:stream_seq", "v")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.HasPrefix(err.Error(), "redis:") {
		t.Errorf("err %q missing redis: prefix", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err %q does not wrap context.Canceled", err)
	}
}

// TestClosedClientReturnsSentinel verifies that a live client, once
// Close() completes, returns ErrClientClosed on subsequent method calls
// rather than the driver's redis.ErrClosed wrapped. AC5/AC7.
func TestClosedClientReturnsSentinel(t *testing.T) {
	mr := startMiniredis(t)
	cfg := redisclient.DefaultConfig()
	cfg.Addr = mr.Addr()
	c, err := redisclient.NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if err := c.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}

	ctx := context.Background()
	checks := []struct {
		name string
		run  func() error
	}{
		{"set-checkpoint", func() error { return c.SetCheckpoint(ctx, "checkpoint:correlator:stream_seq", "v") }},
		{"get-state", func() error { _, err := c.GetState(ctx, "state:default:nginx"); return err }},
		{"append", func() error { _, err := c.Append(ctx, "evidence:incident:x", map[string]any{"k": "v"}); return err }},
		{"len", func() error { _, err := c.Len(ctx, "evidence:incident:x"); return err }},
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(); !errors.Is(err, redisclient.ErrClientClosed) {
				t.Errorf("got %v, want ErrClientClosed", err)
			}
		})
	}
	if raw := c.Raw(); raw != nil {
		t.Errorf("Raw on closed client = %v, want nil", raw)
	}
}

// TestConcurrentClose exercises the sync.Once / mutex guarantee — N
// goroutines each calling Close must all return nil without racing and
// without closing the underlying pool more than once.
func TestConcurrentClose(t *testing.T) {
	mr := startMiniredis(t)
	cfg := redisclient.DefaultConfig()
	cfg.Addr = mr.Addr()
	c, err := redisclient.NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			if err := c.Close(context.Background()); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent close: %v", err)
	}
}
