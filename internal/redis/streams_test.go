package redis_test

import (
	"context"
	"strings"
	"testing"
	"time"

	redisclient "github.com/olokotoh/olaitan/internal/redis"
)

func TestStreamsAppendReadRange(t *testing.T) {
	mr := startMiniredis(t)
	c := newTestClient(t, mr)
	ctx := context.Background()
	stream := "evidence:incident:INC-1"

	ids := make([]string, 0, 3)
	for i := 0; i < 3; i++ {
		id, err := c.Append(ctx, stream, map[string]any{"seq": i})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		ids = append(ids, id)
	}

	entries, err := c.Range(ctx, stream, "-", "+")
	if err != nil {
		t.Fatalf("range: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("range returned %d entries, want 3", len(entries))
	}
	for i, e := range entries {
		if e.ID != ids[i] {
			t.Errorf("entry %d ID = %q, want %q", i, e.ID, ids[i])
		}
	}

	n, err := c.Len(ctx, stream)
	if err != nil {
		t.Fatalf("len: %v", err)
	}
	if n != 3 {
		t.Errorf("len = %d, want 3", n)
	}

	// Read-from-start: use "0" as lastID to replay all entries.
	read, err := c.Read(ctx, stream, "0", 10, 0)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(read) != 3 {
		t.Errorf("read returned %d, want 3", len(read))
	}
}

func TestStreamsMaxLenApprox(t *testing.T) {
	mr := startMiniredis(t)

	cfg := redisclient.DefaultConfig()
	cfg.Addr = mr.Addr()
	cfg.StreamMaxLen = 100

	c, err := redisclient.NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })

	ctx := context.Background()
	stream := "evidence:transitions:default:nginx"

	for i := 0; i < 1000; i++ {
		if _, err := c.Append(ctx, stream, map[string]any{"i": i}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	n, err := c.Len(ctx, stream)
	if err != nil {
		t.Fatalf("len: %v", err)
	}
	// Approx trim: miniredis honours MAXLEN but is allowed to keep a few
	// more entries than the cap (real Redis uses radix-tree block
	// boundaries). Accept anything within the documented slack.
	if n < 100 || n > 200 {
		t.Errorf("len = %d, want within [100, 200] (MAXLEN~ 100)", n)
	}
}

func TestStreamsRejectNonEvidencePrefix(t *testing.T) {
	mr := startMiniredis(t)
	c := newTestClient(t, mr)
	ctx := context.Background()

	cases := []struct {
		name   string
		stream string
	}{
		{"state-prefix", "state:default:nginx"},
		{"health-prefix", "health:ring-1"},
		{"baseline-prefix", "baseline:default:nginx:metrics"},
		{"no-prefix", "raw-stream"},
		{"empty", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.Append(ctx, tc.stream, map[string]any{"k": "v"})
			if err == nil {
				t.Fatal("expected rejection, got nil")
			}
			if !strings.HasPrefix(err.Error(), "redis:") {
				t.Errorf("err %q missing redis: prefix", err)
			}
		})
	}
}

func TestStreamsReadNoBlock(t *testing.T) {
	mr := startMiniredis(t)
	c := newTestClient(t, mr)
	ctx := context.Background()

	// Empty stream, non-blocking read returns nil without error.
	entries, err := c.Read(ctx, "evidence:incident:empty", "0", 10, 0)
	if err != nil {
		t.Fatalf("read empty: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("read returned %d entries, want 0", len(entries))
	}

	// After an append, read-from-start picks it up.
	if _, err := c.Append(ctx, "evidence:incident:read", map[string]any{"k": "v"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	entries, err = c.Read(ctx, "evidence:incident:read", "0", 10, 0)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("read returned %d entries, want 1", len(entries))
	}
	if entries[0].Fields["k"] != "v" {
		t.Errorf("field k = %q, want %q", entries[0].Fields["k"], "v")
	}
}

func TestStreamsReadBlockTimeoutReturnsNil(t *testing.T) {
	mr := startMiniredis(t)
	c := newTestClient(t, mr)
	ctx := context.Background()

	start := time.Now()
	entries, err := c.Read(ctx, "evidence:incident:blocking", "$", 1, 50*time.Millisecond)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("read block: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("read returned %d entries, want 0 on timeout", len(entries))
	}
	if elapsed < 40*time.Millisecond {
		t.Errorf("block returned after %v; expected ≥ ~50ms", elapsed)
	}
}
