package redis_test

import (
	"context"
	"testing"

	redisclient "github.com/olokotoh/olaitan/internal/redis"
)

// TestDeferredReport_FIFO confirms RPUSH-tail + LPOP-head gives FIFO ordering:
// the oldest enqueued envelope is peeked/committed first (AC2/AC3).
func TestDeferredReport_FIFO(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	cli := newTestClient(t, mr)

	want := []string{"first", "second", "third"}
	for _, v := range want {
		if _, err := cli.EnqueueDeferredReport(ctx, []byte(v), 0); err != nil {
			t.Fatalf("enqueue %q: %v", v, err)
		}
	}
	if n, err := cli.DeferredReportLen(ctx); err != nil || n != 3 {
		t.Fatalf("len = %d, %v; want 3", n, err)
	}
	for _, v := range want {
		got, ok, err := cli.PeekDeferredReport(ctx)
		if err != nil || !ok {
			t.Fatalf("peek %q: ok=%v err=%v", v, ok, err)
		}
		if string(got) != v {
			t.Fatalf("peek = %q, want %q (FIFO order)", got, v)
		}
		if err := cli.CommitDeferredReport(ctx); err != nil {
			t.Fatalf("commit %q: %v", v, err)
		}
	}
	// Queue drained: peek reports empty, len 0.
	if _, ok, err := cli.PeekDeferredReport(ctx); err != nil || ok {
		t.Fatalf("peek after drain: ok=%v err=%v; want empty", ok, err)
	}
	if n, err := cli.DeferredReportLen(ctx); err != nil || n != 0 {
		t.Fatalf("len after drain = %d, %v; want 0", n, err)
	}
}

// TestDeferredReport_BoundedDropOldest confirms the bounded queue drops the
// OLDEST entries once it reaches the cap and reports the drop count (PO
// ratification 7 / BI-6).
func TestDeferredReport_BoundedDropOldest(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	cli := newTestClient(t, mr)

	const cap = 3
	// Enqueue 5 with a cap of 3: the first two ("a","b") are dropped, leaving
	// the freshest three ("c","d","e").
	in := []string{"a", "b", "c", "d", "e"}
	var totalDropped int64
	for _, v := range in {
		dropped, err := cli.EnqueueDeferredReport(ctx, []byte(v), cap)
		if err != nil {
			t.Fatalf("enqueue %q: %v", v, err)
		}
		totalDropped += dropped
	}
	if totalDropped != 2 {
		t.Fatalf("total dropped = %d, want 2", totalDropped)
	}
	if n, err := cli.DeferredReportLen(ctx); err != nil || n != cap {
		t.Fatalf("len = %d, %v; want %d", n, err, cap)
	}
	// The head must now be "c" (oldest survivor), confirming drop-from-head.
	got, ok, err := cli.PeekDeferredReport(ctx)
	if err != nil || !ok {
		t.Fatalf("peek: ok=%v err=%v", ok, err)
	}
	if string(got) != "c" {
		t.Fatalf("head = %q, want %q (oldest survivor after drop-oldest)", got, "c")
	}
}

// TestDeferredReport_EmptyEnvelopeRejected confirms an empty envelope is a
// caller error, not a silent enqueue.
func TestDeferredReport_EmptyEnvelopeRejected(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	cli := newTestClient(t, mr)
	if _, err := cli.EnqueueDeferredReport(ctx, nil, 0); err == nil {
		t.Fatal("empty envelope should be rejected")
	}
}

// TestDeferredReport_CommitEmptyIsNoError confirms committing (LPOP) an empty
// list is not an error (a concurrent drain may have removed the head).
func TestDeferredReport_CommitEmptyIsNoError(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	cli := newTestClient(t, mr)
	if err := cli.CommitDeferredReport(ctx); err != nil {
		t.Fatalf("commit on empty list: %v", err)
	}
}

// TestDeferredReport_ClosedClient confirms a closed client returns
// ErrClientClosed rather than panicking.
func TestDeferredReport_ClosedClient(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	cfg := redisclient.DefaultConfig()
	cfg.Addr = mr.Addr()
	cli, err := redisclient.NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	_ = cli.Close(ctx)
	if _, err := cli.EnqueueDeferredReport(ctx, []byte("x"), 0); err == nil {
		t.Fatal("enqueue on closed client should error")
	}
	if _, _, err := cli.PeekDeferredReport(ctx); err == nil {
		t.Fatal("peek on closed client should error")
	}
	if err := cli.CommitDeferredReport(ctx); err == nil {
		t.Fatal("commit on closed client should error")
	}
	if _, err := cli.DeferredReportLen(ctx); err == nil {
		t.Fatal("len on closed client should error")
	}
}
