//go:build integration

package loader

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestWatch_ReloadsOnConfigMapDataSwap(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "olt-impact-005.yaml", ruleOLT005)

	l := New(dir, nil)
	if err := l.Load(); err != nil {
		t.Fatalf("initial Load: %v", err)
	}

	var reloads atomic.Int64
	gotCorpus := make(chan *Corpus, 4)
	l.Subscribe(func(c *Corpus) {
		reloads.Add(1)
		select {
		case gotCorpus <- c:
		default:
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcherErr := make(chan error, 1)
	go func() { watcherErr <- l.Watch(ctx) }()
	// Settle so the AddFunc plumbing is live before we mutate the dir.
	time.Sleep(50 * time.Millisecond)

	// Add a second rule (simulates the operator running
	// `helm upgrade --set rules.*` which appends a key to the
	// projected ConfigMap data).
	writeRule(t, dir, "olt-priv-001.yaml", ruleOLT006)

	deadline := time.After(2 * time.Second)
	for {
		if reloads.Load() >= 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("watcher did not reload within 2s")
		case <-time.After(10 * time.Millisecond):
		}
	}

	c := <-gotCorpus
	if c.Len() != 2 {
		t.Errorf("post-reload Len = %d, want 2", c.Len())
	}

	cancel()
	if err := <-watcherErr; err != nil {
		t.Errorf("Watch returned %v on ctx cancel; want nil", err)
	}
}

func TestWatch_RejectsBadReloadAndRetainsPrev(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "olt-impact-005.yaml", ruleOLT005)
	l := New(dir, nil)
	if err := l.Load(); err != nil {
		t.Fatalf("initial Load: %v", err)
	}
	prev := l.Get()

	var reloads atomic.Int64
	l.Subscribe(func(c *Corpus) { reloads.Add(1) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcherErr := make(chan error, 1)
	go func() { watcherErr <- l.Watch(ctx) }()
	time.Sleep(50 * time.Millisecond)

	// Drop a broken rule in. The reload should be rejected and
	// the previous corpus should stay active.
	if err := os.WriteFile(filepath.Join(dir, "broken.yaml"), []byte(ruleBadAttack), 0o600); err != nil {
		t.Fatalf("write broken.yaml: %v", err)
	}

	time.Sleep(300 * time.Millisecond)

	if reloads.Load() != 0 {
		t.Errorf("subscriber fired %d times on failed reload; want 0", reloads.Load())
	}
	if l.Get() != prev {
		t.Errorf("active corpus changed; want previous pointer retained on reload failure")
	}

	cancel()
	if err := <-watcherErr; err != nil {
		t.Errorf("Watch err = %v, want nil", err)
	}
}

func TestWatch_DoubleStartReturnsRunningError(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "olt-impact-005.yaml", ruleOLT005)
	l := New(dir, nil)
	if err := l.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = l.Watch(ctx) }()
	time.Sleep(50 * time.Millisecond)

	err := l.Watch(context.Background())
	if err != ErrWatcherRunning {
		t.Errorf("second Watch = %v, want %v", err, ErrWatcherRunning)
	}
}
