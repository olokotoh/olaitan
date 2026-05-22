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

// TestWatch_ReloadsOnDataSymlinkSwap exercises the Kubernetes
// projected-volume rotation pattern explicitly: K8s renders the
// ConfigMap data into a timestamped subdirectory and atomically
// flips the `..data` symlink between revisions. fsnotify on the
// parent dir sees a RENAME event when the symlink target changes;
// the loader's eventAffectsCorpus accepts events whose base name is
// "..data" and triggers a reload. Closes the AC5(i) symlink-swap
// gap that the previous TestWatch_ReloadsOnConfigMapDataSwap only
// approximated via a plain file CREATE (code-review P13 / AC5(i) /
// Task 4.5).
func TestWatch_ReloadsOnDataSymlinkSwap(t *testing.T) {
	root := t.TempDir()

	// Lay out a K8s-style projected-volume directory:
	//   root/
	//     ..2026_05_21_00_00_00_000000001/   ← rev A (target)
	//       olt-impact-005.yaml
	//     ..data -> ..2026_05_21_00_00_00_000000001
	//     olt-impact-005.yaml -> ..data/olt-impact-005.yaml
	revA := filepath.Join(root, "..2026_05_21_00_00_00_000000001")
	if err := os.Mkdir(revA, 0o755); err != nil {
		t.Fatalf("mkdir revA: %v", err)
	}
	writeRule(t, revA, "olt-impact-005.yaml", ruleOLT005)
	if err := os.Symlink(revA, filepath.Join(root, "..data")); err != nil {
		t.Skipf("symlinks unsupported on this filesystem: %v", err)
	}
	if err := os.Symlink(filepath.Join("..data", "olt-impact-005.yaml"),
		filepath.Join(root, "olt-impact-005.yaml")); err != nil {
		t.Fatalf("symlink olt-impact-005: %v", err)
	}

	l := New(root, nil)
	if err := l.Load(); err != nil {
		t.Fatalf("initial Load: %v", err)
	}
	if got := l.Get().Len(); got != 1 {
		t.Fatalf("post-initial-Load Len = %d, want 1", got)
	}

	var reloads atomic.Int64
	l.Subscribe(func(*Corpus) { reloads.Add(1) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcherErr := make(chan error, 1)
	go func() { watcherErr <- l.Watch(ctx) }()
	time.Sleep(50 * time.Millisecond)

	// Build rev B (a second rule alongside the first) and flip the
	// ..data symlink to point at it. This is the swap K8s performs
	// when a ConfigMap is mutated.
	revB := filepath.Join(root, "..2026_05_21_00_00_00_000000002")
	if err := os.Mkdir(revB, 0o755); err != nil {
		t.Fatalf("mkdir revB: %v", err)
	}
	writeRule(t, revB, "olt-impact-005.yaml", ruleOLT005)
	writeRule(t, revB, "olt-priv-001.yaml", ruleOLT006)

	// Add the top-level symlink for the new key in revB. K8s creates
	// one top-level symlink per ConfigMap key, each pointing through
	// the ..data symlink. This must exist before the ..data swap so
	// the reload sees both files.
	if err := os.Symlink(filepath.Join("..data", "olt-priv-001.yaml"),
		filepath.Join(root, "olt-priv-001.yaml")); err != nil {
		t.Fatalf("symlink olt-priv-001 (top-level): %v", err)
	}

	// Atomic symlink swap via rename-on-temporary. K8s uses
	// renameat2(... RENAME_EXCHANGE) when available; the fallback
	// pattern is os.Symlink(newTemp) + os.Rename(newTemp, target).
	tmp := filepath.Join(root, "..data_tmp")
	if err := os.Symlink(revB, tmp); err != nil {
		t.Fatalf("symlink ..data_tmp: %v", err)
	}
	if err := os.Rename(tmp, filepath.Join(root, "..data")); err != nil {
		t.Fatalf("rename tmp -> ..data: %v", err)
	}

	deadline := time.After(2 * time.Second)
	for reloads.Load() == 0 {
		select {
		case <-deadline:
			t.Fatalf("watcher did not reload after ..data symlink swap within 2s")
		case <-time.After(10 * time.Millisecond):
		}
	}

	if got := l.Get().Len(); got != 2 {
		t.Errorf("post-swap Len = %d, want 2 (rev B has two rules)", got)
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
