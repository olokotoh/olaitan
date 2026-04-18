package config_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/config"
)

// quietLogger returns a slog.Logger that discards output so test stdout
// stays focused on failure messages.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// writeFileAtomic mirrors the K8s ConfigMap atomic-swap semantic tests
// depend on: write to tmp, os.Rename over target. Identical to the
// harness in config_test.go but exported for clarity of intent here.
func writeFileAtomic(t *testing.T, path, body string) {
	t.Helper()
	writeYAML(t, path, body)
}

func newTempConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "olaitan.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestNewManagerRejectsInvalidFile(t *testing.T) {
	path := newTempConfig(t, "detection:\n  baseline_window: -1s\n")
	if _, err := config.NewManager(path, quietLogger()); err == nil {
		t.Fatal("expected NewManager to reject invalid config")
	}
}

func TestManagerGetReturnsInitial(t *testing.T) {
	path := newTempConfig(t, validYAML)
	m, err := config.NewManager(path, quietLogger())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	cfg := m.Get()
	if cfg == nil || cfg.Analyst.Provider != "api" {
		t.Fatalf("Get returned %+v", cfg)
	}
}

// replaceYAML rewrites the file in two different ways depending on op:
// "overwrite" uses os.WriteFile (bare-host edit), "atomic" uses
// tmp+rename (K8s ConfigMap swap). Both exercise the same code path
// from the watcher's perspective but through different event
// sequences, which is exactly what AC5 demands we cover.
func replaceYAML(t *testing.T, path, body, op string) {
	t.Helper()
	switch op {
	case "overwrite":
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("overwrite: %v", err)
		}
	case "atomic":
		writeFileAtomic(t, path, body)
	default:
		t.Fatalf("unknown op %q", op)
	}
}

func TestWatchHappyPath(t *testing.T) {
	for _, op := range []string{"overwrite", "atomic"} {
		t.Run(op, func(t *testing.T) {
			path := newTempConfig(t, validYAML)
			m, err := config.NewManager(path, quietLogger())
			if err != nil {
				t.Fatalf("NewManager: %v", err)
			}

			fired := make(chan *config.Config, 4)
			m.Subscribe(func(c *config.Config) { fired <- c })

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			watchDone := make(chan error, 1)
			go func() { watchDone <- m.Watch(ctx) }()

			// Give Watch a moment to register the parent-dir watch.
			time.Sleep(50 * time.Millisecond)

			updated := strings.Replace(validYAML, "score_cap: 35", "score_cap: 42", 1)
			replaceYAML(t, path, updated, op)

			select {
			case cfg := <-fired:
				if cfg.Analyst.ScoreCap != 42 {
					t.Errorf("subscriber saw score_cap=%d, want 42", cfg.Analyst.ScoreCap)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("subscriber did not fire within 2s")
			}

			if got := m.Get().Analyst.ScoreCap; got != 42 {
				t.Errorf("Get().ScoreCap = %d, want 42", got)
			}

			cancel()
			if err := <-watchDone; err != nil {
				t.Errorf("Watch returned %v, want nil", err)
			}
		})
	}
}

func TestWatchRejectsInvalidReload(t *testing.T) {
	path := newTempConfig(t, validYAML)
	m, err := config.NewManager(path, quietLogger())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	origCap := m.Get().Analyst.ScoreCap

	var fires atomic.Int32
	m.Subscribe(func(*config.Config) { fires.Add(1) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watchDone := make(chan error, 1)
	go func() { watchDone <- m.Watch(ctx) }()
	time.Sleep(50 * time.Millisecond)

	// score_cap: 150 violates the [0,100] bound — reload must reject.
	bad := strings.Replace(validYAML, "score_cap: 35", "score_cap: 150", 1)
	writeFileAtomic(t, path, bad)

	// Give the debounce + reload attempt time to run and log-reject.
	time.Sleep(300 * time.Millisecond)

	if got := fires.Load(); got != 0 {
		t.Errorf("subscriber fired %d times on rejected reload, want 0", got)
	}
	if got := m.Get().Analyst.ScoreCap; got != origCap {
		t.Errorf("Get().ScoreCap = %d after reject, want retained %d", got, origCap)
	}

	cancel()
	<-watchDone
}

func TestWatchCtxCancelStopsCleanly(t *testing.T) {
	path := newTempConfig(t, validYAML)
	m, err := config.NewManager(path, quietLogger())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Watch(ctx) }()
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Watch returned %v, want nil on ctx cancel", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Watch did not return within 500ms of ctx cancel")
	}
}

func TestWatchDoubleRejected(t *testing.T) {
	path := newTempConfig(t, validYAML)
	m, err := config.NewManager(path, quietLogger())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	first := make(chan error, 1)
	go func() { first <- m.Watch(ctx) }()
	time.Sleep(30 * time.Millisecond)

	if err := m.Watch(ctx); !errors.Is(err, config.ErrWatcherRunning) {
		t.Errorf("second Watch = %v, want ErrWatcherRunning", err)
	}

	cancel()
	<-first
}

func TestSubscriberPanicContained(t *testing.T) {
	path := newTempConfig(t, validYAML)
	m, err := config.NewManager(path, quietLogger())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	var secondFired atomic.Int32
	m.Subscribe(func(*config.Config) { panic("boom") })
	m.Subscribe(func(*config.Config) { secondFired.Add(1) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watchDone := make(chan error, 1)
	go func() { watchDone <- m.Watch(ctx) }()
	time.Sleep(50 * time.Millisecond)

	updated := strings.Replace(validYAML, "score_cap: 35", "score_cap: 42", 1)
	writeFileAtomic(t, path, updated)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && secondFired.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if secondFired.Load() == 0 {
		t.Error("second subscriber never fired — panic escaped or watcher stopped")
	}

	// Watcher must still be live — trigger another reload and assert
	// the good subscriber fires again.
	updated2 := strings.Replace(validYAML, "score_cap: 35", "score_cap: 50", 1)
	writeFileAtomic(t, path, updated2)
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && secondFired.Load() < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	if secondFired.Load() < 2 {
		t.Error("watcher stopped after subscriber panic")
	}

	cancel()
	<-watchDone
}

func TestConcurrentGetDuringReload(t *testing.T) {
	path := newTempConfig(t, validYAML)
	m, err := config.NewManager(path, quietLogger())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watchDone := make(chan error, 1)
	go func() { watchDone <- m.Watch(ctx) }()
	time.Sleep(30 * time.Millisecond)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					cfg := m.Get()
					if cfg == nil {
						t.Error("Get returned nil during reload")
						return
					}
					_ = cfg.Analyst.ScoreCap
				}
			}
		}()
	}

	for i := 0; i < 10; i++ {
		body := strings.Replace(validYAML, "score_cap: 35", "score_cap: "+strconv.Itoa(30+i), 1)
		writeFileAtomic(t, path, body)
		time.Sleep(15 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)

	close(stop)
	wg.Wait()

	final := m.Get().Analyst.ScoreCap
	if final < 30 || final > 39 {
		t.Errorf("final score_cap = %d, want one of [30,39]", final)
	}

	cancel()
	<-watchDone
}

func TestNilReceiverGuards(t *testing.T) {
	var m *config.Manager

	if got := m.Get(); got != nil {
		t.Errorf("nil Manager.Get = %+v, want nil", got)
	}
	m.Subscribe(nil) // must not panic
	m.Subscribe(func(*config.Config) { t.Error("should never fire") })

	if err := m.Watch(context.Background()); err != nil {
		t.Errorf("nil Manager.Watch = %v, want nil", err)
	}
}
