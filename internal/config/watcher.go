package config

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
)

// debounceWindow coalesces the 3-4 fsnotify events a Kubernetes
// ConfigMap projected-volume swap emits within ~1 ms (CREATE of
// ..data.tmp, RENAME to ..data, REMOVE of the prior timestamped
// directory, occasional CHMOD). 50 ms is wide enough to merge those
// bursts on macOS's coarser FSEvents clock, narrow enough that an
// operator running `kubectl edit configmap` does not perceive a lag.
// Reset-on-event / fire-on-quiet is the correct semantic — "wait N ms
// between reloads" would drop a change arriving mid-cooldown.
const debounceWindow = 50 * time.Millisecond

// Manager owns the current *Config, the fsnotify watch goroutine, and
// the subscriber fan-out. Reads are lock-free via atomic.Pointer; the
// reload path is the only writer. Callers hand the *Manager (not the
// snapshot pointer) to long-lived rings that need reload callbacks.
type Manager struct {
	path    string
	cur     atomic.Pointer[Config]
	subsMu  sync.Mutex
	subs    []func(*Config)
	log     *slog.Logger
	running atomic.Bool
}

// NewManager loads and validates the config at path up front, so a
// broken file fails construction rather than exploding asynchronously
// in Watch. If log is nil, slog.Default() is used.
func NewManager(path string, log *slog.Logger) (*Manager, error) {
	cfg, err := Load(path)
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.Default()
	}
	m := &Manager{path: path, log: log}
	m.cur.Store(cfg)
	log.Info("config: loaded", "path", path)
	return m, nil
}

// Get returns the current *Config atomically. Safe for concurrent
// callers on the ring hot path. Returns nil on a nil receiver so call
// sites can be defensive without panicking during teardown.
func (m *Manager) Get() *Config {
	if m == nil {
		return nil
	}
	return m.cur.Load()
}

// Subscribe registers a callback fired after every successful reload
// (NOT on the initial load — the caller already has that pointer from
// NewManager). Callbacks run synchronously on the watcher goroutine;
// they must not block. A panic is recovered, logged, and does not
// stop the watcher or other subscribers.
//
// Nil receiver or nil fn is a silent no-op so ring constructors can
// call Subscribe unconditionally without guarding.
func (m *Manager) Subscribe(fn func(*Config)) {
	if m == nil || fn == nil {
		return
	}
	m.subsMu.Lock()
	m.subs = append(m.subs, fn)
	m.subsMu.Unlock()
}

// Watch blocks on ctx, re-parsing + re-validating the file on change
// and fanning out to subscribers. Returns nil when ctx is cancelled
// (cancellation is the expected termination signal, not an error);
// returns ErrWatcherRunning if a Watch is already live, and a wrapped
// fsnotify error if the inotify/kqueue handle fails to open.
//
// On parse/validate failure the previous *Config is retained — readers
// continue to see the last-known-good value, and the watcher logs
// "config: reload rejected" with the underlying error.
func (m *Manager) Watch(ctx context.Context) error {
	if m == nil {
		return nil
	}
	if !m.running.CompareAndSwap(false, true) {
		return ErrWatcherRunning
	}
	defer m.running.Store(false)

	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("config: fsnotify: %w", err)
	}
	defer func() { _ = w.Close() }()

	// Watch the parent directory, not the file itself. Kubernetes
	// ConfigMap volumes swap a ..data symlink atomically; a watch on
	// the file inode vanishes with the old inode. Parent-dir watching
	// catches the symlink rename on every supported platform.
	dir := filepath.Dir(m.path)
	if err := w.Add(dir); err != nil {
		return fmt.Errorf("config: watch %q: %w", dir, err)
	}

	// time.AfterFunc sidesteps the classic Timer.Reset race (Stop →
	// drain C → Reset); repeated Reset within the debounce window just
	// postpones the single scheduled callback.
	timer := time.AfterFunc(debounceWindow, func() { m.reload() })
	timer.Stop()
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil

		case ev, ok := <-w.Events:
			if !ok {
				return nil
			}
			if !m.eventAffectsTarget(ev) {
				continue
			}
			// K8s ConfigMap projected volumes drop and recreate the
			// parent dir's children during a swap; the file-level
			// watch gets torn down on some platforms. Re-adding the
			// parent dir is cheap and idempotent on fsnotify.
			if ev.Op&(fsnotify.Remove|fsnotify.Rename) != 0 {
				_ = w.Remove(dir)
				if err := w.Add(dir); err != nil {
					m.log.Error("config: rewatch", "dir", dir, "err", err)
				}
			}
			timer.Reset(debounceWindow)

		case err, ok := <-w.Errors:
			if !ok {
				return nil
			}
			m.log.Error("config: fsnotify", "path", m.path, "err", err)
		}
	}
}

// eventAffectsTarget narrows the parent-dir event stream to events
// that actually touch our config file. The ..data symlink rename is
// the K8s ConfigMap swap signal; the direct path match covers
// bare-host edits and os.Rename tests.
func (m *Manager) eventAffectsTarget(ev fsnotify.Event) bool {
	target := filepath.Clean(m.path)
	evName := filepath.Clean(ev.Name)
	if evName == target {
		return true
	}
	// K8s swaps the `..data` symlink inside the mount dir; dereffing
	// the target after a ..data rename yields a different inode but
	// the same logical file path. Trigger a reload on any ..data
	// event so the subsequent Load sees the fresh contents.
	if filepath.Base(evName) == "..data" && filepath.Dir(evName) == filepath.Dir(target) {
		return true
	}
	return false
}

// reload re-parses and re-validates the file. On success it atomically
// swaps the pointer and fans out to subscribers under a defer/recover
// that contains per-subscriber panics. On failure the previous *Config
// is retained and the caller's next Get() returns the old pointer.
func (m *Manager) reload() {
	cfg, err := Load(m.path)
	if err != nil {
		m.log.Error("config: reload rejected", "path", m.path, "err", err)
		return
	}

	m.cur.Store(cfg)
	m.log.Info("config: reloaded", "path", m.path)

	// Snapshot subscribers under the mutex, then release it before
	// calling out. Callbacks must not re-enter Subscribe; if they do
	// under the mutex we'd deadlock.
	m.subsMu.Lock()
	snap := make([]func(*Config), len(m.subs))
	copy(snap, m.subs)
	m.subsMu.Unlock()

	for _, fn := range snap {
		m.callSubscriber(fn, cfg)
	}
}

func (m *Manager) callSubscriber(fn func(*Config), cfg *Config) {
	defer func() {
		if r := recover(); r != nil {
			m.log.Error("config: subscriber panic",
				"path", m.path, "panic", r, "stack", string(debug.Stack()))
		}
	}()
	fn(cfg)
}
