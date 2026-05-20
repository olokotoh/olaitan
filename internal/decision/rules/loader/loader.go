// Package loader walks an OLT rule directory, parses every YAML
// file via the parser package, and exposes the resulting corpus
// behind an atomic.Pointer so the engine's hot path observes
// lock-free reads. A companion fsnotify-backed Watcher reloads the
// corpus when Kubernetes swaps the ConfigMap-projected ..data
// symlink, mirroring the semantics of internal/config/watcher.go
// (parent-dir watch, 50 ms debounce, atomic swap, recover-on-panic
// subscriber fan-out).
//
// Reload-rejected semantics: a parse or validation failure on
// reload logs "rules: reload rejected" with the offending file path
// and underlying error, then returns without touching the active
// corpus pointer. Readers continue to see the previous good corpus
// and the engine pod stays Ready. The pod-side ATT&CK gate (AC4)
// fires only on the initial Load() call invoked at startup.
package loader

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/olokotoh/olaitan/internal/decision/rules/parser"
)

// debounceWindow coalesces the 3-4 fsnotify events Kubernetes emits
// during a ConfigMap projected-volume swap into one reload pass. The
// 50 ms value matches internal/config/watcher.go; see its commentary
// for why the value sits where it does.
const debounceWindow = 50 * time.Millisecond

// ErrWatcherRunning is returned when Watch is called on a Loader
// that already has a live watcher goroutine.
var ErrWatcherRunning = errors.New("loader: watcher already running")

// Corpus is an immutable snapshot of the rule set. The struct value
// is intentionally small (two slices and a map) so atomic.Pointer
// swaps are cheap; callers must NOT mutate a returned *Corpus.
type Corpus struct {
	// Rules is the ordered slice of parsed rules. Order matches a
	// stable lexicographic sort over SourcePath so two loads of the
	// same directory produce byte-identical corpora.
	Rules []*parser.Rule
	// ByID indexes Rules by Rule.ID. The loader rejects duplicate
	// IDs at Load time so this index is total: every ID present in
	// Rules appears in ByID.
	ByID map[string]*parser.Rule
}

// Len returns the rule count. Safe on nil receivers.
func (c *Corpus) Len() int {
	if c == nil {
		return 0
	}
	return len(c.Rules)
}

// Loader owns the rule directory path, the active *Corpus pointer,
// the subscriber fan-out, and the watcher goroutine state. Reads on
// the hot path go through Get() which performs an atomic.Pointer
// load; Watch is the only writer.
type Loader struct {
	dir string
	cur atomic.Pointer[Corpus]
	log *slog.Logger

	subsMu sync.Mutex
	subs   []func(*Corpus)

	running atomic.Bool
}

// New constructs a Loader for the given directory. The directory is
// not read until Load is called; pass nil for log to inherit
// slog.Default().
func New(dir string, log *slog.Logger) *Loader {
	if log == nil {
		log = slog.Default()
	}
	return &Loader{dir: dir, log: log.With("component", "rules-loader")}
}

// Load reads every *.yaml / *.yml file under l.dir, parses each via
// parser.ParseRule, builds a *Corpus, and atomically swaps the
// active pointer. On failure the previous *Corpus is retained and
// the error is returned without mutating the pointer.
//
// Load is the ATT&CK / rule-ID gate (AC4): any rule whose attack:
// list is empty, missing, or contains an invalid token, or whose ID
// does not match the OLT rule-ID grammar, causes Load to return a
// single-line error identifying the file path and the offending
// token. The error propagates to startAggregatorRing's errgroup at
// startup; an unstartable corpus crashes the pod and surfaces in
// the readiness probe.
func (l *Loader) Load() error {
	corpus, err := l.loadOnce()
	if err != nil {
		return err
	}
	l.cur.Store(corpus)
	l.log.Info("rules: loaded", "dir", l.dir, "count", corpus.Len())
	return nil
}

// Get returns the active *Corpus, or nil if Load has never
// succeeded. Safe for concurrent callers; the engine's hot path
// goes through this getter.
func (l *Loader) Get() *Corpus {
	if l == nil {
		return nil
	}
	return l.cur.Load()
}

// Subscribe registers a callback fired after every successful
// reload. The callback runs synchronously on the watcher goroutine
// under defer/recover so a single panicking subscriber does not
// silence the rest. NewManager-style "fired on initial load too"
// is intentionally not provided: callers already hold the pointer
// returned by Load.
func (l *Loader) Subscribe(fn func(*Corpus)) {
	if l == nil || fn == nil {
		return
	}
	l.subsMu.Lock()
	l.subs = append(l.subs, fn)
	l.subsMu.Unlock()
}

// Watch blocks until ctx is cancelled, reloading the corpus on
// ConfigMap projected-volume swaps. Returns nil on ctx.Done,
// ErrWatcherRunning if a Watch is already live, and a wrapped
// fsnotify error if the inotify/kqueue handle fails to open.
//
// On reload failure the previous corpus is retained and the
// watcher logs "rules: reload rejected"; the watcher does not exit.
func (l *Loader) Watch(ctx context.Context) error {
	if l == nil {
		return nil
	}
	if !l.running.CompareAndSwap(false, true) {
		return ErrWatcherRunning
	}
	defer l.running.Store(false)

	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("rules: fsnotify: %w", err)
	}
	defer func() { _ = w.Close() }()

	if err := w.Add(l.dir); err != nil {
		return fmt.Errorf("rules: watch %q: %w", l.dir, err)
	}

	timer := time.AfterFunc(debounceWindow, func() { l.reload() })
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
			if !l.eventAffectsCorpus(ev) {
				continue
			}
			// K8s ConfigMap volumes recreate the children during
			// a swap; fsnotify's per-file watch vanishes with the
			// old inode on some platforms. Re-add the parent on
			// remove/rename so subsequent swaps still wake us.
			if ev.Op&(fsnotify.Remove|fsnotify.Rename) != 0 {
				_ = w.Remove(l.dir)
				if err := w.Add(l.dir); err != nil {
					l.log.Error("rules: rewatch", "dir", l.dir, "err", err)
				}
			}
			timer.Reset(debounceWindow)

		case err, ok := <-w.Errors:
			if !ok {
				return nil
			}
			l.log.Error("rules: fsnotify", "dir", l.dir, "err", err)
		}
	}
}

// eventAffectsCorpus narrows the parent-dir event stream to events
// that should trigger a reload. We accept any YAML file event and
// the canonical ..data symlink rename that K8s emits.
func (l *Loader) eventAffectsCorpus(ev fsnotify.Event) bool {
	base := filepath.Base(ev.Name)
	if base == "..data" {
		return true
	}
	ext := filepath.Ext(base)
	return ext == ".yaml" || ext == ".yml"
}

func (l *Loader) reload() {
	corpus, err := l.loadOnce()
	if err != nil {
		l.log.Error("rules: reload rejected", "dir", l.dir, "err", err)
		return
	}
	l.cur.Store(corpus)
	l.log.Info("rules: reloaded", "dir", l.dir, "count", corpus.Len())

	l.subsMu.Lock()
	snap := make([]func(*Corpus), len(l.subs))
	copy(snap, l.subs)
	l.subsMu.Unlock()

	for _, fn := range snap {
		l.callSubscriber(fn, corpus)
	}
}

func (l *Loader) callSubscriber(fn func(*Corpus), corpus *Corpus) {
	defer func() {
		if r := recover(); r != nil {
			l.log.Error("rules: subscriber panic",
				"dir", l.dir, "panic", r, "stack", string(debug.Stack()))
		}
	}()
	fn(corpus)
}

// loadOnce walks l.dir, parses every YAML, and assembles a *Corpus
// without touching the active pointer. Used by both the eager Load
// and the watcher's reload path. Duplicate IDs are rejected with a
// single-line error citing both source paths so an operator can
// reconcile the conflict.
func (l *Loader) loadOnce() (*Corpus, error) {
	type entry struct {
		path string
		rule *parser.Rule
	}
	var entries []entry

	err := filepath.WalkDir(l.dir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		bytes, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("rules: read %s: %w", path, err)
		}
		rule, err := parser.ParseRule(bytes)
		if err != nil {
			return fmt.Errorf("rules: parse %s: %w", path, err)
		}
		rule.SourcePath = path
		entries = append(entries, entry{path: path, rule: rule})
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].path < entries[j].path
	})

	corpus := &Corpus{
		Rules: make([]*parser.Rule, 0, len(entries)),
		ByID:  make(map[string]*parser.Rule, len(entries)),
	}
	for _, e := range entries {
		if prev, dup := corpus.ByID[e.rule.ID]; dup {
			return nil, fmt.Errorf("rules: duplicate id %q in %s and %s", e.rule.ID, prev.SourcePath, e.path)
		}
		corpus.ByID[e.rule.ID] = e.rule
		corpus.Rules = append(corpus.Rules, e.rule)
	}
	return corpus, nil
}
