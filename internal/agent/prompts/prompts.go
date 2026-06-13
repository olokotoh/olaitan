// Package prompts loads the per-role analyst system prompts from a
// directory (a Kubernetes ConfigMap projected volume, mounted at
// /etc/olaitan/prompts/ by the Helm chart) and exposes the current set
// behind an atomic.Pointer so the investigation chain observes lock-free
// reads. A companion fsnotify-backed watcher reloads the set when
// Kubernetes swaps the ConfigMap-projected ..data symlink, mirroring the
// semantics of internal/decision/rules/loader (parent-dir watch, 50 ms
// debounce, atomic swap, recover-on-panic subscriber fan-out).
//
// Every role has a binary-embedded default (defaults/*.txt) so the
// controller runs with zero mounted files: a file absent from the mount
// falls back to its embedded default, which is why a partial ConfigMap
// is valid. A file that EXISTS but is unreadable or oversized is a
// reload-rejected condition: the previous Set is retained and the pod
// stays Ready (Story 3.13 BI-2).
//
// Canonical content: a prompt's Text and its content Hash are computed
// over the trailing-newline-trimmed file bytes, so an operator-authored
// file (conventionally newline-terminated) hashes identically to the
// embedded default and the composed wire prompt is unchanged by editor
// newline conventions. The Hash is the prompt-version identifier carried
// to AUDIT.assessments (Story 3.14) for reproducibility (NFR41).
package prompts

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
)

//go:embed defaults/*.txt
var defaultFS embed.FS

// debounceWindow coalesces the 3-4 fsnotify events Kubernetes emits
// during a ConfigMap projected-volume swap into one reload pass. The
// 50 ms value matches internal/config/watcher.go and the rules loader.
const debounceWindow = 50 * time.Millisecond

// maxPromptFileBytes caps a single prompt file at 64 KiB. The default
// prompts are well under 1 KiB; the cap defends against an oversized or
// malicious ConfigMap entry that would otherwise let a reload balloon
// controller memory.
const maxPromptFileBytes = 64 << 10

// ErrWatcherRunning is returned when Watch is called on a Store that
// already has a live watcher goroutine.
var ErrWatcherRunning = errors.New("prompts: watcher already running")

// Role names a per-role analyst prompt. The four roles are fixed; the
// file basename under the prompts directory is "<role>.txt".
type Role string

const (
	RoleL1     Role = "l1"
	RoleL2     Role = "l2"
	RoleSenior Role = "senior"
	RoleDFIR   Role = "dfir"
)

// roles is the canonical iteration order (stable for logging and tests).
var roles = []Role{RoleL1, RoleL2, RoleSenior, RoleDFIR}

// Roles returns the fixed set of prompt roles in canonical order.
func Roles() []Role { return append([]Role(nil), roles...) }

// Prompt is one role's loaded prompt: the canonical Text and its content
// Hash. Hash is the lowercase hex sha256 of Text.
type Prompt struct {
	Text string
	Hash string
}

// Set is an immutable snapshot of all four role prompts. Callers must NOT
// mutate a returned *Set; the watcher swaps a fresh *Set atomically.
type Set struct {
	byRole map[Role]Prompt
}

// Prompt returns the prompt for role. An unknown role yields the zero
// Prompt (empty Text and Hash); callers pass only the four typed Role
// constants, so this is a defensive default, not a normal path.
func (s *Set) Prompt(role Role) Prompt {
	if s == nil {
		return Prompt{}
	}
	return s.byRole[role]
}

// Hash returns role's content hash, or "" on a nil Set / unknown role.
func (s *Set) Hash(role Role) string { return s.Prompt(role).Hash }

// Store owns the prompts directory path, the active *Set pointer, the
// subscriber fan-out, and the watcher goroutine state. Reads go through
// Get() (an atomic.Pointer load); the watcher is the only writer.
type Store struct {
	dir string
	cur atomic.Pointer[Set]
	log *slog.Logger

	subsMu sync.Mutex
	subs   []func(*Set)

	running atomic.Bool
}

// New constructs a Store for the given directory. The directory is not
// read until Load is called; pass nil for log to inherit slog.Default().
func New(dir string, log *slog.Logger) *Store {
	if log == nil {
		log = slog.Default()
	}
	return &Store{dir: dir, log: log.With("component", "prompts-store")}
}

// Load reads every "<role>.txt" under s.dir, falling back to the embedded
// default for any role whose file is absent, and atomically swaps the
// active *Set. A file that exists but is unreadable or oversized fails
// the load WITHOUT mutating the active pointer (the caller decides
// whether a startup failure is fatal; a reload retains the prior Set).
func (s *Store) Load() error {
	set, err := s.loadOnce()
	if err != nil {
		return err
	}
	s.cur.Store(set)
	s.log.Info("prompts: loaded", "dir", s.dir,
		"l1", set.Hash(RoleL1), "l2", set.Hash(RoleL2),
		"senior", set.Hash(RoleSenior), "dfir", set.Hash(RoleDFIR))
	return nil
}

// Get returns the active *Set, or nil if Load has never succeeded. Safe
// for concurrent callers on the chain hot path.
func (s *Store) Get() *Set {
	if s == nil {
		return nil
	}
	return s.cur.Load()
}

// Subscribe registers a callback fired after every successful reload
// (NOT on the initial Load — the caller already holds that pointer). The
// callback runs on the debounce-timer goroutine under defer/recover so a
// single panicking subscriber does not silence the rest. Nil receiver or
// nil fn is a no-op.
func (s *Store) Subscribe(fn func(*Set)) {
	if s == nil || fn == nil {
		return
	}
	s.subsMu.Lock()
	s.subs = append(s.subs, fn)
	s.subsMu.Unlock()
}

// Watch blocks until ctx is cancelled, reloading on ConfigMap
// projected-volume swaps. Returns nil on ctx.Done, ErrWatcherRunning if
// a Watch is already live, and a wrapped fsnotify error if the
// inotify/kqueue handle fails to open. On reload failure the previous
// Set is retained and the watcher logs "prompts: reload rejected"; the
// watcher does not exit.
func (s *Store) Watch(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if !s.running.CompareAndSwap(false, true) {
		return ErrWatcherRunning
	}
	defer s.running.Store(false)

	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("prompts: fsnotify: %w", err)
	}
	defer func() { _ = w.Close() }()

	if err := w.Add(s.dir); err != nil {
		return fmt.Errorf("prompts: watch %q: %w", s.dir, err)
	}

	timer := time.AfterFunc(debounceWindow, func() { s.reload() })
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
			if !s.eventAffectsSet(ev) {
				continue
			}
			// K8s ConfigMap volumes recreate the children during a
			// swap; re-add the parent on remove/rename so subsequent
			// swaps still wake us (rules-loader precedent).
			if ev.Op&(fsnotify.Remove|fsnotify.Rename) != 0 {
				_ = w.Remove(s.dir)
				if err := w.Add(s.dir); err != nil {
					s.log.Error("prompts: rewatch", "dir", s.dir, "err", err)
				}
			}
			timer.Reset(debounceWindow)

		case err, ok := <-w.Errors:
			if !ok {
				return nil
			}
			s.log.Error("prompts: fsnotify", "dir", s.dir, "err", err)
		}
	}
}

// eventAffectsSet narrows the parent-dir event stream to the canonical
// ..data symlink swap and the four "<role>.txt" files.
func (s *Store) eventAffectsSet(ev fsnotify.Event) bool {
	base := filepath.Base(ev.Name)
	if base == "..data" {
		return true
	}
	for _, r := range roles {
		if base == string(r)+".txt" {
			return true
		}
	}
	return false
}

func (s *Store) reload() {
	set, err := s.loadOnce()
	if err != nil {
		s.log.Error("prompts: reload rejected", "dir", s.dir, "err", err)
		return
	}
	s.cur.Store(set)
	s.log.Info("prompts: reloaded", "dir", s.dir,
		"l1", set.Hash(RoleL1), "l2", set.Hash(RoleL2),
		"senior", set.Hash(RoleSenior), "dfir", set.Hash(RoleDFIR))

	s.subsMu.Lock()
	snap := make([]func(*Set), len(s.subs))
	copy(snap, s.subs)
	s.subsMu.Unlock()

	for _, fn := range snap {
		s.callSubscriber(fn, set)
	}
}

func (s *Store) callSubscriber(fn func(*Set), set *Set) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("prompts: subscriber panic",
				"dir", s.dir, "panic", r, "stack", string(debug.Stack()))
		}
	}()
	fn(set)
}

// loadOnce assembles a *Set from s.dir without touching the active
// pointer. For each role it reads "<dir>/<role>.txt"; a NotExist error
// falls back to the embedded default; any other read error, or a file
// over the size cap, fails the whole load (reload-rejected semantics).
func (s *Store) loadOnce() (*Set, error) {
	set := &Set{byRole: make(map[Role]Prompt, len(roles))}
	for _, role := range roles {
		text, err := s.readRole(role)
		if err != nil {
			return nil, err
		}
		set.byRole[role] = newPrompt(text)
	}
	return set, nil
}

// readRole returns role's canonical prompt text: the mounted file when
// present, otherwise the embedded default.
func (s *Store) readRole(role Role) (string, error) {
	path := filepath.Join(s.dir, string(role)+".txt")
	info, err := os.Stat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return embeddedDefault(role)
	case err != nil:
		return "", fmt.Errorf("prompts: stat %s: %w", path, err)
	}
	if info.Size() > maxPromptFileBytes {
		return "", fmt.Errorf("prompts: %s exceeds %d-byte cap (got %d)", path, maxPromptFileBytes, info.Size())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("prompts: read %s: %w", path, err)
	}
	return canonical(string(raw)), nil
}

// embeddedDefault returns the binary-embedded default text for role. A
// missing embed is a build-artifact corruption, surfaced as an error.
func embeddedDefault(role Role) (string, error) {
	raw, err := defaultFS.ReadFile("defaults/" + string(role) + ".txt")
	if err != nil {
		return "", fmt.Errorf("prompts: embedded default %s: %w", role, err)
	}
	return canonical(string(raw)), nil
}

// canonical trims trailing newlines so trailing-newline conventions do
// not perturb the content hash or the composed wire prompt.
func canonical(s string) string { return strings.TrimRight(s, "\n") }

// newPrompt computes the content hash of canonical text.
func newPrompt(text string) Prompt {
	sum := sha256.Sum256([]byte(text))
	return Prompt{Text: text, Hash: hex.EncodeToString(sum[:])}
}
