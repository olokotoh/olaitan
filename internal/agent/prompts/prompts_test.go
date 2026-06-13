package prompts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// writePrompt writes "<role>.txt" with body (newline-terminated, the
// conventional operator form) into dir.
func writePrompt(t *testing.T, dir string, role Role, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, string(role)+".txt"), []byte(body+"\n"), 0o644); err != nil {
		t.Fatalf("write %s: %v", role, err)
	}
}

func hashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// TestLoadAllFromDir loads four operator-authored files and checks the
// canonical (newline-trimmed) text and its content hash for each role.
func TestLoadAllFromDir(t *testing.T) {
	dir := t.TempDir()
	want := map[Role]string{
		RoleL1:     "L1 system prompt",
		RoleL2:     "L2 system prompt",
		RoleSenior: "Senior system prompt",
		RoleDFIR:   "DFIR system prompt",
	}
	for r, body := range want {
		writePrompt(t, dir, r, body)
	}
	s := New(dir, nil)
	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	set := s.Get()
	for r, body := range want {
		p := set.Prompt(r)
		if p.Text != body {
			t.Errorf("%s text = %q, want %q (trailing newline must be trimmed)", r, p.Text, body)
		}
		if p.Hash != hashOf(body) {
			t.Errorf("%s hash = %q, want %q", r, p.Hash, hashOf(body))
		}
	}
}

// TestMissingFileFallsBackToEmbeddedDefault proves a role absent from the
// mount uses its binary-embedded default (a partial ConfigMap is valid),
// and the loaded default reproduces the Story 3.8 prompt text.
func TestMissingFileFallsBackToEmbeddedDefault(t *testing.T) {
	dir := t.TempDir()
	writePrompt(t, dir, RoleL1, "custom L1")
	// l2/senior/dfir intentionally absent.

	s := New(dir, nil)
	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	set := s.Get()
	if got := set.Prompt(RoleL1).Text; got != "custom L1" {
		t.Errorf("l1 = %q, want custom L1", got)
	}
	// The embedded default must be the byte-identical Story 3.8 L1 prompt.
	const wantL2 = "You are the L2 verification analyst. Verify or refute the L1 hypothesis against the evidence."
	if got := set.Prompt(RoleL2).Text; got != wantL2 {
		t.Errorf("l2 default = %q, want %q", got, wantL2)
	}
	if set.Prompt(RoleSenior).Text == "" || set.Prompt(RoleDFIR).Text == "" {
		t.Error("senior/dfir defaults must be non-empty")
	}
}

// TestEmptyDirUsesAllDefaults proves the zero-mount case (a missing or
// empty directory) loads every embedded default without error.
func TestEmptyDirUsesAllDefaults(t *testing.T) {
	s := New(t.TempDir(), nil)
	if err := s.Load(); err != nil {
		t.Fatalf("Load empty dir: %v", err)
	}
	set := s.Get()
	for _, r := range Roles() {
		if set.Prompt(r).Text == "" || set.Prompt(r).Hash == "" {
			t.Errorf("role %s: empty default text/hash", r)
		}
	}
}

// TestHashStableAcrossLoads proves two loads of the same content yield the
// same hash (reproducibility, NFR41) and that a trailing-newline change
// does NOT move the hash (canonical form).
func TestHashStableAcrossLoads(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "l1.txt"), []byte("same body"), 0o644); err != nil {
		t.Fatal(err)
	}
	s1 := New(dir, nil)
	if err := s1.Load(); err != nil {
		t.Fatal(err)
	}
	h1 := s1.Get().Hash(RoleL1)

	// Rewrite the same body WITH a trailing newline; hash must not move.
	if err := os.WriteFile(filepath.Join(dir, "l1.txt"), []byte("same body\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s2 := New(dir, nil)
	if err := s2.Load(); err != nil {
		t.Fatal(err)
	}
	if h2 := s2.Get().Hash(RoleL1); h1 != h2 {
		t.Errorf("hash moved on trailing-newline-only change: %q vs %q", h1, h2)
	}
}

// TestOversizeFileRejected proves a file over the cap fails Load and (on a
// store that already loaded once) retains the prior set.
func TestOversizeFileRejected(t *testing.T) {
	dir := t.TempDir()
	writePrompt(t, dir, RoleL1, "ok")
	s := New(dir, nil)
	if err := s.Load(); err != nil {
		t.Fatalf("initial Load: %v", err)
	}
	prior := s.Get().Hash(RoleL1)

	big := strings.Repeat("x", maxPromptFileBytes+1)
	if err := os.WriteFile(filepath.Join(dir, "l1.txt"), []byte(big), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Load(); err == nil {
		t.Fatal("oversize file must fail Load")
	}
	if s.Get().Hash(RoleL1) != prior {
		t.Error("rejected Load must retain prior set")
	}
}

// TestPresentEmptyFileRejected proves a present-but-empty (or whitespace-
// only) prompt file fails the load and retains the prior set, rather than
// silently serving an empty system prompt (round-1 edge-case HIGH).
func TestPresentEmptyFileRejected(t *testing.T) {
	for _, body := range []string{"", "\n", "   \n\t"} {
		dir := t.TempDir()
		writePrompt(t, dir, RoleL1, "good")
		s := New(dir, nil)
		if err := s.Load(); err != nil {
			t.Fatalf("initial Load: %v", err)
		}
		prior := s.Get().Hash(RoleL1)

		if err := os.WriteFile(filepath.Join(dir, "l1.txt"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := s.Load(); err == nil {
			t.Errorf("empty/whitespace prompt (%q) must fail Load", body)
		}
		if s.Get().Hash(RoleL1) != prior {
			t.Errorf("rejected Load must retain prior set (body %q)", body)
		}
	}
}

// TestFileAtExactlyCapAccepted pins the size-cap boundary: a file at exactly
// maxPromptFileBytes loads (the comparison is `>`, not `>=`).
func TestFileAtExactlyCapAccepted(t *testing.T) {
	dir := t.TempDir()
	body := strings.Repeat("x", maxPromptFileBytes)
	if err := os.WriteFile(filepath.Join(dir, "l1.txt"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, r := range []Role{RoleL2, RoleSenior, RoleDFIR} {
		writePrompt(t, dir, r, string(r))
	}
	s := New(dir, nil)
	if err := s.Load(); err != nil {
		t.Fatalf("file at exactly the cap must load: %v", err)
	}
	if got := len(s.Get().Prompt(RoleL1).Text); got != maxPromptFileBytes {
		t.Errorf("loaded length = %d, want %d", got, maxPromptFileBytes)
	}
}

// TestWatchToleratesMissingDir proves a watcher on a nonexistent prompts
// directory (the analyst.prompts.enabled=false case) does NOT error — it
// disables hot-reload and returns nil on ctx cancel, so it never tears down
// the aggregator errgroup (round-1 edge-case HIGH).
func TestWatchToleratesMissingDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	s := New(missing, nil)
	if err := s.Load(); err != nil {
		t.Fatalf("Load on missing dir must succeed on embedded defaults: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Watch(ctx) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Watch on missing dir returned %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Watch on missing dir did not return after ctx cancel")
	}
}

// TestReloadSwapsSet drives the watcher: an in-place file edit triggers a
// reload that the Subscribe callback observes with the new hash.
func TestReloadSwapsSet(t *testing.T) {
	dir := t.TempDir()
	writePrompt(t, dir, RoleL1, "v1")
	for _, r := range []Role{RoleL2, RoleSenior, RoleDFIR} {
		writePrompt(t, dir, r, string(r)+" body")
	}
	s := New(dir, nil)
	if err := s.Load(); err != nil {
		t.Fatal(err)
	}

	got := make(chan string, 4)
	s.Subscribe(func(set *Set) { got <- set.Hash(RoleL1) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Watch(ctx) }()

	// Give the watcher a moment to add the dir watch, then edit.
	time.Sleep(50 * time.Millisecond)
	writePrompt(t, dir, RoleL1, "v2")

	select {
	case h := <-got:
		if h != hashOf("v2") {
			t.Errorf("reload hash = %q, want %q", h, hashOf("v2"))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reload callback not fired within 3s")
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("Watch returned %v", err)
	}
}

// TestWatchRejectsSecondWatcher proves the running-guard.
func TestWatchRejectsSecondWatcher(t *testing.T) {
	s := New(t.TempDir(), nil)
	if err := s.Load(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	go func() { close(started); _ = s.Watch(ctx) }()
	<-started
	time.Sleep(50 * time.Millisecond)
	if err := s.Watch(ctx); err != ErrWatcherRunning {
		t.Errorf("second Watch = %v, want ErrWatcherRunning", err)
	}
}

// TestConcurrentGetDuringReload exercises lock-free reads against a
// reload under the race detector.
func TestConcurrentGetDuringReload(t *testing.T) {
	dir := t.TempDir()
	writePrompt(t, dir, RoleL1, "body")
	s := New(dir, nil)
	if err := s.Load(); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = s.Get().Hash(RoleL1)
				}
			}
		}()
	}
	for i := 0; i < 50; i++ {
		s.reload()
	}
	close(stop)
	wg.Wait()
}
