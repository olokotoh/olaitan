package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/agent/prompts"
	"github.com/olokotoh/olaitan/internal/decision/analyst"
)

// TestPromptHotReloadFlipsChainVersion is the Story 3.13 AC5 integration
// proof: a ConfigMap edit observed by the prompts watcher flips the prompt
// version recorded on the NEXT chain run, and emits a prompt_version_changed
// log line carrying the old and new content hashes.
func TestPromptHotReloadFlipsChainVersion(t *testing.T) {
	dir := t.TempDir()
	writeRolePrompt(t, dir, prompts.RoleL1, "L1 prompt v1")
	writeRolePrompt(t, dir, prompts.RoleL2, "L2 prompt v1")
	writeRolePrompt(t, dir, prompts.RoleSenior, "Senior prompt v1")
	writeRolePrompt(t, dir, prompts.RoleDFIR, "DFIR prompt v1")

	var logbuf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logbuf, nil))

	store := prompts.New(dir, log)
	if err := store.Load(); err != nil {
		t.Fatalf("store.Load: %v", err)
	}

	// A scripted full chain; install the store's prompts so the recorded
	// version is the content hash, not the helper's placeholder.
	chain := scriptedFullChain(t)
	set0 := store.Get()
	chain.SetPrompts(
		promptSpecFor(set0, prompts.RoleL1),
		promptSpecFor(set0, prompts.RoleL2),
		promptSpecFor(set0, prompts.RoleSenior),
	)

	// Wire the production reload callback.
	prev := store.Get()
	store.Subscribe(func(set *prompts.Set) {
		for _, role := range prompts.Roles() {
			if oldH, newH := prev.Hash(role), set.Hash(role); oldH != newH {
				log.Info("prompt_version_changed", "role", string(role), "old_hash", oldH, "new_hash", newH)
			}
		}
		chain.SetPrompts(
			promptSpecFor(set, prompts.RoleL1),
			promptSpecFor(set, prompts.RoleL2),
			promptSpecFor(set, prompts.RoleSenior),
		)
		prev = set
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- store.Watch(ctx) }()
	time.Sleep(50 * time.Millisecond)

	// Pre-reload run records the v1 L1 hash.
	res, err := chain.Run(ctx, triggeringPackage("80"))
	if err != nil {
		t.Fatalf("chain.Run pre-reload: %v", err)
	}
	wantV1 := set0.Hash(prompts.RoleL1)
	if res.L1 == nil || res.L1.PromptVersion != wantV1 {
		t.Fatalf("pre-reload L1 PromptVersion = %v, want %s", promptVerOrNil(res.L1), wantV1)
	}

	// Edit the L1 prompt; the watcher reload must flip the next run's hash.
	writeRolePrompt(t, dir, prompts.RoleL1, "L1 prompt v2 CHANGED")

	deadline := time.After(3 * time.Second)
	var wantV2 string
	for {
		res, err = chain.Run(ctx, triggeringPackage("80"))
		if err != nil {
			t.Fatalf("chain.Run post-reload: %v", err)
		}
		cur := store.Get().Hash(prompts.RoleL1)
		if res.L1 != nil && res.L1.PromptVersion == cur && cur != wantV1 {
			wantV2 = cur
			break
		}
		select {
		case <-deadline:
			t.Fatalf("prompt version did not flip after reload (still %s)", promptVerOrNil(res.L1))
		case <-time.After(25 * time.Millisecond):
		}
	}

	if wantV2 == wantV1 {
		t.Fatal("post-reload hash equals pre-reload hash")
	}
	logs := logbuf.String()
	if !strings.Contains(logs, "prompt_version_changed") {
		t.Errorf("missing prompt_version_changed log: %s", logs)
	}
	if !strings.Contains(logs, wantV1) || !strings.Contains(logs, wantV2) {
		t.Errorf("prompt_version_changed log missing old/new hashes (%s -> %s): %s", wantV1, wantV2, logs)
	}
	cancel()
	if werr := <-done; werr != nil {
		t.Errorf("Watch: %v", werr)
	}
}

// TestPromptPartialDirUsesEmbeddedDefaults proves a partial ConfigMap (only
// l1 present) loads the embedded defaults for the absent roles, so the chain
// builds with a non-empty Senior prompt hash.
func TestPromptPartialDirUsesEmbeddedDefaults(t *testing.T) {
	dir := t.TempDir()
	writeRolePrompt(t, dir, prompts.RoleL1, "only L1 mounted")

	store := prompts.New(dir, nil)
	if err := store.Load(); err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	set := store.Get()
	if set.Prompt(prompts.RoleL1).Text != "only L1 mounted" {
		t.Errorf("l1 = %q", set.Prompt(prompts.RoleL1).Text)
	}
	for _, r := range []prompts.Role{prompts.RoleL2, prompts.RoleSenior, prompts.RoleDFIR} {
		if set.Hash(r) == "" || set.Prompt(r).Text == "" {
			t.Errorf("role %s: embedded default not loaded", r)
		}
	}
}

func writeRolePrompt(t *testing.T, dir string, role prompts.Role, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, string(role)+".txt"), []byte(body+"\n"), 0o644); err != nil {
		t.Fatalf("write %s: %v", role, err)
	}
}

func promptVerOrNil(r *analyst.L1Result) string {
	if r == nil {
		return "<nil>"
	}
	return r.PromptVersion
}
