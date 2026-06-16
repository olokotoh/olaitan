package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRun_OfflineEmitsAndProvesBound drives the CLI end-to-end in offline
// mode and asserts it prints the bound proof and emits the artefacts.
func TestRun_OfflineEmitsAndProvesBound(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"--offline", "--config", "rslt-full", "--provider", "claude",
		"--trials", "5", "--out", dir,
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v\nstderr: %s", err, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"max threat score:   10.5",
		"past SUSPICIOUS:    0",
		"cap violations:     0",
		"bound holds:        true",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout missing %q\n--- got ---\n%s", want, out)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "fr55-offline-fake-rslt-full", "trials.jsonl")); err != nil {
		t.Errorf("trials.jsonl not emitted: %v", err)
	}
}

// TestRun_OllamaBound proves the cap-parameterised Ollama bound (7.5).
func TestRun_OllamaBound(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"--offline", "--config", "rsl", "--provider", "ollama", "--trials", "3"}, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(stdout.String(), "max threat score:   7.5") {
		t.Errorf("expected Ollama bound 7.5\n%s", stdout.String())
	}
}

// TestRun_RequiresOffline proves the CLI refuses to run without --offline
// (the real cluster run is a deferred carry-forward, BI-2).
func TestRun_RequiresOffline(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"--config", "rsl", "--provider", "claude"}, &stdout, &stderr); err == nil {
		t.Fatal("expected error without --offline")
	}
}

// TestRun_RejectsUnknownConfigAndProvider proves the CLI fails closed on a
// bad config or provider rather than running the wrong experiment.
func TestRun_RejectsUnknownConfigAndProvider(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"--offline", "--config", "bogus", "--provider", "claude"}, &stdout, &stderr); err == nil {
		t.Fatal("expected error for unknown config")
	}
	stdout.Reset()
	stderr.Reset()
	if err := run([]string{"--offline", "--config", "rsl", "--provider", "bogus"}, &stdout, &stderr); err == nil {
		t.Fatal("expected error for unknown provider")
	}
}
