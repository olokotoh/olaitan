package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRun_OfflineEmitsArtefacts drives the CLI end-to-end in offline mode and
// asserts it prints the rubric proof summary and emits the rubric.score.v1
// artefacts under the reserved runs/rubric/ sub-tree (AC5).
func TestRun_OfflineEmitsArtefacts(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	err := run([]string{"--offline", "--scenario", "s1", "--raters", "2", "--out", dir}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v\nstderr: %s", err, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"scenario: s1",
		"synthetic: true",
		"rubric scores:      20 records",
		"blinded pairs:      1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout missing %q\n--- got ---\n%s", want, out)
		}
	}
	for _, name := range []string{"scores.jsonl", "metadata.yaml"} {
		if _, err := os.Stat(filepath.Join(dir, "rubric-offline-s1", name)); err != nil {
			t.Errorf("%s not emitted: %v", name, err)
		}
	}
}

// TestRun_OfflineWithWorkflow asserts --workflow writes the static-file rater
// workflow (the blinded reports + per-rater scoring sheets) (AC2/OQ3).
func TestRun_OfflineWithWorkflow(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	if err := run([]string{"--offline", "--out", dir, "--workflow"}, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v\nstderr: %s", err, stderr.String())
	}
	workflowDir := filepath.Join(dir, "rubric-offline-s1", "workflow")
	if _, err := os.Stat(workflowDir); err != nil {
		t.Errorf("workflow dir not emitted: %v", err)
	}
}

// TestRun_RequiresOffline proves the CLI refuses to run without --offline (the
// real N>=3 x N=10 rater study is a deferred carry-forward, BI-2).
func TestRun_RequiresOffline(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"--scenario", "s1"}, &stdout, &stderr); err == nil {
		t.Fatal("expected error without --offline")
	}
}
