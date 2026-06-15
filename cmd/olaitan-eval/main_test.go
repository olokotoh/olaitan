package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// writeCommittedShapeManifest writes a valid manifest into dir and returns
// its path. Reuses the validManifestYAML fixture from manifest_test.go.
func writeCommittedShapeManifest(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "manifest.yaml")
	if err := os.WriteFile(path, []byte(validManifestYAML), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return path
}

// TestParseFlags_Dispatch_RSLTFull asserts the AC4 invocation
// `--scenario s1 --config rslt-full --runs 15` PARSES and dispatches (the
// rich rslt-full EXECUTION awaits Story 5.2/5.3).
func TestParseFlags_Dispatch_RSLTFull(t *testing.T) {
	cfg, err := parseFlags([]string{
		"--manifest", "eval/manifest.yaml",
		"--scenario", "s1",
		"--config", "rslt-full",
		"--runs", "15",
	}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if cfg.scenario != "s1" || cfg.config != "rslt-full" || cfg.runs != 15 {
		t.Errorf("parsed cfg = %+v; want scenario=s1 config=rslt-full runs=15", cfg)
	}
	if cfg.manifestPath != "eval/manifest.yaml" {
		t.Errorf("manifestPath = %q; want eval/manifest.yaml", cfg.manifestPath)
	}
}

func TestParseFlags_Defaults(t *testing.T) {
	cfg, err := parseFlags([]string{"--scenario", "s1", "--config", "rs"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if cfg.manifestPath != "eval/manifest.yaml" {
		t.Errorf("default manifest = %q; want eval/manifest.yaml", cfg.manifestPath)
	}
	if cfg.runs != 1 {
		t.Errorf("default runs = %d; want 1", cfg.runs)
	}
	if cfg.out != "runs" {
		t.Errorf("default out = %q; want runs", cfg.out)
	}
}

func TestParseFlags_RequiredAndRange(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"missing scenario", []string{"--config", "rs"}},
		{"missing config", []string{"--scenario", "s1"}},
		{"runs below 1", []string{"--scenario", "s1", "--config", "rs", "--runs", "0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseFlags(tc.args, &bytes.Buffer{}); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestParseFlags_AllowUnverified(t *testing.T) {
	cfg, err := parseFlags([]string{
		"--scenario", "s1", "--config", "rs",
		"--allow-unverified", "aggregator, falco_rule_corpus",
	}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if len(cfg.allowUnverified) != 2 || cfg.allowUnverified[0] != "aggregator" || cfg.allowUnverified[1] != "falco_rule_corpus" {
		t.Errorf("allowUnverified = %v; want [aggregator falco_rule_corpus]", cfg.allowUnverified)
	}
}

// runIDPattern matches the OA3 run_id format:
// <compact-UTC-timestamp>-<scenario>-<config>-<short-hash>.
var runIDPattern = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-s1-rs-[0-9a-f]{12}$`)

func TestNewRunID_Format(t *testing.T) {
	at := time.Date(2026, 6, 15, 9, 30, 0, 0, time.UTC)
	id := newRunID(at, "s1", "rs", "69d1b5f452cd0d91eec2bbe94f6047ab68588b7a5faf724bc57dda0d86462a5a")
	if !runIDPattern.MatchString(id) {
		t.Errorf("run_id %q does not match the OA3 format", id)
	}
	if !strings.HasPrefix(id, "20260615T093000Z-s1-rs-69d1b5f452cd") {
		t.Errorf("run_id %q has wrong prefix or short-hash", id)
	}
}

// TestRun_LayoutTrialsAndMetadata drives a full run with the digest gate
// bypassed via --allow-unverified and asserts the run-dir layout, the
// per-trial dirs, the placeholder capture, and the metadata.yaml
// manifest_sha256 field == sha256sum of the manifest fixture.
func TestRun_LayoutTrialsAndMetadata(t *testing.T) {
	dir := t.TempDir()
	manifestPath := writeCommittedShapeManifest(t, dir)
	outDir := filepath.Join(dir, "runs")

	var stdout, stderr bytes.Buffer
	err := run([]string{
		"--manifest", manifestPath,
		"--scenario", "s1",
		"--config", "rs",
		"--runs", "3",
		"--out", outDir,
		"--allow-unverified", "aggregator",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: unexpected error: %v\nstderr:\n%s", err, stderr.String())
	}

	runID := extractRunID(t, stdout.String())
	runDir := filepath.Join(outDir, runID)

	// Run dir exists.
	if fi, err := os.Stat(runDir); err != nil || !fi.IsDir() {
		t.Fatalf("run dir %q missing: %v", runDir, err)
	}

	// Three trial dirs, each with the placeholder capture.
	for trial := 1; trial <= 3; trial++ {
		trialDir := filepath.Join(runDir, fmt.Sprintf("trial-%d", trial))
		if fi, err := os.Stat(trialDir); err != nil || !fi.IsDir() {
			t.Errorf("trial dir %q missing: %v", trialDir, err)
		}
		marker := filepath.Join(trialDir, capturePlaceholderName)
		if _, err := os.Stat(marker); err != nil {
			t.Errorf("placeholder capture %q missing: %v", marker, err)
		}
	}
	// No phantom trial-4.
	if _, err := os.Stat(filepath.Join(runDir, "trial-4")); err == nil {
		t.Errorf("unexpected trial-4 dir present; runs=3 must produce exactly 3 trials")
	}

	// metadata.yaml carries the matching manifest_sha256.
	md := readMetadata(t, filepath.Join(runDir, "metadata.yaml"))
	wantHash := sha256sumOf(t, manifestPath)
	if md.ManifestSHA256 != wantHash {
		t.Errorf("metadata manifest_sha256 = %s; want %s (sha256sum of the fixture)", md.ManifestSHA256, wantHash)
	}
	if md.RunID != runID {
		t.Errorf("metadata run_id = %s; want %s", md.RunID, runID)
	}
	if md.Scenario != "s1" || md.Config != "rs" || md.Runs != 3 {
		t.Errorf("metadata fields = %+v; want scenario=s1 config=rs runs=3", md)
	}
	if md.StartedAt == "" || md.FinishedAt == "" {
		t.Errorf("metadata started_at/finished_at must be populated")
	}
	if md.OlaitanEvalVersion == "" {
		t.Errorf("metadata olaitan_eval_version must be populated")
	}
}

// TestRun_DigestGateRefusesWithoutAllowlist asserts the fail-closed gate
// (BI-6): with no container runtime resolver reachable and no
// --allow-unverified, the run REFUSES to start (non-zero, a clear error).
func TestRun_DigestGateRefusesWithoutAllowlist(t *testing.T) {
	dir := t.TempDir()
	manifestPath := writeCommittedShapeManifest(t, dir)

	var stdout, stderr bytes.Buffer
	err := run([]string{
		"--manifest", manifestPath,
		"--scenario", "s1",
		"--config", "rs",
		"--out", filepath.Join(dir, "runs"),
	}, &stdout, &stderr)
	if err == nil {
		t.Fatalf("expected a fail-closed REFUSE, got nil")
	}
	if !strings.Contains(err.Error(), "digest gate REFUSE") {
		t.Errorf("error %q is not the fail-closed digest-gate refusal", err.Error())
	}
}

// TestImageDigestVerifier_GateBehaviour exercises the verifier seam
// directly with an injected resolver: a match passes, a mismatch refuses,
// an unresolvable digest refuses, and an allow-listed artefact bypasses.
func TestImageDigestVerifier_GateBehaviour(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	const pinnedHex = "2158bb18545621bc64d93dbeb1999a123bfdce638ea3e50c7fad60c00b711227"
	m := &Manifest{Images: map[string]string{
		"aggregator": "ghcr.io/olokotoh/olaitan@sha256:" + pinnedHex,
	}}

	t.Run("match passes", func(t *testing.T) {
		v := &imageDigestVerifier{logger: logger, resolveDigest: func(context.Context, string) (string, error) {
			return "sha256:" + pinnedHex, nil
		}}
		if err := v.Verify(context.Background(), m); err != nil {
			t.Errorf("expected pass on matching digest, got %v", err)
		}
	})

	t.Run("mismatch refuses", func(t *testing.T) {
		v := &imageDigestVerifier{logger: logger, resolveDigest: func(context.Context, string) (string, error) {
			return "sha256:" + strings.Repeat("0", 64), nil
		}}
		err := v.Verify(context.Background(), m)
		if err == nil || !strings.Contains(err.Error(), "mismatch") {
			t.Errorf("expected a mismatch REFUSE, got %v", err)
		}
	})

	t.Run("unresolvable refuses", func(t *testing.T) {
		v := &imageDigestVerifier{logger: logger, resolveDigest: func(context.Context, string) (string, error) {
			return "", fmt.Errorf("no runtime")
		}}
		err := v.Verify(context.Background(), m)
		if err == nil || !strings.Contains(err.Error(), "unresolvable") {
			t.Errorf("expected an unresolvable REFUSE, got %v", err)
		}
	})

	t.Run("allow-listed bypass", func(t *testing.T) {
		v := &imageDigestVerifier{
			logger:          logger,
			allowUnverified: map[string]bool{"aggregator": true},
			resolveDigest: func(context.Context, string) (string, error) {
				return "", fmt.Errorf("no runtime")
			},
		}
		if err := v.Verify(context.Background(), m); err != nil {
			t.Errorf("expected allow-listed bypass to pass, got %v", err)
		}
	})

	t.Run("nil resolver fails closed", func(t *testing.T) {
		v := &imageDigestVerifier{logger: logger}
		if err := v.Verify(context.Background(), m); err == nil {
			t.Errorf("expected a nil-resolver REFUSE (fail-closed), got nil")
		}
	})
}

// TestRunner_PhaseOrderAndDeferredCleanup asserts the Runner drives the
// five seams in the architecture-mandated order (BI-2) and that Cleanup
// runs even when an earlier phase errors.
func TestRunner_PhaseOrderAndDeferredCleanup(t *testing.T) {
	t.Run("happy order", func(t *testing.T) {
		rec := &phaseRecorder{}
		r := &Runner{
			Cluster: rec, Overlay: rec, Scenario: rec, Capturer: rec,
			Config: "rs", Logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		}
		if err := r.Run(context.Background(), t.TempDir()); err != nil {
			t.Fatalf("Run: %v", err)
		}
		want := []string{"reset", "warm", "apply", "scenario", "capture", "cleanup"}
		if strings.Join(rec.order, ",") != strings.Join(want, ",") {
			t.Errorf("phase order = %v; want %v", rec.order, want)
		}
	})

	t.Run("cleanup runs after scenario error", func(t *testing.T) {
		rec := &phaseRecorder{failScenario: true}
		r := &Runner{
			Cluster: rec, Overlay: rec, Scenario: rec, Capturer: rec,
			Config: "rs", Logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		}
		err := r.Run(context.Background(), t.TempDir())
		if err == nil || !strings.Contains(err.Error(), "scenario run") {
			t.Fatalf("expected a scenario-run error, got %v", err)
		}
		if !contains(rec.order, "cleanup") {
			t.Errorf("cleanup did not run after a scenario error; order=%v", rec.order)
		}
		if contains(rec.order, "capture") {
			t.Errorf("capture must not run after a scenario error; order=%v", rec.order)
		}
	})
}

// phaseRecorder is a test double implementing all four lifecycle seams,
// recording the order phases ran.
type phaseRecorder struct {
	order        []string
	failScenario bool
}

func (p *phaseRecorder) Reset(context.Context) error { p.order = append(p.order, "reset"); return nil }
func (p *phaseRecorder) Warm(context.Context) error  { p.order = append(p.order, "warm"); return nil }
func (p *phaseRecorder) Cleanup(context.Context) error {
	p.order = append(p.order, "cleanup")
	return nil
}
func (p *phaseRecorder) Apply(context.Context, string) error {
	p.order = append(p.order, "apply")
	return nil
}
func (p *phaseRecorder) Run(context.Context) error {
	p.order = append(p.order, "scenario")
	if p.failScenario {
		return fmt.Errorf("boom")
	}
	return nil
}
func (p *phaseRecorder) Capture(context.Context, string) error {
	p.order = append(p.order, "capture")
	return nil
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// --- test helpers -------------------------------------------------------

func extractRunID(t *testing.T, stdout string) string {
	t.Helper()
	for _, line := range strings.Split(stdout, "\n") {
		if strings.HasPrefix(line, "run_id: ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "run_id: "))
		}
	}
	t.Fatalf("run_id not found in stdout:\n%s", stdout)
	return ""
}

func readMetadata(t *testing.T, path string) metadata {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read metadata: %v", err)
	}
	var md metadata
	if err := yaml.Unmarshal(raw, &md); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	return md
}

func sha256sumOf(t *testing.T, path string) string {
	t.Helper()
	m, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest for hash: %v", err)
	}
	return m.SHA256()
}
