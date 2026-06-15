//go:build e2e

// This file holds the Story 5.1 AC5 eval-harness smoke test. It is the
// load-bearing end-to-end proof that the olaitan-eval binary wires through
// from the reproducibility envelope to a captured run on a real kind
// cluster, scoped to the LIGHTEST honest arm (BI-7): a single
// `olaitan-eval --scenario s1 --config rs --runs 1` invocation against the
// RS arm (Falco-off, NO LLM) reusing the Story-1.19 rs_smoke kind bring-up
// that already passes in the default CI e2e job.
//
// HONEST SCOPE (BI-8): the "all artefacts captured" clause is scoped to
// the MINIMAL set: the per-run metadata.yaml (carrying manifest_sha256)
// plus the placeholder capture marker. The six-file rich artefact set
// (events / evidence / assessments / fsm / report) is Story 5.4 and is NOT
// pretended here.
//
// The test is `e2e`-build-tag gated and COMPILES under
// `go vet -tags=e2e ./tests/e2e/...`. It SKIPS gracefully when the kind
// cluster or the olaitan-eval binary is not present, so
// `go test -tags=e2e ./...` on a machine without the harness does not
// hard-fail. It is driven by `make eval-smoke` (the e2e-local precedent)
// and runs in the default CI e2e job alongside the RS smoke (it reuses the
// SAME RS bring-up, OA5).
package e2e_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// evalSmokeMetadata mirrors the MINIMAL metadata.yaml schema olaitan-eval
// writes (cmd/olaitan-eval/main.go). Only the fields the AC5 assertion
// reads are declared.
type evalSmokeMetadata struct {
	RunID          string `yaml:"run_id"`
	ManifestSHA256 string `yaml:"manifest_sha256"`
	Scenario       string `yaml:"scenario"`
	Config         string `yaml:"config"`
}

// repoRoot returns the repository root relative to tests/e2e/ so the test
// can locate eval/manifest.yaml and build cmd/olaitan-eval/.
func repoRoot() string {
	return filepath.Join("..", "..")
}

// TestEvalSmoke_S1_RS_OneTrial is the Story 5.1 AC5 pin: a single S1 + RS
// + 1-trial olaitan-eval run completes (exit 0), runs/<run_id>/ exists,
// metadata.yaml is present and carries manifest_sha256 matching
// sha256sum eval/manifest.yaml, and the minimal placeholder capture wrote
// its marker (BI-7, BI-8).
func TestEvalSmoke_S1_RS_OneTrial(t *testing.T) {
	requireKindCluster(t)
	waitForPodsReady(t)

	root := repoRoot()
	manifestPath := filepath.Join(root, "eval", "manifest.yaml")

	// Build the olaitan-eval binary into a temp dir so the test does not
	// depend on a pre-built bin/ (make eval-smoke builds it; this keeps
	// the test self-contained when run via `go test -tags=e2e`).
	binDir := t.TempDir()
	bin := filepath.Join(binDir, "olaitan-eval")
	build := exec.Command("go", "build", "-o", bin, "./cmd/olaitan-eval")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build olaitan-eval: %v\n%s", err, out)
	}

	// The image digest pinned in eval/manifest.yaml is a placeholder (the
	// published image is not yet digest-pinned in the chart; Story 5.3).
	// The fail-closed digest gate would REFUSE it, so allow-list the
	// aggregator image for the smoke run (the documented escape hatch,
	// BI-6). This honestly voids the reproducibility guarantee for that
	// single artefact for the smoke run only.
	outDir := filepath.Join(t.TempDir(), "runs")
	cmd := exec.Command(bin,
		"--manifest", manifestPath,
		"--scenario", "s1",
		"--config", "rs",
		"--runs", "1",
		"--out", outDir,
		"--allow-unverified", "aggregator",
	)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("olaitan-eval run failed (want exit 0): %v\n%s", err, out)
	}

	runID := parseRunID(t, string(out))
	if runID == "" {
		t.Fatalf("olaitan-eval did not print a run_id:\n%s", out)
	}
	runDir := filepath.Join(outDir, runID)
	if fi, err := os.Stat(runDir); err != nil || !fi.IsDir() {
		t.Fatalf("runs/<run_id>/ dir %q missing: %v", runDir, err)
	}

	// metadata.yaml present + manifest_sha256 matches sha256sum of the
	// committed manifest (BI-5).
	mdPath := filepath.Join(runDir, "metadata.yaml")
	mdRaw, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatalf("metadata.yaml missing: %v", err)
	}
	var md evalSmokeMetadata
	if err := yaml.Unmarshal(mdRaw, &md); err != nil {
		t.Fatalf("parse metadata.yaml: %v", err)
	}
	wantHash := fileSHA256(t, manifestPath)
	if md.ManifestSHA256 != wantHash {
		t.Errorf("metadata manifest_sha256 = %s; want %s (sha256sum eval/manifest.yaml)", md.ManifestSHA256, wantHash)
	}
	if md.Scenario != "s1" || md.Config != "rs" {
		t.Errorf("metadata scenario/config = %s/%s; want s1/rs", md.Scenario, md.Config)
	}

	// The minimal placeholder capture wrote its marker for trial-1 (BI-8;
	// the six-file rich set is Story 5.4).
	marker := filepath.Join(runDir, "trial-1", "CAPTURE_PLACEHOLDER.md")
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("placeholder capture marker %q missing: %v", marker, err)
	}
}

// parseRunID extracts the run_id from olaitan-eval's stdout.
func parseRunID(t *testing.T, out string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "run_id: ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "run_id: "))
		}
	}
	return ""
}

// fileSHA256 returns the lowercase-hex SHA256 of the file at path, the
// independent re-derivation of the manifest hash (BI-5).
func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
