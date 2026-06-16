package fr55

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Emit writes the FR55 run artefacts under
// dir/<provider>-<config>/ (OQ1): a trials.jsonl (one fr55.trial.v1 line
// per trial) and a sibling metadata.yaml carrying the Story-5.5 join keys
// (scenario: benign-adversarial, config, manifest_sha256) plus the
// FR55-specific summary fields (provider, n_trials, max_threat_score,
// n_past_suspicious, bound), so the artefact loads cleanly through
// Story-5.5's io.load_run_set metadata reader AND matches build_fr55_rows'
// scenario == "benign-adversarial" join (BI-7).
//
// dir is the FR55 RESERVED sub-tree (e.g. runs/fr55/), kept separate from
// the main 4x5 grid so analyse.py:_known_grid does not orphan the
// benign-adversarial scenario (OQ1). The run-dir name and the metadata
// run_id are prefixed OfflineRunIDPrefix and the provider is labelled
// honestly (BI-2): the offline fake set is never a thesis-final number.
//
// The run-dir name also encodes the EMULATED provider SHAPE (Story 5.6 R2):
// fr55-offline-fake-<shape>-<config>. Without the shape the same config
// under two shapes (claude cap 35 / ollama cap 25) both wrote to
// fr55-offline-fake-<config> and silently overwrote one another; the shape
// makes every offline run dir collision-free and CLI-reproducible. The
// transport label stays the honest "fake" (provider: fake in the metadata).
//
// Emit is deterministic: it sorts nothing it does not already control,
// uses no wall-clock in the artefact bytes, and computes manifest_sha256
// over the canonical trials.jsonl bytes, so two runs of the same RunResult
// produce byte-identical artefacts.
func Emit(dir string, result RunResult) error {
	runDirName := RunDirName(result.Summary)
	runDir := filepath.Join(dir, runDirName)
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return fmt.Errorf("fr55: create run dir %s: %w", runDir, err)
	}

	trialsBytes, err := marshalTrials(result.Trials)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(runDir, "trials.jsonl"), trialsBytes, 0o644); err != nil {
		return fmt.Errorf("fr55: write trials.jsonl: %w", err)
	}

	manifest := manifestSHA256(trialsBytes)
	metaBytes := marshalMetadata(runDirName, manifest, result.Summary)
	if err := os.WriteFile(filepath.Join(runDir, "metadata.yaml"), metaBytes, 0o644); err != nil {
		return fmt.Errorf("fr55: write metadata.yaml: %w", err)
	}
	return nil
}

// RunDirName is the single source of truth for the offline run-dir name (and
// the matching metadata run_id), so the CLI banner and the emitter stay in
// sync. It is fr55-offline-fake-<shape>-<config> when a provider shape is
// present (the collision-free Story 5.6 R2 form), and falls back to the bare
// fr55-offline-fake-<config> when no shape is set (pre-R2 callers). The
// "fake" transport marker is always retained (BI-2).
func RunDirName(sum BoundSummary) string {
	if sum.Shape != "" {
		return fmt.Sprintf("%s%s-%s-%s", OfflineRunIDPrefix, sum.Provider, sum.Shape, sum.Config)
	}
	return fmt.Sprintf("%s%s-%s", OfflineRunIDPrefix, sum.Provider, sum.Config)
}

// marshalTrials renders the trials as canonical JSONL: one compact
// json.Marshal line per trial, in trial-index order (the slice order the
// harness produced, which is already index order). A trailing newline
// follows the last line so the file is a clean append target.
func marshalTrials(trials []Trial) ([]byte, error) {
	var b strings.Builder
	for _, tr := range trials {
		line, err := json.Marshal(tr)
		if err != nil {
			return nil, fmt.Errorf("fr55: marshal trial %d: %w", tr.TrialIndex, err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}

// manifestSHA256 is the deterministic provenance hash over the canonical
// trials.jsonl bytes: the metadata join key (manifest_sha256) the
// Story-5.5 reader carries. A fixed input yields a fixed hash.
func manifestSHA256(trialsBytes []byte) string {
	sum := sha256.Sum256(trialsBytes)
	return hex.EncodeToString(sum[:])
}

// marshalMetadata renders the metadata.yaml the Story-5.5 io.load_run_set
// reader and the build_fr55_rows aggregation consume (BI-7, OQ1). The
// fields are written in a fixed order with no wall-clock, so the bytes are
// deterministic. Values are simple scalars (strings, ints, a float), so a
// hand-rolled writer is sufficient and avoids a YAML dependency in the
// harness.
func marshalMetadata(runID, manifest string, sum BoundSummary) []byte {
	holds := "false"
	if sum.Holds() {
		holds = "true"
	}
	lines := []string{
		fmt.Sprintf("run_id: %s", runID),
		fmt.Sprintf("manifest_sha256: %s", manifest),
		// The Story-5.5 join key: build_fr55_rows joins on
		// scenario == "benign-adversarial".
		fmt.Sprintf("scenario: %s", MetadataScenario),
		fmt.Sprintf("config: %s", sum.Config),
		// The honest provider marker (BI-2): "fake" on the offline set.
		fmt.Sprintf("provider: %s", sum.Provider),
		// The emulated provider shape (BI-6, Story 5.6 R2): which per-provider
		// cap the fake reported. DISTINCT from the honest "fake" transport
		// above; it makes the offline run dir collision-free + self-describing.
		fmt.Sprintf("shape: %s", sum.Shape),
		fmt.Sprintf("n_trials: %d", sum.NTrials),
		// The bound-proof summary fields the FR55 row reads (AC4/AC6).
		fmt.Sprintf("max_threat_score: %s", formatFloat(sum.MaxThreatScore)),
		fmt.Sprintf("n_past_suspicious: %d", sum.NPastSuspicious),
		fmt.Sprintf("cap_violation_total: %d", sum.CapViolationTotal),
		fmt.Sprintf("bound: %s", formatFloat(sum.Bound)),
		fmt.Sprintf("bound_holds: %s", holds),
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

// formatFloat renders a float deterministically with a single decimal
// place (the FR55 bounds and scores are exact to 0.1: 10.5 / 7.5 / 0.0).
func formatFloat(f float64) string {
	return fmt.Sprintf("%.1f", f)
}
