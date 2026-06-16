package rubric

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ScoresFile is the rubric.score.v1 JSONL filename (one record per
// (incident, variant, rater, dimension) Likert score), sibling of metadata.yaml
// in each rubric run dir (OQ4).
const ScoresFile = "scores.jsonl"

// MetadataFile is the sibling metadata.yaml carrying the join/provenance keys
// the Story-5.5 load_rubric_scores reader consumes (OQ4).
const MetadataFile = "metadata.yaml"

// RunDirName is the single source of truth for the offline rubric run-dir name
// (and the matching metadata run_id), so the CLI banner and the emitter stay in
// sync. The OfflineRunDirPrefix marks the synthetic set honestly (BI-2).
func RunDirName(sum Summary) string {
	return fmt.Sprintf("%s%s", OfflineRunDirPrefix, sum.Scenario)
}

// Emit writes the rubric run artefacts under the reserved runs/rubric/ sub-tree
// (OQ4): dir/<run-dir>/scores.jsonl (the rubric.score.v1 records) and a sibling
// metadata.yaml carrying the join/provenance keys (scenario, manifest_sha256,
// n_incidents, n_raters, synthetic). dir is the rubric RESERVED sub-tree (e.g.
// runs/rubric/), kept separate from the main 4x5 grid so analyse.py:load_run_set
// does not orphan it (mirrors the Story-5.6 runs/fr55/ reservation).
//
// Emit is deterministic: it writes the records in the sorted order the harness
// produced, uses no wall-clock in the artefact bytes, and computes
// manifest_sha256 over the canonical scores.jsonl bytes, so two runs of the same
// Result produce byte-identical artefacts.
func Emit(dir string, result Result) error {
	runDirName := RunDirName(result.Summary)
	runDir := filepath.Join(dir, runDirName)
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return fmt.Errorf("rubric: create run dir %s: %w", runDir, err)
	}

	scoresBytes, err := marshalScores(result.Scores)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(runDir, ScoresFile), scoresBytes, 0o644); err != nil {
		return fmt.Errorf("rubric: write %s: %w", ScoresFile, err)
	}

	manifest := manifestSHA256(scoresBytes)
	metaBytes := marshalMetadata(runDirName, manifest, result.Summary)
	if err := os.WriteFile(filepath.Join(runDir, MetadataFile), metaBytes, 0o644); err != nil {
		return fmt.Errorf("rubric: write %s: %w", MetadataFile, err)
	}
	return nil
}

// marshalScores renders the rubric.score.v1 records as canonical JSONL: one
// compact json.Marshal line per record, in the sorted order the harness
// produced. A trailing newline follows the last line so the file is a clean
// append target.
func marshalScores(scores []RubricScore) ([]byte, error) {
	var b strings.Builder
	for i, sc := range scores {
		line, err := json.Marshal(sc)
		if err != nil {
			return nil, fmt.Errorf("rubric: marshal score %d: %w", i, err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}

// manifestSHA256 is the deterministic provenance hash over the canonical
// scores.jsonl bytes: the metadata join key (manifest_sha256) the Story-5.5
// reader carries. A fixed input yields a fixed hash.
func manifestSHA256(scoresBytes []byte) string {
	sum := sha256.Sum256(scoresBytes)
	return hex.EncodeToString(sum[:])
}

// marshalMetadata renders the metadata.yaml the Story-5.5 load_rubric_scores
// reader consumes (OQ4). The fields are written in a fixed order with no
// wall-clock, so the bytes are deterministic. Values are simple scalars, so a
// hand-rolled writer is sufficient and avoids a YAML dependency in the harness
// (mirrors the Story-5.6 fr55 emitter).
func marshalMetadata(runID, manifest string, sum Summary) []byte {
	synthetic := "false"
	if sum.Synthetic {
		synthetic = "true"
	}
	lines := []string{
		fmt.Sprintf("run_id: %s", runID),
		fmt.Sprintf("manifest_sha256: %s", manifest),
		// The Story-5.5 join key: load_rubric_scores carries the scenario.
		fmt.Sprintf("scenario: %s", sum.Scenario),
		fmt.Sprintf("n_incidents: %d", sum.NIncidents),
		fmt.Sprintf("n_raters: %d", sum.NRaters),
		// The honesty marker (BI-2): synthetic on the offline set.
		fmt.Sprintf("synthetic: %s", synthetic),
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}
