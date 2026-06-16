package rubric

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// EmitStaticWorkflow writes the STATIC-FILE rater workflow (OQ3, the RECOMMENDED
// no-web-UI exposure) under dir/<run-dir>/workflow/ (AC2): per incident, the two
// BLINDED report files (report-a.md / report-b.md, with the variant label NOT
// visible to the rater) and a per-rater scoring-sheet template (the 5 canonical
// dimensions x the Likert scale) the rater fills in and returns. The un-blinding
// key is NOT written into the rater-facing files (the rater must not see it);
// it lives only in the in-memory BlindedPair.Slots and is applied at scoring
// time. The files are deterministic (seeded blinding, sorted iteration).
//
// This is the OFFLINE proof's exposure path; the committed rubric DEFINITION doc
// (analysis/rubric/rubric-definition.md) describes the administration. No live
// web UI / server is emitted (OQ3).
func EmitStaticWorkflow(dir string, result Result) error {
	runDirName := RunDirName(result.Summary)
	workflowDir := filepath.Join(dir, runDirName, "workflow")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		return fmt.Errorf("rubric: create workflow dir %s: %w", workflowDir, err)
	}

	for _, pair := range result.Pairs {
		incidentDir := filepath.Join(workflowDir, pair.IncidentID)
		if err := os.MkdirAll(incidentDir, 0o755); err != nil {
			return fmt.Errorf("rubric: create incident dir %s: %w", incidentDir, err)
		}
		for _, report := range pair.Reports {
			// The blinded report file carries ONLY the slot label and the body;
			// the variant is never written here (the blinding key is kept
			// separate, AC2).
			path := filepath.Join(incidentDir, report.Slot+".md")
			if err := os.WriteFile(path, []byte(report.Body), 0o644); err != nil {
				return fmt.Errorf("rubric: write blinded report %s: %w", path, err)
			}
		}
		for raterIdx := 1; raterIdx <= result.Summary.NRaters; raterIdx++ {
			rater := fmt.Sprintf("%s%d", OfflineRaterPrefix, raterIdx)
			sheet := scoringSheet(pair.IncidentID, rater)
			path := filepath.Join(incidentDir, "scoring-sheet-"+rater+".md")
			if err := os.WriteFile(path, []byte(sheet), 0o644); err != nil {
				return fmt.Errorf("rubric: write scoring sheet %s: %w", path, err)
			}
		}
	}
	return nil
}

// scoringSheet renders a per-rater, per-incident scoring-sheet template (AC2):
// the rater scores each blinded slot (report-a, report-b) on the 5 canonical
// dimensions using the documented Likert 1-5 scale, WITHOUT knowing which slot is
// the LLM-generated variant. The bytes are deterministic (the canonical
// dimensions iterate in fixed order). The filled sheet is parsed back at scoring
// time and the slot scores are un-blinded via the BlindedPair key.
func scoringSheet(incidentID, rater string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Rubric scoring sheet\n\n")
	fmt.Fprintf(&b, "- incident_id: %s\n", incidentID)
	fmt.Fprintf(&b, "- rater: %s\n", rater)
	fmt.Fprintf(&b, "- likert_scale: %d (low) to %d (high)\n\n", LikertMin, LikertMax)
	b.WriteString("Score each report (report-a and report-b) on every dimension. ")
	b.WriteString("You are NOT told which report is machine-generated; score on the documented anchors only ")
	b.WriteString("(see analysis/rubric/rubric-definition.md).\n\n")
	for _, slot := range blindLabels {
		fmt.Fprintf(&b, "## %s\n\n", slot)
		fmt.Fprintf(&b, "| dimension | score (%d-%d) |\n", LikertMin, LikertMax)
		b.WriteString("|---|---|\n")
		for _, dim := range CanonicalDimensions {
			fmt.Fprintf(&b, "| %s |  |\n", dim)
		}
		b.WriteString("\n")
	}
	return b.String()
}
