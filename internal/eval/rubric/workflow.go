package rubric

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// EmitStaticWorkflow writes the STATIC-FILE rater workflow (OQ3, the RECOMMENDED
// no-web-UI exposure) under dir/<run-dir>/workflow/ (AC2): per incident, the two
// BLINDED report files (report-a.md / report-b.md, with a NORMALISED
// variant-agnostic front-matter header so neither the variant label nor the
// asymmetric provenance metadata is visible to the rater, HIGH-1) and a
// per-rater scoring-sheet template (the 5 canonical
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
			// The rater-facing report file carries the prose body under a
			// NORMALISED, variant-agnostic front-matter header so the two slots
			// are indistinguishable in their identifying metadata (HIGH-1): the
			// asymmetric variant front-matter (report.v1 vs rubric.templated.v1,
			// report_kind, dfir_provider, dfir_model, prompt_hash) is STRIPPED
			// here and retained only in the off-disk un-blinding key/archive. The
			// prose itself legitimately differs (raters score quality); only the
			// metadata header must not label the source (AC2).
			path := filepath.Join(incidentDir, report.Slot+".md")
			body := blindReportBody(pair.IncidentID, report.Body)
			if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
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

// SchemaVersionBlindedReport is the NEUTRAL, variant-agnostic schema_version
// stamped on every rater-facing blinded report file (HIGH-1). It replaces the
// asymmetric per-variant front-matter (the LLM variant's report.v1 vs the
// templated baseline's rubric.templated.v1) so the two slots are
// INDISTINGUISHABLE in their identifying header. The full per-variant
// provenance is retained ONLY in the off-disk un-blinding key (BlindedPair),
// never in the rater-facing file.
const SchemaVersionBlindedReport = "rubric.blinded.v1"

// blindReportBody normalises a rendered variant body for the rater-facing file
// (HIGH-1): it STRIPS the variant-identifying YAML front-matter (the LLM
// variant's report.v1 + prompt_hash + dfir_provider + dfir_model, and the
// templated baseline's rubric.templated.v1 + report_kind) and replaces it with
// a single neutral header that carries only the variant-agnostic
// schema_version and the shared incident_id, so a rater cannot tell which slot
// is the machine/LLM report from the metadata. The prose body below the
// front-matter is preserved verbatim (raters legitimately score its quality).
// The incident_id is taken from the caller (the un-blinding-key incident_id),
// not parsed from the body, so a malformed front-matter cannot leak through.
func blindReportBody(incidentID, body string) string {
	prose := stripFrontMatter(body)
	var b strings.Builder
	b.WriteString("---\n")
	fmt.Fprintf(&b, "schema_version: %q\n", SchemaVersionBlindedReport)
	fmt.Fprintf(&b, "incident_id: %q\n", incidentID)
	b.WriteString("---\n\n")
	b.WriteString(prose)
	return b.String()
}

// stripFrontMatter removes a leading YAML front-matter block (the "---\n" ...
// "\n---\n" header both variant renderers emit) and returns the prose body that
// follows, with any leading blank lines after the closing fence trimmed. A body
// with no leading front-matter is returned unchanged (defensive).
func stripFrontMatter(body string) string {
	const fence = "---\n"
	if !strings.HasPrefix(body, fence) {
		return body
	}
	rest := body[len(fence):]
	end := strings.Index(rest, "\n"+fence)
	if end < 0 {
		// No closing fence: not a well-formed front-matter block; leave as-is.
		return body
	}
	prose := rest[end+len("\n"+fence):]
	return strings.TrimLeft(prose, "\n")
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
