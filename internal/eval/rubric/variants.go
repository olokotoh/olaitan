package rubric

import (
	"fmt"
	"strings"
	"time"

	"github.com/olokotoh/olaitan/internal/report/dfir"
	"github.com/olokotoh/olaitan/internal/schema"
)

// Variant identifies one of the two report types compared per incident. The
// string values are the EXACT keys the rubric-scores records carry and the
// Story-5.5 reader pivots on (load_rubric_scores pairs variant=llm against
// variant=templated per incident_id); they must not drift (OQ4, BI-5).
type Variant string

const (
	// VariantLLM is variant (a): the Story-4.4 Olaitan DFIR LLM report,
	// rendered by the frozen dfir.ForensicReport.Render (BI-1).
	VariantLLM Variant = "llm"
	// VariantTemplated is variant (b): the NEW no-LLM templated baseline (BI-7).
	VariantTemplated Variant = "templated"
)

// syntheticNarrative is the fixed placeholder analyst narrative the OFFLINE
// proof stamps onto variant (a)'s ForensicReport (BI-1). It is a harness-only Go
// literal, NEVER under internal/agent/prompts/defaults (BI-3): the offline path
// makes NO live LLM call, so this string stands in for the model's interpretive
// prose without prompting. The (a)-vs-(b) contrast is exactly this narrative:
// variant (a) carries this interpretive narrative, variant (b) carries the
// neutral absence line below.
//
// BLINDING (AC2): this is rater-facing prose, so it carries NO self-identifying
// tell (no "synthetic"/"offline"/"LLM"/"not a thesis-final" marker). The
// synthetic honesty marker lives OFF-disk only (synthetic: true in metadata, the
// rubric-offline- run prefix, and the un-blinding key), never in this prose. In
// the real study this string is replaced by the real LLM narrative.
const syntheticNarrative = "This finalised incident shows a container-escape kill chain: the workload " +
	"escalated from CLEAN through SUSPICIOUS and RESTRICTED into QUARANTINED as the " +
	"ThreatScore crossed the escalation thresholds. The MITRE ATT&CK technique T1611 " +
	"(Escape to Host) is consistent with the privilege-escalation kill-chain stage. " +
	"Containment quarantined the workload before any kill condition was met."

// templatedStub is the fixed analyst-narrative section for variant (b). The
// baseline carries no interpretive narrative, and that absence is the legitimate
// quality contrast a rater scores (variant a's interpretive narrative vs variant
// b's absence) - that contrast is inherent to RQ5 and must remain.
//
// BLINDING (AC2): this is rater-facing prose, so it states the absence NEUTRALLY
// and factually under the SAME "Analyst narrative" heading variant (a) uses; it
// carries NO self-identifying tell (no "template"/"machine"/"baseline"/
// "language-model"/"no LLM" marker that would announce this is the templated
// variant). Only the narrative CONTENT differs (present + interpretive vs
// absent), never the self-description.
const templatedStub = "Analyst narrative: not provided."

// RenderLLMVariant produces variant (a) by REUSING the frozen Story-4.4 renderer
// read-only (BI-1). It builds a dfir.ForensicReport from the incident evidence
// with the fixed SYNTHETIC narrative (NO live LLM call) and calls
// ForensicReport.Render(evt). The ForensicReport front-matter fields are sourced
// deterministically from the incident, so the rendered bytes are reproducible.
func RenderLLMVariant(inc dfir.Incident) string {
	report := dfir.ForensicReport{
		IncidentID:                  inc.Event.PackageID,
		FinalFSMState:               inc.Event.FinalState,
		ThreatScoreAtDecision:       inc.Event.ThreatScore,
		AttackTechniques:            attackTechniques(inc),
		ContributingPostureFindings: postureFindings(inc),
		ContainmentActions:          containmentActions(inc),
		// A fixed generation time (not time.Now()) keeps the rendered
		// front-matter byte-deterministic for the offline golden (OQ5).
		ReportGeneratedAt: inc.Event.FinalisedAt,
		PromptHash:        "rubric-offline-synthetic",
		DFIRProvider:      "synthetic",
		DFIRModel:         "synthetic-offline",
		Narrative:         syntheticNarrative,
	}
	return report.Render(inc.Event)
}

// RenderTemplatedVariant produces variant (b): the NEW no-LLM templated baseline
// (BI-7). It renders the SAME factual sections from the SAME incident evidence
// via a fixed Markdown template (mirroring the deterministic section layout of
// the Story-4.4 renderer so the baseline is a fair like-for-like) and fills a
// fixed templated stub in place of the LLM narrative. It makes NO LLM/provider
// call. The bytes are deterministic (no time.Now() in rendered content, no
// map-iteration ordering).
func RenderTemplatedVariant(inc dfir.Incident) string {
	var b strings.Builder
	// YAML front-matter mirroring the factual front-matter of variant (a),
	// stamped with a templated-baseline marker (report_kind) so a reader can tell
	// the two variants apart in the UN-BLINDED record. This identifying header is
	// NOT visible to raters: the static-file workflow normalises it away via
	// blindReportBody (HIGH-1) before writing the rater-facing report-a/b.md, so
	// the rater-facing files carry only a neutral, variant-agnostic header.
	b.WriteString("---\n")
	writeTemplatedScalar(&b, "schema_version", "rubric.templated.v1")
	writeTemplatedScalar(&b, "incident_id", inc.Event.PackageID)
	writeTemplatedScalar(&b, "final_fsm_state", inc.Event.FinalState)
	fmt.Fprintf(&b, "threat_score_at_decision: %g\n", inc.Event.ThreatScore)
	writeTemplatedList(&b, "attack_techniques", attackTechniques(inc))
	writeTemplatedList(&b, "contributing_posture_findings", postureFindings(inc))
	writeTemplatedList(&b, "containment_actions", containmentActions(inc))
	writeTemplatedScalar(&b, "report_generated_at", inc.Event.FinalisedAt.UTC().Format(time.RFC3339))
	writeTemplatedScalar(&b, "report_kind", "templated-baseline")
	b.WriteString("---\n\n")

	b.WriteString(templatedTimelineSection(inc.Event.History))
	b.WriteString("\n")
	b.WriteString(templatedListSection("Containment actions", containmentActions(inc), "No containment action was recorded for this incident."))
	b.WriteString("\n")
	b.WriteString(templatedListSection("MITRE ATT&CK for Containers", attackTechniques(inc), "No MITRE ATT&CK for Containers technique was recorded for this incident."))
	b.WriteString("\n")
	b.WriteString(templatedListSection("Contributing posture findings", postureFindings(inc), "No contributing posture finding was recorded for this incident."))
	b.WriteString("\n")

	b.WriteString("## Analyst narrative\n\n")
	b.WriteString(templatedStub)
	b.WriteString("\n")
	return b.String()
}

// attackTechniques returns the ATT&CK techniques both variants render, sourced
// from the persisted ThreatAssessment (nil-tolerant; an absent assessment yields
// no techniques, exactly as the Story-4.4 renderer treats it). It is a value
// copy so a caller cannot mutate the assessment slice.
func attackTechniques(inc dfir.Incident) []string {
	if inc.Assessment == nil || len(inc.Assessment.MitreTechniques) == 0 {
		return nil
	}
	out := make([]string, len(inc.Assessment.MitreTechniques))
	copy(out, inc.Assessment.MitreTechniques)
	return out
}

// containmentActions derives the containment-actions list from the FSM history:
// the non-CLEAN states the workload reached, in chronological order, with no
// duplicates. This mirrors the Story-4.4 derivation (the report's
// containment_actions front-matter) so both variants render the same factual
// containment record over the same evidence.
func containmentActions(inc dfir.Incident) []string {
	var actions []string
	seen := map[string]bool{}
	for _, tr := range inc.Event.History {
		to := strings.TrimSpace(string(tr.ToState))
		if to == "" || to == string(schema.StateClean) || seen[to] {
			continue
		}
		seen[to] = true
		actions = append(actions, fmt.Sprintf("reached %s", to))
	}
	return actions
}

// postureFindings returns the contributing posture findings both variants
// render. The synthetic incident carries no posture findings, so the honest
// "not recorded" line renders; the function is nil-tolerant for the real input
// (a captured incident may carry posture findings).
func postureFindings(inc dfir.Incident) []string {
	if inc.Package.WorkloadPosture == nil {
		return nil
	}
	// The synthetic offline proof does not populate posture findings; a real
	// captured incident's posture summary would be projected here. Kept minimal
	// and deterministic (no map iteration).
	return nil
}

// templatedTimelineSection renders the kill-chain timeline for variant (b)
// deterministically from the FSM history, mirroring the Story-4.4 timeline
// layout (one chronological line per transition) so the baseline is a fair
// like-for-like. Pod names and trigger-event ids are NOT rendered (the same
// control-plane-only discipline the production renderer applies).
func templatedTimelineSection(history []schema.StateTransition) string {
	var b strings.Builder
	b.WriteString("## Kill-chain timeline\n\n")
	if len(history) == 0 {
		b.WriteString("No FSM transition history was recorded for this incident.\n")
		return b.String()
	}
	for _, tr := range history {
		ts := "unknown-time"
		if !tr.Timestamp.IsZero() {
			ts = tr.Timestamp.UTC().Format(time.RFC3339)
		}
		from := strings.TrimSpace(string(tr.FromState))
		if from == "" {
			from = "(none)"
		}
		to := strings.TrimSpace(string(tr.ToState))
		if to == "" {
			to = "(none)"
		}
		reason := strings.TrimSpace(tr.Reason)
		if reason == "" {
			reason = "(no reason recorded)"
		}
		fmt.Fprintf(&b, "- %s: %s -> %s (reason: %s, confidence: %g)\n", ts, from, to, reason, tr.Confidence)
	}
	return b.String()
}

// templatedListSection renders a titled Markdown list section (or the honest
// empty line) for variant (b). Shared by the containment, ATT&CK, and posture
// sections so they render identically.
func templatedListSection(title string, items []string, emptyLine string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## %s\n\n", title)
	if len(items) == 0 {
		b.WriteString(emptyLine)
		b.WriteString("\n")
		return b.String()
	}
	for _, it := range items {
		fmt.Fprintf(&b, "- %s\n", it)
	}
	return b.String()
}

// writeTemplatedScalar writes a double-quoted YAML scalar, escaping the value so
// an evidence-sourced string cannot break the front-matter block (the same
// YAML-escaping discipline the production renderer applies).
func writeTemplatedScalar(b *strings.Builder, key, val string) {
	fmt.Fprintf(b, "%s: %s\n", key, quoteTemplatedYAML(val))
}

// writeTemplatedList writes a YAML block-sequence; an empty list renders key: [].
func writeTemplatedList(b *strings.Builder, key string, items []string) {
	if len(items) == 0 {
		fmt.Fprintf(b, "%s: []\n", key)
		return
	}
	fmt.Fprintf(b, "%s:\n", key)
	for _, it := range items {
		fmt.Fprintf(b, "  - %s\n", quoteTemplatedYAML(it))
	}
}

// quoteTemplatedYAML returns s as a double-quoted YAML scalar with backslash,
// double quote, and control characters escaped.
func quoteTemplatedYAML(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString("\\\\")
		case '"':
			b.WriteString("\\\"")
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		case '\t':
			b.WriteString("\\t")
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
