// Package dfir hosts the Story 4.4 DFIR forensic-report agent (FR43), the
// Ring-5 (report) component that consumes the Story 4.3 INCIDENTS.finalised
// event and produces an analyst-grade ForensicReport: a Markdown report with
// YAML front-matter (deterministically rendered kill-chain timeline, containment
// actions, and MITRE ATT&CK for Containers annotations, plus the model's
// interpretive narrative).
//
// # Architecture and trust boundary (BI-1, BI-12)
//
// The DFIR agent is a durable JetStream CONSUMER of the append-only INCIDENTS
// stream, NOT an fsm.TransitionSink and NOT a fourth analyst-chain tier. The
// trigger flows ONE-WAY: the Story 4.3 settling controller publishes
// IncidentFinalised, the DFIR agent consumes it and emits a report on
// REPORTS.generated. The report is downstream of the FSM, never upstream: this
// package produces an ARTIFACT + a metric ONLY. There is NO GuardCappedConfidence
// call, NO LLMCappedConfidence field, NO internal/decision/score import, NO FSM
// import. The LLM-cannot-escalate thesis is preserved (TRUST-BOUND FENCE).
//
// # Validation approach (BI-6 JSON->render hybrid)
//
// The LLM returns a STRUCTURED ForensicReport JSON document validated against
// the embedded schema via the Epic-3 jsonschema/v6 pipeline; the runner then
// RENDERS it deterministically in Go to YAML-front-matter + Markdown. The LLM
// never controls raw Markdown structure, which closes the prompt-injection
// breakout surface. The deterministic front-matter fields are sourced from the
// IncidentFinalised event and the persisted ThreatAssessment / WorkloadPosture,
// NOT invented by the model (AC2).
//
// # Redaction contract (AC4, BI-5)
//
// All incident evidence travels on Request.Package, where the provider's
// pre-send Redact() guards it automatically for the DFIR role (ZERO new
// redaction code). The runner NEVER interpolates raw event excerpts or
// un-redacted strings into the DFIR Prompt text or the front-matter.
//
// # Ring discipline
//
// This package may import the substrate it operates over (internal/schema,
// internal/nats, internal/subjects, internal/agent/provider, internal/metrics)
// and the response-side event type it consumes (internal/response/settling). It
// MUST NOT import internal/decision/score or any FSM package (the trust-bound
// fence). internal/report/redact forbids importing this package back (it is a
// leaf the redact package treats as a CONSUMER).
//
// # Scope fence (BI-13)
//
// Story 4.4 builds ONLY the DFIR agent, the ForensicReport schema + report, the
// INCIDENTS.finalised consumer, the REPORTS.generated emission, and the
// AUDIT.assessments DFIR row. It does NOT build persistence-side redaction of
// the report body (Story 4.5), the durable S3-compatible report WRITE with
// content-addressed key + KMS + object lock (Story 4.6), or the retry/deferred
// queue (Story 4.7). The REPORTS.generated event CARRIES the content-addressed
// report URL field but 4.4 does not perform the durable write.
package dfir

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/olokotoh/olaitan/internal/response/settling"
	"github.com/olokotoh/olaitan/internal/schema"
)

// forensicSchemaJSON is the embedded runtime copy of the authoritative
// ForensicReport JSON schema. It MUST stay byte-identical to
// docs/schemas/forensic_report.json (guarded by TestEmbeddedSchemaMatchesDocs);
// the embed directive cannot reference the docs tree across package boundaries,
// hence the co-located copy (Open Assumption 3).
//
//go:embed forensic_report_schema.json
var forensicSchemaJSON []byte

// SchemaVersionForensicReport is the canonical schema_version of the DFIR
// MODEL-FACING report contract (docs/schemas/forensic_report.json), stamped by
// the runner after validation. It versions the model response contract, not the
// persisted/rendered Go struct.
const SchemaVersionForensicReport = "report.v1"

// SchemaVersionReportGenerated is stamped on every ReportGenerated wire event
// per the architecture's schema-versioning ADR. It versions independently of
// the INCIDENTS.finalised subject and the AUDIT.* subjects.
const SchemaVersionReportGenerated = "reports.generated.v1"

// ForensicReport is the structured DFIR forensic report (FR43). It is the
// MODEL-facing JSON document the LLM returns (validated against the embedded
// schema) AND the rendered-report carrier: the deterministic front-matter
// fields are force-stamped by the runner from the IncidentFinalised event and
// the persisted ThreatAssessment / WorkloadPosture (AC2, not invented by the
// model), and Narrative is the interpretive analyst prose the LLM supplies.
//
// Round-1 review follow-up (anti-hallucination): the model supplies ONLY the
// Narrative. The factual report sections (kill-chain timeline, containment
// actions, MITRE ATT&CK annotations) are assembled DETERMINISTICALLY in Go by
// Render from the IncidentFinalised event history and the chosen
// ThreatAssessment, so the model never prints a fact it could fabricate. The
// rendered Markdown artifact (YAML front-matter + deterministic factual
// sections + the model's narrative) is produced by Render.
type ForensicReport struct {
	// SchemaVersion is stamped to report.v1 by the runner after validation;
	// optional (or null) from the model.
	SchemaVersion string `json:"schema_version,omitempty"`
	// IncidentID is the finalised incident's package_id.
	IncidentID string `json:"incident_id"`
	// FinalFSMState is the non-CLEAN state the workload settled in.
	FinalFSMState string `json:"final_fsm_state"`
	// ThreatScoreAtDecision is the ThreatScore captured at final-state entry.
	ThreatScoreAtDecision float64 `json:"threat_score_at_decision"`
	// AttackTechniques are the ATT&CK for Containers technique annotations,
	// sourced from the persisted ThreatAssessment.MitreTechniques.
	AttackTechniques []string `json:"attack_techniques,omitempty"`
	// ContributingPostureFindings are RBAC/NetworkPolicy/PodSecurityContext
	// findings at the time of the incident.
	ContributingPostureFindings []string `json:"contributing_posture_findings,omitempty"`
	// ContainmentActions are the actions Olaitan took (the non-CLEAN states
	// reached, optional checkpoint), derived from the FSM history.
	ContainmentActions []string `json:"containment_actions,omitempty"`
	// ReportGeneratedAt is the report generation time (the runner clock).
	ReportGeneratedAt time.Time `json:"report_generated_at"`
	// PromptHash is the DFIR prompt content hash (PromptSpec.Version).
	PromptHash string `json:"prompt_hash"`
	// DFIRProvider is the provider that served the DFIR call (e.g. "claude").
	DFIRProvider string `json:"dfir_provider"`
	// DFIRModel is the model id that served the DFIR call.
	DFIRModel string `json:"dfir_model"`
	// Narrative is the interpretive analyst prose the LLM supplies (the
	// factual sections are rendered deterministically, NOT modelled).
	Narrative string `json:"narrative"`
}

// Render produces the deterministic YAML-front-matter + Markdown artifact from
// the schema-validated report (BI-6). The LLM never controls this rendering: it
// is pure Go.
//
// Round-1 review follow-up (anti-hallucination): the factual sections are
// assembled here from the IncidentFinalised event history and the validated
// front-matter values, NOT from model output. The renderer assembles, in order:
// the YAML front-matter, the deterministic kill-chain timeline section (from
// evt.History), the deterministic containment-actions section, the deterministic
// MITRE ATT&CK section, and finally the model's interpretive narrative section.
// The model never prints a fact it could fabricate (a timestamp, a from->to
// state, a technique); it only supplies the narrative prose. Front-matter
// list/string values are YAML-escaped so a model-controlled posture-finding
// string cannot break out of the block.
func (r ForensicReport) Render(evt settling.IncidentFinalised) string {
	var b strings.Builder
	b.WriteString("---\n")
	writeYAMLScalar(&b, "schema_version", SchemaVersionForensicReport)
	writeYAMLScalar(&b, "incident_id", r.IncidentID)
	writeYAMLScalar(&b, "final_fsm_state", r.FinalFSMState)
	// %g renders the score without spurious trailing zeros; it is a plain
	// number, not a model-controlled string, so it needs no escaping.
	fmt.Fprintf(&b, "threat_score_at_decision: %g\n", r.ThreatScoreAtDecision)
	writeYAMLList(&b, "attack_techniques", r.AttackTechniques)
	writeYAMLList(&b, "contributing_posture_findings", r.ContributingPostureFindings)
	writeYAMLList(&b, "containment_actions", r.ContainmentActions)
	writeYAMLScalar(&b, "report_generated_at", r.ReportGeneratedAt.UTC().Format(time.RFC3339))
	writeYAMLScalar(&b, "prompt_hash", r.PromptHash)
	writeYAMLScalar(&b, "dfir_provider", r.DFIRProvider)
	writeYAMLScalar(&b, "dfir_model", r.DFIRModel)
	b.WriteString("---\n\n")

	// Deterministic factual sections (the anti-hallucination core). These are
	// assembled in Go; the model cannot influence them.
	b.WriteString(renderTimelineSection(evt.History))
	b.WriteString("\n")
	b.WriteString(renderContainmentSection(r.ContainmentActions))
	b.WriteString("\n")
	b.WriteString(renderATTACKSection(r.AttackTechniques))
	b.WriteString("\n")
	b.WriteString(renderPostureSection(r.ContributingPostureFindings))
	b.WriteString("\n")

	// The model's interpretive narrative section.
	b.WriteString("## Analyst narrative\n\n")
	b.WriteString(r.Narrative)
	if !strings.HasSuffix(r.Narrative, "\n") {
		b.WriteString("\n")
	}
	return b.String()
}

// renderTimelineSection renders the kill-chain timeline (AC3 section 1)
// deterministically from the FSM transition history: one chronological line per
// transition carrying the RFC3339 timestamp, the from->to state move, the
// reason, and the confidence. Pod names and raw event ids are STRIPPED
// (control-plane facts only): the per-pod identity and the trigger-event ids are
// runtime evidence that must not leak into the rendered report front-matter or
// body (the redaction discipline). An empty history renders an explicit honest
// line rather than inviting the model to invent one (BI-9: the controller never
// blocks finalisation on history).
func renderTimelineSection(history []schema.StateTransition) string {
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

// renderContainmentSection renders the containment-actions section (AC3)
// deterministically from the already-derived containment_actions front-matter
// (sourced from the FSM history). An empty list renders an honest line.
func renderContainmentSection(actions []string) string {
	var b strings.Builder
	b.WriteString("## Containment actions\n\n")
	if len(actions) == 0 {
		b.WriteString("No containment action was recorded for this incident.\n")
		return b.String()
	}
	for _, a := range actions {
		fmt.Fprintf(&b, "- %s\n", a)
	}
	return b.String()
}

// renderATTACKSection renders the MITRE ATT&CK for Containers section (AC3)
// deterministically from the techniques sourced off the persisted
// ThreatAssessment. When no technique is available the section renders the
// explicit honest line rather than letting the model fabricate a technique
// (round-1 review follow-up: PO Option A, the gap is stated, not filled).
func renderATTACKSection(techniques []string) string {
	var b strings.Builder
	b.WriteString("## MITRE ATT&CK for Containers\n\n")
	if len(techniques) == 0 {
		b.WriteString("No MITRE ATT&CK for Containers technique was recorded for this incident.\n")
		return b.String()
	}
	for _, tech := range techniques {
		fmt.Fprintf(&b, "- %s\n", tech)
	}
	return b.String()
}

// renderPostureSection renders the contributing-posture-findings section (AC3)
// deterministically from the force-stamped contributing_posture_findings
// front-matter (sourced from the package WorkloadPosture, NEVER from model
// output: round-2 review follow-up). An empty list renders the honest "not
// recorded" line rather than letting the model fabricate a posture finding it
// has no data for (PO Option A).
func renderPostureSection(findings []string) string {
	var b strings.Builder
	b.WriteString("## Contributing posture findings\n\n")
	if len(findings) == 0 {
		b.WriteString("No contributing posture finding was recorded for this incident.\n")
		return b.String()
	}
	for _, f := range findings {
		fmt.Fprintf(&b, "- %s\n", f)
	}
	return b.String()
}

// writeYAMLScalar writes a single quoted YAML key/value, escaping the value so
// a model-controlled string cannot break the block (it is always a double-quoted
// scalar). YAML double-quoted scalars escape backslash and double-quote.
func writeYAMLScalar(b *strings.Builder, key, val string) {
	fmt.Fprintf(b, "%s: %s\n", key, quoteYAML(val))
}

// writeYAMLList writes a YAML block-sequence; an empty list renders as `key: []`.
func writeYAMLList(b *strings.Builder, key string, items []string) {
	if len(items) == 0 {
		fmt.Fprintf(b, "%s: []\n", key)
		return
	}
	fmt.Fprintf(b, "%s:\n", key)
	for _, it := range items {
		fmt.Fprintf(b, "  - %s\n", quoteYAML(it))
	}
}

// quoteYAML returns s as a double-quoted YAML scalar with backslash, double
// quote, and control characters escaped. Newlines and tabs are escaped so a
// multi-line model string stays on one logical line and cannot inject extra
// YAML keys.
func quoteYAML(s string) string {
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

// ReportGenerated is the REPORTS.generated wire event (schema_version
// reports.generated.v1): the Story 4.4 DFIR-report announcement (AC5). It is
// published when the DFIR agent has generated a ForensicReport for a finalised
// incident, carrying the report SHA256 and the content-addressed report URL.
//
// ReportURL is NAMED NEUTRALLY (backend-neutral S3-compatible storage, PO
// ratification OA4): it is the COMPUTED content-addressed key the report WOULD
// occupy (reports/{yyyy}/{mm}/{dd}/{sha256}.md), NOT an AWS-specific s3_url. The
// actual durable write + KMS + object-lock are Story 4.6 (out of scope); in
// traceability provenance this field maps to AC5's "S3 URL". This carries NO
// LLM-cappable confidence or score field (the trust-bound fence): it is a pure
// metadata announcement of a produced artifact.
type ReportGenerated struct {
	SchemaVersion string `json:"schema_version"`
	// IncidentID is the finalised incident's package_id (the report subject).
	IncidentID string `json:"incident_id"`
	// WorkloadID is the workload the incident keyed on.
	WorkloadID string `json:"workload_id"`
	// ReportSHA256 is the lowercase-hex SHA256 of the rendered report bytes.
	ReportSHA256 string `json:"report_sha256"`
	// ReportURL is the COMPUTED content-addressed key the report would occupy
	// (reports/{yyyy}/{mm}/{dd}/{sha256}.md). Backend-neutral; the durable
	// write is Story 4.6 (OA4). Maps to AC5's "S3 URL".
	ReportURL string `json:"report_url"`
	// FinalFSMState echoes the report's final FSM state for consumer routing.
	FinalFSMState string `json:"final_fsm_state"`
	// GeneratedAt is the report generation time.
	GeneratedAt time.Time `json:"generated_at"`
}

// reportSHA256 returns the lowercase-hex SHA256 of the rendered report bytes.
func reportSHA256(rendered string) string {
	sum := sha256.Sum256([]byte(rendered))
	return hex.EncodeToString(sum[:])
}

// contentAddressedKey computes the content-addressed report key the report
// would occupy under the S3-compatible layout (OA4): reports/{yyyy}/{mm}/{dd}/
// {sha256}.md. The date partition is the generation time (UTC), so a report's
// key is deterministic from its content + generation day. This is the URL field
// 4.4 populates; the durable write is Story 4.6.
func contentAddressedKey(generatedAt time.Time, sha string) string {
	t := generatedAt.UTC()
	return fmt.Sprintf("reports/%04d/%02d/%02d/%s.md", t.Year(), int(t.Month()), t.Day(), sha)
}
