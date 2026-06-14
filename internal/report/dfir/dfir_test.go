package dfir

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/agent/provider"
	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/response/settling"
	"github.com/olokotoh/olaitan/internal/schema"
)

// fakeProvider mirrors the analyst fakeProvider: a scripted provider.Provider.
// failTimes returns (failResp, failErr) for the first failTimes calls before
// falling through to (resp, err), so a "fail N then succeed" retry script can be
// expressed.
type fakeProvider struct {
	name      string
	model     string
	resp      provider.Response
	err       error
	got       provider.Request
	calls     int
	failTimes int
	failResp  provider.Response
	failErr   error
}

func (f *fakeProvider) Name() string                 { return f.name }
func (f *fakeProvider) Model() string                { return f.model }
func (f *fakeProvider) MaxContextTokens() int        { return 200000 }
func (f *fakeProvider) ScoreCap() int                { return 35 }
func (f *fakeProvider) SupportsStreaming() bool      { return false }
func (f *fakeProvider) Health(context.Context) error { return nil }

func (f *fakeProvider) Analyse(_ context.Context, req provider.Request) (provider.Response, error) {
	f.calls++
	f.got = req
	if f.failTimes > 0 {
		f.failTimes--
		return f.failResp, f.failErr
	}
	return f.resp, f.err
}

// fakeReportPublisher captures REPORTS.generated emissions.
type fakeReportPublisher struct {
	events []ReportGenerated
	err    error
}

func (p *fakeReportPublisher) PublishReportGenerated(_ context.Context, evt ReportGenerated) error {
	if p.err != nil {
		return p.err
	}
	p.events = append(p.events, evt)
	return nil
}

// fakeAuditRecorder captures AUDIT.assessments DFIR rows.
type fakeAuditRecorder struct {
	records []DFIRAuditRecord
}

func (r *fakeAuditRecorder) RecordDFIRAssessment(_ context.Context, rec DFIRAuditRecord) error {
	r.records = append(r.records, rec)
	return nil
}

// validReportJSON is a schema-conforming model reply. Per the round-2 review
// follow-up the model contract requires ONLY the narrative, so this mirrors what
// a real model returns under the DFIR prompt ("return a single JSON document
// carrying ONLY the narrative field"): a narrative-only document. The
// controller force-stamps EVERY other field (the deterministic front-matter +
// the posture findings) after validation; the factual sections (timeline,
// containment, ATT&CK, posture) are rendered deterministically by the runner,
// NOT from the model.
const validReportJSON = `{
  "narrative": "The miner ran."
}`

func testIncident() Incident {
	return Incident{
		Event: settling.IncidentFinalised{
			SchemaVersion: settling.SchemaVersionIncidentFinalised,
			PackageID:     "pkg-dfir-1",
			WorkloadID:    "ns/Deployment/web",
			FinalState:    "QUARANTINED",
			ThreatScore:   42.5,
			FinalisedAt:   time.Date(2026, 6, 14, 10, 0, 0, 0, time.UTC),
			History: []schema.StateTransition{
				{ToState: schema.PodSecurityState("SUSPICIOUS")},
				{ToState: schema.PodSecurityState("RESTRICTED")},
				{ToState: schema.PodSecurityState("QUARANTINED")},
			},
		},
		Package: schema.EvidencePackage{
			PackageID:  "pkg-dfir-1",
			WorkloadID: "ns/Deployment/web",
		},
		Assessment: &schema.ThreatAssessment{
			MitreTechniques: []string{"T1611"},
			KillChainStage:  "execution",
		},
	}
}

func newAgent(t *testing.T, fp *fakeProvider, rp ReportPublisher, ar AuditRecorder) *Agent {
	t.Helper()
	reg := metrics.NewRegistry()
	a, err := NewDFIR(fp, PromptSpec{System: "you are the DFIR analyst", Version: "dfir.test.v1"}, rp, ar, nil, reg, nil)
	if err != nil {
		t.Fatalf("NewDFIR: %v", err)
	}
	// Pin the clock so report_generated_at and the content key are deterministic.
	a.now = func() time.Time { return time.Date(2026, 6, 14, 10, 0, 5, 0, time.UTC) }
	return a
}

// TestGenerate_SchemaConformingRender: a schema-conforming reply yields a valid
// rendered ForensicReport announced on REPORTS.generated, with the deterministic
// front-matter SOURCED from the incident (not the model's values).
func TestGenerate_SchemaConformingRender(t *testing.T) {
	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8", resp: provider.Response{Raw: validReportJSON, StopReason: "end_turn", Model: "claude-opus-4-8"}}
	rp := &fakeReportPublisher{}
	ar := &fakeAuditRecorder{}
	a := newAgent(t, fp, rp, ar)

	rendered, reported, err := a.Generate(context.Background(), testIncident())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !reported {
		t.Fatal("expected reported=true")
	}
	// Front-matter is authoritative-sourced, NOT the model's values.
	for _, want := range []string{
		"schema_version: \"report.v1\"",
		"incident_id: \"pkg-dfir-1\"",
		"final_fsm_state: \"QUARANTINED\"",
		"threat_score_at_decision: 42.5",
		"prompt_hash: \"dfir.test.v1\"",
		"dfir_provider: \"claude\"",
		"dfir_model: \"claude-opus-4-8\"",
		"- \"T1611\"", // technique from the assessment, not the model's T9999
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("rendered report missing %q\n---\n%s", want, rendered)
		}
	}
	// With a narrative-only model reply and no package posture, the posture
	// front-matter is empty and the section prints the honest "not recorded" line
	// (posture is force-stamped from the package, never modelled).
	if !strings.Contains(rendered, "contributing_posture_findings: []") {
		t.Errorf("posture front-matter must be empty for a nil package posture\n%s", rendered)
	}
	if !strings.Contains(rendered, "No contributing posture finding was recorded for this incident.") {
		t.Errorf("posture section must print the honest not-recorded line\n%s", rendered)
	}
	// The narrative (model output) is preserved under the narrative section.
	if !strings.Contains(rendered, "## Analyst narrative") || !strings.Contains(rendered, "The miner ran.") {
		t.Error("rendered report dropped the model narrative")
	}
	// REPORTS.generated emitted with SHA + content-addressed key.
	if len(rp.events) != 1 {
		t.Fatalf("want 1 REPORTS.generated event, got %d", len(rp.events))
	}
	ev := rp.events[0]
	if ev.IncidentID != "pkg-dfir-1" || ev.WorkloadID != "ns/Deployment/web" || ev.FinalFSMState != "QUARANTINED" {
		t.Errorf("announcement metadata wrong: %+v", ev)
	}
	if len(ev.ReportSHA256) != 64 {
		t.Errorf("report SHA256 not 64 hex chars: %q", ev.ReportSHA256)
	}
	wantKey := "reports/2026/06/14/" + ev.ReportSHA256 + ".md"
	if ev.ReportURL != wantKey {
		t.Errorf("content-addressed key = %q, want %q", ev.ReportURL, wantKey)
	}
	// AUDIT.assessments DFIR row recorded with the prompt hash.
	if len(ar.records) != 1 {
		t.Fatalf("want 1 audit record, got %d", len(ar.records))
	}
	if ar.records[0].Status != statusSuccess || ar.records[0].PromptVersion != "dfir.test.v1" {
		t.Errorf("audit record wrong: %+v", ar.records[0])
	}
}

// TestGenerate_SchemaViolationFailsClosed: a schema-violating reply generates NO
// report, records the failure in AUDIT.assessments, and announces nothing
// (fail-closed, OA5).
func TestGenerate_SchemaViolationFailsClosed(t *testing.T) {
	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8", resp: provider.Response{Raw: `{"body": 123}`, StopReason: "end_turn"}}
	rp := &fakeReportPublisher{}
	ar := &fakeAuditRecorder{}
	a := newAgent(t, fp, rp, ar)

	rendered, reported, err := a.Generate(context.Background(), testIncident())
	if !errors.Is(err, ErrSchemaViolation) {
		t.Fatalf("want ErrSchemaViolation, got %v", err)
	}
	if reported || rendered != "" {
		t.Fatal("a schema-violating reply must not produce a report")
	}
	if len(rp.events) != 0 {
		t.Error("fail-closed must announce nothing on REPORTS.generated")
	}
	if len(ar.records) != 1 || ar.records[0].Status != statusSchemaViolation {
		t.Errorf("the failure must be recorded in AUDIT.assessments with schema_violation status, got %+v", ar.records)
	}
}

// TestGenerate_ProviderUnavailableFailsClosed: a provider error fails closed and
// audits the unavailable status.
func TestGenerate_ProviderUnavailableFailsClosed(t *testing.T) {
	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8", err: errors.New("dial timeout")}
	rp := &fakeReportPublisher{}
	ar := &fakeAuditRecorder{}
	a := newAgent(t, fp, rp, ar)

	_, reported, err := a.Generate(context.Background(), testIncident())
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("want ErrProviderUnavailable, got %v", err)
	}
	if reported {
		t.Fatal("a provider failure must not report")
	}
	if len(ar.records) != 1 || ar.records[0].Status != statusUnavailable {
		t.Errorf("provider failure must audit unavailable, got %+v", ar.records)
	}
}

// TestGenerate_TruncationIsFailure: a max_tokens stop reason is a fail-closed
// failure (a truncated report must never be persisted, BI-7).
func TestGenerate_TruncationIsFailure(t *testing.T) {
	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8", resp: provider.Response{Raw: validReportJSON, StopReason: "max_tokens"}}
	rp := &fakeReportPublisher{}
	ar := &fakeAuditRecorder{}
	a := newAgent(t, fp, rp, ar)

	_, reported, err := a.Generate(context.Background(), testIncident())
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("a max_tokens truncation must fail closed, got %v", err)
	}
	if reported || len(rp.events) != 0 {
		t.Fatal("a truncated report must never be announced")
	}
	if len(ar.records) != 1 || ar.records[0].Status != statusUnavailable {
		t.Errorf("truncation must audit unavailable, got %+v", ar.records)
	}
}

// TestGenerate_RedeliveryIsIdempotent: a redelivery of the same finalisation
// (same FinalisedMsgID) does not emit a second report.
func TestGenerate_RedeliveryIsIdempotent(t *testing.T) {
	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8", resp: provider.Response{Raw: validReportJSON, StopReason: "end_turn"}}
	rp := &fakeReportPublisher{}
	ar := &fakeAuditRecorder{}
	a := newAgent(t, fp, rp, ar)
	inc := testIncident()

	if _, reported, err := a.Generate(context.Background(), inc); err != nil || !reported {
		t.Fatalf("first delivery: reported=%v err=%v", reported, err)
	}
	// Redelivery of the SAME finalisation.
	rendered2, reported2, err := a.Generate(context.Background(), inc)
	if err != nil {
		t.Fatalf("redelivery returned an error: %v", err)
	}
	if reported2 || rendered2 != "" {
		t.Fatal("a redelivery must not emit a second report")
	}
	if fp.calls != 1 {
		t.Errorf("a redelivery must not spend a second provider call, got %d", fp.calls)
	}
	if len(rp.events) != 1 {
		t.Errorf("a redelivery must not announce a second report, got %d", len(rp.events))
	}
}

// TestGenerate_DistinctIncidentNotSuppressed: a different finalisation (distinct
// FinalisedMsgID) IS reported even after a prior report.
func TestGenerate_DistinctIncidentNotSuppressed(t *testing.T) {
	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8", resp: provider.Response{Raw: validReportJSON, StopReason: "end_turn"}}
	rp := &fakeReportPublisher{}
	a := newAgent(t, fp, rp, nil)

	inc1 := testIncident()
	inc2 := testIncident()
	inc2.Event.PackageID = "pkg-dfir-2"
	inc2.Event.FinalisedAt = inc1.Event.FinalisedAt.Add(time.Second)

	if _, r1, _ := a.Generate(context.Background(), inc1); !r1 {
		t.Fatal("first incident not reported")
	}
	if _, r2, _ := a.Generate(context.Background(), inc2); !r2 {
		t.Fatal("a distinct incident must be reported")
	}
	if len(rp.events) != 2 {
		t.Errorf("want 2 announcements for 2 distinct incidents, got %d", len(rp.events))
	}
}

// TestGenerate_EmptyHistoryTolerated: an empty FSM history still renders, with
// the containment falling back to the final state alone (BI-9).
func TestGenerate_EmptyHistoryTolerated(t *testing.T) {
	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8", resp: provider.Response{Raw: validReportJSON, StopReason: "end_turn"}}
	a := newAgent(t, fp, &fakeReportPublisher{}, nil)
	inc := testIncident()
	inc.Event.History = nil

	rendered, reported, err := a.Generate(context.Background(), inc)
	if err != nil || !reported {
		t.Fatalf("empty history must still render: reported=%v err=%v", reported, err)
	}
	if !strings.Contains(rendered, "applied QUARANTINED") {
		t.Errorf("empty-history containment must fall back to the final state\n%s", rendered)
	}
}

// TestGenerate_RedactionContract: the runner must NEVER interpolate evidence into
// the Prompt; all evidence travels on Request.Package, and the prompt text is the
// fixed instruction only.
func TestGenerate_RedactionContract(t *testing.T) {
	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8", resp: provider.Response{Raw: validReportJSON, StopReason: "end_turn"}}
	a := newAgent(t, fp, &fakeReportPublisher{}, nil)
	inc := testIncident()
	if _, _, err := a.Generate(context.Background(), inc); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if fp.got.Prompt.User != dfirUserInstruction {
		t.Error("the user prompt must be the fixed instruction (no evidence interpolation)")
	}
	if fp.got.Role != provider.RoleDFIR {
		t.Errorf("the request role must be RoleDFIR, got %q", fp.got.Role)
	}
	if fp.got.Package.PackageID != inc.Package.PackageID {
		t.Error("evidence must travel on Request.Package")
	}
	// The prompt must not carry the workload id or threat score (would imply
	// interpolated evidence/framing).
	if strings.Contains(fp.got.Prompt.User, inc.Event.WorkloadID) {
		t.Error("the prompt must not interpolate the workload id")
	}
}

// TestGenerate_PromptHashAudit: the front-matter prompt_hash matches the loaded
// spec version and the AUDIT.assessments dfir PromptVersion (AC6).
func TestGenerate_PromptHashAudit(t *testing.T) {
	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8", resp: provider.Response{Raw: validReportJSON, StopReason: "end_turn"}}
	ar := &fakeAuditRecorder{}
	a := newAgent(t, fp, &fakeReportPublisher{}, ar)
	rendered, _, err := a.Generate(context.Background(), testIncident())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.Contains(rendered, "prompt_hash: \"dfir.test.v1\"") {
		t.Errorf("front-matter prompt_hash mismatch\n%s", rendered)
	}
	if len(ar.records) != 1 || ar.records[0].PromptVersion != "dfir.test.v1" {
		t.Errorf("audit prompt version mismatch: %+v", ar.records)
	}
}

// scenarioTechnique pins the five evaluation scenarios to their bound techniques
// (AC6 S1-S5).
var scenarioTechnique = map[string]string{
	"S1": "T1611",
	"S2": "T1552",
	"S3": "T1613",
	"S4": "T1071",
	"S5": "T1496",
}

// TestGenerate_ScenarioTechniqueRendering: each S1-S5 scenario renders with its
// bound technique sourced from the persisted ThreatAssessment (AC6).
func TestGenerate_ScenarioTechniqueRendering(t *testing.T) {
	for scen, tech := range scenarioTechnique {
		scen, tech := scen, tech
		t.Run(scen, func(t *testing.T) {
			fp := &fakeProvider{name: "claude", model: "claude-opus-4-8", resp: provider.Response{Raw: validReportJSON, StopReason: "end_turn"}}
			a := newAgent(t, fp, &fakeReportPublisher{}, nil)
			inc := testIncident()
			inc.Event.PackageID = "pkg-" + scen
			inc.Assessment = &schema.ThreatAssessment{MitreTechniques: []string{tech}}
			rendered, reported, err := a.Generate(context.Background(), inc)
			if err != nil || !reported {
				t.Fatalf("%s: reported=%v err=%v", scen, reported, err)
			}
			if !strings.Contains(rendered, "- \""+tech+"\"") {
				t.Errorf("%s: rendered report missing bound technique %q\n%s", scen, tech, rendered)
			}
		})
	}
}

// TestGenerate_NilAssessmentTechniquesOmitted: a finalisation with no persisted
// assessment renders the techniques list empty (BI-9: it does not assume a
// bundle/assessment exists).
func TestGenerate_NilAssessmentTechniquesOmitted(t *testing.T) {
	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8", resp: provider.Response{Raw: validReportJSON, StopReason: "end_turn"}}
	a := newAgent(t, fp, &fakeReportPublisher{}, nil)
	inc := testIncident()
	inc.Assessment = nil
	rendered, _, err := a.Generate(context.Background(), inc)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.Contains(rendered, "attack_techniques: []") {
		t.Errorf("nil assessment must render an empty techniques list\n%s", rendered)
	}
}

// TestRender_YAMLEscaping: a model-supplied posture finding with a newline /
// quote cannot break out of the YAML front-matter block.
func TestRender_YAMLEscaping(t *testing.T) {
	r := ForensicReport{
		IncidentID:                  "id\"injected: true",
		FinalFSMState:               "RESTRICTED",
		ContributingPostureFindings: []string{"finding with\nnewline", "quote\"here"},
		ReportGeneratedAt:           time.Unix(0, 0).UTC(),
		PromptHash:                  "h",
		DFIRProvider:                "claude",
		DFIRModel:                   "claude-opus-4-8",
		Narrative:                   "narrative",
	}
	rendered := r.Render(settling.IncidentFinalised{})
	// The escaping contract guards the YAML FRONT-MATTER block (between the two
	// --- fences), where a breakout would inject a live YAML key. The Markdown
	// body sections legitimately render multi-line content as bullets, so the
	// assertion is scoped to the front-matter.
	frontMatter := rendered
	if _, after, ok := strings.Cut(rendered, "---\n"); ok {
		if fm, _, ok2 := strings.Cut(after, "\n---\n"); ok2 {
			frontMatter = fm
		}
	}
	// The injected key must be escaped, not a live YAML key.
	if strings.Contains(frontMatter, "\ninjected: true") {
		t.Errorf("model string broke out of the quoted scalar\n%s", rendered)
	}
	if strings.Contains(frontMatter, "finding with\nnewline") {
		t.Errorf("a newline in a posture finding was not escaped in the front-matter\n%s", rendered)
	}
}

// TestReportGenerated_WireRoundTrip: the wire event round-trips and carries the
// neutral report_url field name (not s3_url) per OA4.
func TestReportGenerated_WireRoundTrip(t *testing.T) {
	evt := ReportGenerated{
		SchemaVersion: SchemaVersionReportGenerated,
		IncidentID:    "pkg-1",
		WorkloadID:    "wl",
		ReportSHA256:  "abc",
		ReportURL:     "reports/2026/06/14/abc.md",
		FinalFSMState: "QUARANTINED",
		GeneratedAt:   time.Unix(0, 0).UTC(),
	}
	b, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	js := string(b)
	if !strings.Contains(js, "\"report_url\"") {
		t.Error("wire event must use the neutral report_url field name")
	}
	if strings.Contains(js, "s3_url") {
		t.Error("wire event must NOT name the field s3_url (OA4 backend-neutral)")
	}
	var back ReportGenerated
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back != evt {
		t.Errorf("round-trip mismatch: %+v vs %+v", back, evt)
	}
}

// TestDecodeIncident: a wire IncidentFinalised decodes into a minimal Incident
// carrying the package/workload ids on Request.Package.
func TestDecodeIncident(t *testing.T) {
	evt := settling.IncidentFinalised{
		SchemaVersion: settling.SchemaVersionIncidentFinalised,
		PackageID:     "pkg-x",
		WorkloadID:    "wl-x",
		FinalState:    "RESTRICTED",
		ThreatScore:   7,
		FinalisedAt:   time.Unix(0, 0).UTC(),
	}
	b, _ := json.Marshal(evt)
	inc, err := decodeIncident(b)
	if err != nil {
		t.Fatalf("decodeIncident: %v", err)
	}
	if inc.Event.PackageID != "pkg-x" || inc.Package.PackageID != "pkg-x" || inc.Package.WorkloadID != "wl-x" {
		t.Errorf("decoded incident wrong: %+v", inc)
	}
}

// TestGenerate_NarrativeGroundedViaPriorAssessment: the provider receives a
// PriorAssessment whose Reasoning carries the FSM transition summary, AND no pod
// name or raw event id leaks into the prompt or the PriorAssessment (round-1
// review follow-up R1-HIGH-1). This exercises the SYNTHESISED path (no persisted
// assessment), the production case.
func TestGenerate_NarrativeGroundedViaPriorAssessment(t *testing.T) {
	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8", resp: provider.Response{Raw: validReportJSON, StopReason: "end_turn"}}
	a := newAgent(t, fp, &fakeReportPublisher{}, nil)

	inc := testIncident()
	inc.Assessment = nil // synthesised grounding path
	// History carrying control-plane facts plus a pod name + raw event ids that
	// must NOT leak into the grounding channel.
	const podName = "web-7c9b-pod-leak"
	const eventID = "evt-raw-id-leak-123"
	inc.Event.History = []schema.StateTransition{
		{
			Timestamp:     time.Date(2026, 6, 14, 9, 59, 0, 0, time.UTC),
			FromState:     schema.PodSecurityState("SUSPICIOUS"),
			ToState:       schema.PodSecurityState("RESTRICTED"),
			Reason:        "escalation_threshold_crossed",
			Confidence:    55,
			Pod:           schema.PodRef{Name: podName},
			TriggerEvents: []string{eventID},
		},
	}

	if _, _, err := a.Generate(context.Background(), inc); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	pa := fp.got.PriorAssessment
	if pa == nil {
		t.Fatal("the provider must receive a grounding PriorAssessment")
	}
	// (a) The Reasoning carries the transition summary.
	if !strings.Contains(pa.Reasoning, "SUSPICIOUS -> RESTRICTED") {
		t.Errorf("PriorAssessment.Reasoning must carry the transition summary, got %q", pa.Reasoning)
	}
	if !strings.Contains(pa.Reasoning, "escalation_threshold_crossed") {
		t.Errorf("PriorAssessment.Reasoning must carry the transition reason, got %q", pa.Reasoning)
	}
	if string(pa.RecommendedState) != inc.Event.FinalState || pa.Confidence.Total != inc.Event.ThreatScore {
		t.Errorf("synthesised assessment must mirror the event final state/score, got state=%q total=%v", pa.RecommendedState, pa.Confidence.Total)
	}
	// (b) NO pod name / raw event id leaks into the prompt or the PriorAssessment.
	for _, leak := range []string{podName, eventID} {
		if strings.Contains(pa.Reasoning, leak) {
			t.Errorf("PriorAssessment.Reasoning leaked %q (pod name / raw event id)", leak)
		}
		if strings.Contains(fp.got.Prompt.User, leak) || strings.Contains(fp.got.Prompt.System, leak) {
			t.Errorf("the prompt leaked %q (pod name / raw event id)", leak)
		}
	}
}

// TestGenerate_SchemaViolationRetriesThenFailsClosed: a provider returning
// malformed JSON every time is retried the bounded number of times, then fails
// closed with ErrSchemaViolation (AC6 round-1 review follow-up R1-MED-1).
func TestGenerate_SchemaViolationRetriesThenFailsClosed(t *testing.T) {
	// failTimes large enough that every attempt returns the malformed reply.
	fp := &fakeProvider{
		name: "claude", model: "claude-opus-4-8",
		failTimes: 99,
		failResp:  provider.Response{Raw: `{"narrative": 123}`, StopReason: "end_turn"},
		// Unreached fall-through (would be valid); proves the retry never
		// "succeeds" past the malformed replies.
		resp: provider.Response{Raw: validReportJSON, StopReason: "end_turn"},
	}
	ar := &fakeAuditRecorder{}
	a := newAgent(t, fp, &fakeReportPublisher{}, ar)

	_, reported, err := a.Generate(context.Background(), testIncident())
	if !errors.Is(err, ErrSchemaViolation) {
		t.Fatalf("want ErrSchemaViolation after bounded retry, got %v", err)
	}
	if reported {
		t.Fatal("a persistent schema violation must fail closed")
	}
	if fp.calls != dfirSchemaAttempts {
		t.Errorf("want %d bounded attempts, got %d", dfirSchemaAttempts, fp.calls)
	}
	if len(ar.records) != 1 || ar.records[0].Status != statusSchemaViolation {
		t.Errorf("the exhausted retry must audit schema_violation, got %+v", ar.records)
	}
}

// TestGenerate_SchemaViolationThenSucceeds: a provider that violates once then
// returns a valid reply succeeds within the bounded retry budget (AC6).
func TestGenerate_SchemaViolationThenSucceeds(t *testing.T) {
	fp := &fakeProvider{
		name: "claude", model: "claude-opus-4-8",
		failTimes: 1,
		failResp:  provider.Response{Raw: `{"narrative": 123}`, StopReason: "end_turn"},
		resp:      provider.Response{Raw: validReportJSON, StopReason: "end_turn", Model: "claude-opus-4-8"},
	}
	a := newAgent(t, fp, &fakeReportPublisher{}, nil)
	_, reported, err := a.Generate(context.Background(), testIncident())
	if err != nil || !reported {
		t.Fatalf("a retry-then-success must report: reported=%v err=%v", reported, err)
	}
	if fp.calls != 2 {
		t.Errorf("want 2 attempts (1 violation + 1 success), got %d", fp.calls)
	}
}

// TestRender_DeterministicSections: the rendered report carries the
// deterministic kill-chain timeline assembled from the event history (timestamp,
// from->to, reason, confidence) with pod names / raw event ids STRIPPED, and the
// model never controls those facts (round-1 review follow-up item 1).
func TestRender_DeterministicSections(t *testing.T) {
	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8", resp: provider.Response{Raw: validReportJSON, StopReason: "end_turn"}}
	a := newAgent(t, fp, &fakeReportPublisher{}, nil)

	inc := testIncident()
	inc.Event.History = []schema.StateTransition{
		{
			Timestamp:     time.Date(2026, 6, 14, 9, 58, 0, 0, time.UTC),
			FromState:     schema.PodSecurityState("CLEAN"),
			ToState:       schema.PodSecurityState("SUSPICIOUS"),
			Reason:        "escalation_threshold_crossed",
			Confidence:    40,
			Pod:           schema.PodRef{Name: "leaky-pod-name"},
			TriggerEvents: []string{"leaky-event-id"},
		},
	}
	rendered, _, err := a.Generate(context.Background(), inc)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, want := range []string{
		"## Kill-chain timeline",
		"2026-06-14T09:58:00Z: CLEAN -> SUSPICIOUS (reason: escalation_threshold_crossed, confidence: 40)",
		"## Containment actions",
		"## MITRE ATT&CK for Containers",
		"## Analyst narrative",
		"The miner ran.",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("rendered report missing %q\n---\n%s", want, rendered)
		}
	}
	// Pod name / raw event id must NOT leak into the rendered report.
	for _, leak := range []string{"leaky-pod-name", "leaky-event-id"} {
		if strings.Contains(rendered, leak) {
			t.Errorf("rendered report leaked %q (control-plane facts only)", leak)
		}
	}
}

// TestRender_EmptyHistoryTimeline: an empty history renders the honest
// "no history recorded" timeline line (round-1 review follow-up item 1).
func TestRender_EmptyHistoryTimeline(t *testing.T) {
	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8", resp: provider.Response{Raw: validReportJSON, StopReason: "end_turn"}}
	a := newAgent(t, fp, &fakeReportPublisher{}, nil)
	inc := testIncident()
	inc.Event.History = nil
	rendered, _, err := a.Generate(context.Background(), inc)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.Contains(rendered, "No FSM transition history was recorded for this incident.") {
		t.Errorf("empty history must render the honest gap line\n%s", rendered)
	}
}

// TestRender_NoTechniqueRecorded: a synthesised grounding (no persisted
// assessment) renders the honest "no MITRE technique recorded" line rather than
// a fabricated technique (round-1 review follow-up PO Option A).
func TestRender_NoTechniqueRecorded(t *testing.T) {
	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8", resp: provider.Response{Raw: validReportJSON, StopReason: "end_turn"}}
	a := newAgent(t, fp, &fakeReportPublisher{}, nil)
	inc := testIncident()
	inc.Assessment = nil
	rendered, _, err := a.Generate(context.Background(), inc)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.Contains(rendered, "No MITRE ATT&CK for Containers technique was recorded for this incident.") {
		t.Errorf("a synthesised grounding must render the honest ATT&CK gap line\n%s", rendered)
	}
	if !strings.Contains(rendered, "attack_techniques: []") {
		t.Errorf("front-matter techniques must stay empty for a synthesised grounding\n%s", rendered)
	}
}

// TestParseForensicReport_FenceStripped: a fenced reply is fence-stripped and
// parses; a whitespace-only narrative is rejected.
func TestParseForensicReport_FenceStripped(t *testing.T) {
	sch, err := reportSchema.compiled()
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	fenced := "```json\n" + validReportJSON + "\n```"
	if _, perr := parseForensicReport(sch, fenced); perr != nil {
		t.Errorf("fenced valid report must parse: %v", perr)
	}
	blank := `{"narrative":"   "}`
	if _, perr := parseForensicReport(sch, blank); perr == nil {
		t.Error("a whitespace-only narrative must be rejected")
	}
}

// TestGenerate_NarrativeOnlyResponseValidatesAndRenders is the round-2 review
// follow-up FIX 1 proof: a real model returns a document carrying ONLY the
// narrative (the schema requires only narrative), and the runner produces a
// fully-rendered report with the front-matter force-stamped from the incident.
// This is the assertion prod works: before the fix, a narrative-only reply
// failed validation on the 7 then-required fields and fail-closed produced zero
// reports.
func TestGenerate_NarrativeOnlyResponseValidatesAndRenders(t *testing.T) {
	const narrativeOnly = `{"narrative":"A cryptominer executed inside the workload."}`
	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8", resp: provider.Response{Raw: narrativeOnly, StopReason: "end_turn", Model: "claude-opus-4-8"}}
	rp := &fakeReportPublisher{}
	a := newAgent(t, fp, rp, nil)

	rendered, reported, err := a.Generate(context.Background(), testIncident())
	if err != nil {
		t.Fatalf("a narrative-only reply must validate and render: %v", err)
	}
	if !reported {
		t.Fatal("a narrative-only reply must produce a report")
	}
	// The controller force-stamps the entire front-matter even though the model
	// supplied none of it.
	for _, want := range []string{
		"schema_version: \"report.v1\"",
		"incident_id: \"pkg-dfir-1\"",
		"final_fsm_state: \"QUARANTINED\"",
		"threat_score_at_decision: 42.5",
		"prompt_hash: \"dfir.test.v1\"",
		"dfir_provider: \"claude\"",
		"dfir_model: \"claude-opus-4-8\"",
		"- \"T1611\"", // technique force-stamped from the assessment
		"## Kill-chain timeline",
		"## Containment actions",
		"## MITRE ATT&CK for Containers",
		"## Contributing posture findings",
		"A cryptominer executed inside the workload.",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("rendered report missing %q\n---\n%s", want, rendered)
		}
	}
	if len(rp.events) != 1 {
		t.Fatalf("want 1 REPORTS.generated event, got %d", len(rp.events))
	}
}

// TestGenerate_ModelPostureFindingsDiscarded is the round-2 review follow-up FIX
// 2 proof: posture is force-stamped from the package WorkloadPosture and the
// model never controls it. With a nil package posture (the 4.4 prod case) the
// contributing_posture_findings front-matter is empty and the posture section
// prints the honest "not recorded" line, regardless of model output (the schema
// now forbids unknown fields via additionalProperties:false and the fixture is
// narrative-only, so the model cannot even smuggle posture findings in).
func TestGenerate_ModelPostureFindingsDiscarded(t *testing.T) {
	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8", resp: provider.Response{Raw: validReportJSON, StopReason: "end_turn"}}
	a := newAgent(t, fp, &fakeReportPublisher{}, nil)
	inc := testIncident()
	inc.Package.WorkloadPosture = nil // the 4.4 prod case: no posture snapshot

	rendered, reported, err := a.Generate(context.Background(), inc)
	if err != nil || !reported {
		t.Fatalf("reported=%v err=%v", reported, err)
	}
	if !strings.Contains(rendered, "contributing_posture_findings: []") {
		t.Errorf("a nil package posture must render an empty posture front-matter list\n%s", rendered)
	}
	if !strings.Contains(rendered, "No contributing posture finding was recorded for this incident.") {
		t.Errorf("a nil package posture must render the honest not-recorded posture line\n%s", rendered)
	}
}

// TestGenerate_PosturePresentForceStamped exercises the populated posture path:
// when the package DOES carry a WorkloadPosture, the runner derives the finding
// strings from it (force-stamped), and they render in the posture section.
func TestGenerate_PosturePresentForceStamped(t *testing.T) {
	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8", resp: provider.Response{Raw: validReportJSON, StopReason: "end_turn"}}
	a := newAgent(t, fp, &fakeReportPublisher{}, nil)
	inc := testIncident()
	inc.Package.WorkloadPosture = &schema.WorkloadPosture{
		ClusterRoleBindings: []schema.ClusterRoleBindingRef{{Name: "crb-1", RoleName: "cluster-admin"}},
	}

	rendered, reported, err := a.Generate(context.Background(), inc)
	if err != nil || !reported {
		t.Fatalf("reported=%v err=%v", reported, err)
	}
	if !strings.Contains(rendered, "cluster-role binding grants cluster-admin") {
		t.Errorf("a present posture must render its force-stamped finding\n%s", rendered)
	}
}
