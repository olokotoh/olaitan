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

// validReportJSON is a schema-conforming model reply. The deterministic
// front-matter fields are present (the schema requires them) but the runner
// overwrites them from the incident; the body and posture findings are the
// model output the runner keeps.
const validReportJSON = `{
  "incident_id": "model-supplied-id",
  "final_fsm_state": "QUARANTINED",
  "threat_score_at_decision": 12,
  "attack_techniques": ["T9999"],
  "contributing_posture_findings": ["overly-broad RBAC binding cluster-admin"],
  "containment_actions": ["model action"],
  "report_generated_at": "2026-01-01T00:00:00Z",
  "prompt_hash": "model-hash",
  "dfir_provider": "model-provider",
  "dfir_model": "model-model",
  "body": "## Kill-chain timeline\nexecve xmrig\n\n## MITRE ATT&CK\nT1611\n\n## Posture\nRBAC\n\n## Containment\nQUARANTINED applied\n\n## Narrative\nThe miner ran."
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
	a, err := NewDFIR(fp, PromptSpec{System: "you are the DFIR analyst", Version: "dfir.test.v1"}, rp, ar, reg, nil)
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
	if strings.Contains(rendered, "T9999") {
		t.Error("rendered report leaked the model-supplied technique T9999 (must source from the assessment)")
	}
	if strings.Contains(rendered, "model-supplied-id") {
		t.Error("rendered report leaked the model-supplied incident_id (must source from the event)")
	}
	// Body (model output) is preserved.
	if !strings.Contains(rendered, "The miner ran.") {
		t.Error("rendered report dropped the model body")
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
		Body:                        "body",
	}
	rendered := r.Render()
	// The injected key must be escaped, not a live YAML key.
	if strings.Contains(rendered, "\ninjected: true") {
		t.Errorf("model string broke out of the quoted scalar\n%s", rendered)
	}
	if strings.Contains(rendered, "finding with\nnewline") {
		t.Errorf("a newline in a posture finding was not escaped\n%s", rendered)
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

// TestParseForensicReport_FenceStripped: a fenced reply is fence-stripped and
// parses; a whitespace-only body is rejected.
func TestParseForensicReport_FenceStripped(t *testing.T) {
	sch, err := reportSchema.compiled()
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	fenced := "```json\n" + validReportJSON + "\n```"
	if _, perr := parseForensicReport(sch, fenced); perr != nil {
		t.Errorf("fenced valid report must parse: %v", perr)
	}
	blank := `{"incident_id":"i","final_fsm_state":"RESTRICTED","threat_score_at_decision":1,"report_generated_at":"2026-01-01T00:00:00Z","prompt_hash":"h","dfir_provider":"claude","dfir_model":"m","body":"   "}`
	if _, perr := parseForensicReport(sch, blank); perr == nil {
		t.Error("a whitespace-only body must be rejected")
	}
}
