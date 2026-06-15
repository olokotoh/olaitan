package capture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/subjects"
)

// TestEnvelope_RoundTrip asserts the self-describing JSONL envelope (AC2/BI-4)
// marshals to the four-key shape and round-trips with the payload preserved
// verbatim.
func TestEnvelope_RoundTrip(t *testing.T) {
	payload := json.RawMessage(`{"package_id":"pkg-1","schema_version":"evidence.v1"}`)
	env := Envelope{
		SchemaVersion: schemaVersionEvidence,
		PublishedAt:   "2026-06-15T10:00:00Z",
		Subject:       subjects.EvidencePackages,
		Payload:       payload,
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// The envelope's four keys are present.
	for _, key := range []string{"schema_version", "published_at", "subject", "payload"} {
		if !strings.Contains(string(b), `"`+key+`"`) {
			t.Errorf("envelope JSON missing key %q: %s", key, b)
		}
	}
	var back Envelope
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Subject != subjects.EvidencePackages {
		t.Errorf("subject = %q; want %q", back.Subject, subjects.EvidencePackages)
	}
	// The payload's own schema_version is preserved INSIDE the payload (BI-4).
	var inner struct {
		PackageID     string `json:"package_id"`
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(back.Payload, &inner); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if inner.PackageID != "pkg-1" || inner.SchemaVersion != "evidence.v1" {
		t.Errorf("payload not preserved verbatim: %+v", inner)
	}
}

// TestJSONLSpecs_UseRealSubjectConstants asserts the artefact->subject map uses
// the REAL internal/subjects constants (BI-1), NEVER hard-coded strings, and
// that assessments sources ONLY AUDIT.assessments (BI-2).
func TestJSONLSpecs_UseRealSubjectConstants(t *testing.T) {
	specs := jsonlSpecs()
	bySubject := map[string]jsonlSpec{}
	for _, s := range specs {
		bySubject[s.artefact] = s
	}
	cases := []struct {
		artefact    string
		wantSubject string
		wantStream  string
	}{
		{EventsArtefact, subjects.RawPrefix + ">", "EVENTS_RAW"},
		{EvidenceArtefact, subjects.EvidencePackages, "EVIDENCE"},
		{AssessmentsArtefact, subjects.AuditAssessments, "AUDIT_ASSESSMENTS"},
		{FSMArtefact, subjects.AuditTransitions, "AUDIT_TRANSITIONS"},
	}
	for _, c := range cases {
		s, ok := bySubject[c.artefact]
		if !ok {
			t.Errorf("no spec for artefact %q", c.artefact)
			continue
		}
		if s.filterSubject != c.wantSubject {
			t.Errorf("%s subject = %q; want %q", c.artefact, s.filterSubject, c.wantSubject)
		}
		if s.stream != c.wantStream {
			t.Errorf("%s stream = %q; want %q", c.artefact, s.stream, c.wantStream)
		}
	}
	// assessments uses the single real subject (BI-2): no ASSESSMENTS.completed.
	if bySubject[AssessmentsArtefact].filterSubject != subjects.AuditAssessments {
		t.Errorf("assessments must source only AUDIT.assessments (BI-2)")
	}
	// report uses REPORTS.generated.
	if reportSpec().filterSubject != subjects.ReportsGenerated {
		t.Errorf("report subject = %q; want %q", reportSpec().filterSubject, subjects.ReportsGenerated)
	}
}

// TestMeasure_FloorAndExactCriteria exercises the floor-aware measure-vs-target
// logic (BI-9) across detect/miss cases.
func TestMeasure_FloorAndExactCriteria(t *testing.T) {
	start := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	transAt := start.Add(15 * time.Second)

	tx := func(state string, at time.Time) json.RawMessage {
		b, _ := json.Marshal(map[string]any{"after_state": state, "decided_at": at})
		return b
	}

	t.Run("exact match within budget passes", func(t *testing.T) {
		m := Measure([]json.RawMessage{tx("SUSPICIOUS", transAt)}, nil,
			Target{FSMState: "SUSPICIOUS", TimeToDetectSeconds: 30, Floor: false}, start)
		if !m.SuccessCriterionMet {
			t.Errorf("exact-match SUSPICIOUS within 30s should pass: %+v", m)
		}
		if m.MeasuredTimeToDetect != 15 {
			t.Errorf("ttd = %d; want 15", m.MeasuredTimeToDetect)
		}
		if m.FSMStateSource != FSMSourceObservedTransitions {
			t.Errorf("fsm_state_source = %q; want observed_transitions", m.FSMStateSource)
		}
	})

	t.Run("floor: higher state passes", func(t *testing.T) {
		m := Measure([]json.RawMessage{tx("QUARANTINED", transAt)}, nil,
			Target{FSMState: "RESTRICTED", TimeToDetectSeconds: 30, Floor: true}, start)
		if !m.SuccessCriterionMet {
			t.Errorf("floor RESTRICTED met by QUARANTINED should pass: %+v", m)
		}
		if m.MeasuredFinalFSMState != "QUARANTINED" {
			t.Errorf("final state = %q; want QUARANTINED (highest observed)", m.MeasuredFinalFSMState)
		}
	})

	t.Run("exact: higher state fails (not floor)", func(t *testing.T) {
		m := Measure([]json.RawMessage{tx("QUARANTINED", transAt)}, nil,
			Target{FSMState: "RESTRICTED", TimeToDetectSeconds: 30, Floor: false}, start)
		if m.SuccessCriterionMet {
			t.Errorf("exact RESTRICTED must NOT be met by QUARANTINED: %+v", m)
		}
	})

	t.Run("over the time budget fails", func(t *testing.T) {
		late := start.Add(45 * time.Second)
		m := Measure([]json.RawMessage{tx("SUSPICIOUS", late)}, nil,
			Target{FSMState: "SUSPICIOUS", TimeToDetectSeconds: 30, Floor: false}, start)
		if m.SuccessCriterionMet {
			t.Errorf("detect at 45s over a 30s budget must fail: %+v", m)
		}
	})

	t.Run("no signal is a never-detected miss", func(t *testing.T) {
		m := Measure(nil, nil, Target{FSMState: "SUSPICIOUS", TimeToDetectSeconds: 30}, start)
		if m.SuccessCriterionMet {
			t.Errorf("no-signal run must be a miss")
		}
		if m.MeasuredTimeToDetect != NeverDetectedSentinel {
			t.Errorf("ttd = %d; want sentinel %d", m.MeasuredTimeToDetect, NeverDetectedSentinel)
		}
		if m.FSMStateSource != FSMSourceNone {
			t.Errorf("fsm_state_source = %q; want none", m.FSMStateSource)
		}
	})
}

// TestMeasure_DetectionSignalOnly asserts BI-8 honesty: with an EvidencePackage
// signal but NO FSM transition, the final state is the detection-signal state
// labelled detection_signal_only (never a fabricated transition state).
func TestMeasure_DetectionSignalOnly(t *testing.T) {
	start := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	ev, _ := json.Marshal(map[string]any{"assembled_at": start.Add(10 * time.Second)})
	m := Measure(nil, []json.RawMessage{ev},
		Target{FSMState: "SUSPICIOUS", TimeToDetectSeconds: 30, Floor: false}, start)
	if m.FSMStateSource != FSMSourceDetectionSignalOnly {
		t.Errorf("fsm_state_source = %q; want detection_signal_only", m.FSMStateSource)
	}
	if m.MeasuredFinalFSMState != "SUSPICIOUS" {
		t.Errorf("detection-signal state = %q; want the target SUSPICIOUS", m.MeasuredFinalFSMState)
	}
	if m.MeasuredTimeToDetect != 10 {
		t.Errorf("ttd = %d; want 10 (evidence assembly time)", m.MeasuredTimeToDetect)
	}
	if !m.SuccessCriterionMet {
		t.Errorf("detection-signal SUSPICIOUS within budget should meet the criterion: %+v", m)
	}
}

// TestCheckSize_UnderAndOver asserts the size cap (AC4/BI-10): under the cap is
// clean, over trips the durable flag, and the artefacts are NOT deleted.
func TestCheckSize_UnderAndOver(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.jsonl"), []byte("hello\nworld\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	under, err := CheckSize(dir, 1024)
	if err != nil {
		t.Fatalf("CheckSize: %v", err)
	}
	if under.SizeCapExceeded {
		t.Errorf("12 bytes under a 1024-byte cap must not trip the alert")
	}
	if under.SizeBytes != 12 {
		t.Errorf("size = %d; want 12", under.SizeBytes)
	}

	over, err := CheckSize(dir, 4)
	if err != nil {
		t.Fatalf("CheckSize: %v", err)
	}
	if !over.SizeCapExceeded {
		t.Errorf("12 bytes over a 4-byte cap must trip the alert")
	}
	// Fail-OPEN: the artefact is still there.
	if _, err := os.Stat(filepath.Join(dir, "a.jsonl")); err != nil {
		t.Errorf("artefact was deleted on cap exceed; the cap must be fail-LOUD not fail-delete")
	}

	// A non-positive cap falls back to the default so a mis-wired flag cannot
	// disable the signal.
	def, err := CheckSize(dir, 0)
	if err != nil {
		t.Fatalf("CheckSize: %v", err)
	}
	if def.Cap != DefaultMaxRunSizeBytes {
		t.Errorf("zero cap = %d; want default %d", def.Cap, DefaultMaxRunSizeBytes)
	}
}

// TestWriteReport_NoReportPath asserts the honest no-S3 / no-report fallback
// (BI-5/OQ3): the file exists and carries an explicit no-report note rather
// than pretending a body was fetched.
func TestWriteReport_NoReportPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ReportArtefact)
	if err := writeReport(path, nil); err != nil {
		t.Fatalf("writeReport: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if !strings.Contains(string(body), "No REPORTS.generated event") {
		t.Errorf("no-report report.md must carry the honest note: %s", body)
	}
}

// TestWriteReport_WithAnnouncement asserts the header projection of a captured
// REPORTS.generated announcement (BI-5).
func TestWriteReport_WithAnnouncement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ReportArtefact)
	payload, _ := json.Marshal(map[string]any{
		"incident_id":     "pkg-9",
		"report_sha256":   "abc123",
		"report_url":      "reports/2026/06/15/abc123.md",
		"final_fsm_state": "QUARANTINED",
	})
	env := Envelope{SchemaVersion: schemaVersionReportEvent, Subject: subjects.ReportsGenerated, Payload: payload}
	if err := writeReport(path, []Envelope{env}); err != nil {
		t.Fatalf("writeReport: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	for _, want := range []string{"pkg-9", "abc123", "reports/2026/06/15/abc123.md", "QUARANTINED", "NOT the report body"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("report.md missing %q:\n%s", want, body)
		}
	}
}

// TestWriteJSONL_EmptyFileExists asserts an empty drain still writes the file
// (AC5: all six artefacts must exist even when a subject carried no traffic).
func TestWriteJSONL_EmptyFileExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, EventsArtefact)
	if err := writeJSONL(path, nil); err != nil {
		t.Fatalf("writeJSONL: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("empty artefact missing: %v", err)
	}
	if fi.Size() != 0 {
		t.Errorf("empty drain wrote %d bytes; want an empty file", fi.Size())
	}
}

// TestCapture_NilClientWritesEmptyArtefacts asserts the no-NATS path writes all
// five non-metadata artefacts empty (AC5) without fabricating traffic.
func TestCapture_NilClientWritesEmptyArtefacts(t *testing.T) {
	dir := t.TempDir()
	c := New(Config{Client: nil})
	res, err := c.Capture(t.Context(), dir)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if res.Counts.Events != 0 || res.Counts.Evidence != 0 || res.Counts.Reports != 0 {
		t.Errorf("nil-client drain captured traffic: %+v", res.Counts)
	}
	for _, name := range []string{EventsArtefact, EvidenceArtefact, AssessmentsArtefact, FSMArtefact, ReportArtefact} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("artefact %q missing on the no-NATS path: %v", name, err)
		}
	}
}
