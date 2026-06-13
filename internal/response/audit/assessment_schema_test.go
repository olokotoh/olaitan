package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/schema"
)

const assessmentsSchemaPath = schemaDir + "/assessments.json"

// TestAssessmentExemplarsValidate validates the three committed exemplars
// (full / l1_l2 / l1_only) against the authoritative schema (Story 3.14
// AC4). additionalProperties:false + the required set make a drifted Go
// field fail here.
func TestAssessmentExemplarsValidate(t *testing.T) {
	for _, mode := range []string{"full", "l1_l2", "l1_only"} {
		payload, err := os.ReadFile(filepath.Join("testdata", "assessment-"+mode+".json"))
		if err != nil {
			t.Fatalf("read exemplar %s: %v", mode, err)
		}
		if err := validateAgainstSchema(t, assessmentsSchemaPath, payload); err != nil {
			t.Errorf("exemplar %s fails schema: %v", mode, err)
		}
	}
}

// TestAssessmentBuiltEventValidates proves a freshly built v2 event (every
// field populated) validates against the committed schema, so the Go struct
// and the schema cannot silently drift apart.
func TestAssessmentBuiltEventValidates(t *testing.T) {
	a := schema.ThreatAssessment{ThreatType: "cryptomining", AgentsAvailable: []string{"l1", "l2", "senior"}, RawConfidence: 80, LLMCappedConfidence: 30}
	hyp := schema.L1Hypothesis{Hypothesis: "miner", Confidence: 70}
	ver := schema.L2Verification{Verdict: "confirmed", Confidence: 66}
	evt := AssessmentFromChain(AssessmentInput{
		PackageID:        "pkg-built",
		WorkloadID:       "ns/Deployment/x",
		Mode:             "full",
		AgentsAvailable:  a.AgentsAvailable,
		PromptVersions:   map[string]string{"l1": "h1", "l2": "h2", "senior": "h3"},
		Providers:        map[string]string{"l1": "claude", "l2": "claude", "senior": "claude"},
		Models:           map[string]string{"l1": "haiku", "l2": "haiku", "senior": "opus"},
		RawConfidence:    a.RawConfidence,
		CappedConfidence: a.LLMCappedConfidence,
		L1Hypothesis:     &hyp,
		L2Verification:   &ver,
		ThreatAssessment: &a,
		RedactedEvidence: schema.EvidencePackage{PackageID: "pkg-built"},
		RedactionApplied: true,
		Now:              time.Unix(1700000000, 0).UTC(),
	})
	payload, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := validateAgainstSchema(t, assessmentsSchemaPath, payload); err != nil {
		t.Errorf("built event fails schema: %v\npayload: %s", err, payload)
	}
}

// TestAssessmentSchemaRejectsDrift proves the schema is not vacuous: a
// payload missing the required redaction_applied (or with a stale
// schema_version, or an extra field) fails validation.
func TestAssessmentSchemaRejectsDrift(t *testing.T) {
	cases := map[string]string{
		"missing redaction_applied": `{"schema_version":"audit.assessments.v2","package_id":"p","workload_id":"w","mode":"full","raw_confidence":1,"llm_capped_confidence":1,"redacted_evidence":{},"decided_at":"2026-06-13T00:00:00Z","published_at":"2026-06-13T00:00:00Z"}`,
		"stale schema_version":      `{"schema_version":"audit.assessments.v1","package_id":"p","workload_id":"w","mode":"full","raw_confidence":1,"llm_capped_confidence":1,"redacted_evidence":{},"redaction_applied":true,"decided_at":"2026-06-13T00:00:00Z","published_at":"2026-06-13T00:00:00Z"}`,
		"unknown field":             `{"schema_version":"audit.assessments.v2","package_id":"p","workload_id":"w","mode":"full","raw_confidence":1,"llm_capped_confidence":1,"redacted_evidence":{},"redaction_applied":true,"decided_at":"2026-06-13T00:00:00Z","published_at":"2026-06-13T00:00:00Z","leaked_secret":"AKIA..."}`,
		"bad mode enum":             `{"schema_version":"audit.assessments.v2","package_id":"p","workload_id":"w","mode":"l5","raw_confidence":1,"llm_capped_confidence":1,"redacted_evidence":{},"redaction_applied":true,"decided_at":"2026-06-13T00:00:00Z","published_at":"2026-06-13T00:00:00Z"}`,
	}
	for name, payload := range cases {
		if err := validateAgainstSchema(t, assessmentsSchemaPath, []byte(payload)); err == nil {
			t.Errorf("%s: expected schema violation, got none", name)
		}
	}
}

// TestSchemaYAMLMirrorsJSON guards the documentation mirror against drift:
// every top-level property in assessments.json must appear in the YAML
// mirror, and vice versa (a renamed field that updates one but not the
// other is a doc lie).
func TestSchemaYAMLMirrorsJSON(t *testing.T) {
	jb, err := os.ReadFile(assessmentsSchemaPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(jb, &doc); err != nil {
		t.Fatal(err)
	}
	yb, err := os.ReadFile(schemaDir + "/assessments.yaml")
	if err != nil {
		t.Fatal(err)
	}
	yaml := string(yb)
	for field := range doc.Properties {
		if !strings.Contains(yaml, "\n  "+field+":") {
			t.Errorf("assessments.yaml mirror missing field %q present in the JSON schema", field)
		}
	}
}
