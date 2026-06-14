package settling

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"

	"github.com/olokotoh/olaitan/internal/schema"
)

// schemaDir is the committed JSON-Schema home, relative to this package.
const schemaDir = "../../../docs/schemas/incidents"

// validateAgainstSchema compiles the committed draft-2020-12 JSON-Schema at
// schemaPath and validates payload against it, returning the validator's
// path-annotated error on drift. additionalProperties:false + the required set
// mean a renamed/removed/added field FAILS here.
func validateAgainstSchema(t *testing.T, schemaPath string, payload []byte) error {
	t.Helper()
	sb, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read schema %s: %v", schemaPath, err)
	}
	schemaDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(sb))
	if err != nil {
		t.Fatalf("unmarshal schema %s: %v", schemaPath, err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(schemaPath, schemaDoc); err != nil {
		t.Fatalf("add schema resource %s: %v", schemaPath, err)
	}
	sch, err := c.Compile(schemaPath)
	if err != nil {
		t.Fatalf("compile schema %s: %v", schemaPath, err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return sch.Validate(inst)
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestIncidentFinalised_ValidatesAgainstSchema(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	evt := IncidentFinalised{
		SchemaVersion: SchemaVersionIncidentFinalised,
		PackageID:     "pkg-1",
		WorkloadID:    "ns/Deployment/web",
		FinalState:    string(schema.StateQuarantined),
		ThreatScore:   88.5,
		FinalisedAt:   now,
		History: []schema.StateTransition{
			{
				Timestamp:   now.Add(-90 * time.Second),
				FromState:   schema.StateClean,
				ToState:     schema.StateSuspicious,
				TriggerType: "automated",
				Confidence:  40,
				WorkloadID:  "ns/Deployment/web",
				PackageID:   "pkg-1",
				Reason:      schema.ReasonEscalationThresholdCrossed,
			},
			{
				Timestamp:   now.Add(-60 * time.Second),
				FromState:   schema.StateSuspicious,
				ToState:     schema.StateQuarantined,
				TriggerType: "automated",
				Confidence:  88.5,
				WorkloadID:  "ns/Deployment/web",
				PackageID:   "pkg-1",
				Reason:      schema.ReasonEscalationThresholdCrossed,
			},
		},
	}
	if err := validateAgainstSchema(t, filepath.Join(schemaDir, "finalised.json"), mustMarshal(t, evt)); err != nil {
		t.Fatalf("IncidentFinalised failed schema validation: %v", err)
	}

	// A PRESERVED_KILLED final state with an empty history (history read failed
	// and nothing observed in-process) is still a valid finalisation.
	evt2 := IncidentFinalised{
		SchemaVersion: SchemaVersionIncidentFinalised,
		PackageID:     "pkg-2",
		WorkloadID:    "ns/Deployment/api",
		FinalState:    string(schema.StatePreservedKilled),
		ThreatScore:   95,
		FinalisedAt:   now,
		History:       nil,
	}
	if err := validateAgainstSchema(t, filepath.Join(schemaDir, "finalised.json"), mustMarshal(t, evt2)); err != nil {
		t.Fatalf("IncidentFinalised with nil history failed schema validation: %v", err)
	}
}

// TestIncidentFinalised_DriftFailsValidation pins that the schema is a genuine
// drift trap: a renamed field, an out-of-enum final_state (notably CLEAN, which
// must never finalise), and a missing required field all FAIL.
func TestIncidentFinalised_DriftFailsValidation(t *testing.T) {
	// CLEAN is intentionally outside the final_state enum (AC4: CLEAN is not an
	// incident and must never be a finalised state).
	clean := []byte(`{"schema_version":"incidents.finalised.v1","package_id":"p","workload_id":"w","final_state":"CLEAN","threat_score":0,"finalised_at":"2026-06-14T12:00:00Z","history":[]}`)
	if err := validateAgainstSchema(t, filepath.Join(schemaDir, "finalised.json"), clean); err == nil {
		t.Fatal("expected schema validation to FAIL on final_state=CLEAN (AC4), but it passed")
	}
	// A renamed field -> additionalProperties:false rejects it AND the required
	// "final_state" is now missing.
	renamed := []byte(`{"schema_version":"incidents.finalised.v1","package_id":"p","workload_id":"w","state":"QUARANTINED","threat_score":1,"finalised_at":"2026-06-14T12:00:00Z","history":[]}`)
	if err := validateAgainstSchema(t, filepath.Join(schemaDir, "finalised.json"), renamed); err == nil {
		t.Fatal("expected schema validation to FAIL on a renamed field, but it passed")
	}
	// A history item with a drifted reason must also fail (the items are validated).
	badHist := []byte(`{"schema_version":"incidents.finalised.v1","package_id":"p","workload_id":"w","final_state":"QUARANTINED","threat_score":1,"finalised_at":"2026-06-14T12:00:00Z","history":[{"timestamp":"2026-06-14T11:59:00Z","from_state":"CLEAN","to_state":"SUSPICIOUS","trigger_type":"automated","confidence":1,"reason":"not_a_reason"}]}`)
	if err := validateAgainstSchema(t, filepath.Join(schemaDir, "finalised.json"), badHist); err == nil {
		t.Fatal("expected schema validation to FAIL on an out-of-enum history reason, but it passed")
	}
}

// TestSchemaJSONYAMLAgreement asserts the .json properties and .yaml fields
// describe the SAME top-level field set, so the documentation mirror cannot
// silently diverge from the machine contract (BI-6.4).
func TestSchemaJSONYAMLAgreement(t *testing.T) {
	jsonProps := jsonSchemaProps(t, filepath.Join(schemaDir, "finalised.json"))
	yamlProps := yamlMirrorFields(t, filepath.Join(schemaDir, "finalised.yaml"))
	if !equalStringSets(jsonProps, yamlProps) {
		t.Errorf("finalised: json properties %v != yaml fields %v", jsonProps, yamlProps)
	}
}

func jsonSchemaProps(t *testing.T, path string) map[string]struct{} {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc struct {
		Properties map[string]any `json:"properties"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	out := map[string]struct{}{}
	for k := range doc.Properties {
		out[k] = struct{}{}
	}
	return out
}

func yamlMirrorFields(t *testing.T, path string) map[string]struct{} {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc struct {
		Fields map[string]any `yaml:"fields"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	out := map[string]struct{}{}
	for k := range doc.Fields {
		out[k] = struct{}{}
	}
	return out
}

func equalStringSets(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}
