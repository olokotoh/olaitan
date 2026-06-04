package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"

	"github.com/olokotoh/olaitan/internal/response/netpol"
	"github.com/olokotoh/olaitan/internal/schema"
)

// schemaDir is the committed JSON-Schema home, relative to this package.
const schemaDir = "../../../docs/schemas/audit"

// validateAgainstSchema compiles the committed draft-2020-12 JSON-Schema at
// schemaPath and validates payload against it, returning the validator's
// path-annotated error on drift (BI-6.2). additionalProperties:false + the
// required set mean a renamed/removed/added Go field FAILS here, which is
// exactly AC6's "fail any payload that drifts from schema".
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

func TestAuditTransition_ValidatesAgainstSchema(t *testing.T) {
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	st := schema.StateTransition{
		FromState:   schema.StateClean,
		ToState:     schema.StateRestricted,
		Confidence:  72.5,
		PackageID:   "pkg-1",
		WorkloadID:  "ns/Deployment/web",
		TriggerType: "automated",
		Reason:      schema.ReasonEscalationThresholdCrossed,
		Timestamp:   now,
	}
	evt := transitionFromState(st, now.Add(time.Second))
	if err := validateAgainstSchema(t, filepath.Join(schemaDir, "transitions.json"), mustMarshal(t, evt)); err != nil {
		t.Fatalf("automated transition failed schema validation: %v", err)
	}

	// An override-driven transition carries operator_id + trigger_type=override.
	stOvr := st
	stOvr.TriggerType = "override"
	stOvr.Reason = schema.ReasonOperatorOverride
	stOvr.OperatorID = "alice"
	stOvr.ToState = schema.StateQuarantined
	ovr := transitionFromState(stOvr, now.Add(time.Second))
	if err := validateAgainstSchema(t, filepath.Join(schemaDir, "transitions.json"), mustMarshal(t, ovr)); err != nil {
		t.Fatalf("override transition failed schema validation: %v", err)
	}
}

func TestAuditPolicy_ValidatesAgainstSchema(t *testing.T) {
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	cases := []netpol.PolicyAuditEvent{
		{Action: netpol.AuditActionApply, WorkloadID: "ns/Deployment/web", Namespace: "ns", PolicyName: "olaitan-restricted-abc", PolicyKind: netpol.AuditPolicyKindRestricted, FSMState: string(schema.StateRestricted), Result: "applied", SpecSummary: netpol.AuditSpecEgressAllowlist, PackageID: "pkg-1"},
		{Action: netpol.AuditActionSupersedeDelete, WorkloadID: "ns/Deployment/web", Namespace: "ns", PolicyName: "olaitan-restricted-abc", PolicyKind: netpol.AuditPolicyKindRestricted, FSMState: string(schema.StateQuarantined), Result: "superseded", SpecSummary: netpol.AuditSpecRemoved},
		// deescalation_remove: a set removal carries no policy_name/policy_kind.
		{Action: netpol.AuditActionDeescalationRemove, WorkloadID: "ns/Deployment/web", Namespace: "ns", FSMState: string(schema.StateClean), Result: "removed", SpecSummary: netpol.AuditSpecRemoved},
		{Action: netpol.AuditActionGCDelete, WorkloadID: "ns/Deployment/web", Namespace: "ns", PolicyName: "olaitan-quarantined-abc", PolicyKind: netpol.AuditPolicyKindQuarantined, FSMState: string(schema.StateQuarantined), Result: "gc_deleted", SpecSummary: netpol.AuditSpecRemoved},
	}
	for _, c := range cases {
		evt := policyFromEvent(c, now)
		if err := validateAgainstSchema(t, filepath.Join(schemaDir, "policies.json"), mustMarshal(t, evt)); err != nil {
			t.Fatalf("policy action %q failed schema validation: %v", c.Action, err)
		}
	}
}

// TestAuditPolicy_DriftFailsValidation proves AC6 is not vacuous: a payload
// with a renamed field (or a value outside the closed enum) FAILS validation.
func TestAuditPolicy_DriftFailsValidation(t *testing.T) {
	// A renamed field ("act" instead of "action") -> additionalProperties:false
	// rejects it AND the required "action" is now missing.
	drifted := []byte(`{"schema_version":"audit.policies.v1","act":"apply","workload_id":"w","namespace":"ns","fsm_state":"RESTRICTED","result":"applied","spec_summary":"egress_allowlist","published_at":"2026-06-04T12:00:00Z"}`)
	if err := validateAgainstSchema(t, filepath.Join(schemaDir, "policies.json"), drifted); err == nil {
		t.Fatal("expected schema validation to FAIL on a renamed field, but it passed (AC6 would be vacuous)")
	}
	// A value outside the closed action enum must also fail.
	badEnum := []byte(`{"schema_version":"audit.policies.v1","action":"frobnicate","workload_id":"w","namespace":"ns","fsm_state":"RESTRICTED","result":"applied","spec_summary":"egress_allowlist","published_at":"2026-06-04T12:00:00Z"}`)
	if err := validateAgainstSchema(t, filepath.Join(schemaDir, "policies.json"), badEnum); err == nil {
		t.Fatal("expected schema validation to FAIL on an out-of-enum action, but it passed")
	}
}

// TestAuditPolicy_OmitEmptyOnSetRemoval confirms a deescalation_remove omits
// policy_name/policy_kind/package_id on the wire (BI-9 set removal).
func TestAuditPolicy_OmitEmptyOnSetRemoval(t *testing.T) {
	evt := policyFromEvent(netpol.PolicyAuditEvent{
		Action: netpol.AuditActionDeescalationRemove, WorkloadID: "w", Namespace: "ns",
		FSMState: string(schema.StateClean), Result: "removed", SpecSummary: netpol.AuditSpecRemoved,
	}, time.Now())
	b := mustMarshal(t, evt)
	for _, k := range []string{"policy_name", "policy_kind", "package_id"} {
		if bytes.Contains(b, []byte(`"`+k+`"`)) {
			t.Errorf("expected %q to be omitted on a set removal, got: %s", k, b)
		}
	}
}

// TestSchemaJSONYAMLAgreement asserts the .json and .yaml mirrors describe the
// SAME field set (BI-6.4), so the documentation cannot silently diverge from
// the machine contract.
func TestSchemaJSONYAMLAgreement(t *testing.T) {
	for _, subj := range []string{"transitions", "overrides", "policies"} {
		jsonProps := jsonSchemaProps(t, filepath.Join(schemaDir, subj+".json"))
		yamlProps := yamlMirrorFields(t, filepath.Join(schemaDir, subj+".yaml"))
		if !equalStringSets(jsonProps, yamlProps) {
			t.Errorf("%s: json properties %v != yaml fields %v", subj, jsonProps, yamlProps)
		}
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
