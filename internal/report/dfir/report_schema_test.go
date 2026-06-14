package dfir

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestEmbeddedSchemaMatchesDocs pins the BI-4 byte-identity guarantee: the
// runtime go:embed copy and the authoritative committed schema can never
// silently diverge (the analyst l1_schema_test precedent).
func TestEmbeddedSchemaMatchesDocs(t *testing.T) {
	docs, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "schemas", "forensic_report.json"))
	if err != nil {
		t.Fatalf("read docs schema: %v", err)
	}
	if !bytes.Equal(docs, forensicSchemaJSON) {
		t.Error("internal/report/dfir/forensic_report_schema.json differs from docs/schemas/forensic_report.json; copy the docs file over the embedded one")
	}
}

// TestForensicReportSchemaJSONYAMLAgreement asserts the .json and .yaml mirrors
// describe the SAME field set AND agree on required-ness (the l1_schema_test
// pattern), so the documentation cannot silently diverge from the machine
// contract.
func TestForensicReportSchemaJSONYAMLAgreement(t *testing.T) {
	jb, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "schemas", "forensic_report.json"))
	if err != nil {
		t.Fatalf("read json schema: %v", err)
	}
	var jdoc struct {
		Properties map[string]any `json:"properties"`
		Required   []string       `json:"required"`
	}
	if err := json.Unmarshal(jb, &jdoc); err != nil {
		t.Fatalf("unmarshal json schema: %v", err)
	}

	yb, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "schemas", "forensic_report.yaml"))
	if err != nil {
		t.Fatalf("read yaml mirror: %v", err)
	}
	var ydoc struct {
		Fields map[string]struct {
			Required bool `yaml:"required"`
		} `yaml:"fields"`
	}
	if err := yaml.Unmarshal(yb, &ydoc); err != nil {
		t.Fatalf("unmarshal yaml mirror: %v", err)
	}

	for k := range jdoc.Properties {
		if _, ok := ydoc.Fields[k]; !ok {
			t.Errorf("json property %q missing from yaml mirror", k)
		}
	}
	for k := range ydoc.Fields {
		if _, ok := jdoc.Properties[k]; !ok {
			t.Errorf("yaml field %q missing from json schema", k)
		}
	}

	jrequired := map[string]bool{}
	for _, k := range jdoc.Required {
		jrequired[k] = true
	}
	for k, f := range ydoc.Fields {
		if f.Required != jrequired[k] {
			t.Errorf("required-ness disagrees for %q: yaml=%v json=%v", k, f.Required, jrequired[k])
		}
	}
}

// TestForensicReportSchemaCompiles pins that the embedded schema compiles under
// the jsonschema/v6 pipeline so the runner's compile-once seam can never ship a
// corrupt schema.
func TestForensicReportSchemaCompiles(t *testing.T) {
	if _, err := reportSchema.compiled(); err != nil {
		t.Fatalf("embedded forensic_report schema failed to compile: %v", err)
	}
}
