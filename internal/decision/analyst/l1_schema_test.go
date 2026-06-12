package analyst

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

// TestEmbeddedSchemaMatchesDocs pins the BI-5 byte-identity guarantee:
// the runtime go:embed copy and the authoritative committed schema can
// never silently diverge.
func TestEmbeddedSchemaMatchesDocs(t *testing.T) {
	docs, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "schemas", "l1_hypothesis.json"))
	if err != nil {
		t.Fatalf("read docs schema: %v", err)
	}
	if !bytes.Equal(docs, l1SchemaJSON) {
		t.Error("internal/decision/analyst/l1_hypothesis_schema.json differs from docs/schemas/l1_hypothesis.json; copy the docs file over the embedded one")
	}
}

// TestL1SchemaJSONYAMLAgreement asserts the .json and .yaml mirrors
// describe the SAME field set (the docs/schemas/audit pattern), so the
// documentation cannot silently diverge from the machine contract.
func TestL1SchemaJSONYAMLAgreement(t *testing.T) {
	jb, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "schemas", "l1_hypothesis.json"))
	if err != nil {
		t.Fatalf("read json schema: %v", err)
	}
	var jdoc struct {
		Properties map[string]any `json:"properties"`
	}
	if err := json.Unmarshal(jb, &jdoc); err != nil {
		t.Fatalf("unmarshal json schema: %v", err)
	}

	yb, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "schemas", "l1_hypothesis.yaml"))
	if err != nil {
		t.Fatalf("read yaml mirror: %v", err)
	}
	var ydoc struct {
		Fields map[string]any `yaml:"fields"`
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
}

// TestL1HypothesisExemplars validates every committed exemplar in
// testdata/ against the embedded schema (AC5): files named *_valid*
// must pass, files named *_invalid_* must fail.
func TestL1HypothesisExemplars(t *testing.T) {
	sch, err := compiledL1Schema()
	if err != nil {
		t.Fatalf("compile embedded schema: %v", err)
	}
	paths, err := filepath.Glob(filepath.Join("testdata", "l1_hypothesis_*.json"))
	if err != nil {
		t.Fatalf("glob testdata: %v", err)
	}
	var valid, invalid int
	for _, p := range paths {
		p := p
		t.Run(filepath.Base(p), func(t *testing.T) {
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatalf("read exemplar: %v", err)
			}
			inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
			if err != nil {
				t.Fatalf("exemplar is not JSON: %v", err)
			}
			verr := sch.Validate(inst)
			switch {
			case strings.Contains(p, "_invalid_"):
				invalid++
				if verr == nil {
					t.Errorf("invalid exemplar %s passed schema validation", p)
				}
			default:
				valid++
				if verr != nil {
					t.Errorf("valid exemplar %s failed schema validation: %v", p, verr)
				}
			}
		})
	}
	if valid < 1 || invalid < 3 {
		t.Errorf("exemplar coverage too thin: %d valid, %d invalid (want >=1 and >=3)", valid, invalid)
	}
}
