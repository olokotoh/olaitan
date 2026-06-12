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

	// Required-ness must agree too (round-1 review: a names-only check
	// lets the mirror silently flip a field's required flag).
	var jreq struct {
		Required []string `json:"required"`
	}
	if err := json.Unmarshal(jb, &jreq); err != nil {
		t.Fatalf("unmarshal json required: %v", err)
	}
	jrequired := map[string]bool{}
	for _, k := range jreq.Required {
		jrequired[k] = true
	}
	var yreq struct {
		Fields map[string]struct {
			Required bool `yaml:"required"`
		} `yaml:"fields"`
	}
	if err := yaml.Unmarshal(yb, &yreq); err != nil {
		t.Fatalf("unmarshal yaml required flags: %v", err)
	}
	for k, f := range yreq.Fields {
		if f.Required != jrequired[k] {
			t.Errorf("required-ness disagrees for %q: yaml=%v json=%v", k, f.Required, jrequired[k])
		}
	}
}

// invalidExemplarKeyword maps each invalid exemplar to the JSON-Schema
// keyword (or message fragment) its violation must be reported under
// (round-1 review: a mis-authored exemplar failing for the WRONG reason
// must not pass silently).
var invalidExemplarKeyword = map[string]string{
	"l1_hypothesis_invalid_missing_hypothesis.json": "hypothesis",
	"l1_hypothesis_invalid_confidence_range.json":   "maximum",
	"l1_hypothesis_invalid_empty_citations.json":    "minItems",
	"l1_hypothesis_invalid_extra_field.json":        "additional properties",
}

// TestL1HypothesisExemplars validates every committed exemplar in
// testdata/ against the embedded schema (AC5): files named
// l1_hypothesis_valid_* must pass, files named l1_hypothesis_invalid_*
// must fail for the expected reason; any other name is an error
// (round-1 review: a stray file must not silently join the
// must-validate set).
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
		base := filepath.Base(p)
		t.Run(base, func(t *testing.T) {
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
			case strings.HasPrefix(base, "l1_hypothesis_invalid_"):
				invalid++
				if verr == nil {
					t.Fatalf("invalid exemplar %s passed schema validation", p)
				}
				keyword, known := invalidExemplarKeyword[base]
				if !known {
					t.Fatalf("invalid exemplar %s has no expected-keyword entry; add it to invalidExemplarKeyword", base)
				}
				if !strings.Contains(verr.Error(), keyword) {
					t.Errorf("exemplar %s failed for the wrong reason: want %q in error, got: %v", base, keyword, verr)
				}
			case strings.HasPrefix(base, "l1_hypothesis_valid_"):
				valid++
				if verr != nil {
					t.Errorf("valid exemplar %s failed schema validation: %v", p, verr)
				}
			default:
				t.Fatalf("exemplar %s matches neither l1_hypothesis_valid_* nor l1_hypothesis_invalid_*; rename it", base)
			}
		})
	}
	if valid < 1 || invalid < 3 {
		t.Errorf("exemplar coverage too thin: %d valid, %d invalid (want >=1 and >=3)", valid, invalid)
	}
}
