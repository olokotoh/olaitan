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

// TestEmbeddedL2SchemaMatchesDocs pins the BI-3 byte-identity guarantee
// for the L2 schema (the Story 3.5 BI-5 pattern).
func TestEmbeddedL2SchemaMatchesDocs(t *testing.T) {
	docs, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "schemas", "l2_verification.json"))
	if err != nil {
		t.Fatalf("read docs schema: %v", err)
	}
	if !bytes.Equal(docs, l2SchemaJSON) {
		t.Error("internal/decision/analyst/l2_verification_schema.json differs from docs/schemas/l2_verification.json; copy the docs file over the embedded one")
	}
}

// TestL2SchemaJSONYAMLAgreement asserts the .json and .yaml mirrors
// describe the SAME field set with the SAME required-ness.
func TestL2SchemaJSONYAMLAgreement(t *testing.T) {
	jb, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "schemas", "l2_verification.json"))
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

	yb, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "schemas", "l2_verification.yaml"))
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

	jrequired := map[string]bool{}
	for _, k := range jdoc.Required {
		jrequired[k] = true
	}
	for k := range jdoc.Properties {
		f, ok := ydoc.Fields[k]
		if !ok {
			t.Errorf("json property %q missing from yaml mirror", k)
			continue
		}
		if f.Required != jrequired[k] {
			t.Errorf("required-ness disagrees for %q: yaml=%v json=%v", k, f.Required, jrequired[k])
		}
	}
	for k := range ydoc.Fields {
		if _, ok := jdoc.Properties[k]; !ok {
			t.Errorf("yaml field %q missing from json schema", k)
		}
	}
}

// invalidL2ExemplarKeyword maps each invalid L2 exemplar to the
// JSON-Schema keyword (or message fragment) its violation must be
// reported under.
var invalidL2ExemplarKeyword = map[string]string{
	"l2_verification_invalid_bad_verdict.json":      "value must be one of",
	"l2_verification_invalid_missing_finding.json":  "finding",
	"l2_verification_invalid_empty_verified.json":   "minItems",
	"l2_verification_invalid_confidence_range.json": "maximum",
}

// TestL2VerificationExemplars validates every committed L2 exemplar
// against the embedded schema with the strict name classifier.
func TestL2VerificationExemplars(t *testing.T) {
	sch, err := l2Schema.compiled()
	if err != nil {
		t.Fatalf("compile embedded schema: %v", err)
	}
	paths, err := filepath.Glob(filepath.Join("testdata", "l2_verification_*.json"))
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
			case strings.HasPrefix(base, "l2_verification_invalid_"):
				invalid++
				if verr == nil {
					t.Fatalf("invalid exemplar %s passed schema validation", p)
				}
				keyword, known := invalidL2ExemplarKeyword[base]
				if !known {
					t.Fatalf("invalid exemplar %s has no expected-keyword entry", base)
				}
				if !strings.Contains(verr.Error(), keyword) {
					t.Errorf("exemplar %s failed for the wrong reason: want %q in error, got: %v", base, keyword, verr)
				}
			case strings.HasPrefix(base, "l2_verification_valid_"):
				valid++
				if verr != nil {
					t.Errorf("valid exemplar %s failed schema validation: %v", p, verr)
				}
			default:
				t.Fatalf("exemplar %s matches neither l2_verification_valid_* nor l2_verification_invalid_*; rename it", base)
			}
		})
	}
	if valid < 2 || invalid < 4 {
		t.Errorf("exemplar coverage too thin: %d valid, %d invalid (want >=2 and >=4)", valid, invalid)
	}
}
