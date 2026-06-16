// Command olaitan-schemagen reflection-generates the external-consumer
// JSON-Schema files for the plain wire/persisted carrier types in
// internal/schema, then derives a human-readable YAML mirror for each.
//
// SCOPE (Story 6.3 generation-mechanism decision, recorded in the story
// Dev Notes): this generator reflects ONLY over the three Class A
// carriers (Event, EvidencePackage, WorkloadPosture). Those structs are
// plain snake_case-tagged data carriers with no semantic constraints
// beyond shape and required-ness, so reflection over them yields a
// faithful draft-2020-12 schema. The hand-curated, model-facing Class B
// schemas (l1_hypothesis, l2_verification, threat_assessment,
// forensic_report, state_transition, fsm_state, audit/*) are NOT touched
// here: they encode maxLength bounds, enums, uniqueItems, and
// programmatically-enforced referential rules that reflection cannot
// reproduce and that are the authoritative go:embed validation source.
// Do not "helpfully" widen the generated set over a Class B contract;
// that is a design conversation, not a silent edit.
//
// The AC3 drift gate (`make schemas && git diff --exit-code
// docs/schemas/`) covers the WHOLE docs/schemas/ tree: a Class A struct
// change that is not regenerated, AND a hand-edit to any committed file,
// both surface as a non-empty diff. Output is deterministic (invopop's
// orderedmap preserves struct-field order; required slices follow field
// order), so running this twice from a clean tree is a no-op.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/invopop/jsonschema"

	"github.com/olokotoh/olaitan/internal/schema"
)

// target binds one Class A struct to its emitted file basenames and the
// metadata that heads the YAML mirror.
type target struct {
	// base is the file stem under docs/schemas/ (no extension).
	base string
	// schemaName is the `schema:` value in the YAML mirror, mirroring
	// the docs/schemas/state_transition.yaml house style.
	schemaName string
	// title heads the JSON schema and the YAML mirror comment.
	title string
	// goType is the source-of-truth Go type, named in the YAML header.
	goType string
	// instance is a zero pointer reflected to produce the schema.
	instance any
}

// generated is the literal allow-list of Class A targets. Widening this
// to a Class B (curated) schema is forbidden (see the package comment).
var generated = []target{
	{
		base:       "olt_event",
		schemaName: "olt_event.v1",
		title:      "Event (olt_event.v1)",
		goType:     "schema.Event",
		instance:   &schema.Event{},
	},
	{
		base:       "evidence_package",
		schemaName: "evidence_package.v1",
		title:      "EvidencePackage (evidence_package.v1)",
		goType:     "schema.EvidencePackage",
		instance:   &schema.EvidencePackage{},
	},
	{
		base:       "workload_posture",
		schemaName: "workload_posture.v1",
		title:      "WorkloadPosture (workload_posture.v1)",
		goType:     "schema.WorkloadPosture",
		instance:   &schema.WorkloadPosture{},
	},
}

func main() {
	outDir := "docs/schemas"
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}
	if err := run(outDir); err != nil {
		fmt.Fprintln(os.Stderr, "olaitan-schemagen:", err)
		os.Exit(1)
	}
}

func run(outDir string) error {
	for _, t := range generated {
		s := reflect(t)

		jsonBytes, err := renderJSON(s)
		if err != nil {
			return fmt.Errorf("%s: render json: %w", t.base, err)
		}
		if err := os.WriteFile(filepath.Join(outDir, t.base+".json"), jsonBytes, 0o644); err != nil {
			return fmt.Errorf("%s: write json: %w", t.base, err)
		}

		yamlBytes := renderYAMLMirror(t, s)
		if err := os.WriteFile(filepath.Join(outDir, t.base+".yaml"), yamlBytes, 0o644); err != nil {
			return fmt.Errorf("%s: write yaml: %w", t.base, err)
		}
	}
	return nil
}

// reflect builds the inlined (no $defs reference) draft-2020-12 schema
// for one target and stamps a stable $id/title so the output is both
// deterministic and self-describing.
func reflect(t target) *jsonschema.Schema {
	r := &jsonschema.Reflector{ExpandedStruct: true, DoNotReference: true}
	s := r.Reflect(t.instance)
	s.ID = jsonschema.ID("https://github.com/olokotoh/olaitan/docs/schemas/" + t.base + ".json")
	s.Title = t.title
	s.Description = "Generated from " + t.goType + " by cmd/olaitan-schemagen (Story 6.3, NFR40). " +
		"Authoritative machine-readable wire/persisted contract; " + t.base + ".yaml is the human-readable mirror. " +
		"Regenerate with `make schemas`; CI fails any drift (NFR33)."
	return s
}

// renderJSON marshals the schema with two-space indentation and a
// trailing newline so the committed file matches the docs/schemas house
// style and re-runs are byte-identical.
func renderJSON(s *jsonschema.Schema) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// renderYAMLMirror derives the schema:/fields: documentation mirror from
// the top-level properties of the reflected schema, in the
// docs/schemas/state_transition.yaml shape. It walks the ordered
// property map (struct-field order) so the output is deterministic, and
// it carries the required flag from the schema's top-level required set.
func renderYAMLMirror(t target, s *jsonschema.Schema) []byte {
	required := map[string]bool{}
	for _, k := range s.Required {
		required[k] = true
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# Canonical on-wire shape of %s.\n", t.goType)
	b.WriteString("#\n")
	fmt.Fprintf(&b, "# AUTHORITATIVE validation source: docs/schemas/%s.json\n", t.base)
	b.WriteString("# (draft 2020-12). This YAML is the documentation mirror in the\n")
	b.WriteString("# docs/schemas/state_transition.yaml style. BOTH files are\n")
	fmt.Fprintf(&b, "# generated from %s by cmd/olaitan-schemagen; regenerate with\n", t.goType)
	b.WriteString("# `make schemas` (CI fails any drift, NFR33). Source of truth for\n")
	fmt.Fprintf(&b, "# the Go shape: internal/schema (type %s).\n", strings.TrimPrefix(t.goType, "schema."))
	fmt.Fprintf(&b, "schema: %s\n", t.schemaName)
	b.WriteString("fields:\n")

	if s.Properties != nil {
		for pair := s.Properties.Oldest(); pair != nil; pair = pair.Next() {
			name := pair.Key
			ps := pair.Value
			fmt.Fprintf(&b, "  %s:\n", name)
			fmt.Fprintf(&b, "    type: %s\n", yamlType(ps))
			fmt.Fprintf(&b, "    required: %t\n", required[name])
		}
	}
	return []byte(b.String())
}

// yamlType reduces a property schema to a single human-facing type token
// for the mirror. The mirror is documentation, not a validator, so a
// coarse token (object/array/the scalar type) is sufficient and stable;
// the .json carries the full machine contract. A schema reflected from a
// json.RawMessage field marshals to the boolean `true` (any-JSON), which
// invopop models with an empty Type: report it as "any".
func yamlType(ps *jsonschema.Schema) string {
	if ps == nil || ps.Type == "" {
		return "any"
	}
	return ps.Type
}
