package main

import (
	"strings"
	"testing"
)

// TestParse_DefaultReadFromYAMLLeaf is the anti-drift invariant: the
// documented default is read from the YAML value beneath the annotation,
// never from the annotation text, so it can never disagree with the real
// default.
func TestParse_DefaultReadFromYAMLLeaf(t *testing.T) {
	src := []byte(`
group:
  # @schema type:number minimum:0 effect:"sigmas above mean" ref:FR18
  sigma: 3.0
  # @schema type:duration effect:"warm-up window" ref:FR18
  warmup: "30m"
`)
	params, err := parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(params) != 2 {
		t.Fatalf("want 2 params, got %d", len(params))
	}

	got := map[string]param{}
	for _, p := range params {
		got[p.path] = p
	}

	if p := got["group.sigma"]; p.def != "3.0" {
		t.Errorf("group.sigma default = %q, want %q (read from the YAML leaf, not the annotation)", p.def, "3.0")
	}
	if p := got["group.warmup"]; p.def != `"30m"` {
		t.Errorf("group.warmup default = %q, want %q", p.def, `"30m"`)
	}
}

// TestParse_AllSixAC3Attributes asserts an annotated leaf emits the six
// AC3 attributes (name=path, type, default, range, effect, ref).
func TestParse_AllSixAC3Attributes(t *testing.T) {
	src := []byte(`
group:
  # @schema type:integer minimum:1 maximum:100 effect:"the effect text" ref:FR30
  cap: 35
`)
	params, err := parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(params) != 1 {
		t.Fatalf("want 1 param, got %d", len(params))
	}
	p := params[0]
	if p.path != "group.cap" {
		t.Errorf("name(path) = %q, want group.cap", p.path)
	}
	if p.typ != "integer" {
		t.Errorf("type = %q, want integer", p.typ)
	}
	if p.def != "35" {
		t.Errorf("default = %q, want 35", p.def)
	}
	if p.rang != "1 to 100" {
		t.Errorf("range = %q, want %q", p.rang, "1 to 100")
	}
	if p.effect != "the effect text" {
		t.Errorf("effect = %q, want %q", p.effect, "the effect text")
	}
	if p.ref != "FR30" {
		t.Errorf("ref = %q, want FR30", p.ref)
	}
}

// TestParse_RefOptional covers the AC3 "where applicable" clause: a leaf
// annotated without a ref still emits cleanly with no FR/NFR cell.
func TestParse_RefOptional(t *testing.T) {
	src := []byte(`
group:
  # @schema type:integer minimum:1 effect:"no ref here"
  port: 9090
`)
	params, err := parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(params) != 1 {
		t.Fatalf("want 1 param, got %d", len(params))
	}
	if params[0].ref != "" {
		t.Errorf("ref = %q, want empty", params[0].ref)
	}
	// The renderer must substitute a dash for an empty ref.
	md := string(render(params, "x.yaml"))
	if !strings.Contains(md, "| - |") {
		t.Errorf("rendered table missing the `-` ref cell for a ref-less value:\n%s", md)
	}
}

// TestParse_SiblingLeafKeysDisambiguated guards the real bug found in
// development: identical leaf keys (endpoint/model) under sibling parents
// (api vs local) must resolve to distinct dotted paths, not collapse onto
// the first occurrence.
func TestParse_SiblingLeafKeysDisambiguated(t *testing.T) {
	src := []byte(`
analyst:
  api:
    # @schema type:string effect:"api endpoint"
    endpoint: ""
  local:
    # @schema type:string effect:"local endpoint"
    endpoint: ""
`)
	params, err := parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	paths := map[string]bool{}
	for _, p := range params {
		paths[p.path] = true
	}
	for _, want := range []string{"analyst.api.endpoint", "analyst.local.endpoint"} {
		if !paths[want] {
			t.Errorf("missing disambiguated path %q; got %v", want, paths)
		}
	}
}

// TestRender_Deterministic asserts byte-identical output across runs over
// the same input (the FR47 drift-gate prerequisite).
func TestRender_Deterministic(t *testing.T) {
	src := []byte(`
a:
  # @schema type:integer minimum:0 effect:"first" ref:FR1
  x: 1
b:
  # @schema type:string effect:"second"
  y: "v"
`)
	params, err := parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	first := string(render(params, "values.yaml"))
	second := string(render(params, "values.yaml"))
	if first != second {
		t.Errorf("render not deterministic:\n--- first ---\n%s\n--- second ---\n%s", first, second)
	}
	// Group headings must follow document order (a before b).
	if strings.Index(first, "## `a`") > strings.Index(first, "## `b`") {
		t.Errorf("group order not preserved (a should precede b):\n%s", first)
	}
}

// TestParse_MissingTypeFails asserts a malformed annotation (no type) is a
// loud error, not a silently-omitted row.
func TestParse_MissingTypeFails(t *testing.T) {
	src := []byte(`
group:
  # @schema minimum:0 effect:"no type"
  x: 1
`)
	if _, err := parse(src); err == nil {
		t.Errorf("expected an error for an annotation missing `type:`, got nil")
	}
}

// TestRangeOf table-drives the valid-range rendering, including the
// enum-with-trailing-empty (inherit) case and the no-range dash.
func TestRangeOf(t *testing.T) {
	cases := []struct {
		name  string
		attrs map[string]string
		want  string
	}{
		{"min+max", map[string]string{"minimum": "0", "maximum": "100"}, "0 to 100"},
		{"min only", map[string]string{"minimum": "1"}, "minimum 1"},
		{"max only", map[string]string{"maximum": "1"}, "maximum 1"},
		{"enum", map[string]string{"enum": "a|b|c"}, "one of: a, b, c"},
		{"enum inherit", map[string]string{"enum": "claude|openai|"}, "one of: claude, openai (or empty to inherit)"},
		{"pattern", map[string]string{"pattern": "a Go duration"}, "a Go duration"},
		{"none", map[string]string{}, "-"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := rangeOf(c.attrs); got != c.want {
				t.Errorf("rangeOf(%v) = %q, want %q", c.attrs, got, c.want)
			}
		})
	}
}

// TestParseAttrs_EscapedQuotes covers a quoted value containing an escaped
// quote (the nats.streamMaxBytesOverride annotation shape).
func TestParseAttrs_EscapedQuotes(t *testing.T) {
	attrs, err := parseAttrs(`type:string pattern:"a \"quoted\" example" ref:NFR3`)
	if err != nil {
		t.Fatalf("parseAttrs: %v", err)
	}
	if attrs["pattern"] != `a "quoted" example` {
		t.Errorf("pattern = %q, want %q", attrs["pattern"], `a "quoted" example`)
	}
	if attrs["type"] != "string" || attrs["ref"] != "NFR3" {
		t.Errorf("unexpected attrs: %v", attrs)
	}
}
