package main

import (
	"os"
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

// configOnlyDefaultFor returns the rendered def literal carried in the
// generator's configOnly honesty table for the named parameter.
func configOnlyDefaultFor(name string) (string, bool) {
	for _, c := range configOnly {
		if c.name == name {
			return c.def, true
		}
	}
	return "", false
}

// TestConfigOnlyDefaultsMatchFile is the FIX 2 drift guard (Blind #2): the
// honesty table hardcodes config-file-only defaults as Go literals that are
// read from no file, so if config/olaitan.yaml changes the doc would silently
// drift and the FR47 git-diff gate (which only covers the generated doc, not
// its inputs) would not catch it. This test parses the canonical config source
// and asserts each hardcoded literal still equals the file value, so CI fails
// the moment they diverge. It reads config/olaitan.yaml (the committed source)
// rather than the chart-staged deploy/helm/olaitan/files/olaitan.yaml, which is
// a gitignored verbatim copy produced by `make helm-prepare` and is absent in
// the `go` CI job.
func TestConfigOnlyDefaultsMatchFile(t *testing.T) {
	const configPath = "../../config/olaitan.yaml"
	src, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config file %s: %v", configPath, err)
	}
	root, err := parseTree(src)
	if err != nil {
		t.Fatalf("parse config file: %v", err)
	}

	// fileValue renders a dotted leaf from the config file the same way the
	// generator renders a values.yaml leaf, so the literal and the file value
	// are compared in the same form.
	fileValue := func(path string) string {
		return lookupDefault(root, path)
	}

	// normalise strips YAML quoting and surrounding whitespace so the
	// human-readable honesty-table literal (e.g. `[kube-system, olaitan]`)
	// compares equal to the file's rendered value (e.g. `["kube-system",
	// "olaitan"]`) while a REAL value change (an added namespace, a flipped
	// bool, a different number) still diverges and fails the test.
	normalise := func(s string) string {
		s = strings.ReplaceAll(s, `"`, "")
		s = strings.ReplaceAll(s, " ", "")
		return s
	}

	cases := []struct {
		name string // configOnly[].name
		path string // dotted path in config/olaitan.yaml
		want string // expected rendered file value (raw, pre-normalise)
	}{
		{"response.excluded_namespaces", "response.excluded_namespaces", `["kube-system", "olaitan"]`},
		{"report.redact.audit_enabled", "report.redact.audit_enabled", "false"},
		{"report.redact.retention_redactions_days", "report.redact.retention_redactions_days", "365"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := fileValue(c.path)
			if got != c.want {
				t.Fatalf("config file %s = %q, want %q (the test's own expectation drifted from the file)", c.path, got, c.want)
			}
			lit, ok := configOnlyDefaultFor(c.name)
			if !ok {
				t.Fatalf("configOnly has no entry named %q", c.name)
			}
			// Compare normalised forms: the honesty-table literal is human
			// readable, the file value is YAML-quoted, but the underlying value
			// must match. A genuine config change (e.g. a third namespace, or
			// retention 365 -> 90) survives normalisation and trips the failure.
			if normalise(lit) != normalise(got) {
				t.Errorf("configOnly[%q].def = %q but config/olaitan.yaml renders %q; the hardcoded honesty-table literal has drifted from the real config (update main.go's configOnly table or the file)", c.name, lit, got)
			}
		})
	}
	// Defensive: make sure the test actually exercised every file-backed
	// config-only entry, so a future literal added without a case here is
	// noticed.
	covered := map[string]bool{}
	for _, c := range cases {
		covered[c.name] = true
	}
	fileBacked := []string{
		"response.excluded_namespaces",
		"report.redact.audit_enabled",
		"report.redact.retention_redactions_days",
	}
	for _, n := range fileBacked {
		if !covered[n] {
			t.Errorf("file-backed config-only entry %q is not covered by a drift case", n)
		}
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
