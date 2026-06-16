// Command olaitan-helmdoc generates the operator-facing Helm values
// reference (docs/helm-values.md) from the structured `# @schema ...`
// annotations carried in deploy/helm/olaitan/values.yaml.
//
// SCOPE (Story 6.4 generation-mechanism decision, recorded in the story
// Dev Notes): this generator documents ONLY the values.yaml leaves that
// carry a `# @schema ...` annotation comment on the line immediately
// above them. The annotation set is scoped to the FR47 AC1 surface (the
// ~1247-line values.yaml is not annotated wholesale, which would be
// churn); a contributor adding a tunable value annotates it and reruns
// `make helm-values-doc`. The DEFAULT for each value is read from the
// YAML leaf itself, never typed into the annotation, so the documented
// default can never drift from the real default (the FR47 "without
// manual upkeep that drifts" contract).
//
// Two FR47-named parameters have NO Helm value (they live only in
// config/olaitan.yaml): excluded namespaces (detection.excluded_
// namespaces) and redaction patterns (report.redact). Per-component
// logging level is likewise not a tunable knob (slog runs process-wide
// at its default level in cmd/olaitan/main.go). These are emitted from
// the literal configOnly table below into a clearly-labelled
// "Config-file-only parameters (not Helm-exposed)" section so the FR47
// surface stays complete and HONEST; they are NOT fabricated as fake
// values.yaml keys.
//
// The FR47 drift gate (`make helm-values-doc` then `git add -N
// docs/helm-values.md && git diff --exit-code docs/helm-values.md`)
// covers the whole generated file: a values.yaml annotation or default
// change that is not regenerated, AND a hand-edit to the committed doc,
// both surface as a non-empty diff. Output is deterministic (the
// annotations are walked in values.yaml document order via a line scan
// that preserves file order), so running this twice from a clean tree
// is a no-op.
package main

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	defaultValuesPath = "deploy/helm/olaitan/values.yaml"
	defaultOutPath    = "docs/helm-values.md"
)

// schemaTag is the annotation marker. A single comment line of the form
//
//	# @schema type:number minimum:0 effect:"sigmas above mean" ref:FR18
//
// placed immediately above a leaf value annotates that leaf. The
// default is read from the leaf, not the annotation.
const schemaTag = "# @schema"

// param is one documented value: its dotted path, the annotation
// attributes, and the real default read from the YAML leaf.
type param struct {
	// group is the top-level values.yaml key (the section heading).
	group string
	// path is the dotted key path (e.g. baselines.sigmaMultiplier).
	path string
	// typ is the annotation `type:` attribute.
	typ string
	// rang is the human-readable valid range (from minimum/maximum/
	// enum/pattern), or "-" when the annotation declares none.
	rang string
	// effect is the annotation `effect:` description.
	effect string
	// ref is the annotation `ref:` FR/NFR reference, or "" when absent
	// (the AC3 "where applicable" clause).
	ref string
	// def is the default rendered from the YAML leaf value.
	def string
}

// configOnlyParam documents an FR47-named parameter that is NOT exposed
// as a Helm value and lives only in config/olaitan.yaml.
type configOnlyParam struct {
	name     string
	typ      string
	def      string
	rang     string
	effect   string
	ref      string
	location string
}

// configOnly is the literal honesty table for the FR47-named items with
// no Helm value (recorded binding interpretation; see the package
// comment and the Story 6.4 Dev Notes). These are documented, never
// fabricated as values.yaml keys.
var configOnly = []configOnlyParam{
	{
		name:     "response.excluded_namespaces",
		typ:      "array",
		def:      "[kube-system, olaitan]",
		rang:     "list of namespace names",
		effect:   "namespaces whose events are dropped before correlation (self-exclusion + control plane)",
		ref:      "FR47",
		location: "config/olaitan.yaml (response.excluded_namespaces)",
	},
	{
		name:     "report.redact.audit_enabled",
		typ:      "boolean",
		def:      "false",
		rang:     "true|false",
		effect:   "gates the AUDIT.redactions SIEM emission; redaction itself is ALWAYS applied at every LLM/persistence boundary regardless of this flag (NFR15)",
		ref:      "FR41/NFR15",
		location: "config/olaitan.yaml (report.redact)",
	},
	{
		name:     "report.redact.retention_redactions_days",
		typ:      "integer",
		def:      "365",
		rang:     "minimum 1 (days)",
		effect:   "AUDIT_REDACTIONS JetStream stream MaxAge; the redaction-pattern set itself is code-embedded, not a tunable value",
		ref:      "NFR16",
		location: "config/olaitan.yaml (report.redact.retention_redactions_days)",
	},
	{
		name:     "logging level (per component)",
		typ:      "string",
		def:      "info",
		rang:     "not configurable",
		effect:   "structured slog JSON logging runs process-wide at its default level (cmd/olaitan/main.go: slog.NewJSONHandler(stderr, nil)); there is no per-component log-level knob in the chart or config today",
		ref:      "-",
		location: "cmd/olaitan/main.go (hardcoded; not a Helm or config value)",
	},
	{
		name:     "Redis key-family TTLs",
		typ:      "duration",
		def:      "baseline:* 48h, fsm:{workload_id} no-TTL",
		rang:     "not configurable",
		effect:   "the baseline:* family carries a 48h server-side Redis TTL (EXPIRE, internal/redis/setters.go ttlBaseline) and the fsm:{workload_id} family carries NO TTL (BI-2, so durable FSM state survives an arbitrary restart gap); both are code-fixed, not Helm values",
		ref:      "-",
		location: "internal/keys/keys.go, internal/redis/setters.go (code-fixed; not a Helm or config value)",
	},
	{
		name:     "NATS core-stream time retention (MaxAge)",
		typ:      "duration",
		def:      "EVENTS 24h, EVENTS_RAW 6h, EVIDENCE never-expire",
		rang:     "not configurable",
		effect:   "the core-stream MaxAge values for EVENTS, EVENTS_RAW and EVIDENCE are code-fixed in internal/nats/streams.go, not a Helm value; only the size cap (nats.streamMaxBytesOverride, the OLT_NATS_STREAM_MAXBYTES_OVERRIDE env var) is Helm-exposed",
		ref:      "-",
		location: "internal/nats/streams.go (code-fixed; only nats.streamMaxBytesOverride is Helm-exposed)",
	},
	{
		name:     "worker pool sizes and graceful shutdown grace period",
		typ:      "integer",
		def:      "folded into aggregator.replicas (1); no separate grace-period knob",
		rang:     "not configurable",
		effect:   "the worker pool maps to aggregator.replicas (hard-constrained to 1; the rings are cooperative goroutines in one process), and there is no separate terminationGracePeriodSeconds knob (the process drains on SIGTERM within the default 30s grace)",
		ref:      "-",
		location: "deploy/helm/olaitan/values.yaml aggregator.replicas (folded); no separate grace-period value",
	},
}

func main() {
	valuesPath := defaultValuesPath
	outPath := defaultOutPath
	if len(os.Args) > 1 {
		valuesPath = os.Args[1]
	}
	if len(os.Args) > 2 {
		outPath = os.Args[2]
	}
	if err := run(valuesPath, outPath); err != nil {
		fmt.Fprintln(os.Stderr, "olaitan-helmdoc:", err)
		os.Exit(1)
	}
}

func run(valuesPath, outPath string) error {
	src, err := os.ReadFile(valuesPath)
	if err != nil {
		return fmt.Errorf("read values: %w", err)
	}
	params, err := parse(src)
	if err != nil {
		return fmt.Errorf("parse annotations: %w", err)
	}
	if len(params) == 0 {
		return fmt.Errorf("no `%s` annotations found in %s", schemaTag, valuesPath)
	}
	md := render(params, valuesPath)
	if err := os.WriteFile(outPath, md, 0o644); err != nil {
		return fmt.Errorf("write doc: %w", err)
	}
	return nil
}

// parse walks the values.yaml source line-by-line (preserving document
// order, so output is deterministic), pairing each `# @schema ...`
// annotation comment with the leaf key on the next non-blank line, and
// reads that leaf's default value from the parsed YAML tree.
func parse(src []byte) ([]param, error) {
	root, err := parseTree(src)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(src), "\n")
	var params []param
	var pendingAnno string

	for idx, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		switch {
		case trimmed == "":
			// Blank lines do not break an annotation/leaf pairing; the
			// annotation must sit on the line(s) above its leaf but a
			// stray blank should not silently drop it. We keep it.
			continue
		case strings.HasPrefix(trimmed, schemaTag):
			pendingAnno = strings.TrimSpace(strings.TrimPrefix(trimmed, schemaTag))
			continue
		case strings.HasPrefix(trimmed, "#"):
			// A non-annotation comment between the annotation and its
			// leaf would orphan the annotation; treat it as breaking
			// the pairing so a misplaced annotation fails loudly (the
			// generated section would simply omit it, caught in review).
			if pendingAnno != "" {
				pendingAnno = ""
			}
			continue
		}

		if pendingAnno == "" {
			continue
		}

		key := leafKey(trimmed)
		if key == "" {
			pendingAnno = ""
			continue
		}
		// keyPath rebuilds the dotted path by scanning upward from THIS
		// line index (idx); using the index, not a content match, is
		// load-bearing because leaf keys like `endpoint`/`model` repeat
		// identically under sibling parents (analyst.api vs analyst.local).
		path := keyPath(idx, leadingSpaces(raw), key, lines)
		def := lookupDefault(root, path)
		p, err := buildParam(path, pendingAnno, def)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		params = append(params, p)
		pendingAnno = ""
	}
	return params, nil
}

// parseTree decodes the values.yaml into a mapping node tree for
// default lookups.
func parseTree(src []byte) (*yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, err
	}
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		return doc.Content[0], nil
	}
	return &doc, nil
}

func leadingSpaces(s string) int {
	return len(s) - len(strings.TrimLeft(s, " "))
}

// leafKey extracts the YAML key from a `key: value` or `key:` line,
// returning "" when the line is not a mapping key.
func leafKey(trimmed string) string {
	idx := strings.Index(trimmed, ":")
	if idx <= 0 {
		return ""
	}
	key := strings.TrimSpace(trimmed[:idx])
	if key == "" || strings.ContainsAny(key, " \t") {
		return ""
	}
	return key
}

// keyPath reconstructs the dotted path of the annotated leaf at line
// leafIdx by scanning upward for shallower-indented parent keys.
func keyPath(leafIdx, indent int, leaf string, lines []string) string {
	parts := []string{leaf}
	curIndent := indent
	for i := leafIdx - 1; i >= 0 && curIndent > 0; i-- {
		l := lines[i]
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "-") {
			continue
		}
		ind := leadingSpaces(l)
		if ind < curIndent {
			if k := leafKey(t); k != "" {
				parts = append([]string{k}, parts...)
				curIndent = ind
			}
		}
	}
	return strings.Join(parts, ".")
}

// lookupDefault resolves a dotted path against the parsed tree and
// renders the leaf value as a documentation default string.
func lookupDefault(root *yaml.Node, path string) string {
	node := root
	for _, key := range strings.Split(path, ".") {
		node = mapChild(node, key)
		if node == nil {
			return "(unset)"
		}
	}
	return renderValue(node)
}

// mapChild returns the value node for key in a mapping node, or nil.
func mapChild(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// renderValue renders a YAML node as a compact documentation default.
func renderValue(n *yaml.Node) string {
	switch n.Kind {
	case yaml.ScalarNode:
		if n.Tag == "!!null" || n.Value == "" && n.Tag == "!!null" {
			return "null"
		}
		if n.Value == "" {
			return `""`
		}
		if n.Tag == "!!str" {
			return fmt.Sprintf("%q", n.Value)
		}
		return n.Value
	case yaml.MappingNode:
		if len(n.Content) == 0 {
			return "{}"
		}
		var b strings.Builder
		b.WriteString("{")
		for i := 0; i+1 < len(n.Content); i += 2 {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(n.Content[i].Value)
			b.WriteString(": ")
			b.WriteString(renderValue(n.Content[i+1]))
		}
		b.WriteString("}")
		return b.String()
	case yaml.SequenceNode:
		if len(n.Content) == 0 {
			return "[]"
		}
		var items []string
		for _, c := range n.Content {
			items = append(items, renderValue(c))
		}
		return "[" + strings.Join(items, ", ") + "]"
	default:
		return n.Value
	}
}

// buildParam parses one annotation attribute string into a param,
// carrying the leaf path and the default read from the YAML.
func buildParam(path, anno, def string) (param, error) {
	attrs, err := parseAttrs(anno)
	if err != nil {
		return param{}, err
	}
	typ := attrs["type"]
	if typ == "" {
		return param{}, fmt.Errorf("annotation missing required `type:` attribute")
	}
	group := strings.SplitN(path, ".", 2)[0]
	return param{
		group:  group,
		path:   path,
		typ:    typ,
		rang:   rangeOf(attrs),
		effect: attrs["effect"],
		ref:    attrs["ref"],
		def:    def,
	}, nil
}

// parseAttrs parses `key:value key:"quoted value"` pairs from an
// annotation body. Quoted values may contain spaces.
func parseAttrs(s string) (map[string]string, error) {
	attrs := map[string]string{}
	r := []rune(s)
	i := 0
	for i < len(r) {
		for i < len(r) && r[i] == ' ' {
			i++
		}
		if i >= len(r) {
			break
		}
		start := i
		for i < len(r) && r[i] != ':' {
			i++
		}
		if i >= len(r) {
			return nil, fmt.Errorf("malformed annotation attribute (missing ':') near %q", string(r[start:]))
		}
		key := strings.TrimSpace(string(r[start:i]))
		i++ // skip ':'
		var val string
		if i < len(r) && r[i] == '"' {
			i++
			var sb strings.Builder
			for i < len(r) && r[i] != '"' {
				if r[i] == '\\' && i+1 < len(r) {
					i++ // unescape: keep the next rune literally
				}
				sb.WriteRune(r[i])
				i++
			}
			val = sb.String()
			if i < len(r) {
				i++ // skip closing quote
			}
		} else {
			vs := i
			for i < len(r) && r[i] != ' ' {
				i++
			}
			val = string(r[vs:i])
		}
		attrs[key] = val
	}
	return attrs, nil
}

// rangeOf renders a human-readable valid-range string from the range
// attributes, or "-" when none are present.
func rangeOf(attrs map[string]string) string {
	if e, ok := attrs["enum"]; ok && e != "" {
		members := strings.Split(e, "|")
		var named []string
		emptyAllowed := false
		for _, m := range members {
			if m == "" {
				emptyAllowed = true
				continue
			}
			named = append(named, m)
		}
		out := "one of: " + strings.Join(named, ", ")
		if emptyAllowed {
			out += " (or empty to inherit)"
		}
		return out
	}
	if p, ok := attrs["pattern"]; ok && p != "" {
		return p
	}
	mn, hasMin := attrs["minimum"]
	mx, hasMax := attrs["maximum"]
	switch {
	case hasMin && hasMax:
		return fmt.Sprintf("%s to %s", mn, mx)
	case hasMin:
		return "minimum " + mn
	case hasMax:
		return "maximum " + mx
	default:
		return "-"
	}
}

// render emits the deterministic Markdown reference. Groups appear in
// values.yaml document order (params are appended in scan order);
// within a group the params keep their file order too.
func render(params []param, valuesPath string) []byte {
	var b bytes.Buffer
	b.WriteString("# Olaitan Helm values reference\n\n")
	fmt.Fprintf(&b, "Generated by `cmd/olaitan-helmdoc` from `%s`. Do NOT edit by hand:\n", valuesPath)
	b.WriteString("regenerate with `make helm-values-doc`; CI fails any drift (FR47).\n\n")
	b.WriteString("Each value below is documented with its name, type, default (read from\n")
	b.WriteString("the chart's real `values.yaml`, so it never drifts), valid range, effect,\n")
	b.WriteString("and (where applicable) the FR/NFR reference. To document a new tunable,\n")
	b.WriteString("annotate its leaf in `values.yaml` with a `# @schema ...` comment and\n")
	b.WriteString("rerun `make helm-values-doc` (see `docs/contributing.md`).\n\n")

	// Group order: first appearance in scan order.
	var order []string
	seen := map[string]bool{}
	byGroup := map[string][]param{}
	for _, p := range params {
		if !seen[p.group] {
			seen[p.group] = true
			order = append(order, p.group)
		}
		byGroup[p.group] = append(byGroup[p.group], p)
	}

	for _, g := range order {
		fmt.Fprintf(&b, "## `%s`\n\n", g)
		b.WriteString("| Value | Type | Default | Valid range | Effect | Ref |\n")
		b.WriteString("|-------|------|---------|-------------|--------|-----|\n")
		for _, p := range byGroup[g] {
			ref := p.ref
			if ref == "" {
				ref = "-"
			}
			fmt.Fprintf(&b, "| `%s` | %s | `%s` | %s | %s | %s |\n",
				p.path, p.typ, mdEscape(p.def), mdEscape(p.rang), mdEscape(p.effect), ref)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Config-file-only parameters (not Helm-exposed)\n\n")
	b.WriteString("These FR47-named parameters are NOT chart values: they live in\n")
	b.WriteString("`config/olaitan.yaml` (or are code-fixed) and are documented here for\n")
	b.WriteString("completeness. Set them by editing the mounted config, not via `--set`.\n\n")
	b.WriteString("| Parameter | Type | Default | Valid range | Effect | Ref | Where |\n")
	b.WriteString("|-----------|------|---------|-------------|--------|-----|-------|\n")
	// Stable order: as declared (deterministic), but sort defensively by
	// name so a reordering of the literal table never churns the diff.
	co := make([]configOnlyParam, len(configOnly))
	copy(co, configOnly)
	sort.SliceStable(co, func(i, j int) bool { return co[i].name < co[j].name })
	for _, c := range co {
		ref := c.ref
		if ref == "" {
			ref = "-"
		}
		fmt.Fprintf(&b, "| %s | %s | `%s` | %s | %s | %s | %s |\n",
			mdEscape(c.name), c.typ, mdEscape(c.def), mdEscape(c.rang), mdEscape(c.effect), ref, mdEscape(c.location))
	}
	b.WriteString("\n")
	return b.Bytes()
}

// mdEscape escapes the pipe character so a value containing it does not
// break the Markdown table column boundary.
func mdEscape(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}
