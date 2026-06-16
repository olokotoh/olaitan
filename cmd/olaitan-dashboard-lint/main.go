// Command olaitan-dashboard-lint mechanically enforces that every pre-built
// Grafana dashboard under deploy/grafana/dashboards/ is valid and grounded in
// a metric the agent actually exports (Story 6.7, FR50/NFR32/NFR34). It is the
// "no live Grafana" testable proxy for the AC2 "every panel references a real
// metric" guarantee: a dashboard that references a non-existent or retired
// metric name renders empty against a live Prometheus, which a human review of
// JSON cannot reliably catch, so CI catches it here instead.
//
// The tool performs two checks over each dashboards/*.json file:
//
//  1. Structure + schema pin (AC3): the file parses as JSON, carries a
//     non-empty title, a panels array, and the pinned schemaVersion (39,
//     Grafana 11.1.x). A wrong or missing schemaVersion fails the build.
//
//  2. Metric-reference correctness (AC2): every Prometheus metric name
//     referenced in any panel target expr must exist in the CANONICAL metric
//     set. The canonical set is DERIVED FROM THE CODE, not hand-maintained,
//     and is scoped to REAL Prometheus registration sites via go/ast (NOT a
//     raw byte grep, which would leak retired names from negative tests,
//     fakes from test fixtures, doc-comment mentions, and YAML/JSON struct
//     tags into the allow-list). A name is canonical only if it is an
//     "olaitan_*" string literal (or a name-constant resolving to one) that
//     reaches a Prometheus registration site:
//
//     - the Name: field of a prometheus.{Counter,Gauge,Histogram,Summary}Opts
//     composite literal (and the ...Vec variants share that Opts shape);
//     - an argument to a metric registrar call (a callee whose name begins
//     with "register"/"Register" - the metrics.Registry.Register* methods
//     and the per-package register* wrappers); or
//     - a direct string-literal element of a metric-table composite literal
//     (the posturePromName positional-struct table feeds prometheus
//     CounterOpts{Name: p.name} through a loop).
//
//     *_test.go files are excluded entirely, so a negative-test literal (e.g.
//     the retired olaitan_decision_llm_cap_violation_total asserted GONE in
//     cmd/olaitan/llm_observability_test.go) never enters the canonical set.
//     A small EXCLUDE allow-list (retiredMetrics) belt-and-suspenders removes
//     the Story 4.9 retired names so a dashboard cannot reference them even if
//     a derivation re-introduced them.
//
// Histogram-derived suffixes (_bucket / _count / _sum) resolve to their base
// metric before the canonical-set lookup.
//
// This is a SEPARATE make target and a SEPARATE always-on CI step (not folded
// into golangci-lint), so a dashboard-grounding failure is attributable rather
// than buried among the staticcheck/errcheck output, matching the Story 6.5
// olaitan-lint / 6.3 schema-gate / 6.4 helm-doc-gate step-per-enforcement
// precedent.
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// PinnedSchemaVersion is the Grafana dashboard schemaVersion every committed
// dashboard must declare. 39 corresponds to Grafana 11.1.x (the last line
// using the classic dashboard JSON model before the Grafana 12 schema rework);
// the rationale is documented in deploy/grafana/README.md.
const PinnedSchemaVersion = 39

// retiredMetrics are olaitan_* literals that appear in the Go source ONLY
// inside rename-documenting Help strings / comments (Story 4.9 reconciliation)
// or as test-only registrations. They are NOT live exported metrics, so a
// dashboard must never reference them; we strip them from the code-derived
// canonical set so a dashboard that does so fails.
var retiredMetrics = map[string]struct{}{
	"olaitan_dfir_reports_total":                     {}, // renamed -> olaitan_report_dfir_calls_total (Story 4.9)
	"olaitan_dfir_report_generation_seconds":         {}, // renamed -> olaitan_report_dfir_duration_seconds (Story 4.9)
	"olaitan_decision_rules_evaluation_seconds_test": {}, // test-only histogram name
	"olaitan_decision_llm_cap_violation_total":       {}, // renamed -> olaitan_llm_cap_violation_total (Story 3.15/FR50)
}

// metricLiteral matches a fully-qualified Olaitan metric name. The trailing
// boundary excludes a partial-prefix literal (e.g. "olaitan_sensor_posture_").
var metricLiteral = regexp.MustCompile(`olaitan_[a-z0-9_]+`)

// histogramSuffix strips the Prometheus histogram-derived suffix so a panel
// referencing olaitan_x_seconds_bucket resolves to the registered base metric
// olaitan_x_seconds.
var histogramSuffix = regexp.MustCompile(`_(bucket|count|sum)$`)

func main() {
	dashboardsDir := "deploy/grafana/dashboards"
	codeRoots := []string{"internal", "cmd"}
	if len(os.Args) > 1 {
		dashboardsDir = os.Args[1]
	}
	if len(os.Args) > 2 {
		codeRoots = os.Args[2:]
	}

	canonical, err := canonicalMetrics(codeRoots)
	if err != nil {
		fmt.Fprintf(os.Stderr, "olaitan-dashboard-lint: derive canonical metric set: %v\n", err)
		os.Exit(2)
	}
	if len(canonical) == 0 {
		fmt.Fprintf(os.Stderr, "olaitan-dashboard-lint: derived an EMPTY canonical metric set from %v - refusing to pass (a bad scan would let every metric through)\n", codeRoots)
		os.Exit(2)
	}

	findings, err := lintDashboards(dashboardsDir, canonical)
	if err != nil {
		fmt.Fprintf(os.Stderr, "olaitan-dashboard-lint: %v\n", err)
		os.Exit(2)
	}

	if len(findings) > 0 {
		for _, f := range findings {
			fmt.Fprintln(os.Stderr, f)
		}
		fmt.Fprintf(os.Stderr, "olaitan-dashboard-lint: %d finding(s)\n", len(findings))
		os.Exit(1)
	}

	fmt.Printf("olaitan-dashboard-lint: OK (%d canonical metrics, all dashboard panels grounded, schemaVersion %d)\n",
		len(canonical), PinnedSchemaVersion)
}

// canonicalMetrics parses the Go source tree under roots with go/ast and
// returns the set of every olaitan_* metric name registered at a real
// Prometheus registration site, minus the retired/test-only allow-list.
//
// Unlike a raw byte grep (which leaks retired names from negative tests,
// fakes from test fixtures, doc-comment mentions, and YAML/JSON struct tags),
// this resolves the canonical set ONLY from registration sites (see the
// package comment for the three accepted shapes). _test.go files are skipped
// entirely. Name-constants (the repo's `const FooMetricName = "olaitan_foo"`
// pattern, used as a registrar arg or Opts Name:) are resolved to their
// literal value before inclusion, so a metric registered via a constant is
// still recognised.
func canonicalMetrics(roots []string) (map[string]struct{}, error) {
	files, err := goFiles(roots)
	if err != nil {
		return nil, err
	}

	fset := token.NewFileSet()
	parsed := make([]*ast.File, 0, len(files))
	for _, path := range files {
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil, fmt.Errorf("parse %s: %w", path, perr)
		}
		parsed = append(parsed, f)
	}

	// First pass: collect every `const Ident = "olaitan_..."` so a metric
	// registered via a name-constant resolves to its literal value. Constants
	// are package-scoped and the registration sites live in the same package,
	// so a flat cross-file map is sufficient.
	nameConsts := make(map[string]string)
	for _, f := range parsed {
		ast.Inspect(f, func(n ast.Node) bool {
			gd, ok := n.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				return true
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					if lit, ok := metricStringLiteral(vs.Values[i]); ok {
						nameConsts[name.Name] = lit
					}
				}
			}
			return true
		})
	}

	// resolve returns the olaitan_* metric name an expression denotes, if it is
	// a string literal or an identifier bound to a metric-name constant.
	resolve := func(e ast.Expr) (string, bool) {
		if lit, ok := metricStringLiteral(e); ok {
			return lit, true
		}
		if id, ok := e.(*ast.Ident); ok {
			if lit, ok := nameConsts[id.Name]; ok {
				return lit, true
			}
		}
		// A package-qualified constant (e.g. provider.CallsMetricName) resolves
		// to the same flat map by its bare name; the registration call always
		// lives in the same module so the literal was captured above.
		if sel, ok := e.(*ast.SelectorExpr); ok {
			if lit, ok := nameConsts[sel.Sel.Name]; ok {
				return lit, true
			}
		}
		return "", false
	}

	set := make(map[string]struct{})
	add := func(name string) {
		if _, retired := retiredMetrics[name]; retired {
			return
		}
		set[name] = struct{}{}
	}

	for _, f := range parsed {
		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CallExpr:
				// Sink 1: an argument to a metric registrar call. The repo's
				// registrars (metrics.Registry.Register* methods, the
				// per-package register* wrappers) all take the metric name as a
				// string argument; collect every olaitan_* string/const arg so
				// the rule is position-independent across the registrar shapes.
				if isRegistrarCall(node.Fun) {
					for _, arg := range node.Args {
						if name, ok := resolve(arg); ok {
							add(name)
						}
					}
				}
			case *ast.CompositeLit:
				if isPromOptsLit(node.Type) {
					// Sink 2: the Name: field of a prometheus.*Opts literal.
					for _, elt := range node.Elts {
						kv, ok := elt.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Name" {
							if name, ok := resolve(kv.Value); ok {
								add(name)
							}
						}
					}
				} else {
					// Sink 3: a direct olaitan_* string-literal element of a
					// metric-table composite literal (the posturePromName
					// positional struct table, whose name field is fed into
					// prometheus.CounterOpts{Name: p.name} by a loop). Help
					// strings and short keys do not match the metric-name
					// shape, so only true metric names are captured.
					for _, elt := range node.Elts {
						if lit, ok := metricStringLiteral(elt); ok {
							add(lit)
						}
					}
				}
			}
			return true
		})
	}
	return set, nil
}

// goFiles returns the sorted set of non-test .go files under roots.
func goFiles(roots []string) ([]string, error) {
	var files []string
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			files = append(files, path)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(files)
	return files, nil
}

// metricStringLiteral returns the unquoted value of e if e is a string literal
// whose value is a fully-qualified olaitan_* metric name.
func metricStringLiteral(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s := strings.Trim(lit.Value, "`\"")
	if metricLiteral.MatchString(s) && metricLiteral.FindString(s) == s {
		return s, true
	}
	return "", false
}

// isRegistrarCall reports whether fun is a call to a Prometheus metric
// registrar: either a method/function whose name begins with "register" or
// "Register" (the metrics.Registry.Register* methods and the per-package
// register* wrappers), or a prometheus.New{Counter,Gauge,Histogram,Summary}*
// constructor. The metric name is then collected from the call's string args.
func isRegistrarCall(fun ast.Expr) bool {
	name := ""
	switch f := fun.(type) {
	case *ast.SelectorExpr:
		name = f.Sel.Name
	case *ast.Ident:
		name = f.Name
	default:
		return false
	}
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, "register") {
		return true
	}
	if strings.HasPrefix(name, "New") && (strings.Contains(name, "Counter") ||
		strings.Contains(name, "Gauge") || strings.Contains(name, "Histogram") ||
		strings.Contains(name, "Summary")) {
		return true
	}
	return false
}

// isPromOptsLit reports whether t is a prometheus.{Counter,Gauge,Histogram,
// Summary}Opts type (the ...Vec constructors reuse the same Opts shape).
func isPromOptsLit(t ast.Expr) bool {
	sel, ok := t.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "prometheus" {
		return false
	}
	switch sel.Sel.Name {
	case "CounterOpts", "GaugeOpts", "HistogramOpts", "SummaryOpts":
		return true
	}
	return false
}

// dashboard is the minimal Grafana dashboard shape this tool inspects. Unknown
// fields are ignored; the tool asserts only the load-bearing structure.
type dashboard struct {
	Title         string     `json:"title"`
	SchemaVersion *int       `json:"schemaVersion"`
	Panels        []panel    `json:"panels"`
	Templating    templating `json:"templating"`
}

type panel struct {
	Targets []target `json:"targets"`
	// Row panels nest their children under "panels"; flatten them so a metric
	// inside a collapsed row is still checked.
	Panels []panel `json:"panels"`
}

type target struct {
	Expr string `json:"expr"`
}

// templating carries the dashboard's template-variable list so a metric-backed
// variable query cannot smuggle a fake metric past the gate (Story 6.7
// follow-up FIX 4).
type templating struct {
	List []templateVar `json:"list"`
}

// templateVar models one template variable. query may be a bare string (e.g. a
// datasource-type variable's "prometheus") or an object whose "query"/"expr"
// holds the PromQL, so it is captured as raw JSON and any string content is
// scanned for metric references. definition mirrors the resolved query for
// query-type variables.
type templateVar struct {
	Query      json.RawMessage `json:"query"`
	Definition string          `json:"definition"`
}

// lintDashboards validates every *.json under dir and returns one finding
// string per problem (an empty slice means the gate passes).
func lintDashboards(dir string, canonical map[string]struct{}) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read dashboards dir %q: %w", dir, err)
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no *.json dashboards found under %q", dir)
	}
	sort.Strings(files)

	var findings []string
	for _, f := range files {
		findings = append(findings, lintFile(f, canonical)...)
	}
	return findings, nil
}

func lintFile(path string, canonical map[string]struct{}) []string {
	var findings []string

	b, err := os.ReadFile(path)
	if err != nil {
		return []string{fmt.Sprintf("%s: read: %v", path, err)}
	}

	var d dashboard
	if err := json.Unmarshal(b, &d); err != nil {
		return []string{fmt.Sprintf("%s: invalid JSON: %v", path, err)}
	}

	if strings.TrimSpace(d.Title) == "" {
		findings = append(findings, fmt.Sprintf("%s: missing dashboard title", path))
	}
	switch {
	case d.SchemaVersion == nil:
		findings = append(findings, fmt.Sprintf("%s: missing schemaVersion (expected %d)", path, PinnedSchemaVersion))
	case *d.SchemaVersion != PinnedSchemaVersion:
		findings = append(findings, fmt.Sprintf("%s: schemaVersion %d, expected the pinned %d (Grafana 11.1.x)", path, *d.SchemaVersion, PinnedSchemaVersion))
	}
	if len(d.Panels) == 0 {
		findings = append(findings, fmt.Sprintf("%s: dashboard has no panels", path))
	}

	exprs := collectExprs(d.Panels)
	if len(exprs) == 0 {
		findings = append(findings, fmt.Sprintf("%s: no panel target expressions found", path))
	}
	for _, expr := range exprs {
		findings = append(findings, checkMetrics(path, "panel expr", expr, canonical)...)
	}

	// FIX 4: scan template-variable queries so a future metric-backed variable
	// cannot smuggle a fake metric past the gate. The current dashboards use
	// only a datasource-type variable (query "prometheus"), which references no
	// olaitan_* metric, so this does not change their pass/fail.
	for _, q := range collectTemplatingQueries(d.Templating) {
		findings = append(findings, checkMetrics(path, "templating query", q, canonical)...)
	}
	return findings
}

// checkMetrics returns one finding per olaitan_* metric in s that is not in the
// canonical set. kind labels the source location (panel expr / templating
// query) for the operator.
func checkMetrics(path, kind, s string, canonical map[string]struct{}) []string {
	var findings []string
	for _, m := range metricLiteral.FindAllString(s, -1) {
		if metricKnown(m, canonical) {
			continue
		}
		findings = append(findings, fmt.Sprintf("%s: %s references unknown metric %q (not registered in code; source: %s)", path, kind, m, s))
	}
	return findings
}

// collectTemplatingQueries returns every string fragment of each template
// variable's query and definition. query may be a bare JSON string or an object
// (whose nested string values, e.g. "query"/"expr", carry the PromQL); both
// shapes are flattened to strings so metric references are caught.
func collectTemplatingQueries(t templating) []string {
	var out []string
	for _, v := range t.List {
		out = append(out, jsonStrings(v.Query)...)
		if strings.TrimSpace(v.Definition) != "" {
			out = append(out, v.Definition)
		}
	}
	return out
}

// jsonStrings extracts every string value reachable in raw (a bare string, or
// the string leaves of an object/array). Non-string scalars are ignored.
func jsonStrings(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	var out []string
	var walk func(any)
	walk = func(n any) {
		switch t := n.(type) {
		case string:
			if strings.TrimSpace(t) != "" {
				out = append(out, t)
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(v)
	return out
}

// metricKnown reports whether m is a registered metric. It first tries the
// literal name (so a gauge legitimately ending in _count such as
// olaitan_report_writes_deferred_count is matched directly), then falls back
// to the histogram base name (so olaitan_x_seconds_bucket resolves to the
// registered histogram olaitan_x_seconds). The literal-first order is
// load-bearing: stripping _count unconditionally would wrongly reject the
// deferred-count gauge.
func metricKnown(m string, canonical map[string]struct{}) bool {
	if _, ok := canonical[m]; ok {
		return true
	}
	if base := histogramSuffix.ReplaceAllString(m, ""); base != m {
		if _, ok := canonical[base]; ok {
			return true
		}
	}
	return false
}

// collectExprs flattens every target expr in the panel tree (including nested
// row panels).
func collectExprs(panels []panel) []string {
	var out []string
	for _, p := range panels {
		for _, t := range p.Targets {
			if strings.TrimSpace(t.Expr) != "" {
				out = append(out, t.Expr)
			}
		}
		out = append(out, collectExprs(p.Panels)...)
	}
	return out
}
