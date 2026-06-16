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
//     set. The canonical set is DERIVED FROM THE CODE, not hand-maintained:
//     the tool scans the Go source tree for "olaitan_*" string literals (the
//     same grounding the dashboards are authored against), so adding a real
//     metric auto-allows it and a fake one fails. A small EXCLUDE allow-list
//     removes the Story 4.9 retired names (which survive in code only inside
//     rename-documenting Help strings/comments) and the test-only name, so a
//     dashboard cannot reference a retired metric.
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

// canonicalMetrics walks the Go source tree under roots and returns the set of
// every olaitan_* metric name registered in code, minus the retired/test-only
// allow-list. It scans raw file bytes for the metric literals (the names are
// always string literals at the registration call sites), which is sufficient
// and keeps the tool dependency-free; comments that mention a retired name are
// stripped by the explicit retiredMetrics exclusion.
func canonicalMetrics(roots []string) (map[string]struct{}, error) {
	set := make(map[string]struct{})
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			b, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			for _, m := range metricLiteral.FindAllString(string(b), -1) {
				if _, retired := retiredMetrics[m]; retired {
					continue
				}
				set[m] = struct{}{}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return set, nil
}

// dashboard is the minimal Grafana dashboard shape this tool inspects. Unknown
// fields are ignored; the tool asserts only the load-bearing structure.
type dashboard struct {
	Title         string  `json:"title"`
	SchemaVersion *int    `json:"schemaVersion"`
	Panels        []panel `json:"panels"`
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
		for _, m := range metricLiteral.FindAllString(expr, -1) {
			if metricKnown(m, canonical) {
				continue
			}
			findings = append(findings, fmt.Sprintf("%s: panel expr references unknown metric %q (not registered in code; expr: %s)", path, m, expr))
		}
	}
	return findings
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
