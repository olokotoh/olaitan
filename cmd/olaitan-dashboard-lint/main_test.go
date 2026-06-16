package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// canonical is a small fixed canonical set for the fixture-driven tests; the
// real tree is exercised separately by TestRealDashboardsPass.
func fixtureCanonical() map[string]struct{} {
	return map[string]struct{}{
		"olaitan_source_healthy":               {},
		"olaitan_sensor_events_total":          {},
		"olaitan_llm_call_duration_seconds":    {},
		"olaitan_report_writes_deferred_count": {},
	}
}

func writeJSON(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write fixture %s: %v", name, err)
	}
	return p
}

func TestValidDashboardPasses(t *testing.T) {
	dir := t.TempDir()
	p := writeJSON(t, dir, "ok.json", `{
		"title": "Source health",
		"schemaVersion": 39,
		"panels": [
			{"targets": [{"expr": "min(olaitan_source_healthy) by (source)"}]},
			{"targets": [{"expr": "histogram_quantile(0.99, sum by (le) (rate(olaitan_llm_call_duration_seconds_bucket[5m])))"}]}
		]
	}`)

	findings := lintFile(p, fixtureCanonical())
	if len(findings) != 0 {
		t.Fatalf("expected a clean valid dashboard, got findings: %v", findings)
	}
}

func TestFakeMetricIsRejected(t *testing.T) {
	dir := t.TempDir()
	p := writeJSON(t, dir, "fake.json", `{
		"title": "Bogus",
		"schemaVersion": 39,
		"panels": [
			{"targets": [{"expr": "rate(olaitan_totally_made_up_total[5m])"}]}
		]
	}`)

	findings := lintFile(p, fixtureCanonical())
	if len(findings) == 0 {
		t.Fatal("expected a finding for the fabricated metric, got none")
	}
	if !strings.Contains(strings.Join(findings, "\n"), "olaitan_totally_made_up_total") {
		t.Fatalf("finding should name the fake metric, got: %v", findings)
	}
}

func TestRetiredMetricIsRejected(t *testing.T) {
	// A retired Story-4.9 name must be rejected even though the literal still
	// exists in code (inside rename-documenting Help strings). The fixture
	// canonical set intentionally omits it (as the real derive does via the
	// retiredMetrics exclusion).
	dir := t.TempDir()
	p := writeJSON(t, dir, "retired.json", `{
		"title": "Retired name",
		"schemaVersion": 39,
		"panels": [
			{"targets": [{"expr": "rate(olaitan_dfir_reports_total[5m])"}]}
		]
	}`)

	findings := lintFile(p, fixtureCanonical())
	if len(findings) == 0 {
		t.Fatal("expected a finding for the retired metric name, got none")
	}
}

func TestWrongSchemaVersionIsRejected(t *testing.T) {
	dir := t.TempDir()
	p := writeJSON(t, dir, "v36.json", `{
		"title": "Old schema",
		"schemaVersion": 36,
		"panels": [
			{"targets": [{"expr": "olaitan_source_healthy"}]}
		]
	}`)

	findings := lintFile(p, fixtureCanonical())
	joined := strings.Join(findings, "\n")
	if !strings.Contains(joined, "schemaVersion 36") {
		t.Fatalf("expected a schemaVersion finding, got: %v", findings)
	}
}

func TestMissingSchemaVersionIsRejected(t *testing.T) {
	dir := t.TempDir()
	p := writeJSON(t, dir, "noschema.json", `{
		"title": "No schema",
		"panels": [{"targets": [{"expr": "olaitan_source_healthy"}]}]
	}`)

	findings := lintFile(p, fixtureCanonical())
	if !strings.Contains(strings.Join(findings, "\n"), "missing schemaVersion") {
		t.Fatalf("expected a missing-schemaVersion finding, got: %v", findings)
	}
}

func TestInvalidJSONIsRejected(t *testing.T) {
	dir := t.TempDir()
	p := writeJSON(t, dir, "broken.json", `{ this is not json `)

	findings := lintFile(p, fixtureCanonical())
	if !strings.Contains(strings.Join(findings, "\n"), "invalid JSON") {
		t.Fatalf("expected an invalid-JSON finding, got: %v", findings)
	}
}

func TestNestedRowPanelMetricsAreChecked(t *testing.T) {
	dir := t.TempDir()
	p := writeJSON(t, dir, "rows.json", `{
		"title": "Rows",
		"schemaVersion": 39,
		"panels": [
			{"type": "row", "panels": [
				{"targets": [{"expr": "rate(olaitan_fake_in_a_row_total[5m])"}]}
			]}
		]
	}`)

	findings := lintFile(p, fixtureCanonical())
	if !strings.Contains(strings.Join(findings, "\n"), "olaitan_fake_in_a_row_total") {
		t.Fatalf("expected the nested-row fake metric to be caught, got: %v", findings)
	}
}

func TestHistogramSuffixResolvesToBase(t *testing.T) {
	dir := t.TempDir()
	p := writeJSON(t, dir, "hist.json", `{
		"title": "Histogram",
		"schemaVersion": 39,
		"panels": [
			{"targets": [
				{"expr": "olaitan_llm_call_duration_seconds_bucket"},
				{"expr": "olaitan_llm_call_duration_seconds_count"},
				{"expr": "olaitan_llm_call_duration_seconds_sum"}
			]}
		]
	}`)

	findings := lintFile(p, fixtureCanonical())
	if len(findings) != 0 {
		t.Fatalf("histogram _bucket/_count/_sum should resolve to the base metric, got: %v", findings)
	}
}

// TestCanonicalSetExcludesRetired proves the code-derived canonical set does
// not contain the retired names even though their literals are in the tree.
func TestCanonicalSetExcludesRetired(t *testing.T) {
	set, err := canonicalMetrics([]string{repoRoot(t, "internal"), repoRoot(t, "cmd")})
	if err != nil {
		t.Fatalf("derive canonical set: %v", err)
	}
	if len(set) == 0 {
		t.Fatal("derived an empty canonical set from the real tree")
	}
	for retired := range retiredMetrics {
		if _, ok := set[retired]; ok {
			t.Errorf("retired metric %q leaked into the canonical set", retired)
		}
	}
	// Sanity: a known-live metric is present.
	if _, ok := set["olaitan_source_healthy"]; !ok {
		t.Error("expected olaitan_source_healthy in the canonical set")
	}
}

// TestRealDashboardsPass runs the full guard over the six committed dashboards
// against the real code-derived canonical set: every panel metric must exist.
func TestRealDashboardsPass(t *testing.T) {
	canonical, err := canonicalMetrics([]string{repoRoot(t, "internal"), repoRoot(t, "cmd")})
	if err != nil {
		t.Fatalf("derive canonical set: %v", err)
	}
	findings, err := lintDashboards(repoRoot(t, "deploy/grafana/dashboards"), canonical)
	if err != nil {
		t.Fatalf("lint committed dashboards: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("committed dashboards must pass the guard, got findings:\n%s", strings.Join(findings, "\n"))
	}
}

// repoRoot resolves a path relative to the repository root from the test's
// working directory (cmd/olaitan-dashboard-lint/).
func repoRoot(t *testing.T, rel string) string {
	t.Helper()
	return filepath.Join("..", "..", rel)
}
