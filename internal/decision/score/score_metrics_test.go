package score

import (
	"testing"

	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/schema"
)

// gatheredCounter returns the current value of a counter metric by
// name, or -1 if absent. The metrics package binds counters via
// NewCounterFunc reading from an in-process atomic, so the only way
// to observe the value at test time is to gather the registry.
func gatheredCounter(t *testing.T, reg *metrics.Registry, name string) float64 {
	t.Helper()
	mfs, err := reg.Gatherer().Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			return m.GetCounter().GetValue()
		}
	}
	return -1
}

// TestNew_RegistersMetricFamilies asserts that constructing a
// Calculator with a non-nil registry registers the three Story 2.1
// metric families. CounterVec / HistogramVec families do not surface
// in Gather() output until at least one label combination has been
// observed; the test drives one Score() call to make the
// histogram-vec family visible before gathering.
func TestNew_RegistersMetricFamilies(t *testing.T) {
	reg := metrics.NewRegistry()
	c, err := newWithGetter(staticGetter(defaultScoreCfg()), reg)
	if err != nil {
		t.Fatalf("newWithGetter: %v", err)
	}
	if _, err := c.Score(&schema.EvidencePackage{}); err != nil {
		t.Fatalf("Score: %v", err)
	}

	mfs, err := reg.Gatherer().Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	want := map[string]bool{
		"olaitan_decision_score_evaluations_total":  false,
		"olaitan_decision_score_total":              false,
		"olaitan_decision_score_evaluation_seconds": false,
	}
	for _, mf := range mfs {
		if _, ok := want[mf.GetName()]; ok {
			want[mf.GetName()] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("metric %q not registered", name)
		}
	}
}

// TestScore_IncrementsEvaluationsCounter pins the counter behaviour:
// one Score() call increments olaitan_decision_score_evaluations_total
// by exactly 1.
func TestScore_IncrementsEvaluationsCounter(t *testing.T) {
	reg := metrics.NewRegistry()
	c, err := newWithGetter(staticGetter(defaultScoreCfg()), reg)
	if err != nil {
		t.Fatalf("newWithGetter: %v", err)
	}

	before := gatheredCounter(t, reg, "olaitan_decision_score_evaluations_total")
	if _, err := c.Score(&schema.EvidencePackage{}); err != nil {
		t.Fatalf("Score: %v", err)
	}
	after := gatheredCounter(t, reg, "olaitan_decision_score_evaluations_total")

	if got := after - before; got != 1 {
		t.Fatalf("evaluations_total delta: want 1, got %v", got)
	}
}

// TestScore_HistogramLabelCardinalityFinite locks the cardinality
// bound for olaitan_decision_score_total: 3 components x 4 buckets =
// 12 maximum series per architecture.md:476 guidance.
func TestScore_HistogramLabelCardinalityFinite(t *testing.T) {
	reg := metrics.NewRegistry()
	c, err := newWithGetter(staticGetter(defaultScoreCfg()), reg)
	if err != nil {
		t.Fatalf("newWithGetter: %v", err)
	}

	cases := []*schema.EvidencePackage{
		{},
		{RuleMatches: []schema.RuleMatch{{Severity: "25"}}},
		{RuleMatches: []schema.RuleMatch{{Severity: "75"}}},
		{RuleMatches: []schema.RuleMatch{{Severity: "100"}}, BaselineDeviations: []schema.BaselineDeviation{{Sigma: 10}}},
	}
	for _, p := range cases {
		if _, err := c.Score(p); err != nil {
			t.Fatalf("Score: %v", err)
		}
	}

	mfs, err := reg.Gatherer().Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	var totalSeries int
	for _, mf := range mfs {
		if mf.GetName() != "olaitan_decision_score_total" {
			continue
		}
		totalSeries = len(mf.GetMetric())
	}
	if totalSeries == 0 {
		t.Fatalf("score_total: no series observed after %d Score() calls", len(cases))
	}
	if totalSeries > 12 {
		t.Fatalf("score_total cardinality: %d series exceeds 12-series ceiling", totalSeries)
	}
}

// TestScore_NilRegistryConstructs locks that the calculator
// constructs successfully without a registry (production wiring
// always supplies one, but unit tests in this package commonly omit
// it). The Score path becomes observability-free without panicking.
func TestScore_NilRegistryConstructs(t *testing.T) {
	c, err := newWithGetter(staticGetter(defaultScoreCfg()), nil)
	if err != nil {
		t.Fatalf("newWithGetter: %v", err)
	}
	if _, err := c.Score(&schema.EvidencePackage{}); err != nil {
		t.Fatalf("Score: %v", err)
	}
}
