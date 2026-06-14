package dfir

import (
	"context"
	"testing"

	dto "github.com/prometheus/client_model/go"

	"github.com/olokotoh/olaitan/internal/agent/provider"
	"github.com/olokotoh/olaitan/internal/metrics"
)

// gatherFamily gathers the registry and returns the metric family by name (or
// nil if not registered). The Story 3.15 metric-registration test precedent.
func gatherFamily(t *testing.T, reg *metrics.Registry, name string) *dto.MetricFamily {
	t.Helper()
	mfs, err := reg.Gatherer().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == name {
			return mf
		}
	}
	return nil
}

// newAgentWithReg builds a DFIR agent over a fresh registry the test owns so it
// can gather and assert the canonical metric set (Story 4.9 AC1/AC2).
func newAgentWithReg(t *testing.T, fp *fakeProvider) (*Agent, *metrics.Registry) {
	t.Helper()
	reg := metrics.NewRegistry()
	a, err := NewDFIR(fp, PromptSpec{System: "you are the DFIR analyst", Version: "dfir.test.v1"}, &fakeReportPublisher{}, nil, nil, nil, reg, nil)
	if err != nil {
		t.Fatalf("NewDFIR: %v", err)
	}
	return a, reg
}

// TestForensicMetrics_DFIRCallsCanonical asserts the renamed AC1 counter
// olaitan_report_dfir_calls_total is registered as a counter with the {provider,
// status} label set and increments with the provider + status values on a
// generation; the OLD Story 4.4 name olaitan_dfir_reports_total is NOT registered
// (Story 4.9 BI-1/BI-3, the clean rename).
func TestForensicMetrics_DFIRCallsCanonical(t *testing.T) {
	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8", resp: provider.Response{Raw: validReportJSON, StopReason: "end_turn", Model: "claude-opus-4-8"}}
	a, reg := newAgentWithReg(t, fp)

	if mf := gatherFamily(t, reg, "olaitan_dfir_reports_total"); mf != nil {
		t.Fatalf("OLD name olaitan_dfir_reports_total is still registered; the rename must drop it")
	}

	if _, _, err := a.Generate(context.Background(), testIncident()); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// A labelled CounterVec surfaces in Gather only after a label combination is
	// touched; one generation touches {provider=claude, status=success}.
	mf := gatherFamily(t, reg, "olaitan_report_dfir_calls_total")
	if mf == nil {
		t.Fatalf("canonical olaitan_report_dfir_calls_total not registered")
	}
	if mf.GetType() != dto.MetricType_COUNTER {
		t.Fatalf("olaitan_report_dfir_calls_total type = %v, want COUNTER", mf.GetType())
	}
	if got := len(mf.GetMetric()); got != 1 {
		t.Fatalf("series count = %d, want 1 after one generation", got)
	}
	series := mf.GetMetric()[0]
	labels := map[string]string{}
	for _, lp := range series.GetLabel() {
		labels[lp.GetName()] = lp.GetValue()
	}
	if labels["provider"] != "claude" {
		t.Errorf("provider label = %q, want claude", labels["provider"])
	}
	if labels["status"] != statusSuccess {
		t.Errorf("status label = %q, want %q", labels["status"], statusSuccess)
	}
	if got := series.GetCounter().GetValue(); got != 1 {
		t.Errorf("counter value = %v, want 1", got)
	}
}

// TestForensicMetrics_DFIRCallsProviderUnknown asserts OA1: an empty provider
// Name() yields the literal "unknown" provider label, never the empty string.
func TestForensicMetrics_DFIRCallsProviderUnknown(t *testing.T) {
	fp := &fakeProvider{name: "", model: "m", resp: provider.Response{Raw: validReportJSON, StopReason: "end_turn", Model: "m"}}
	a, reg := newAgentWithReg(t, fp)
	if _, _, err := a.Generate(context.Background(), testIncident()); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	mf := gatherFamily(t, reg, "olaitan_report_dfir_calls_total")
	if mf == nil || len(mf.GetMetric()) != 1 {
		t.Fatalf("expected one series, got %v", mf)
	}
	for _, lp := range mf.GetMetric()[0].GetLabel() {
		if lp.GetName() == "provider" && lp.GetValue() != "unknown" {
			t.Errorf("empty provider label = %q, want unknown", lp.GetValue())
		}
	}
}

// TestForensicMetrics_DFIRDurationCanonical asserts the renamed AC1 histogram
// olaitan_report_dfir_duration_seconds is registered as a histogram and observes;
// the OLD name olaitan_dfir_report_generation_seconds is NOT registered (BI-1).
func TestForensicMetrics_DFIRDurationCanonical(t *testing.T) {
	fp := &fakeProvider{name: "claude", model: "m", resp: provider.Response{Raw: validReportJSON, StopReason: "end_turn", Model: "m"}}
	a, reg := newAgentWithReg(t, fp)

	if mf := gatherFamily(t, reg, "olaitan_dfir_report_generation_seconds"); mf != nil {
		t.Fatalf("OLD histogram name still registered; the rename must drop it")
	}
	mf := gatherFamily(t, reg, "olaitan_report_dfir_duration_seconds")
	if mf == nil {
		t.Fatalf("canonical olaitan_report_dfir_duration_seconds not registered")
	}
	if mf.GetType() != dto.MetricType_HISTOGRAM {
		t.Fatalf("olaitan_report_dfir_duration_seconds type = %v, want HISTOGRAM", mf.GetType())
	}

	if _, _, err := a.Generate(context.Background(), testIncident()); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	mf = gatherFamily(t, reg, "olaitan_report_dfir_duration_seconds")
	if got := mf.GetMetric()[0].GetHistogram().GetSampleCount(); got != 1 {
		t.Errorf("histogram sample count = %d, want 1", got)
	}
}

// TestForensicMetrics_DrainedCounterRegistered asserts the NEW dedicated drained
// counter olaitan_report_writes_deferred_drained_total is registered as a counter
// (Story 4.9 AC2/BI-5). The drain-increment behaviour is proved in
// TestWriteReport_DefersBeyondBudget and the deferq package tests.
func TestForensicMetrics_DrainedCounterRegistered(t *testing.T) {
	fp := &fakeProvider{name: "claude", model: "m"}
	a, reg := newAgentWithReg(t, fp)
	a.deferredDrained.Add(0)
	mf := gatherFamily(t, reg, "olaitan_report_writes_deferred_drained_total")
	if mf == nil {
		t.Fatalf("olaitan_report_writes_deferred_drained_total not registered")
	}
	if mf.GetType() != dto.MetricType_COUNTER {
		t.Fatalf("drained counter type = %v, want COUNTER", mf.GetType())
	}
}

// TestForensicMetrics_S3WriterCanonical is the AC2 confirm-only assertion: the
// existing S3-writer metric families already carry the canonical names + label
// sets + types and need no change (Story 4.9 BI-6/BI-7).
func TestForensicMetrics_S3WriterCanonical(t *testing.T) {
	fp := &fakeProvider{name: "claude", model: "m"}
	a, reg := newAgentWithReg(t, fp)

	// Touch each labelled handle so the family surfaces in Gather (a CounterVec
	// with no observed label combination produces no metric family). Add(0) /
	// Observe make the assertion robust without exercising the write path.
	a.writes.WithLabelValues(writeResultSuccess).Add(0)
	a.writeSecs.Observe(0)
	a.deferredGauge.Add(0)

	cases := []struct {
		name string
		typ  dto.MetricType
	}{
		{"olaitan_report_writes_total", dto.MetricType_COUNTER},
		{"olaitan_report_write_duration_seconds", dto.MetricType_HISTOGRAM},
		{"olaitan_report_writes_deferred_count", dto.MetricType_GAUGE},
	}
	for _, c := range cases {
		mf := gatherFamily(t, reg, c.name)
		if mf == nil {
			t.Errorf("%s not registered", c.name)
			continue
		}
		if mf.GetType() != c.typ {
			t.Errorf("%s type = %v, want %v", c.name, mf.GetType(), c.typ)
		}
	}
}
