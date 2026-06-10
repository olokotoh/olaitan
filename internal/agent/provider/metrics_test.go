package provider

import (
	"testing"

	"github.com/olokotoh/olaitan/internal/metrics"
)

// Story 3.3 BI-3: registration must be idempotent so two providers (the
// Story 3.8 routing future) share one olaitan_llm_calls_total family.
func TestRegisterCallsMetricIdempotent(t *testing.T) {
	reg := metrics.NewRegistry()

	first, err := RegisterCallsMetric(reg)
	if err != nil {
		t.Fatalf("first registration: %v", err)
	}
	second, err := RegisterCallsMetric(reg)
	if err != nil {
		t.Fatalf("second registration: %v (must reuse, not fail)", err)
	}
	if first != second {
		t.Error("second registration returned a different collector; AlreadyRegisteredError reuse broken")
	}

	// Both handles feed the same family.
	first.WithLabelValues("claude", "l1", StatusSuccess).Inc()
	second.WithLabelValues("openai", "l1", StatusSuccess).Inc()
	mfs, err := reg.Gatherer().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == CallsMetricName {
			if got := len(mf.GetMetric()); got != 2 {
				t.Errorf("family has %d series, want 2 (claude + openai side by side)", got)
			}
			return
		}
	}
	t.Fatalf("%s not found in registry", CallsMetricName)
}

func TestRegisterCallsMetricNilRegistry(t *testing.T) {
	var reg *metrics.Registry
	if _, err := RegisterCallsMetric(reg); err == nil {
		t.Fatal("nil registry: err = nil, want error")
	}
}
