package analyst

import (
	"testing"

	"github.com/olokotoh/olaitan/internal/metrics"
)

// Story 3.5 BI-8: registration must be idempotent so the L2 (3.6) and
// Senior (3.7) runners share one olaitan_decision_llm_calls_total family.
func TestRegisterDecisionCallsMetricIdempotent(t *testing.T) {
	reg := metrics.NewRegistry()

	first, err := RegisterDecisionCallsMetric(reg)
	if err != nil {
		t.Fatalf("first registration: %v", err)
	}
	second, err := RegisterDecisionCallsMetric(reg)
	if err != nil {
		t.Fatalf("second registration: %v (must reuse, not fail)", err)
	}
	if first != second {
		t.Error("second registration returned a different collector; AlreadyRegisteredError reuse broken")
	}

	// Both handles feed the same family, and increments are visible
	// (Story 3.4 lesson: metric proofs must INCREMENT).
	first.WithLabelValues("claude", "l1", StatusSuccess).Inc()
	second.WithLabelValues("ollama", "l1", StatusSchemaViolation).Inc()
	mfs, err := reg.Gatherer().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == DecisionCallsMetricName {
			if got := len(mf.GetMetric()); got != 2 {
				t.Errorf("family has %d series, want 2", got)
			}
			var total float64
			for _, m := range mf.GetMetric() {
				total += m.GetCounter().GetValue()
			}
			if total != 2 {
				t.Errorf("family total = %v, want 2", total)
			}
			return
		}
	}
	t.Fatalf("%s not found in registry", DecisionCallsMetricName)
}

func TestRegisterDecisionCallsMetricNilRegistry(t *testing.T) {
	var reg *metrics.Registry
	if _, err := RegisterDecisionCallsMetric(reg); err == nil {
		t.Fatal("nil registry: err = nil, want error")
	}
}
