package provider

import (
	"errors"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/olokotoh/olaitan/internal/metrics"
)

// CallsMetricName is the shared per-call outcome counter family every
// concrete Provider increments (Story 3.2 BI-4 / Story 3.3 BI-3).
const CallsMetricName = "olaitan_llm_calls_total"

const callsMetricHelp = "LLM transport calls by provider, analyst role and final outcome " +
	"(success, transient_failure, permanent_failure, timeout). One increment " +
	"per Analyse call; bounded label set (Story 3.2 BI-4 / Story 3.3 BI-3)."

// RegisterCallsMetric registers (or re-uses) the shared
// olaitan_llm_calls_total counter on reg and returns the handle.
//
// Story 3.2 registered the family inside claude.New; with a second
// provider in the same process (the Story 3.8 per-role routing future,
// and any dual-provider test registry) that would hit a
// duplicate-registration error. This helper makes registration
// idempotent: when the family is already registered it unwraps
// prometheus.AlreadyRegisteredError (reachable through the
// metrics-package wrap via errors.As) and returns the EXISTING collector,
// so every provider increments the same family with its own provider
// label value. The cardinality bound is {providers} x 4 roles x 4
// statuses, well within the metrics.go:357-362 rule.
func RegisterCallsMetric(reg *metrics.Registry) (*prometheus.CounterVec, error) {
	vec, err := reg.RegisterCounterVec(CallsMetricName, callsMetricHelp, []string{"provider", "role", "status"})
	if err != nil {
		var already prometheus.AlreadyRegisteredError
		if errors.As(err, &already) {
			if existing, ok := already.ExistingCollector.(*prometheus.CounterVec); ok {
				return existing, nil
			}
			return nil, fmt.Errorf("provider: %s already registered with a different collector type: %w", CallsMetricName, err)
		}
		return nil, fmt.Errorf("provider: register %s: %w", CallsMetricName, err)
	}
	return vec, nil
}
