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

// CallDurationMetricName is the shared per-call latency histogram every
// provider observes (Story 3.15 FR50): olaitan_llm_call_duration_seconds.
const CallDurationMetricName = "olaitan_llm_call_duration_seconds"

const callDurationMetricHelp = "LLM transport call wall-clock latency in seconds by provider and analyst role " +
	"(Story 3.15 FR50). One observation per Analyse call, so a retry or Ollama fall-through " +
	"each contributes its own sample. Unit: seconds."

// callDurationBuckets span the per-role budgets (L1/L2 30 s, Senior 60 s):
// sub-second detail for healthy calls plus coarse buckets up to the 60 s
// Senior ceiling so a SLO breach is visible.
var callDurationBuckets = []float64{0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60}

// RegisterCallDurationMetric registers (or re-uses) the shared
// olaitan_llm_call_duration_seconds histogram on reg and returns the handle.
// Idempotent across providers in one process, mirroring RegisterCallsMetric.
func RegisterCallDurationMetric(reg *metrics.Registry) (*prometheus.HistogramVec, error) {
	vec, err := reg.RegisterHistogramVec(CallDurationMetricName, callDurationMetricHelp, []string{"provider", "role"}, callDurationBuckets)
	if err != nil {
		var already prometheus.AlreadyRegisteredError
		if errors.As(err, &already) {
			if existing, ok := already.ExistingCollector.(*prometheus.HistogramVec); ok {
				return existing, nil
			}
			return nil, fmt.Errorf("provider: %s already registered with a different collector type: %w", CallDurationMetricName, err)
		}
		return nil, fmt.Errorf("provider: register %s: %w", CallDurationMetricName, err)
	}
	return vec, nil
}
