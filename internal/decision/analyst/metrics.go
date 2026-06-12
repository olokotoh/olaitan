package analyst

import (
	"errors"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/olokotoh/olaitan/internal/metrics"
)

// DecisionCallsMetricName is the decision-ring per-call outcome counter
// family every investigation-chain runner increments (Story 3.5 BI-8;
// metric naming convention architecture.md:472-476).
const DecisionCallsMetricName = "olaitan_decision_llm_calls_total"

const decisionCallsMetricHelp = "Investigation-chain analyst calls by provider, role and decision " +
	"outcome (success, unavailable, schema_violation, success_low_confidence; " +
	"the last is reserved for the Story 3.7 Senior and is not emitted before " +
	"then). One increment per Run; bounded label set (Story 3.5 BI-8, " +
	"architecture.md:318 llm_status enum)."

// L2SkippedMetricName is the AC4-named chain-gate counter family: one
// increment per investigation chain that skips L2 (Story 3.6 BI-6).
const L2SkippedMetricName = "olaitan_decision_llm_l2_skipped_total"

const l2SkippedMetricHelp = "Investigation chains that skipped the L2 verification stage, by reason. " +
	"Bounded reason set: l1_unavailable (the L1 stage failed with provider " +
	"unavailability, so the chain short-circuits to Senior-on-evidence-only " +
	"mode; Story 3.10 may extend the set). Incremented by the Story 3.7 " +
	"orchestrator at the ShouldSkipL2 gate (Story 3.6 BI-6)."

// RegisterL2SkippedMetric registers (or re-uses) the
// olaitan_decision_llm_l2_skipped_total counter on reg, idempotently
// like RegisterDecisionCallsMetric.
func RegisterL2SkippedMetric(reg *metrics.Registry) (*prometheus.CounterVec, error) {
	vec, err := reg.RegisterCounterVec(L2SkippedMetricName, l2SkippedMetricHelp, []string{"reason"})
	if err != nil {
		var already prometheus.AlreadyRegisteredError
		if errors.As(err, &already) {
			if existing, ok := already.ExistingCollector.(*prometheus.CounterVec); ok {
				return existing, nil
			}
			return nil, fmt.Errorf("analyst: %s already registered with a different collector type: %w", L2SkippedMetricName, err)
		}
		return nil, fmt.Errorf("analyst: register %s: %w", L2SkippedMetricName, err)
	}
	return vec, nil
}

// RegisterDecisionCallsMetric registers (or re-uses) the shared
// olaitan_decision_llm_calls_total counter on reg and returns the handle.
//
// Registration is idempotent for the same reason as
// provider.RegisterCallsMetric (Story 3.3 BI-3): the L2 (Story 3.6) and
// Senior (Story 3.7) runners, and any multi-runner test registry, must
// increment the SAME family rather than hit a duplicate-registration
// error. The cardinality bound is {providers} x 3 emitting roles x 4
// statuses, well within the metrics.go:357-362 rule.
func RegisterDecisionCallsMetric(reg *metrics.Registry) (*prometheus.CounterVec, error) {
	vec, err := reg.RegisterCounterVec(DecisionCallsMetricName, decisionCallsMetricHelp, []string{"provider", "role", "status"})
	if err != nil {
		var already prometheus.AlreadyRegisteredError
		if errors.As(err, &already) {
			if existing, ok := already.ExistingCollector.(*prometheus.CounterVec); ok {
				return existing, nil
			}
			return nil, fmt.Errorf("analyst: %s already registered with a different collector type: %w", DecisionCallsMetricName, err)
		}
		return nil, fmt.Errorf("analyst: register %s: %w", DecisionCallsMetricName, err)
	}
	return vec, nil
}
