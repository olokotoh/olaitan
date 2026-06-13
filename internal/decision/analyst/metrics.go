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
	"the last is reserved for Story 3.11 (the score-fold acting threshold) and " +
	"is not emitted before then). One increment per Run; bounded label set " +
	"(Story 3.5 BI-8, architecture.md:318 llm_status enum)."

// L2SkippedMetricName is the AC4-named chain-gate counter family: one
// increment per investigation chain that skips L2 (Story 3.6 BI-6).
const L2SkippedMetricName = "olaitan_decision_llm_l2_skipped_total"

const l2SkippedMetricHelp = "Investigation chains that skipped the L2 verification stage, by reason. " +
	"Bounded reason set: l1_unavailable (the L1 stage failed with provider " +
	"unavailability, so the chain short-circuits to Senior-on-evidence-only " +
	"mode) and l1_schema_violation (L1's single pre-3.10 attempt returned a " +
	"schema violation, leaving no valid hypothesis to verify; Story 3.10's " +
	"three-strike policy will re-route this class). Incremented by the Story " +
	"3.7 orchestrator when it short-circuits L2 (Story 3.6 BI-6, Story 3.7 BI-7)."

// RegisterL2SkippedMetric registers (or re-uses) the
// olaitan_decision_llm_l2_skipped_total counter on reg, idempotently
// like RegisterDecisionCallsMetric.
func RegisterL2SkippedMetric(reg *metrics.Registry) (*prometheus.CounterVec, error) {
	return registerCounterVec(reg, L2SkippedMetricName, l2SkippedMetricHelp, []string{"reason"})
}

// RecordL2Skip increments the skip counter under a bounded reason. It
// refuses an empty reason (ShouldSkipL2 returns "" on the no-skip path;
// incrementing unconditionally would mint an empty-label series) so the
// bounded-label guarantee does not rest on every caller checking the
// bool first (Story 3.6 round-1 review).
func RecordL2Skip(vec *prometheus.CounterVec, reason string) {
	if vec == nil || reason == "" {
		return
	}
	vec.WithLabelValues(reason).Inc()
}

// registerCounterVec is the shared idempotent registration dance every
// decision-ring family uses (Story 3.6 round-1 hoist): when the family
// is already registered it unwraps prometheus.AlreadyRegisteredError
// and returns the EXISTING collector.
func registerCounterVec(reg *metrics.Registry, name, help string, labels []string) (*prometheus.CounterVec, error) {
	vec, err := reg.RegisterCounterVec(name, help, labels)
	if err != nil {
		var already prometheus.AlreadyRegisteredError
		if errors.As(err, &already) {
			if existing, ok := already.ExistingCollector.(*prometheus.CounterVec); ok {
				return existing, nil
			}
			return nil, fmt.Errorf("analyst: %s already registered with a different collector type: %w", name, err)
		}
		return nil, fmt.Errorf("analyst: register %s: %w", name, err)
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
	return registerCounterVec(reg, DecisionCallsMetricName, decisionCallsMetricHelp, []string{"provider", "role", "status"})
}
