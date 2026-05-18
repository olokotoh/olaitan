// Package trigger defines the Ring-2 correlator trigger contract.
package trigger

import (
	"sort"
	"time"

	"github.com/olokotoh/olaitan/internal/correlator/window"
	"github.com/olokotoh/olaitan/internal/schema"
)

const (
	// TypeMultiSignal fires when a workload window contains events
	// from enough distinct sensor sources.
	TypeMultiSignal = "multi_signal"
	// TypeRuleMatch represents an external Sigma/OLT rule match input.
	TypeRuleMatch = "rule_match"
	// TypeBaselineDeviation represents an external >=3 sigma baseline input.
	TypeBaselineDeviation = "baseline_deviation"
)

// Trigger is the in-process representation of a correlator trigger.
type Trigger struct {
	Type              string
	WorkloadID        string
	EventID           string
	RuleMatch         *schema.RuleMatch
	BaselineDeviation *schema.BaselineDeviation
	DistinctSources   []schema.EventSource
	FiredAt           time.Time
}

// RuleMatch constructs an external rule-match trigger.
func RuleMatch(workloadID string, match schema.RuleMatch, firedAt time.Time) Trigger {
	return Trigger{Type: TypeRuleMatch, WorkloadID: workloadID, EventID: match.EventID, RuleMatch: &match, FiredAt: firedAt}
}

// BaselineDeviation constructs an external baseline-deviation trigger.
func BaselineDeviation(workloadID string, deviation schema.BaselineDeviation, firedAt time.Time) Trigger {
	return Trigger{Type: TypeBaselineDeviation, WorkloadID: workloadID, EventID: deviation.PodUID, BaselineDeviation: &deviation, FiredAt: firedAt}
}

// EvaluateMultiSignal returns a trigger when snap has at least minSources
// distinct event sources. DistinctSources is sorted for deterministic JSON.
func EvaluateMultiSignal(snap window.Snapshot, minSources int, firedAt time.Time) (Trigger, bool) {
	if minSources <= 0 {
		minSources = 2
	}
	seen := map[schema.EventSource]struct{}{}
	for _, ev := range snap.Events {
		if ev.Source != "" {
			seen[ev.Source] = struct{}{}
		}
	}
	if len(seen) < minSources {
		return Trigger{}, false
	}
	sources := make([]schema.EventSource, 0, len(seen))
	for source := range seen {
		sources = append(sources, source)
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i] < sources[j] })
	return Trigger{Type: TypeMultiSignal, WorkloadID: snap.WorkloadID, DistinctSources: sources, FiredAt: firedAt}, true
}
