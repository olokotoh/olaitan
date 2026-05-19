package schema

import "time"

// EvidencePackage is the Ring-2 sliding-window evidence bundle emitted
// by the correlator for downstream rule, baseline, analyst, and DFIR
// consumers.
//
// SamplingActive and SampledSources are package-level honesty
// indicators: when the Story 1.13 rate-limit breaker engages for one
// or more sources contributing to the window, the per-event Sampled
// flag is set on each affected event. The cap-enforcement pass may
// later drop those events to fit the 128 KiB wire budget, so the
// package-level indicators are computed before size-cap reduction and
// survive it. Downstream consumers must treat SamplingActive=true as
// "this window's coverage was degraded" regardless of which events
// remain attached.
type EvidencePackage struct {
	SchemaVersion      string              `json:"schema_version"`
	PackageID          string              `json:"package_id"`
	WorkloadID         string              `json:"workload_id"`
	WorkloadIdentity   WorkloadIdentity    `json:"workload_identity"`
	AssembledAt        time.Time           `json:"assembled_at"`
	WindowStart        time.Time           `json:"window_start"`
	WindowEnd          time.Time           `json:"window_end"`
	Trigger            EvidenceTrigger     `json:"trigger"`
	Events             []Event             `json:"events,omitempty"`
	RuleMatches        []RuleMatch         `json:"rule_matches,omitempty"`
	BaselineDeviations []BaselineDeviation `json:"baseline_deviations,omitempty"`
	WorkloadPosture    *WorkloadPosture    `json:"workload_posture,omitempty"`
	DegradedSources    []string            `json:"degraded_sources,omitempty"`
	SamplingActive     bool                `json:"sampling_active,omitempty"`
	SampledSources     []EventSource       `json:"sampled_sources,omitempty"`
	Overflow           *EvidenceOverflow   `json:"overflow,omitempty"`
}

// EvidenceTrigger records why the correlator assembled a package.
type EvidenceTrigger struct {
	Type              string             `json:"type"`
	EventID           string             `json:"event_id,omitempty"`
	RuleMatch         *RuleMatch         `json:"rule_match,omitempty"`
	BaselineDeviation *BaselineDeviation `json:"baseline_deviation,omitempty"`
	DistinctSources   []EventSource      `json:"distinct_sources,omitempty"`
	FiredAt           time.Time          `json:"fired_at"`
}

// EvidenceOverflow describes deterministic package reduction when the
// on-wire package would otherwise exceed the configured byte cap.
type EvidenceOverflow struct {
	OriginalEventCount int             `json:"original_event_count"`
	IncludedEventCount int             `json:"included_event_count"`
	DroppedEventCount  int             `json:"dropped_event_count"`
	Counts             []EvidenceCount `json:"counts,omitempty"`
}

// EvidenceCount is a stable count grouped by event source and category.
type EvidenceCount struct {
	Source   EventSource   `json:"source"`
	Category EventCategory `json:"category"`
	Count    int           `json:"count"`
}
