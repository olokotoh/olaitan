package falco

import "github.com/olokotoh/olaitan/internal/sourcehealth"

// SourceHealth is the in-process health tracker for the Falco signal
// source. Story 1.6 hosted the concrete implementation in this package;
// Story 1.7 (Kubernetes audit webhook) is the second concrete consumer,
// at which point the tracker graduates to the shared
// internal/sourcehealth package per the rule-of-three minus one. This
// alias preserves the symbol path the Falco-package tests still use
// (SourceHealth, MarkHealthy, MarkUnhealthy, Status) so the refactor
// is byte-for-byte behaviour-preserving.
//
// Story 1.12 (per-source health and event metrics surface) binds this
// tracker to a Prometheus gauge `source_healthy{source="falco"}` per
// FR8 by reading Adapter.Health(); see falco.go for the narrow
// sourcehealth.Reader exposed there.
type SourceHealth = sourcehealth.Tracker
