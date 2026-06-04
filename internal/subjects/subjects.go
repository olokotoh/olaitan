// Package subjects defines the NATS subject hierarchy for inter-ring
// communication. Constants match the architecture's subject contract.
// Builders validate inputs and return an error when inputs contain
// NATS-reserved characters (`.`, `*`, `>`) or whitespace.
package subjects

import (
	"fmt"
	"strings"
)

// RawPrefix is the common prefix shared by every per-source raw subject.
// JetStream stream configs may use `RawPrefix + ">"` to cover the whole
// raw-event hierarchy with a single subscription token. The trailing
// dot keeps the prefix aligned with the per-source constants below.
const RawPrefix = "olaitan.events.raw."

// Ring 1 → Ring 2: raw events per source. Defined in terms of
// RawPrefix so the relationship is explicit; refactoring the prefix
// (or adding a sixth source) flows through automatically and the
// JetStream coverage tests cannot drift from the constant set.
const (
	RawFalco   = RawPrefix + "falco"
	RawAudit   = RawPrefix + "audit"
	RawRuntime = RawPrefix + "runtime"
	RawNetwork = RawPrefix + "network"
	RawAppLog  = RawPrefix + "applog"
)

// Ring 1 → Ring 2: normalised events (common schema).
const Normalised = "olaitan.events.normalised"

// CorrelatedPrefix is the subject prefix for Ring 2 → Ring 3 correlated
// event groups per pod. Use Correlated(namespace, pod) to build a subject.
const CorrelatedPrefix = "olaitan.correlated."

// Ring 3 → Ring 4: threat assessments by severity band.
const (
	ThreatsPrefix  = "olaitan.threats."
	ThreatsWatch   = "olaitan.threats.watch"
	ThreatsAlert   = "olaitan.threats.alert"
	ThreatsAct     = "olaitan.threats.act"
	ThreatsIsolate = "olaitan.threats.isolate"
)

// StatePrefix is the subject prefix for Ring 4 state transitions per pod.
// Use State(namespace, pod) to build a subject.
const StatePrefix = "olaitan.state."

// EvidencePrefix is the subject prefix for DFIR evidence records.
// Use Evidence(kind) to build a subject.
const EvidencePrefix = "olaitan.evidence."

// OverridesApplied is the Story 2.7 published subject on which the operator-
// override controller emits one event per applied AND per rejected override
// (FR38/FR39, architecture.md:225/447). It follows the architecture's
// literal dotted UPPER published-contract naming (distinct from the lower
// olaitan.* per-pod subjects above). The append-only AUDIT.overrides SIEM
// subject (FR40) is Story 2.8 (AuditOverrides below).
const OverridesApplied = "OVERRIDES.applied"

// Story 2.8: the three append-only SIEM audit subjects (FR40/NFR16,
// architecture.md:380/447/613). Each carries a committed JSON-Schema
// (docs/schemas/audit/) and rides a dedicated LimitsPolicy JetStream stream
// (append-only by retention: transitions 90d, overrides/policies 365d). They
// follow the architecture's literal dotted UPPER published-contract naming,
// matching the OverridesApplied precedent above. The two sibling SIEM subjects
// AUDIT.assessments and AUDIT.redactions (Epic 3) are NOT defined here.
const (
	AuditTransitions = "AUDIT.transitions"
	AuditOverrides   = "AUDIT.overrides"
	AuditPolicies    = "AUDIT.policies"
)

// EvidencePackages is the Ring-2 EvidencePackage subject.
const EvidencePackages = EvidencePrefix + "packages"

// Health: per-ring health status.
const (
	HealthPrefix    = "olaitan.health."
	HealthHeartbeat = "olaitan.health.heartbeat"
)

// reservedHealthRings names ring tokens that collide with dedicated health
// subjects and must not be passed to Health.
var reservedHealthRings = map[string]struct{}{
	"heartbeat": {},
}

// validateToken returns an error when s is empty or contains a NATS-reserved
// character (`.`, `*`, `>`) or whitespace.
func validateToken(s string) error {
	if s == "" {
		return fmt.Errorf("empty token")
	}
	for _, r := range s {
		switch r {
		case '.', '*', '>':
			return fmt.Errorf("reserved character %q in token %q", r, s)
		}
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return fmt.Errorf("whitespace in token %q", s)
		}
	}
	return nil
}

// Correlated returns the NATS subject for a specific pod's correlated events.
func Correlated(namespace, pod string) (string, error) {
	if err := validateToken(namespace); err != nil {
		return "", fmt.Errorf("subjects: correlated namespace: %w", err)
	}
	if err := validateToken(pod); err != nil {
		return "", fmt.Errorf("subjects: correlated pod: %w", err)
	}
	return CorrelatedPrefix + namespace + "." + pod, nil
}

// State returns the NATS subject for a specific pod's state transitions.
func State(namespace, pod string) (string, error) {
	if err := validateToken(namespace); err != nil {
		return "", fmt.Errorf("subjects: state namespace: %w", err)
	}
	if err := validateToken(pod); err != nil {
		return "", fmt.Errorf("subjects: state pod: %w", err)
	}
	return StatePrefix + namespace + "." + pod, nil
}

// Health returns the NATS subject for a specific ring's health status.
// Ring tokens that would collide with a dedicated health-subject constant
// (e.g. "heartbeat") are rejected.
func Health(ring string) (string, error) {
	if err := validateToken(ring); err != nil {
		return "", fmt.Errorf("subjects: health ring: %w", err)
	}
	if _, reserved := reservedHealthRings[strings.ToLower(ring)]; reserved {
		return "", fmt.Errorf("subjects: health ring %q is reserved", ring)
	}
	return HealthPrefix + ring, nil
}

// Evidence returns the NATS subject for a specific evidence kind.
func Evidence(kind string) (string, error) {
	if err := validateToken(kind); err != nil {
		return "", fmt.Errorf("subjects: evidence kind: %w", err)
	}
	return EvidencePrefix + kind, nil
}
