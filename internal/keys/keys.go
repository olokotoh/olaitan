// Package keys defines the Redis key hierarchy used by every ring.
// Constants match the architecture's key contract (baseline, checkpoint,
// state, evidence, health). Builders validate their inputs and reject
// Redis-hierarchy-reserved characters (`:`, `*`, `?`, `[`) and whitespace,
// so builder output is never a pattern and never collides with a
// neighbouring namespace.
package keys

import (
	"fmt"
	"strings"
)

// Prefix constants for each key family. All keys built by this package
// begin with one of these.
const (
	BaselinePrefix   = "baseline:"
	CheckpointPrefix = "checkpoint:"
	StatePrefix      = "state:"
	EvidencePrefix   = "evidence:"
	HealthPrefix     = "health:"
)

// Fixed checkpoint keys owned by Ring 3 (correlator).
const (
	CheckpointCorrelatorStreamSeq   = "checkpoint:correlator:stream_seq"
	CheckpointCorrelatorWindowState = "checkpoint:correlator:window_state"
)

// Family identifies a Redis key family for TTL-policy enforcement.
type Family int

const (
	FamilyUnknown Family = iota
	FamilyBaseline
	FamilyCheckpoint
	FamilyState
	FamilyEvidence
	FamilyHealth
)

// FamilyOf returns the Family a key belongs to by its prefix, or
// FamilyUnknown when the key matches no known prefix.
func FamilyOf(key string) Family {
	switch {
	case strings.HasPrefix(key, BaselinePrefix):
		return FamilyBaseline
	case strings.HasPrefix(key, CheckpointPrefix):
		return FamilyCheckpoint
	case strings.HasPrefix(key, StatePrefix):
		return FamilyState
	case strings.HasPrefix(key, EvidencePrefix):
		return FamilyEvidence
	case strings.HasPrefix(key, HealthPrefix):
		return FamilyHealth
	default:
		return FamilyUnknown
	}
}

// validateToken rejects inputs that would break the key hierarchy or let
// a builder emit a Redis glob pattern: empty string, whitespace, `:`
// (the hierarchy separator), and the glob metacharacters `*`, `?`, `[`.
func validateToken(s string) error {
	if s == "" {
		return fmt.Errorf("empty token")
	}
	for _, r := range s {
		switch r {
		case ':', '*', '?', '[':
			return fmt.Errorf("reserved character %q in token %q", r, s)
		}
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return fmt.Errorf("whitespace in token %q", s)
		}
	}
	return nil
}

// BaselineMetrics returns the Redis key for a pod's baseline metrics hash.
// Layout: baseline:<namespace>:<pod>:metrics.
func BaselineMetrics(namespace, pod string) (string, error) {
	if err := validateToken(namespace); err != nil {
		return "", fmt.Errorf("keys: baseline-metrics namespace: %w", err)
	}
	if err := validateToken(pod); err != nil {
		return "", fmt.Errorf("keys: baseline-metrics pod: %w", err)
	}
	return BaselinePrefix + namespace + ":" + pod + ":metrics", nil
}

// BaselineWindow returns the Redis key for a pod's rolling-window baseline.
// Layout: baseline:<namespace>:<pod>:window.
func BaselineWindow(namespace, pod string) (string, error) {
	if err := validateToken(namespace); err != nil {
		return "", fmt.Errorf("keys: baseline-window namespace: %w", err)
	}
	if err := validateToken(pod); err != nil {
		return "", fmt.Errorf("keys: baseline-window pod: %w", err)
	}
	return BaselinePrefix + namespace + ":" + pod + ":window", nil
}

// State returns the Redis key for a pod's current FSM state cache.
// Layout: state:<namespace>:<pod>.
func State(namespace, pod string) (string, error) {
	if err := validateToken(namespace); err != nil {
		return "", fmt.Errorf("keys: state namespace: %w", err)
	}
	if err := validateToken(pod); err != nil {
		return "", fmt.Errorf("keys: state pod: %w", err)
	}
	return StatePrefix + namespace + ":" + pod, nil
}

// EvidenceIncident returns the Redis key for an incident's evidence record.
// Layout: evidence:incident:<incident_id>.
func EvidenceIncident(incidentID string) (string, error) {
	if err := validateToken(incidentID); err != nil {
		return "", fmt.Errorf("keys: evidence-incident id: %w", err)
	}
	return EvidencePrefix + "incident:" + incidentID, nil
}

// EvidenceTransitions returns the Redis Streams key for a pod's state-
// transition log. Layout: evidence:transitions:<namespace>:<pod>.
func EvidenceTransitions(namespace, pod string) (string, error) {
	if err := validateToken(namespace); err != nil {
		return "", fmt.Errorf("keys: evidence-transitions namespace: %w", err)
	}
	if err := validateToken(pod); err != nil {
		return "", fmt.Errorf("keys: evidence-transitions pod: %w", err)
	}
	return EvidencePrefix + "transitions:" + namespace + ":" + pod, nil
}

// Health returns the Redis key that caches a ring's latest health report.
// Layout: health:<ring>.
func Health(ring string) (string, error) {
	if err := validateToken(ring); err != nil {
		return "", fmt.Errorf("keys: health ring: %w", err)
	}
	return HealthPrefix + ring, nil
}
