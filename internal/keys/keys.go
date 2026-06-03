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
	// FSMStatePrefix is the Story 2.3 durable FSM-state family
	// (fsm:{workload_id} and fsm:{workload_id}:history per
	// architecture.md:455). It is distinct from StatePrefix: the state:
	// family is a 1h-TTL per-pod cache keyed by (namespace, pod), whereas
	// the fsm: family is keyed by the canonical three-segment workload_id
	// and carries NO TTL (FSM state must survive an arbitrary restart gap;
	// Story 2.3 BI-2).
	FSMStatePrefix = "fsm:"
	// OverridePrefix is the Story 2.7 operator-override family
	// (override:{workload_id} per architecture.md:455). It is keyed by the
	// canonical three-segment workload_id exactly like the fsm: family but,
	// unlike fsm:, it carries a NATIVE Redis TTL equal to the override's
	// requested duration (default 1h): the native TTL IS the FR39 release
	// mechanism, so the override's lifetime is wall-clock-correct across a
	// controller restart (Story 2.7 BI-3/BI-4). This is the deliberate
	// divergence from the no-TTL fsm: family.
	OverridePrefix = "override:"
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
	FamilyFSM
	FamilyOverride
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
	case strings.HasPrefix(key, OverridePrefix):
		return FamilyOverride
	case strings.HasPrefix(key, FSMStatePrefix):
		return FamilyFSM
	default:
		return FamilyUnknown
	}
}

// validateToken enforces an allowlist: [A-Za-z0-9_.-] only. This is a
// superset of DNS-1123 names (k8s namespace/pod/ring identifiers) and
// the common "INC-123"-style incident IDs, while rejecting every Redis
// hierarchy separator, glob metacharacter, ASCII whitespace, and
// Unicode control rune in one rule.
//
// Also rejects the single-character tokens "-" and "+" because they
// collide with XRANGE's stream sentinels when an evidence key is later
// used as the stream argument.
func validateToken(s string) error {
	if s == "" {
		return fmt.Errorf("empty token")
	}
	if s == "-" || s == "+" {
		return fmt.Errorf("token %q collides with XRANGE sentinel", s)
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '.' || r == '-':
		default:
			return fmt.Errorf("disallowed character %q in token %q (allowed: [A-Za-z0-9_.-])", r, s)
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

// validateWorkloadID accepts a canonical workload identifier produced by
// WorkloadID or PodFallbackID ("<namespace>/<owner-kind>/<owner-name>")
// and verifies it has exactly three slash-delimited segments, each a
// valid token. This is the per-segment guard that lets the fsm: builders
// embed the two architecture-specified "/" separators while still
// rejecting Redis hierarchy separators, glob metacharacters, and
// whitespace inside any segment.
func validateWorkloadID(workloadID string) error {
	if workloadID == "" {
		return fmt.Errorf("empty workload-id")
	}
	segs := strings.Split(workloadID, "/")
	if len(segs) != 3 {
		return fmt.Errorf("workload-id %q must have exactly three segments (namespace/owner-kind/owner-name)", workloadID)
	}
	for _, s := range segs {
		if err := validateToken(s); err != nil {
			return fmt.Errorf("workload-id segment: %w", err)
		}
	}
	return nil
}

// FSMState returns the Story 2.3 durable FSM-state key for a workload.
// Layout: fsm:<workload_id> where workload_id is the canonical
// "<namespace>/<owner-kind>/<owner-name>" form from WorkloadID. The key
// carries NO TTL (FSM state must survive an arbitrary restart gap).
func FSMState(workloadID string) (string, error) {
	if err := validateWorkloadID(workloadID); err != nil {
		return "", fmt.Errorf("keys: fsm-state: %w", err)
	}
	return FSMStatePrefix + workloadID, nil
}

// Override returns the Story 2.7 operator-override key for a workload.
// Layout: override:<workload_id> where workload_id is the canonical
// "<namespace>/<owner-kind>/<owner-name>" form from WorkloadID. Unlike
// the no-TTL fsm: family, this key is written with a NATIVE Redis TTL
// equal to the override's requested duration: the native TTL is the FR39
// release mechanism (BI-3/BI-4).
func Override(workloadID string) (string, error) {
	if err := validateWorkloadID(workloadID); err != nil {
		return "", fmt.Errorf("keys: override: %w", err)
	}
	return OverridePrefix + workloadID, nil
}

// FSMHistory returns the Story 2.3 append-only transition-history key for
// a workload. Layout: fsm:<workload_id>:history (a Redis list). Distinct
// from the EvidenceTransitions stream and from the Story 2.8 NATS audit
// subject; this list is operational state, bounded by an LTRIM cap.
func FSMHistory(workloadID string) (string, error) {
	if err := validateWorkloadID(workloadID); err != nil {
		return "", fmt.Errorf("keys: fsm-history: %w", err)
	}
	return FSMStatePrefix + workloadID + ":history", nil
}
