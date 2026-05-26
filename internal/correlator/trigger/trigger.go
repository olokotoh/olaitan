// Package trigger defines the Ring-2 correlator trigger contract.
package trigger

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"

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
//
// ResolvedIdentity is the optional cache-warm identity the correlator
// attaches once it has resolved the workload from the event's PodRef
// (closure decision P11). When non-nil the assembler skips its own
// kube fetch and reuses this identity for the package; when nil the
// assembler falls back to its own fetch, preserving the
// FireRuleMatch / FireBaselineDeviation entry-point behaviour for
// callers that have not pre-resolved.
//
// Pod is the optional cache-warm pod object captured by the correlator
// at identity-resolution time. When non-nil the assembler hands it to
// the posture client directly instead of re-fetching it from the
// apiserver -- this preserves the Story 1.14 P11 "no Pods.Get on
// cache-warm path" invariant while still giving the posture client the
// real OwnerReferences it needs to walk RBAC and NetworkPolicy.
type Trigger struct {
	Type              string
	WorkloadID        string
	EventID           string
	RuleMatch         *schema.RuleMatch
	BaselineDeviation *schema.BaselineDeviation
	DistinctSources   []schema.EventSource
	FiredAt           time.Time
	ResolvedIdentity  *schema.WorkloadIdentity
	Pod               *corev1.Pod
}

// RuleMatch constructs an external rule-match trigger.
func RuleMatch(workloadID string, match schema.RuleMatch, firedAt time.Time) Trigger {
	return Trigger{Type: TypeRuleMatch, WorkloadID: workloadID, EventID: match.EventID, RuleMatch: &match, FiredAt: firedAt}
}

// BaselineDeviation constructs an external baseline-deviation trigger.
func BaselineDeviation(workloadID string, deviation schema.BaselineDeviation, firedAt time.Time) Trigger {
	return Trigger{Type: TypeBaselineDeviation, WorkloadID: workloadID, EventID: deviation.PodUID, BaselineDeviation: &deviation, FiredAt: firedAt}
}

// MultiSignal constructs a multi-signal trigger for snap with a
// deterministic EventID derived from the sorted event IDs in the
// snapshot. Populating EventID with a window-content fingerprint
// keeps the downstream packageID hash unique even when two assemblies
// land in the same nanosecond, which would otherwise collide on the
// empty EventID seed.
func MultiSignal(snap window.Snapshot, distinctSources []schema.EventSource, firedAt time.Time) Trigger {
	return Trigger{
		Type:            TypeMultiSignal,
		WorkloadID:      snap.WorkloadID,
		EventID:         multiSignalEventID(snap),
		DistinctSources: append([]schema.EventSource(nil), distinctSources...),
		FiredAt:         firedAt,
	}
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
	return MultiSignal(snap, sources, firedAt), true
}

// multiSignalEventID returns a deterministic fingerprint of the sorted
// event IDs in snap. The fingerprint feeds the assembler's packageID
// hash so two assemblies cannot share the same JetStream WithMsgID
// even when they land in the same nanosecond.
func multiSignalEventID(snap window.Snapshot) string {
	if len(snap.Events) == 0 {
		return ""
	}
	ids := make([]string, 0, len(snap.Events))
	for _, ev := range snap.Events {
		ids = append(ids, ev.ID)
	}
	sort.Strings(ids)
	h := sha256.New()
	for _, id := range ids {
		h.Write([]byte(id))
		h.Write([]byte{0})
	}
	sum := h.Sum(nil)
	return "ms-" + hex.EncodeToString(sum[:8])
}
