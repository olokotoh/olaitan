package keys

import (
	"fmt"
	"net/url"
)

// WorkloadID returns the canonical workload identifier in the form
// "<namespace>/<owner-kind>/<owner-name>" per architecture.md:457.
// Each segment is URL-encoded so a workload whose name contains the
// architecture's "/" separator does not collide with the structural
// separators of the identifier.
//
// This is the FIRST builder in internal/keys/ whose output is NOT a
// Redis key. It is a logical workload identity consumed by callers
// that may further build Redis keys from it (architecture.md:455 lists
// `baseline:{workload_id}:{metric}` and `fsm:{workload_id}` as
// composed Redis-key forms). The validateToken allow-list runs per
// segment, which rejects Redis hierarchy separators, glob
// metacharacters, ASCII whitespace, and Unicode control runes inside
// each segment; the output then contains exactly two architecture-
// specified "/" runes between the three segments.
//
// Callers that pass an empty argument, or any argument containing a
// disallowed rune, receive ("", error). The error string is prefixed
// "keys:" per the repo-wide convention.
func WorkloadID(namespace, ownerKind, ownerName string) (string, error) {
	if err := validateToken(namespace); err != nil {
		return "", fmt.Errorf("keys: workload-id namespace: %w", err)
	}
	if err := validateToken(ownerKind); err != nil {
		return "", fmt.Errorf("keys: workload-id owner-kind: %w", err)
	}
	if err := validateToken(ownerName); err != nil {
		return "", fmt.Errorf("keys: workload-id owner-name: %w", err)
	}
	return url.PathEscape(namespace) + "/" + url.PathEscape(ownerKind) + "/" + url.PathEscape(ownerName), nil
}

// PodFallbackID returns the orphan-pod fallback workload identifier
// in the form "<namespace>/Pod/<pod-name>" per architecture.md:457.
// The literal owner-kind "Pod" is the canonical sentinel so consumers
// can distinguish resolved vs orphan workloads via a string compare
// on the second segment without inspecting a separate boolean.
func PodFallbackID(namespace, podName string) (string, error) {
	if err := validateToken(namespace); err != nil {
		return "", fmt.Errorf("keys: pod-fallback-id namespace: %w", err)
	}
	if err := validateToken(podName); err != nil {
		return "", fmt.Errorf("keys: pod-fallback-id pod-name: %w", err)
	}
	return url.PathEscape(namespace) + "/Pod/" + url.PathEscape(podName), nil
}
