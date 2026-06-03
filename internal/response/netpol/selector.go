package netpol

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// errNoPodLabels is returned when an orphan-pod workload carries no labels,
// so no NetworkPolicy podSelector can target it. The manager surfaces this
// as a skipped apply rather than a crash.
var errNoPodLabels = errors.New("netpol: orphan pod has no labels to build a podSelector")

// errEmptySelector is returned when the resolved owner selector is nil or
// carries neither MatchLabels nor MatchExpressions. An empty podSelector in a
// NetworkPolicy selects ALL pods in the namespace, so building a RESTRICTED
// policy from it would block egress for every workload in that namespace, not
// just the suspect one. The manager surfaces this as a skipped apply rather
// than producing a namespace-wide block.
var errEmptySelector = errors.New("netpol: resolved owner selector is empty; would select all pods in the namespace")

// errUnsupportedKind is returned for an owner kind the manager cannot resolve
// a podSelector for (e.g. CronJob; see the Story 2.4 Dev Agent Record CronJob
// deferral amendment). The manager classifies it as a skip, not an error.
var errUnsupportedKind = errors.New("netpol: unsupported owner kind")

// isNonEnforceable reports whether err is a non-transient outcome that means
// the workload cannot or should not be enforced (unsupported owner kind,
// unlabelled orphan pod, or an empty owner selector), as opposed to a genuine
// transient API error. The manager counts these as skipped, not error.
func isNonEnforceable(err error) bool {
	return errors.Is(err, errUnsupportedKind) ||
		errors.Is(err, errNoPodLabels) ||
		errors.Is(err, errEmptySelector)
}

// selectorIsEmpty reports whether a label selector would match every pod in
// the namespace (nil, or no MatchLabels and no MatchExpressions).
func selectorIsEmpty(sel *metav1.LabelSelector) bool {
	return sel == nil || (len(sel.MatchLabels) == 0 && len(sel.MatchExpressions) == 0)
}

// nonEmptySelector returns sel unless it is empty, in which case it returns
// errEmptySelector so the caller skips the apply rather than producing a
// namespace-wide block.
func nonEmptySelector(sel *metav1.LabelSelector) (*metav1.LabelSelector, error) {
	if selectorIsEmpty(sel) {
		return nil, errEmptySelector
	}
	return sel, nil
}

// workloadRef is the parsed canonical workload identity. For a resolved
// workload (Deployment/StatefulSet/...) ownerName is set; for the orphan
// fallback ownerKind == "Pod" and podName is set.
type workloadRef struct {
	namespace string
	ownerKind string
	ownerName string
	podName   string
}

// parseWorkloadID inverts keys.WorkloadID / keys.PodFallbackID. The id is
// "<namespace>/<owner-kind>/<owner-name>" with each segment url.PathEscape'd
// (keys/workload.go), so we split on the two literal "/" separators and
// PathUnescape each segment. The "Pod" owner-kind sentinel marks the
// orphan-pod fallback, whose third segment is the pod name.
func parseWorkloadID(id string) (workloadRef, error) {
	parts := strings.Split(id, "/")
	if len(parts) != 3 {
		return workloadRef{}, fmt.Errorf("netpol: malformed workload id %q: want 3 segments", id)
	}
	ns, err := url.PathUnescape(parts[0])
	if err != nil {
		return workloadRef{}, fmt.Errorf("netpol: workload id %q namespace segment: %w", id, err)
	}
	kind, err := url.PathUnescape(parts[1])
	if err != nil {
		return workloadRef{}, fmt.Errorf("netpol: workload id %q owner-kind segment: %w", id, err)
	}
	name, err := url.PathUnescape(parts[2])
	if err != nil {
		return workloadRef{}, fmt.Errorf("netpol: workload id %q name segment: %w", id, err)
	}
	if ns == "" || kind == "" || name == "" {
		return workloadRef{}, fmt.Errorf("netpol: workload id %q has an empty segment", id)
	}
	if kind == "Pod" {
		return workloadRef{namespace: ns, ownerKind: "Pod", podName: name}, nil
	}
	return workloadRef{namespace: ns, ownerKind: kind, ownerName: name}, nil
}

// resolveSelector resolves the workload's pod label selector by reading the
// owner object's spec.selector. NetworkPolicy podSelector matches pods that
// carry (a superset of) the owner's selector labels, so the owner selector
// targets exactly the workload's pods. The orphan-pod fallback builds a
// selector from the pod's own labels.
//
// A NotFound error from the owner Get is returned verbatim so the caller
// can distinguish "workload already gone" (benign) from a transient API
// error, and so the GC path can reuse this method for an existence check.
func (m *Manager) resolveSelector(ctx context.Context, ref workloadRef) (*metav1.LabelSelector, error) {
	switch ref.ownerKind {
	case "Deployment":
		o, err := m.cs.AppsV1().Deployments(ref.namespace).Get(ctx, ref.ownerName, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return nonEmptySelector(o.Spec.Selector)
	case "StatefulSet":
		o, err := m.cs.AppsV1().StatefulSets(ref.namespace).Get(ctx, ref.ownerName, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return nonEmptySelector(o.Spec.Selector)
	case "DaemonSet":
		o, err := m.cs.AppsV1().DaemonSets(ref.namespace).Get(ctx, ref.ownerName, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return nonEmptySelector(o.Spec.Selector)
	case "ReplicaSet":
		o, err := m.cs.AppsV1().ReplicaSets(ref.namespace).Get(ctx, ref.ownerName, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return nonEmptySelector(o.Spec.Selector)
	case "Job":
		o, err := m.cs.BatchV1().Jobs(ref.namespace).Get(ctx, ref.ownerName, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return nonEmptySelector(o.Spec.Selector)
	case "Pod":
		p, err := m.cs.CoreV1().Pods(ref.namespace).Get(ctx, ref.podName, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		if len(p.Labels) == 0 {
			return nil, errNoPodLabels
		}
		labels := make(map[string]string, len(p.Labels))
		for k, v := range p.Labels {
			labels[k] = v
		}
		return &metav1.LabelSelector{MatchLabels: labels}, nil
	default:
		// Unsupported owner kind (e.g. CronJob, which owns Jobs and has no
		// spec.selector of its own). Wrap the sentinel so the manager can
		// classify this as a skip, not an error, via errors.Is.
		return nil, fmt.Errorf("%w: %q", errUnsupportedKind, ref.ownerKind)
	}
}

// ownerExists reports whether the workload's owner object still exists. It
// reuses resolveSelector's Get and maps a NotFound to (false, nil). A
// non-NotFound error is propagated so the GC path leaves the policy in
// place for a later reconcile rather than deleting on a transient blip.
func (m *Manager) ownerExists(ctx context.Context, ref workloadRef) (bool, error) {
	_, err := m.resolveSelector(ctx, ref)
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		// errNoPodLabels means the pod exists but is unlabelled; it exists.
		// errEmptySelector means the owner exists but resolves to an empty
		// selector; the owner exists either way, so the policy is not orphaned.
		if errors.Is(err, errNoPodLabels) || errors.Is(err, errEmptySelector) {
			return true, nil
		}
		return false, err
	}
	return true, nil
}
