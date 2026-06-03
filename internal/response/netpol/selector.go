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
		return o.Spec.Selector, nil
	case "StatefulSet":
		o, err := m.cs.AppsV1().StatefulSets(ref.namespace).Get(ctx, ref.ownerName, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return o.Spec.Selector, nil
	case "DaemonSet":
		o, err := m.cs.AppsV1().DaemonSets(ref.namespace).Get(ctx, ref.ownerName, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return o.Spec.Selector, nil
	case "ReplicaSet":
		o, err := m.cs.AppsV1().ReplicaSets(ref.namespace).Get(ctx, ref.ownerName, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return o.Spec.Selector, nil
	case "Job":
		o, err := m.cs.BatchV1().Jobs(ref.namespace).Get(ctx, ref.ownerName, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return o.Spec.Selector, nil
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
		return nil, fmt.Errorf("netpol: unsupported owner kind %q", ref.ownerKind)
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
		if errors.Is(err, errNoPodLabels) {
			return true, nil
		}
		return false, err
	}
	return true, nil
}
