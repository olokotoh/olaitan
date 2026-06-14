package forensics

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// errEmptySelector is returned when the resolved owner selector is empty; a
// pod List with an empty selector would return EVERY pod in the namespace, so
// the controller refuses it rather than capturing and deleting the whole
// namespace (mirror netpol's namespace-wide guard).
var errEmptySelector = errors.New("forensics: resolved owner selector is empty; would match all pods in the namespace")

// resolvePods resolves a workload_id to the concrete pod names to capture and
// delete (BI-6, net-new). This pod-by-selector List has no existing reusable
// helper at HEAD (netpol only ever writes/deletes NetworkPolicies by name; the
// only Pods().Delete in the tree is a test), so it is introduced here.
//
//   - For the orphan-pod fallback (ownerKind == "Pod") the single named pod is
//     returned directly.
//   - For a resolved owner (Deployment/StatefulSet/DaemonSet/ReplicaSet/Job) the
//     owner's spec.selector is read and pods are Listed by it.
//
// A NotFound on the owner Get yields an empty result (the workload is already
// gone; nothing to capture). An empty selector is refused (errEmptySelector) so
// the controller never deletes a whole namespace.
func (c *Controller) resolvePods(ctx context.Context, ref workloadRef) ([]string, error) {
	if ref.ownerKind == "Pod" {
		// Confirm the pod still exists; a NotFound means already-gone (empty set).
		if _, err := c.cs.CoreV1().Pods(ref.namespace).Get(ctx, ref.podName, metav1.GetOptions{}); err != nil {
			if apierrors.IsNotFound(err) {
				return nil, nil
			}
			return nil, fmt.Errorf("forensics: get orphan pod %s/%s: %w", ref.namespace, ref.podName, err)
		}
		return []string{ref.podName}, nil
	}

	sel, err := c.resolveSelector(ctx, ref)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	list, err := c.cs.CoreV1().Pods(ref.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: metav1.FormatLabelSelector(sel),
	})
	if err != nil {
		return nil, fmt.Errorf("forensics: list pods for %s/%s/%s: %w", ref.namespace, ref.ownerKind, ref.ownerName, err)
	}
	names := make([]string, 0, len(list.Items))
	for i := range list.Items {
		names = append(names, list.Items[i].Name)
	}
	return names, nil
}

// resolveSelector reads the workload owner's spec.selector, mirroring netpol's
// resolveSelector. A NotFound is returned verbatim so resolvePods can map it to
// "already gone". An empty selector is refused (errEmptySelector). The orphan
// "Pod" kind is handled by resolvePods directly and never reaches here.
func (c *Controller) resolveSelector(ctx context.Context, ref workloadRef) (*metav1.LabelSelector, error) {
	switch ref.ownerKind {
	case "Deployment":
		o, err := c.cs.AppsV1().Deployments(ref.namespace).Get(ctx, ref.ownerName, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return nonEmptySelector(o.Spec.Selector)
	case "StatefulSet":
		o, err := c.cs.AppsV1().StatefulSets(ref.namespace).Get(ctx, ref.ownerName, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return nonEmptySelector(o.Spec.Selector)
	case "DaemonSet":
		o, err := c.cs.AppsV1().DaemonSets(ref.namespace).Get(ctx, ref.ownerName, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return nonEmptySelector(o.Spec.Selector)
	case "ReplicaSet":
		o, err := c.cs.AppsV1().ReplicaSets(ref.namespace).Get(ctx, ref.ownerName, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return nonEmptySelector(o.Spec.Selector)
	case "Job":
		o, err := c.cs.BatchV1().Jobs(ref.namespace).Get(ctx, ref.ownerName, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return nonEmptySelector(o.Spec.Selector)
	default:
		return nil, fmt.Errorf("forensics: unsupported owner kind %q", ref.ownerKind)
	}
}

// nonEmptySelector returns sel unless it is empty (mirror netpol).
func nonEmptySelector(sel *metav1.LabelSelector) (*metav1.LabelSelector, error) {
	if sel == nil || (len(sel.MatchLabels) == 0 && len(sel.MatchExpressions) == 0) {
		return nil, errEmptySelector
	}
	return sel, nil
}

// newBundleReader returns a fresh reader over the captured bundle bytes so each
// upload attempt (including a retry) starts from the bundle head.
func newBundleReader(bundle []byte) *bytes.Reader {
	return bytes.NewReader(bundle)
}
