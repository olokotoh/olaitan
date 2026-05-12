package posture

import (
	"context"
	"errors"
	"fmt"
	"sort"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

// ErrInvalidPodSelector is returned when a NetworkPolicy carries a
// pod-selector that LabelSelectorAsSelector cannot parse. The error
// wraps the offending policy's name so the caller's UnavailableReason
// log line is actionable.
var ErrInvalidPodSelector = errors.New("posture: invalid NetworkPolicy podSelector")

// ApplicableNetworkPolicies lists the NetworkPolicies in `namespace`
// whose spec.podSelector matches `podLabels`. Per Kubernetes
// NetworkPolicy semantics:
//
//   - matchLabels entries are AND'ed (a pod must match every label),
//   - matchExpressions support In/NotIn/Exists/DoesNotExist operators,
//   - an empty podSelector selects all pods in the namespace.
//
// The function does NOT inspect cross-namespace policies; only
// policies in the workload's own namespace are returned, because the
// applicability is governed by spec.podSelector against the workload's
// pod labels and policies in other namespaces are scoped to their own
// pod sets.
//
// The result is sorted by NetworkPolicy name so the caller's
// downstream JSON serialisation is deterministic; downstream Sigma
// rules that pattern-match policy names rely on stable ordering.
//
// Guardrail 22 (read-on-demand only): one round trip per posture
// query, amortised by the cache in cache.go. No informer cache is
// used here.
func ApplicableNetworkPolicies(ctx context.Context, cs kubernetes.Interface, namespace string, podLabels map[string]string) ([]networkingv1.NetworkPolicy, error) {
	if cs == nil {
		return nil, errors.New("posture: clientset is nil")
	}
	if namespace == "" {
		return nil, errors.New("posture: namespace is empty")
	}

	list, err := cs.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("posture: list NetworkPolicies in %q: %w", namespace, err)
	}

	labelSet := labels.Set(podLabels)
	out := make([]networkingv1.NetworkPolicy, 0, len(list.Items))
	for i := range list.Items {
		np := &list.Items[i]
		sel, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
		if err != nil {
			return nil, fmt.Errorf("posture: NetworkPolicy %s/%s: %w (%v)", np.Namespace, np.Name, ErrInvalidPodSelector, err)
		}
		if sel.Matches(labelSet) {
			out = append(out, *np)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})

	return out, nil
}
