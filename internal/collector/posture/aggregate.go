package posture

import (
	"context"
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/olokotoh/olaitan/internal/keys"
	"github.com/olokotoh/olaitan/internal/schema"
)

// Goldmane workload aggregates (Story 11.2b, PR #205; moved here by Story
// 12.8 so the correlator and the posture client share one resolver).
//
// Calico Goldmane does not name a WorkloadEndpoint by pod. FlowKey.source_name
// is "a set of pods that share a GenerateName", rendered as the GenerateName
// plus "*": a Deployment pod web-bd846c7f-kx8cv appears as "web-bd846c7f-*", a
// DaemonSet pod as "fluent-bit-*", a StatefulSet pod (whose GenerateName is
// still "<set>-") as "db-*", a CronJob's Job pod as "backup-29340000-*". A pod
// with no GenerateName keeps its full name and resolves like any other pod.
// Non-pod endpoints (public/private networks "pub"/"pvt", host endpoints,
// global network sets) carry the namespace "-".
//
// Resolution: a live pod of the set is the representative and its owner walk
// (ResolveWorkloadIdentity) gives the identity, so a Goldmane flow lands on
// the same workload id as a Falco event from the same pod, by construction.
// Cost: one pod LIST in the namespace (served from the apiserver watch cache),
// plus at most the two owner GETs of the walk; a ReplicaSet GET only when no
// live pod carries the GenerateName. Caching is the caller's: the correlator
// keeps an identity cache and a negative cache, the posture client its
// posture cache.

// ErrAggregateUnresolved reports a Goldmane aggregate that no live pod and no
// ReplicaSet backs (the workload is gone, or never was a controller set).
var ErrAggregateUnresolved = errors.New("goldmane aggregate: no pod or ReplicaSet backs it")

// GoldmaneAggregatePrefix reports whether name is a Goldmane workload
// aggregate and returns the GenerateName it stands for ("web-bd846c7f-" for
// "web-bd846c7f-*"): a single trailing "*" after a non-empty prefix. A "*"
// anywhere else is not an aggregate. A Kubernetes pod name can never contain
// "*", so the name alone cannot be mistaken for a real pod; the correlator
// additionally requires a network-source event before treating it as one.
func GoldmaneAggregatePrefix(name string) (string, bool) {
	if len(name) < 2 || !strings.HasSuffix(name, "*") || strings.Count(name, "*") != 1 {
		return "", false
	}
	return strings.TrimSuffix(name, "*"), true
}

// CheckAggregateRef rejects a ref that cannot name a pod set before any
// lookup: the "-" namespace of a non-pod endpoint, or a prefix with characters
// no Kubernetes name carries. Cheap; callers do not cache its result.
func CheckAggregateRef(namespace, prefix string) error {
	_, err := keys.PodFallbackID(namespace, strings.TrimSuffix(prefix, "-"))
	return err
}

// ResolveGoldmaneAggregate maps a Goldmane aggregate to its owning workload.
//
//  1. A live pod of the set (GenerateName == prefix) is the representative:
//     its owner walk gives the identity, and the pod itself is returned so a
//     posture can be taken from it, exactly as for a Falco event from that pod.
//  2. With no live pod (a rollout scaled the ReplicaSet to zero, or the flow
//     arrived after the pod exited; Goldmane reports 15s or more late), a
//     ReplicaSet named after the prefix is walked instead, so a late flow of
//     a Deployment still lands on the Deployment. The returned pod is nil.
//
// The identity is never an orphan-pod one: bare pods that merely share a
// GenerateName are separate workloads, and a failed owner walk is an error
// rather than a fallback (review round 1 of Story 11.2b), so an aggregate
// never splits a workload's flows away from its Falco events.
func ResolveGoldmaneAggregate(ctx context.Context, cs kubernetes.Interface, namespace, prefix string) (schema.WorkloadIdentity, *corev1.Pod, error) {
	if err := CheckAggregateRef(namespace, prefix); err != nil {
		return schema.WorkloadIdentity{}, nil, err
	}
	if cs == nil {
		return schema.WorkloadIdentity{}, nil, fmt.Errorf("goldmane aggregate %s/%s*: no kubernetes client to resolve it", namespace, prefix)
	}
	// ResourceVersion "0" lets the apiserver answer from its watch cache
	// rather than a quorum read of etcd.
	pods, err := cs.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{ResourceVersion: "0"})
	if err != nil {
		return schema.WorkloadIdentity{}, nil, fmt.Errorf("goldmane aggregate %s/%s*: list pods: %w", namespace, prefix, err)
	}
	if rep := representativePod(pods.Items, prefix); rep != nil {
		// Unlike a single pod's own event, an aggregate must NOT fall back to
		// the representative's orphan-pod ID when the owner walk fails: that ID
		// would be cached under the aggregate key and split every replica's
		// flows away from the Deployment window Falco events use (Story 11.2b
		// review round 1). A failed walk is a miss, retried by the caller.
		identity, err := ResolveWorkloadIdentity(ctx, cs, rep)
		if err != nil {
			return schema.WorkloadIdentity{}, nil, fmt.Errorf("goldmane aggregate %s/%s*: owner walk of %s: %w", namespace, prefix, rep.Name, err)
		}
		if identity.OwnerKind == "Pod" {
			// Defensive: representativePod only returns controller-owned
			// pods. Bare pods that merely share a GenerateName are separate
			// orphan workloads; picking one would attribute every flow of
			// the set to that one pod (Story 11.2b review round 1).
			return schema.WorkloadIdentity{}, nil, fmt.Errorf("goldmane aggregate %s/%s*: pods have no controller: %w", namespace, prefix, ErrAggregateUnresolved)
		}
		return identity, rep, nil
	}

	rsName := strings.TrimSuffix(prefix, "-")
	if rsName == prefix || rsName == "" {
		return schema.WorkloadIdentity{}, nil, fmt.Errorf("goldmane aggregate %s/%s*: %w", namespace, prefix, ErrAggregateUnresolved)
	}
	yes := true
	stub := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace:       namespace,
		Name:            rsName,
		OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: rsName, Controller: &yes}},
	}}
	identity, err := ResolveWorkloadIdentity(ctx, cs, stub)
	if err != nil {
		if errors.Is(err, ErrControllerNotFound) || apierrors.IsNotFound(err) {
			return schema.WorkloadIdentity{}, nil, fmt.Errorf("goldmane aggregate %s/%s*: %w", namespace, prefix, ErrAggregateUnresolved)
		}
		return schema.WorkloadIdentity{}, nil, fmt.Errorf("goldmane aggregate %s/%s*: %w", namespace, prefix, err)
	}
	return identity, nil, nil
}

// representativePod picks a pod of the aggregate. GenerateName must equal the
// prefix exactly (so "web-" never matches a "web-canary-" pod), and the pod's
// controller must be the object the prefix is named after (the ReplicaSet,
// DaemonSet, StatefulSet or Job whose name is the prefix without its trailing
// "-"; Story 12.8 review). That skips a bare pod, or one owned by something
// else, that merely shares the GenerateName: it would otherwise make the set
// unresolvable, or lend its ServiceAccount and security context to the
// workload's posture. A running pod (not terminating, not Succeeded or
// Failed) is preferred, so a posture is taken from a live pod; a terminating
// or finished one still names the right owner and is used only when nothing
// else is left.
func representativePod(pods []corev1.Pod, prefix string) *corev1.Pod {
	owner := strings.TrimSuffix(prefix, "-")
	var fallback *corev1.Pod
	for i := range pods {
		p := &pods[i]
		if p.GenerateName != prefix {
			continue
		}
		if ctrl := metav1.GetControllerOf(p); ctrl == nil || ctrl.Name != owner {
			continue
		}
		if p.DeletionTimestamp == nil && p.Status.Phase != corev1.PodSucceeded && p.Status.Phase != corev1.PodFailed {
			return p.DeepCopy()
		}
		if fallback == nil {
			fallback = p
		}
	}
	if fallback != nil {
		return fallback.DeepCopy()
	}
	return nil
}
