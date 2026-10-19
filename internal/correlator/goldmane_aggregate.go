package correlator

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/olokotoh/olaitan/internal/collector/posture"
	"github.com/olokotoh/olaitan/internal/keys"
	"github.com/olokotoh/olaitan/internal/schema"
)

// Goldmane workload aggregates (Story 11.2b, found by the 2026-10-19 live
// gate).
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
// The CNI adapter (internal/collector/cni/translate.go) publishes the
// aggregate verbatim with the pod_name_kind:generatename tag and leaves the
// workload lookup to the correlator, as its package doc and the posture
// package doc describe: resolve the hint to a representative pod, then walk
// that pod's owners. Doing exactly that means a Goldmane flow lands on the
// same WorkloadID as a Falco event from the same pod, by construction.
//
// Cost (the Story 10.7 property, no per-event uncached apiserver call): one
// pod LIST in the namespace per aggregate per identity-cache TTL, plus at most
// the two owner GETs posture.ResolveWorkloadIdentity already makes. A
// ReplicaSet GET is added only when no live pod carries the GenerateName. An
// unresolvable aggregate is negative-cached for aggregateNegativeTTL.

// errAggregateUnresolved reports a Goldmane aggregate that no live pod and no
// ReplicaSet backs (the workload is gone, or never was a controller set).
var errAggregateUnresolved = errors.New("goldmane aggregate: no pod or ReplicaSet backs it")

// goldmaneAggregatePrefix reports whether ev names a Goldmane workload
// aggregate and returns the GenerateName it stands for ("web-bd846c7f-" for
// "web-bd846c7f-*"). Only network-source events qualify, and only a single
// trailing "*" after a non-empty prefix: a "*" anywhere else, or from another
// source, is not an aggregate and stays on the key-validation rejection path.
func goldmaneAggregatePrefix(ev schema.Event) (string, bool) {
	if ev.Source != schema.SourceNetwork {
		return "", false
	}
	name := ev.Pod.Name
	if len(name) < 2 || !strings.HasSuffix(name, "*") || strings.Count(name, "*") != 1 {
		return "", false
	}
	return strings.TrimSuffix(name, "*"), true
}

// resolveAggregateCached resolves a Goldmane aggregate through the negative
// cache. key is the identity-cache key of the aggregate; positive results are
// cached by the caller.
func (c *Correlator) resolveAggregateCached(ctx context.Context, key, namespace, prefix string, now time.Time) (string, schema.WorkloadIdentity, *corev1.Pod, error) {
	// Reject a ref that cannot name a pod before any lookup: the "-"
	// namespace of a non-pod endpoint, or a prefix with characters no
	// Kubernetes name carries. Cheap, so never cached.
	if _, err := keys.PodFallbackID(namespace, strings.TrimSuffix(prefix, "-")); err != nil {
		return "", schema.WorkloadIdentity{}, nil, err
	}
	if c.kube == nil {
		return "", schema.WorkloadIdentity{}, nil, fmt.Errorf("goldmane aggregate %s/%s*: no kubernetes client to resolve it", namespace, prefix)
	}
	if v, ok := c.aggregateMisses.Load(key); ok {
		if exp, _ := v.(time.Time); now.Before(exp) {
			return "", schema.WorkloadIdentity{}, nil, fmt.Errorf("goldmane aggregate %s/%s* (negative-cached): %w", namespace, prefix, errAggregateUnresolved)
		}
		c.aggregateMisses.Delete(key)
	}
	id, identity, pod, err := c.resolveAggregate(ctx, namespace, prefix)
	if err != nil {
		// Every failure is negative-cached, transient apiserver errors
		// included: retrying per event is exactly the rate-limiter storm
		// Story 10.7 removed.
		c.rememberAggregateMiss(key, now)
		return "", schema.WorkloadIdentity{}, nil, err
	}
	return id, identity, pod, nil
}

// rememberAggregateMiss negative-caches key and prunes expired misses so the
// map stays bounded by the aggregates seen within one negative TTL. Misses are
// rare (at most one per aggregate per TTL), so the scan is cheap.
func (c *Correlator) rememberAggregateMiss(key string, now time.Time) {
	c.aggregateMisses.Range(func(k, v any) bool {
		if exp, _ := v.(time.Time); !now.Before(exp) {
			c.aggregateMisses.Delete(k)
		}
		return true
	})
	c.aggregateMisses.Store(key, now.Add(aggregateNegativeTTL))
}

// resolveAggregate maps a Goldmane aggregate to its owning workload.
//
//  1. A live pod of the set (GenerateName == prefix) is the representative:
//     its owner walk gives the identity, and the pod itself feeds the posture
//     client, exactly as for a Falco event from that pod.
//  2. With no live pod (a rollout scaled the ReplicaSet to zero, or the flow
//     arrived after the pod exited; Goldmane reports 15s or more late), a
//     ReplicaSet named after the prefix is walked instead, so a late flow of
//     a Deployment still lands on the Deployment. No representative pod is
//     returned then; the assembler degrades posture as for any pod-less
//     trigger.
func (c *Correlator) resolveAggregate(ctx context.Context, namespace, prefix string) (string, schema.WorkloadIdentity, *corev1.Pod, error) {
	// ResourceVersion "0" lets the apiserver answer from its watch cache
	// rather than a quorum read of etcd.
	pods, err := c.kube.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{ResourceVersion: "0"})
	if err != nil {
		return "", schema.WorkloadIdentity{}, nil, fmt.Errorf("goldmane aggregate %s/%s*: list pods: %w", namespace, prefix, err)
	}
	if rep := representativePod(pods.Items, prefix); rep != nil {
		fallbackID, err := keys.PodFallbackID(rep.Namespace, rep.Name)
		if err != nil {
			return "", schema.WorkloadIdentity{}, nil, err
		}
		return c.identityForPod(ctx, rep, fallbackID)
	}

	rsName := strings.TrimSuffix(prefix, "-")
	if rsName == prefix || rsName == "" {
		return "", schema.WorkloadIdentity{}, nil, fmt.Errorf("goldmane aggregate %s/%s*: %w", namespace, prefix, errAggregateUnresolved)
	}
	yes := true
	stub := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace:       namespace,
		Name:            rsName,
		OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: rsName, Controller: &yes}},
	}}
	identity, err := posture.ResolveWorkloadIdentity(ctx, c.kube, stub)
	if err != nil {
		if errors.Is(err, posture.ErrControllerNotFound) || apierrors.IsNotFound(err) {
			return "", schema.WorkloadIdentity{}, nil, fmt.Errorf("goldmane aggregate %s/%s*: %w", namespace, prefix, errAggregateUnresolved)
		}
		return "", schema.WorkloadIdentity{}, nil, fmt.Errorf("goldmane aggregate %s/%s*: %w", namespace, prefix, err)
	}
	id, err := keys.WorkloadID(identity.Namespace, identity.OwnerKind, identity.OwnerName)
	if err != nil {
		return "", schema.WorkloadIdentity{}, nil, err
	}
	return id, identity, nil, nil
}

// representativePod picks a pod of the aggregate: GenerateName must equal the
// prefix exactly (so "web-" never matches a "web-canary-" pod). A pod that is
// not terminating is preferred; a terminating one still names the right owner.
func representativePod(pods []corev1.Pod, prefix string) *corev1.Pod {
	var fallback *corev1.Pod
	for i := range pods {
		p := &pods[i]
		if p.GenerateName != prefix {
			continue
		}
		if p.DeletionTimestamp == nil {
			out := p.DeepCopy()
			return out
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
