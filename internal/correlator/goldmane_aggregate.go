package correlator

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/olokotoh/olaitan/internal/collector/posture"
	"github.com/olokotoh/olaitan/internal/keys"
	"github.com/olokotoh/olaitan/internal/schema"
)

// Goldmane workload aggregates (Story 11.2b, found by the 2026-10-19 live
// gate). The resolver itself (what "web-bd846c7f-*" means, the representative
// pod, the ReplicaSet fallback) lives in internal/collector/posture since
// Story 12.8, so the posture client resolves the same names the same way.
// What stays here is correlator-specific: only a network-source event may
// name an aggregate, positive results ride the identity cache, and
// unresolvable aggregates are negative-cached for aggregateNegativeTTL (the
// Story 10.7 property: no per-event uncached apiserver call).
//
// The CNI adapter (internal/collector/cni/translate.go) publishes the
// aggregate verbatim with the pod_name_kind:generatename tag and leaves the
// workload lookup to the correlator, as its package doc and the posture
// package doc describe.

// goldmaneAggregatePrefix reports whether ev names a Goldmane workload
// aggregate and returns the GenerateName it stands for. Only network-source
// events qualify: a "*" from another source is not an aggregate and stays on
// the key-validation rejection path.
func goldmaneAggregatePrefix(ev schema.Event) (string, bool) {
	if ev.Source != schema.SourceNetwork {
		return "", false
	}
	return posture.GoldmaneAggregatePrefix(ev.Pod.Name)
}

// resolveAggregateCached resolves a Goldmane aggregate through the negative
// cache. key is the identity-cache key of the aggregate; positive results are
// cached by the caller.
func (c *Correlator) resolveAggregateCached(ctx context.Context, key, namespace, prefix string, now time.Time) (string, schema.WorkloadIdentity, *corev1.Pod, error) {
	// Reject a ref that cannot name a pod before any lookup. Cheap, so never
	// cached.
	if err := posture.CheckAggregateRef(namespace, prefix); err != nil {
		return "", schema.WorkloadIdentity{}, nil, err
	}
	if c.kube == nil {
		return "", schema.WorkloadIdentity{}, nil, fmt.Errorf("goldmane aggregate %s/%s*: no kubernetes client to resolve it", namespace, prefix)
	}
	if v, ok := c.aggregateMisses.Load(key); ok {
		if exp, _ := v.(time.Time); now.Before(exp) {
			return "", schema.WorkloadIdentity{}, nil, fmt.Errorf("goldmane aggregate %s/%s* (negative-cached): %w", namespace, prefix, posture.ErrAggregateUnresolved)
		}
		c.aggregateMisses.CompareAndDelete(key, v)
	}
	id, identity, pod, err := c.resolveAggregate(ctx, namespace, prefix)
	if err != nil {
		// Every apiserver failure is negative-cached, transient ones
		// included: retrying per event is exactly the rate-limiter storm
		// Story 10.7 removed. The cost is that flows of that aggregate are
		// dropped for up to aggregateNegativeTTL (one Goldmane batch). A
		// cancelled caller context is not the aggregate's fault and is not
		// cached.
		if ctx.Err() == nil {
			c.rememberAggregateMiss(key, now)
		}
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
			c.aggregateMisses.CompareAndDelete(k, v)
		}
		return true
	})
	c.aggregateMisses.Store(key, now.Add(aggregateNegativeTTL))
}

// resolveAggregate maps a Goldmane aggregate to its owning workload id through
// the shared posture.ResolveGoldmaneAggregate. The representative pod, when
// there is one, rides the trigger to the assembler so posture is taken from
// it without a second lookup; with only a ReplicaSet it is nil and the
// assembler degrades posture as for any pod-less trigger.
func (c *Correlator) resolveAggregate(ctx context.Context, namespace, prefix string) (string, schema.WorkloadIdentity, *corev1.Pod, error) {
	identity, pod, err := posture.ResolveGoldmaneAggregate(ctx, c.kube, namespace, prefix)
	if err != nil {
		return "", schema.WorkloadIdentity{}, nil, err
	}
	id, err := keys.WorkloadID(identity.Namespace, identity.OwnerKind, identity.OwnerName)
	if err != nil {
		return "", schema.WorkloadIdentity{}, nil, err
	}
	return id, identity, pod, nil
}
