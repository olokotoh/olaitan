package correlator

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"

	"github.com/olokotoh/olaitan/internal/schema"
)

// Story 10.7, found by the AC4 live run on kind-full. Calico Goldmane
// aggregates flows by pod prefix, so the CNI source publishes pod names such
// as "coredns-7db6d8ff4d-*", and uses "-" as the namespace of a non-pod
// endpoint. Neither can name a real pod: Kubernetes names are DNS-1123, a
// strict subset of what the Redis key tokens allow. Every such event was still
// sent to the apiserver as a Pod GET before the key validation rejected it,
// and a rejected ref is never cached, so each one cost a round-trip through
// client-go's rate limiter. On kind-full that capped the correlator at about
// nine events a second against twelve arriving, the EVENTS_RAW backlog grew
// without bound, and a real Falco alert from an in-pod attack was never
// reached. A ref the key layer will reject must be rejected before any
// apiserver call.
func TestResolveRejectsUnkeyableRefWithoutAPICall(t *testing.T) {
	for _, tc := range []struct {
		name string
		ref  schema.PodRef
	}{
		{"goldmane aggregated pod name", schema.PodRef{Namespace: "kube-system", Name: "coredns-7db6d8ff4d-*"}},
		{"goldmane non-pod namespace", schema.PodRef{Namespace: "-", Name: "some-host"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kube := kubefake.NewSimpleClientset()
			c := &Correlator{kube: kube, identityCacheTTL: 30 * time.Second}
			_, _, _, err := c.resolveAndCacheIdentity(context.Background(), schema.Event{ID: "ev", Pod: tc.ref})
			if err == nil {
				t.Fatalf("ref %+v resolved, want a key-validation error", tc.ref)
			}
			if n := len(kube.Actions()); n != 0 {
				t.Fatalf("ref %+v cost %d apiserver call(s) before being rejected, want 0: %v", tc.ref, n, kube.Actions())
			}
		})
	}
}

// The pre-check must not reject a real pod: a valid ref still resolves
// through the apiserver to its owning workload.
func TestResolveValidRefStillQueriesAPI(t *testing.T) {
	kube := kubefake.NewSimpleClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "victim-84468698bb-hmtnr", Namespace: "attack"}})
	c := &Correlator{kube: kube, identityCacheTTL: 30 * time.Second}
	id, _, _, err := c.resolveAndCacheIdentity(context.Background(), schema.Event{ID: "ev", Pod: schema.PodRef{Namespace: "attack", Name: "victim-84468698bb-hmtnr"}})
	if err != nil {
		t.Fatalf("valid ref rejected: %v", err)
	}
	if id == "" {
		t.Fatal("valid ref resolved to an empty workload id")
	}
	if len(kube.Actions()) == 0 {
		t.Fatal("valid ref did not reach the apiserver; the pre-check must only reject unkeyable refs")
	}
}
