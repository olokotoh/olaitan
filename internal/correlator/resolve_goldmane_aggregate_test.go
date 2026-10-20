package correlator

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubefake "k8s.io/client-go/kubernetes/fake"

	"github.com/olokotoh/olaitan/internal/schema"
)

// Story 11.2b live gate, 2026-10-19 (kind-full on AWS, Falco ON). The real S4
// beacon flows reached EVENTS_RAW but the correlator dropped every one of
// them: Goldmane names a WorkloadEndpoint by the GenerateName its pods share
// plus "*" ("web-bd846c7f-*"), and the Story 10.7 pre-check rejected that
// name as an unkeyable pod. No Goldmane flow ever reached a window, so
// OLT-NET-002 (S4) and OLT-IMPACT-006 (S5) could not match. These tests pin
// the fix: an aggregate resolves to the workload that owns those pods,
// through the same owner walk a Falco event's pod takes, with caching so the
// Story 10.7 performance property holds.

const liveS4FlowFixture = "testdata/goldmane-s4-flows-live-2026-10-19.jsonl"

// loadLiveS4Flows returns the real S4 Goldmane flow events captured from
// EVENTS_RAW on the 2026-10-19 live run, unmodified.
func loadLiveS4Flows(t *testing.T) []schema.Event {
	t.Helper()
	f, err := os.Open(liveS4FlowFixture)
	if err != nil {
		t.Fatalf("open %s: %v", liveS4FlowFixture, err)
	}
	defer func() { _ = f.Close() }()
	var out []schema.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev schema.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("decode fixture line: %v", err)
		}
		out = append(out, ev)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan %s: %v", liveS4FlowFixture, err)
	}
	if len(out) == 0 {
		t.Fatalf("%s holds no events", liveS4FlowFixture)
	}
	return out
}

func controllerRef(kind, name string) []metav1.OwnerReference {
	yes := true
	return []metav1.OwnerReference{{Kind: kind, Name: name, Controller: &yes}}
}

// s4Cluster is the tenant-acme/web Deployment of the S4 run: the Deployment,
// its ReplicaSet web-bd846c7f, and one live pod of that ReplicaSet.
func s4Cluster() []runtime.Object {
	return []runtime.Object{
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "tenant-acme"}},
		&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "web-bd846c7f", Namespace: "tenant-acme", OwnerReferences: controllerRef("Deployment", "web")}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: "web-bd846c7f-kx8cv", GenerateName: "web-bd846c7f-", Namespace: "tenant-acme",
			UID: "web-uid", OwnerReferences: controllerRef("ReplicaSet", "web-bd846c7f"),
		}},
		// A neighbour in the same namespace whose GenerateName shares the
		// "web-" prefix must never be picked for "web-bd846c7f-*".
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: "web-canary-x1", GenerateName: "web-canary-", Namespace: "tenant-acme",
			OwnerReferences: controllerRef("ReplicaSet", "web-canary"),
		}},
	}
}

func newAggregateTestCorrelator(objs ...runtime.Object) (*Correlator, *kubefake.Clientset) {
	kube := kubefake.NewSimpleClientset(objs...)
	return &Correlator{kube: kube, identityCacheTTL: 30 * time.Second}, kube
}

func TestResolveGoldmaneAggregateToOwningDeployment(t *testing.T) {
	for _, ev := range loadLiveS4Flows(t) {
		c, _ := newAggregateTestCorrelator(s4Cluster()...)
		id, identity, pod, err := c.resolveAndCacheIdentity(context.Background(), ev)
		if err != nil {
			t.Fatalf("live flow %s (%s/%s) not resolved: %v", ev.ID, ev.Pod.Namespace, ev.Pod.Name, err)
		}
		if id != "tenant-acme/Deployment/web" {
			t.Fatalf("live flow %s resolved to %q, want tenant-acme/Deployment/web", ev.ID, id)
		}
		if identity.OwnerKind != "Deployment" || identity.OwnerName != "web" || identity.Namespace != "tenant-acme" {
			t.Fatalf("identity = %+v, want tenant-acme Deployment/web", identity)
		}
		if pod == nil || pod.Name != "web-bd846c7f-kx8cv" {
			t.Fatalf("representative pod = %v, want the live pod web-bd846c7f-kx8cv (posture needs a real pod)", pod)
		}
	}
}

// The property the live gate needs: a Falco alert raised inside a pod and the
// Goldmane flow that pod opened are one workload, so they meet in one window.
func TestFalcoEventAndGoldmaneFlowShareWorkloadID(t *testing.T) {
	c, _ := newAggregateTestCorrelator(s4Cluster()...)
	flow := loadLiveS4Flows(t)[0]
	falco := schema.Event{
		ID: "falco-1", Source: schema.SourceFalco, Category: schema.CategorySyscall,
		Pod: schema.PodRef{Namespace: "tenant-acme", Name: "web-bd846c7f-kx8cv", UID: "web-uid"},
	}
	falcoID, _, _, err := c.resolveAndCacheIdentity(context.Background(), falco)
	if err != nil {
		t.Fatalf("falco event: %v", err)
	}
	flowID, _, _, err := c.resolveAndCacheIdentity(context.Background(), flow)
	if err != nil {
		t.Fatalf("goldmane flow: %v", err)
	}
	if falcoID != flowID {
		t.Fatalf("falco event -> %q, goldmane flow -> %q: one Deployment must be one window", falcoID, flowID)
	}
}

// Every owner shape Goldmane aggregates resolves to the identity a Falco event
// from the same pod would get (posture.ResolveWorkloadIdentity), because the
// aggregate is resolved through a real pod of the set.
func TestResolveGoldmaneAggregateOwnerShapes(t *testing.T) {
	cases := []struct {
		name   string
		objs   []runtime.Object
		ref    schema.PodRef
		wantID string
	}{
		{
			name: "daemonset",
			objs: []runtime.Object{&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
				Name: "fluent-bit-7xk2p", GenerateName: "fluent-bit-", Namespace: "logging",
				OwnerReferences: controllerRef("DaemonSet", "fluent-bit"),
			}}},
			ref:    schema.PodRef{Namespace: "logging", Name: "fluent-bit-*"},
			wantID: "logging/DaemonSet/fluent-bit",
		},
		{
			name: "statefulset",
			objs: []runtime.Object{&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
				Name: "db-0", GenerateName: "db-", Namespace: "tenant-acme",
				OwnerReferences: controllerRef("StatefulSet", "db"),
			}}},
			ref:    schema.PodRef{Namespace: "tenant-acme", Name: "db-*"},
			wantID: "tenant-acme/StatefulSet/db",
		},
		{
			name: "cronjob job",
			objs: []runtime.Object{
				&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "backup-29340000", Namespace: "ops", OwnerReferences: controllerRef("CronJob", "backup")}},
				&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
					Name: "backup-29340000-q8w2z", GenerateName: "backup-29340000-", Namespace: "ops",
					OwnerReferences: controllerRef("Job", "backup-29340000"),
				}},
			},
			ref:    schema.PodRef{Namespace: "ops", Name: "backup-29340000-*"},
			wantID: "ops/CronJob/backup",
		},
		{
			// The ReplicaSet's pods are gone (a rollout scaled it to zero, or
			// the flow arrived after the pod exited) but the ReplicaSet is
			// still there: resolve through it rather than drop the flow.
			name: "replicaset with no live pod",
			objs: []runtime.Object{
				&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "web-8447d48b7", Namespace: "tenant-acme", OwnerReferences: controllerRef("Deployment", "web")}},
			},
			ref:    schema.PodRef{Namespace: "tenant-acme", Name: "web-8447d48b7-*"},
			wantID: "tenant-acme/Deployment/web",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := newAggregateTestCorrelator(tc.objs...)
			ev := schema.Event{ID: "flow", Source: schema.SourceNetwork, Category: schema.CategoryFlow, Pod: tc.ref}
			id, _, _, err := c.resolveAndCacheIdentity(context.Background(), ev)
			if err != nil {
				t.Fatalf("aggregate %s/%s not resolved: %v", tc.ref.Namespace, tc.ref.Name, err)
			}
			if id != tc.wantID {
				t.Fatalf("aggregate %s/%s -> %q, want %q", tc.ref.Namespace, tc.ref.Name, id, tc.wantID)
			}
		})
	}
}

// Story 10.7 performance property: no per-event uncached apiserver call. A
// resolved aggregate is served from the identity cache; an unresolvable one is
// negative-cached, so a stream of its flows costs one lookup per TTL, not one
// per event.
func TestResolveGoldmaneAggregateIsCached(t *testing.T) {
	c, kube := newAggregateTestCorrelator(s4Cluster()...)
	flows := loadLiveS4Flows(t)
	if _, _, _, err := c.resolveAndCacheIdentity(context.Background(), flows[0]); err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	first := len(kube.Actions())
	lists := 0
	for _, a := range kube.Actions() {
		if a.GetVerb() == "list" {
			lists++
		}
	}
	if lists != 1 {
		t.Fatalf("cold resolve made %d pod LISTs, want exactly 1: %v", lists, kube.Actions())
	}
	for _, ev := range flows {
		if _, _, _, err := c.resolveAndCacheIdentity(context.Background(), ev); err != nil {
			t.Fatalf("cached resolve: %v", err)
		}
	}
	if got := len(kube.Actions()); got != first {
		t.Fatalf("warm aggregate cost %d more apiserver call(s): %v", got-first, kube.Actions()[first:])
	}
}

func TestUnresolvableGoldmaneAggregateIsNegativeCached(t *testing.T) {
	c, kube := newAggregateTestCorrelator(s4Cluster()...)
	now := time.Date(2026, 10, 19, 20, 53, 0, 0, time.UTC)
	c.now = func() time.Time { return now }
	ghost := schema.Event{ID: "flow", Source: schema.SourceNetwork, Category: schema.CategoryFlow,
		Pod: schema.PodRef{Namespace: "tenant-acme", Name: "ghost-5f9c7d-*"}}
	if _, _, _, err := c.resolveAndCacheIdentity(context.Background(), ghost); err == nil {
		t.Fatal("an aggregate no pod or ReplicaSet backs resolved; want an error")
	}
	first := len(kube.Actions())
	if first == 0 {
		t.Fatal("unresolvable aggregate made no apiserver call; it must be looked up once")
	}
	for i := 0; i < 50; i++ {
		if _, _, _, err := c.resolveAndCacheIdentity(context.Background(), ghost); err == nil {
			t.Fatal("negative-cached aggregate resolved")
		}
	}
	if got := len(kube.Actions()); got != first {
		t.Fatalf("negative-cached aggregate cost %d more apiserver call(s)", got-first)
	}
	// After the negative TTL the aggregate is looked up again, so a
	// workload created moments after its first flow is not blind for long.
	if _, ok := c.identityCache.Load("tenant-acme/ghost-5f9c7d-*"); ok {
		t.Fatal("an unresolved aggregate was stored in the positive identity cache")
	}
	now = now.Add(aggregateNegativeTTL + time.Second)
	if _, _, _, err := c.resolveAndCacheIdentity(context.Background(), ghost); err == nil {
		t.Fatal("ghost aggregate resolved after the negative TTL")
	}
	if got := len(kube.Actions()); got == first {
		t.Fatal("negative cache never expired")
	}
}

// Review round 1: a failed owner walk of the representative pod must be a
// miss, never a pod-level identity cached under the aggregate key (that would
// split the replicas' flows away from the Deployment window).
func TestAggregateOwnerWalkFailureIsNotCachedAsPodIdentity(t *testing.T) {
	// The pod names a ReplicaSet controller that does not exist.
	c, _ := newAggregateTestCorrelator(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "web-bd846c7f-kx8cv", GenerateName: "web-bd846c7f-", Namespace: "tenant-acme",
		OwnerReferences: controllerRef("ReplicaSet", "web-bd846c7f"),
	}})
	flow := loadLiveS4Flows(t)[0]
	if id, _, _, err := c.resolveAndCacheIdentity(context.Background(), flow); err == nil {
		t.Fatalf("aggregate resolved to %q despite a failed owner walk", id)
	}
	if _, ok := c.identityCache.Load(flow.Pod.Namespace + "/" + flow.Pod.Name); ok {
		t.Fatal("failed owner walk was cached as a positive identity")
	}
}

// Only a network-source WorkloadEndpoint aggregate takes the owner lookup.
// Non-pod endpoints and a "*" from any other source stay rejected before any
// apiserver call (the Story 10.7 property for refs that cannot name a pod).
func TestNonAggregateUnkeyableRefsStayRejectedWithoutAPICall(t *testing.T) {
	for _, tc := range []struct {
		name string
		ev   schema.Event
	}{
		{"goldmane public network endpoint", schema.Event{Source: schema.SourceNetwork, Pod: schema.PodRef{Namespace: "-", Name: "pub"}}},
		{"goldmane host endpoint", schema.Event{Source: schema.SourceNetwork, Pod: schema.PodRef{Namespace: "-", Name: "node-1-eth0"}}},
		{"aggregate in the non-pod namespace", schema.Event{Source: schema.SourceNetwork, Pod: schema.PodRef{Namespace: "-", Name: "web-abc-*"}}},
		{"bare star", schema.Event{Source: schema.SourceNetwork, Pod: schema.PodRef{Namespace: "tenant-acme", Name: "*"}}},
		{"star from a non-network source", schema.Event{Source: schema.SourceFalco, Pod: schema.PodRef{Namespace: "tenant-acme", Name: "web-abc-*"}}},
		{"star inside the name", schema.Event{Source: schema.SourceNetwork, Pod: schema.PodRef{Namespace: "tenant-acme", Name: "we*b-abc-*"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, kube := newAggregateTestCorrelator(s4Cluster()...)
			tc.ev.ID = "ev"
			if _, _, _, err := c.resolveAndCacheIdentity(context.Background(), tc.ev); err == nil {
				t.Fatalf("ref %+v resolved, want a rejection", tc.ev.Pod)
			}
			if n := len(kube.Actions()); n != 0 {
				t.Fatalf("ref %+v cost %d apiserver call(s) before rejection, want 0: %v", tc.ev.Pod, n, kube.Actions())
			}
		})
	}
}

// Review round 1: bare pods sharing a GenerateName are separate orphans; the
// aggregate must not be pinned to one of them.
func TestAggregateOfBarePodsIsUnresolved(t *testing.T) {
	c, _ := newAggregateTestCorrelator(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "runner-abcde", GenerateName: "runner-", Namespace: "tenant-acme",
	}})
	ev := schema.Event{ID: "flow", Source: schema.SourceNetwork, Pod: schema.PodRef{Namespace: "tenant-acme", Name: "runner-*"}}
	if id, _, _, err := c.resolveAndCacheIdentity(context.Background(), ev); err == nil {
		t.Fatalf("bare-pod aggregate resolved to %q", id)
	}
}

// Review round 1: a cached aggregate must not let a non-network event with the
// same "*" name through.
func TestStarNameFromOtherSourceDoesNotHitAggregateCache(t *testing.T) {
	c, kube := newAggregateTestCorrelator(s4Cluster()...)
	flow := loadLiveS4Flows(t)[0]
	if _, _, _, err := c.resolveAndCacheIdentity(context.Background(), flow); err != nil {
		t.Fatal(err)
	}
	n := len(kube.Actions())
	falco := schema.Event{ID: "f", Source: schema.SourceFalco, Pod: flow.Pod}
	if _, _, _, err := c.resolveAndCacheIdentity(context.Background(), falco); err == nil {
		t.Fatal("non-network '*' name resolved through the aggregate cache")
	}
	if len(kube.Actions()) != n {
		t.Fatal("rejection cost an apiserver call")
	}
}
