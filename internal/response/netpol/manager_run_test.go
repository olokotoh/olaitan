package netpol

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/olokotoh/olaitan/internal/schema"
)

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}

func TestRun_AppliesQueuedTransitionThenStopsOnCancel(t *testing.T) {
	sel := map[string]string{"app": "web"}
	m := newTestManager(t, Config{ClusterCIDRs: []string{"10.96.0.0/12"}, ReconcileInterval: time.Hour}, deployment("ns", "web", sel))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()

	m.Publish(restrictedTransition("ns/Deployment/web", "pkg-1"))
	name := PolicyName("ns/Deployment/web")
	waitFor(t, func() bool {
		_, err := m.cs.NetworkingV1().NetworkPolicies("ns").Get(context.Background(), name, metav1.GetOptions{})
		return err == nil
	})

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v, want nil on cancel", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}

func TestRun_ReconcileTickGarbageCollects(t *testing.T) {
	orphan := m_buildManagedPolicy("ns", "orphan", "ns/Deployment/ghost")
	m := newTestManager(t, Config{ClusterCIDRs: []string{"10.96.0.0/12"}, ReconcileInterval: 20 * time.Millisecond}, orphan)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = m.Run(ctx) }()

	waitFor(t, func() bool {
		_, err := m.cs.NetworkingV1().NetworkPolicies("ns").Get(context.Background(), "orphan", metav1.GetOptions{})
		return err != nil // gone
	})
}

func TestHandle_WithMetricsObservesLatencyAndCounts(t *testing.T) {
	sel := map[string]string{"app": "web"}
	reg := metricsRegistryForTest(t)
	cs := fake.NewSimpleClientset(runtime.Object(deployment("ns", "web", sel)))
	m, err := New(Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, cs, reg, discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	st := restrictedTransition("ns/Deployment/web", "pkg-1")
	st.Timestamp = time.Now().Add(-50 * time.Millisecond)
	m.handle(context.Background(), st)

	if got := testutil.ToFloat64(m.applyTotal.WithLabelValues("applied")); got != 1 {
		t.Fatalf("apply_total{applied} = %v, want 1", got)
	}
	if got := testutil.CollectAndCount(m.applySeconds); got != 1 {
		t.Fatalf("apply_seconds sample count = %d, want 1", got)
	}
}

func TestHandle_ParseErrorCounted(t *testing.T) {
	reg := metricsRegistryForTest(t)
	cs := fake.NewSimpleClientset()
	m, _ := New(Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, cs, reg, discardLog())
	m.handle(context.Background(), schema.StateTransition{ToState: schema.StateRestricted, WorkloadID: "malformed-id"})
	if got := testutil.ToFloat64(m.applyTotal.WithLabelValues("error")); got != 1 {
		t.Fatalf("apply_total{error} = %v, want 1", got)
	}
}

func TestHandle_MissingWorkloadSkipped(t *testing.T) {
	reg := metricsRegistryForTest(t)
	cs := fake.NewSimpleClientset()
	m, _ := New(Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, cs, reg, discardLog())
	// Valid id but the Deployment does not exist -> resolve NotFound -> skipped.
	m.handle(context.Background(), restrictedTransition("ns/Deployment/ghost", "pkg-1"))
	if got := testutil.ToFloat64(m.applyTotal.WithLabelValues("skipped")); got != 1 {
		t.Fatalf("apply_total{skipped} = %v, want 1", got)
	}
}

func TestResolveSelector_DaemonSetAndReplicaSet(t *testing.T) {
	objs := []runtime.Object{
		&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "ds"}, Spec: appsv1.DaemonSetSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"k": "ds"}}}},
		&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "rs"}, Spec: appsv1.ReplicaSetSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"k": "rs"}}}},
	}
	m := newTestManager(t, Config{}, objs...)
	ctx := context.Background()
	for _, tc := range []struct {
		kind, name, want string
	}{
		{"DaemonSet", "ds", "ds"},
		{"ReplicaSet", "rs", "rs"},
	} {
		sel, err := m.resolveSelector(ctx, workloadRef{namespace: "ns", ownerKind: tc.kind, ownerName: tc.name})
		if err != nil {
			t.Fatalf("%s: %v", tc.kind, err)
		}
		if sel.MatchLabels["k"] != tc.want {
			t.Fatalf("%s selector = %v", tc.kind, sel.MatchLabels)
		}
	}
}

func TestOwnerExists(t *testing.T) {
	m := newTestManager(t, Config{}, deployment("ns", "web", map[string]string{"app": "web"}))
	ctx := context.Background()
	if ok, err := m.ownerExists(ctx, workloadRef{namespace: "ns", ownerKind: "Deployment", ownerName: "web"}); err != nil || !ok {
		t.Fatalf("existing owner: ok=%v err=%v", ok, err)
	}
	if ok, err := m.ownerExists(ctx, workloadRef{namespace: "ns", ownerKind: "Deployment", ownerName: "ghost"}); err != nil || ok {
		t.Fatalf("missing owner: ok=%v err=%v (want false, nil)", ok, err)
	}
}

func TestPolicyEqual(t *testing.T) {
	base := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Labels: managedLabels(), Annotations: map[string]string{AnnFSMState: "RESTRICTED"}},
		Spec:       networkingv1.NetworkPolicySpec{PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}},
	}
	same := base.DeepCopy()
	// The apiserver may add extra labels; desired must still be a subset.
	same.Labels["extra"] = "added"
	if !policyEqual(same, base) {
		t.Fatal("policyEqual should treat a superset of labels as equal")
	}
	diffSpec := base.DeepCopy()
	diffSpec.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}
	if policyEqual(diffSpec, base) {
		t.Fatal("policyEqual should detect a spec difference")
	}
	diffAnn := base.DeepCopy()
	diffAnn.Annotations[AnnFSMState] = "QUARANTINED"
	if policyEqual(diffAnn, base) {
		t.Fatal("policyEqual should detect an annotation difference")
	}
}
