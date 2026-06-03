package netpol

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/schema"
)

func metricsRegistryForTest(t *testing.T) *metrics.Registry {
	t.Helper()
	return metrics.NewRegistry()
}

func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestManager(t *testing.T, cfg Config, objects ...runtime.Object) *Manager {
	t.Helper()
	cs := fake.NewSimpleClientset(objects...)
	m, err := New(cfg, cs, nil, discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

func restrictedTransition(workloadID, packageID string) schema.StateTransition {
	return schema.StateTransition{
		Timestamp:  time.Now(),
		FromState:  schema.StateSuspicious,
		ToState:    schema.StateRestricted,
		WorkloadID: workloadID,
		PackageID:  packageID,
	}
}

func deployment(ns, name string, sel map[string]string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: sel}},
	}
}

func TestNew_NilClientsetRejected(t *testing.T) {
	if _, err := New(Config{}, nil, nil, discardLog()); err == nil {
		t.Fatal("want error for nil clientset, got nil")
	}
}

func TestParseWorkloadID(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		want    workloadRef
		wantErr bool
	}{
		{"deployment", "team-a/Deployment/web", workloadRef{namespace: "team-a", ownerKind: "Deployment", ownerName: "web"}, false},
		{"orphan pod", "team-a/Pod/lonely-123", workloadRef{namespace: "team-a", ownerKind: "Pod", podName: "lonely-123"}, false},
		{"escaped segment", "ns/Deployment/web%2Fextra", workloadRef{namespace: "ns", ownerKind: "Deployment", ownerName: "web/extra"}, false},
		{"too few segments", "ns/web", workloadRef{}, true},
		{"empty segment", "ns//web", workloadRef{}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseWorkloadID(tc.id)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("parseWorkloadID(%q) = %+v, want %+v", tc.id, got, tc.want)
			}
		})
	}
}

func TestPolicyName_DeterministicAndPrefixed(t *testing.T) {
	a := PolicyName("ns/Deployment/web")
	b := PolicyName("ns/Deployment/web")
	c := PolicyName("ns/Deployment/api")
	if a != b {
		t.Fatalf("PolicyName not deterministic: %q vs %q", a, b)
	}
	if a == c {
		t.Fatalf("PolicyName collided for distinct workloads")
	}
	if len(a) != len(policyNamePrefix)+12 {
		t.Fatalf("PolicyName %q has unexpected length", a)
	}
}

func TestResolveSelector_OwnerKinds(t *testing.T) {
	sel := map[string]string{"app": "web"}
	objs := []runtime.Object{
		deployment("ns", "web", sel),
		&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "db"}, Spec: appsv1.StatefulSetSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "db"}}}},
		&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "batch"}, Spec: batchv1.JobSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"job": "batch"}}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "orphan", Labels: map[string]string{"run": "orphan"}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "nolabels"}},
	}
	m := newTestManager(t, Config{}, objs...)
	ctx := context.Background()

	cases := []struct {
		name      string
		ref       workloadRef
		wantLabel map[string]string
		wantErr   bool
	}{
		{"deployment", workloadRef{namespace: "ns", ownerKind: "Deployment", ownerName: "web"}, sel, false},
		{"statefulset", workloadRef{namespace: "ns", ownerKind: "StatefulSet", ownerName: "db"}, map[string]string{"app": "db"}, false},
		{"job", workloadRef{namespace: "ns", ownerKind: "Job", ownerName: "batch"}, map[string]string{"job": "batch"}, false},
		{"orphan pod", workloadRef{namespace: "ns", ownerKind: "Pod", podName: "orphan"}, map[string]string{"run": "orphan"}, false},
		{"pod without labels", workloadRef{namespace: "ns", ownerKind: "Pod", podName: "nolabels"}, nil, true},
		{"missing owner", workloadRef{namespace: "ns", ownerKind: "Deployment", ownerName: "ghost"}, nil, true},
		{"unsupported kind", workloadRef{namespace: "ns", ownerKind: "Frobnicator", ownerName: "x"}, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := m.resolveSelector(ctx, tc.ref)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got selector %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for k, v := range tc.wantLabel {
				if got.MatchLabels[k] != v {
					t.Fatalf("selector %+v missing %s=%s", got.MatchLabels, k, v)
				}
			}
		})
	}
}

func TestBuildPolicy_LabelsAnnotationsAndEgress(t *testing.T) {
	m := newTestManager(t, Config{ClusterCIDRs: []string{"10.96.0.0/12"}, ExtraAllowedCIDRs: []string{"203.0.113.0/24"}})
	st := restrictedTransition("ns/Deployment/web", "pkg-42")
	ref := workloadRef{namespace: "ns", ownerKind: "Deployment", ownerName: "web"}
	np := m.buildPolicy(ref, &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, st)

	if np.Name != PolicyName(st.WorkloadID) {
		t.Fatalf("policy name %q != deterministic name", np.Name)
	}
	if np.Labels[LabelManagedBy] != ManagedByValue {
		t.Fatalf("missing managed-by label: %v", np.Labels)
	}
	if np.Annotations[AnnFSMState] != string(schema.StateRestricted) {
		t.Fatalf("fsm-state annotation = %q", np.Annotations[AnnFSMState])
	}
	if np.Annotations[AnnPackageID] != "pkg-42" {
		t.Fatalf("package-id annotation = %q", np.Annotations[AnnPackageID])
	}
	if np.Annotations[AnnWorkloadID] != st.WorkloadID {
		t.Fatalf("workload-id annotation = %q", np.Annotations[AnnWorkloadID])
	}
	if len(np.Spec.PolicyTypes) != 1 || np.Spec.PolicyTypes[0] != networkingv1.PolicyTypeEgress {
		t.Fatalf("policyTypes = %v, want [Egress] (ingress untouched under RESTRICTED)", np.Spec.PolicyTypes)
	}
	// The allow-list must include RFC 1918, the cluster CIDR, and the extra CIDR.
	cidrs := map[string]bool{}
	for _, rule := range np.Spec.Egress {
		for _, peer := range rule.To {
			if peer.IPBlock != nil {
				cidrs[peer.IPBlock.CIDR] = true
			}
		}
	}
	for _, want := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "10.96.0.0/12", "203.0.113.0/24"} {
		if !cidrs[want] {
			t.Fatalf("egress allow-list missing %s (have %v)", want, cidrs)
		}
	}
	// A DNS (port 53) egress rule must be present (BI-8).
	foundDNS := false
	for _, rule := range np.Spec.Egress {
		for _, p := range rule.Ports {
			if p.Port != nil && p.Port.IntValue() == 53 {
				foundDNS = true
			}
		}
	}
	if !foundDNS {
		t.Fatal("no explicit DNS (port 53) egress rule found")
	}
}

func TestApply_CreateThenIdempotentReapply(t *testing.T) {
	sel := map[string]string{"app": "web"}
	m := newTestManager(t, Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, deployment("ns", "web", sel))
	ctx := context.Background()
	st := restrictedTransition("ns/Deployment/web", "pkg-1")
	ref := workloadRef{namespace: "ns", ownerKind: "Deployment", ownerName: "web"}
	np := m.buildPolicy(ref, &metav1.LabelSelector{MatchLabels: sel}, st)

	r1, err := m.apply(ctx, np)
	if err != nil || r1 != "applied" {
		t.Fatalf("first apply = (%q, %v), want (applied, nil)", r1, err)
	}
	// Re-apply an identical desired state: must be a no-op.
	np2 := m.buildPolicy(ref, &metav1.LabelSelector{MatchLabels: sel}, st)
	r2, err := m.apply(ctx, np2)
	if err != nil || r2 != "noop" {
		t.Fatalf("idempotent re-apply = (%q, %v), want (noop, nil)", r2, err)
	}
	// The policy exists in the API with the managed labels.
	got, err := m.cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, np.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get applied policy: %v", err)
	}
	if got.Labels[LabelManagedBy] != ManagedByValue {
		t.Fatalf("applied policy missing managed-by label")
	}
}

func TestApply_UpdatesOnChangedPackageID(t *testing.T) {
	sel := map[string]string{"app": "web"}
	m := newTestManager(t, Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, deployment("ns", "web", sel))
	ctx := context.Background()
	ref := workloadRef{namespace: "ns", ownerKind: "Deployment", ownerName: "web"}

	np1 := m.buildPolicy(ref, &metav1.LabelSelector{MatchLabels: sel}, restrictedTransition("ns/Deployment/web", "pkg-1"))
	if _, err := m.apply(ctx, np1); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	np2 := m.buildPolicy(ref, &metav1.LabelSelector{MatchLabels: sel}, restrictedTransition("ns/Deployment/web", "pkg-2"))
	r, err := m.apply(ctx, np2)
	if err != nil || r != "applied" {
		t.Fatalf("apply with new package-id = (%q, %v), want (applied, nil)", r, err)
	}
	got, _ := m.cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, np2.Name, metav1.GetOptions{})
	if got.Annotations[AnnPackageID] != "pkg-2" {
		t.Fatalf("package-id annotation not updated: %q", got.Annotations[AnnPackageID])
	}
}

func TestHandle_AppliesPolicyForRestrictedTransition(t *testing.T) {
	sel := map[string]string{"app": "web"}
	m := newTestManager(t, Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, deployment("ns", "web", sel))
	ctx := context.Background()
	st := restrictedTransition("ns/Deployment/web", "pkg-1")

	m.handle(ctx, st)

	_, err := m.cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, PolicyName(st.WorkloadID), metav1.GetOptions{})
	if err != nil {
		t.Fatalf("handle did not create the policy: %v", err)
	}
}

func TestHandle_SkipsExcludedNamespace(t *testing.T) {
	sel := map[string]string{"app": "x"}
	m := newTestManager(t, Config{ClusterCIDRs: []string{"10.96.0.0/12"}, ExcludedNamespaces: []string{"kube-system"}}, deployment("kube-system", "x", sel))
	ctx := context.Background()
	st := restrictedTransition("kube-system/Deployment/x", "pkg-1")

	m.handle(ctx, st)

	_, err := m.cs.NetworkingV1().NetworkPolicies("kube-system").Get(ctx, PolicyName(st.WorkloadID), metav1.GetOptions{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("expected no policy in excluded namespace, got err=%v", err)
	}
}

func TestPublish_FiltersAndEnqueues(t *testing.T) {
	m := newTestManager(t, Config{ClusterCIDRs: []string{"10.96.0.0/12"}})
	// Non-RESTRICTED transitions are ignored (not enqueued).
	m.Publish(schema.StateTransition{ToState: schema.StateSuspicious, WorkloadID: "ns/Deployment/web"})
	if len(m.queue) != 0 {
		t.Fatalf("non-RESTRICTED transition was enqueued: queue len %d", len(m.queue))
	}
	// A RESTRICTED transition is enqueued.
	m.Publish(restrictedTransition("ns/Deployment/web", "pkg-1"))
	if len(m.queue) != 1 {
		t.Fatalf("RESTRICTED transition not enqueued: queue len %d", len(m.queue))
	}
}

func TestPublish_DropsWhenQueueFull(t *testing.T) {
	cs := fake.NewSimpleClientset()
	m, err := New(Config{ClusterCIDRs: []string{"10.96.0.0/12"}, QueueSize: 1}, cs, nil, discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.Publish(restrictedTransition("ns/Deployment/a", "p1")) // fills the queue
	m.Publish(restrictedTransition("ns/Deployment/b", "p2")) // dropped, must not block
	if len(m.queue) != 1 {
		t.Fatalf("queue len = %d, want 1 (second publish dropped)", len(m.queue))
	}
}

func TestReconcileGC_DeletesOrphanKeepsLive(t *testing.T) {
	sel := map[string]string{"app": "live"}
	live := m_buildManagedPolicy("ns", "live", "ns/Deployment/live")
	orphan := m_buildManagedPolicy("ns", "orphan", "ns/Deployment/ghost")
	// Only the live workload's Deployment exists.
	m := newTestManager(t, Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, deployment("ns", "live", sel), live, orphan)
	ctx := context.Background()

	m.reconcileGC(ctx)

	if _, err := m.cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, "live", metav1.GetOptions{}); err != nil {
		t.Fatalf("live policy was deleted: %v", err)
	}
	if _, err := m.cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, "orphan", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("orphan policy not garbage-collected: err=%v", err)
	}
}

// m_buildManagedPolicy builds a managed NetworkPolicy with the workload-id
// annotation, mimicking one the manager would have applied.
func m_buildManagedPolicy(ns, name, workloadID string) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   ns,
			Name:        name,
			Labels:      managedLabels(),
			Annotations: map[string]string{AnnWorkloadID: workloadID, AnnFSMState: string(schema.StateRestricted)},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		},
	}
}

func TestReconcileGC_IgnoresUnmanagedPolicies(t *testing.T) {
	// An operator-owned policy without the managed-by label and without a
	// workload-id annotation must never be touched by GC.
	user := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "user-policy"},
		Spec:       networkingv1.NetworkPolicySpec{PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}},
	}
	m := newTestManager(t, Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, user)
	ctx := context.Background()
	m.reconcileGC(ctx)
	if _, err := m.cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, "user-policy", metav1.GetOptions{}); err != nil {
		t.Fatalf("unmanaged policy was deleted: %v", err)
	}
}

func TestRegisterMetrics_NoError(t *testing.T) {
	// Smoke-test that metric registration against a real registry succeeds.
	reg := metricsRegistryForTest(t)
	cs := fake.NewSimpleClientset()
	if _, err := New(Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, cs, reg, discardLog()); err != nil {
		t.Fatalf("New with metrics registry: %v", err)
	}
}
