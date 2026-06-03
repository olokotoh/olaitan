package netpol

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
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
	k8stesting "k8s.io/client-go/testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/schema"
)

// testutilToFloat reads the current value of the apply_total{result} series.
func testutilToFloat(t *testing.T, m *Manager, result string) float64 {
	t.Helper()
	return testutil.ToFloat64(m.applyTotal.WithLabelValues(result))
}

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

func quarantinedTransition(workloadID, packageID string) schema.StateTransition {
	return schema.StateTransition{
		Timestamp:  time.Now(),
		FromState:  schema.StateRestricted,
		ToState:    schema.StateQuarantined,
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

func TestBuildPolicy_OmitsEmptyPackageIDAnnotation(t *testing.T) {
	m := newTestManager(t, Config{ClusterCIDRs: []string{"10.96.0.0/12"}})
	ref := workloadRef{namespace: "ns", ownerKind: "Deployment", ownerName: "web"}
	sel := &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}

	// Present case: a non-empty package id is carried.
	withPkg := m.buildPolicy(ref, sel, restrictedTransition("ns/Deployment/web", "pkg-7"))
	if withPkg.Annotations[AnnPackageID] != "pkg-7" {
		t.Fatalf("package-id annotation = %q, want pkg-7", withPkg.Annotations[AnnPackageID])
	}

	// Absent case: an empty package id must omit the annotation key entirely
	// (mirrors the schema omitempty intent).
	noPkg := m.buildPolicy(ref, sel, restrictedTransition("ns/Deployment/web", ""))
	if _, ok := noPkg.Annotations[AnnPackageID]; ok {
		t.Fatalf("package-id annotation present for empty PackageID: %v", noPkg.Annotations)
	}
	// The other annotations must still be set.
	if noPkg.Annotations[AnnFSMState] != string(schema.StateRestricted) {
		t.Fatalf("fsm-state annotation missing when package id empty")
	}
	if noPkg.Annotations[AnnWorkloadID] != "ns/Deployment/web" {
		t.Fatalf("workload-id annotation missing when package id empty")
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
	// Only PRESERVED_KILLED has no managed-policy desired set and is dropped
	// (Story 2.6, BI-1): CLEAN and SUSPICIOUS are now removal states and ARE
	// enqueued (see TestPublish_EnqueuesRemovalStates).
	m.Publish(schema.StateTransition{ToState: schema.StatePreservedKilled, WorkloadID: "ns/Deployment/web"})
	if len(m.queue) != 0 {
		t.Fatalf("PRESERVED_KILLED transition was enqueued: queue len %d", len(m.queue))
	}
	// A RESTRICTED transition is enqueued.
	m.Publish(restrictedTransition("ns/Deployment/web", "pkg-1"))
	if len(m.queue) != 1 {
		t.Fatalf("RESTRICTED transition not enqueued: queue len %d", len(m.queue))
	}
	// A QUARANTINED transition is also enqueued (Story 2.5, BI-1).
	m.Publish(quarantinedTransition("ns/Deployment/web", "pkg-1"))
	if len(m.queue) != 2 {
		t.Fatalf("QUARANTINED transition not enqueued: queue len %d", len(m.queue))
	}
}

func TestEnforcedState_AcceptSet(t *testing.T) {
	accepted := map[schema.PodSecurityState]bool{
		schema.StateRestricted:  true,
		schema.StateQuarantined: true,
	}
	for _, s := range []schema.PodSecurityState{
		schema.StateClean, schema.StateSuspicious, schema.StateRestricted,
		schema.StateQuarantined, schema.StatePreservedKilled,
	} {
		if got := enforcedState(s); got != accepted[s] {
			t.Fatalf("enforcedState(%q) = %v, want %v", s, got, accepted[s])
		}
	}
}

func TestPolicyNameFor_PerStatePrefixedSameSuffix(t *testing.T) {
	const id = "ns/Deployment/web"
	restricted := policyNameFor(schema.StateRestricted, id)
	quarantined := policyNameFor(schema.StateQuarantined, id)

	if restricted != PolicyName(id) {
		t.Fatalf("policyNameFor(RESTRICTED) = %q != PolicyName(id) = %q", restricted, PolicyName(id))
	}
	if !strings.HasPrefix(restricted, policyNamePrefix) {
		t.Fatalf("restricted name %q missing prefix %q", restricted, policyNamePrefix)
	}
	if !strings.HasPrefix(quarantined, quarantinedNamePrefix) {
		t.Fatalf("quarantined name %q missing prefix %q", quarantined, quarantinedNamePrefix)
	}
	// Same 12-hex sha256 suffix; the two names differ only by prefix.
	suffixR := strings.TrimPrefix(restricted, policyNamePrefix)
	suffixQ := strings.TrimPrefix(quarantined, quarantinedNamePrefix)
	if suffixR != suffixQ {
		t.Fatalf("suffixes differ: restricted %q vs quarantined %q", suffixR, suffixQ)
	}
	if len(suffixQ) != 12 {
		t.Fatalf("hash suffix %q has unexpected length %d", suffixQ, len(suffixQ))
	}
	// Deterministic.
	if policyNameFor(schema.StateQuarantined, id) != quarantined {
		t.Fatal("policyNameFor(QUARANTINED) is not deterministic")
	}
}

func TestBuildPolicy_QuarantinedDenyAll(t *testing.T) {
	m := newTestManager(t, Config{ClusterCIDRs: []string{"10.96.0.0/12"}})
	st := quarantinedTransition("ns/Deployment/web", "pkg-9")
	ref := workloadRef{namespace: "ns", ownerKind: "Deployment", ownerName: "web"}
	sel := &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}
	np := m.buildPolicy(ref, sel, st)

	if np.Name != policyNameFor(schema.StateQuarantined, st.WorkloadID) {
		t.Fatalf("quarantine policy name %q != deterministic quarantine name", np.Name)
	}
	if !strings.HasPrefix(np.Name, quarantinedNamePrefix) {
		t.Fatalf("quarantine policy name %q missing quarantine prefix", np.Name)
	}
	// policyTypes must be exactly [Ingress, Egress].
	if len(np.Spec.PolicyTypes) != 2 {
		t.Fatalf("policyTypes = %v, want [Ingress, Egress]", np.Spec.PolicyTypes)
	}
	haveIngress, haveEgress := false, false
	for _, pt := range np.Spec.PolicyTypes {
		switch pt {
		case networkingv1.PolicyTypeIngress:
			haveIngress = true
		case networkingv1.PolicyTypeEgress:
			haveEgress = true
		}
	}
	if !haveIngress || !haveEgress {
		t.Fatalf("policyTypes = %v, want both Ingress and Egress", np.Spec.PolicyTypes)
	}
	// Deny-all: both rule slices nil/empty, and crucially NOT a stray empty
	// rule struct (which would invert to allow-all, BI-4).
	if len(np.Spec.Ingress) != 0 {
		t.Fatalf("quarantine Ingress = %v, want nil/empty (no allow-all rule)", np.Spec.Ingress)
	}
	if len(np.Spec.Egress) != 0 {
		t.Fatalf("quarantine Egress = %v, want nil/empty (no allow-all rule)", np.Spec.Egress)
	}
	if np.Spec.Ingress != nil {
		t.Fatal("quarantine Ingress is a non-nil empty slice; want nil to avoid any stray rule")
	}
	if np.Spec.Egress != nil {
		t.Fatal("quarantine Egress is a non-nil empty slice; want nil to avoid any stray rule")
	}
	if np.Annotations[AnnFSMState] != string(schema.StateQuarantined) {
		t.Fatalf("fsm-state annotation = %q, want QUARANTINED", np.Annotations[AnnFSMState])
	}
	if np.Annotations[AnnFSMState] != "QUARANTINED" {
		t.Fatalf("fsm-state annotation literal = %q, want QUARANTINED", np.Annotations[AnnFSMState])
	}
	if np.Labels[LabelManagedBy] != ManagedByValue {
		t.Fatalf("quarantine policy missing managed-by label: %v", np.Labels)
	}
	if np.Annotations[AnnWorkloadID] != st.WorkloadID {
		t.Fatalf("workload-id annotation = %q", np.Annotations[AnnWorkloadID])
	}
	if np.Annotations[AnnPackageID] != "pkg-9" {
		t.Fatalf("package-id annotation = %q", np.Annotations[AnnPackageID])
	}
	if np.Spec.PodSelector.MatchLabels["app"] != "web" {
		t.Fatalf("podSelector = %v", np.Spec.PodSelector)
	}
}

func TestBuildPolicy_RestrictedGoldenUnchangedAlongsideQuarantine(t *testing.T) {
	// Assert the RESTRICTED rendering is unchanged when the builder is now
	// state-keyed: egress allow-list present, policyTypes [Egress] only,
	// AnnFSMState == RESTRICTED.
	m := newTestManager(t, Config{ClusterCIDRs: []string{"10.96.0.0/12"}})
	st := restrictedTransition("ns/Deployment/web", "pkg-1")
	ref := workloadRef{namespace: "ns", ownerKind: "Deployment", ownerName: "web"}
	np := m.buildPolicy(ref, &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, st)

	if len(np.Spec.PolicyTypes) != 1 || np.Spec.PolicyTypes[0] != networkingv1.PolicyTypeEgress {
		t.Fatalf("RESTRICTED policyTypes = %v, want [Egress]", np.Spec.PolicyTypes)
	}
	if len(np.Spec.Egress) == 0 {
		t.Fatal("RESTRICTED egress allow-list missing")
	}
	if np.Spec.Ingress != nil {
		t.Fatalf("RESTRICTED Ingress = %v, want nil", np.Spec.Ingress)
	}
	if np.Annotations[AnnFSMState] != string(schema.StateRestricted) {
		t.Fatalf("RESTRICTED fsm-state annotation = %q", np.Annotations[AnnFSMState])
	}
	if !strings.HasPrefix(np.Name, policyNamePrefix) {
		t.Fatalf("RESTRICTED policy name %q missing restricted prefix", np.Name)
	}
}

func TestHandle_QuarantineAppliesAndDeletesRestricted(t *testing.T) {
	sel := map[string]string{"app": "web"}
	m := newTestManager(t, Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, deployment("ns", "web", sel))
	ctx := context.Background()
	workloadID := "ns/Deployment/web"

	// Pre-existing RESTRICTED policy (the workload passed through RESTRICTED).
	m.handle(ctx, restrictedTransition(workloadID, "pkg-1"))
	restrictedName := policyNameFor(schema.StateRestricted, workloadID)
	if _, err := m.cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, restrictedName, metav1.GetOptions{}); err != nil {
		t.Fatalf("precondition: restricted policy not applied: %v", err)
	}

	// QUARANTINED transition: applies the quarantine policy, then deletes the
	// restricted policy (apply-before-delete).
	m.handle(ctx, quarantinedTransition(workloadID, "pkg-2"))

	// Causal order in the assertions: quarantine present first ...
	quarantineName := policyNameFor(schema.StateQuarantined, workloadID)
	q, err := m.cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, quarantineName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("quarantine policy not applied: %v", err)
	}
	if q.Annotations[AnnFSMState] != "QUARANTINED" {
		t.Fatalf("quarantine policy fsm-state = %q, want QUARANTINED", q.Annotations[AnnFSMState])
	}
	if len(q.Spec.PolicyTypes) != 2 {
		t.Fatalf("quarantine policyTypes = %v, want [Ingress, Egress]", q.Spec.PolicyTypes)
	}
	// ... then the restricted policy is gone.
	if _, err := m.cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, restrictedName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("restricted policy not superseded (deleted): err=%v", err)
	}
}

func TestHandle_QuarantineWithoutPriorRestrictedIsNoOpDelete(t *testing.T) {
	sel := map[string]string{"app": "web"}
	m := newTestManager(t, Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, deployment("ns", "web", sel))
	ctx := context.Background()
	workloadID := "ns/Deployment/web"

	// QUARANTINED with NO prior restricted policy: still applies quarantine,
	// and the absent-restricted delete is a no-op (no error, no crash).
	m.handle(ctx, quarantinedTransition(workloadID, "pkg-1"))

	quarantineName := policyNameFor(schema.StateQuarantined, workloadID)
	if _, err := m.cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, quarantineName, metav1.GetOptions{}); err != nil {
		t.Fatalf("quarantine policy not applied: %v", err)
	}
	restrictedName := policyNameFor(schema.StateRestricted, workloadID)
	if _, err := m.cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, restrictedName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("unexpected restricted policy present: err=%v", err)
	}
}

func TestDeleteSupersededRestricted_NoOpWhenAbsent(t *testing.T) {
	m := newTestManager(t, Config{ClusterCIDRs: []string{"10.96.0.0/12"}})
	ctx := context.Background()
	ref := workloadRef{namespace: "ns", ownerKind: "Deployment", ownerName: "web"}
	// No restricted policy exists; the delete must be a silent no-op (NotFound
	// treated as success, no panic, no error surfaced).
	m.deleteSupersededRestricted(ctx, ref, "ns/Deployment/web")
}

// syntheticAPIError is a non-NotFound, non-AlreadyExists server error the
// reactor tests inject to simulate a transient apiserver failure. apierrors
// helpers classify it as a generic error (not NotFound), so handle takes the
// genuine-error path and counts "error".
var syntheticAPIError = apierrors.NewInternalError(errors.New("synthetic apiserver failure"))

func TestHandle_FailedQuarantineApplyPreservesRestricted(t *testing.T) {
	// Safety invariant (apply-before-delete): a FAILED quarantine apply must
	// NEVER delete the restricted policy. Pre-create the restricted policy, then
	// fail every networkpolicies create/update so the quarantine apply errors;
	// the restricted policy MUST survive and the manager MUST count an error.
	sel := map[string]string{"app": "web"}
	reg := metricsRegistryForTest(t)
	cs := fake.NewSimpleClientset(runtime.Object(deployment("ns", "web", sel)))
	m, err := New(Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, cs, reg, discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	workloadID := "ns/Deployment/web"
	restrictedName := policyNameFor(schema.StateRestricted, workloadID)

	// Pre-create the RESTRICTED policy (the workload passed through RESTRICTED).
	m.handle(ctx, restrictedTransition(workloadID, "pkg-1"))
	if _, gerr := cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, restrictedName, metav1.GetOptions{}); gerr != nil {
		t.Fatalf("precondition: restricted policy not applied: %v", gerr)
	}

	// Now fail all networkpolicies create AND update with a synthetic
	// non-NotFound error so the quarantine apply fails.
	cs.PrependReactor("create", "networkpolicies", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, syntheticAPIError
	})
	cs.PrependReactor("update", "networkpolicies", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, syntheticAPIError
	})

	m.handle(ctx, quarantinedTransition(workloadID, "pkg-2"))

	// (a) The failed quarantine apply was counted as an error.
	if got := testutilToFloat(t, m, "error"); got != 1 {
		t.Fatalf("apply_total{error} = %v, want 1 for a failed quarantine apply", got)
	}
	// (b) The RESTRICTED policy is STILL present: the failed apply did NOT
	// trigger the supersession delete (the load-bearing safety invariant).
	if _, gerr := cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, restrictedName, metav1.GetOptions{}); gerr != nil {
		t.Fatalf("restricted policy was deleted after a FAILED quarantine apply (safety invariant violated): %v", gerr)
	}
	// And no quarantine policy was created.
	quarantineName := policyNameFor(schema.StateQuarantined, workloadID)
	if _, gerr := cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, quarantineName, metav1.GetOptions{}); !apierrors.IsNotFound(gerr) {
		t.Fatalf("quarantine policy unexpectedly present after failed apply: err=%v", gerr)
	}
}

func TestHandle_QuarantineSucceedsButRestrictedDeleteFailsIsSwallowed(t *testing.T) {
	// WARN-branch coverage: the quarantine apply SUCCEEDS but the best-effort
	// supersession delete of the restricted policy returns a non-NotFound error.
	// handle must NOT fail (no panic, returns normally), the quarantine policy
	// must be present, and the restricted policy is still present (the delete
	// failed but was swallowed as best-effort WARN).
	sel := map[string]string{"app": "web"}
	m := newTestManager(t, Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, deployment("ns", "web", sel))
	cs := m.cs.(*fake.Clientset)
	ctx := context.Background()
	workloadID := "ns/Deployment/web"
	restrictedName := policyNameFor(schema.StateRestricted, workloadID)
	quarantineName := policyNameFor(schema.StateQuarantined, workloadID)

	// Pre-create the RESTRICTED policy.
	m.handle(ctx, restrictedTransition(workloadID, "pkg-1"))
	if _, gerr := cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, restrictedName, metav1.GetOptions{}); gerr != nil {
		t.Fatalf("precondition: restricted policy not applied: %v", gerr)
	}

	// Fail every networkpolicies delete (the quarantine create/update path is
	// left untouched, so the apply still succeeds).
	cs.PrependReactor("delete", "networkpolicies", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, syntheticAPIError
	})

	// Must not panic and must return normally.
	m.handle(ctx, quarantinedTransition(workloadID, "pkg-2"))

	// The quarantine policy IS present (apply succeeded).
	if _, gerr := cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, quarantineName, metav1.GetOptions{}); gerr != nil {
		t.Fatalf("quarantine policy not applied: %v", gerr)
	}
	// The restricted policy is still present: the delete failed and was
	// swallowed as best-effort WARN, not surfaced as a handle failure.
	if _, gerr := cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, restrictedName, metav1.GetOptions{}); gerr != nil {
		t.Fatalf("restricted policy missing; the failed best-effort delete should have left it in place: %v", gerr)
	}
}

func TestHandle_QuarantineSkipsExcludedNamespace(t *testing.T) {
	// Mirror of TestHandle_SkipsExcludedNamespace for QUARANTINED: a QUARANTINED
	// transition into an excluded namespace must NOT apply a quarantine policy
	// AND must NOT delete a pre-existing restricted policy there. Count "skipped".
	sel := map[string]string{"app": "x"}
	reg := metricsRegistryForTest(t)
	restricted := m_buildManagedPolicy("kube-system", policyNameFor(schema.StateRestricted, "kube-system/Deployment/x"), "kube-system/Deployment/x")
	cs := fake.NewSimpleClientset(runtime.Object(deployment("kube-system", "x", sel)), runtime.Object(restricted))
	m, err := New(Config{ClusterCIDRs: []string{"10.96.0.0/12"}, ExcludedNamespaces: []string{"kube-system"}}, cs, reg, discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	workloadID := "kube-system/Deployment/x"

	m.handle(ctx, quarantinedTransition(workloadID, "pkg-1"))

	if got := testutilToFloat(t, m, "skipped"); got != 1 {
		t.Fatalf("apply_total{skipped} = %v, want 1 for excluded-namespace QUARANTINED", got)
	}
	// No quarantine policy was created.
	quarantineName := policyNameFor(schema.StateQuarantined, workloadID)
	if _, gerr := cs.NetworkingV1().NetworkPolicies("kube-system").Get(ctx, quarantineName, metav1.GetOptions{}); !apierrors.IsNotFound(gerr) {
		t.Fatalf("quarantine policy created in excluded namespace: err=%v", gerr)
	}
	// The pre-existing restricted policy survives (no supersession delete ran).
	restrictedName := policyNameFor(schema.StateRestricted, workloadID)
	if _, gerr := cs.NetworkingV1().NetworkPolicies("kube-system").Get(ctx, restrictedName, metav1.GetOptions{}); gerr != nil {
		t.Fatalf("restricted policy in excluded namespace was deleted by a skipped QUARANTINED: %v", gerr)
	}
}

func TestHandle_QuarantineIdempotentReapply(t *testing.T) {
	sel := map[string]string{"app": "web"}
	reg := metricsRegistryForTest(t)
	cs := fake.NewSimpleClientset(runtime.Object(deployment("ns", "web", sel)))
	m, err := New(Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, cs, reg, discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	st := quarantinedTransition("ns/Deployment/web", "pkg-1")

	m.handle(ctx, st)
	if got := testutilToFloat(t, m, "applied"); got != 1 {
		t.Fatalf("apply_total{applied} after first quarantine = %v, want 1", got)
	}
	// Re-emit the identical QUARANTINED transition: idempotent noop apply, and
	// the (already-absent) restricted delete is a no-op.
	m.handle(ctx, st)
	if got := testutilToFloat(t, m, "noop"); got != 1 {
		t.Fatalf("apply_total{noop} after re-quarantine = %v, want 1", got)
	}
}

func TestHandle_QuarantineUnresolvableSkipped(t *testing.T) {
	reg := metricsRegistryForTest(t)
	cs := fake.NewSimpleClientset()
	m, err := New(Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, cs, reg, discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Valid id, owner does not exist -> resolve NotFound -> skipped, not error.
	m.handle(context.Background(), quarantinedTransition("ns/Deployment/ghost", "pkg-1"))
	if got := testutilToFloat(t, m, "skipped"); got != 1 {
		t.Fatalf("apply_total{skipped} = %v, want 1 for unresolvable QUARANTINED", got)
	}
	if got := testutilToFloat(t, m, "error"); got != 0 {
		t.Fatalf("apply_total{error} = %v, want 0", got)
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

func TestReconcileGC_CollectsManagedOrphanEvenInExcludedNamespace(t *testing.T) {
	// A managed orphan policy must be GC'd regardless of namespace exclusion.
	// Excluding a namespace stops handle applying NEW policies there, but a
	// policy Olaitan already created must still be collectable once its owner
	// is gone, otherwise excluding a namespace after a policy was applied would
	// strand our own orphan permanently.
	orphan := m_buildManagedPolicy("kube-system", "orphan", "kube-system/Deployment/ghost")
	m := newTestManager(t, Config{ClusterCIDRs: []string{"10.96.0.0/12"}, ExcludedNamespaces: []string{"kube-system"}}, orphan)
	ctx := context.Background()

	m.reconcileGC(ctx)

	if _, err := m.cs.NetworkingV1().NetworkPolicies("kube-system").Get(ctx, "orphan", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("managed orphan in excluded namespace was not GC'd: err=%v", err)
	}
}

// m_buildManagedQuarantinePolicy builds a managed QUARANTINED deny-all policy
// carrying the workload-id and fsm-state=QUARANTINED annotations, mimicking one
// the manager would have applied for a quarantined workload.
func m_buildManagedQuarantinePolicy(ns, name, workloadID string) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   ns,
			Name:        name,
			Labels:      managedLabels(),
			Annotations: map[string]string{AnnWorkloadID: workloadID, AnnFSMState: string(schema.StateQuarantined)},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
		},
	}
}

func TestReconcileGC_RemovesSupersededRestrictedKeepsQuarantine(t *testing.T) {
	// Supersession backstop (FIX A): simulate a FAILED inline supersession where
	// a workload in QUARANTINED still carries its RESTRICTED policy alongside the
	// QUARANTINED policy. The owner Deployment still exists, so orphan GC alone
	// would NOT reap the lingering restricted policy. The reconcile pass must
	// delete the superseded RESTRICTED policy and keep the QUARANTINED policy.
	//
	// A separate workload (no quarantine policy) keeps only a RESTRICTED policy:
	// it must be left untouched by this pass (only superseded policies are
	// removed; its owner still exists, so orphan GC does not touch it either).
	selSup := map[string]string{"app": "sup"}
	selKeep := map[string]string{"app": "keep"}
	supWID := "ns/Deployment/sup"
	keepWID := "ns/Deployment/keep"

	supRestricted := m_buildManagedPolicy("ns", policyNameFor(schema.StateRestricted, supWID), supWID)
	supQuarantine := m_buildManagedQuarantinePolicy("ns", policyNameFor(schema.StateQuarantined, supWID), supWID)
	keepRestricted := m_buildManagedPolicy("ns", policyNameFor(schema.StateRestricted, keepWID), keepWID)

	reg := metricsRegistryForTest(t)
	cs := fake.NewSimpleClientset(
		runtime.Object(deployment("ns", "sup", selSup)),
		runtime.Object(deployment("ns", "keep", selKeep)),
		runtime.Object(supRestricted),
		runtime.Object(supQuarantine),
		runtime.Object(keepRestricted),
	)
	m, err := New(Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, cs, reg, discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	m.reconcileGC(ctx)

	// The superseded RESTRICTED policy is deleted.
	if _, gerr := cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, supRestricted.Name, metav1.GetOptions{}); !apierrors.IsNotFound(gerr) {
		t.Fatalf("superseded restricted policy was not removed by reconcile: err=%v", gerr)
	}
	// The QUARANTINED policy survives.
	if _, gerr := cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, supQuarantine.Name, metav1.GetOptions{}); gerr != nil {
		t.Fatalf("quarantine policy was incorrectly removed by reconcile: %v", gerr)
	}
	// The unrelated RESTRICTED policy (no quarantine for its workload) survives:
	// it is not superseded, and its owner still exists so it is not an orphan.
	if _, gerr := cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, keepRestricted.Name, metav1.GetOptions{}); gerr != nil {
		t.Fatalf("non-superseded restricted policy was incorrectly removed by reconcile: %v", gerr)
	}
	// The supersession was counted exactly once.
	if got := testutilToFloat(t, m, "superseded"); got != 1 {
		t.Fatalf("apply_total{superseded} = %v, want 1", got)
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

// ---- Story 2.6: de-escalation policy removal (FR35) ----

// suspiciousTransition / cleanTransition mirror restrictedTransition /
// quarantinedTransition for the Story 2.6 removal states.
func suspiciousTransition(workloadID, packageID string) schema.StateTransition {
	return schema.StateTransition{
		Timestamp:  time.Now(),
		FromState:  schema.StateRestricted,
		ToState:    schema.StateSuspicious,
		WorkloadID: workloadID,
		PackageID:  packageID,
	}
}

func cleanTransition(workloadID, packageID string) schema.StateTransition {
	return schema.StateTransition{
		Timestamp:  time.Now(),
		FromState:  schema.StateSuspicious,
		ToState:    schema.StateClean,
		WorkloadID: workloadID,
		PackageID:  packageID,
	}
}

// fakeOracle is an injectable netpol.StateOracle for the FSM-target-aware
// reconcile tests. states maps a workload id to its current FSM target; an
// absent key reports not-ok (the FSM has no opinion).
type fakeOracle struct {
	states map[string]schema.PodSecurityState
}

func (f fakeOracle) CurrentState(workloadID string) (schema.PodSecurityState, bool) {
	s, ok := f.states[workloadID]
	return s, ok
}

func TestRemovalState_Predicate(t *testing.T) {
	removal := map[schema.PodSecurityState]bool{
		schema.StateSuspicious: true,
		schema.StateClean:      true,
	}
	for _, s := range []schema.PodSecurityState{
		schema.StateClean, schema.StateSuspicious, schema.StateRestricted,
		schema.StateQuarantined, schema.StatePreservedKilled,
	} {
		if got := removalState(s); got != removal[s] {
			t.Fatalf("removalState(%q) = %v, want %v", s, got, removal[s])
		}
	}
}

func TestPublish_EnqueuesRemovalStates(t *testing.T) {
	m := newTestManager(t, Config{ClusterCIDRs: []string{"10.96.0.0/12"}})
	// SUSPICIOUS and CLEAN are now enqueued (Story 2.6, BI-1).
	m.Publish(suspiciousTransition("ns/Deployment/web", "pkg-1"))
	m.Publish(cleanTransition("ns/Deployment/web", "pkg-2"))
	if len(m.queue) != 2 {
		t.Fatalf("removal transitions not enqueued: queue len %d, want 2", len(m.queue))
	}
	// PRESERVED_KILLED is still dropped (neither enforced nor removal).
	m.Publish(schema.StateTransition{ToState: schema.StatePreservedKilled, WorkloadID: "ns/Deployment/web"})
	if len(m.queue) != 2 {
		t.Fatalf("PRESERVED_KILLED was enqueued: queue len %d, want 2", len(m.queue))
	}
}

func TestHandle_RestrictedDeletesSupersededQuarantine(t *testing.T) {
	// QUARANTINED->RESTRICTED de-escalation (AC1): the restricted policy is
	// applied AND the pre-existing quarantine deny-all is removed, in causal
	// order (restricted present before quarantine absent).
	sel := map[string]string{"app": "web"}
	workloadID := "ns/Deployment/web"
	quarantine := m_buildManagedQuarantinePolicy("ns", policyNameFor(schema.StateQuarantined, workloadID), workloadID)
	m := newTestManager(t, Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, deployment("ns", "web", sel), quarantine)
	ctx := context.Background()
	restrictedName := policyNameFor(schema.StateRestricted, workloadID)
	quarantineName := policyNameFor(schema.StateQuarantined, workloadID)

	m.handle(ctx, restrictedTransition(workloadID, "pkg-1"))

	// Restricted present first ...
	r, err := m.cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, restrictedName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("restricted policy not applied on de-escalation: %v", err)
	}
	if r.Annotations[AnnFSMState] != string(schema.StateRestricted) {
		t.Fatalf("restricted fsm-state annotation = %q, want RESTRICTED", r.Annotations[AnnFSMState])
	}
	if len(r.Spec.PolicyTypes) != 1 || r.Spec.PolicyTypes[0] != networkingv1.PolicyTypeEgress {
		t.Fatalf("restricted policyTypes = %v, want [Egress]", r.Spec.PolicyTypes)
	}
	// ... then the superseded quarantine deny-all is gone.
	if _, err := m.cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, quarantineName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("superseded quarantine policy not removed on de-escalation: err=%v", err)
	}
}

func TestHandle_RestrictedWithoutPriorQuarantineIsNoOpDelete(t *testing.T) {
	sel := map[string]string{"app": "web"}
	m := newTestManager(t, Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, deployment("ns", "web", sel))
	ctx := context.Background()
	workloadID := "ns/Deployment/web"

	// RESTRICTED with NO prior quarantine policy: still applies restricted, and
	// the absent-quarantine delete is a no-op.
	m.handle(ctx, restrictedTransition(workloadID, "pkg-1"))

	restrictedName := policyNameFor(schema.StateRestricted, workloadID)
	if _, err := m.cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, restrictedName, metav1.GetOptions{}); err != nil {
		t.Fatalf("restricted policy not applied: %v", err)
	}
	quarantineName := policyNameFor(schema.StateQuarantined, workloadID)
	if _, err := m.cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, quarantineName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("unexpected quarantine policy present: err=%v", err)
	}
}

func TestDeleteSupersededQuarantine_NoOpWhenAbsent(t *testing.T) {
	m := newTestManager(t, Config{ClusterCIDRs: []string{"10.96.0.0/12"}})
	ctx := context.Background()
	ref := workloadRef{namespace: "ns", ownerKind: "Deployment", ownerName: "web"}
	// No quarantine policy exists; the delete must be a silent no-op.
	m.deleteSupersededQuarantine(ctx, ref, "ns/Deployment/web")
}

func TestHandle_SuspiciousRemovesBothPolicies(t *testing.T) {
	// SUSPICIOUS removal (AC2): both managed policies for the workload are
	// removed, counted "removed".
	workloadID := "ns/Deployment/web"
	restricted := m_buildManagedPolicy("ns", policyNameFor(schema.StateRestricted, workloadID), workloadID)
	quarantine := m_buildManagedQuarantinePolicy("ns", policyNameFor(schema.StateQuarantined, workloadID), workloadID)
	reg := metricsRegistryForTest(t)
	cs := fake.NewSimpleClientset(runtime.Object(restricted), runtime.Object(quarantine))
	m, err := New(Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, cs, reg, discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	m.handle(ctx, suspiciousTransition(workloadID, "pkg-1"))

	if _, gerr := cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, restricted.Name, metav1.GetOptions{}); !apierrors.IsNotFound(gerr) {
		t.Fatalf("restricted policy not removed on SUSPICIOUS: err=%v", gerr)
	}
	if _, gerr := cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, quarantine.Name, metav1.GetOptions{}); !apierrors.IsNotFound(gerr) {
		t.Fatalf("quarantine policy not removed on SUSPICIOUS: err=%v", gerr)
	}
	if got := testutilToFloat(t, m, "removed"); got != 1 {
		t.Fatalf("apply_total{removed} = %v, want 1", got)
	}
	if got := testutilToFloat(t, m, "error"); got != 0 {
		t.Fatalf("apply_total{error} = %v, want 0", got)
	}
}

func TestHandle_CleanRemovesBothAndVerifiesAbsence(t *testing.T) {
	// CLEAN removal (AC3): both managed policies removed, absence verified, no
	// resolveSelector needed (no owner created), counted "removed".
	workloadID := "ns/Deployment/web"
	restricted := m_buildManagedPolicy("ns", policyNameFor(schema.StateRestricted, workloadID), workloadID)
	quarantine := m_buildManagedQuarantinePolicy("ns", policyNameFor(schema.StateQuarantined, workloadID), workloadID)
	reg := metricsRegistryForTest(t)
	cs := fake.NewSimpleClientset(runtime.Object(restricted), runtime.Object(quarantine))
	m, err := New(Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, cs, reg, discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	m.handle(ctx, cleanTransition(workloadID, "pkg-1"))

	if _, gerr := cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, restricted.Name, metav1.GetOptions{}); !apierrors.IsNotFound(gerr) {
		t.Fatalf("restricted policy not removed on CLEAN: err=%v", gerr)
	}
	if _, gerr := cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, quarantine.Name, metav1.GetOptions{}); !apierrors.IsNotFound(gerr) {
		t.Fatalf("quarantine policy not removed on CLEAN: err=%v", gerr)
	}
	if got := testutilToFloat(t, m, "removed"); got != 1 {
		t.Fatalf("apply_total{removed} = %v, want 1", got)
	}
	if got := testutilToFloat(t, m, "error"); got != 0 {
		t.Fatalf("apply_total{error} = %v, want 0", got)
	}
}

func TestHandle_CleanWithNothingPresentIsCleanNoOp(t *testing.T) {
	// A CLEAN de-escalation for a workload that was never isolated: both deletes
	// are NotFound no-ops, both verification reads confirm absence, the result is
	// a successful "removed", NEVER "error" (BI-5, Open Assumption 3).
	reg := metricsRegistryForTest(t)
	cs := fake.NewSimpleClientset()
	m, err := New(Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, cs, reg, discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	workloadID := "ns/Deployment/web"

	m.handle(ctx, cleanTransition(workloadID, "pkg-1"))

	if got := testutilToFloat(t, m, "removed"); got != 1 {
		t.Fatalf("apply_total{removed} = %v, want 1 for a no-op CLEAN", got)
	}
	if got := testutilToFloat(t, m, "error"); got != 0 {
		t.Fatalf("apply_total{error} = %v, want 0 for a no-op CLEAN", got)
	}
	// No policy was created.
	if _, gerr := cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, policyNameFor(schema.StateRestricted, workloadID), metav1.GetOptions{}); !apierrors.IsNotFound(gerr) {
		t.Fatalf("unexpected restricted policy present after no-op CLEAN: err=%v", gerr)
	}
}

func TestHandle_RemovalSkipsExcludedNamespace(t *testing.T) {
	// A SUSPICIOUS/CLEAN removal into an excluded namespace is skipped (mirrors
	// the apply path); a pre-existing managed policy there is NOT touched by the
	// inline path (the reconcile/orphan-GC remains the safety net).
	workloadID := "kube-system/Deployment/x"
	restricted := m_buildManagedPolicy("kube-system", policyNameFor(schema.StateRestricted, workloadID), workloadID)
	reg := metricsRegistryForTest(t)
	cs := fake.NewSimpleClientset(runtime.Object(restricted))
	m, err := New(Config{ClusterCIDRs: []string{"10.96.0.0/12"}, ExcludedNamespaces: []string{"kube-system"}}, cs, reg, discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	m.handle(ctx, suspiciousTransition(workloadID, "pkg-1"))

	if got := testutilToFloat(t, m, "skipped"); got != 1 {
		t.Fatalf("apply_total{skipped} = %v, want 1 for excluded-namespace removal", got)
	}
	if got := testutilToFloat(t, m, "removed"); got != 0 {
		t.Fatalf("apply_total{removed} = %v, want 0 for a skipped removal", got)
	}
	// The pre-existing policy survives (inline path did not touch it).
	if _, gerr := cs.NetworkingV1().NetworkPolicies("kube-system").Get(ctx, restricted.Name, metav1.GetOptions{}); gerr != nil {
		t.Fatalf("policy in excluded namespace was deleted by a skipped removal: %v", gerr)
	}
}

func TestHandle_RemovalMalformedWorkloadIDIsError(t *testing.T) {
	reg := metricsRegistryForTest(t)
	cs := fake.NewSimpleClientset()
	m, err := New(Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, cs, reg, discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Malformed id (2 segments): parseWorkloadID fails on the removal path too,
	// counted "error" (mirrors the apply path).
	m.handle(context.Background(), cleanTransition("ns/web", "pkg-1"))
	if got := testutilToFloat(t, m, "error"); got != 1 {
		t.Fatalf("apply_total{error} = %v, want 1 for a malformed-id removal", got)
	}
}

func TestHandle_CleanReDeletesStraySurvivor(t *testing.T) {
	// CLEAN verification re-delete branch (BI-5): a delete returns success but a
	// follow-up Get still finds the policy (a stale object). The manager
	// re-deletes once; the second delete then succeeds, so the result is
	// "removed", not "error". We simulate "delete reports success but object
	// lingers" by intercepting only the FIRST delete with a no-op success
	// reactor that leaves the object in place.
	workloadID := "ns/Deployment/web"
	restricted := m_buildManagedPolicy("ns", policyNameFor(schema.StateRestricted, workloadID), workloadID)
	reg := metricsRegistryForTest(t)
	cs := fake.NewSimpleClientset(runtime.Object(restricted))
	m, err := New(Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, cs, reg, discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	restrictedName := restricted.Name

	var deleteCalls int
	cs.PrependReactor("delete", "networkpolicies", func(action k8stesting.Action) (bool, runtime.Object, error) {
		da := action.(k8stesting.DeleteAction)
		if da.GetName() == restrictedName {
			deleteCalls++
			if deleteCalls == 1 {
				// Report success WITHOUT removing the object: simulate a delete
				// that returned ok but did not take effect.
				return true, nil, nil
			}
		}
		// Subsequent calls fall through to the default tracker (real delete).
		return false, nil, nil
	})

	m.handle(ctx, cleanTransition(workloadID, "pkg-1"))

	// The stray survivor was re-deleted and is now gone.
	if _, gerr := cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, restrictedName, metav1.GetOptions{}); !apierrors.IsNotFound(gerr) {
		t.Fatalf("stray restricted policy not re-deleted on CLEAN: err=%v", gerr)
	}
	if deleteCalls < 2 {
		t.Fatalf("expected a re-delete on the stray survivor; delete calls = %d", deleteCalls)
	}
	if got := testutilToFloat(t, m, "removed"); got != 1 {
		t.Fatalf("apply_total{removed} = %v, want 1 after a successful re-delete", got)
	}
	if got := testutilToFloat(t, m, "error"); got != 0 {
		t.Fatalf("apply_total{error} = %v, want 0 after a successful re-delete", got)
	}
}

func TestReconcileGC_TargetRestrictedDeletesStaleQuarantine(t *testing.T) {
	// FSM-target-aware reconcile (BI-2c): with the oracle reporting the workload
	// as RESTRICTED, a co-existing QUARANTINED deny-all (the de-escalation
	// residue of a failed inline delete) is removed, and the freshly-applied
	// RESTRICTED policy SURVIVES (the backstop does not re-delete it).
	sel := map[string]string{"app": "web"}
	workloadID := "ns/Deployment/web"
	restricted := m_buildManagedPolicy("ns", policyNameFor(schema.StateRestricted, workloadID), workloadID)
	quarantine := m_buildManagedQuarantinePolicy("ns", policyNameFor(schema.StateQuarantined, workloadID), workloadID)
	reg := metricsRegistryForTest(t)
	cs := fake.NewSimpleClientset(
		runtime.Object(deployment("ns", "web", sel)),
		runtime.Object(restricted),
		runtime.Object(quarantine),
	)
	m, err := New(Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, cs, reg, discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.SetStateOracle(fakeOracle{states: map[string]schema.PodSecurityState{workloadID: schema.StateRestricted}})
	ctx := context.Background()

	m.reconcileGC(ctx)

	// The stale QUARANTINED deny-all is removed.
	if _, gerr := cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, quarantine.Name, metav1.GetOptions{}); !apierrors.IsNotFound(gerr) {
		t.Fatalf("stale quarantine policy not removed for RESTRICTED target: err=%v", gerr)
	}
	// The RESTRICTED policy survives (NOT re-deleted).
	if _, gerr := cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, restricted.Name, metav1.GetOptions{}); gerr != nil {
		t.Fatalf("RESTRICTED policy was wrongly re-deleted on de-escalation: %v", gerr)
	}
	if got := testutilToFloat(t, m, "removed"); got != 1 {
		t.Fatalf("apply_total{removed} = %v, want 1", got)
	}
}

func TestReconcileGC_TargetQuarantinedDeletesStaleRestricted(t *testing.T) {
	// FSM-target-aware reconcile (BI-2c) Story 2.5 regression: with the oracle
	// reporting QUARANTINED, a lingering RESTRICTED policy (escalation residue)
	// is removed and the QUARANTINED deny-all survives.
	sel := map[string]string{"app": "web"}
	workloadID := "ns/Deployment/web"
	restricted := m_buildManagedPolicy("ns", policyNameFor(schema.StateRestricted, workloadID), workloadID)
	quarantine := m_buildManagedQuarantinePolicy("ns", policyNameFor(schema.StateQuarantined, workloadID), workloadID)
	reg := metricsRegistryForTest(t)
	cs := fake.NewSimpleClientset(
		runtime.Object(deployment("ns", "web", sel)),
		runtime.Object(restricted),
		runtime.Object(quarantine),
	)
	m, err := New(Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, cs, reg, discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.SetStateOracle(fakeOracle{states: map[string]schema.PodSecurityState{workloadID: schema.StateQuarantined}})
	ctx := context.Background()

	m.reconcileGC(ctx)

	if _, gerr := cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, restricted.Name, metav1.GetOptions{}); !apierrors.IsNotFound(gerr) {
		t.Fatalf("escalation-residue restricted policy not removed for QUARANTINED target: err=%v", gerr)
	}
	if _, gerr := cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, quarantine.Name, metav1.GetOptions{}); gerr != nil {
		t.Fatalf("quarantine policy wrongly removed for QUARANTINED target: %v", gerr)
	}
	if got := testutilToFloat(t, m, "superseded"); got != 1 {
		t.Fatalf("apply_total{superseded} = %v, want 1", got)
	}
}

func TestReconcileGC_TargetSuspiciousDeletesBothWhenOwnerExists(t *testing.T) {
	// FSM-target-aware reconcile (BI-2c/BI-6): with the oracle reporting
	// SUSPICIOUS and the owner still present, BOTH managed policies are removed
	// (a failed inline removal self-heals).
	sel := map[string]string{"app": "web"}
	workloadID := "ns/Deployment/web"
	restricted := m_buildManagedPolicy("ns", policyNameFor(schema.StateRestricted, workloadID), workloadID)
	quarantine := m_buildManagedQuarantinePolicy("ns", policyNameFor(schema.StateQuarantined, workloadID), workloadID)
	reg := metricsRegistryForTest(t)
	cs := fake.NewSimpleClientset(
		runtime.Object(deployment("ns", "web", sel)),
		runtime.Object(restricted),
		runtime.Object(quarantine),
	)
	m, err := New(Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, cs, reg, discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.SetStateOracle(fakeOracle{states: map[string]schema.PodSecurityState{workloadID: schema.StateSuspicious}})
	ctx := context.Background()

	m.reconcileGC(ctx)

	if _, gerr := cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, restricted.Name, metav1.GetOptions{}); !apierrors.IsNotFound(gerr) {
		t.Fatalf("restricted policy not removed for SUSPICIOUS target: err=%v", gerr)
	}
	if _, gerr := cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, quarantine.Name, metav1.GetOptions{}); !apierrors.IsNotFound(gerr) {
		t.Fatalf("quarantine policy not removed for SUSPICIOUS target: err=%v", gerr)
	}
	if got := testutilToFloat(t, m, "removed"); got != 2 {
		t.Fatalf("apply_total{removed} = %v, want 2 (both policies)", got)
	}
}

func TestReconcileGC_NotOkLeavesPolicyWhenOwnerExists(t *testing.T) {
	// BI-2c not-ok rule: the FSM has NO entry for the workload (oracle not-ok)
	// but a managed policy lingers and the owner still EXISTS. The desired-state
	// backstop must NOT delete it (avoid stripping protection from a workload the
	// FSM merely lost track of, e.g. after an unrestored restart); the orphan-GC
	// pass leaves it too because the owner exists. The policy SURVIVES.
	sel := map[string]string{"app": "web"}
	workloadID := "ns/Deployment/web"
	restricted := m_buildManagedPolicy("ns", policyNameFor(schema.StateRestricted, workloadID), workloadID)
	reg := metricsRegistryForTest(t)
	cs := fake.NewSimpleClientset(
		runtime.Object(deployment("ns", "web", sel)),
		runtime.Object(restricted),
	)
	m, err := New(Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, cs, reg, discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Oracle knows nothing about this workload (empty map -> not-ok).
	m.SetStateOracle(fakeOracle{states: map[string]schema.PodSecurityState{}})
	ctx := context.Background()

	m.reconcileGC(ctx)

	if _, gerr := cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, restricted.Name, metav1.GetOptions{}); gerr != nil {
		t.Fatalf("policy for a not-ok workload with a live owner was wrongly deleted: %v", gerr)
	}
	if got := testutilToFloat(t, m, "removed"); got != 0 {
		t.Fatalf("apply_total{removed} = %v, want 0 for a not-ok live workload", got)
	}
	if got := testutilToFloat(t, m, "superseded"); got != 0 {
		t.Fatalf("apply_total{superseded} = %v, want 0 for a not-ok live workload", got)
	}
}

func TestReconcileGC_NotOkOrphanStillCollected(t *testing.T) {
	// BI-2c not-ok rule + orphan-GC authority: the FSM has no entry (not-ok) AND
	// the owner is gone. The orphan-GC pass (the sole authority for not-ok) reaps
	// the policy as gc_deleted.
	workloadID := "ns/Deployment/ghost"
	orphan := m_buildManagedPolicy("ns", policyNameFor(schema.StateRestricted, workloadID), workloadID)
	reg := metricsRegistryForTest(t)
	cs := fake.NewSimpleClientset(runtime.Object(orphan)) // no Deployment -> owner gone
	m, err := New(Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, cs, reg, discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.SetStateOracle(fakeOracle{states: map[string]schema.PodSecurityState{}})
	ctx := context.Background()

	m.reconcileGC(ctx)

	if _, gerr := cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, orphan.Name, metav1.GetOptions{}); !apierrors.IsNotFound(gerr) {
		t.Fatalf("not-ok orphan policy not collected by orphan GC: err=%v", gerr)
	}
	if got := testutilToFloat(t, m, "gc_deleted"); got != 1 {
		t.Fatalf("apply_total{gc_deleted} = %v, want 1", got)
	}
}

func TestReconcileGC_NilOraclePreservesShippedBehaviour(t *testing.T) {
	// With oracle == nil, the reconcile retains the shipped Story 2.5
	// "quarantine object wins" supersession: a RESTRICTED policy co-existing with
	// a QUARANTINED policy object is deleted as superseded, regardless of FSM.
	sel := map[string]string{"app": "web"}
	workloadID := "ns/Deployment/web"
	restricted := m_buildManagedPolicy("ns", policyNameFor(schema.StateRestricted, workloadID), workloadID)
	quarantine := m_buildManagedQuarantinePolicy("ns", policyNameFor(schema.StateQuarantined, workloadID), workloadID)
	reg := metricsRegistryForTest(t)
	cs := fake.NewSimpleClientset(
		runtime.Object(deployment("ns", "web", sel)),
		runtime.Object(restricted),
		runtime.Object(quarantine),
	)
	m, err := New(Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, cs, reg, discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// No oracle set: nil-oracle fallback path.
	ctx := context.Background()

	m.reconcileGC(ctx)

	if _, gerr := cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, restricted.Name, metav1.GetOptions{}); !apierrors.IsNotFound(gerr) {
		t.Fatalf("nil-oracle: superseded restricted not removed: err=%v", gerr)
	}
	if _, gerr := cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, quarantine.Name, metav1.GetOptions{}); gerr != nil {
		t.Fatalf("nil-oracle: quarantine wrongly removed: %v", gerr)
	}
	if got := testutilToFloat(t, m, "superseded"); got != 1 {
		t.Fatalf("nil-oracle apply_total{superseded} = %v, want 1", got)
	}
}
