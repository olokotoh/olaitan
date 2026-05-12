package posture_test

import (
	"context"
	"errors"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	gvkschema "k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/olokotoh/olaitan/internal/collector/posture"
	olaitanschema "github.com/olokotoh/olaitan/internal/schema"
)

func boolPtrLocal(b bool) *bool { return &b }

func defaultCfg(now time.Time) posture.Config {
	cfg := posture.DefaultConfig()
	cfg.NowFn = func() time.Time { return now }
	return cfg
}

func samplePod() *corev1.Pod {
	runAsNonRoot := true
	allowEsc := false
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "payments-api-abc-xyz",
			Namespace: "payments",
			Labels:    map[string]string{"app": "payments-api"},
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "ReplicaSet", Name: "payments-api-abc", Controller: boolPtrLocal(true)},
			},
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "payments-sa",
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot: &runAsNonRoot,
			},
			Containers: []corev1.Container{
				{
					Name: "api",
					SecurityContext: &corev1.SecurityContext{
						AllowPrivilegeEscalation: &allowEsc,
					},
				},
			},
		},
	}
}

func TestNew_RejectsZeroCacheTTL(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cfg := posture.DefaultConfig()
	cfg.CacheTTL = 0
	_, err := posture.New(cfg, cs, nil)
	if err == nil {
		t.Fatalf("expected error for cache_ttl=0")
	}
}

func TestNew_RejectsCacheTTLAboveCeiling(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cfg := posture.DefaultConfig()
	cfg.CacheTTL = 90 * time.Second
	_, err := posture.New(cfg, cs, nil)
	if err == nil {
		t.Fatalf("expected error for cache_ttl above MaxCacheTTL")
	}
}

func TestNew_RejectsZeroFetchTimeout(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cfg := posture.DefaultConfig()
	cfg.FetchTimeout = 0
	_, err := posture.New(cfg, cs, nil)
	if err == nil {
		t.Fatalf("expected error for fetch_timeout=0")
	}
}

func TestNew_RejectsNilClientset(t *testing.T) {
	_, err := posture.New(posture.DefaultConfig(), nil, nil)
	if err == nil {
		t.Fatalf("expected error for nil clientset")
	}
}

func TestGet_HappyPathPopulatesIdentityAndSecurityContext(t *testing.T) {
	t0 := time.Date(2026, 5, 12, 22, 0, 0, 0, time.UTC)
	pod := samplePod()
	cs := fake.NewSimpleClientset(
		// Owner ReplicaSet -> Deployment chain.
		newReplicaSetOwnedByDeployment("payments-api-abc", "payments", "payments-api"),
	)

	c, err := posture.New(defaultCfg(t0), cs, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got, err := c.Get(context.Background(), pod)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Identity.OwnerKind != "Deployment" || got.Identity.OwnerName != "payments-api" {
		t.Errorf("Identity: got %+v, want Deployment/payments-api", got.Identity)
	}
	if got.ServiceAccount != "payments-sa" {
		t.Errorf("ServiceAccount: got %q, want payments-sa", got.ServiceAccount)
	}
	if got.PodSecurityContext == nil || got.PodSecurityContext.RunAsNonRoot == nil || !*got.PodSecurityContext.RunAsNonRoot {
		t.Errorf("PodSecurityContext.RunAsNonRoot: got %+v, want non-nil true", got.PodSecurityContext)
	}
	if len(got.ContainerSecurityContexts) != 1 {
		t.Fatalf("ContainerSecurityContexts: got %d, want 1", len(got.ContainerSecurityContexts))
	}
	if got.ContainerSecurityContexts[0].Kind != olaitanschema.ContainerKindRegular {
		t.Errorf("Container kind: got %q, want regular", got.ContainerSecurityContexts[0].Kind)
	}
	if got.Unavailable {
		t.Errorf("Unavailable: got true, want false")
	}
}

func TestGet_OrphanPodMarksOrphanAndCachesUnderFallbackKey(t *testing.T) {
	t0 := time.Date(2026, 5, 12, 22, 0, 0, 0, time.UTC)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "ad-hoc", Namespace: "scratch"},
		Spec:       corev1.PodSpec{ServiceAccountName: "default"},
	}
	cs := fake.NewSimpleClientset()
	c, err := posture.New(defaultCfg(t0), cs, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got, err := c.Get(context.Background(), pod)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.OrphanPod || got.Identity.OwnerKind != "Pod" {
		t.Errorf("OrphanPod fallback: got %+v, want Pod kind + OrphanPod=true", got.Identity)
	}
	if c.PostureOrphanPods() != 1 {
		t.Errorf("PostureOrphanPods: got %d, want 1", c.PostureOrphanPods())
	}
}

func TestGet_CacheHitOnSecondCall(t *testing.T) {
	t0 := time.Date(2026, 5, 12, 22, 0, 0, 0, time.UTC)
	pod := samplePod()
	cs := fake.NewSimpleClientset(newReplicaSetOwnedByDeployment("payments-api-abc", "payments", "payments-api"))
	c, err := posture.New(defaultCfg(t0), cs, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := c.Get(context.Background(), pod); err != nil {
		t.Fatalf("first Get: %v", err)
	}
	if _, err := c.Get(context.Background(), pod); err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if c.PostureCacheHits() != 1 {
		t.Errorf("PostureCacheHits: got %d, want 1", c.PostureCacheHits())
	}
	if c.PostureCacheMisses() != 1 {
		t.Errorf("PostureCacheMisses: got %d, want 1", c.PostureCacheMisses())
	}
}

func TestGet_CacheMissAfterTTL(t *testing.T) {
	t0 := time.Date(2026, 5, 12, 22, 0, 0, 0, time.UTC)
	cur := t0
	cfg := posture.DefaultConfig()
	cfg.NowFn = func() time.Time { return cur }
	pod := samplePod()
	cs := fake.NewSimpleClientset(newReplicaSetOwnedByDeployment("payments-api-abc", "payments", "payments-api"))
	c, err := posture.New(cfg, cs, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Get(context.Background(), pod); err != nil {
		t.Fatalf("first Get: %v", err)
	}
	cur = t0.Add(61 * time.Second)
	if _, err := c.Get(context.Background(), pod); err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if c.PostureCacheHits() != 0 {
		t.Errorf("PostureCacheHits: got %d, want 0 (both calls miss after TTL)", c.PostureCacheHits())
	}
	if c.PostureCacheMisses() != 2 {
		t.Errorf("PostureCacheMisses: got %d, want 2", c.PostureCacheMisses())
	}
}

func TestGet_BypassCacheForcesRefetch(t *testing.T) {
	t0 := time.Date(2026, 5, 12, 22, 0, 0, 0, time.UTC)
	pod := samplePod()
	cs := fake.NewSimpleClientset(newReplicaSetOwnedByDeployment("payments-api-abc", "payments", "payments-api"))
	c, err := posture.New(defaultCfg(t0), cs, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Get(context.Background(), pod); err != nil {
		t.Fatalf("first Get: %v", err)
	}
	if _, err := c.Get(context.Background(), pod, posture.WithBypassCache()); err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if c.PostureCacheHits() != 0 {
		t.Errorf("PostureCacheHits: got %d, want 0 (bypass skips cache)", c.PostureCacheHits())
	}
	if c.PostureCacheMisses() != 2 {
		t.Errorf("PostureCacheMisses: got %d, want 2", c.PostureCacheMisses())
	}
}

func TestGet_FetchErrorMarksUnavailableTransient(t *testing.T) {
	t0 := time.Date(2026, 5, 12, 22, 0, 0, 0, time.UTC)
	pod := samplePod()
	cs := fake.NewSimpleClientset(newReplicaSetOwnedByDeployment("payments-api-abc", "payments", "payments-api"))
	// Inject a transient error on RoleBindings list.
	cs.PrependReactor("list", "rolebindings", func(_ k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewServiceUnavailable("simulated apiserver outage")
	})

	c, err := posture.New(defaultCfg(t0), cs, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got, err := c.Get(context.Background(), pod)
	if err == nil {
		t.Fatalf("expected error from Get under transient outage")
	}
	if !got.Unavailable {
		t.Errorf("Unavailable: got false, want true")
	}
	if got.UnavailableReason != olaitanschema.PostureUnavailableTransient {
		t.Errorf("UnavailableReason: got %q, want %q", got.UnavailableReason, olaitanschema.PostureUnavailableTransient)
	}
	if c.PostureUnavailable() != 1 {
		t.Errorf("PostureUnavailable: got %d, want 1", c.PostureUnavailable())
	}
}

func TestGet_PermissionDeniedClassifiedCorrectly(t *testing.T) {
	t0 := time.Date(2026, 5, 12, 22, 0, 0, 0, time.UTC)
	pod := samplePod()
	cs := fake.NewSimpleClientset(newReplicaSetOwnedByDeployment("payments-api-abc", "payments", "payments-api"))
	cs.PrependReactor("list", "clusterrolebindings", func(_ k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(gvkschema.GroupResource{Resource: "clusterrolebindings"}, "any", errors.New("rbac denial"))
	})

	c, err := posture.New(defaultCfg(t0), cs, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got, err := c.Get(context.Background(), pod)
	if err == nil {
		t.Fatalf("expected error from Get under rbac denial")
	}
	if got.UnavailableReason != olaitanschema.PostureUnavailablePermissionDenied {
		t.Errorf("UnavailableReason: got %q, want permission_denied", got.UnavailableReason)
	}
}

func TestGet_NetworkPoliciesMatchedAndSummarised(t *testing.T) {
	t0 := time.Date(2026, 5, 12, 22, 0, 0, 0, time.UTC)
	pod := samplePod()

	matching := networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-frontend", Namespace: "payments"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "payments-api"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress:     []networkingv1.NetworkPolicyIngressRule{{}, {}}, // 2 ingress rules
		},
	}
	other := networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: "payments"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "backend"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		},
	}
	cs := fake.NewSimpleClientset(
		newReplicaSetOwnedByDeployment("payments-api-abc", "payments", "payments-api"),
		&matching, &other,
	)

	c, err := posture.New(defaultCfg(t0), cs, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got, err := c.Get(context.Background(), pod)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.NetworkPolicies) != 1 {
		t.Fatalf("NetworkPolicies: got %d, want 1", len(got.NetworkPolicies))
	}
	if got.NetworkPolicies[0].Name != "allow-frontend" {
		t.Errorf("NetworkPolicy name: got %q, want allow-frontend", got.NetworkPolicies[0].Name)
	}
	if got.NetworkPolicies[0].IngressRules != 2 {
		t.Errorf("IngressRules: got %d, want 2", got.NetworkPolicies[0].IngressRules)
	}
}

func TestGet_RoleBindingsAndClusterRoleBindingsMatchByServiceAccount(t *testing.T) {
	t0 := time.Date(2026, 5, 12, 22, 0, 0, 0, time.UTC)
	pod := samplePod()

	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "payments-role", Namespace: "payments"},
		Rules: []rbacv1.PolicyRule{
			{Verbs: []string{"get", "list", "watch"}, Resources: []string{"secrets"}},
		},
	}
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "payments-rb", Namespace: "payments"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "payments-sa", Namespace: "payments"}},
		RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "payments-role"},
	}
	clusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "node-reader"},
		Rules: []rbacv1.PolicyRule{
			{Verbs: []string{"get"}, Resources: []string{"nodes"}},
		},
	}
	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "payments-crb"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "payments-sa", Namespace: "payments"}},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "node-reader"},
	}
	unrelated := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "other-rb", Namespace: "payments"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "default", Namespace: "payments"}},
		RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "payments-role"},
	}

	cs := fake.NewSimpleClientset(
		newReplicaSetOwnedByDeployment("payments-api-abc", "payments", "payments-api"),
		role, rb, clusterRole, crb, unrelated,
	)

	c, err := posture.New(defaultCfg(t0), cs, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got, err := c.Get(context.Background(), pod)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.RoleBindings) != 1 || got.RoleBindings[0].Name != "payments-rb" {
		t.Errorf("RoleBindings: got %+v, want only payments-rb", got.RoleBindings)
	}
	if got.RoleBindings[0].RoleKind != "Role" {
		t.Errorf("RoleBindings[0].RoleKind: got %q, want Role", got.RoleBindings[0].RoleKind)
	}
	if len(got.RoleBindings[0].Verbs) != 3 {
		t.Errorf("RoleBindings[0].Verbs: got %v, want 3 entries", got.RoleBindings[0].Verbs)
	}
	if len(got.ClusterRoleBindings) != 1 || got.ClusterRoleBindings[0].Name != "payments-crb" {
		t.Errorf("ClusterRoleBindings: got %+v, want only payments-crb", got.ClusterRoleBindings)
	}
}

func TestGet_NilPodReturnsError(t *testing.T) {
	t0 := time.Date(2026, 5, 12, 22, 0, 0, 0, time.UTC)
	cs := fake.NewSimpleClientset()
	c, err := posture.New(defaultCfg(t0), cs, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Get(context.Background(), nil); err == nil {
		t.Fatalf("expected error for nil pod")
	}
}

// newReplicaSetOwnedByDeployment is a small fixture helper.
func newReplicaSetOwnedByDeployment(rsName, namespace, deploymentName string) runtime.Object {
	ctrl := true
	return &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      rsName,
			Namespace: namespace,
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "Deployment", Name: deploymentName, Controller: &ctrl},
			},
		},
	}
}
