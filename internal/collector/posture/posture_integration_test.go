//go:build integration

package posture_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/olokotoh/olaitan/internal/collector/posture"
	"github.com/olokotoh/olaitan/internal/schema"
)

// envtestState holds the package-shared envtest plumbing. We start
// kube-apiserver + etcd once in TestMain and reuse the rest.Config
// across all integration tests, mirroring Story 1.6's TestMain pattern
// at internal/collector/falco/falco_integration_test.go.
var envtestState struct {
	env *envtest.Environment
	cfg *rest.Config
	cs  *kubernetes.Clientset
	mu  sync.Mutex
}

func TestMain(m *testing.M) {
	// Locate the kube-apiserver/etcd binaries fetched by `make
	// envtest-bin`. The default path is bin/k8s/<version>-linux-amd64.
	// Operators can override via KUBEBUILDER_ASSETS for CI variants.
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		root, err := repoRoot()
		if err == nil {
			candidates, _ := filepath.Glob(filepath.Join(root, "bin", "k8s", "k8s", "*-linux-amd64"))
			if len(candidates) == 0 {
				candidates, _ = filepath.Glob(filepath.Join(root, "bin", "k8s", "*-linux-amd64"))
			}
			if len(candidates) > 0 {
				os.Setenv("KUBEBUILDER_ASSETS", candidates[0])
			}
		}
	}

	env := &envtest.Environment{}
	cfg, err := env.Start()
	if err != nil {
		// AC5 requires the integration suite to exercise a real
		// kube-apiserver. Exiting 0 here would let CI report green
		// while skipping every test, hiding regressions and silently
		// invalidating AC5's "real-boundary" guarantee.
		//
		// Two escape hatches are honoured:
		//
		//   POSTURE_INTEGRATION_SKIP=1  - explicit opt-out for
		//       sandboxes where envtest binaries cannot be made
		//       available (e.g., air-gapped review jobs). Operators
		//       must set this consciously so the missing coverage is
		//       a deliberate choice, not a silent skip.
		//
		//   POSTURE_INTEGRATION_REQUIRED=1 - explicit opt-in for CI
		//       jobs that promise envtest is wired up (so a
		//       misconfiguration surfaces as a non-zero exit rather
		//       than getting masked by the legacy permissive default).
		//
		// The default when neither is set is to skip with exit 0 to
		// preserve developer workflows that run `go test -tags=
		// integration` without first running `make envtest-bin`,
		// while still allowing CI to flip the contract via the
		// REQUIRED toggle once the workflow gains an envtest-bin
		// step.
		if os.Getenv("POSTURE_INTEGRATION_REQUIRED") == "1" {
			os.Stderr.WriteString("posture integration: envtest unavailable (POSTURE_INTEGRATION_REQUIRED=1, failing the run): " + err.Error() + "\n")
			os.Exit(1)
		}
		if os.Getenv("POSTURE_INTEGRATION_SKIP") == "1" {
			os.Stderr.WriteString("posture integration: envtest unavailable (POSTURE_INTEGRATION_SKIP=1, exiting 0): " + err.Error() + "\n")
			os.Exit(0)
		}
		os.Stderr.WriteString("posture integration: envtest unavailable: " + err.Error() + "\n")
		os.Stderr.WriteString("posture integration: set POSTURE_INTEGRATION_SKIP=1 to allow exit 0, or POSTURE_INTEGRATION_REQUIRED=1 to fail loudly. Exiting 0 for compatibility.\n")
		os.Exit(0)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		os.Stderr.WriteString("posture integration: clientset construction failed: " + err.Error() + "\n")
		_ = env.Stop()
		os.Exit(1)
	}
	envtestState.env = env
	envtestState.cfg = cfg
	envtestState.cs = cs

	code := m.Run()

	if err := env.Stop(); err != nil {
		os.Stderr.WriteString("posture integration: envtest.Stop failed: " + err.Error() + "\n")
	}
	os.Exit(code)
}

// repoRoot walks up from the cwd until it finds go.mod.
func repoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(wd, "go.mod")); err == nil {
			return wd, nil
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			return "", os.ErrNotExist
		}
		wd = parent
	}
}

func skipIfNoEnvtest(t *testing.T) {
	t.Helper()
	if envtestState.cs == nil {
		t.Skip("envtest binaries unavailable; skipping integration suite")
	}
}

// freshCounter monotonically tags every namespace produced by fresh
// so two tests running within the same nanosecond do not collide.
// (time.Now().UnixNano() is not unique enough on hosts where the
// monotonic clock has coarser-than-nanosecond resolution.)
var freshCounter atomic.Uint64

// fresh returns a clientset and a unique namespace for an integration
// test case, applying the namespace to envtest so test runs do not
// collide on resource names. The namespace name combines the caller-
// supplied prefix, a UnixNano-second tag, and a monotonic counter so
// rapid re-runs and parallel subtests do not collide.
func fresh(t *testing.T, name string) (kubernetes.Interface, string) {
	t.Helper()
	skipIfNoEnvtest(t)
	ns := fmt.Sprintf("%s-%d-%d", name, time.Now().UnixNano(), freshCounter.Add(1))
	_, err := envtestState.cs.CoreV1().Namespaces().Create(context.Background(), &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: ns},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create namespace %q: %v", ns, err)
	}
	t.Cleanup(func() {
		_ = envtestState.cs.CoreV1().Namespaces().Delete(context.Background(), ns, metav1.DeleteOptions{})
	})
	return envtestState.cs, ns
}

func boolPtrTest(b bool) *bool { return &b }

// installFixture populates the standard payments-app fixture used by
// the happy-path tests.
func installFixture(t *testing.T, cs kubernetes.Interface, ns string) *corev1.Pod {
	t.Helper()
	ctx := context.Background()

	_, err := cs.CoreV1().ServiceAccounts(ns).Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "payments-sa", Namespace: ns},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create SA: %v", err)
	}

	_, err = cs.AppsV1().Deployments(ns).Create(ctx, &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "payments", Namespace: ns, Labels: map[string]string{"app": "payments"}},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "payments"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "payments"}},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "api", Image: "scratch"}},
				},
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create Deployment: %v", err)
	}

	rs, err := cs.AppsV1().ReplicaSets(ns).Create(ctx, &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "payments-abc",
			Namespace: ns,
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "apps/v1", Kind: "Deployment", Name: "payments", Controller: boolPtrTest(true), UID: "dep-uid"},
			},
		},
		Spec: appsv1.ReplicaSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "payments"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "payments"}},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "api", Image: "scratch"}},
				},
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create ReplicaSet: %v", err)
	}

	runAsNonRoot := true
	allowEsc := false
	pod, err := cs.CoreV1().Pods(ns).Create(ctx, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "payments-abc-xyz",
			Namespace: ns,
			Labels:    map[string]string{"app": "payments"},
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "payments-abc", Controller: boolPtrTest(true), UID: rs.UID},
			},
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "payments-sa",
			SecurityContext:    &corev1.PodSecurityContext{RunAsNonRoot: &runAsNonRoot},
			Containers: []corev1.Container{
				{
					Name:            "api",
					Image:           "scratch",
					SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &allowEsc},
				},
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create Pod: %v", err)
	}

	_, err = cs.RbacV1().Roles(ns).Create(ctx, &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "payments-role", Namespace: ns},
		Rules: []rbacv1.PolicyRule{
			{Verbs: []string{"get", "list", "watch"}, APIGroups: []string{""}, Resources: []string{"secrets"}},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create Role: %v", err)
	}
	_, err = cs.RbacV1().RoleBindings(ns).Create(ctx, &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "payments-role-binding", Namespace: ns},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "payments-sa", Namespace: ns}},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "payments-role"},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create RoleBinding: %v", err)
	}

	_, err = cs.RbacV1().ClusterRoles().Create(ctx, &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "payments-cluster-role-" + ns},
		Rules: []rbacv1.PolicyRule{
			{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"nodes"}},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create ClusterRole: %v", err)
	}
	_, err = cs.RbacV1().ClusterRoleBindings().Create(ctx, &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "payments-cluster-role-binding-" + ns},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "payments-sa", Namespace: ns}},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "payments-cluster-role-" + ns},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create ClusterRoleBinding: %v", err)
	}
	t.Cleanup(func() {
		_ = cs.RbacV1().ClusterRoles().Delete(context.Background(), "payments-cluster-role-"+ns, metav1.DeleteOptions{})
		_ = cs.RbacV1().ClusterRoleBindings().Delete(context.Background(), "payments-cluster-role-binding-"+ns, metav1.DeleteOptions{})
	})

	_, err = cs.NetworkingV1().NetworkPolicies(ns).Create(ctx, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "payments-allow-frontend", Namespace: ns},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "payments"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress:     []networkingv1.NetworkPolicyIngressRule{{}},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create matching NetworkPolicy: %v", err)
	}
	_, err = cs.NetworkingV1().NetworkPolicies(ns).Create(ctx, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: ns},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "backend"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create unrelated NetworkPolicy: %v", err)
	}

	return pod
}

func defaultCfgWithClock(now time.Time) posture.Config {
	cfg := posture.DefaultConfig()
	cfg.NowFn = func() time.Time { return now }
	return cfg
}

func TestIntegration_PostureHappyPath(t *testing.T) {
	cs, ns := fresh(t, "happy")
	pod := installFixture(t, cs, ns)

	c, err := posture.New(defaultCfgWithClock(time.Now()), cs, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got, err := c.Get(context.Background(), pod)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Identity.OwnerKind != "Deployment" || got.Identity.OwnerName != "payments" {
		t.Errorf("Identity: got %+v, want Deployment/payments", got.Identity)
	}
	if got.ServiceAccount != "payments-sa" {
		t.Errorf("ServiceAccount: got %q, want payments-sa", got.ServiceAccount)
	}
	if len(got.RoleBindings) != 1 || got.RoleBindings[0].Name != "payments-role-binding" {
		t.Errorf("RoleBindings: got %+v, want only payments-role-binding", got.RoleBindings)
	}
	if len(got.ClusterRoleBindings) != 1 {
		t.Errorf("ClusterRoleBindings: got %+v, want 1", got.ClusterRoleBindings)
	}
	if len(got.NetworkPolicies) != 1 || got.NetworkPolicies[0].Name != "payments-allow-frontend" {
		t.Errorf("NetworkPolicies: got %+v, want only payments-allow-frontend", got.NetworkPolicies)
	}
	if got.PodSecurityContext == nil || got.PodSecurityContext.RunAsNonRoot == nil || !*got.PodSecurityContext.RunAsNonRoot {
		t.Errorf("PodSecurityContext.RunAsNonRoot: got %+v", got.PodSecurityContext)
	}
	if len(got.ContainerSecurityContexts) != 1 {
		t.Fatalf("ContainerSecurityContexts: got %d, want 1", len(got.ContainerSecurityContexts))
	}
	if got.Unavailable || got.OrphanPod {
		t.Errorf("flags: got Unavailable=%v OrphanPod=%v, want both false", got.Unavailable, got.OrphanPod)
	}
}

func TestIntegration_OrphanPodFallback(t *testing.T) {
	cs, ns := fresh(t, "orphan")
	ctx := context.Background()
	orphan, err := cs.CoreV1().Pods(ns).Create(ctx, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "orphan-pod", Namespace: ns},
		Spec: corev1.PodSpec{
			ServiceAccountName: "default",
			Containers:         []corev1.Container{{Name: "ad-hoc", Image: "scratch"}},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create orphan Pod: %v", err)
	}

	c, err := posture.New(defaultCfgWithClock(time.Now()), cs, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got, err := c.Get(ctx, orphan)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.OrphanPod || got.Identity.OwnerKind != "Pod" || got.Identity.OwnerName != "orphan-pod" {
		t.Errorf("orphan identity: got %+v, want Pod/orphan-pod OrphanPod=true", got.Identity)
	}
	if got.Identity.PodName != "orphan-pod" {
		t.Errorf("PodName: got %q, want orphan-pod", got.Identity.PodName)
	}
}

func TestIntegration_CacheHitOnSecondCall(t *testing.T) {
	cs, ns := fresh(t, "cachehit")
	pod := installFixture(t, cs, ns)

	c, err := posture.New(defaultCfgWithClock(time.Now()), cs, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i := 0; i < 2; i++ {
		if _, err := c.Get(context.Background(), pod); err != nil {
			t.Fatalf("Get %d: %v", i, err)
		}
	}
	if c.PostureCacheHits() != 1 {
		t.Errorf("PostureCacheHits: got %d, want 1", c.PostureCacheHits())
	}
}

func TestIntegration_CacheMissAfterTTL(t *testing.T) {
	cs, ns := fresh(t, "ttlmiss")
	pod := installFixture(t, cs, ns)

	t0 := time.Now()
	cur := t0
	cfg := posture.DefaultConfig()
	cfg.NowFn = func() time.Time { return cur }

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
	if c.PostureCacheHits() != 0 || c.PostureCacheMisses() != 2 {
		t.Errorf("counters: hits=%d misses=%d, want 0 hits + 2 misses", c.PostureCacheHits(), c.PostureCacheMisses())
	}
}

func TestIntegration_BypassCacheOption(t *testing.T) {
	cs, ns := fresh(t, "bypass")
	pod := installFixture(t, cs, ns)

	c, err := posture.New(defaultCfgWithClock(time.Now()), cs, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := c.Get(context.Background(), pod); err != nil {
		t.Fatalf("first Get: %v", err)
	}
	if _, err := c.Get(context.Background(), pod, posture.WithBypassCache()); err != nil {
		t.Fatalf("bypass Get: %v", err)
	}
	if c.PostureCacheHits() != 0 {
		t.Errorf("PostureCacheHits: got %d, want 0 (bypass skips cache)", c.PostureCacheHits())
	}
}

func TestIntegration_NetworkPolicyMatchExpressions(t *testing.T) {
	cs, ns := fresh(t, "matchexpr")
	pod := installFixture(t, cs, ns)

	_, err := cs.NetworkingV1().NetworkPolicies(ns).Create(context.Background(), &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "expr-policy", Namespace: ns},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "app", Operator: metav1.LabelSelectorOpIn, Values: []string{"payments", "payments-canary"}},
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create expr policy: %v", err)
	}

	c, err := posture.New(defaultCfgWithClock(time.Now()), cs, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := c.Get(context.Background(), pod)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	var foundExpr, foundMatch bool
	for _, np := range got.NetworkPolicies {
		if np.Name == "expr-policy" {
			foundExpr = true
		}
		if np.Name == "payments-allow-frontend" {
			foundMatch = true
		}
	}
	if !foundExpr || !foundMatch {
		t.Errorf("NetworkPolicies: got %+v, want both expr-policy and payments-allow-frontend", got.NetworkPolicies)
	}
}

func TestIntegration_StatefulSetLineage(t *testing.T) {
	cs, ns := fresh(t, "sts")
	ctx := context.Background()

	_, err := cs.AppsV1().StatefulSets(ns).Create(ctx, &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: "kafka", Namespace: ns},
		Spec: appsv1.StatefulSetSpec{
			ServiceName: "kafka",
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "kafka"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "kafka"}},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "broker", Image: "scratch"}},
				},
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create StatefulSet: %v", err)
	}

	pod, err := cs.CoreV1().Pods(ns).Create(ctx, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kafka-0",
			Namespace: ns,
			Labels:    map[string]string{"app": "kafka"},
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "apps/v1", Kind: "StatefulSet", Name: "kafka", Controller: boolPtrTest(true), UID: "sts-uid"},
			},
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "default",
			Containers:         []corev1.Container{{Name: "broker", Image: "scratch"}},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create Pod: %v", err)
	}

	c, err := posture.New(defaultCfgWithClock(time.Now()), cs, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := c.Get(ctx, pod)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Identity.OwnerKind != "StatefulSet" || got.Identity.OwnerName != "kafka" {
		t.Errorf("Identity: got %+v, want StatefulSet/kafka", got.Identity)
	}
}

func TestIntegration_CronJobLineage(t *testing.T) {
	cs, ns := fresh(t, "cron")
	ctx := context.Background()

	_, err := cs.BatchV1().CronJobs(ns).Create(ctx, &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{Name: "nightly", Namespace: ns},
		Spec: batchv1.CronJobSpec{
			Schedule: "0 0 * * *",
			JobTemplate: batchv1.JobTemplateSpec{
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							RestartPolicy: corev1.RestartPolicyOnFailure,
							Containers:    []corev1.Container{{Name: "task", Image: "scratch"}},
						},
					},
				},
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create CronJob: %v", err)
	}

	job, err := cs.BatchV1().Jobs(ns).Create(ctx, &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nightly-12345",
			Namespace: ns,
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "batch/v1", Kind: "CronJob", Name: "nightly", Controller: boolPtrTest(true), UID: "cj-uid"},
			},
		},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyOnFailure,
					Containers:    []corev1.Container{{Name: "task", Image: "scratch"}},
				},
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create Job: %v", err)
	}

	pod, err := cs.CoreV1().Pods(ns).Create(ctx, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nightly-12345-abc",
			Namespace: ns,
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "batch/v1", Kind: "Job", Name: "nightly-12345", Controller: boolPtrTest(true), UID: job.UID},
			},
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "default",
			Containers:         []corev1.Container{{Name: "task", Image: "scratch"}},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create Pod: %v", err)
	}

	c, err := posture.New(defaultCfgWithClock(time.Now()), cs, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := c.Get(ctx, pod)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Identity.OwnerKind != "CronJob" || got.Identity.OwnerName != "nightly" {
		t.Errorf("Identity: got %+v, want CronJob/nightly", got.Identity)
	}
}

func TestIntegration_UnavailableReasonStaysClassedNotRaw(t *testing.T) {
	cs, ns := fresh(t, "redact")
	pod := installFixture(t, cs, ns)

	// Cancel the context to force a transient deadline.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c, err := posture.New(defaultCfgWithClock(time.Now()), cs, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, _ := c.Get(ctx, pod)
	if got == nil {
		t.Fatalf("Get returned nil posture under cancellation; expected partial struct")
	}
	if !got.Unavailable {
		t.Errorf("Unavailable: got false, want true")
	}
	if got.UnavailableReason != schema.PostureUnavailableTransient {
		t.Errorf("UnavailableReason: got %q, want %q", got.UnavailableReason, schema.PostureUnavailableTransient)
	}
	// The reason must be exactly one of the four classes (no
	// substring of the underlying error). Guard against any future
	// refactor that accidentally pipes err.Error() through.
	switch got.UnavailableReason {
	case schema.PostureUnavailableTransient,
		schema.PostureUnavailablePermissionDenied,
		schema.PostureUnavailableNotFound,
		schema.PostureUnavailablePermanent:
		// fine
	default:
		t.Errorf("UnavailableReason %q is not a classified value", got.UnavailableReason)
	}
}
