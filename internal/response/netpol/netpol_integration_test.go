//go:build integration

package netpol

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// envtestState holds the package-shared envtest plumbing, started once in
// TestMain and reused across the integration suite (AC5). Mirrors the
// Story 1.11 posture integration TestMain pattern.
var envtestState struct {
	env *envtest.Environment
	cfg *rest.Config
	cs  *kubernetes.Clientset
}

func TestMain(m *testing.M) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		if root, err := repoRoot(); err == nil {
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
		// AC5 requires a real kube-apiserver. The default behaviour is to
		// skip (exit 0) so a developer without envtest binaries is not
		// blocked, while CI can flip the contract:
		//   NETPOL_INTEGRATION_REQUIRED=1 -> fail loudly on missing envtest.
		//   NETPOL_INTEGRATION_SKIP=1     -> explicit opt-out, exit 0.
		if os.Getenv("NETPOL_INTEGRATION_REQUIRED") == "1" {
			os.Stderr.WriteString("netpol integration: envtest unavailable (NETPOL_INTEGRATION_REQUIRED=1, failing): " + err.Error() + "\n")
			os.Exit(1)
		}
		os.Stderr.WriteString("netpol integration: envtest unavailable; exiting 0 (set NETPOL_INTEGRATION_REQUIRED=1 to fail loudly): " + err.Error() + "\n")
		os.Exit(0)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		os.Stderr.WriteString("netpol integration: clientset construction failed: " + err.Error() + "\n")
		_ = env.Stop()
		os.Exit(1)
	}
	envtestState.env = env
	envtestState.cfg = cfg
	envtestState.cs = cs

	code := m.Run()

	if err := env.Stop(); err != nil {
		os.Stderr.WriteString("netpol integration: envtest.Stop failed: " + err.Error() + "\n")
	}
	os.Exit(code)
}

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

var nsCounter atomic.Uint64

func freshNamespace(t *testing.T) string {
	t.Helper()
	if envtestState.cs == nil {
		t.Skip("envtest binaries unavailable; skipping integration suite")
	}
	ns := fmt.Sprintf("netpol-it-%d-%d", time.Now().UnixNano(), nsCounter.Add(1))
	if _, err := envtestState.cs.CoreV1().Namespaces().Create(context.Background(), &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: ns},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create namespace %q: %v", ns, err)
	}
	t.Cleanup(func() {
		_ = envtestState.cs.CoreV1().Namespaces().Delete(context.Background(), ns, metav1.DeleteOptions{})
	})
	return ns
}

// TestIntegration_ApplyIdempotentReapplyAndOrphanGC exercises the three AC5
// behaviours against a real kube-apiserver: policy application with the
// correct selector/egress/labels/annotations, idempotent re-apply (no
// spurious Update), and orphan garbage collection after the workload owner
// is deleted.
func TestIntegration_ApplyIdempotentReapplyAndOrphanGC(t *testing.T) {
	ns := freshNamespace(t)
	cs := envtestState.cs
	ctx := context.Background()
	sel := map[string]string{"app": "web"}

	if _, err := cs.AppsV1().Deployments(ns).Create(ctx, &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "web"},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: sel},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: sel},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "busybox"}}},
			},
		},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create deployment: %v", err)
	}

	m, err := New(Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, cs, nil, discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	workloadID := ns + "/Deployment/web"
	st := restrictedTransition(workloadID, "pkg-1")
	ref := workloadRef{namespace: ns, ownerKind: "Deployment", ownerName: "web"}

	// (a) Apply against the real API.
	m.handle(ctx, st)
	name := PolicyName(workloadID)
	got, err := cs.NetworkingV1().NetworkPolicies(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("policy not applied: %v", err)
	}
	if got.Labels[LabelManagedBy] != ManagedByValue {
		t.Fatalf("missing managed-by label: %v", got.Labels)
	}
	if got.Annotations[AnnFSMState] != "RESTRICTED" || got.Annotations[AnnPackageID] != "pkg-1" {
		t.Fatalf("annotations wrong: %v", got.Annotations)
	}
	if len(got.Spec.PolicyTypes) != 1 || got.Spec.PolicyTypes[0] != networkingv1.PolicyTypeEgress {
		t.Fatalf("policyTypes = %v", got.Spec.PolicyTypes)
	}
	if got.Spec.PodSelector.MatchLabels["app"] != "web" {
		t.Fatalf("podSelector = %v", got.Spec.PodSelector)
	}
	rv := got.ResourceVersion

	// (b) Idempotent re-apply: a fresh identical desired state must be a
	// no-op (no Update, so the resourceVersion is unchanged).
	np := m.buildPolicy(ref, &metav1.LabelSelector{MatchLabels: sel}, st)
	result, err := m.apply(ctx, np)
	if err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	if result != "noop" {
		t.Fatalf("re-apply result = %q, want noop", result)
	}
	after, err := cs.NetworkingV1().NetworkPolicies(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get after re-apply: %v", err)
	}
	if after.ResourceVersion != rv {
		t.Fatalf("idempotent re-apply mutated the object: rv %q -> %q", rv, after.ResourceVersion)
	}

	// (c) Orphan GC: delete the workload owner, reconcile, policy is removed.
	if err := cs.AppsV1().Deployments(ns).Delete(ctx, "web", metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete deployment: %v", err)
	}
	m.reconcileGC(ctx)
	if _, err := cs.NetworkingV1().NetworkPolicies(ns).Get(ctx, name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("orphan policy not garbage-collected: err=%v", err)
	}
}
