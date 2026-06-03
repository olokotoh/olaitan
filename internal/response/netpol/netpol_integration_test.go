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

	"github.com/olokotoh/olaitan/internal/schema"
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
	// Explicit opt-out: skip the envtest-backed suite without even attempting
	// to locate or start a kube-apiserver. Mirrors the documented contract in
	// the env.Start() failure branch below.
	if os.Getenv("NETPOL_INTEGRATION_SKIP") == "1" {
		os.Stderr.WriteString("netpol integration: NETPOL_INTEGRATION_SKIP=1, skipping (exit 0)\n")
		os.Exit(0)
	}

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

// TestIntegration_RestrictedToQuarantineAtomicReplacement exercises the
// Story 2.5 RESTRICTED->QUARANTINED transition against a real kube-apiserver
// (AC5): the deny-all quarantine policy is applied with the correct
// policyTypes/labels/annotation/selector, the previous RESTRICTED policy is
// removed cleanly (apply-before-delete), the QUARANTINED re-apply is an
// idempotent no-op, and the unchanged orphan GC collects the quarantine policy
// once its owner is deleted (BI-8).
func TestIntegration_RestrictedToQuarantineAtomicReplacement(t *testing.T) {
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
	ref := workloadRef{namespace: ns, ownerKind: "Deployment", ownerName: "web"}
	restrictedName := PolicyName(workloadID)
	quarantineName := policyNameFor(schema.StateQuarantined, workloadID)

	// (1) RESTRICTED first: the egress-only policy exists.
	m.handle(ctx, restrictedTransition(workloadID, "pkg-1"))
	r, err := cs.NetworkingV1().NetworkPolicies(ns).Get(ctx, restrictedName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("restricted policy not applied: %v", err)
	}
	if len(r.Spec.PolicyTypes) != 1 || r.Spec.PolicyTypes[0] != networkingv1.PolicyTypeEgress {
		t.Fatalf("restricted policyTypes = %v, want [Egress]", r.Spec.PolicyTypes)
	}

	// (2) QUARANTINED: deny-all applied, restricted removed cleanly.
	m.handle(ctx, quarantinedTransition(workloadID, "pkg-2"))

	q, err := cs.NetworkingV1().NetworkPolicies(ns).Get(ctx, quarantineName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("quarantine policy not applied: %v", err)
	}
	if q.Labels[LabelManagedBy] != ManagedByValue {
		t.Fatalf("quarantine policy missing managed-by label: %v", q.Labels)
	}
	if q.Annotations[AnnFSMState] != "QUARANTINED" {
		t.Fatalf("quarantine fsm-state annotation = %q, want QUARANTINED", q.Annotations[AnnFSMState])
	}
	if len(q.Spec.PolicyTypes) != 2 {
		t.Fatalf("quarantine policyTypes = %v, want [Ingress, Egress]", q.Spec.PolicyTypes)
	}
	if len(q.Spec.Ingress) != 0 || len(q.Spec.Egress) != 0 {
		t.Fatalf("quarantine deny-all has rules: ingress=%v egress=%v", q.Spec.Ingress, q.Spec.Egress)
	}
	if q.Spec.PodSelector.MatchLabels["app"] != "web" {
		t.Fatalf("quarantine podSelector = %v", q.Spec.PodSelector)
	}
	// Previous RESTRICTED policy is removed cleanly (AC2/AC5).
	if _, err := cs.NetworkingV1().NetworkPolicies(ns).Get(ctx, restrictedName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("restricted policy not removed after quarantine: err=%v", err)
	}
	qrv := q.ResourceVersion

	// (3) Idempotent QUARANTINED re-apply: a fresh identical desired state is a
	// no-op and leaves the quarantine policy's resourceVersion unchanged.
	np := m.buildPolicy(ref, &metav1.LabelSelector{MatchLabels: sel}, quarantinedTransition(workloadID, "pkg-2"))
	result, err := m.apply(ctx, np)
	if err != nil {
		t.Fatalf("quarantine re-apply: %v", err)
	}
	if result != "noop" {
		t.Fatalf("quarantine re-apply result = %q, want noop", result)
	}
	after, err := cs.NetworkingV1().NetworkPolicies(ns).Get(ctx, quarantineName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get after quarantine re-apply: %v", err)
	}
	if after.ResourceVersion != qrv {
		t.Fatalf("idempotent quarantine re-apply mutated the object: rv %q -> %q", qrv, after.ResourceVersion)
	}

	// (4) Orphan GC (BI-8): delete the owner, reconcile, quarantine policy is
	// collected by the unchanged managed-by GC selector.
	if err := cs.AppsV1().Deployments(ns).Delete(ctx, "web", metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete deployment: %v", err)
	}
	m.reconcileGC(ctx)
	if _, err := cs.NetworkingV1().NetworkPolicies(ns).Get(ctx, quarantineName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("orphan quarantine policy not garbage-collected: err=%v", err)
	}
}

// itOracle is an envtest-side fake StateOracle for the de-escalation-residue
// reconcile assertions (Story 2.6, BI-2c).
type itOracle struct {
	states map[string]schema.PodSecurityState
}

func (o itOracle) CurrentState(workloadID string) (schema.PodSecurityState, bool) {
	s, ok := o.states[workloadID]
	return s, ok
}

func itCreateDeployment(t *testing.T, ns, name string, sel map[string]string) {
	t.Helper()
	if _, err := envtestState.cs.AppsV1().Deployments(ns).Create(context.Background(), &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: sel},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: sel},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "busybox"}}},
			},
		},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create deployment %q: %v", name, err)
	}
}

// TestIntegration_DeescalationLifecycle exercises the full Story 2.6
// de-escalation lifecycle QUARANTINED -> RESTRICTED -> SUSPICIOUS -> CLEAN
// against a real kube-apiserver (AC4). It asserts the managed-policy set at each
// step: QUARANTINED present alone (the Story 2.5 state), then RESTRICTED applied
// and QUARANTINED removed (AC1 atomic relaxation, restricted asserted present
// BEFORE quarantine absent), then both removed at SUSPICIOUS (AC2), then both
// absent and the absence observable via a follow-up read at CLEAN (AC3).
func TestIntegration_DeescalationLifecycle(t *testing.T) {
	ns := freshNamespace(t)
	cs := envtestState.cs
	ctx := context.Background()
	sel := map[string]string{"app": "web"}
	itCreateDeployment(t, ns, "web", sel)

	m, err := New(Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, cs, nil, discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	workloadID := ns + "/Deployment/web"
	restrictedName := PolicyName(workloadID)
	quarantineName := policyNameFor(schema.StateQuarantined, workloadID)

	// (1) QUARANTINED: deny-all present, restricted absent (Story 2.5 state).
	m.handle(ctx, quarantinedTransition(workloadID, "pkg-q"))
	q, err := cs.NetworkingV1().NetworkPolicies(ns).Get(ctx, quarantineName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("quarantine policy not applied: %v", err)
	}
	if len(q.Spec.PolicyTypes) != 2 {
		t.Fatalf("quarantine policyTypes = %v, want [Ingress, Egress]", q.Spec.PolicyTypes)
	}
	if _, err := cs.NetworkingV1().NetworkPolicies(ns).Get(ctx, restrictedName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("restricted policy unexpectedly present at QUARANTINED: err=%v", err)
	}

	// (2) RESTRICTED (AC1 atomic relaxation): restricted applied, quarantine
	// removed. Assert restricted present BEFORE asserting quarantine absent (the
	// apply-before-delete causal order; no policy-less window).
	m.handle(ctx, restrictedTransition(workloadID, "pkg-r"))
	r, err := cs.NetworkingV1().NetworkPolicies(ns).Get(ctx, restrictedName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("restricted policy not applied on de-escalation: %v", err)
	}
	if len(r.Spec.PolicyTypes) != 1 || r.Spec.PolicyTypes[0] != networkingv1.PolicyTypeEgress {
		t.Fatalf("restricted policyTypes = %v, want [Egress]", r.Spec.PolicyTypes)
	}
	if r.Annotations[AnnFSMState] != "RESTRICTED" {
		t.Fatalf("restricted fsm-state annotation = %q, want RESTRICTED", r.Annotations[AnnFSMState])
	}
	if _, err := cs.NetworkingV1().NetworkPolicies(ns).Get(ctx, quarantineName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("quarantine policy not removed on de-escalation to RESTRICTED: err=%v", err)
	}

	// (3) SUSPICIOUS (AC2): both managed policies removed.
	m.handle(ctx, suspiciousTransition(workloadID, "pkg-s"))
	if _, err := cs.NetworkingV1().NetworkPolicies(ns).Get(ctx, restrictedName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("restricted policy not removed on SUSPICIOUS: err=%v", err)
	}
	if _, err := cs.NetworkingV1().NetworkPolicies(ns).Get(ctx, quarantineName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("quarantine policy not removed on SUSPICIOUS: err=%v", err)
	}

	// (4) CLEAN (AC3): both absent, absence observable via a follow-up read.
	m.handle(ctx, cleanTransition(workloadID, "pkg-c"))
	if _, err := cs.NetworkingV1().NetworkPolicies(ns).Get(ctx, restrictedName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("restricted policy present at CLEAN: err=%v", err)
	}
	if _, err := cs.NetworkingV1().NetworkPolicies(ns).Get(ctx, quarantineName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("quarantine policy present at CLEAN: err=%v", err)
	}
}

// TestIntegration_DeescalationResidueReconcile exercises the FSM-target-aware
// reconcile backstop (Story 2.6, BI-2c) against a real apiserver. With the
// oracle reporting RESTRICTED, a co-existing quarantine deny-all (the failed
// inline-delete residue) is removed and the freshly-applied restricted policy
// survives. The mirror assertion (target QUARANTINED) guards the Story 2.5
// escalation-residue regression.
func TestIntegration_DeescalationResidueReconcile(t *testing.T) {
	ns := freshNamespace(t)
	cs := envtestState.cs
	ctx := context.Background()
	sel := map[string]string{"app": "web"}
	itCreateDeployment(t, ns, "web", sel)
	itCreateDeployment(t, ns, "api", sel)

	m, err := New(Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, cs, nil, discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	deWID := ns + "/Deployment/web" // de-escalation residue: target RESTRICTED
	esWID := ns + "/Deployment/api" // escalation residue: target QUARANTINED
	m.SetStateOracle(itOracle{states: map[string]schema.PodSecurityState{
		deWID: schema.StateRestricted,
		esWID: schema.StateQuarantined,
	}})

	// Seed BOTH policies for each workload (the overlap a failed inline delete
	// leaves behind).
	for _, wid := range []string{deWID, esWID} {
		m.handle(ctx, restrictedTransition(wid, "pkg-r"))
		// Apply the quarantine deny-all directly without the inline supersession
		// removing the restricted policy, by building+applying it.
		ref, _ := parseWorkloadID(wid)
		np := m.buildPolicy(ref, &metav1.LabelSelector{MatchLabels: sel}, quarantinedTransition(wid, "pkg-q"))
		if _, aerr := m.apply(ctx, np); aerr != nil {
			t.Fatalf("seed quarantine for %q: %v", wid, aerr)
		}
	}

	m.reconcileGC(ctx)

	// De-escalation residue (target RESTRICTED): quarantine removed, restricted survives.
	if _, err := cs.NetworkingV1().NetworkPolicies(ns).Get(ctx, policyNameFor(schema.StateQuarantined, deWID), metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("de-escalation residue quarantine not removed: err=%v", err)
	}
	if _, err := cs.NetworkingV1().NetworkPolicies(ns).Get(ctx, PolicyName(deWID), metav1.GetOptions{}); err != nil {
		t.Fatalf("restricted policy wrongly re-deleted on de-escalation: %v", err)
	}

	// Escalation residue (target QUARANTINED): restricted removed, quarantine survives.
	if _, err := cs.NetworkingV1().NetworkPolicies(ns).Get(ctx, PolicyName(esWID), metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("escalation residue restricted not removed: err=%v", err)
	}
	if _, err := cs.NetworkingV1().NetworkPolicies(ns).Get(ctx, policyNameFor(schema.StateQuarantined, esWID), metav1.GetOptions{}); err != nil {
		t.Fatalf("quarantine policy wrongly removed for QUARANTINED target: %v", err)
	}
}

// TestIntegration_CleanNoOpWithNothingPresent exercises the CLEAN no-op case
// (Story 2.6, BI-5) against a real apiserver: a CLEAN de-escalation for a
// workload with no managed policies succeeds, creates nothing, and the
// verification read confirms absence.
func TestIntegration_CleanNoOpWithNothingPresent(t *testing.T) {
	ns := freshNamespace(t)
	cs := envtestState.cs
	ctx := context.Background()
	sel := map[string]string{"app": "web"}
	itCreateDeployment(t, ns, "web", sel)

	m, err := New(Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, cs, nil, discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	workloadID := ns + "/Deployment/web"

	m.handle(ctx, cleanTransition(workloadID, "pkg-c"))

	if _, err := cs.NetworkingV1().NetworkPolicies(ns).Get(ctx, PolicyName(workloadID), metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("restricted policy created on no-op CLEAN: err=%v", err)
	}
	if _, err := cs.NetworkingV1().NetworkPolicies(ns).Get(ctx, policyNameFor(schema.StateQuarantined, workloadID), metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("quarantine policy created on no-op CLEAN: err=%v", err)
	}
}
