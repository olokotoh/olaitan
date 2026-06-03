//go:build integration

package override

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/olokotoh/olaitan/internal/config"
	"github.com/olokotoh/olaitan/internal/metrics"
	redisclient "github.com/olokotoh/olaitan/internal/redis"
	"github.com/olokotoh/olaitan/internal/response/fsm"
	"github.com/olokotoh/olaitan/internal/schema"
)

// envtestState holds the package-shared envtest plumbing, started once in
// TestMain and reused across the integration suite (AC6). Mirrors the netpol /
// posture integration TestMain pattern; Redis is miniredis (AC6 "real K8s API
// plus miniredis/v2").
var envtestState struct {
	env *envtest.Environment
	cfg *rest.Config
	cs  *kubernetes.Clientset
}

func TestMain(m *testing.M) {
	if os.Getenv("OVERRIDE_INTEGRATION_SKIP") == "1" {
		os.Stderr.WriteString("override integration: OVERRIDE_INTEGRATION_SKIP=1, skipping (exit 0)\n")
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
		if os.Getenv("OVERRIDE_INTEGRATION_REQUIRED") == "1" {
			os.Stderr.WriteString("override integration: envtest unavailable (OVERRIDE_INTEGRATION_REQUIRED=1, failing): " + err.Error() + "\n")
			os.Exit(1)
		}
		os.Stderr.WriteString("override integration: envtest unavailable; exiting 0 (set OVERRIDE_INTEGRATION_REQUIRED=1 to fail loudly): " + err.Error() + "\n")
		os.Exit(0)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		os.Stderr.WriteString("override integration: clientset construction failed: " + err.Error() + "\n")
		_ = env.Stop()
		os.Exit(1)
	}
	envtestState.env = env
	envtestState.cfg = cfg
	envtestState.cs = cs

	code := m.Run()
	if err := env.Stop(); err != nil {
		os.Stderr.WriteString("override integration: envtest.Stop failed: " + err.Error() + "\n")
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

func freshNamespaceIT(t *testing.T) string {
	t.Helper()
	if envtestState.cs == nil {
		t.Skip("envtest binaries unavailable; skipping integration suite")
	}
	ns := fmt.Sprintf("override-it-%d-%d", time.Now().UnixNano(), nsCounter.Add(1))
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

// realObjects creates a Deployment -> ReplicaSet -> Pod chain against the real
// API (envtest runs no controllers, so the owner refs are set explicitly) and
// returns the pod's name. The owner-walk in resolveWorkloadID then yields
// ns/Deployment/web.
func realObjects(t *testing.T, ns string, podAnns map[string]string) string {
	t.Helper()
	cs := envtestState.cs
	ctx := context.Background()
	trueVal := true
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
	if _, err := cs.AppsV1().ReplicaSets(ns).Create(ctx, &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: "web-rs",
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "web", UID: "u-dep", Controller: &trueVal}},
		},
		Spec: appsv1.ReplicaSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: sel},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: sel},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "busybox"}}},
			},
		},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create replicaset: %v", err)
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: "web-abc", Labels: sel, Annotations: podAnns,
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "web-rs", UID: "u-rs", Controller: &trueVal}},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "busybox"}}},
	}
	if _, err := cs.CoreV1().Pods(ns).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create pod: %v", err)
	}
	return pod.Name
}

func itStore(t *testing.T) (*Store, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	rcfg := redisclient.DefaultConfig()
	rcfg.Addr = mr.Addr()
	cli, err := redisclient.NewClient(rcfg)
	if err != nil {
		t.Fatalf("redis client: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close(context.Background()) })
	store, err := NewStore(cli)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	return store, mr
}

func itMachine(t *testing.T, sink fsm.TransitionSink) *fsm.Machine {
	t.Helper()
	m, err := fsm.New(nil, nil, sink, nil)
	if err != nil {
		t.Fatalf("fsm.New: %v", err)
	}
	_ = config.DefaultOverride()
	return m
}

func itController(t *testing.T, store *Store, machine *fsm.Machine, pub OverridePublisher, reg *metrics.Registry) *Controller {
	t.Helper()
	c, err := New(Config{PollInterval: time.Second, DefaultTTL: time.Hour}, envtestState.cs, store, machine, pub, reg, nil)
	if err != nil {
		t.Fatalf("controller New: %v", err)
	}
	return c
}

// TestIntegration_AnnotationObservationAndTTL exercises AC1/AC3: an annotated
// pod against the real API is observed, pinned, and recorded with a ~30m
// native TTL, and an applied OVERRIDES.applied event is published.
func TestIntegration_AnnotationObservationAndTTL(t *testing.T) {
	ns := freshNamespaceIT(t)
	realObjects(t, ns, map[string]string{AnnotationState: "RESTRICTED", AnnotationTTL: "30m"})
	store, mr := itStore(t)
	pub := &fakePublisher{}
	machine := itMachine(t, fsm.NopSink{})
	c := itController(t, store, machine, pub, nil)

	c.reconcile(context.Background())

	wl := ns + "/Deployment/web"
	if s, pinned := machine.IsPinned(wl); !pinned || s != schema.StateRestricted {
		t.Fatalf("IsPinned = (%s, %v), want (RESTRICTED, true)", s, pinned)
	}
	if ttl := mr.TTL("override:" + wl); ttl != 30*time.Minute {
		t.Errorf("override TTL = %s, want 30m (AC3)", ttl)
	}
	evts := pub.all()
	if len(evts) != 1 || evts[0].Rejected {
		t.Fatalf("events = %+v, want one applied event", evts)
	}
}

// TestIntegration_TTLExpiryReleases exercises AC2: after the native TTL
// elapses (miniredis FastForward) and the annotation is gone, a poll releases
// the pin and the FSM resumes score-driven control.
func TestIntegration_TTLExpiryReleases(t *testing.T) {
	ns := freshNamespaceIT(t)
	realObjects(t, ns, map[string]string{AnnotationState: "RESTRICTED", AnnotationTTL: "30m"})
	store, mr := itStore(t)
	pub := &fakePublisher{}
	machine := itMachine(t, fsm.NopSink{})
	c := itController(t, store, machine, pub, nil)
	c.reconcile(context.Background())

	wl := ns + "/Deployment/web"
	// Remove the annotation and expire the native TTL.
	cs := envtestState.cs
	ctx := context.Background()
	pod, _ := cs.CoreV1().Pods(ns).Get(ctx, "web-abc", metav1.GetOptions{})
	pod.Annotations = nil
	if _, err := cs.CoreV1().Pods(ns).Update(ctx, pod, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update pod: %v", err)
	}
	mr.FastForward(31 * time.Minute)
	c.reconcile(ctx)

	if _, pinned := machine.IsPinned(wl); pinned {
		t.Fatal("TTL expiry must release the pin (AC2)")
	}
	// Score-driven re-evaluation: a high score now escalates from CLEAN.
	st := machine.Evaluate(wl, 100, "pkg")
	if st.ToState != schema.StateSuspicious {
		t.Errorf("post-release Evaluate = %s, want SUSPICIOUS (resumed score-driven control)", st.ToState)
	}
}

// TestIntegration_ManualRemoval exercises AC4: removing the annotation before
// the TTL expires releases the pin immediately and clears Redis.
func TestIntegration_ManualRemoval(t *testing.T) {
	ns := freshNamespaceIT(t)
	realObjects(t, ns, map[string]string{AnnotationState: "QUARANTINED", AnnotationTTL: "1h"})
	store, _ := itStore(t)
	pub := &fakePublisher{}
	machine := itMachine(t, fsm.NopSink{})
	c := itController(t, store, machine, pub, nil)
	ctx := context.Background()
	c.reconcile(ctx)

	wl := ns + "/Deployment/web"
	cs := envtestState.cs
	pod, _ := cs.CoreV1().Pods(ns).Get(ctx, "web-abc", metav1.GetOptions{})
	pod.Annotations = nil
	if _, err := cs.CoreV1().Pods(ns).Update(ctx, pod, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update pod: %v", err)
	}
	c.reconcile(ctx)

	if _, pinned := machine.IsPinned(wl); pinned {
		t.Fatal("manual removal must release the pin (AC4)")
	}
	if _, ok, _ := store.Get(ctx, wl); ok {
		t.Fatal("manual removal must clear Redis (AC4)")
	}
}

// TestIntegration_RejectedOverride exercises AC5: a PRESERVED_KILLED annotation
// is rejected with the event + metric and leaves the FSM/Redis untouched.
func TestIntegration_RejectedOverride(t *testing.T) {
	ns := freshNamespaceIT(t)
	realObjects(t, ns, map[string]string{AnnotationState: "PRESERVED_KILLED"})
	store, _ := itStore(t)
	pub := &fakePublisher{}
	reg := metrics.NewRegistry()
	machine := itMachine(t, fsm.NopSink{})
	c := itController(t, store, machine, pub, reg)
	ctx := context.Background()
	c.reconcile(ctx)

	wl := ns + "/Deployment/web"
	if _, pinned := machine.IsPinned(wl); pinned {
		t.Fatal("PRESERVED_KILLED must not pin (AC5)")
	}
	if _, ok, _ := store.Get(ctx, wl); ok {
		t.Fatal("rejected override must not write Redis (AC5)")
	}
	evts := pub.all()
	if len(evts) != 1 || !evts[0].Rejected || evts[0].Reason != ReasonStateUnavailable {
		t.Fatalf("events = %+v, want one rejected state_unavailable event (AC5)", evts)
	}
	if got := counterValue(t, reg, "olaitan_response_override_rejected_total", "state_unavailable"); got != 1 {
		t.Errorf("rejected counter = %v, want 1 (AC5)", got)
	}
}

// TestIntegration_PinDrivesEnforcementSink exercises Task 6.2 / BI-7: an
// override to RESTRICTED reaches a recording sink as a transition INTO
// RESTRICTED, proving the pin routes through the FSM sink with no new
// enforcement code (the netpol manager would enqueue this same transition).
func TestIntegration_PinDrivesEnforcementSink(t *testing.T) {
	ns := freshNamespaceIT(t)
	realObjects(t, ns, map[string]string{AnnotationState: "RESTRICTED", AnnotationTTL: "30m"})
	store, _ := itStore(t)
	pub := &fakePublisher{}
	rec := &recordingSink{}
	machine := itMachine(t, rec)
	c := itController(t, store, machine, pub, nil)
	c.reconcile(context.Background())

	wl := ns + "/Deployment/web"
	got := rec.transitions()
	if len(got) != 1 {
		t.Fatalf("recording sink saw %d transitions, want exactly 1 (the pin)", len(got))
	}
	if got[0].ToState != schema.StateRestricted || got[0].TriggerType != "override" || got[0].WorkloadID != wl {
		t.Fatalf("pin transition = %+v, want ToState=RESTRICTED TriggerType=override workload=%s", got[0], wl)
	}
}
