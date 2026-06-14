package forensics

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

func TestParseWorkloadID(t *testing.T) {
	cases := []struct {
		id      string
		wantNS  string
		wantK   string
		wantN   string
		wantPod string
		wantErr bool
	}{
		{id: "ns/Deployment/web", wantNS: "ns", wantK: "Deployment", wantN: "web"},
		{id: "ns/Pod/lonely", wantNS: "ns", wantK: "Pod", wantPod: "lonely"},
		{id: "bad", wantErr: true},
		{id: "a/b", wantErr: true},
		{id: "//", wantErr: true},
		{id: "ns//web", wantErr: true},
	}
	for _, tc := range cases {
		ref, err := parseWorkloadID(tc.id)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("%q: want error", tc.id)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%q: %v", tc.id, err)
		}
		if ref.namespace != tc.wantNS || ref.ownerKind != tc.wantK {
			t.Fatalf("%q: got %+v", tc.id, ref)
		}
		if tc.wantPod != "" && ref.podName != tc.wantPod {
			t.Fatalf("%q: pod %q", tc.id, ref.podName)
		}
	}
}

// TestResolvePods_Deployment lists pods by the owner selector.
func TestResolvePods_Deployment(t *testing.T) {
	sel := map[string]string{"app": "web"}
	cs := fake.NewSimpleClientset(
		runtime.Object(&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "web"},
			Spec:       appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: sel}},
		}),
		runtime.Object(pod("ns", "web-1", sel)),
		runtime.Object(pod("ns", "web-2", sel)),
		runtime.Object(pod("ns", "other", map[string]string{"app": "db"})),
	)
	c, _ := New(Config{}, cs, &fakeUploader{}, nil, discardLog())
	names, err := c.resolvePods(context.Background(), workloadRef{namespace: "ns", ownerKind: "Deployment", ownerName: "web"})
	if err != nil {
		t.Fatalf("resolvePods: %v", err)
	}
	if len(names) != 2 {
		t.Fatalf("resolved %v, want 2 web pods", names)
	}
}

// TestResolvePods_OwnerGone returns an empty set on a NotFound owner.
func TestResolvePods_OwnerGone(t *testing.T) {
	cs := fake.NewSimpleClientset()
	c, _ := New(Config{}, cs, &fakeUploader{}, nil, discardLog())
	names, err := c.resolvePods(context.Background(), workloadRef{namespace: "ns", ownerKind: "Deployment", ownerName: "gone"})
	if err != nil {
		t.Fatalf("resolvePods: %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("want empty, got %v", names)
	}
}

// TestResolvePods_OrphanGone returns empty when the orphan pod is gone.
func TestResolvePods_OrphanGone(t *testing.T) {
	cs := fake.NewSimpleClientset()
	c, _ := New(Config{}, cs, &fakeUploader{}, nil, discardLog())
	names, err := c.resolvePods(context.Background(), workloadRef{namespace: "ns", ownerKind: "Pod", podName: "gone"})
	if err != nil {
		t.Fatalf("resolvePods: %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("want empty, got %v", names)
	}
}

// TestResolveSelector_EmptySelectorRefused guards the namespace-wide block.
func TestResolveSelector_EmptySelectorRefused(t *testing.T) {
	cs := fake.NewSimpleClientset(runtime.Object(&appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "web"},
		Spec:       appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{}},
	}))
	c, _ := New(Config{}, cs, &fakeUploader{}, nil, discardLog())
	if _, err := c.resolveSelector(context.Background(), workloadRef{namespace: "ns", ownerKind: "Deployment", ownerName: "web"}); err != errEmptySelector {
		t.Fatalf("want errEmptySelector, got %v", err)
	}
}

// TestResolveSelector_UnsupportedKind covers the default branch.
func TestResolveSelector_UnsupportedKind(t *testing.T) {
	cs := fake.NewSimpleClientset()
	c, _ := New(Config{}, cs, &fakeUploader{}, nil, discardLog())
	if _, err := c.resolveSelector(context.Background(), workloadRef{namespace: "ns", ownerKind: "CronJob", ownerName: "c"}); err == nil {
		t.Fatal("want error for unsupported kind")
	}
}

// TestResolveSelector_AllOwnerKinds exercises every supported owner kind so the
// resolveSelector switch is fully covered.
func TestResolveSelector_AllOwnerKinds(t *testing.T) {
	sel := map[string]string{"app": "x"}
	lsel := &metav1.LabelSelector{MatchLabels: sel}
	objs := []runtime.Object{
		&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "ss"}, Spec: appsv1.StatefulSetSpec{Selector: lsel}},
		&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "ds"}, Spec: appsv1.DaemonSetSpec{Selector: lsel}},
		&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "rs"}, Spec: appsv1.ReplicaSetSpec{Selector: lsel}},
		&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "job"}, Spec: batchv1.JobSpec{Selector: lsel}},
	}
	cs := fake.NewSimpleClientset(objs...)
	c, _ := New(Config{}, cs, &fakeUploader{}, nil, discardLog())
	for _, tc := range []struct{ kind, name string }{
		{"StatefulSet", "ss"}, {"DaemonSet", "ds"}, {"ReplicaSet", "rs"}, {"Job", "job"},
	} {
		got, err := c.resolveSelector(context.Background(), workloadRef{namespace: "ns", ownerKind: tc.kind, ownerName: tc.name})
		if err != nil {
			t.Fatalf("%s: %v", tc.kind, err)
		}
		if got.MatchLabels["app"] != "x" {
			t.Fatalf("%s: selector %v", tc.kind, got)
		}
	}
}

var _ = corev1.Pod{}
