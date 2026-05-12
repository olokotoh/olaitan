package posture_test

import (
	"context"
	"errors"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/olokotoh/olaitan/internal/collector/posture"
)

// newOwnerRef builds a metav1.OwnerReference for the given kind/name
// with Controller=true so metav1.GetControllerOf picks it up.
func newOwnerRef(kind, name, uid string) metav1.OwnerReference {
	ctrl := true
	return metav1.OwnerReference{
		Kind:       kind,
		Name:       name,
		UID:        types.UID(uid),
		Controller: &ctrl,
	}
}

func TestResolveWorkloadIdentity_PodOwnedByDeploymentViaReplicaSet(t *testing.T) {
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "payments-abc",
			Namespace:       "payments",
			OwnerReferences: []metav1.OwnerReference{newOwnerRef("Deployment", "payments-api", "dep-uid")},
		},
	}
	cs := fake.NewSimpleClientset(rs)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "payments-abc-xyz",
			Namespace:       "payments",
			OwnerReferences: []metav1.OwnerReference{newOwnerRef("ReplicaSet", "payments-abc", "rs-uid")},
		},
	}

	id, err := posture.ResolveWorkloadIdentity(context.Background(), cs, pod)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.OwnerKind != "Deployment" || id.OwnerName != "payments-api" {
		t.Errorf("identity: got %+v, want Deployment/payments-api", id)
	}
	if id.Namespace != "payments" {
		t.Errorf("namespace: got %q, want payments", id.Namespace)
	}
}

func TestResolveWorkloadIdentity_PodOwnedByReplicaSetWithoutDeployment(t *testing.T) {
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "free-rs",
			Namespace:       "ops",
			OwnerReferences: nil,
		},
	}
	cs := fake.NewSimpleClientset(rs)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "free-rs-abc",
			Namespace:       "ops",
			OwnerReferences: []metav1.OwnerReference{newOwnerRef("ReplicaSet", "free-rs", "rs-uid")},
		},
	}

	id, err := posture.ResolveWorkloadIdentity(context.Background(), cs, pod)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.OwnerKind != "ReplicaSet" || id.OwnerName != "free-rs" {
		t.Errorf("identity: got %+v, want ReplicaSet/free-rs", id)
	}
}

func TestResolveWorkloadIdentity_PodOwnedByJobInCronJob(t *testing.T) {
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "nightly-12345",
			Namespace:       "ops",
			OwnerReferences: []metav1.OwnerReference{newOwnerRef("CronJob", "nightly", "cj-uid")},
		},
	}
	cs := fake.NewSimpleClientset(job)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "nightly-12345-abc",
			Namespace:       "ops",
			OwnerReferences: []metav1.OwnerReference{newOwnerRef("Job", "nightly-12345", "job-uid")},
		},
	}

	id, err := posture.ResolveWorkloadIdentity(context.Background(), cs, pod)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.OwnerKind != "CronJob" || id.OwnerName != "nightly" {
		t.Errorf("identity: got %+v, want CronJob/nightly", id)
	}
}

func TestResolveWorkloadIdentity_PodOwnedByStandaloneJob(t *testing.T) {
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "one-off",
			Namespace: "ops",
		},
	}
	cs := fake.NewSimpleClientset(job)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "one-off-abc",
			Namespace:       "ops",
			OwnerReferences: []metav1.OwnerReference{newOwnerRef("Job", "one-off", "job-uid")},
		},
	}

	id, err := posture.ResolveWorkloadIdentity(context.Background(), cs, pod)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.OwnerKind != "Job" || id.OwnerName != "one-off" {
		t.Errorf("identity: got %+v, want Job/one-off", id)
	}
}

func TestResolveWorkloadIdentity_PodOwnedByStatefulSet(t *testing.T) {
	cs := fake.NewSimpleClientset()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "kafka-0",
			Namespace:       "data",
			OwnerReferences: []metav1.OwnerReference{newOwnerRef("StatefulSet", "kafka", "sts-uid")},
		},
	}

	id, err := posture.ResolveWorkloadIdentity(context.Background(), cs, pod)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.OwnerKind != "StatefulSet" || id.OwnerName != "kafka" {
		t.Errorf("identity: got %+v, want StatefulSet/kafka", id)
	}
}

func TestResolveWorkloadIdentity_PodOwnedByDaemonSet(t *testing.T) {
	cs := fake.NewSimpleClientset()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "fluent-bit-abc",
			Namespace:       "logging",
			OwnerReferences: []metav1.OwnerReference{newOwnerRef("DaemonSet", "fluent-bit", "ds-uid")},
		},
	}

	id, err := posture.ResolveWorkloadIdentity(context.Background(), cs, pod)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.OwnerKind != "DaemonSet" || id.OwnerName != "fluent-bit" {
		t.Errorf("identity: got %+v, want DaemonSet/fluent-bit", id)
	}
}

func TestResolveWorkloadIdentity_OrphanPodFallback(t *testing.T) {
	cs := fake.NewSimpleClientset()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ad-hoc-debug",
			Namespace: "scratch",
		},
	}

	id, err := posture.ResolveWorkloadIdentity(context.Background(), cs, pod)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.OwnerKind != "Pod" || id.OwnerName != "ad-hoc-debug" {
		t.Errorf("identity: got %+v, want Pod/ad-hoc-debug", id)
	}
	if id.PodName != "ad-hoc-debug" {
		t.Errorf("PodName: got %q, want ad-hoc-debug", id.PodName)
	}
}

func TestResolveWorkloadIdentity_ReplicaSetNotFoundFallsBackToOrphan(t *testing.T) {
	cs := fake.NewSimpleClientset()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "phantom-pod",
			Namespace:       "payments",
			OwnerReferences: []metav1.OwnerReference{newOwnerRef("ReplicaSet", "ghost-rs", "rs-uid")},
		},
	}

	id, err := posture.ResolveWorkloadIdentity(context.Background(), cs, pod)
	if !errors.Is(err, posture.ErrControllerNotFound) {
		t.Fatalf("err: got %v, want ErrControllerNotFound", err)
	}
	if id.OwnerKind != "Pod" || id.OwnerName != "phantom-pod" {
		t.Errorf("fallback identity: got %+v, want Pod/phantom-pod", id)
	}
}

func TestResolveWorkloadIdentity_NilPodReturnsError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	_, err := posture.ResolveWorkloadIdentity(context.Background(), cs, nil)
	if err == nil {
		t.Fatalf("expected error for nil pod, got nil")
	}
}

// TestResolveWorkloadIdentity_ReplicaSetWithNonDeploymentParent
// covers the edge case where a ReplicaSet is owned by a
// non-Deployment controller (a custom CRD or a partially-detached
// RS). The resolver should return the ReplicaSet identity rather
// than walking further.
func TestResolveWorkloadIdentity_ReplicaSetWithNonDeploymentParent(t *testing.T) {
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "custom-rs",
			Namespace:       "ops",
			OwnerReferences: []metav1.OwnerReference{newOwnerRef("CustomController", "ctrl", "ctrl-uid")},
		},
	}
	cs := fake.NewSimpleClientset(rs)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "custom-rs-pod",
			Namespace:       "ops",
			OwnerReferences: []metav1.OwnerReference{newOwnerRef("ReplicaSet", "custom-rs", "rs-uid")},
		},
	}

	id, err := posture.ResolveWorkloadIdentity(context.Background(), cs, pod)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.OwnerKind != "ReplicaSet" || id.OwnerName != "custom-rs" {
		t.Errorf("identity: got %+v, want ReplicaSet/custom-rs", id)
	}
}
