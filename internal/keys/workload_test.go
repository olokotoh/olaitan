package keys_test

import (
	"strings"
	"testing"

	"github.com/olokotoh/olaitan/internal/keys"
)

func TestWorkloadIDHappyPath(t *testing.T) {
	cases := []struct {
		name, namespace, ownerKind, ownerName, want string
	}{
		{"deployment", "payments", "Deployment", "payments-api", "payments/Deployment/payments-api"},
		{"statefulset", "data", "StatefulSet", "kafka-broker", "data/StatefulSet/kafka-broker"},
		{"daemonset", "kube-system", "DaemonSet", "kube-proxy", "kube-system/DaemonSet/kube-proxy"},
		{"cronjob", "ops", "CronJob", "nightly-rollup", "ops/CronJob/nightly-rollup"},
		{"job", "ops", "Job", "one-off", "ops/Job/one-off"},
		{"replicaset-fallthrough", "payments", "ReplicaSet", "payments-api-abc123", "payments/ReplicaSet/payments-api-abc123"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := keys.WorkloadID(tc.namespace, tc.ownerKind, tc.ownerName)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("WorkloadID: got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPodFallbackIDHappyPath(t *testing.T) {
	cases := []struct {
		name, namespace, pod, want string
	}{
		{"default-ns", "default", "lone-pod", "default/Pod/lone-pod"},
		{"app-ns", "scratch", "ad-hoc-debug", "scratch/Pod/ad-hoc-debug"},
		{"dotted-name", "scratch", "name.with.dots", "scratch/Pod/name.with.dots"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := keys.PodFallbackID(tc.namespace, tc.pod)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("PodFallbackID: got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWorkloadIDValidation(t *testing.T) {
	cases := []struct {
		name      string
		namespace string
		ownerKind string
		ownerName string
		wantSub   string
	}{
		{"empty-namespace", "", "Deployment", "app", "empty"},
		{"empty-kind", "ns", "", "app", "empty"},
		{"empty-name", "ns", "Deployment", "", "empty"},
		{"slash-in-namespace", "ns/inner", "Deployment", "app", "disallowed"},
		{"slash-in-kind", "ns", "Dep/loyment", "app", "disallowed"},
		{"slash-in-name", "ns", "Deployment", "app/v2", "disallowed"},
		{"colon-in-name", "ns", "Deployment", "app:v2", "disallowed"},
		{"star-in-kind", "ns", "Deploy*", "app", "disallowed"},
		{"tab-in-name", "ns", "Deployment", "app\tname", "disallowed"},
		{"control-in-namespace", "n\x00s", "Deployment", "app", "disallowed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := keys.WorkloadID(tc.namespace, tc.ownerKind, tc.ownerName)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("err %q does not contain %q", err, tc.wantSub)
			}
			if !strings.HasPrefix(err.Error(), "keys: workload-id") {
				t.Errorf("err %q missing keys: workload-id prefix", err)
			}
		})
	}
}

func TestPodFallbackIDValidation(t *testing.T) {
	cases := []struct {
		name, namespace, pod, wantSub string
	}{
		{"empty-namespace", "", "pod", "empty"},
		{"empty-pod", "ns", "", "empty"},
		{"slash-in-pod", "ns", "lone/pod", "disallowed"},
		{"colon-in-pod", "ns", "lone:pod", "disallowed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := keys.PodFallbackID(tc.namespace, tc.pod)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("err %q does not contain %q", err, tc.wantSub)
			}
			if !strings.HasPrefix(err.Error(), "keys: pod-fallback-id") {
				t.Errorf("err %q missing keys: pod-fallback-id prefix", err)
			}
		})
	}
}

// TestWorkloadIDSegmentSeparatorCount documents the contract that the
// builder's output contains exactly two "/" runes (the architecture-
// specified separators between the three segments) when none of the
// inputs contain "/". Each segment is URL-encoded, so a "/" inside an
// input is escaped to "%2F" and does not contribute to the structural
// separator count. With our validator rejecting raw "/" inside any
// segment this is equivalent to saying the structural separator count
// is always exactly two.
func TestWorkloadIDSegmentSeparatorCount(t *testing.T) {
	id, err := keys.WorkloadID("default", "Deployment", "app")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Count(id, "/") != 2 {
		t.Errorf("workload-id %q: got %d separators, want 2", id, strings.Count(id, "/"))
	}
	if strings.Count(id, "%2F") != 0 {
		t.Errorf("workload-id %q: got URL-encoded separator from clean input; want none", id)
	}
}

func TestPodFallbackIDOwnerKindIsLiteralPod(t *testing.T) {
	id, err := keys.PodFallbackID("default", "lone-pod")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(id, "/Pod/") {
		t.Errorf("pod-fallback-id %q: missing /Pod/ literal owner-kind sentinel", id)
	}
}

// TestWorkloadIDRejectsPodOwnerKind guards the orphan-pod sentinel.
// WorkloadID must refuse owner-kind "Pod" so a string-compare on the
// second segment unambiguously distinguishes resolved workloads from
// PodFallbackID's orphan-pod fallback.
func TestWorkloadIDRejectsPodOwnerKind(t *testing.T) {
	_, err := keys.WorkloadID("default", "Pod", "lone-pod")
	if err == nil {
		t.Fatalf("expected error rejecting owner-kind \"Pod\", got nil")
	}
	if !strings.Contains(err.Error(), "reserved for PodFallbackID") {
		t.Errorf("err %q does not mention PodFallbackID reservation", err)
	}
}
