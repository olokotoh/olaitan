// Package posture implements the read-on-demand workload posture
// client (FR7), the sixth Ring 1 source described at
// architecture.md:45 ("five streaming adapters plus one read-on-demand
// posture client"), architecture.md:751 (production path
// internal/collector/posture/), and architecture.md:324 ("posture is
// read on-demand at investigation time, not via continuous Watch.
// Cache TTL 60 seconds keyed by workload_id").
//
// The package exposes a synchronous K8s-API client that, given a
// representative *corev1.Pod, returns a *schema.WorkloadPosture
// populated with:
//
//   - the workload's RBAC bindings (RoleBindings in the namespace plus
//     ClusterRoleBindings whose subjects include the workload's
//     ServiceAccount with the workload's namespace),
//   - the NetworkPolicies in the namespace whose spec.podSelector
//     matches the pod's label set,
//   - the pod-level PodSecurityContext plus the per-container
//     SecurityContext arrays.
//
// Three guardrails govern the package:
//
//   - (22) Read-on-demand only. No informer cache, no continuous Watch
//     (architecture.md:324). The in-memory TTL cache (cache.go) covers
//     the freshness budget; the WithBypassCache option (posture.go)
//     covers the Story 3.x LLM-eligible fresh-fetch path
//     (architecture.md:326).
//   - (23) Two-API-call ceiling per owner-resolution. owner.go walks
//     at most two K8s API hops per pod (ReplicaSet -> Deployment OR
//     Job -> CronJob). Deeper walks return the deepest resolved level
//     rather than continuing.
//   - (24) Error redaction at the K8s API boundary (NFR15). The Client
//     returns UnavailableReason as one of four classes (transient,
//     permission_denied, not_found, permanent); the full err.Error()
//     is logged via slog but never embedded in the posture payload
//     that flows into the LLM prompt.
//
// Caller contract: the posture client takes *corev1.Pod, NOT a
// FlowKey or any other source-specific identifier. The correlator
// (Story 1.14) resolves source-specific hints (such as Goldmane's
// FlowKey.source_name carried with the pod_name_kind:generatename
// tag from Story 1.10) to a representative pod before calling Get.
// This keeps the posture client decoupled from Goldmane proto
// specifics or any future source-specific identity scheme.
//
// Hand-offs to other stories:
//
//   - Story 1.12 (per-source health and event metrics surface)
//     binds the atomic counters exposed via getters (PostureCacheHits,
//     PostureCacheMisses, PostureAPIErrors, PostureOrphanPods,
//     PostureUnavailable) to the Prometheus surface as
//     olaitan_sensor_posture_* metrics.
//   - Story 1.14 (sliding-window correlator) calls Client.Get at
//     EvidencePackage assembly time and propagates Unavailable=true
//     onto EvidencePackage.posture_unavailable.
//   - Story 3.8 (investigation chain trigger) calls Get with
//     WithBypassCache() for LLM-eligible packages
//     (architecture.md:326).
package posture

import (
	"context"
	"errors"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/olokotoh/olaitan/internal/schema"
)

// Sentinel errors. The package uses errors.Is for typed-check
// classification; substring matching on error messages is forbidden
// here per the Story 1.7 patch P7, Story 1.8 P28, and Story 1.10 P35
// precedents.
var (
	// ErrControllerNotFound is returned by the owner-resolver when a
	// pod's immediate controller is referenced via
	// OwnerReferences but the controller object cannot be fetched
	// from the K8s API (apierrors.IsNotFound at the typed fetch
	// step). The caller treats this as an orphan-pod fallback path.
	ErrControllerNotFound = errors.New("posture: controller not found")
)

// ResolveWorkloadIdentity walks pod.OwnerReferences to the top-most
// controller and returns the canonical workload identity per
// architecture.md:457 ("namespace/owner-kind/owner-name URL-encoded,
// fallback to namespace/pod-name for orphan pods").
//
// Algorithm (mirrors kubernetes/pkg/controller/replicaset
// /replica_set.go:resolveControllerRef with the Deployment lineage
// step added per kubernetes/pkg/controller/deployment
// /deployment_controller.go):
//
//  1. metav1.GetControllerOf(pod) -> if nil, return orphan-pod
//     fallback (OwnerKind=Pod, OwnerName=<pod-name>).
//  2. ReplicaSet -> fetch the RS; metav1.GetControllerOf(rs) -> if
//     Deployment, return that. Otherwise return ReplicaSet.
//  3. Job -> fetch the Job; metav1.GetControllerOf(job) -> if
//     CronJob, return that. Otherwise return Job.
//  4. Any other controller (StatefulSet, DaemonSet, custom CRD) ->
//     return the immediate controller verbatim.
//
// Error handling:
//
//   - apierrors.IsNotFound at the intermediate fetch -> wrap
//     ErrControllerNotFound; caller decides whether to fallback or
//     surface the error.
//   - any other error -> return verbatim so the caller can classify
//     it via posture.classify and mark the posture Unavailable.
//
// Guardrail 23: at most TWO K8s API hops per pod
// (RS -> Deployment OR Job -> CronJob). The architecture's
// read-on-demand cost budget is honoured by this ceiling plus the
// 60s cache that amortises across investigations.
func ResolveWorkloadIdentity(ctx context.Context, cs kubernetes.Interface, pod *corev1.Pod) (schema.WorkloadIdentity, error) {
	if pod == nil {
		return schema.WorkloadIdentity{}, errors.New("posture: pod is nil")
	}

	orphan := schema.WorkloadIdentity{
		Namespace: pod.Namespace,
		OwnerKind: "Pod",
		OwnerName: pod.Name,
		PodName:   pod.Name,
	}

	controller := metav1.GetControllerOf(pod)
	if controller == nil {
		return orphan, nil
	}

	switch controller.Kind {
	case "ReplicaSet":
		rs, err := cs.AppsV1().ReplicaSets(pod.Namespace).Get(ctx, controller.Name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return orphan, fmt.Errorf("posture: owner ReplicaSet %s/%s: %w", pod.Namespace, controller.Name, ErrControllerNotFound)
			}
			return schema.WorkloadIdentity{}, fmt.Errorf("posture: fetch ReplicaSet %s/%s: %w", pod.Namespace, controller.Name, err)
		}
		if parent := metav1.GetControllerOf(rs); parent != nil && parent.Kind == "Deployment" {
			return schema.WorkloadIdentity{
				Namespace: pod.Namespace,
				OwnerKind: "Deployment",
				OwnerName: parent.Name,
			}, nil
		}
		return schema.WorkloadIdentity{
			Namespace: pod.Namespace,
			OwnerKind: "ReplicaSet",
			OwnerName: rs.Name,
		}, nil

	case "Job":
		job, err := cs.BatchV1().Jobs(pod.Namespace).Get(ctx, controller.Name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return orphan, fmt.Errorf("posture: owner Job %s/%s: %w", pod.Namespace, controller.Name, ErrControllerNotFound)
			}
			return schema.WorkloadIdentity{}, fmt.Errorf("posture: fetch Job %s/%s: %w", pod.Namespace, controller.Name, err)
		}
		if parent := metav1.GetControllerOf(job); parent != nil && parent.Kind == "CronJob" {
			return schema.WorkloadIdentity{
				Namespace: pod.Namespace,
				OwnerKind: "CronJob",
				OwnerName: parent.Name,
			}, nil
		}
		return schema.WorkloadIdentity{
			Namespace: pod.Namespace,
			OwnerKind: "Job",
			OwnerName: job.Name,
		}, nil

	default:
		// StatefulSet, DaemonSet, any custom-resource controller:
		// return the immediate controller verbatim. The owner-walk
		// stops at the first level.
		return schema.WorkloadIdentity{
			Namespace: pod.Namespace,
			OwnerKind: controller.Kind,
			OwnerName: controller.Name,
		}, nil
	}
}

// Silence unused import warnings on the kinds we reference only in
// docstrings; the typed clientset usage above keeps the apps/v1 and
// batch/v1 packages live, but adding explicit references guards
// against a future refactor inadvertently dropping them.
var (
	_ = appsv1.SchemeGroupVersion
	_ = batchv1.SchemeGroupVersion
)
