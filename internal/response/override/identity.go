package override

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/olokotoh/olaitan/internal/keys"
)

// Annotation keys an operator sets on a pod or owner to drive an override
// (architecture.md:463). The TTL annotation is optional (default 1h, BI-8).
const (
	AnnotationState = "olaitan.io/state-override"
	AnnotationTTL   = "olaitan.io/state-override-ttl"
)

// resolveWorkloadID resolves a pod to its canonical "<namespace>/<owner-kind>/
// <owner-name>" workload_id by walking pod.OwnerReferences with the typed
// clients directly (BI-12). This is a Ring-clean reimplementation of the
// two-hop owner walk posture.ResolveWorkloadIdentity performs (RS->Deployment
// OR Job->CronJob), copied here rather than imported because posture is Ring 1
// and a Ring-4 import would violate the ring rule. At most two K8s API hops
// per pod (the same guardrail-23 ceiling). An orphan pod (no controller, or an
// owner that cannot be fetched) falls back to "<namespace>/Pod/<pod-name>".
func resolveWorkloadID(ctx context.Context, cs kubernetes.Interface, pod *corev1.Pod) (string, error) {
	if pod == nil {
		return "", fmt.Errorf("override: resolve: nil pod")
	}

	controller := metav1.GetControllerOf(pod)
	if controller == nil {
		return keys.PodFallbackID(pod.Namespace, pod.Name)
	}

	switch controller.Kind {
	case "ReplicaSet":
		rs, err := cs.AppsV1().ReplicaSets(pod.Namespace).Get(ctx, controller.Name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return keys.PodFallbackID(pod.Namespace, pod.Name)
			}
			return "", fmt.Errorf("override: fetch ReplicaSet %s/%s: %w", pod.Namespace, controller.Name, err)
		}
		if parent := metav1.GetControllerOf(rs); parent != nil && parent.Kind == "Deployment" {
			return keys.WorkloadID(pod.Namespace, "Deployment", parent.Name)
		}
		return keys.WorkloadID(pod.Namespace, "ReplicaSet", rs.Name)

	case "Job":
		job, err := cs.BatchV1().Jobs(pod.Namespace).Get(ctx, controller.Name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return keys.PodFallbackID(pod.Namespace, pod.Name)
			}
			return "", fmt.Errorf("override: fetch Job %s/%s: %w", pod.Namespace, controller.Name, err)
		}
		if parent := metav1.GetControllerOf(job); parent != nil && parent.Kind == "CronJob" {
			return keys.WorkloadID(pod.Namespace, "CronJob", parent.Name)
		}
		return keys.WorkloadID(pod.Namespace, "Job", job.Name)

	default:
		// StatefulSet, DaemonSet, any custom-resource controller: the
		// immediate controller verbatim. The walk stops at the first level.
		return keys.WorkloadID(pod.Namespace, controller.Kind, controller.Name)
	}
}

// ownerAnnotations fetches the resolved top-most owner object's annotations
// (BI-9 precedence: the owner annotation applies to all the owner's pods). It
// uses the already-granted get verb (no watch, BI-1). An owner that cannot be
// fetched yields nil annotations (the pod-level annotation, if any, still
// governs). The walk mirrors resolveWorkloadID so the owner object read is the
// SAME top-most controller the workload_id keys on.
func ownerAnnotations(ctx context.Context, cs kubernetes.Interface, pod *corev1.Pod) map[string]string {
	if pod == nil {
		return nil
	}
	controller := metav1.GetControllerOf(pod)
	if controller == nil {
		return nil
	}
	switch controller.Kind {
	case "ReplicaSet":
		rs, err := cs.AppsV1().ReplicaSets(pod.Namespace).Get(ctx, controller.Name, metav1.GetOptions{})
		if err != nil {
			return nil
		}
		if parent := metav1.GetControllerOf(rs); parent != nil && parent.Kind == "Deployment" {
			dep, derr := cs.AppsV1().Deployments(pod.Namespace).Get(ctx, parent.Name, metav1.GetOptions{})
			if derr != nil {
				return nil
			}
			return dep.Annotations
		}
		return rs.Annotations

	case "Job":
		job, err := cs.BatchV1().Jobs(pod.Namespace).Get(ctx, controller.Name, metav1.GetOptions{})
		if err != nil {
			return nil
		}
		if parent := metav1.GetControllerOf(job); parent != nil && parent.Kind == "CronJob" {
			cj, cerr := cs.BatchV1().CronJobs(pod.Namespace).Get(ctx, parent.Name, metav1.GetOptions{})
			if cerr != nil {
				return nil
			}
			return cj.Annotations
		}
		return job.Annotations

	case "StatefulSet":
		ss, err := cs.AppsV1().StatefulSets(pod.Namespace).Get(ctx, controller.Name, metav1.GetOptions{})
		if err != nil {
			return nil
		}
		return ss.Annotations
	case "DaemonSet":
		ds, err := cs.AppsV1().DaemonSets(pod.Namespace).Get(ctx, controller.Name, metav1.GetOptions{})
		if err != nil {
			return nil
		}
		return ds.Annotations
	default:
		return nil
	}
}
