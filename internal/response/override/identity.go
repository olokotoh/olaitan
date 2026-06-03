package override

import (
	"context"
	"fmt"
	"strings"

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
	// AnnotationOperator carries the operator identity that applied the
	// override (FIX 4). It is optional: absent leaves operator_id empty.
	AnnotationOperator = "olaitan.io/state-override-by"
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
// uses the already-granted get verb (no watch, BI-1). The walk mirrors
// resolveWorkloadID so the owner object read is the SAME top-most controller
// the workload_id keys on.
//
// It distinguishes "owner has no annotation" (nil map, nil error - fine, the
// pod-level annotation, if any, still governs) from "owner GET errored" with a
// NON-NotFound (transient) error, which is propagated so the caller can mark
// the workload indeterminate and refuse to release it this tick (FIX 1). A
// NotFound on an owner is treated as "no annotation" (nil, nil): the owner
// genuinely does not exist, so it carries no override annotation.
func ownerAnnotations(ctx context.Context, cs kubernetes.Interface, pod *corev1.Pod) (map[string]string, error) {
	if pod == nil {
		return nil, nil
	}
	controller := metav1.GetControllerOf(pod)
	if controller == nil {
		return nil, nil
	}
	switch controller.Kind {
	case "ReplicaSet":
		rs, err := cs.AppsV1().ReplicaSets(pod.Namespace).Get(ctx, controller.Name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil, nil
			}
			return nil, fmt.Errorf("override: get ReplicaSet %s/%s annotations: %w", pod.Namespace, controller.Name, err)
		}
		if parent := metav1.GetControllerOf(rs); parent != nil && parent.Kind == "Deployment" {
			dep, derr := cs.AppsV1().Deployments(pod.Namespace).Get(ctx, parent.Name, metav1.GetOptions{})
			if derr != nil {
				if apierrors.IsNotFound(derr) {
					return nil, nil
				}
				return nil, fmt.Errorf("override: get Deployment %s/%s annotations: %w", pod.Namespace, parent.Name, derr)
			}
			return dep.Annotations, nil
		}
		return rs.Annotations, nil

	case "Job":
		job, err := cs.BatchV1().Jobs(pod.Namespace).Get(ctx, controller.Name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil, nil
			}
			return nil, fmt.Errorf("override: get Job %s/%s annotations: %w", pod.Namespace, controller.Name, err)
		}
		if parent := metav1.GetControllerOf(job); parent != nil && parent.Kind == "CronJob" {
			cj, cerr := cs.BatchV1().CronJobs(pod.Namespace).Get(ctx, parent.Name, metav1.GetOptions{})
			if cerr != nil {
				if apierrors.IsNotFound(cerr) {
					return nil, nil
				}
				return nil, fmt.Errorf("override: get CronJob %s/%s annotations: %w", pod.Namespace, parent.Name, cerr)
			}
			return cj.Annotations, nil
		}
		return job.Annotations, nil

	case "StatefulSet":
		ss, err := cs.AppsV1().StatefulSets(pod.Namespace).Get(ctx, controller.Name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil, nil
			}
			return nil, fmt.Errorf("override: get StatefulSet %s/%s annotations: %w", pod.Namespace, controller.Name, err)
		}
		return ss.Annotations, nil
	case "DaemonSet":
		ds, err := cs.AppsV1().DaemonSets(pod.Namespace).Get(ctx, controller.Name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil, nil
			}
			return nil, fmt.Errorf("override: get DaemonSet %s/%s annotations: %w", pod.Namespace, controller.Name, err)
		}
		return ds.Annotations, nil
	default:
		return nil, nil
	}
}

// ownerStatus is the tri-state result of confirmOwnerAnnotation (FIX 2(b),
// round 2): a direct read of the workload's owner object to confirm whether the
// override annotation is GENUINELY gone before a "manual removal" release. It
// disambiguates the owner-scaled-to-zero / rollout-churn false positive where a
// pinned workload has zero live pods this tick (a successful-but-empty pod
// list) yet the owner still carries the annotation, so the pods' transient
// absence must NOT be read as a removal.
type ownerStatus int

const (
	// ownerRemovalConfirmed: the owner is gone (NotFound) OR present without the
	// override annotation. Either way the override is genuinely removed -> the
	// caller may release the pin.
	ownerRemovalConfirmed ownerStatus = iota
	// ownerStillAnnotated: the owner object is present and STILL carries the
	// override annotation, so the workload is still desired (its pods are merely
	// absent this tick) -> the caller must NOT release.
	ownerStillAnnotated
	// ownerIndeterminate: a non-NotFound read error (or an unparseable
	// workload_id) means the owner state could not be determined -> the caller
	// must NOT release (treat as indeterminate, retain the pin).
	ownerIndeterminate
)

// confirmOwnerAnnotation reads the workload_id's owner object directly to decide
// whether a candidate "manual removal" is genuine (FIX 2(b), round 2). It parses
// the canonical "<namespace>/<kind>/<name>" workload_id, GETs that owner via the
// typed client, and reports whether the owner still carries the
// olaitan.io/state-override annotation. An orphan-pod identity
// ("<namespace>/Pod/<pod-name>") has no durable owner object; its annotation
// lives only on the (now-absent) pod, so a confirmed-absent pod IS a confirmed
// removal (ownerRemovalConfirmed).
func confirmOwnerAnnotation(ctx context.Context, cs kubernetes.Interface, workloadID string) ownerStatus {
	ns, kind, name, ok := splitWorkloadID(workloadID)
	if !ok {
		// An unparseable workload_id cannot be confirmed; be conservative.
		return ownerIndeterminate
	}

	var anns map[string]string
	var err error
	switch kind {
	case "Pod":
		// Orphan-pod identity: the annotation lived on the pod, which the pod
		// list already confirmed absent. There is no separate owner to consult.
		p, gerr := cs.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
		if gerr != nil {
			if apierrors.IsNotFound(gerr) {
				return ownerRemovalConfirmed
			}
			return ownerIndeterminate
		}
		anns = p.Annotations
	case "Deployment":
		o, gerr := cs.AppsV1().Deployments(ns).Get(ctx, name, metav1.GetOptions{})
		anns, err = annotationsOrStatus(o.GetAnnotations(), gerr)
		if err != nil {
			return statusFromGetErr(gerr)
		}
	case "ReplicaSet":
		o, gerr := cs.AppsV1().ReplicaSets(ns).Get(ctx, name, metav1.GetOptions{})
		anns, err = annotationsOrStatus(o.GetAnnotations(), gerr)
		if err != nil {
			return statusFromGetErr(gerr)
		}
	case "StatefulSet":
		o, gerr := cs.AppsV1().StatefulSets(ns).Get(ctx, name, metav1.GetOptions{})
		anns, err = annotationsOrStatus(o.GetAnnotations(), gerr)
		if err != nil {
			return statusFromGetErr(gerr)
		}
	case "DaemonSet":
		o, gerr := cs.AppsV1().DaemonSets(ns).Get(ctx, name, metav1.GetOptions{})
		anns, err = annotationsOrStatus(o.GetAnnotations(), gerr)
		if err != nil {
			return statusFromGetErr(gerr)
		}
	case "Job":
		o, gerr := cs.BatchV1().Jobs(ns).Get(ctx, name, metav1.GetOptions{})
		anns, err = annotationsOrStatus(o.GetAnnotations(), gerr)
		if err != nil {
			return statusFromGetErr(gerr)
		}
	case "CronJob":
		o, gerr := cs.BatchV1().CronJobs(ns).Get(ctx, name, metav1.GetOptions{})
		anns, err = annotationsOrStatus(o.GetAnnotations(), gerr)
		if err != nil {
			return statusFromGetErr(gerr)
		}
	default:
		// An owner kind we do not GET (a custom-resource controller): we cannot
		// confirm the owner's annotation directly, so be conservative and treat
		// it as indeterminate (retain the pin) rather than release on an
		// unproven absence.
		return ownerIndeterminate
	}

	if _, present := anns[AnnotationState]; present {
		return ownerStillAnnotated
	}
	return ownerRemovalConfirmed
}

// annotationsOrStatus folds the (annotations, getErr) pair so the per-kind
// branch can early-return a status on a GET error while returning the
// annotations on success. The returned error is non-nil ONLY when gerr is
// non-nil, signalling the caller to map it via statusFromGetErr.
func annotationsOrStatus(anns map[string]string, gerr error) (map[string]string, error) {
	if gerr != nil {
		return nil, gerr
	}
	return anns, nil
}

// statusFromGetErr maps an owner GET error to the conservative release status:
// NotFound is a confirmed removal (the owner is genuinely gone, so it carries
// no annotation); any other (transient) error is indeterminate (retain).
func statusFromGetErr(gerr error) ownerStatus {
	if apierrors.IsNotFound(gerr) {
		return ownerRemovalConfirmed
	}
	return ownerIndeterminate
}

// splitWorkloadID parses a canonical "<namespace>/<kind>/<name>" workload_id
// into its three segments. It returns ok=false when the id does not have
// exactly three non-empty segments (a malformed or orphaned id the caller
// treats conservatively). The name segment may itself be empty-rejected; the
// namespace/kind/name produced by keys.WorkloadID / keys.PodFallbackID always
// satisfy this shape.
func splitWorkloadID(workloadID string) (ns, kind, name string, ok bool) {
	parts := strings.SplitN(workloadID, "/", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}
