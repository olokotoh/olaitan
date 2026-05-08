package applog

import (
	"encoding/json"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

// InjectOptions are the per-call knobs forwarded by the webhook.
type InjectOptions struct {
	// UseNativeSidecar selects the K8s 1.28+ native sidecar pattern
	// (initContainer with restartPolicy: Always per KEP-753). When
	// false, the sidecar is injected into spec.containers.
	UseNativeSidecar bool

	// SidecarImage is the image:tag string for the sidecar container.
	// Required; the webhook surfaces an error for empty values rather
	// than silently injecting a broken pod.
	SidecarImage string

	// Resource knobs (CPU / Memory request and limit). Empty falls
	// back to the chart's documented defaults: 10m / 32Mi requests,
	// 100m / 128Mi limits.
	SidecarCPURequest    string
	SidecarMemoryRequest string
	SidecarCPULimit      string
	SidecarMemoryLimit   string
}

// jsonPatchOp models a single JSON Patch (RFC 6902) operation. Only
// the op/path/value subset we use is serialised; "from" is omitted
// because we never use move/copy.
type jsonPatchOp struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

// Inject returns the JSON Patch byte slice the webhook should attach
// to the AdmissionResponse, or an empty slice when no mutation is
// needed (idempotent re-fire). Returns an error only on structural
// problems with the supplied Pod (e.g. zero containers); failurePolicy
// at the configuration layer is Ignore so the webhook always still
// returns Allowed=true.
//
// The patch (when non-empty) consists of three groups of operations:
//
//  1. Add the sidecar container to either spec.initContainers (native
//     sidecar mode) or spec.containers (fallback mode). The init
//     case sets restartPolicy: Always per KEP-753 so the kubelet
//     treats it as a sidecar, not a startup-only init.
//  2. Add the shared emptyDir volume to spec.volumes.
//  3. Add the volumeMount to the targeted peer container's
//     volumeMounts.
//
// When the destination collection is currently nil/missing on the
// Pod, the patch first creates the empty collection: a JSON Patch
// "add" against `/spec/initContainers/-` requires the parent array
// to already exist, so we bracket with an explicit `add /spec/initContainers
// []` when needed.
//
// Idempotency: if a container named SidecarContainerName already
// exists in either initContainers or containers, Inject returns nil
// (empty patch). The webhook safely re-fires without duplicating the
// sidecar.
func Inject(pod *corev1.Pod, opts InjectOptions) ([]byte, error) {
	if pod == nil {
		return nil, errors.New("applog/inject: nil pod")
	}
	if opts.SidecarImage == "" {
		return nil, errors.New("applog/inject: empty sidecar image")
	}

	// Idempotency check.
	if alreadyInjected(pod) {
		return nil, nil
	}

	peerIdx, err := selectPeerContainer(pod)
	if err != nil {
		return nil, err
	}

	sidecar := buildSidecarContainer(opts)

	ops := make([]jsonPatchOp, 0, 6)

	// Step 1: ensure the destination container collection exists,
	// then append the sidecar.
	if opts.UseNativeSidecar {
		if pod.Spec.InitContainers == nil {
			ops = append(ops, jsonPatchOp{Op: "add", Path: "/spec/initContainers", Value: []corev1.Container{}})
		}
		ops = append(ops, jsonPatchOp{Op: "add", Path: "/spec/initContainers/-", Value: sidecar})
	} else {
		// containers is required to be non-empty by Pod validation,
		// so the array always exists; no defensive create needed.
		ops = append(ops, jsonPatchOp{Op: "add", Path: "/spec/containers/-", Value: sidecar})
	}

	// Step 2: ensure spec.volumes exists, then add the shared emptyDir.
	sharedVolume := corev1.Volume{
		Name: SharedVolumeName,
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	}
	if pod.Spec.Volumes == nil {
		ops = append(ops, jsonPatchOp{Op: "add", Path: "/spec/volumes", Value: []corev1.Volume{}})
	}
	ops = append(ops, jsonPatchOp{Op: "add", Path: "/spec/volumes/-", Value: sharedVolume})

	// Step 3: mount the shared volume into the peer container.
	mount := corev1.VolumeMount{
		Name:      SharedVolumeName,
		MountPath: SharedVolumeMountPath,
	}
	peer := pod.Spec.Containers[peerIdx]
	if peer.VolumeMounts == nil {
		ops = append(ops, jsonPatchOp{Op: "add",
			Path:  fmt.Sprintf("/spec/containers/%d/volumeMounts", peerIdx),
			Value: []corev1.VolumeMount{}})
	}
	ops = append(ops, jsonPatchOp{Op: "add",
		Path:  fmt.Sprintf("/spec/containers/%d/volumeMounts/-", peerIdx),
		Value: mount})

	return json.Marshal(ops)
}

// alreadyInjected returns true when a container named
// SidecarContainerName already exists in either spec.initContainers or
// spec.containers. Idempotent re-fire from another mutating webhook is
// safe.
func alreadyInjected(pod *corev1.Pod) bool {
	for _, c := range pod.Spec.InitContainers {
		if c.Name == SidecarContainerName {
			return true
		}
	}
	for _, c := range pod.Spec.Containers {
		if c.Name == SidecarContainerName {
			return true
		}
	}
	return false
}

// selectPeerContainer returns the index into pod.Spec.Containers of
// the peer application container the sidecar is targeting. The
// olaitan.io/log-sidecar-container annotation, when present, names a
// specific container; otherwise the first container in the list is
// chosen.
//
// Returns an error when the Pod has zero containers (a structural
// invariant violation; the apiserver would reject such a Pod
// independently, but we surface a clear error rather than panic).
func selectPeerContainer(pod *corev1.Pod) (int, error) {
	if len(pod.Spec.Containers) == 0 {
		return 0, errors.New("applog/inject: pod has zero containers")
	}
	if name, ok := pod.Annotations[AnnotationTargetContainer]; ok && name != "" {
		for i, c := range pod.Spec.Containers {
			if c.Name == name {
				return i, nil
			}
		}
		return 0, fmt.Errorf("applog/inject: target container %q not found in spec.containers", name)
	}
	return 0, nil
}

// buildSidecarContainer constructs the corev1.Container spec the
// patch will inject. The structure is constant per opts (no
// per-Pod customisation beyond resources and image); the
// downward-API env vars carry the per-pod identity.
func buildSidecarContainer(opts InjectOptions) corev1.Container {
	c := corev1.Container{
		Name:  SidecarContainerName,
		Image: opts.SidecarImage,
		Args:  []string{"applog-sidecar"},
		Env: []corev1.EnvVar{
			{Name: "K8S_POD_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}},
			{Name: "K8S_POD_NAMESPACE", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"}}},
			{Name: "K8S_POD_UID", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.uid"}}},
			{Name: "K8S_NODE_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"}}},
			{Name: "OLAITAN_TARGET_CONTAINER", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{
				FieldPath: fmt.Sprintf("metadata.annotations['%s']", AnnotationTargetContainer),
			}}},
		},
		VolumeMounts: []corev1.VolumeMount{
			{Name: SharedVolumeName, MountPath: SharedVolumeMountPath, ReadOnly: true},
		},
		Resources: buildResourceRequirements(opts),
		SecurityContext: &corev1.SecurityContext{
			RunAsNonRoot:             ptrTrue(),
			ReadOnlyRootFilesystem:   ptrTrue(),
			AllowPrivilegeEscalation: ptrFalse(),
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		},
	}
	if opts.UseNativeSidecar {
		// KEP-753: native sidecar requires restartPolicy: Always set
		// on the initContainer. The Always pointer below is recognised
		// by the K8s 1.28+ apiserver when the SidecarContainers
		// feature gate is enabled (default-on in 1.29).
		policy := corev1.ContainerRestartPolicyAlways
		c.RestartPolicy = &policy
	}
	return c
}

// buildResourceRequirements assembles ResourceRequirements from the
// opts; empty strings fall back to the documented defaults.
func buildResourceRequirements(opts InjectOptions) corev1.ResourceRequirements {
	requests := corev1.ResourceList{}
	limits := corev1.ResourceList{}
	if v := opts.SidecarCPURequest; v != "" {
		if q, err := resource.ParseQuantity(v); err == nil {
			requests[corev1.ResourceCPU] = q
		}
	} else {
		requests[corev1.ResourceCPU] = resource.MustParse("10m")
	}
	if v := opts.SidecarMemoryRequest; v != "" {
		if q, err := resource.ParseQuantity(v); err == nil {
			requests[corev1.ResourceMemory] = q
		}
	} else {
		requests[corev1.ResourceMemory] = resource.MustParse("32Mi")
	}
	if v := opts.SidecarCPULimit; v != "" {
		if q, err := resource.ParseQuantity(v); err == nil {
			limits[corev1.ResourceCPU] = q
		}
	} else {
		limits[corev1.ResourceCPU] = resource.MustParse("100m")
	}
	if v := opts.SidecarMemoryLimit; v != "" {
		if q, err := resource.ParseQuantity(v); err == nil {
			limits[corev1.ResourceMemory] = q
		}
	} else {
		limits[corev1.ResourceMemory] = resource.MustParse("128Mi")
	}
	return corev1.ResourceRequirements{Requests: requests, Limits: limits}
}

func ptrTrue() *bool  { v := true; return &v }
func ptrFalse() *bool { v := false; return &v }
