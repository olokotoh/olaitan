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

	// Sidecar runtime knobs forwarded from the chart through the
	// webhook's env into the injected sidecar container as
	// OLAITAN_APPLOG_* env vars. Empty falls back to the adapter's
	// compiled defaults. Stringly-typed so the chart can pass
	// duration / int values verbatim; the adapter parses on start-up.
	SidecarStdoutPath          string
	SidecarStderrPath          string
	SidecarChannelBuffer       string
	SidecarMaxLineBytes        string
	SidecarPublishStallTimeout string
	SidecarStalenessTimeout    string
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

	// Pass the resolved peer container name into the sidecar build so
	// OLAITAN_TARGET_CONTAINER is set deterministically rather than
	// relying on the downward-API fieldRef to an annotation that may
	// or may not be present (the common case is no annotation, where
	// the field-ref resolves to empty and the sidecar fails-fast on
	// start-up).
	peerContainerName := pod.Spec.Containers[peerIdx].Name
	sidecar, err := buildSidecarContainer(opts, peerContainerName)
	if err != nil {
		return nil, err
	}

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

	// Step 2: ensure spec.volumes exists, then add the shared emptyDir
	// only if no volume of the same name is already present. The
	// duplicate-name check protects against another mutating webhook
	// (or operator hand-edit) that already added the volume; appending
	// twice would make the apiserver reject the Pod with "duplicate
	// volume name".
	if !hasVolumeNamed(pod, SharedVolumeName) {
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
	}

	// Step 3: mount the shared volume into the peer container, again
	// guarding against an existing mount at the same path (a previous
	// admission cycle, or operator hand-edit, may already have wired
	// it in). The peer mount is intentionally read-write (the default
	// when ReadOnly is unset): the cooperation contract documented in
	// APPLOG.md requires the application container to write its
	// stdout/stderr to /var/log/app/stdout.log and stderr.log, which
	// the sidecar then tails read-only. The repo's general
	// read-only-mount preference does not apply here because making
	// this mount read-only would break the FR5 ingest path.
	peer := pod.Spec.Containers[peerIdx]
	if !hasMountAtPath(peer.VolumeMounts, SharedVolumeMountPath) {
		mount := corev1.VolumeMount{
			Name:      SharedVolumeName,
			MountPath: SharedVolumeMountPath,
		}
		if peer.VolumeMounts == nil {
			ops = append(ops, jsonPatchOp{Op: "add",
				Path:  fmt.Sprintf("/spec/containers/%d/volumeMounts", peerIdx),
				Value: []corev1.VolumeMount{}})
		}
		ops = append(ops, jsonPatchOp{Op: "add",
			Path:  fmt.Sprintf("/spec/containers/%d/volumeMounts/-", peerIdx),
			Value: mount})
	}

	return json.Marshal(ops)
}

// hasVolumeNamed reports whether pod.Spec.Volumes already contains a
// volume of the given name. Used in Inject's idempotency guard so a
// re-fire does not append a duplicate volume entry (the apiserver
// rejects duplicate volume names with a clear error, but we should
// not generate the invalid patch in the first place).
func hasVolumeNamed(pod *corev1.Pod, name string) bool {
	for _, v := range pod.Spec.Volumes {
		if v.Name == name {
			return true
		}
	}
	return false
}

// hasMountAtPath reports whether mounts already includes an entry at
// the given mount path. Used by Inject to guard against duplicate
// peer-container mounts on re-fire.
func hasMountAtPath(mounts []corev1.VolumeMount, path string) bool {
	for _, m := range mounts {
		if m.MountPath == path {
			return true
		}
	}
	return false
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
//
// peerContainerName is the resolved name of the application container
// the sidecar is targeting; it is set into the OLAITAN_TARGET_CONTAINER
// env var as a literal value rather than via a downward-API fieldRef
// to an annotation, because the common case is that no annotation is
// present and the field-ref would resolve to empty (which would then
// fail-fast in the sidecar's startup guard).
func buildSidecarContainer(opts InjectOptions, peerContainerName string) (corev1.Container, error) {
	env := []corev1.EnvVar{
		{Name: "K8S_POD_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}},
		{Name: "K8S_POD_NAMESPACE", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"}}},
		{Name: "K8S_POD_UID", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.uid"}}},
		{Name: "K8S_NODE_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"}}},
		{Name: "OLAITAN_TARGET_CONTAINER", Value: peerContainerName},
	}
	// Forward chart-tuned sidecar runtime knobs. Empty values are not
	// emitted so the adapter's compiled defaults stay in force.
	if v := opts.SidecarStdoutPath; v != "" {
		env = append(env, corev1.EnvVar{Name: "OLAITAN_APPLOG_STDOUT_PATH", Value: v})
	}
	if v := opts.SidecarStderrPath; v != "" {
		env = append(env, corev1.EnvVar{Name: "OLAITAN_APPLOG_STDERR_PATH", Value: v})
	}
	if v := opts.SidecarChannelBuffer; v != "" {
		env = append(env, corev1.EnvVar{Name: "OLAITAN_APPLOG_CHANNEL_BUFFER", Value: v})
	}
	if v := opts.SidecarMaxLineBytes; v != "" {
		env = append(env, corev1.EnvVar{Name: "OLAITAN_APPLOG_MAX_LINE_BYTES", Value: v})
	}
	if v := opts.SidecarPublishStallTimeout; v != "" {
		env = append(env, corev1.EnvVar{Name: "OLAITAN_APPLOG_PUBLISH_STALL_TIMEOUT", Value: v})
	}
	if v := opts.SidecarStalenessTimeout; v != "" {
		env = append(env, corev1.EnvVar{Name: "OLAITAN_APPLOG_STALENESS_TIMEOUT", Value: v})
	}

	resources, err := buildResourceRequirements(opts)
	if err != nil {
		return corev1.Container{}, err
	}
	c := corev1.Container{
		Name:  SidecarContainerName,
		Image: opts.SidecarImage,
		// Set Command explicitly so the contract does not depend on
		// the Dockerfile's ENTRYPOINT (a future image-build refactor
		// that wraps the binary in a launcher script would otherwise
		// silently break the sidecar). Args carries the multi-call
		// subcommand the binary dispatches on.
		Command: []string{"olaitan"},
		Args:    []string{"applog-sidecar"},
		Env:     env,
		VolumeMounts: []corev1.VolumeMount{
			{Name: SharedVolumeName, MountPath: SharedVolumeMountPath, ReadOnly: true},
		},
		Resources: resources,
		SecurityContext: &corev1.SecurityContext{
			// Pod Security Standards "restricted" baseline plus the
			// nonroot UID/GID pair from the distroless image. Without
			// these explicit values the sidecar would inherit the
			// peer container's PodSecurityContext, which an operator
			// running a privileged workload might have widened.
			SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			RunAsNonRoot:             ptrTrue(),
			RunAsUser:                ptrInt64(65532),
			RunAsGroup:               ptrInt64(65532),
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
	return c, nil
}

// ptrInt64 returns a pointer to the supplied int64. Used for
// SecurityContext numeric fields that take *int64 to distinguish unset
// from zero.
func ptrInt64(v int64) *int64 { return &v }

// buildResourceRequirements assembles ResourceRequirements from the
// opts; empty strings fall back to the documented defaults. A
// non-empty value that fails resource.ParseQuantity is surfaced as an
// error so the webhook fails the admission request loudly instead of
// silently injecting empty Requests/Limits (which would behave very
// differently from the documented defaults and is hard to diagnose
// after the fact).
func buildResourceRequirements(opts InjectOptions) (corev1.ResourceRequirements, error) {
	requests := corev1.ResourceList{}
	limits := corev1.ResourceList{}
	parse := func(field, val, fallback string) (resource.Quantity, error) {
		if val == "" {
			return resource.MustParse(fallback), nil
		}
		q, err := resource.ParseQuantity(val)
		if err != nil {
			return resource.Quantity{}, fmt.Errorf("applog/inject: invalid %s quantity %q: %w", field, val, err)
		}
		return q, nil
	}
	q, err := parse("SidecarCPURequest", opts.SidecarCPURequest, "10m")
	if err != nil {
		return corev1.ResourceRequirements{}, err
	}
	requests[corev1.ResourceCPU] = q
	q, err = parse("SidecarMemoryRequest", opts.SidecarMemoryRequest, "32Mi")
	if err != nil {
		return corev1.ResourceRequirements{}, err
	}
	requests[corev1.ResourceMemory] = q
	q, err = parse("SidecarCPULimit", opts.SidecarCPULimit, "100m")
	if err != nil {
		return corev1.ResourceRequirements{}, err
	}
	limits[corev1.ResourceCPU] = q
	q, err = parse("SidecarMemoryLimit", opts.SidecarMemoryLimit, "128Mi")
	if err != nil {
		return corev1.ResourceRequirements{}, err
	}
	limits[corev1.ResourceMemory] = q
	return corev1.ResourceRequirements{Requests: requests, Limits: limits}, nil
}

func ptrTrue() *bool  { v := true; return &v }
func ptrFalse() *bool { v := false; return &v }
