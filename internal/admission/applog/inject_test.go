package applog

import (
	"encoding/json"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func samplePod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "payments-7f8b9c",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationEnable: AnnotationValueEnabled,
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "payments", Image: "myreg/payments:1.0"},
			},
		},
	}
}

func defaultInjectOpts() InjectOptions {
	return InjectOptions{
		UseNativeSidecar: true,
		SidecarImage:     "ghcr.io/olokotoh/olaitan:dev",
	}
}

func TestInject_HappyPath(t *testing.T) {
	pod := samplePod()
	patch, err := Inject(pod, defaultInjectOpts())
	if err != nil {
		t.Fatalf("Inject: %v", err)
	}
	if len(patch) == 0 {
		t.Fatal("expected non-empty patch")
	}
	var ops []jsonPatchOp
	if err := json.Unmarshal(patch, &ops); err != nil {
		t.Fatalf("unmarshal patch: %v", err)
	}
	if len(ops) < 3 {
		t.Errorf("expected >= 3 ops, got %d", len(ops))
	}
}

func TestInject_NoAnnotation_Skipped(t *testing.T) {
	// Inject does not check the annotation -- the webhook handler
	// does. So passing a no-annotation pod through Inject does still
	// return a patch. This test instead verifies the webhook
	// handler's annotationEnabled gate.
	enabled, deprecated := annotationEnabled(nil)
	if enabled {
		t.Errorf("nil annotations: enabled should be false")
	}
	if deprecated {
		t.Errorf("nil annotations: deprecated should be false")
	}

	enabled, _ = annotationEnabled(map[string]string{"other": "thing"})
	if enabled {
		t.Errorf("non-matching annotations: enabled should be false")
	}
}

func TestInject_DeprecatedKey_AcceptedAsAlias(t *testing.T) {
	enabled, deprecated := annotationEnabled(map[string]string{
		AnnotationEnableDeprecated: AnnotationValueEnabled,
	})
	if !enabled {
		t.Errorf("deprecated annotation: enabled should be true")
	}
	if !deprecated {
		t.Errorf("deprecated annotation: deprecated should be true")
	}
}

func TestInject_CanonicalKeyTakesPrecedence(t *testing.T) {
	enabled, deprecated := annotationEnabled(map[string]string{
		AnnotationEnable:           AnnotationValueEnabled,
		AnnotationEnableDeprecated: AnnotationValueEnabled,
	})
	if !enabled {
		t.Errorf("both keys present: enabled should be true")
	}
	if deprecated {
		t.Errorf("canonical key takes precedence: deprecated should be false")
	}
}

func TestInject_Idempotent(t *testing.T) {
	pod := samplePod()
	pod.Spec.InitContainers = []corev1.Container{
		{Name: SidecarContainerName, Image: "stale-image"},
	}
	patch, err := Inject(pod, defaultInjectOpts())
	if err != nil {
		t.Fatalf("Inject: %v", err)
	}
	if patch != nil {
		t.Errorf("idempotent re-fire: expected nil patch, got %s", patch)
	}
}

func TestInject_NativeSidecarPatchShape(t *testing.T) {
	pod := samplePod()
	opts := defaultInjectOpts()
	opts.UseNativeSidecar = true
	patch, err := Inject(pod, opts)
	if err != nil {
		t.Fatalf("Inject: %v", err)
	}
	var ops []jsonPatchOp
	if err := json.Unmarshal(patch, &ops); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Find the op that adds the sidecar container.
	var sidecarOp *jsonPatchOp
	for i := range ops {
		if ops[i].Path == "/spec/initContainers/-" {
			sidecarOp = &ops[i]
			break
		}
	}
	if sidecarOp == nil {
		t.Fatalf("native sidecar mode did not target /spec/initContainers/-: ops=%+v", ops)
	}
	// Re-marshal the value into a corev1.Container to verify
	// restartPolicy: Always.
	body, err := json.Marshal(sidecarOp.Value)
	if err != nil {
		t.Fatalf("marshal sidecar: %v", err)
	}
	var c corev1.Container
	if err := json.Unmarshal(body, &c); err != nil {
		t.Fatalf("decode sidecar: %v", err)
	}
	if c.RestartPolicy == nil || *c.RestartPolicy != corev1.ContainerRestartPolicyAlways {
		t.Errorf("native sidecar must set RestartPolicy=Always, got %v", c.RestartPolicy)
	}
}

func TestInject_ForwardsRateLimitEnv(t *testing.T) {
	pod := samplePod()
	opts := defaultInjectOpts()
	opts.SidecarRateLimitEnabled = "true"
	opts.SidecarRateLimitThreshold = "500"
	opts.SidecarRateLimitCooldown = "30"
	opts.SidecarRateLimitSampling = "0.005"

	patch, err := Inject(pod, opts)
	if err != nil {
		t.Fatalf("Inject: %v", err)
	}
	var ops []jsonPatchOp
	if err := json.Unmarshal(patch, &ops); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	sidecar := decodeInjectedSidecar(t, ops, "/spec/initContainers/-")
	env := map[string]string{}
	for _, e := range sidecar.Env {
		env[e.Name] = e.Value
	}
	want := map[string]string{
		"OLAITAN_RATE_LIMIT_ENABLED":                  "true",
		"OLAITAN_RATE_LIMIT_THRESHOLD_EVENTS_PER_SEC": "500",
		"OLAITAN_RATE_LIMIT_COOLDOWN_SECONDS":         "30",
		"OLAITAN_RATE_LIMIT_SAMPLING_RATE":            "0.005",
	}
	for k, v := range want {
		if env[k] != v {
			t.Errorf("env[%s]: got %q, want %q", k, env[k], v)
		}
	}
}

func TestInject_FallbackToContainers_WhenNativeSidecarDisabled(t *testing.T) {
	pod := samplePod()
	opts := defaultInjectOpts()
	opts.UseNativeSidecar = false
	patch, err := Inject(pod, opts)
	if err != nil {
		t.Fatalf("Inject: %v", err)
	}
	var ops []jsonPatchOp
	if err := json.Unmarshal(patch, &ops); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, op := range ops {
		if op.Path == "/spec/initContainers/-" {
			t.Errorf("fallback mode should NOT add to initContainers; ops=%+v", ops)
		}
	}
	found := false
	for _, op := range ops {
		if op.Path == "/spec/containers/-" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("fallback mode must add to /spec/containers/-, ops=%+v", ops)
	}
}

func decodeInjectedSidecar(t *testing.T, ops []jsonPatchOp, path string) corev1.Container {
	t.Helper()
	for i := range ops {
		if ops[i].Path != path {
			continue
		}
		body, err := json.Marshal(ops[i].Value)
		if err != nil {
			t.Fatalf("marshal sidecar: %v", err)
		}
		var c corev1.Container
		if err := json.Unmarshal(body, &c); err != nil {
			t.Fatalf("decode sidecar: %v", err)
		}
		return c
	}
	t.Fatalf("sidecar op %q not found: ops=%+v", path, ops)
	return corev1.Container{}
}

func TestInject_VolumeMountedOnPeerContainer(t *testing.T) {
	pod := samplePod()
	patch, err := Inject(pod, defaultInjectOpts())
	if err != nil {
		t.Fatalf("Inject: %v", err)
	}
	var ops []jsonPatchOp
	if err := json.Unmarshal(patch, &ops); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	found := false
	for _, op := range ops {
		if op.Path == "/spec/containers/0/volumeMounts/-" || op.Path == "/spec/containers/0/volumeMounts" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected volumeMount on /spec/containers/0/volumeMounts; ops=%+v", ops)
	}
}

func TestInject_TwoAppContainers_TargetsAnnotated(t *testing.T) {
	pod := samplePod()
	pod.Spec.Containers = []corev1.Container{
		{Name: "primary", Image: "p:1"},
		{Name: "helper", Image: "h:1"},
	}
	pod.Annotations[AnnotationTargetContainer] = "helper"

	patch, err := Inject(pod, defaultInjectOpts())
	if err != nil {
		t.Fatalf("Inject: %v", err)
	}
	var ops []jsonPatchOp
	if err := json.Unmarshal(patch, &ops); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, op := range ops {
		if op.Path == "/spec/containers/0/volumeMounts/-" {
			t.Errorf("targeted helper but mount landed on container 0; ops=%+v", ops)
		}
	}
	wantPath := "/spec/containers/1/volumeMounts/-"
	found := false
	for _, op := range ops {
		if op.Path == wantPath {
			found = true
		}
	}
	if !found {
		t.Errorf("expected mount on %q; ops=%+v", wantPath, ops)
	}
}

func TestInject_ExistingVolumesArray_Preserved(t *testing.T) {
	pod := samplePod()
	pod.Spec.Volumes = []corev1.Volume{
		{Name: "config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{}}},
	}
	patch, err := Inject(pod, defaultInjectOpts())
	if err != nil {
		t.Fatalf("Inject: %v", err)
	}
	var ops []jsonPatchOp
	if err := json.Unmarshal(patch, &ops); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, op := range ops {
		if op.Path == "/spec/volumes" {
			t.Errorf("must NOT recreate /spec/volumes when already present; ops=%+v", ops)
		}
	}
	want := "/spec/volumes/-"
	found := false
	for _, op := range ops {
		if op.Path == want {
			found = true
		}
	}
	if !found {
		t.Errorf("expected volume add at %q; ops=%+v", want, ops)
	}
}

func TestInject_ZeroContainers_Errors(t *testing.T) {
	pod := samplePod()
	pod.Spec.Containers = nil
	_, err := Inject(pod, defaultInjectOpts())
	if err == nil {
		t.Error("expected error on zero containers")
	}
}

func TestInject_TargetContainerNotFound_Errors(t *testing.T) {
	pod := samplePod()
	pod.Annotations[AnnotationTargetContainer] = "no-such-container"
	_, err := Inject(pod, defaultInjectOpts())
	if err == nil {
		t.Error("expected error when target container annotation does not match any container")
	}
}

func TestInject_EmptyImage_Errors(t *testing.T) {
	pod := samplePod()
	opts := defaultInjectOpts()
	opts.SidecarImage = ""
	_, err := Inject(pod, opts)
	if err == nil {
		t.Error("expected error on empty sidecar image")
	}
}

func TestInject_NilPod_Errors(t *testing.T) {
	_, err := Inject(nil, defaultInjectOpts())
	if err == nil {
		t.Error("expected error on nil pod")
	}
}
