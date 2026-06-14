package forensics

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

// TestCaptureFallback_AssemblesBundle confirms the bundle contains pod.json and
// per-container current/previous logs, and is a valid gzip-tar.
func TestCaptureFallback_AssemblesBundle(t *testing.T) {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "web-abc", Labels: map[string]string{"app": "web"}},
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{Name: "init"}},
			Containers:     []corev1.Container{{Name: "app"}, {Name: "sidecar"}},
		},
	}
	cs := fake.NewSimpleClientset(runtime.Object(p))

	bundle, err := captureFallback(context.Background(), cs, "ns", "web-abc")
	if err != nil {
		t.Fatalf("captureFallback: %v", err)
	}
	files := readBundle(t, bundle)

	if _, ok := files["meta/pod.json"]; !ok {
		t.Fatalf("bundle missing meta/pod.json: %v keys", keys(files))
	}
	// The fake clientset serves a synthetic log stream for GetLogs, so every
	// container has a current log file.
	for _, c := range []string{"app", "sidecar", "init"} {
		if _, ok := files["logs/"+c+".current.log"]; !ok {
			t.Fatalf("bundle missing logs/%s.current.log: %v", c, keys(files))
		}
	}
	// pod.json must contain the pod name.
	if !strings.Contains(string(files["meta/pod.json"]), "web-abc") {
		t.Fatalf("pod.json does not contain pod name")
	}
}

// TestCaptureFallback_PodNotFound surfaces a NotFound from Get.
func TestCaptureFallback_PodNotFound(t *testing.T) {
	cs := fake.NewSimpleClientset()
	if _, err := captureFallback(context.Background(), cs, "ns", "missing"); err == nil {
		t.Fatal("captureFallback on missing pod: want error, got nil")
	}
}

// TestBundleKey_ContentAddressed confirms the key is deterministic for identical
// content and differs for different content (Open Assumption 3 / BI-7).
func TestBundleKey_ContentAddressed(t *testing.T) {
	a := []byte("forensic-bundle-bytes-A")
	b := []byte("forensic-bundle-bytes-B")

	k1, s1 := bundleKey(a)
	k2, s2 := bundleKey(a)
	k3, s3 := bundleKey(b)

	if k1 != k2 || s1 != s2 {
		t.Fatalf("same content gave different keys: %q vs %q", k1, k2)
	}
	if k1 == k3 || s1 == s3 {
		t.Fatalf("different content gave same key: %q", k1)
	}
	if !strings.HasPrefix(k1, "forensic-bundles/") || !strings.HasSuffix(k1, "/forensic-bundle.tar.gz") {
		t.Fatalf("unexpected key shape: %q", k1)
	}
	if !strings.Contains(k1, s1) {
		t.Fatalf("key %q does not embed sha %q", k1, s1)
	}
}

// TestContainerNames_SortedUnion confirms init+regular+ephemeral names are
// deduped and sorted for a deterministic bundle layout.
func TestContainerNames_SortedUnion(t *testing.T) {
	p := &corev1.Pod{Spec: corev1.PodSpec{
		Containers:     []corev1.Container{{Name: "z"}, {Name: "a"}},
		InitContainers: []corev1.Container{{Name: "m"}},
	}}
	got := containerNames(p)
	want := []string{"a", "m", "z"}
	if len(got) != len(want) {
		t.Fatalf("names = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("names = %v, want %v", got, want)
		}
	}
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
