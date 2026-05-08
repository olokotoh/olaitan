package applog

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

func newTestWebhook(t *testing.T) *Webhook {
	t.Helper()
	cfg := WebhookConfig{
		ListenAddr:       ":0",
		TLSCertFile:      "/tmp/test.crt",
		TLSKeyFile:       "/tmp/test.key",
		UseNativeSidecar: true,
		SidecarImage:     "ghcr.io/olokotoh/olaitan:dev",
	}
	w, err := NewWebhook(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewWebhook: %v", err)
	}
	return w
}

func newAdmissionReview(pod *corev1.Pod) *admissionv1.AdmissionReview {
	raw, _ := json.Marshal(pod)
	return &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Request: &admissionv1.AdmissionRequest{
			UID:       types.UID("test-uid"),
			Namespace: pod.Namespace,
			Object:    runtime.RawExtension{Raw: raw},
		},
	}
}

func sendReview(t *testing.T, w *Webhook, review *admissionv1.AdmissionReview) *admissionv1.AdmissionResponse {
	t.Helper()
	body, err := json.Marshal(review)
	if err != nil {
		t.Fatalf("marshal review: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/mutate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	w.handleMutate(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d body=%s", rr.Code, rr.Body.String())
	}
	var out admissionv1.AdmissionReview
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.Response == nil {
		t.Fatalf("nil response")
	}
	return out.Response
}

func TestWebhookHandler_DecodesAdmissionReviewV1(t *testing.T) {
	w := newTestWebhook(t)
	pod := samplePod()
	resp := sendReview(t, w, newAdmissionReview(pod))
	if !resp.Allowed {
		t.Errorf("expected Allowed=true")
	}
	if resp.Patch == nil {
		t.Errorf("expected non-nil patch for annotated pod")
	}
	if resp.PatchType == nil || *resp.PatchType != admissionv1.PatchTypeJSONPatch {
		t.Errorf("PatchType: got %v want JSONPatch", resp.PatchType)
	}
}

func TestWebhookHandler_NoAnnotation_Allows_NoPatch(t *testing.T) {
	w := newTestWebhook(t)
	pod := samplePod()
	pod.Annotations = nil
	resp := sendReview(t, w, newAdmissionReview(pod))
	if !resp.Allowed {
		t.Errorf("expected Allowed=true for non-annotated pod")
	}
	if resp.Patch != nil {
		t.Errorf("expected nil patch for non-annotated pod, got %s", resp.Patch)
	}
}

func TestWebhookHandler_DeprecatedKey_StillInjects(t *testing.T) {
	w := newTestWebhook(t)
	pod := samplePod()
	pod.Annotations = map[string]string{AnnotationEnableDeprecated: AnnotationValueEnabled}
	resp := sendReview(t, w, newAdmissionReview(pod))
	if resp.Patch == nil {
		t.Errorf("expected patch for deprecated annotation")
	}
	if w.DeprecatedKeyHits() == 0 {
		t.Errorf("DeprecatedKeyHits counter not incremented")
	}
}

func TestWebhookHandler_KubeSystemNamespace_NotInjected(t *testing.T) {
	w := newTestWebhook(t)
	pod := samplePod()
	pod.Namespace = "kube-system"
	review := newAdmissionReview(pod)
	review.Request.Namespace = "kube-system"
	resp := sendReview(t, w, review)
	if resp.Patch != nil {
		t.Errorf("expected nil patch for kube-system pod")
	}
}

func TestWebhookHandler_KubePublic_NotInjected(t *testing.T) {
	w := newTestWebhook(t)
	pod := samplePod()
	pod.Namespace = "kube-public"
	review := newAdmissionReview(pod)
	review.Request.Namespace = "kube-public"
	resp := sendReview(t, w, review)
	if resp.Patch != nil {
		t.Errorf("expected nil patch for kube-public pod")
	}
}

func TestWebhookHandler_RejectsNonPost(t *testing.T) {
	w := newTestWebhook(t)
	req := httptest.NewRequest(http.MethodGet, "/mutate", nil)
	rr := httptest.NewRecorder()
	w.handleMutate(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("got %d want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestWebhookHandler_RejectsNonJSON(t *testing.T) {
	w := newTestWebhook(t)
	req := httptest.NewRequest(http.MethodPost, "/mutate", bytes.NewReader([]byte("not-json")))
	req.Header.Set("Content-Type", "text/plain")
	rr := httptest.NewRecorder()
	w.handleMutate(rr, req)
	if rr.Code != http.StatusUnsupportedMediaType {
		t.Errorf("got %d want %d", rr.Code, http.StatusUnsupportedMediaType)
	}
}

func TestWebhookHandler_HealthzOK(t *testing.T) {
	w := newTestWebhook(t)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	w.mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("got %d want 200", rr.Code)
	}
}

func TestNewWebhook_RejectsEmptyTLSCert(t *testing.T) {
	cfg := WebhookConfig{TLSKeyFile: "/k", SidecarImage: "x"}
	_, err := NewWebhook(cfg, nil)
	if err == nil {
		t.Error("expected error for empty TLSCertFile")
	}
}

func TestNewWebhook_RejectsEmptySidecarImage(t *testing.T) {
	cfg := WebhookConfig{TLSCertFile: "/c", TLSKeyFile: "/k"}
	_, err := NewWebhook(cfg, nil)
	if err == nil {
		t.Error("expected error for empty SidecarImage")
	}
}

func TestWebhookHandler_RequestsTotal_Increments(t *testing.T) {
	w := newTestWebhook(t)
	pod := samplePod()
	before := w.RequestsTotal()
	_ = sendReview(t, w, newAdmissionReview(pod))
	if w.RequestsTotal() <= before {
		t.Errorf("RequestsTotal did not increment: before=%d after=%d", before, w.RequestsTotal())
	}
}

func TestWebhookHandler_InjectedTotal_Increments(t *testing.T) {
	w := newTestWebhook(t)
	pod := samplePod()
	before := w.InjectedTotal()
	_ = sendReview(t, w, newAdmissionReview(pod))
	if w.InjectedTotal() <= before {
		t.Errorf("InjectedTotal did not increment: before=%d after=%d", before, w.InjectedTotal())
	}
}

func TestWebhookHandler_SkippedTotal_IncrementsOnNoAnnotation(t *testing.T) {
	w := newTestWebhook(t)
	pod := samplePod()
	pod.Annotations = nil
	before := w.SkippedTotal()
	_ = sendReview(t, w, newAdmissionReview(pod))
	if w.SkippedTotal() <= before {
		t.Errorf("SkippedTotal did not increment: before=%d after=%d", before, w.SkippedTotal())
	}
}
