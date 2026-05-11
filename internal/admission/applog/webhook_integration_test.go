//go:build integration

package applog

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

// generateTestTLSCert writes a self-signed cert + key into a temp dir
// and returns the file paths. Used by the integration test to drive
// the real ListenAndServeTLS path on a free port.
func generateTestTLSCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "applog-webhook-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	dir := t.TempDir()
	certFile = filepath.Join(dir, "tls.crt")
	keyFile = filepath.Join(dir, "tls.key")
	cf, err := os.Create(certFile)
	if err != nil {
		t.Fatalf("cert file: %v", err)
	}
	if err := pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		t.Fatalf("encode cert: %v", err)
	}
	_ = cf.Close()
	kf, err := os.Create(keyFile)
	if err != nil {
		t.Fatalf("key file: %v", err)
	}
	if err := pem.Encode(kf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		t.Fatalf("encode key: %v", err)
	}
	_ = kf.Close()
	return certFile, keyFile
}

// TestIntegration_WebhookOverRealTLS drives the full handler path
// over httptest.NewTLSServer, asserting the AdmissionReview wire
// format (admissionv1) round-trips correctly. NFR36 anti-mock: no
// mock decoder, no mock encoder; the K8s admissionv1 types and
// json.Unmarshal are real.
func TestIntegration_WebhookOverRealTLS(t *testing.T) {
	cfg := WebhookConfig{
		ListenAddr:       ":0",
		TLSCertFile:      "/tmp/unused.crt",
		TLSKeyFile:       "/tmp/unused.key",
		UseNativeSidecar: true,
		SidecarImage:     "ghcr.io/olokotoh/olaitan:dev",
	}
	w, err := NewWebhook(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewWebhook: %v", err)
	}

	srv := httptest.NewTLSServer(w.Mux())
	defer srv.Close()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "payments-7f8b9c",
			Namespace:   "default",
			Annotations: map[string]string{AnnotationEnable: AnnotationValueEnabled},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "payments", Image: "p:1"}},
		},
	}
	raw, _ := json.Marshal(pod)
	review := &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request: &admissionv1.AdmissionRequest{
			UID:       types.UID("test-uid"),
			Namespace: "default",
			Object:    runtime.RawExtension{Raw: raw},
		},
	}
	body, _ := json.Marshal(review)

	client := srv.Client()
	client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}} //nolint:gosec
	resp, err := client.Post(srv.URL+"/mutate", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bodyText, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, bodyText)
	}
	var out admissionv1.AdmissionReview
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Response == nil || !out.Response.Allowed {
		t.Fatalf("expected Allowed response, got %+v", out.Response)
	}
	if out.Response.Patch == nil {
		t.Errorf("expected non-nil patch in TLS round-trip")
	}
	if out.Response.UID != "test-uid" {
		t.Errorf("UID echo: got %q want %q", out.Response.UID, "test-uid")
	}
}

// TestIntegration_TLSConfig_RequiresValidCert is the genuine negative
// path: ListenAndServeTLS must fail when handed cert / key paths that
// do not exist. Story 1.9 code-review patch: the prior body only
// asserted that valid cert files were generated, which exercised the
// happy path twice and never the failure path.
func TestIntegration_TLSConfig_RequiresValidCert(t *testing.T) {
	// Happy-path sanity: real generated cert + key must load. Without
	// this we have no baseline that LoadX509KeyPair works on a valid
	// keypair.
	certFile, keyFile := generateTestTLSCert(t)
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		t.Fatalf("LoadX509KeyPair(valid) returned err: %v", err)
	}

	// Negative path: feeding the webhook server cert paths that do
	// not exist must cause ListenAndServeTLS to return a non-nil
	// error. Run on a free port (the OS chooses) so the test runner
	// is not constrained.
	cfg := WebhookConfig{
		ListenAddr:       "127.0.0.1:0",
		TLSCertFile:      "/nonexistent/tls.crt",
		TLSKeyFile:       "/nonexistent/tls.key",
		UseNativeSidecar: true,
		SidecarImage:     "ghcr.io/olokotoh/olaitan:dev",
	}
	w, err := NewWebhook(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewWebhook: %v", err)
	}
	// http.ListenAndServeTLS returns the error synchronously on a
	// missing cert file; serve in a goroutine to obtain it.
	errCh := make(chan error, 1)
	go func() { errCh <- w.srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile) }()
	select {
	case got := <-errCh:
		if got == nil {
			t.Errorf("ListenAndServeTLS returned nil with missing cert/key paths")
		}
	case <-time.After(2 * time.Second):
		t.Errorf("ListenAndServeTLS did not return within 2s")
	}
	// Shutdown the server in case it somehow listened (it should not
	// have done so when the cert files do not exist).
	_ = w.srv.Close()
}
