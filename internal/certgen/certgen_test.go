package certgen

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/yaml"
)

const ns = "olaitan"

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func fullSpec() Spec {
	return Spec{
		Namespace:             ns,
		AuditSecret:           "olaitan-audit-tls",
		AuditKubeconfigSecret: "olaitan-audit-webhook-kubeconfig",
		AuditDNSNames:         []string{"olaitan-audit-webhook", "olaitan-audit-webhook.olaitan.svc", "olaitan-audit-webhook.olaitan.svc.cluster.local"},
		AuditIPs:              []string{"127.0.0.1"},
		AuditServer:           "olaitan-audit-webhook.olaitan.svc.cluster.local:8443",
		ApplogSecret:          "olaitan-applog-injector-tls",
		ApplogDNSNames:        []string{"olaitan-applog-injector", "olaitan-applog-injector.olaitan.svc"},
		MutatingWebhook:       "olaitan-applog-injector",
		Labels:                map[string]string{"app.kubernetes.io/instance": "olaitan"},
		Validity:              24 * time.Hour,
		WaitForWebhooks:       time.Second,
	}
}

func webhookObjects() *admissionv1.MutatingWebhookConfiguration {
	return &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "olaitan-applog-injector"},
		Webhooks:   []admissionv1.MutatingWebhook{{Name: "applog.olaitan.io"}},
	}
}

// leftoverAuditStub is the ValidatingWebhookConfiguration an install from
// before #155 may still carry. certgen must not write the audit CA into it.
func leftoverAuditStub() *admissionv1.ValidatingWebhookConfiguration {
	return &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "olaitan-audit"},
		Webhooks:   []admissionv1.ValidatingWebhook{{Name: "audit.olaitan.io"}},
	}
}

func parseCert(t *testing.T, b []byte) *x509.Certificate {
	t.Helper()
	blk, _ := pem.Decode(b)
	if blk == nil {
		t.Fatalf("not PEM: %q", b)
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func pool(t *testing.T, ca []byte) *x509.CertPool {
	t.Helper()
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(ca) {
		t.Fatal("CA does not parse")
	}
	return p
}

func TestRunCreatesTheMaterialAndPatchesTheWebhooks(t *testing.T) {
	m := webhookObjects()
	cs := fake.NewSimpleClientset(m, leftoverAuditStub())
	ctx := context.Background()
	if err := Run(ctx, cs, fullSpec(), quietLog()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	audit, err := cs.CoreV1().Secrets(ns).Get(ctx, "olaitan-audit-tls", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ca := audit.Data["ca.crt"]
	serving := parseCert(t, audit.Data["tls.crt"])
	if _, err := serving.Verify(x509.VerifyOptions{DNSName: "olaitan-audit-webhook.olaitan.svc.cluster.local", Roots: pool(t, ca)}); err != nil {
		t.Errorf("audit serving cert does not verify for the Service FQDN: %v", err)
	}
	if _, err := serving.Verify(x509.VerifyOptions{DNSName: "127.0.0.1", Roots: pool(t, ca)}); err != nil {
		t.Errorf("audit serving cert does not verify for 127.0.0.1: %v", err)
	}
	if len(audit.Data["tls.key"]) == 0 {
		t.Error("audit Secret has no tls.key")
	}
	if audit.Labels["app.kubernetes.io/managed-by"] != "olaitan-certgen" {
		t.Errorf("audit Secret labels = %v", audit.Labels)
	}

	kc, err := cs.CoreV1().Secrets(ns).Get(ctx, "olaitan-audit-webhook-kubeconfig", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Clusters []struct {
			Cluster struct {
				Server string `json:"server"`
				CAData []byte `json:"certificate-authority-data"`
			} `json:"cluster"`
		} `json:"clusters"`
		Users []struct {
			User struct {
				Cert []byte `json:"client-certificate-data"`
				Key  []byte `json:"client-key-data"`
			} `json:"user"`
		} `json:"users"`
	}
	if err := yaml.Unmarshal(kc.Data["webhook-kubeconfig.yaml"], &cfg); err != nil {
		t.Fatalf("kubeconfig does not parse: %v", err)
	}
	if len(cfg.Clusters) != 1 || cfg.Clusters[0].Cluster.Server != "https://olaitan-audit-webhook.olaitan.svc.cluster.local:8443/audit" {
		t.Errorf("kubeconfig server = %+v", cfg.Clusters)
	}
	if string(cfg.Clusters[0].Cluster.CAData) != string(ca) {
		t.Error("kubeconfig CA is not the CA that signed the receiver")
	}
	client := parseCert(t, cfg.Users[0].User.Cert)
	if _, err := client.Verify(x509.VerifyOptions{Roots: pool(t, ca), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("apiserver client cert does not verify as a client cert under the receiver's client CA: %v", err)
	}
	if client.Subject.CommonName != "kube-apiserver" {
		t.Errorf("client CN = %q", client.Subject.CommonName)
	}

	applog, err := cs.CoreV1().Secrets(ns).Get(ctx, "olaitan-applog-injector-tls", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if applog.Type != "kubernetes.io/tls" {
		t.Errorf("applog Secret type = %q", applog.Type)
	}
	if _, err := parseCert(t, applog.Data["tls.crt"]).Verify(x509.VerifyOptions{DNSName: "olaitan-applog-injector.olaitan.svc", Roots: pool(t, applog.Data["ca.crt"])}); err != nil {
		t.Errorf("applog serving cert does not verify: %v", err)
	}

	gm, _ := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, "olaitan-applog-injector", metav1.GetOptions{})
	if string(gm.Webhooks[0].ClientConfig.CABundle) != string(applog.Data["ca.crt"]) {
		t.Error("mutating webhook caBundle is not the applog CA")
	}
	// #155: the audit CA goes into no admission webhook. A leftover stub
	// from an older install keeps an empty caBundle.
	gv, _ := cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(ctx, "olaitan-audit", metav1.GetOptions{})
	if len(gv.Webhooks[0].ClientConfig.CABundle) != 0 {
		t.Error("certgen wrote the audit CA into a ValidatingWebhookConfiguration (#155)")
	}
	for _, b := range [][]byte{audit.Data["tls.crt"], kc.Data["webhook-kubeconfig.yaml"], applog.Data["tls.crt"]} {
		if strings.Contains(string(b), "BEGIN RSA") {
			t.Error("expected ECDSA keys")
		}
	}
}

func TestRunIsIdempotentAndNeverReplacesMaterial(t *testing.T) {
	m := webhookObjects()
	cs := fake.NewSimpleClientset(m)
	ctx := context.Background()
	if err := Run(ctx, cs, fullSpec(), quietLog()); err != nil {
		t.Fatal(err)
	}
	before := map[string]string{}
	for _, n := range []string{"olaitan-audit-tls", "olaitan-audit-webhook-kubeconfig", "olaitan-applog-injector-tls"} {
		s, _ := cs.CoreV1().Secrets(ns).Get(ctx, n, metav1.GetOptions{})
		before[n] = string(s.Data["tls.crt"]) + string(s.Data["webhook-kubeconfig.yaml"])
	}
	// An apply of the chart resets nothing (caBundle is not rendered), but a
	// webhook configuration recreated from scratch must be patched again.
	m2 := webhookObjects()
	_ = cs.AdmissionregistrationV1().MutatingWebhookConfigurations().Delete(ctx, m2.Name, metav1.DeleteOptions{})
	if _, err := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().Create(ctx, m2, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := Run(ctx, cs, fullSpec(), quietLog()); err != nil {
		t.Fatalf("second Run: %v", err)
	}
	for n, b := range before {
		s, _ := cs.CoreV1().Secrets(ns).Get(ctx, n, metav1.GetOptions{})
		if string(s.Data["tls.crt"])+string(s.Data["webhook-kubeconfig.yaml"]) != b {
			t.Errorf("second Run replaced %s", n)
		}
	}
	gm, _ := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, "olaitan-applog-injector", metav1.GetOptions{})
	applog, _ := cs.CoreV1().Secrets(ns).Get(ctx, "olaitan-applog-injector-tls", metav1.GetOptions{})
	if string(gm.Webhooks[0].ClientConfig.CABundle) != string(applog.Data["ca.crt"]) {
		t.Error("a recreated mutating webhook was not re-patched")
	}
}

func TestRunOnlyTouchesWhatItIsGiven(t *testing.T) {
	m := webhookObjects()
	cs := fake.NewSimpleClientset(m)
	spec := Spec{
		Namespace:       ns,
		ApplogSecret:    "olaitan-applog-injector-tls",
		ApplogDNSNames:  []string{"olaitan-applog-injector.olaitan.svc"},
		MutatingWebhook: "olaitan-applog-injector",
		Validity:        time.Hour,
		WaitForWebhooks: time.Second,
	}
	if err := Run(context.Background(), cs, spec, quietLog()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	l, _ := cs.CoreV1().Secrets(ns).List(context.Background(), metav1.ListOptions{})
	if len(l.Items) != 1 {
		t.Errorf("Secrets created = %d, want 1 (applog only)", len(l.Items))
	}
}

func TestRunFailsWhenAWebhookNeverAppears(t *testing.T) {
	cs := fake.NewSimpleClientset()
	spec := fullSpec()
	spec.WaitForWebhooks = 50 * time.Millisecond
	if err := Run(context.Background(), cs, spec, quietLog()); err == nil {
		t.Fatal("Run returned nil although the webhook configurations to patch do not exist")
	}
}

func TestSpecValidate(t *testing.T) {
	s := fullSpec()
	s.AuditServer = ""
	if err := s.Validate(); err == nil {
		t.Error("an audit Secret without an audit server address validated")
	}
	s = fullSpec()
	s.Namespace = ""
	if err := s.Validate(); err == nil {
		t.Error("an empty namespace validated")
	}
	s = Spec{Namespace: ns}
	if err := s.Validate(); err == nil {
		t.Error("a spec with nothing to do validated")
	}
}

// Review (Edge Case Hunter E1): a change of the address the apiserver dials
// (serverAddress, servicePort) or of the Service names makes a new Job run,
// and reusing the old material would leave a cert without the new name and
// a kubeconfig pointing at the old server.
func TestRunRegeneratesWhenTheSpecMoved(t *testing.T) {
	m := webhookObjects()
	cs := fake.NewSimpleClientset(m)
	ctx := context.Background()
	if err := Run(ctx, cs, fullSpec(), quietLog()); err != nil {
		t.Fatal(err)
	}
	moved := fullSpec()
	moved.AuditServer = "127.0.0.1:31443"
	moved.AuditIPs = []string{"127.0.0.1", "10.0.0.7"}
	moved.ApplogDNSNames = append(moved.ApplogDNSNames, "olaitan-applog-injector.olaitan.svc.cluster.local")
	if err := Run(ctx, cs, moved, quietLog()); err != nil {
		t.Fatal(err)
	}
	audit, _ := cs.CoreV1().Secrets(ns).Get(ctx, "olaitan-audit-tls", metav1.GetOptions{})
	if _, err := parseCert(t, audit.Data["tls.crt"]).Verify(x509.VerifyOptions{DNSName: "10.0.0.7", Roots: pool(t, audit.Data["ca.crt"])}); err != nil {
		t.Errorf("audit cert was not regenerated for the new IP: %v", err)
	}
	kc, _ := cs.CoreV1().Secrets(ns).Get(ctx, "olaitan-audit-webhook-kubeconfig", metav1.GetOptions{})
	if !strings.Contains(string(kc.Data["webhook-kubeconfig.yaml"]), "https://127.0.0.1:31443/audit") {
		t.Errorf("kubeconfig still points at the old server:\n%s", kc.Data["webhook-kubeconfig.yaml"])
	}
	applog, _ := cs.CoreV1().Secrets(ns).Get(ctx, "olaitan-applog-injector-tls", metav1.GetOptions{})
	if _, err := parseCert(t, applog.Data["tls.crt"]).Verify(x509.VerifyOptions{DNSName: "olaitan-applog-injector.olaitan.svc.cluster.local", Roots: pool(t, applog.Data["ca.crt"])}); err != nil {
		t.Errorf("applog cert was not regenerated for the new name: %v", err)
	}
}

// Review (Edge Case Hunter E4): a complete Secret certgen did not make (an
// operator-mode Secret left behind on a switch to auto mode, whose ca.crt is
// the apiserver CLIENT CA, not a serving CA) must not be adopted.
func TestRunReplacesASecretItDidNotMake(t *testing.T) {
	m := webhookObjects()
	foreign := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "olaitan-applog-injector-tls", Namespace: ns},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"tls.crt": []byte("x"), "tls.key": []byte("y"), "ca.crt": []byte("operator-ca")},
	}
	cs := fake.NewSimpleClientset(m, foreign)
	ctx := context.Background()
	if err := Run(ctx, cs, fullSpec(), quietLog()); err != nil {
		t.Fatal(err)
	}
	s, _ := cs.CoreV1().Secrets(ns).Get(ctx, "olaitan-applog-injector-tls", metav1.GetOptions{})
	if string(s.Data["ca.crt"]) == "operator-ca" || s.Labels["app.kubernetes.io/managed-by"] != ManagedByLabel {
		t.Errorf("a Secret certgen did not make was adopted: ca=%q labels=%v", s.Data["ca.crt"], s.Labels)
	}
}
