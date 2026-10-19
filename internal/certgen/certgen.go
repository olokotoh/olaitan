// Package certgen generates, in the cluster, the TLS material the chart used
// to require as Helm values (Story 12.7, D1): the audit webhook receiver's
// serving certificate and client CA, the kubeconfig the kube-apiserver uses to
// reach that receiver, and the applog injector's serving certificate. It then
// writes the matching CA into the caBundle of the two webhook configurations.
//
// Why a Job and not the template: `helm template` renders the release
// install.yaml (Story 12.4), and a key generated at render time would be one
// private key published in a release asset and shared by every install. Here
// every install gets its own material, and it never leaves the cluster.
//
// Run is idempotent. A Secret that already holds the expected keys is reused
// as it is, never replaced, so a re-run (an upgrade, a re-apply of
// install.yaml) cannot rotate a certificate under a running receiver. The
// webhook caBundle is written on every run, which repairs a webhook
// configuration that was recreated.
package certgen

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ManagedByLabel marks every Secret certgen creates. helm does not own these
// Secrets, so `helm uninstall` leaves them; the label is how an operator finds
// them (kubectl delete secret -l app.kubernetes.io/managed-by=olaitan-certgen).
const ManagedByLabel = "olaitan-certgen"

// Secret data keys. The audit receiver reads tls.crt, tls.key and ca.crt from
// its mount (config/olaitan.yaml detection.sources.audit); the applog injector
// reads tls.crt and tls.key; ca.crt is kept beside them so a re-run can
// re-patch the webhook caBundle without the CA's key.
const (
	keyCert       = "tls.crt"
	keyKey        = "tls.key"
	keyCA         = "ca.crt"
	keyKubeconfig = "webhook-kubeconfig.yaml"
)

// Spec says what to generate. Empty secret names skip that part.
type Spec struct {
	Namespace string

	// Audit webhook receiver: serving cert for these names, signed by a fresh
	// CA that also signs the kube-apiserver's client cert, so the receiver's
	// ca.crt (the client CA) and the kubeconfig's certificate-authority-data
	// are the same certificate.
	AuditSecret           string
	AuditKubeconfigSecret string
	AuditDNSNames         []string
	AuditIPs              []string
	// AuditServer is host:port the kube-apiserver dials (the chart's
	// olaitan.auditWebhook.server), written into the kubeconfig.
	AuditServer string

	// Applog injector: serving cert for these names, with its own CA.
	ApplogSecret   string
	ApplogDNSNames []string

	// Webhook configurations whose caBundle is set: the applog injector's
	// MutatingWebhookConfiguration (applog CA) and the audit admission stub's
	// ValidatingWebhookConfiguration (audit CA).
	MutatingWebhook   string
	ValidatingWebhook string

	// Labels added to every Secret created (plus the managed-by label).
	Labels map[string]string
	// Validity of every certificate. Zero means ten years.
	Validity time.Duration
	// WaitForWebhooks bounds the wait for a webhook configuration that does
	// not exist yet (kubectl apply creates the Job and the configurations in
	// one pass, in no guaranteed order). Zero means two minutes.
	WaitForWebhooks time.Duration
}

// Validate reports a Spec that cannot do anything useful or would write a
// broken kubeconfig.
func (s Spec) Validate() error {
	if s.Namespace == "" {
		return errors.New("certgen: namespace is required")
	}
	if s.AuditSecret == "" && s.ApplogSecret == "" {
		return errors.New("certgen: nothing to do (set the audit and/or applog Secret)")
	}
	if s.AuditSecret != "" {
		if s.AuditKubeconfigSecret == "" || s.AuditServer == "" {
			return errors.New("certgen: the audit Secret needs the kubeconfig Secret name and the server address the apiserver dials")
		}
		if len(s.AuditDNSNames) == 0 && len(s.AuditIPs) == 0 {
			return errors.New("certgen: the audit serving cert needs at least one DNS name or IP")
		}
	}
	if s.ApplogSecret != "" && len(s.ApplogDNSNames) == 0 {
		return errors.New("certgen: the applog serving cert needs at least one DNS name")
	}
	if s.ValidatingWebhook != "" && s.AuditSecret == "" {
		return errors.New("certgen: the validating webhook takes the audit CA; set the audit Secret")
	}
	if s.MutatingWebhook != "" && s.ApplogSecret == "" {
		return errors.New("certgen: the mutating webhook takes the applog CA; set the applog Secret")
	}
	for _, ip := range s.AuditIPs {
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("certgen: audit IP %q is not an IP address", ip)
		}
	}
	return nil
}

// Run creates whatever material is missing and patches the webhook caBundles.
func Run(ctx context.Context, cs kubernetes.Interface, spec Spec, log *slog.Logger) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	if log == nil {
		log = slog.Default()
	}
	validity := spec.Validity
	if validity <= 0 {
		validity = 10 * 365 * 24 * time.Hour
	}
	wait := spec.WaitForWebhooks
	if wait <= 0 {
		wait = 2 * time.Minute
	}
	g := generator{cs: cs, spec: spec, log: log, validity: validity}

	if spec.AuditSecret != "" {
		auditCA, err := g.ensureAudit(ctx)
		if err != nil {
			return err
		}
		if spec.ValidatingWebhook != "" {
			if err := patchValidating(ctx, cs, spec.ValidatingWebhook, auditCA, wait); err != nil {
				return err
			}
			log.Info("certgen: caBundle set", "validatingwebhookconfiguration", spec.ValidatingWebhook)
		}
	}
	if spec.ApplogSecret != "" {
		applogCA, err := g.ensureApplog(ctx)
		if err != nil {
			return err
		}
		if spec.MutatingWebhook != "" {
			if err := patchMutating(ctx, cs, spec.MutatingWebhook, applogCA, wait); err != nil {
				return err
			}
			log.Info("certgen: caBundle set", "mutatingwebhookconfiguration", spec.MutatingWebhook)
		}
	}
	return nil
}

type generator struct {
	cs       kubernetes.Interface
	spec     Spec
	log      *slog.Logger
	validity time.Duration
}

func (g generator) secrets() typedSecrets { return g.cs.CoreV1().Secrets(g.spec.Namespace) }

type typedSecrets interface {
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.Secret, error)
	Create(ctx context.Context, s *corev1.Secret, opts metav1.CreateOptions) (*corev1.Secret, error)
	Update(ctx context.Context, s *corev1.Secret, opts metav1.UpdateOptions) (*corev1.Secret, error)
}

// existing returns the Secret when it exists and holds every key, nil when it
// does not exist, and the Secret with complete=false when it exists but is
// missing a key (someone emptied it).
func (g generator) existing(ctx context.Context, name string, keys ...string) (*corev1.Secret, bool, error) {
	s, err := g.secrets().Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("certgen: get Secret %s: %w", name, err)
	}
	for _, k := range keys {
		if len(s.Data[k]) == 0 {
			return s, false, nil
		}
	}
	return s, true, nil
}

// ensureAudit returns the audit CA PEM, creating the receiver Secret and the
// apiserver kubeconfig Secret when either is missing. The two are one set (the
// kubeconfig's client cert is signed by the receiver's client CA), so a
// missing half regenerates both.
func (g generator) ensureAudit(ctx context.Context) ([]byte, error) {
	tlsS, tlsOK, err := g.existing(ctx, g.spec.AuditSecret, keyCert, keyKey, keyCA)
	if err != nil {
		return nil, err
	}
	kcS, kcOK, err := g.existing(ctx, g.spec.AuditKubeconfigSecret, keyKubeconfig)
	if err != nil {
		return nil, err
	}
	if tlsOK && kcOK {
		g.log.Info("certgen: audit material exists; reusing it", "secret", g.spec.AuditSecret)
		return tlsS.Data[keyCA], nil
	}
	if tlsS != nil || kcS != nil {
		g.log.Warn("certgen: audit material is incomplete; generating a new set (restart the collector so the receiver loads it)",
			"secret", g.spec.AuditSecret, "kubeconfig_secret", g.spec.AuditKubeconfigSecret)
	}

	ca, caKey, err := newCA("olaitan-audit-ca", g.validity)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(g.spec.AuditIPs))
	for _, s := range g.spec.AuditIPs {
		ips = append(ips, net.ParseIP(s))
	}
	serving, servingKey, err := newLeaf(ca, caKey, g.spec.AuditDNSNames, ips, "olaitan-audit-webhook", x509.ExtKeyUsageServerAuth, g.validity)
	if err != nil {
		return nil, err
	}
	client, clientKey, err := newLeaf(ca, caKey, nil, nil, "kube-apiserver", x509.ExtKeyUsageClientAuth, g.validity)
	if err != nil {
		return nil, err
	}
	caPEM := pemCert(ca)
	tlsData := map[string][]byte{keyCert: pemCert(serving), keyKey: servingKey, keyCA: caPEM}
	kubeconfig := buildKubeconfig(g.spec.AuditServer, caPEM, pemCert(client), clientKey)

	// Create the receiver Secret first: if another run won the race, adopt
	// ITS CA and leave the kubeconfig to that run (or rebuild it below).
	stored, err := g.put(ctx, g.spec.AuditSecret, corev1.SecretTypeTLS, tlsData, tlsS)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(stored.Data[keyCA], caPEM) {
		// Lost a create race to a concurrent run; its kubeconfig matches its CA.
		g.log.Info("certgen: another run created the audit material first; using it")
		return stored.Data[keyCA], nil
	}
	if _, err := g.put(ctx, g.spec.AuditKubeconfigSecret, corev1.SecretTypeOpaque, map[string][]byte{keyKubeconfig: kubeconfig}, kcS); err != nil {
		return nil, err
	}
	g.log.Info("certgen: audit material created", "secret", g.spec.AuditSecret, "kubeconfig_secret", g.spec.AuditKubeconfigSecret)
	return caPEM, nil
}

// ensureApplog returns the applog CA PEM, creating the injector Secret when
// it is missing.
func (g generator) ensureApplog(ctx context.Context) ([]byte, error) {
	s, ok, err := g.existing(ctx, g.spec.ApplogSecret, keyCert, keyKey, keyCA)
	if err != nil {
		return nil, err
	}
	if ok {
		g.log.Info("certgen: applog material exists; reusing it", "secret", g.spec.ApplogSecret)
		return s.Data[keyCA], nil
	}
	ca, caKey, err := newCA("olaitan-applog-ca", g.validity)
	if err != nil {
		return nil, err
	}
	serving, servingKey, err := newLeaf(ca, caKey, g.spec.ApplogDNSNames, nil, "olaitan-applog-injector", x509.ExtKeyUsageServerAuth, g.validity)
	if err != nil {
		return nil, err
	}
	caPEM := pemCert(ca)
	stored, err := g.put(ctx, g.spec.ApplogSecret, corev1.SecretTypeTLS,
		map[string][]byte{keyCert: pemCert(serving), keyKey: servingKey, keyCA: caPEM}, s)
	if err != nil {
		return nil, err
	}
	g.log.Info("certgen: applog material ready", "secret", g.spec.ApplogSecret)
	return stored.Data[keyCA], nil
}

// put creates the Secret, or fills an existing incomplete one. On a create
// race (AlreadyExists) it returns whatever the winner stored.
func (g generator) put(ctx context.Context, name string, typ corev1.SecretType, data map[string][]byte, current *corev1.Secret) (*corev1.Secret, error) {
	if current != nil {
		upd := current.DeepCopy()
		upd.Data = data
		if upd.Labels == nil {
			upd.Labels = map[string]string{}
		}
		for k, v := range g.labels() {
			upd.Labels[k] = v
		}
		out, err := g.secrets().Update(ctx, upd, metav1.UpdateOptions{})
		if err != nil {
			return nil, fmt.Errorf("certgen: update Secret %s: %w", name, err)
		}
		return out, nil
	}
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: g.spec.Namespace, Labels: g.labels()},
		Type:       typ,
		Data:       data,
	}
	out, err := g.secrets().Create(ctx, s, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		won, gerr := g.secrets().Get(ctx, name, metav1.GetOptions{})
		if gerr != nil {
			return nil, fmt.Errorf("certgen: Secret %s appeared during create but cannot be read: %w", name, gerr)
		}
		return won, nil
	}
	if err != nil {
		return nil, fmt.Errorf("certgen: create Secret %s: %w", name, err)
	}
	return out, nil
}

func (g generator) labels() map[string]string {
	out := map[string]string{"app.kubernetes.io/managed-by": ManagedByLabel}
	for k, v := range g.spec.Labels {
		if k == "app.kubernetes.io/managed-by" {
			continue
		}
		out[k] = v
	}
	return out
}

// patchMutating and patchValidating set the caBundle of every webhook in the
// named configuration, retrying while the configuration does not exist yet.
func patchMutating(ctx context.Context, cs kubernetes.Interface, name string, ca []byte, wait time.Duration) error {
	api := cs.AdmissionregistrationV1().MutatingWebhookConfigurations()
	return untilFound(ctx, wait, "mutatingwebhookconfiguration "+name, func() error {
		w, err := api.Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		changed := false
		for i := range w.Webhooks {
			if !bytes.Equal(w.Webhooks[i].ClientConfig.CABundle, ca) {
				w.Webhooks[i].ClientConfig.CABundle = ca
				changed = true
			}
		}
		if !changed {
			return nil
		}
		_, err = api.Update(ctx, w, metav1.UpdateOptions{})
		return err
	})
}

func patchValidating(ctx context.Context, cs kubernetes.Interface, name string, ca []byte, wait time.Duration) error {
	api := cs.AdmissionregistrationV1().ValidatingWebhookConfigurations()
	return untilFound(ctx, wait, "validatingwebhookconfiguration "+name, func() error {
		w, err := api.Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		changed := false
		for i := range w.Webhooks {
			if !bytes.Equal(w.Webhooks[i].ClientConfig.CABundle, ca) {
				w.Webhooks[i].ClientConfig.CABundle = ca
				changed = true
			}
		}
		if !changed {
			return nil
		}
		_, err = api.Update(ctx, w, metav1.UpdateOptions{})
		return err
	})
}

// untilFound retries fn while it fails with NotFound or a write Conflict,
// for at most wait.
func untilFound(ctx context.Context, wait time.Duration, what string, fn func() error) error {
	deadline := time.Now().Add(wait)
	delay := 50 * time.Millisecond
	for {
		err := fn()
		if err == nil {
			return nil
		}
		if !apierrors.IsNotFound(err) && !apierrors.IsConflict(err) {
			return fmt.Errorf("certgen: patch %s: %w", what, err)
		}
		if time.Now().Add(delay).After(deadline) {
			return fmt.Errorf("certgen: %s: still failing after %s: %w", what, wait, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		if delay < 2*time.Second {
			delay *= 2
		}
	}
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
}

func newCA(cn string, validity time.Duration) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("certgen: CA key: %w", err)
	}
	sn, err := serial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().Add(-5 * time.Minute)
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"olaitan"}},
		NotBefore:             now,
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("certgen: CA cert: %w", err)
	}
	ca, err := x509.ParseCertificate(der)
	return ca, key, err
}

func newLeaf(ca *x509.Certificate, caKey *ecdsa.PrivateKey, dns []string, ips []net.IP, cn string, usage x509.ExtKeyUsage, validity time.Duration) (*x509.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("certgen: leaf key: %w", err)
	}
	sn, err := serial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().Add(-5 * time.Minute)
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"olaitan"}},
		NotBefore:    now,
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		DNSNames:     dns,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("certgen: leaf cert %s: %w", cn, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return cert, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}

func pemCert(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

// buildKubeconfig is the same shape templates/audit-webhook-kubeconfig-secret.yaml
// renders for operator-supplied material.
func buildKubeconfig(server string, ca, cert, key []byte) []byte {
	b64 := base64.StdEncoding.EncodeToString
	return []byte(fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
  - name: olaitan-audit
    cluster:
      server: https://%s/audit
      certificate-authority-data: %s
users:
  - name: kube-apiserver
    user:
      client-certificate-data: %s
      client-key-data: %s
contexts:
  - name: olaitan-audit
    context:
      cluster: olaitan-audit
      user: kube-apiserver
current-context: olaitan-audit
`, server, b64(ca), b64(cert), b64(key)))
}
