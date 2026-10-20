package applog

// #156 (drain on shutdown) and #157 (serving-cert reload) tests. They run a
// real TLS listener on 127.0.0.1, so they cover the path the API server uses,
// not only the in-process mux.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// newKeyPairPEM returns a self-signed serving cert for 127.0.0.1 with the
// given serial, and its key, PEM-encoded.
func newKeyPairPEM(t *testing.T, serial int64) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "olaitan-applog-injector"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
}

// secretVolume mimics the kubelet's atomic writer: tls.crt and tls.key are
// symlinks through ..data, which points at a timestamped directory. A
// rotation writes a new directory and swaps ..data in one rename, which is
// how a renewed Secret reaches a running pod.
type secretVolume struct {
	t   *testing.T
	dir string
	gen int
}

func newSecretVolume(t *testing.T, certPEM, keyPEM []byte) *secretVolume {
	t.Helper()
	v := &secretVolume{t: t, dir: t.TempDir()}
	v.write(certPEM, keyPEM)
	for _, f := range []string{"tls.crt", "tls.key"} {
		if err := os.Symlink(filepath.Join("..data", f), filepath.Join(v.dir, f)); err != nil {
			t.Fatal(err)
		}
	}
	return v
}

func (v *secretVolume) write(certPEM, keyPEM []byte) {
	v.t.Helper()
	v.gen++
	ts := filepath.Join(v.dir, "..gen"+string(rune('0'+v.gen)))
	if err := os.Mkdir(ts, 0o755); err != nil {
		v.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ts, "tls.crt"), certPEM, 0o600); err != nil {
		v.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ts, "tls.key"), keyPEM, 0o600); err != nil {
		v.t.Fatal(err)
	}
	tmp := filepath.Join(v.dir, "..data_tmp")
	if err := os.Symlink(filepath.Base(ts), tmp); err != nil {
		v.t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(v.dir, "..data")); err != nil {
		v.t.Fatal(err)
	}
}

func (v *secretVolume) cert() string { return filepath.Join(v.dir, "tls.crt") }
func (v *secretVolume) key() string  { return filepath.Join(v.dir, "tls.key") }

func startWebhook(t *testing.T, cfg WebhookConfig) (*Webhook, context.CancelFunc, <-chan error) {
	t.Helper()
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.SidecarImage = "olaitan:test"
	cfg.SidecarNATSURL = "nats://nats.olaitan.svc.cluster.local:4222"
	w, err := NewWebhook(cfg, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for w.Addr() == nil {
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("webhook did not start listening: %v", <-done)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
		}
	})
	return w, cancel, done
}

// servedSerial dials the webhook and returns the serial of the leaf it
// presents. Verification is off: the test reads which cert is served.
func servedSerial(t *testing.T, addr string) int64 {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // reads the served leaf only
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer func() { _ = conn.Close() }()
	return conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
}

// #157: a renewed Secret (cert-manager, certgen, or a Path B helm upgrade
// before the pods roll) is served without a restart.
func TestWebhookReloadsRotatedServingCert(t *testing.T) {
	c1, k1 := newKeyPairPEM(t, 1)
	vol := newSecretVolume(t, c1, k1)
	w, _, _ := startWebhook(t, WebhookConfig{
		TLSCertFile: vol.cert(), TLSKeyFile: vol.key(),
		CertReloadInterval: 20 * time.Millisecond,
	})
	addr := w.Addr().String()
	if got := servedSerial(t, addr); got != 1 {
		t.Fatalf("served serial %d before rotation, want 1", got)
	}
	c2, k2 := newKeyPairPEM(t, 2)
	vol.write(c2, k2)
	deadline := time.Now().Add(5 * time.Second)
	for servedSerial(t, addr) != 2 {
		if time.Now().After(deadline) {
			t.Fatal("rotated serving cert was not picked up without a restart (#157)")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A half-written or mismatched pair must not take the webhook down: it keeps
// serving the last good cert and picks up the next good one.
func TestWebhookKeepsLastGoodCertOnBrokenPair(t *testing.T) {
	c1, k1 := newKeyPairPEM(t, 1)
	vol := newSecretVolume(t, c1, k1)
	w, _, _ := startWebhook(t, WebhookConfig{
		TLSCertFile: vol.cert(), TLSKeyFile: vol.key(),
		CertReloadInterval: 20 * time.Millisecond,
	})
	addr := w.Addr().String()
	_, kOther := newKeyPairPEM(t, 9)
	c3, k3 := newKeyPairPEM(t, 3)
	vol.write(c3, kOther) // cert and key do not match
	time.Sleep(150 * time.Millisecond)
	if got := servedSerial(t, addr); got != 1 {
		t.Fatalf("served serial %d after a broken pair, want the last good one (1)", got)
	}
	vol.write(c3, k3)
	deadline := time.Now().Add(5 * time.Second)
	for servedSerial(t, addr) != 3 {
		if time.Now().After(deadline) {
			t.Fatal("the next good pair was not picked up")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Start-up still fails loudly on missing material (the documented contract).
func TestWebhookRunFailsOnMissingCert(t *testing.T) {
	w, err := NewWebhook(WebhookConfig{
		ListenAddr: "127.0.0.1:0", TLSCertFile: filepath.Join(t.TempDir(), "nope.crt"), TLSKeyFile: filepath.Join(t.TempDir(), "nope.key"),
		SidecarImage: "olaitan:test", SidecarNATSURL: "nats://x:4222",
	}, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := w.Run(ctx); err == nil {
		t.Fatal("Run with no cert files returned nil")
	}
}

func get(t *testing.T, addr, path string) (int, error) {
	t.Helper()
	c := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test client
		DisableKeepAlives: true,
	}}
	resp, err := c.Get("https://" + addr + path)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// #156: on shutdown the injector reports not-ready at once but keeps
// accepting connections for ShutdownDelay, so the API server's calls that
// race the endpoint removal are served instead of refused.
func TestWebhookDrainsBeforeClosingTheListener(t *testing.T) {
	c1, k1 := newKeyPairPEM(t, 1)
	vol := newSecretVolume(t, c1, k1)
	delay := 600 * time.Millisecond
	w, cancel, done := startWebhook(t, WebhookConfig{
		TLSCertFile: vol.cert(), TLSKeyFile: vol.key(),
		ShutdownDelay: delay,
	})
	addr := w.Addr().String()
	if code, err := get(t, addr, "/readyz"); err != nil || code != http.StatusOK {
		t.Fatalf("/readyz before shutdown = %d, %v; want 200", code, err)
	}
	start := time.Now()
	cancel()
	// Ready flips first.
	deadline := time.Now().Add(delay / 2)
	for {
		code, err := get(t, addr, "/readyz")
		if err != nil {
			t.Fatalf("/readyz refused during the drain window: %v (#156)", err)
		}
		if code == http.StatusServiceUnavailable {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("/readyz still %d while draining, want 503", code)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Liveness and admission connections are still served inside the window.
	for time.Since(start) < delay*3/4 {
		if code, err := get(t, addr, "/healthz"); err != nil || code != http.StatusOK {
			t.Fatalf("/healthz during the drain window = %d, %v; the listener closed early (#156)", code, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v after a graceful drain", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not return after the drain")
	}
	if took := time.Since(start); took < delay {
		t.Fatalf("Run returned after %v, before the %v drain delay", took, delay)
	}
	if _, err := get(t, addr, "/healthz"); err == nil {
		t.Fatal("listener still open after Run returned")
	}
}
