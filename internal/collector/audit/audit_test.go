package audit

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	natsjs "github.com/nats-io/nats.go/jetstream"
	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"

	"github.com/olokotoh/olaitan/internal/retry"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// stubPublisher captures published events for assertion. attempts
// counts every PublishJS call (success or failure) so tests can
// verify the retry budget actually executed; calls captures only
// successful publishes.
type stubPublisher struct {
	mu        sync.Mutex
	calls     []stubCall
	attempts  atomic.Int64 // every PublishJS invocation, regardless of outcome
	failNext  atomic.Int32 // number of upcoming calls to fail transiently
	failErr   error
	permanent atomic.Bool
}

type stubCall struct {
	subject string
	data    []byte
}

func (s *stubPublisher) PublishJS(_ context.Context, subject string, data any, opts ...natsjs.PublishOpt) (*natsjs.PubAck, error) {
	s.attempts.Add(1)
	if s.failNext.Add(-1) >= 0 {
		err := s.failErr
		if err == nil {
			err = errors.New("transient nats error")
		}
		return nil, err
	}
	if s.permanent.Load() {
		// P28: typed nats.ErrMaxPayload (post-substring-drop). Pre-P28
		// the same string-only error tripped the substring fallback;
		// the typed wrap survives the post-P28 typed-only matcher.
		return nil, fmt.Errorf("publish: %w", nats.ErrMaxPayload)
	}
	b, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	_ = opts
	s.mu.Lock()
	s.calls = append(s.calls, stubCall{subject: subject, data: b})
	s.mu.Unlock()
	return &natsjs.PubAck{Stream: "EVENTS_RAW", Sequence: uint64(len(s.calls))}, nil
}

func (s *stubPublisher) Calls() []stubCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]stubCall(nil), s.calls...)
}

func (s *stubPublisher) Attempts() int64 { return s.attempts.Load() }

// testCerts holds the on-disk paths to a synthetic CA, server cert,
// and client cert generated for a single test.
type testCerts struct {
	caPEM         []byte
	serverCertPEM []byte
	serverKeyPEM  []byte
	clientCertPEM []byte
	clientKeyPEM  []byte
	dir           string

	// Files written for the receiver to load.
	serverCertFile string
	serverKeyFile  string
	clientCAFile   string
}

// genTestCerts is the *testing.T convenience wrapper around genTestCertsTB.
func genTestCerts(t *testing.T) *testCerts { return genTestCertsTB(t) }

// genTestCertsTB produces a tiny PKI: a self-signed CA, a server cert
// with the loopback SAN, and a client cert with CN "kube-apiserver".
// All three are written to a temp dir so the receiver can read them.
// The testing.TB-aware variant lets benchmarks share the helper.
func genTestCertsTB(t testing.TB) *testCerts {
	t.Helper()
	dir := t.TempDir()

	// CA
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	// Server cert
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("srv key: %v", err)
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "audit-receiver"},
		DNSNames:     []string{"localhost", "audit.test.svc"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caTmpl, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("srv cert: %v", err)
	}
	srvCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER})
	srvKeyDER, err := x509.MarshalECPrivateKey(srvKey)
	if err != nil {
		t.Fatalf("srv key marshal: %v", err)
	}
	srvKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: srvKeyDER})

	// Client cert
	cliKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cli key: %v", err)
	}
	cliTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "kube-apiserver"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cliDER, err := x509.CreateCertificate(rand.Reader, cliTmpl, caTmpl, &cliKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("cli cert: %v", err)
	}
	cliCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cliDER})
	cliKeyDER, err := x509.MarshalECPrivateKey(cliKey)
	if err != nil {
		t.Fatalf("cli key marshal: %v", err)
	}
	cliKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: cliKeyDER})

	// Write to disk.
	tc := &testCerts{
		caPEM:          caPEM,
		serverCertPEM:  srvCertPEM,
		serverKeyPEM:   srvKeyPEM,
		clientCertPEM:  cliCertPEM,
		clientKeyPEM:   cliKeyPEM,
		dir:            dir,
		serverCertFile: filepath.Join(dir, "server.crt"),
		serverKeyFile:  filepath.Join(dir, "server.key"),
		clientCAFile:   filepath.Join(dir, "ca.crt"),
	}
	mustWrite := func(path string, b []byte) {
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatalf("write %q: %v", path, err)
		}
	}
	mustWrite(tc.serverCertFile, srvCertPEM)
	mustWrite(tc.serverKeyFile, srvKeyPEM)
	mustWrite(tc.clientCAFile, caPEM)
	return tc
}

// startAdapter starts an Adapter on a random :0 port and returns the
// running adapter, the bound URL (https://127.0.0.1:<port>/audit), and
// the test certs.
func startAdapter(t *testing.T, pub natsPublisher, mut func(*Config)) (*Adapter, string, *testCerts, context.CancelFunc) {
	t.Helper()
	tc := genTestCerts(t)

	// Pre-bind a TCP listener on :0 so we know the port before Run
	// starts, then close it and use that port. There is a tiny TOCTOU
	// race but tests run sequentially per-package and the port stays
	// fresh in the kernel's TIME_WAIT-free range.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick port: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	cfg := Config{
		ListenAddr:        addr,
		TLSCertFile:       tc.serverCertFile,
		TLSKeyFile:        tc.serverKeyFile,
		ClientCAFile:      tc.clientCAFile,
		Hostname:          testNode,
		MaxPayloadBytes:   1 << 20, // 1 MiB
		StalenessTimeout:  500 * time.Millisecond,
		ReadHeaderTimeout: 2 * time.Second,
		ShutdownGrace:     2 * time.Second,
		PublishRetry: retry.Strategy{
			Min:         1 * time.Millisecond,
			Max:         5 * time.Millisecond,
			Multiplier:  2.0,
			Jitter:      0,
			MaxAttempts: 3,
		},
	}
	if mut != nil {
		mut(&cfg)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, err := New(cfg, pub, logger)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() {
		runDone <- a.Run(ctx)
	}()

	// Wait for the listener to come up.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Cleanup(func() {
		cancel()
		select {
		case <-runDone:
		case <-time.After(5 * time.Second):
			t.Errorf("adapter Run did not return after cancel")
		}
	})

	return a, fmt.Sprintf("https://%s/audit", addr), tc, cancel
}

// mtlsClient builds an HTTP client trusting tc.caPEM and presenting
// tc.clientCertPEM/Key. Pass present=false to skip presenting a client
// cert (used by the no-client-cert reject test).
func mtlsClient(t *testing.T, tc *testCerts, present bool) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(tc.caPEM) {
		t.Fatal("client trust pool: no certs")
	}
	tlsCfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12, ServerName: "localhost"}
	if present {
		cert, err := tls.X509KeyPair(tc.clientCertPEM, tc.clientKeyPEM)
		if err != nil {
			t.Fatalf("client cert: %v", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   5 * time.Second,
	}
}

func mustEventList(t *testing.T) []byte {
	t.Helper()
	list := auditv1.EventList{
		TypeMeta: metav1.TypeMeta{Kind: "EventList", APIVersion: "audit.k8s.io/v1"},
		Items: []auditv1.Event{
			{
				TypeMeta:                 metav1.TypeMeta{Kind: "Event", APIVersion: "audit.k8s.io/v1"},
				Level:                    auditv1.LevelMetadata,
				AuditID:                  types.UID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
				Stage:                    auditv1.StageResponseComplete,
				RequestURI:               "/api/v1/namespaces/default/pods/p",
				Verb:                     "create",
				User:                     authnv1.UserInfo{Username: "alice"},
				ObjectRef:                &auditv1.ObjectReference{Resource: "pods", Namespace: "default", Name: "p"},
				RequestReceivedTimestamp: metav1.NewMicroTime(time.Now()),
			},
		},
	}
	b, err := json.Marshal(&list)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestReceiver_HappyPath_Publishes_204(t *testing.T) {
	t.Parallel()
	pub := &stubPublisher{}
	_, url, tc, _ := startAdapter(t, pub, nil)

	client := mtlsClient(t, tc, true)
	resp, err := client.Post(url, "application/json", bytes.NewReader(mustEventList(t)))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status: got %d, want 204", resp.StatusCode)
	}
	calls := pub.Calls()
	if len(calls) != 1 {
		t.Fatalf("publish calls: got %d, want 1", len(calls))
	}
	if calls[0].subject != subjects.RawAudit {
		t.Errorf("subject: got %q, want %q", calls[0].subject, subjects.RawAudit)
	}
}

func TestReceiver_Rejects_NonPOST(t *testing.T) {
	t.Parallel()
	pub := &stubPublisher{}
	a, url, tc, _ := startAdapter(t, pub, nil)

	client := mtlsClient(t, tc, true)
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d, want 405", resp.StatusCode)
	}
	if a.Rejected()["method_not_allowed"] != 1 {
		t.Errorf("rejected counter not incremented: %v", a.Rejected())
	}
}

func TestReceiver_Rejects_NonJSON(t *testing.T) {
	t.Parallel()
	pub := &stubPublisher{}
	a, url, tc, _ := startAdapter(t, pub, nil)

	client := mtlsClient(t, tc, true)
	resp, err := client.Post(url, "application/octet-stream", bytes.NewReader([]byte("garbage")))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("status: got %d, want 415", resp.StatusCode)
	}
	if a.Rejected()["unsupported_media_type"] != 1 {
		t.Errorf("rejected counter not incremented: %v", a.Rejected())
	}
}

func TestReceiver_Rejects_OversizePayload(t *testing.T) {
	t.Parallel()
	pub := &stubPublisher{}
	a, url, tc, _ := startAdapter(t, pub, func(c *Config) {
		c.MaxPayloadBytes = 512 // tiny cap
	})

	// Build a syntactically valid EventList payload that exceeds the
	// cap (otherwise the JSON parser would fail before MaxBytesReader
	// surfaces). The padding sits on a benign string field that the
	// translate step does not constrain.
	pad := strings.Repeat("x", 4096)
	list := auditv1.EventList{
		TypeMeta: metav1.TypeMeta{Kind: "EventList", APIVersion: "audit.k8s.io/v1"},
		Items: []auditv1.Event{
			{
				TypeMeta:                 metav1.TypeMeta{Kind: "Event", APIVersion: "audit.k8s.io/v1"},
				Level:                    auditv1.LevelMetadata,
				AuditID:                  types.UID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
				Stage:                    auditv1.StageResponseComplete,
				Verb:                     "create",
				UserAgent:                pad,
				User:                     authnv1.UserInfo{Username: "alice"},
				ObjectRef:                &auditv1.ObjectReference{Resource: "pods", Name: "p"},
				RequestReceivedTimestamp: metav1.NewMicroTime(time.Now()),
			},
		},
	}
	body, err := json.Marshal(&list)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	client := mtlsClient(t, tc, true)
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want 413; body=%q", resp.StatusCode, respBody)
	}
	if a.Rejected()["payload_too_large"] != 1 {
		t.Errorf("rejected counter not incremented: %v", a.Rejected())
	}
}

func TestReceiver_Rejects_NoClientCert(t *testing.T) {
	t.Parallel()
	pub := &stubPublisher{}
	_, url, tc, _ := startAdapter(t, pub, nil)

	client := mtlsClient(t, tc, false)
	_, err := client.Post(url, "application/json", bytes.NewReader(mustEventList(t)))
	if err == nil {
		t.Fatal("expected TLS handshake failure without client cert")
	}
}

func TestReceiver_Rejects_UnknownClientCA(t *testing.T) {
	t.Parallel()
	pub := &stubPublisher{}
	_, url, tc, _ := startAdapter(t, pub, nil)

	// Build a SECOND CA + client cert that the receiver does NOT trust.
	otherCA := genTestCerts(t)

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(tc.caPEM)
	cert, err := tls.X509KeyPair(otherCA.clientCertPEM, otherCA.clientKeyPEM)
	if err != nil {
		t.Fatalf("kp: %v", err)
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:      pool,
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			ServerName:   "localhost",
		}},
		Timeout: 5 * time.Second,
	}
	_, err = client.Post(url, "application/json", bytes.NewReader(mustEventList(t)))
	if err == nil {
		t.Fatal("expected TLS handshake failure with unknown-CA client cert")
	}
}

func TestReceiver_5xx_When_AllPublishesFailTransiently(t *testing.T) {
	t.Parallel()
	pub := &stubPublisher{}
	pub.failNext.Store(100) // larger than any retry budget x event count
	_, url, tc, _ := startAdapter(t, pub, nil)

	client := mtlsClient(t, tc, true)
	resp, err := client.Post(url, "application/json", bytes.NewReader(mustEventList(t)))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want 500 (all transient publishes failed)", resp.StatusCode)
	}
	// Retry budget assertion (P31): the configured PublishRetry has
	// MaxAttempts=3 and the batch contains exactly 1 event, so we
	// expect exactly 3 PublishJS attempts. A regression that drops the
	// retry loop or shrinks MaxAttempts would surface here.
	if got, want := pub.Attempts(), int64(3); got != want {
		t.Errorf("PublishJS attempts: got %d, want %d (MaxAttempts=3 x 1 event)", got, want)
	}
}

func TestReceiver_204_When_AllPublishesFailPermanently(t *testing.T) {
	t.Parallel()
	pub := &stubPublisher{}
	pub.permanent.Store(true)
	_, url, tc, _ := startAdapter(t, pub, nil)

	client := mtlsClient(t, tc, true)
	resp, err := client.Post(url, "application/json", bytes.NewReader(mustEventList(t)))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	// Permanent (per-event terminal) failures are dropped at the
	// receiver, NOT 5xx'd back to the apiserver.
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want 204 (permanent drop). body=%s", resp.StatusCode, body)
	}
}

func TestReceiver_Health_FlipsHealthyOnFirstPublish(t *testing.T) {
	t.Parallel()
	pub := &stubPublisher{}
	a, url, tc, _ := startAdapter(t, pub, nil)

	// Initially unhealthy: "awaiting initial inbound traffic".
	healthy, err := a.Health().Status()
	if healthy {
		t.Errorf("expected unhealthy at startup, got healthy=true err=%v", err)
	}

	client := mtlsClient(t, tc, true)
	resp, err := client.Post(url, "application/json", bytes.NewReader(mustEventList(t)))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()

	healthy, _ = a.Health().Status()
	if !healthy {
		t.Errorf("expected healthy after first successful publish")
	}
}

func TestReceiver_Health_StalenessFlipsUnhealthy(t *testing.T) {
	t.Parallel()
	pub := &stubPublisher{}
	a, url, tc, _ := startAdapter(t, pub, func(c *Config) {
		c.StalenessTimeout = 200 * time.Millisecond
	})

	// One publish to flip healthy.
	client := mtlsClient(t, tc, true)
	resp, err := client.Post(url, "application/json", bytes.NewReader(mustEventList(t)))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()

	// Healthy now.
	healthy, _ := a.Health().Status()
	if !healthy {
		t.Fatal("expected healthy after publish")
	}

	// Wait past staleness -- watchdog runs every period/2.
	time.Sleep(800 * time.Millisecond)
	healthy, herr := a.Health().Status()
	if healthy {
		t.Errorf("expected unhealthy after staleness, got healthy=true err=%v", herr)
	}
	if herr == nil || !strings.Contains(herr.Error(), "no successful publish") {
		t.Errorf("expected staleness err message, got %v", herr)
	}
}

func TestNew_RejectsMissingFields(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cases := []struct {
		name string
		mut  func(*Config)
	}{
		{"empty ListenAddr", func(c *Config) { c.ListenAddr = "" }},
		{"empty Hostname", func(c *Config) { c.Hostname = "" }},
		{"empty TLSCertFile", func(c *Config) { c.TLSCertFile = "" }},
		{"empty TLSKeyFile", func(c *Config) { c.TLSKeyFile = "" }},
		{"empty ClientCAFile", func(c *Config) { c.ClientCAFile = "" }},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := Config{
				ListenAddr:   ":1",
				Hostname:     "n",
				TLSCertFile:  "x",
				TLSKeyFile:   "x",
				ClientCAFile: "x",
			}
			tc.mut(&cfg)
			_, err := New(cfg, &stubPublisher{}, logger)
			if err == nil {
				t.Errorf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

// TestIsPermanentPublishError_RejectsSubstringOnlyMatch is the audit-
// side regression net for Story 1.8 P28 (back-port of the cri-side
// drop). Pre-P28 the helper matched a lowercased-substring error
// string ("nats: maximum payload exceeded") as terminal even when
// the typed nats.ErrMaxPayload was nowhere in the chain. Post-P28
// only typed-error paths qualify.
func TestIsPermanentPublishError_RejectsSubstringOnlyMatch(t *testing.T) {
	t.Parallel()
	wrapped := fmt.Errorf("publish: %w", nats.ErrMaxPayload)
	if !isPermanentPublishError(wrapped) {
		t.Errorf("isPermanentPublishError(wrapped ErrMaxPayload): got false, want true")
	}
	stringy := errors.New("nats: maximum payload exceeded")
	if isPermanentPublishError(stringy) {
		t.Errorf("isPermanentPublishError(substring-only): got true, want false (P28 dropped substring fallback)")
	}
	if !isPermanentPublishError(fmt.Errorf("publish: %w", nats.ErrNoResponders)) {
		t.Errorf("isPermanentPublishError(ErrNoResponders): got false, want true")
	}
	if !isPermanentPublishError(fmt.Errorf("publish: %w", natsjs.ErrStreamNotFound)) {
		t.Errorf("isPermanentPublishError(ErrStreamNotFound): got false, want true")
	}
}
