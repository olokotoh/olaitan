//go:build integration

package cni

import (
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
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	natsjs "github.com/nats-io/nats.go/jetstream"

	"github.com/olokotoh/olaitan/internal/collector/cni/goldmanepb"
	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// startTestNATS spins up an embedded NATS server with JetStream so
// the integration test exercises the real publish path (NFR36: no
// mock-only ring boundaries).
func startTestNATS(t *testing.T) *natsserver.Server {
	t.Helper()
	opts := &natsserver.Options{
		Host:      "127.0.0.1",
		Port:      -1,
		JetStream: true,
		StoreDir:  t.TempDir(),
		NoLog:     true,
		NoSigs:    true,
	}
	srv, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatalf("start test nats server: %v", err)
	}
	srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats server not ready")
	}
	t.Cleanup(srv.Shutdown)
	return srv
}

// natsTestStreamConfigs is the in-process EVENTS_RAW stream config
// (memory storage, tiny budget) the test exercises. We do not import
// the production StreamConfigs because the production ones request
// file storage which thrashes the test temp dir.
func natsTestStreamConfigs() []natsjs.StreamConfig {
	return []natsjs.StreamConfig{
		{
			Name:       "EVENTS_RAW",
			Subjects:   []string{subjects.RawPrefix + ">"},
			MaxAge:     1 * time.Hour,
			MaxBytes:   1 * 1024 * 1024,
			Storage:    natsjs.MemoryStorage,
			Retention:  natsjs.LimitsPolicy,
			Duplicates: 2 * time.Minute,
		},
	}
}

// testTLSMaterial holds the CA, server, and client materials for a
// fresh mTLS setup. Each integration test gets its own set so cert
// leakage between tests is impossible.
type testTLSMaterial struct {
	caPEM          []byte
	caPath         string
	serverCert     tls.Certificate
	clientCert     tls.Certificate
	clientCert2    tls.Certificate // signed by a DIFFERENT CA (for unauthenticated test)
	clientCAPath   string
	clientCertPath string
	clientKeyPath  string
}

// newTestTLSMaterial builds a fresh self-signed CA, a server cert,
// and a client cert. Returns the assembled material plus written-to-
// disk file paths (the adapter consumes file paths, not in-memory
// certs).
//
// All certs are valid for 24 hours and use prime256v1 ECDSA for fast
// generation; the test does not exercise long-running cert lifetimes.
func newTestTLSMaterial(t *testing.T) *testTLSMaterial {
	t.Helper()
	dir := t.TempDir()

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "olaitan-test-ca"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, caPEM, 0o644); err != nil {
		t.Fatalf("write ca: %v", err)
	}

	mkPair := func(cn string, isServer bool) tls.Certificate {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-1 * time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		if isServer {
			tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			tpl.DNSNames = []string{"localhost"}
			tpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		} else {
			tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, tpl, caTpl, &key.PublicKey, caKey)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		keyDER, _ := x509.MarshalECPrivateKey(key)
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatalf("X509KeyPair: %v", err)
		}
		return cert
	}

	serverCert := mkPair("goldmane-test-server", true)
	clientCert := mkPair("olaitan-agent", false)

	// Write client cert + key for the adapter to load from disk.
	clientCertBlock := &pem.Block{Type: "CERTIFICATE", Bytes: clientCert.Certificate[0]}
	clientKeyBytes, _ := x509.MarshalECPrivateKey(clientCert.PrivateKey.(*ecdsa.PrivateKey))
	clientKeyBlock := &pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyBytes}
	clientCertPath := filepath.Join(dir, "client.crt")
	clientKeyPath := filepath.Join(dir, "client.key")
	if err := os.WriteFile(clientCertPath, pem.EncodeToMemory(clientCertBlock), 0o644); err != nil {
		t.Fatalf("write client cert: %v", err)
	}
	if err := os.WriteFile(clientKeyPath, pem.EncodeToMemory(clientKeyBlock), 0o600); err != nil {
		t.Fatalf("write client key: %v", err)
	}

	// Build a client cert signed by a DIFFERENT CA for the
	// "unauthenticated" path.
	rogueCAKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rogueCATpl := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "olaitan-rogue-ca"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	rogueDER, _ := x509.CreateCertificate(rand.Reader, rogueCATpl, rogueCATpl, &rogueCAKey.PublicKey, rogueCAKey)
	rogueClientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rogueClientTpl := &x509.Certificate{
		SerialNumber: big.NewInt(11),
		Subject:      pkix.Name{CommonName: "olaitan-rogue-client"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	rogueCertDER, _ := x509.CreateCertificate(rand.Reader, rogueClientTpl, rogueCATpl, &rogueClientKey.PublicKey, rogueCAKey)
	rogueCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rogueCertDER})
	rogueKeyDER, _ := x509.MarshalECPrivateKey(rogueClientKey)
	rogueKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: rogueKeyDER})
	rogueClientCert, _ := tls.X509KeyPair(rogueCertPEM, rogueKeyPEM)
	_ = rogueDER

	return &testTLSMaterial{
		caPEM:          caPEM,
		caPath:         caPath,
		serverCert:     serverCert,
		clientCert:     clientCert,
		clientCert2:    rogueClientCert,
		clientCAPath:   caPath,
		clientCertPath: clientCertPath,
		clientKeyPath:  clientKeyPath,
	}
}

// fakeFlowsServer streams the supplied FlowResults in order then
// optionally errors. It is intentionally minimal: AC4's real-boundary
// requirement is satisfied by exercising the real grpc.NewServer
// framing, mTLS handshake, and stream.Send path; this server is not
// a Goldmane replacement and does not honour the FlowFilter.
type fakeFlowsServer struct {
	goldmanepb.UnimplementedFlowsServer
	fixtures []*goldmanepb.FlowResult
	postErr  error // returned after fixtures are sent; nil means block on ctx
	mu       sync.Mutex
	calls    atomic.Int32
}

func (f *fakeFlowsServer) Stream(_ *goldmanepb.FlowStreamRequest, stream grpc.ServerStreamingServer[goldmanepb.FlowResult]) error {
	f.calls.Add(1)
	for _, fr := range f.fixtures {
		if err := stream.Send(fr); err != nil {
			return err
		}
	}
	if f.postErr != nil {
		return f.postErr
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

// startMTLSGoldmaneServer binds a real net.Listen TCP socket, wraps
// it in a grpc.NewServer with mTLS credentials assembled from the
// supplied material, and registers the fakeFlowsServer. Returns the
// gRPC dial address (host:port).
func startMTLSGoldmaneServer(t *testing.T, m *testTLSMaterial, fake *fakeFlowsServer) string {
	t.Helper()
	clientCAs := x509.NewCertPool()
	clientCAs.AppendCertsFromPEM(m.caPEM)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{m.serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		MinVersion:   tls.VersionTLS12,
	}
	creds := credentials.NewTLS(tlsCfg)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer(grpc.Creds(creds))
	goldmanepb.RegisterFlowsServer(srv, fake)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() {
		srv.GracefulStop()
		_ = lis.Close()
	})
	return lis.Addr().String()
}

// integrationFixture returns one valid FlowResult; rolled separately
// from translate_test.go's validFixture because integration tests
// may want subtly different field combinations and the two should
// not share state.
func integrationFixture() *goldmanepb.FlowResult {
	return &goldmanepb.FlowResult{
		Id: 7,
		Flow: &goldmanepb.Flow{
			StartTime: time.Now().Add(-30 * time.Second).Unix(),
			EndTime:   time.Now().Add(-15 * time.Second).Unix(),
			Key: &goldmanepb.FlowKey{
				SourceNamespace: "spike-traffic",
				SourceName:      "curl-loop-",
				SourceType:      goldmanepb.EndpointType_WorkloadEndpoint,
				DestNamespace:   "spike-traffic",
				DestName:        "nginx-",
				DestType:        goldmanepb.EndpointType_WorkloadEndpoint,
				DestPort:        80,
				Proto:           "tcp",
				Action:          goldmanepb.Action_Allow,
				Reporter:        goldmanepb.Reporter_Src,
			},
		},
	}
}

// newIntegrationClient returns a NATS client connected to the test
// server with the EVENTS_RAW stream pre-provisioned.
func newIntegrationClient(t *testing.T, srv *natsserver.Server) *natsclient.Client {
	t.Helper()
	cfg := natsclient.DefaultConfig()
	cfg.URL = srv.ClientURL()
	cfg.Name = "cni-integration-test"
	nc, err := natsclient.NewClient(cfg)
	if err != nil {
		t.Fatalf("nats client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := natsclient.EnsureStreams(ctx, nc.JetStream(), natsTestStreamConfigs()); err != nil {
		t.Fatalf("ensure streams: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = nc.Close(ctx)
	})
	return nc
}

func newIntegrationAdapter(t *testing.T, m *testTLSMaterial, addr string, nc *natsclient.Client) *Adapter {
	t.Helper()
	cfg := Config{
		GoldmaneAddr:        addr,
		ServerName:          "localhost",
		CABundlePath:        m.caPath,
		ClientCertPath:      m.clientCertPath,
		ClientKeyPath:       m.clientKeyPath,
		DialTimeout:         5 * time.Second,
		StalenessTimeout:    250 * time.Millisecond,
		AggregationInterval: 15,
		StartTimeGte:        -60,
		Hostname:            "integration-test-node",
	}
	a, err := New(cfg, nc, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

// consumeOne pulls one NATS message from the supplied subject within
// timeout. Returns the raw payload bytes.
func consumeOne(t *testing.T, srv *natsserver.Server, subject string, timeout time.Duration) []byte {
	t.Helper()
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatalf("nats.Connect: %v", err)
	}
	defer conn.Close()
	js, err := natsjs.New(conn)
	if err != nil {
		t.Fatalf("jetstream.New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cons, err := js.CreateOrUpdateConsumer(ctx, "EVENTS_RAW", natsjs.ConsumerConfig{
		Name:          "test-consumer",
		FilterSubject: subject,
		AckPolicy:     natsjs.AckExplicitPolicy,
	})
	if err != nil {
		t.Fatalf("create consumer: %v", err)
	}
	msg, err := cons.Next(natsjs.FetchMaxWait(timeout))
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	_ = msg.Ack()
	return msg.Data()
}

func TestIntegration_ConnectsAndPublishesOneFlow(t *testing.T) {
	natsSrv := startTestNATS(t)
	nc := newIntegrationClient(t, natsSrv)
	m := newTestTLSMaterial(t)

	fixture := integrationFixture()
	fake := &fakeFlowsServer{fixtures: []*goldmanepb.FlowResult{fixture}}
	addr := startMTLSGoldmaneServer(t, m, fake)

	a := newIntegrationAdapter(t, m, addr, nc)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	data := consumeOne(t, natsSrv, subjects.RawNetwork, 5*time.Second)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Errorf("Run did not return within 2s of cancel")
	}

	var ev schema.Event
	if err := json.Unmarshal(data, &ev); err != nil {
		t.Fatalf("unmarshal published event: %v", err)
	}
	if ev.Source != schema.SourceNetwork {
		t.Errorf("Source: got %q, want %q", ev.Source, schema.SourceNetwork)
	}
	if ev.Category != schema.CategoryFlow {
		t.Errorf("Category: got %q, want %q", ev.Category, schema.CategoryFlow)
	}
	hasGenName := false
	for _, tg := range ev.Tags {
		if tg == "pod_name_kind:generatename" {
			hasGenName = true
		}
	}
	if !hasGenName {
		t.Errorf("missing pod_name_kind:generatename tag (have %v)", ev.Tags)
	}
}

func TestIntegration_HealthFlipOnDialFailure(t *testing.T) {
	natsSrv := startTestNATS(t)
	nc := newIntegrationClient(t, natsSrv)
	m := newTestTLSMaterial(t)

	// Point the adapter at a closed TCP port: the dial fails fast
	// with "connection refused". 127.0.0.1:1 is reliably-closed
	// on a Linux host.
	a := newIntegrationAdapter(t, m, "127.0.0.1:1", nc)
	a.cfg.ConnectRetry.Min = 5 * time.Millisecond
	a.cfg.ConnectRetry.Max = 20 * time.Millisecond
	a.cfg.DialTimeout = 200 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		healthy, lastErr := a.Health().Status()
		if !healthy && lastErr != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("Health did not flip unhealthy within 3s")
}

func TestIntegration_TerminalErrorOnUnauthenticatedClient(t *testing.T) {
	natsSrv := startTestNATS(t)
	nc := newIntegrationClient(t, natsSrv)
	m := newTestTLSMaterial(t)
	// Use the rogue client cert that the server's CA does not
	// trust. Write rogue cert + key to disk under names the adapter
	// loads.
	dir := t.TempDir()
	rogueCert := m.clientCert2
	rogueCertPath := filepath.Join(dir, "rogue.crt")
	rogueKeyPath := filepath.Join(dir, "rogue.key")
	certBlock := &pem.Block{Type: "CERTIFICATE", Bytes: rogueCert.Certificate[0]}
	keyBytes, _ := x509.MarshalECPrivateKey(rogueCert.PrivateKey.(*ecdsa.PrivateKey))
	keyBlock := &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}
	if err := os.WriteFile(rogueCertPath, pem.EncodeToMemory(certBlock), 0o644); err != nil {
		t.Fatalf("write rogue cert: %v", err)
	}
	if err := os.WriteFile(rogueKeyPath, pem.EncodeToMemory(keyBlock), 0o600); err != nil {
		t.Fatalf("write rogue key: %v", err)
	}

	fake := &fakeFlowsServer{}
	addr := startMTLSGoldmaneServer(t, m, fake)

	cfg := Config{
		GoldmaneAddr:        addr,
		ServerName:          "localhost",
		CABundlePath:        m.caPath,
		ClientCertPath:      rogueCertPath,
		ClientKeyPath:       rogueKeyPath,
		DialTimeout:         2 * time.Second,
		StalenessTimeout:    250 * time.Millisecond,
		AggregationInterval: 15,
		StartTimeGte:        -60,
	}
	a, err := New(cfg, nc, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Tight retry so the test ends quickly on a non-terminal path.
	a.cfg.ConnectRetry.Min = 5 * time.Millisecond
	a.cfg.ConnectRetry.Max = 20 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	runErr := a.Run(ctx)
	// Goldmane's mTLS rejection surfaces as either a TLS-layer
	// handshake error (transient) or a gRPC Unauthenticated code
	// (terminal). Either way the adapter must mark itself unhealthy.
	healthy, lastErr := a.Health().Status()
	if healthy {
		t.Errorf("Health: want unhealthy on rogue-CA cert; lastErr=%v, runErr=%v", lastErr, runErr)
	}
}

func TestIntegration_MsgIDDedupAcrossRepublish(t *testing.T) {
	natsSrv := startTestNATS(t)
	nc := newIntegrationClient(t, natsSrv)
	m := newTestTLSMaterial(t)

	// Run the same fixture twice: the adapter publishes a fresh
	// schema.Event with a deterministic ID (calico-flow-<start>-<id>)
	// each time. With WithMsgID dedup the second publish is
	// suppressed by NATS within the 2m duplicate window.
	fixture := integrationFixture()
	fake := &fakeFlowsServer{fixtures: []*goldmanepb.FlowResult{fixture, fixture}}
	addr := startMTLSGoldmaneServer(t, m, fake)

	a := newIntegrationAdapter(t, m, addr, nc)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()

	// Wait long enough for both publishes to attempt.
	time.Sleep(1 * time.Second)

	// Check stream's message count: should be exactly 1 (dedup).
	conn, err := nats.Connect(natsSrv.ClientURL())
	if err != nil {
		t.Fatalf("nats.Connect: %v", err)
	}
	defer conn.Close()
	js, err := natsjs.New(conn)
	if err != nil {
		t.Fatalf("jetstream.New: %v", err)
	}
	ctxQ, cancelQ := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelQ()
	stream, err := js.Stream(ctxQ, "EVENTS_RAW")
	if err != nil {
		t.Fatalf("stream lookup: %v", err)
	}
	info, err := stream.Info(ctxQ)
	if err != nil {
		t.Fatalf("stream info: %v", err)
	}
	if info.State.Msgs != 1 {
		t.Errorf("EVENTS_RAW msg count after dedup: got %d, want 1", info.State.Msgs)
	}
}

func TestIntegration_StreamRecvErrorTriggersReconnect(t *testing.T) {
	natsSrv := startTestNATS(t)
	nc := newIntegrationClient(t, natsSrv)
	m := newTestTLSMaterial(t)

	// Server emits one fixture then closes the stream with
	// codes.Unavailable; the adapter should reconnect.
	fixture := integrationFixture()
	fake := &fakeFlowsServer{
		fixtures: []*goldmanepb.FlowResult{fixture},
		postErr:  status.Error(codes.Unavailable, "synthetic stream tear-down"),
	}
	addr := startMTLSGoldmaneServer(t, m, fake)

	a := newIntegrationAdapter(t, m, addr, nc)
	a.cfg.ConnectRetry.Min = 5 * time.Millisecond
	a.cfg.ConnectRetry.Max = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()

	// Wait for the server to log at least 2 Stream calls (one fail
	// then one reconnect).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if fake.calls.Load() >= 2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("expected adapter to reconnect after stream tear-down (calls=%d)", fake.calls.Load())
}

// compile-time check: avoid unused-helper warnings when the test
// suite shrinks across edits.
var _ = errors.New
var _ = fmt.Sprintf
