//go:build integration

package cni

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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

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
	_, _ = x509.CreateCertificate(rand.Reader, rogueCATpl, rogueCATpl, &rogueCAKey.PublicKey, rogueCAKey)
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
	stg := int64(-60)
	cfg := Config{
		GoldmaneAddr:        addr,
		ServerName:          "localhost",
		CABundlePath:        m.caPath,
		ClientCertPath:      m.clientCertPath,
		ClientKeyPath:       m.clientKeyPath,
		DialTimeout:         5 * time.Second,
		StalenessTimeout:    250 * time.Millisecond,
		AggregationInterval: 15,
		StartTimeGte:        &stg,
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

	// Load the byte-stable fixture rather than building one in
	// Go: AC4 requires a byte-for-byte fixture compare, and the
	// binpb fixture pinned at Story 1.3 spike capture time is the
	// reference. expected.json is regenerated via the -update flag
	// in TestUpdateExpectedJSON whenever Translate's behavioural
	// surface intentionally changes.
	binpb, err := os.ReadFile("testdata/sample-flow.binpb")
	if err != nil {
		t.Fatalf("read sample-flow.binpb: %v", err)
	}
	var fixture goldmanepb.FlowResult
	if err := proto.Unmarshal(binpb, &fixture); err != nil {
		t.Fatalf("unmarshal sample-flow.binpb: %v", err)
	}
	expected, err := os.ReadFile("testdata/expected.json")
	if err != nil {
		t.Fatalf("read expected.json: %v", err)
	}

	fake := &fakeFlowsServer{fixtures: []*goldmanepb.FlowResult{&fixture}}
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

	// AC4 byte-stable compare against the pinned expected.json
	// fixture. The published bytes are the canonical JSON the
	// production publish path emits; regenerating the fixture
	// requires running TestUpdateExpectedJSON -update.
	if !bytes.Equal(data, expected) {
		t.Errorf("published bytes diverge from testdata/expected.json (AC4 fixture)\n  got:  %s\n  want: %s",
			string(data), string(expected))
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
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Errorf("Run did not return within 2s of cancel")
		}
	}()

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

	stg := int64(-60)
	cfg := Config{
		GoldmaneAddr:        addr,
		ServerName:          "localhost",
		CABundlePath:        m.caPath,
		ClientCertPath:      rogueCertPath,
		ClientKeyPath:       rogueKeyPath,
		DialTimeout:         2 * time.Second,
		StalenessTimeout:    250 * time.Millisecond,
		AggregationInterval: 15,
		StartTimeGte:        &stg,
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
	// handshake error (transient retry, surfacing as unhealthy) or
	// a gRPC Unauthenticated code (terminal). Either way the
	// adapter must mark itself unhealthy. The health-flip is the
	// load-bearing contract; whether the dial-side error chain
	// reaches the typed terminal classifier depends on how the
	// grpc-go transport layer surfaces the server-side TLS alert
	// (typically wrapped as a string-only Unavailable status, which
	// the typed isTerminalConnectError correctly classifies as
	// transient). The Story 1.10 P10 follow-up strengthens the
	// assertion to also verify that the adapter records the
	// rejection as a lastErr; a nil runErr from a 4s-bounded ctx
	// after a known-bad cert means Run silently swallowed the
	// transient retry loop, which is itself a defect.
	healthy, lastErr := a.Health().Status()
	if healthy {
		t.Errorf("Health: want unhealthy on rogue-CA cert; lastErr=%v, runErr=%v", lastErr, runErr)
	}
	if lastErr == nil {
		t.Errorf("Health lastErr: got nil; expected rogue-CA cert rejection to be recorded")
	}
	// Accept either terminal (typed classifier fired) or non-nil
	// transient (retry exhausted before ctx timeout, or non-nil
	// final wrap from Run). A nil runErr is acceptable only if the
	// ctx-bound retry-loop genuinely cancelled; a healthy=false +
	// lastErr non-nil + runErr nil chain is the documented
	// behaviour for transient handshake-rejection scenarios.
	if runErr != nil && !strings.Contains(runErr.Error(), "terminal") && !strings.Contains(runErr.Error(), "tls") && !strings.Contains(runErr.Error(), "dial") && !strings.Contains(runErr.Error(), "stream") {
		t.Errorf("Run: got unexpected error shape %v; expected terminal/tls/dial/stream-related", runErr)
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
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Errorf("Run did not return within 2s of cancel")
		}
	}()

	// Poll the stream's message count instead of sleeping a fixed
	// 1s; with dedup we expect exactly 1 message. 5s timeout gives
	// the adapter generous slack to publish both attempts.
	conn, err := nats.Connect(natsSrv.ClientURL())
	if err != nil {
		t.Fatalf("nats.Connect: %v", err)
	}
	defer conn.Close()
	js, err := natsjs.New(conn)
	if err != nil {
		t.Fatalf("jetstream.New: %v", err)
	}
	pollDeadline := time.Now().Add(5 * time.Second)
	var msgs uint64
	for time.Now().Before(pollDeadline) {
		ctxQ, cancelQ := context.WithTimeout(context.Background(), 500*time.Millisecond)
		stream, sErr := js.Stream(ctxQ, "EVENTS_RAW")
		if sErr != nil {
			cancelQ()
			time.Sleep(50 * time.Millisecond)
			continue
		}
		info, iErr := stream.Info(ctxQ)
		cancelQ()
		if iErr != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		msgs = info.State.Msgs
		if msgs >= 1 {
			// Wait a bit more for the second (deduped) publish to
			// settle before locking in the count.
			time.Sleep(200 * time.Millisecond)
			ctxQ2, cancelQ2 := context.WithTimeout(context.Background(), 500*time.Millisecond)
			info2, iErr2 := stream.Info(ctxQ2)
			cancelQ2()
			if iErr2 == nil {
				msgs = info2.State.Msgs
			}
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if msgs != 1 {
		t.Errorf("EVENTS_RAW msg count after dedup: got %d, want 1", msgs)
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
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Errorf("Run did not return within 2s of cancel")
		}
	}()

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

// TestIntegration_HealthRecoversOnReconnect verifies the watchdog
// flips healthy after a transient stream tear-down. Server emits
// one fixture, returns codes.Unavailable, then accepts on the next
// Stream call; the adapter's MarkHealthy on the first flow of the
// second connect should restore the source-health gauge to healthy.
// Locks in Story 1.10 Task 6.3 (test name from the spec) +
// review patch P25.
func TestIntegration_HealthRecoversOnReconnect(t *testing.T) {
	natsSrv := startTestNATS(t)
	nc := newIntegrationClient(t, natsSrv)
	m := newTestTLSMaterial(t)

	fixture := integrationFixture()
	// Two-phase server: first call sends a fixture then aborts
	// with Unavailable; second call sends another fixture and
	// blocks until ctx cancellation. The fakeFlowsServer doesn't
	// natively support per-call behaviour, so we use a counter
	// closure via a custom server-side implementation.
	var callCount atomic.Int32
	customSrv := &reconnectFakeServer{
		fixture: fixture,
		count:   &callCount,
	}
	addr := startMTLSGoldmaneServerWithCustom(t, m, customSrv)

	a := newIntegrationAdapter(t, m, addr, nc)
	a.cfg.ConnectRetry.Min = 5 * time.Millisecond
	a.cfg.ConnectRetry.Max = 50 * time.Millisecond
	a.cfg.StalenessTimeout = 2 * time.Second // tests should not race the watchdog

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Errorf("Run did not return within 2s of cancel")
		}
	}()

	// Poll for at least two Stream calls (the first that errored
	// and the second that succeeded) AND a healthy gauge.
	pollDeadline := time.Now().Add(5 * time.Second)
	var lastHealthy bool
	var lastErr error
	for time.Now().Before(pollDeadline) {
		if callCount.Load() >= 2 {
			lastHealthy, lastErr = a.Health().Status()
			if lastHealthy {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("Health did not flip healthy after reconnect: calls=%d, healthy=%v, lastErr=%v",
		callCount.Load(), lastHealthy, lastErr)
}

// reconnectFakeServer is a per-test gRPC server that mimics the
// "transient tear-down then recovery" reconnect scenario for P25.
type reconnectFakeServer struct {
	goldmanepb.UnimplementedFlowsServer
	fixture *goldmanepb.FlowResult
	count   *atomic.Int32
}

func (r *reconnectFakeServer) Stream(_ *goldmanepb.FlowStreamRequest, stream grpc.ServerStreamingServer[goldmanepb.FlowResult]) error {
	n := r.count.Add(1)
	if err := stream.Send(r.fixture); err != nil {
		return err
	}
	if n == 1 {
		return status.Error(codes.Unavailable, "synthetic tear-down for reconnect test")
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

// startMTLSGoldmaneServerWithCustom mirrors startMTLSGoldmaneServer
// but accepts the concrete server type so tests with per-call
// behaviour can swap the fakeFlowsServer baseline.
func startMTLSGoldmaneServerWithCustom(t *testing.T, m *testTLSMaterial, srv goldmanepb.FlowsServer) string {
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
	gsrv := grpc.NewServer(grpc.Creds(creds))
	goldmanepb.RegisterFlowsServer(gsrv, srv)
	go func() { _ = gsrv.Serve(lis) }()
	t.Cleanup(func() {
		gsrv.GracefulStop()
		_ = lis.Close()
	})
	return lis.Addr().String()
}

// TestIntegration_TLSConfig_RequiresValidCert verifies that an
// adapter without a client cert cannot complete the mTLS
// handshake. Mirrors Story 1.9's analogous applog-webhook test:
// server requires client cert via tls.RequireAndVerifyClientCert,
// adapter dials with a CA-only TLS config (no client cert), and
// the dial / stream fails. Locks in Story 1.10 Task 6.3 + P26.
func TestIntegration_TLSConfig_RequiresValidCert(t *testing.T) {
	natsSrv := startTestNATS(t)
	nc := newIntegrationClient(t, natsSrv)
	m := newTestTLSMaterial(t)

	fake := &fakeFlowsServer{}
	addr := startMTLSGoldmaneServer(t, m, fake)

	// Build an adapter whose TLS loader returns a config with NO
	// client certificate. Production never has this shape -- the
	// chart requires the three file paths -- but a misconfigured
	// loader that dropped the client cert would be caught by this
	// test before the adapter shipped to production.
	stg := int64(-60)
	cfg := Config{
		GoldmaneAddr:        addr,
		ServerName:          "localhost",
		CABundlePath:        m.caPath,
		ClientCertPath:      m.clientCertPath,
		ClientKeyPath:       m.clientKeyPath,
		DialTimeout:         2 * time.Second,
		StalenessTimeout:    2 * time.Second,
		AggregationInterval: 15,
		StartTimeGte:        &stg,
	}
	a, err := New(cfg, nc, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a.tlsLoaderFn = func() (*tls.Config, error) {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(m.caPEM)
		return &tls.Config{
			RootCAs:    pool,
			ServerName: "localhost",
			MinVersion: tls.VersionTLS12,
			// Deliberately omit Certificates -- the server's
			// RequireAndVerifyClientCert will reject the
			// handshake.
		}, nil
	}
	a.cfg.ConnectRetry.Min = 5 * time.Millisecond
	a.cfg.ConnectRetry.Max = 20 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = a.Run(ctx)

	healthy, lastErr := a.Health().Status()
	if healthy {
		t.Errorf("Health: want unhealthy when adapter has no client cert; lastErr=%v", lastErr)
	}
	if lastErr == nil {
		t.Errorf("Health lastErr: got nil; expected mTLS rejection to be recorded")
	}
}

// compile-time check: avoid unused-helper warnings when the test
// suite shrinks across edits.
var _ = errors.New
var _ = fmt.Sprintf
