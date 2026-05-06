package audit

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go/jetstream"
	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"

	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// Integration tests in this file spin up an embedded NATS server and
// the receiver with synthetic mTLS material, so the publish path,
// JetStream WithMsgID dedup, and the per-event subject routing are
// all exercised end-to-end against real-but-in-process dependencies.
// `go test -short` skips them; CI runs without -short to exercise the
// full surface (matches the falco integration-test pattern).
//
// AC6 binding interpretation (Story 1.7 Dev Notes, post-review): the
// AC text and Task 8.5 mandate `sigs.k8s.io/controller-runtime/pkg/
// envtest`; the same Story 1.7 Task 8 Recommended note authorises the
// simpler direct-POST shape used here. After the bmad-code-review
// adversarial pass on PR #16 flagged the divergence, the resolution
// (D1) was to codify the deviation as a Dev Notes binding interp
// rather than backfill envtest, and to mark AC6 as "informed" rather
// than "satisfied" in the traceability provenance row. This test
// exercises the receiver against a real HTTPS + mTLS handshake (TLS
// stack, client-cert pool, full audit.k8s.io/v1 EventList JSON
// parser path) plus a real embedded NATS server with JetStream; the
// piece short-circuited is the apiserver's audit-policy enforcement
// (operator-side flag, not part of the receiver's contract).

func skipIfShortAudit(tb testing.TB) {
	tb.Helper()
	if testing.Short() {
		tb.Skip("integration test skipped under -short")
	}
}

func startTestNATS(t testing.TB) *natsserver.Server {
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

func testStreamConfigsAudit() []jetstream.StreamConfig {
	return []jetstream.StreamConfig{
		{
			Name:      "EVENTS_RAW",
			Subjects:  []string{subjects.RawPrefix + ">"},
			MaxAge:    1 * time.Hour,
			MaxBytes:  4 * 1024 * 1024,
			Storage:   jetstream.MemoryStorage,
			Retention: jetstream.LimitsPolicy,
		},
	}
}

// startReceiverWithRealNATS launches the receiver against an embedded
// NATS server with JetStream and returns the receiver URL plus the
// JetStream context for assertions on published messages.
func startReceiverWithRealNATS(t *testing.T) (url string, tc *testCerts, js jetstream.JetStream, cleanup func()) {
	t.Helper()
	srv := startTestNATS(t)
	cfg := natsclient.DefaultConfig()
	cfg.URL = srv.ClientURL()
	cfg.Name = "audit-int-test"
	nc, err := natsclient.NewClient(cfg)
	if err != nil {
		t.Fatalf("nats client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := natsclient.EnsureStreams(ctx, nc.JetStream(), testStreamConfigsAudit()); err != nil {
		t.Fatalf("ensure streams: %v", err)
	}

	tc = genTestCerts(t)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	_ = l.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, err := New(Config{
		ListenAddr:       addr,
		TLSCertFile:      tc.serverCertFile,
		TLSKeyFile:       tc.serverKeyFile,
		ClientCAFile:     tc.clientCAFile,
		Hostname:         testNode,
		MaxPayloadBytes:  1 << 20,
		StalenessTimeout: 5 * time.Second,
		ShutdownGrace:    2 * time.Second,
	}, nc, logger)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- a.Run(runCtx) }()

	// Wait for listener.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, derr := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if derr == nil {
			_ = conn.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	cleanup = func() {
		runCancel()
		select {
		case <-runDone:
		case <-time.After(5 * time.Second):
			t.Errorf("audit Run did not return after cancel")
		}
		closeCtx, c := context.WithTimeout(context.Background(), 2*time.Second)
		defer c()
		_ = nc.Close(closeCtx)
	}
	t.Cleanup(cleanup)

	return fmt.Sprintf("https://%s/audit", addr), tc, nc.JetStream(), cleanup
}

func TestIntegration_HappyPath_PublishesToJetStream(t *testing.T) {
	t.Parallel()
	skipIfShortAudit(t)

	url, tc, js, _ := startReceiverWithRealNATS(t)
	client := mtlsClient(t, tc, true)

	// Send a small batch with three resource shapes -- pod create,
	// rolebinding update, secret read -- to exercise the verb/resource
	// severity matrix and the tag derivation in one go.
	auditID := func(s byte) types.UID {
		var b [16]byte
		for i := range b {
			b[i] = s
		}
		return types.UID(fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
			b[:4], b[4:6], b[6:8], b[8:10], b[10:]))
	}

	list := auditv1.EventList{
		TypeMeta: metav1.TypeMeta{Kind: "EventList", APIVersion: "audit.k8s.io/v1"},
		Items: []auditv1.Event{
			{
				TypeMeta:                 metav1.TypeMeta{Kind: "Event", APIVersion: "audit.k8s.io/v1"},
				Level:                    auditv1.LevelMetadata,
				AuditID:                  auditID(0xAA),
				Stage:                    auditv1.StageResponseComplete,
				Verb:                     "create",
				User:                     authnv1.UserInfo{Username: "alice"},
				ObjectRef:                &auditv1.ObjectReference{Resource: "pods", Namespace: "default", Name: "p"},
				RequestReceivedTimestamp: metav1.NewMicroTime(time.Now()),
			},
			{
				TypeMeta:                 metav1.TypeMeta{Kind: "Event", APIVersion: "audit.k8s.io/v1"},
				Level:                    auditv1.LevelRequestResponse,
				AuditID:                  auditID(0xBB),
				Stage:                    auditv1.StageResponseComplete,
				Verb:                     "update",
				User:                     authnv1.UserInfo{Username: "bob"},
				ObjectRef:                &auditv1.ObjectReference{Resource: "rolebindings", APIGroup: "rbac.authorization.k8s.io", Namespace: "kube-system", Name: "viewer"},
				RequestReceivedTimestamp: metav1.NewMicroTime(time.Now()),
			},
			{
				TypeMeta:                 metav1.TypeMeta{Kind: "Event", APIVersion: "audit.k8s.io/v1"},
				Level:                    auditv1.LevelMetadata,
				AuditID:                  auditID(0xCC),
				Stage:                    auditv1.StageResponseComplete,
				Verb:                     "get",
				User:                     authnv1.UserInfo{Username: "carol"},
				ObjectRef:                &auditv1.ObjectReference{Resource: "secrets", Namespace: "default", Name: "creds"},
				RequestReceivedTimestamp: metav1.NewMicroTime(time.Now()),
			},
		},
	}
	body, err := json.Marshal(&list)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status: got %d, want 204", resp.StatusCode)
	}

	// Drain JetStream for the three messages and assert the per-event
	// subject + WithMsgID dedup contract.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := js.Stream(ctx, "EVENTS_RAW")
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	cons, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       "audit-int-test",
		AckPolicy:     jetstream.AckExplicitPolicy,
		FilterSubject: subjects.RawAudit,
	})
	if err != nil {
		t.Fatalf("consumer: %v", err)
	}

	var seen []schema.Event
	for i := 0; i < 3; i++ {
		batch, err := cons.Fetch(1, jetstream.FetchMaxWait(2*time.Second))
		if err != nil {
			t.Fatalf("fetch: %v", err)
		}
		for msg := range batch.Messages() {
			var ev schema.Event
			if err := json.Unmarshal(msg.Data(), &ev); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			seen = append(seen, ev)
			_ = msg.Ack()
		}
	}
	if len(seen) != 3 {
		t.Fatalf("expected 3 events on EVENTS_RAW, got %d", len(seen))
	}

	// Sort by ID for stable assertions.
	sort.Slice(seen, func(i, j int) bool { return seen[i].ID < seen[j].ID })
	for _, ev := range seen {
		if ev.Source != schema.SourceAudit {
			t.Errorf("source: got %q want %q", ev.Source, schema.SourceAudit)
		}
		if ev.Category != schema.CategoryAudit {
			t.Errorf("category: got %q want %q", ev.Category, schema.CategoryAudit)
		}
		if ev.Pod.Node != testNode {
			t.Errorf("Pod.Node: got %q want %q", ev.Pod.Node, testNode)
		}
	}
}

func TestIntegration_RetryDedup_AtLeastOnce(t *testing.T) {
	t.Parallel()
	skipIfShortAudit(t)

	url, tc, js, _ := startReceiverWithRealNATS(t)
	client := mtlsClient(t, tc, true)

	// Send the same EventList twice. JetStream's WithMsgID dedup
	// (server-side, 2-minute window) must collapse the duplicate so
	// only one message lands per AuditID.
	body := mustEventList(t)

	for i := 0; i < 2; i++ {
		resp, err := client.Post(url, "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("post %d: %v", i, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("status %d: got %d, want 204", i, resp.StatusCode)
		}
	}

	// Read up to 2 messages; the second should not arrive.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := js.Stream(ctx, "EVENTS_RAW")
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	info, err := stream.Info(ctx)
	if err != nil {
		t.Fatalf("stream info: %v", err)
	}
	if info.State.Msgs != 1 {
		t.Errorf("expected JetStream to dedup the duplicate publish, got %d messages", info.State.Msgs)
	}
}

// TestIntegration_TLSHandshakeWithCorrectCert sanity-checks the full
// mTLS path with a verified client certificate; complements the unit
// reject tests by confirming a valid cert reaches the handler.
func TestIntegration_TLSHandshakeWithCorrectCert(t *testing.T) {
	t.Parallel()
	skipIfShortAudit(t)

	url, tc, _, _ := startReceiverWithRealNATS(t)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(tc.caPEM)
	cert, err := tls.X509KeyPair(tc.clientCertPEM, tc.clientKeyPEM)
	if err != nil {
		t.Fatalf("kp: %v", err)
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:      pool,
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			ServerName:   "localhost",
		}},
		Timeout: 5 * time.Second,
	}
	resp, err := client.Post(url, "application/json", bytes.NewReader(mustEventList(t)))
	if err != nil {
		t.Fatalf("post with valid mTLS: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status: got %d, want 204", resp.StatusCode)
	}
}
