//go:build integration

package notify

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/olokotoh/olaitan/internal/metrics"
	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/report/dfir"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// This integration test asserts NO external infra is required: it stands up an
// in-process NATS server with JetStream, provisions the REPORTS stream, runs the
// real webhook controller as a durable consumer against an httptest.Server, and
// exercises the success / retry / exhaust delivery paths end-to-end. It skips
// cleanly when the in-process server cannot start (no infra needed beyond the
// pure-Go embedded server).

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func startTestServer(t *testing.T) *natsserver.Server {
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
		t.Skipf("in-process nats server unavailable: %v", err)
	}
	srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Skip("nats server not ready")
	}
	t.Cleanup(srv.Shutdown)
	return srv
}

func newTestClient(t *testing.T, srv *natsserver.Server) *natsclient.Client {
	t.Helper()
	c, err := natsclient.NewClient(natsclient.ClientConfig{
		URL:              srv.ClientURL(),
		Name:             "notify-it",
		MaxReconnects:    0,
		ReconnectWait:    time.Second,
		ReconnectBufSize: 1 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

func ensureReportsStream(t *testing.T, c *natsclient.Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.JetStream().CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:       "REPORTS",
		Subjects:   []string{subjects.ReportsGenerated},
		MaxAge:     time.Hour,
		MaxBytes:   1 * 1024 * 1024,
		Storage:    jetstream.MemoryStorage,
		Retention:  jetstream.LimitsPolicy,
		Duplicates: 2 * time.Minute,
	}); err != nil {
		t.Fatalf("ensure REPORTS stream: %v", err)
	}
}

func publishReport(t *testing.T, c *natsclient.Client, evt dfir.ReportGenerated) {
	t.Helper()
	pub, err := dfir.NewNATSReportPublisher(c)
	if err != nil {
		t.Fatalf("NewNATSReportPublisher: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := pub.PublishReportGenerated(ctx, evt); err != nil {
		t.Fatalf("publish report generated: %v", err)
	}
}

func itEvent(sha string) dfir.ReportGenerated {
	return dfir.ReportGenerated{
		SchemaVersion:    dfir.SchemaVersionReportGenerated,
		IncidentID:       "pkg-" + sha,
		WorkloadID:       "ns/Deployment/web",
		ReportSHA256:     sha,
		ReportURL:        "reports/2026/06/14/" + sha + ".md",
		FinalFSMState:    "QUARANTINED",
		GeneratedAt:      time.Date(2026, 6, 14, 10, 0, 0, 0, time.UTC),
		ThreatScore:      88.5,
		AttackTechniques: []string{"T1611"},
	}
}

// TestIntegration_WebhookConsumerSuccess: a real durable consumer of
// REPORTS.generated, against an httptest.Server returning 200, delivers the POST
// once and counts delivered (AC4 success path, against embedded NATS).
func TestIntegration_WebhookConsumerSuccess(t *testing.T) {
	var got payload
	var count int32
	target := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&count, 1)
		_ = json.NewDecoder(r.Body).Decode(&got)
		rw.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	srv := startTestServer(t)
	c := newTestClient(t, srv)
	ensureReportsStream(t, c)

	cfg := Config{URL: target.URL, RetryMaxAttempts: 3, RetryMin: time.Millisecond, RetryMax: 2 * time.Millisecond, Timeout: 2 * time.Second}
	w, err := NewWebhook(cfg, metrics.NewRegistry(), discardLog())
	if err != nil {
		t.Fatalf("NewWebhook: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx, c) }()

	publishReport(t, c, itEvent("aaa1"))

	waitUntil(t, 3*time.Second, func() bool { return atomic.LoadInt32(&count) == 1 })
	cancel()
	if rerr := <-done; rerr != nil {
		t.Fatalf("Run returned: %v", rerr)
	}
	if got.IdempotencyKey != "aaa1" || got.WorkloadID != "ns/Deployment/web" {
		t.Errorf("delivered payload wrong: %+v", got)
	}
	if testutil.ToFloat64(w.delivered.WithLabelValues("delivered")) != 1 {
		t.Errorf("delivered counter != 1")
	}
}

// TestIntegration_WebhookConsumerExhaustDoesNotStall: an always-503 target
// exhausts retry, counts failed, and the consumer drop-and-acks so a SECOND
// report still gets processed (a flaky target never stalls the cursor, AC3/AC4).
func TestIntegration_WebhookConsumerExhaustDoesNotStall(t *testing.T) {
	var count int32
	target := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&count, 1)
		rw.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer target.Close()

	srv := startTestServer(t)
	c := newTestClient(t, srv)
	ensureReportsStream(t, c)

	cfg := Config{URL: target.URL, RetryMaxAttempts: 2, RetryMin: time.Millisecond, RetryMax: 2 * time.Millisecond, Timeout: 2 * time.Second}
	w, err := NewWebhook(cfg, metrics.NewRegistry(), discardLog())
	if err != nil {
		t.Fatalf("NewWebhook: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx, c) }()

	publishReport(t, c, itEvent("bbb1"))
	publishReport(t, c, itEvent("bbb2"))

	// Two reports x 2 attempts each = 4 POSTs; both are drop-and-acked.
	waitUntil(t, 5*time.Second, func() bool {
		return testutil.ToFloat64(w.delivered.WithLabelValues("failed")) == 2
	})
	cancel()
	if rerr := <-done; rerr != nil {
		t.Fatalf("Run returned (the consumer must never crash-loop): %v", rerr)
	}
	if testutil.ToFloat64(w.delivered.WithLabelValues("failed")) != 2 {
		t.Errorf("a stalled cursor: only %v reports reached the exhaust path, want 2",
			testutil.ToFloat64(w.delivered.WithLabelValues("failed")))
	}
}

func waitUntil(t *testing.T, within time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", within)
}
