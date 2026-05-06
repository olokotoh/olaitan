package audit

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"testing"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"

	natsclient "github.com/olokotoh/olaitan/internal/nats"
)

// BenchmarkAdapter_PublishLatency measures end-to-end (HTTP POST →
// PubAck) latency for the receiver. NFR1 budget: p99 ≤ 50ms at 1000
// events/sec/node. The benchmark drives single-event batches against
// a real embedded NATS server; per-iteration latencies are sorted to
// extract p50 and p99, reported as Go bench metrics.
//
// `ns/op` is suppressed (set to 0) per Story 1.6 patch precedent --
// the wall-clock per-iteration timing is not meaningful in
// isolation; the p50/p99 metrics carry the contract.
//
// Run via:
//
//	go test -run=^$ -bench=BenchmarkAdapter_PublishLatency \
//	    -benchtime=10s ./internal/collector/audit/...
//
// Production-class measurement (the AC4 evidence) lands in Story 5.1.
func BenchmarkAdapter_PublishLatency(b *testing.B) {
	if testing.Short() {
		b.Skip("benchmark skipped under -short")
	}
	srv := startTestNATS(b)
	cfg := natsclient.DefaultConfig()
	cfg.URL = srv.ClientURL()
	cfg.Name = "audit-bench"
	nc, err := natsclient.NewClient(cfg)
	if err != nil {
		b.Fatalf("nats: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = nc.Close(ctx)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := natsclient.EnsureStreams(ctx, nc.JetStream(), testStreamConfigsAudit()); err != nil {
		cancel()
		b.Fatalf("ensure streams: %v", err)
	}
	cancel()

	// Receiver setup -- same shape as the integration test.
	tc := genTestCertsB(b)
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
		StalenessTimeout: 5 * time.Minute,
		ShutdownGrace:    2 * time.Second,
	}, nc, logger)
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	runCtx, runCancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- a.Run(runCtx) }()
	defer func() {
		runCancel()
		<-runDone
	}()

	// Wait for listener.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, derr := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if derr == nil {
			_ = conn.Close()
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Build a constant payload so the bench loop measures the
	// receive→publish→ack path rather than per-event JSON build cost.
	mkBody := func(seq int) []byte {
		ev := auditv1.Event{
			TypeMeta:                 metav1.TypeMeta{Kind: "Event", APIVersion: "audit.k8s.io/v1"},
			Level:                    auditv1.LevelMetadata,
			AuditID:                  types.UID(formatAuditID(seq)),
			Stage:                    auditv1.StageResponseComplete,
			Verb:                     "create",
			User:                     authnv1.UserInfo{Username: "alice"},
			ObjectRef:                &auditv1.ObjectReference{Resource: "pods", Namespace: "default", Name: "p"},
			RequestReceivedTimestamp: metav1.NewMicroTime(time.Now()),
		}
		list := auditv1.EventList{
			TypeMeta: metav1.TypeMeta{Kind: "EventList", APIVersion: "audit.k8s.io/v1"},
			Items:    []auditv1.Event{ev},
		}
		b2, _ := json.Marshal(&list)
		return b2
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(tc.caPEM)
	cert, err := tls.X509KeyPair(tc.clientCertPEM, tc.clientKeyPEM)
	if err != nil {
		b.Fatalf("kp: %v", err)
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:      pool,
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			ServerName:   "localhost",
		}, MaxIdleConnsPerHost: 4},
		Timeout: 5 * time.Second,
	}

	url := "https://" + addr + "/audit"
	latencies := make([]time.Duration, 0, b.N)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		body := mkBody(i)
		start := time.Now()
		resp, err := client.Post(url, "application/json", bytes.NewReader(body))
		if err != nil {
			b.Fatalf("post: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			b.Fatalf("status: %d", resp.StatusCode)
		}
		latencies = append(latencies, time.Since(start))
	}
	b.StopTimer()

	if len(latencies) == 0 {
		return
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p50 := latencies[len(latencies)*50/100]
	p99 := latencies[len(latencies)*99/100]
	b.ReportMetric(float64(p50.Milliseconds()), "p50-ms")
	b.ReportMetric(float64(p99.Milliseconds()), "p99-ms")
	// Suppress ns/op so the report focuses on p50/p99 (Story 1.6 precedent).
	b.ReportMetric(0, "ns/op")

}

// formatAuditID renders a deterministic 36-char UUID-shaped string
// keyed off seq so the dedup window does not collapse bench
// iterations.
func formatAuditID(seq int) string {
	hex := "0123456789abcdef"
	out := []byte("00000000-0000-4000-8000-000000000000")
	x := uint64(seq)
	pos := []int{35, 34, 33, 32, 31, 30, 29, 28, 27, 26, 24, 23, 21, 20, 19, 18}
	for _, p := range pos {
		out[p] = hex[x&0xF]
		x >>= 4
	}
	return string(out)
}

// genTestCertsB is the *testing.B convenience wrapper around
// genTestCertsTB.
func genTestCertsB(tb testing.TB) *testCerts {
	tb.Helper()
	return genTestCertsTB(tb)
}
