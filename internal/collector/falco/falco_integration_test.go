package falco

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	natsserver "github.com/nats-io/nats-server/v2/server"
	natsjs "github.com/nats-io/nats.go/jetstream"

	"github.com/olokotoh/olaitan/internal/collector/falco/falcopb"
	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/retry"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// integrationTests in this file spin up an embedded NATS server and a
// bufconn-backed gRPC mock; both are real-but-in-process. `go test
// -short` skips them so the unit-test fast path stays under a second
// per package; CI runs without -short and exercises the full surface.
func skipIfShort(tb testing.TB) {
	tb.Helper()
	if testing.Short() {
		tb.Skip("integration test skipped under -short")
	}
}

// startTestNATS spins up an embedded NATS server with JetStream so the
// integration test exercises the real publish path (NFR35: no
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

// testStreamConfigs returns a single EVENTS_RAW stream sized for the
// runner: MemoryStorage with a tiny budget so disk reservations on
// resource-constrained CI nodes stay reasonable. The other production
// streams (EVENTS, THREATS, EVIDENCE) are not exercised by the Falco
// adapter integration test, so they are intentionally omitted here.
func testStreamConfigs() []natsjs.StreamConfig {
	return []natsjs.StreamConfig{
		{
			Name:      "EVENTS_RAW",
			Subjects:  []string{subjects.RawPrefix + ">"},
			MaxAge:    1 * time.Hour,
			MaxBytes:  1 * 1024 * 1024,
			Storage:   natsjs.MemoryStorage,
			Retention: natsjs.LimitsPolicy,
		},
	}
}

// mockFalcoServer is a hand-rolled implementation of the
// falco.outputs.service gRPC service that emits a fixture sequence of
// Response messages then blocks until ctx ends. The test drives the
// Sub bidi stream by feeding fixtures and counting Recv'd messages on
// the NATS side.
type mockFalcoServer struct {
	falcopb.UnimplementedServiceServer
	fixtures []*falcopb.Response
	// emitted is closed once all fixtures have been Send'ed so callers
	// can wait for completion before cancelling ctx.
	emitted chan struct{}
	// errs surfaces mid-fixture Send errors (or the partially emitted
	// state) to the test, replacing the previous "everything looked
	// like a timeout" failure mode. Tests poll/select on errs to
	// distinguish a genuine emission stall from a Send failure.
	errs chan error
}

func newMockFalco(fixtures []*falcopb.Response) *mockFalcoServer {
	return &mockFalcoServer{
		fixtures: fixtures,
		emitted:  make(chan struct{}),
		errs:     make(chan error, 1),
	}
}

func (m *mockFalcoServer) Sub(stream falcopb.Service_SubServer) error {
	if _, err := stream.Recv(); err != nil {
		// Distinguish ctx-cancel (a normal shutdown) from a real Recv
		// failure so the test does not log a confusing "synthetic
		// error" line on a clean exit.
		if ctxErr := stream.Context().Err(); ctxErr != nil {
			return ctxErr
		}
		select {
		case m.errs <- err:
		default:
		}
		return err
	}
	for i, f := range m.fixtures {
		if err := stream.Send(f); err != nil {
			// Mid-fixture failure: surface the partial state via errs
			// rather than letting the test trip on a generic timeout.
			select {
			case m.errs <- &mockSendError{index: i, total: len(m.fixtures), inner: err}:
			default:
			}
			return err
		}
	}
	close(m.emitted)
	<-stream.Context().Done()
	return stream.Context().Err()
}

// mockSendError carries the partial-emission state so a test can tell
// "sent 2 of 3 then failed" from "stream timed out before any sent".
type mockSendError struct {
	index, total int
	inner        error
}

func (e *mockSendError) Error() string {
	return e.inner.Error()
}

func (e *mockSendError) Unwrap() error {
	return e.inner
}

// startBufconnFalco starts the in-process gRPC server and returns the
// adapter dialFn that resolves the bufconn target.
func startBufconnFalco(t *testing.T, srv *mockFalcoServer) func(context.Context, string) (*grpc.ClientConn, error) {
	t.Helper()
	const bufSize = 1024 * 1024
	lis := bufconn.Listen(bufSize)
	gsrv := grpc.NewServer()
	falcopb.RegisterServiceServer(gsrv, srv)
	go func() {
		_ = gsrv.Serve(lis)
	}()
	t.Cleanup(gsrv.Stop)

	return func(ctx context.Context, _ string) (*grpc.ClientConn, error) {
		return grpc.NewClient(
			"passthrough:///bufconn",
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				return lis.DialContext(ctx)
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
	}
}

// fixtureResponse builds a Falco Response with a unique evt.uuid so the
// test's idempotency-key comparison is deterministic.
func fixtureResponse(i int, when time.Time) *falcopb.Response {
	return &falcopb.Response{
		Time:     timestamppb.New(when),
		Priority: falcopb.Priority_NOTICE,
		Rule:     "Terminal shell in container",
		Output:   "shell spawned in container",
		OutputFields: map[string]string{
			"k8s.pod.name": "payments-7f8b9c-xyz",
			"k8s.ns.name":  "payments",
			"k8s.pod.uid":  "00000000-0000-0000-0000-000000000001",
			"evt.uuid":     fixedUUID(i),
		},
		Hostname: "node-test",
		Tags:     []string{"shell", "T1059"},
		Source:   "syscall",
	}
}

func fixedUUID(i int) string {
	return time.Date(2026, 5, 5, 0, 0, 0, i, time.UTC).Format("20060102T150405.000000000")
}

func TestAdapter_EndToEnd_Bufconn(t *testing.T) {
	skipIfShort(t)

	// === fixtures ===
	now := time.Date(2026, 5, 5, 14, 30, 0, 0, time.UTC)
	fixtures := []*falcopb.Response{
		fixtureResponse(1, now),
		fixtureResponse(2, now.Add(time.Millisecond)),
		fixtureResponse(3, now.Add(2*time.Millisecond)),
	}

	// === embedded NATS ===
	natsSrv := startTestNATS(t)
	natsCfg := natsclient.DefaultConfig()
	natsCfg.URL = natsSrv.ClientURL()
	natsCfg.Name = "falco-it-test"
	natsCfg.MaxReconnects = 0
	natsCfg.ReconnectBufSize = 1 * 1024 * 1024
	nc, err := natsclient.NewClient(natsCfg)
	if err != nil {
		t.Fatalf("new nats client: %v", err)
	}
	t.Cleanup(func() { _ = nc.Close(context.Background()) })

	if err := natsclient.EnsureStreams(context.Background(), nc.JetStream(), testStreamConfigs()); err != nil {
		t.Fatalf("ensure streams: %v", err)
	}

	// === bufconn Falco mock ===
	mock := newMockFalco(fixtures)
	dialFn := startBufconnFalco(t, mock)

	// === subscribe to RawFalco BEFORE adapter starts so we don't race ===
	consumer, err := nc.JetStream().CreateOrUpdateConsumer(context.Background(), "EVENTS_RAW",
		natsjs.ConsumerConfig{
			Name:          "falco-it-test-consumer",
			FilterSubject: subjects.RawFalco,
			AckPolicy:     natsjs.AckExplicitPolicy,
		})
	if err != nil {
		t.Fatalf("consumer: %v", err)
	}

	// === adapter ===
	adapter, err := New(Config{
		Endpoint: "passthrough:///bufconn",
		Hostname: "node-test",
		Retry: retry.Strategy{
			Min: 10 * time.Millisecond, Max: 100 * time.Millisecond, Multiplier: 2.0, Jitter: 0,
			MaxAttempts: 0,
		},
	}, nc, nil)
	if err != nil {
		t.Fatalf("adapter new: %v", err)
	}
	// Inject the bufconn dialer.
	adapter.dialFn = dialFn

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	runDone := make(chan error, 1)
	go func() { runDone <- adapter.Run(ctx) }()

	// === wait for the mock to emit all fixtures ===
	select {
	case <-mock.emitted:
	case err := <-mock.errs:
		t.Fatalf("mock Sub failed mid-fixture: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("mock did not emit fixtures within timeout")
	}

	// === observe the mid-run health snapshot BEFORE we cancel ===
	// mock.emitted closes when the *server* has finished Send'ing; the
	// adapter goroutine may not yet have consumed those messages from
	// the gRPC client buffer (and therefore not yet flipped MarkHealthy
	// after the first successful Recv). Poll until either healthy or a
	// short timeout elapses; health flipping to true is what AC4
	// ("marked unhealthy on Falco unavailability") implies in the
	// inverse: we assert the recovered-healthy state is observable.
	deadline := time.Now().Add(2 * time.Second)
	var healthy bool
	var herr error
	for time.Now().Before(deadline) {
		healthy, herr = adapter.Health().Status()
		if healthy {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !healthy {
		t.Errorf("expected healthy after fixtures published, got healthy=%v lastErr=%v", healthy, herr)
	}

	// === collect events from the consumer ===
	var got []schema.Event
	for len(got) < len(fixtures) {
		batch, err := consumer.Fetch(len(fixtures)-len(got),
			natsjs.FetchMaxWait(2*time.Second))
		if err != nil {
			t.Fatalf("consumer fetch: %v", err)
		}
		for msg := range batch.Messages() {
			var ev schema.Event
			if err := json.Unmarshal(msg.Data(), &ev); err != nil {
				t.Errorf("unmarshal event: %v (data=%q)", err, string(msg.Data()))
				continue
			}
			got = append(got, ev)
			_ = msg.Ack()
		}
	}

	cancel()
	if err := <-runDone; err != nil {
		t.Errorf("adapter Run returned non-nil: %v", err)
	}

	// === assertions on the published events ===
	if len(got) != len(fixtures) {
		t.Fatalf("got %d events, want %d", len(got), len(fixtures))
	}
	// Order is not strictly guaranteed in JetStream pulls; sort by ID.
	sort.Slice(got, func(i, j int) bool { return got[i].ID < got[j].ID })

	expectedIDs := []string{fixedUUID(1), fixedUUID(2), fixedUUID(3)}
	sort.Strings(expectedIDs)
	for i, ev := range got {
		if ev.ID != expectedIDs[i] {
			t.Errorf("event[%d].ID: got %q, want %q", i, ev.ID, expectedIDs[i])
		}
		if ev.Source != schema.SourceFalco {
			t.Errorf("event[%d].Source: got %q, want %q", i, ev.Source, schema.SourceFalco)
		}
		if ev.Category != schema.CategorySyscall {
			t.Errorf("event[%d].Category: got %q, want %q", i, ev.Category, schema.CategorySyscall)
		}
		if ev.Pod.Node != "node-test" {
			t.Errorf("event[%d].Pod.Node: got %q, want node-test", i, ev.Pod.Node)
		}
	}
}

func TestAdapter_RetriesOnDialFailure(t *testing.T) {
	skipIfShort(t)

	// All dial attempts fail; ctx-cancel must terminate the retry loop
	// cleanly with nil. SourceHealth must report unhealthy.
	natsSrv := startTestNATS(t)
	natsCfg := natsclient.DefaultConfig()
	natsCfg.URL = natsSrv.ClientURL()
	natsCfg.MaxReconnects = 0
	nc, err := natsclient.NewClient(natsCfg)
	if err != nil {
		t.Fatal(err)
	}

	syntheticDialErr := errors.New("synthetic dial failure")
	failingDial := func(ctx context.Context, _ string) (*grpc.ClientConn, error) {
		return nil, syntheticDialErr
	}

	adapter, err := New(Config{
		Endpoint: "passthrough:///fail",
		Hostname: "node-test",
		Retry: retry.Strategy{
			Min: 5 * time.Millisecond, Max: 20 * time.Millisecond, Multiplier: 2.0, Jitter: 0,
			MaxAttempts: 0,
		},
	}, nc, nil)
	if err != nil {
		t.Fatal(err)
	}
	adapter.dialFn = failingDial

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	runDone := make(chan error, 1)
	go func() { runDone <- adapter.Run(ctx) }()

	// Wait for Run to return before tearing down NATS so the cleanup
	// is deterministic and the race detector cannot catch an in-flight
	// PublishJS / nc.Close interleave on slow CI runners.
	var runErr error
	select {
	case runErr = <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("adapter Run did not return after ctx-timeout window")
	}
	t.Cleanup(func() { _ = nc.Close(context.Background()) })

	if runErr != nil {
		t.Errorf("Run returned non-nil on ctx-timeout, got %v", runErr)
	}

	healthy, herr := adapter.Health().Status()
	if healthy {
		t.Error("expected unhealthy after persistent dial failure")
	}
	if herr == nil {
		t.Error("expected non-nil lastErr after dial failure")
	}
}

// timingPub wraps a natsPublisher and captures per-call PublishJS
// latencies so the AC3 benchmark can compute a percentile rather than
// a mean throughput. The lock is acquired only on the slow append
// path; reads happen after the bench loop has drained.
type timingPub struct {
	inner     natsPublisher
	mu        sync.Mutex
	latencies []time.Duration
}

func (t *timingPub) PublishJS(ctx context.Context, subject string, data any) (*natsjs.PubAck, error) {
	start := time.Now()
	pa, err := t.inner.PublishJS(ctx, subject, data)
	if err == nil {
		d := time.Since(start)
		t.mu.Lock()
		t.latencies = append(t.latencies, d)
		t.mu.Unlock()
	}
	return pa, err
}

// percentile returns the p-th percentile of the recorded latencies
// using nearest-rank: idx = ceil(p * N) - 1, clamped to [0, N-1]. p is
// in (0, 1].
func (t *timingPub) percentile(p float64) time.Duration {
	t.mu.Lock()
	samples := append([]time.Duration(nil), t.latencies...)
	t.mu.Unlock()
	if len(samples) == 0 {
		return 0
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	idx := int(math.Ceil(p*float64(len(samples)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(samples) {
		idx = len(samples) - 1
	}
	return samples[idx]
}

// BenchmarkAdapter_PublishLatency measures the per-event NATS-publish
// latency and reports both p50 and p99 via b.ReportMetric. AC3 / NFR1
// require p99 <= 50ms at 1000 events/sec/source/node. Run via:
//
//	go test -run=^$ -bench=BenchmarkAdapter_PublishLatency \
//	    -benchtime=2000x ./internal/collector/falco/...
//
// The reported numbers (p50-ms, p99-ms) lend themselves to direct
// comparison with the NFR1 budget; the legacy ns/op figure remains
// available for throughput tracking.
func BenchmarkAdapter_PublishLatency(b *testing.B) {
	natsSrv := startTestNATSBench(b)
	natsCfg := natsclient.DefaultConfig()
	natsCfg.URL = natsSrv.ClientURL()
	natsCfg.MaxReconnects = 0
	nc, err := natsclient.NewClient(natsCfg)
	if err != nil {
		b.Fatal(err)
	}

	if err := natsclient.EnsureStreams(context.Background(), nc.JetStream(), testStreamConfigs()); err != nil {
		b.Fatal(err)
	}

	now := time.Now()
	mock := newMockFalcoBench(b)
	dialFn := startBufconnFalcoBench(b, mock)

	pub := &timingPub{inner: nc}

	adapter, err := New(Config{
		Endpoint: "passthrough:///bench",
		Hostname: "node-bench",
		Retry: retry.Strategy{
			Min: 10 * time.Millisecond, Max: 100 * time.Millisecond, Multiplier: 2, Jitter: 0,
			MaxAttempts: 0,
		},
	}, pub, nil)
	if err != nil {
		b.Fatal(err)
	}
	adapter.dialFn = dialFn

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- adapter.Run(ctx) }()

	// Wait for the stream to be connected before timing.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		healthy, _ := adapter.Health().Status()
		if healthy {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mock.send(fixtureResponse(i, now.Add(time.Duration(i)*time.Millisecond)))
	}
	mock.waitDelivered(b, b.N, 30*time.Second)
	b.StopTimer()

	// Drain the adapter goroutine before closing NATS so the cleanup
	// path is deterministic and the previously-swallowed
	// PublishJS / nc.Close race cannot mask a regression.
	cancel()
	select {
	case <-runDone:
	case <-time.After(5 * time.Second):
		b.Fatal("bench: adapter Run did not return after cancel")
	}
	if err := nc.Close(context.Background()); err != nil {
		b.Logf("bench: nats close: %v", err)
	}

	// Report the percentiles. p99 is the binding number per AC3; p50
	// is reported alongside as a sanity check.
	p50 := pub.percentile(0.50)
	p99 := pub.percentile(0.99)
	b.ReportMetric(float64(p50)/float64(time.Millisecond), "p50-ms")
	b.ReportMetric(float64(p99)/float64(time.Millisecond), "p99-ms")
	if mock.dropped() > 0 {
		b.ReportMetric(float64(mock.dropped()), "dropped-events")
	}
}

// === bench-flavoured helpers (testing.B variants) ===

func startTestNATSBench(b *testing.B) *natsserver.Server {
	b.Helper()
	opts := &natsserver.Options{
		Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: b.TempDir(),
		NoLog: true, NoSigs: true,
	}
	srv, err := natsserver.NewServer(opts)
	if err != nil {
		b.Fatalf("start test nats server: %v", err)
	}
	srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		b.Fatal("nats server not ready")
	}
	b.Cleanup(srv.Shutdown)
	return srv
}

// pacedMockFalco is a bench-only Falco mock that lets the bench loop
// inject events in real-time and counts deliveries. send() is
// non-blocking on a saturated channel; saturation increments a drop
// counter the bench reports rather than wedging silently.
type pacedMockFalco struct {
	falcopb.UnimplementedServiceServer
	sendCh   chan *falcopb.Response
	mu       sync.Mutex
	count    int
	dropCnt  int
}

func newMockFalcoBench(_ *testing.B) *pacedMockFalco {
	return &pacedMockFalco{sendCh: make(chan *falcopb.Response, 1024)}
}

func (m *pacedMockFalco) Sub(stream falcopb.Service_SubServer) error {
	if _, err := stream.Recv(); err != nil {
		if ctxErr := stream.Context().Err(); ctxErr != nil {
			return ctxErr
		}
		return err
	}
	for {
		select {
		case r, ok := <-m.sendCh:
			if !ok {
				return nil
			}
			if err := stream.Send(r); err != nil {
				return err
			}
			m.mu.Lock()
			m.count++
			m.mu.Unlock()
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

func (m *pacedMockFalco) send(r *falcopb.Response) {
	select {
	case m.sendCh <- r:
	default:
		// Channel saturated. Drop and count rather than block; the
		// bench surfaces this via b.ReportMetric so a back-pressure
		// regression cannot hide as a wall-clock hang.
		m.mu.Lock()
		m.dropCnt++
		m.mu.Unlock()
	}
}

func (m *pacedMockFalco) dropped() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dropCnt
}

func (m *pacedMockFalco) waitDelivered(b *testing.B, n int, timeout time.Duration) {
	b.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		c := m.count
		m.mu.Unlock()
		if c >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	m.mu.Lock()
	c := m.count
	m.mu.Unlock()
	b.Fatalf("bench timed out: delivered %d of %d", c, n)
}

func startBufconnFalcoBench(b *testing.B, srv *pacedMockFalco) func(context.Context, string) (*grpc.ClientConn, error) {
	b.Helper()
	const bufSize = 1024 * 1024
	lis := bufconn.Listen(bufSize)
	gsrv := grpc.NewServer()
	falcopb.RegisterServiceServer(gsrv, srv)
	go func() { _ = gsrv.Serve(lis) }()
	b.Cleanup(gsrv.Stop)
	return func(ctx context.Context, _ string) (*grpc.ClientConn, error) {
		return grpc.NewClient(
			"passthrough:///bufconn",
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				return lis.DialContext(ctx)
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
	}
}
