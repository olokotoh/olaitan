//go:build integration

package cri

import (
	"context"
	"math"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	natsserver "github.com/nats-io/nats-server/v2/server"
	natsjs "github.com/nats-io/nats.go/jetstream"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"

	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/retry"
)

// startTestNATSBench is the testing.B variant of startTestNATS.
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

// pacedCRIServer is the bench-flavoured fixture server: lets the
// bench loop inject events one by one and tracks delivery.
type pacedCRIServer struct {
	runtimeapi.UnimplementedRuntimeServiceServer
	sendCh  chan *runtimeapi.ContainerEventResponse
	mu      sync.Mutex
	count   int
	dropCnt int
}

func newPacedCRIServer(_ *testing.B) *pacedCRIServer {
	return &pacedCRIServer{sendCh: make(chan *runtimeapi.ContainerEventResponse, 1024)}
}

func (s *pacedCRIServer) GetContainerEvents(_ *runtimeapi.GetEventsRequest, stream runtimeapi.RuntimeService_GetContainerEventsServer) error {
	for {
		select {
		case ev, ok := <-s.sendCh:
			if !ok {
				return nil
			}
			if err := stream.Send(ev); err != nil {
				return err
			}
			s.mu.Lock()
			s.count++
			s.mu.Unlock()
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

// send blocks on the channel until the gRPC stream loop consumes the
// previous event. Blocking (rather than the non-blocking drop-and-
// count pattern Story 1.6's Falco bench used) keeps the bench
// honestly measuring end-to-end latency under realistic backpressure
// rather than saturating the channel and reporting drops.
func (s *pacedCRIServer) send(ev *runtimeapi.ContainerEventResponse) {
	s.sendCh <- ev
}

func (s *pacedCRIServer) dropped() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropCnt
}

func (s *pacedCRIServer) waitDelivered(b *testing.B, n int, timeout time.Duration) {
	b.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		c := s.count
		s.mu.Unlock()
		if c >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	s.mu.Lock()
	c := s.count
	s.mu.Unlock()
	b.Fatalf("bench timed out: delivered %d of %d", c, n)
}

func startBufconnCRIBench(b *testing.B, srv *pacedCRIServer) func(context.Context, string) (*grpc.ClientConn, error) {
	b.Helper()
	const bufSize = 1024 * 1024
	lis := bufconn.Listen(bufSize)
	gsrv := grpc.NewServer()
	runtimeapi.RegisterRuntimeServiceServer(gsrv, srv)
	go func() { _ = gsrv.Serve(lis) }()
	b.Cleanup(gsrv.Stop)
	return func(ctx context.Context, _ string) (*grpc.ClientConn, error) {
		return grpc.NewClient(
			"passthrough:///bench",
			grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
				return lis.DialContext(ctx)
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
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

func (p *timingPub) PublishJS(ctx context.Context, subject string, data any, opts ...natsjs.PublishOpt) (*natsjs.PubAck, error) {
	start := time.Now()
	pa, err := p.inner.PublishJS(ctx, subject, data, opts...)
	if err == nil {
		d := time.Since(start)
		p.mu.Lock()
		p.latencies = append(p.latencies, d)
		p.mu.Unlock()
	}
	return pa, err
}

func (p *timingPub) percentile(pct float64) time.Duration {
	p.mu.Lock()
	samples := append([]time.Duration(nil), p.latencies...)
	p.mu.Unlock()
	if len(samples) == 0 {
		return 0
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	idx := int(math.Ceil(pct*float64(len(samples)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(samples) {
		idx = len(samples) - 1
	}
	return samples[idx]
}

// BenchmarkAdapter_PublishLatency measures per-event NATS-publish
// latency end-to-end through the bufconn-backed CRI server, the real
// adapter pipeline, and the embedded NATS server. Reports p50 and
// p99 via b.ReportMetric and FAILS the bench (b.Fatalf) when p99
// exceeds 50ms (AC3 / NFR1).
//
// Run via:
//
//	go test -tags=integration -run=^$ -bench=BenchmarkAdapter_PublishLatency \
//	    -benchtime=2000x ./internal/collector/cri/...
//
// Production-class measurement (multi-node cluster, real containerd)
// is owned by the Story 5.1 evaluation harness; this bench is the
// dev-machine sanity gate.
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

	srv := newPacedCRIServer(b)
	dialFn := startBufconnCRIBench(b, srv)

	pub := &timingPub{inner: nc}

	adapter, err := New(Config{
		SocketPath: "/run/containerd/containerd.sock",
		Hostname:   "node-bench",
		ConnectRetry: retry.Strategy{
			Min: 10 * time.Millisecond, Max: 100 * time.Millisecond, Multiplier: 2, Jitter: 0,
			MaxAttempts: 0,
		},
		PublishRetry: retry.Strategy{
			Min: 10 * time.Millisecond, Max: 100 * time.Millisecond, Multiplier: 2, Jitter: 0,
			MaxAttempts: 3,
		},
		DialTimeout:      1 * time.Second,
		StalenessTimeout: 1 * time.Minute,
	}, pub, nil)
	if err != nil {
		b.Fatal(err)
	}
	adapter.dialFn = dialFn

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- adapter.Run(ctx) }()

	// Wait for stream-connected health flag before timing. P14: send
	// the warm-up event exactly once before the wait loop so the
	// post-bench `waitDelivered(b.N+1, ...)` count is exact. Pre-P14
	// the warm-up emit lived inside the polling loop, which on a slow
	// runner sent multiple warm-ups and produced spurious "paced CRI
	// server reported drops" failures.
	deadline := time.Now().Add(3 * time.Second)
	now := time.Now()
	srv.send(fixtureContainerEvent(0, now))
	for time.Now().Before(deadline) {
		healthy, _ := adapter.Health().Status()
		if healthy {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		srv.send(fixtureContainerEvent(i+1, now.Add(time.Duration(i)*time.Microsecond)))
	}
	srv.waitDelivered(b, b.N+1, 30*time.Second) // +1 for the single warm-up event above
	b.StopTimer()
	if dropped := srv.dropped(); dropped > 0 {
		b.Fatalf("bench: paced CRI server reported drops post-bench: %d of %d events", dropped, b.N)
	}

	cancel()
	select {
	case <-runDone:
	case <-time.After(5 * time.Second):
		b.Fatal("bench: adapter Run did not return after cancel")
	}
	if err := nc.Close(context.Background()); err != nil {
		b.Logf("bench: nats close: %v", err)
	}

	// Suppress ns/op (the bench loop calls send() non-blocking and
	// then polls; ns/op conflates send-rate, gRPC stream throughput,
	// and the 1ms waitDelivered poll resolution). Only the
	// percentile metrics are meaningful for AC3's NFR1 budget.
	b.ReportMetric(0, "ns/op")
	p50 := pub.percentile(0.50)
	p99 := pub.percentile(0.99)
	b.ReportMetric(float64(p50)/float64(time.Millisecond), "p50-ms")
	b.ReportMetric(float64(p99)/float64(time.Millisecond), "p99-ms")

	const ac3PNinetyNineMs = 50.0
	if measured := float64(p99) / float64(time.Millisecond); measured > ac3PNinetyNineMs {
		b.Fatalf("AC3 / NFR1 gate failed: p99 publish latency %.2fms exceeds %vms (samples=%d)",
			measured, ac3PNinetyNineMs, len(pub.latencies))
	}
}
