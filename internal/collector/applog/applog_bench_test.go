//go:build integration

package applog

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	natsjs "github.com/nats-io/nats.go/jetstream"

	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// BenchmarkAdapter_PublishLatency drives 1000 lines through the
// adapter via real os.Pipe + embedded NATS and reports the per-event
// receive-to-PubAck p50 and p99 latencies. Asserts the NFR1 ceiling
// (p99 <= 50ms) -- gate fires b.Fatal if exceeded. Mirrors the
// Story 1.7 / 1.8 closure pattern (P33 retrofitted into the original
// commit here).
//
// b.ReportMetric is used so `go test -bench=. -benchmem` displays the
// p50 / p99 numbers alongside the standard Go bench output. ns/op is
// suppressed (Story 1.6 follow-up patch precedent: ns/op for an
// asynchronous pipeline is nonsensical).
func BenchmarkAdapter_PublishLatency(b *testing.B) {
	// Stand up an embedded NATS with JetStream in-process.
	tmpDir := b.TempDir()
	srv, err := natsserver.NewServer(&natsserver.Options{
		Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: tmpDir, NoLog: true, NoSigs: true,
	})
	if err != nil {
		b.Fatalf("nats server: %v", err)
	}
	srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		b.Fatal("nats not ready")
	}
	b.Cleanup(srv.Shutdown)

	cfg := natsclient.DefaultConfig()
	cfg.URL = srv.ClientURL()
	cfg.Name = "applog-bench"
	nc, err := natsclient.NewClient(cfg)
	if err != nil {
		b.Fatalf("nats client: %v", err)
	}
	b.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = nc.Close(ctx)
	})

	ctx, cancelStreams := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelStreams()
	if err := natsclient.EnsureStreams(ctx, nc.JetStream(), []natsjs.StreamConfig{{
		Name:      "EVENTS_RAW",
		Subjects:  []string{subjects.RawPrefix + ">"},
		MaxAge:    1 * time.Hour,
		MaxBytes:  64 * 1024 * 1024,
		Storage:   natsjs.MemoryStorage,
		Retention: natsjs.LimitsPolicy,
	}}); err != nil {
		b.Fatalf("ensure streams: %v", err)
	}
	stream, err := nc.JetStream().Stream(ctx, "EVENTS_RAW")
	if err != nil {
		b.Fatalf("get stream: %v", err)
	}
	consumer, err := stream.CreateOrUpdateConsumer(ctx, natsjs.ConsumerConfig{
		Name:          "applog-bench-consumer",
		FilterSubject: subjects.RawAppLog,
		AckPolicy:     natsjs.AckExplicitPolicy,
	})
	if err != nil {
		b.Fatalf("consumer: %v", err)
	}

	adapter, err := New(Config{
		StdoutPath:    "/dev/null/stdout-stub",
		StderrPath:    "/dev/null/stderr-stub",
		Pod:           schema.PodRef{Name: "bench-pod", Namespace: "default", UID: "uid-bench", Node: "node-1"},
		Container:     "bench-app",
		ChannelBuffer: 1024,
	}, nc, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		b.Fatalf("new adapter: %v", err)
	}

	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		b.Fatalf("os.Pipe: %v", err)
	}
	off := &atomic.Int64{}
	rb := adapter.recBuilder()
	adapter.stdoutTailFn = func(ctx context.Context, sink chan<- LineRecord) error {
		closeDone := make(chan struct{})
		go func() {
			defer close(closeDone)
			<-ctx.Done()
			_ = stdoutR.Close()
		}()
		err := runReaderTail(ctx, stdoutR, "stdout", sink, adapter.shed, off, adapter.nowFn, rb, adapter.log)
		<-closeDone
		return err
	}
	adapter.stderrTailFn = func(ctx context.Context, sink chan<- LineRecord) error {
		<-ctx.Done()
		return nil
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- adapter.Run(runCtx) }()
	b.Cleanup(func() {
		runCancel()
		<-runDone
		_ = stdoutW.Close()
	})

	const N = 1000
	latencies := make([]time.Duration, 0, N)
	b.ResetTimer()
	for i := 0; i < N; i++ {
		_, _ = stdoutW.Write([]byte("benchmark\n"))
	}

	deadline := time.Now().Add(60 * time.Second)
	for len(latencies) < N && time.Now().Before(deadline) {
		remaining := time.Until(deadline)
		if remaining > 1*time.Second {
			remaining = 1 * time.Second
		}
		batch, err := consumer.Fetch(N-len(latencies), natsjs.FetchMaxWait(remaining))
		if err != nil {
			continue
		}
		now := time.Now()
		for msg := range batch.Messages() {
			var ev schema.Event
			if err := json.Unmarshal(msg.Data(), &ev); err != nil {
				continue
			}
			latencies = append(latencies, now.Sub(ev.Timestamp))
			_ = msg.Ack()
		}
	}
	b.StopTimer()

	if len(latencies) < N/2 {
		b.Fatalf("collected only %d/%d latencies; bus may be unreachable", len(latencies), N)
	}

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p50 := latencies[len(latencies)/2]
	p99Idx := (len(latencies) * 99) / 100
	if p99Idx >= len(latencies) {
		p99Idx = len(latencies) - 1
	}
	p99 := latencies[p99Idx]

	b.ReportMetric(float64(p50.Microseconds())/1000.0, "p50-ms")
	b.ReportMetric(float64(p99.Microseconds())/1000.0, "p99-ms")
	b.ReportMetric(0, "ns/op")

	if p99 > 50*time.Millisecond {
		b.Fatalf("NFR1 gate: p99=%s exceeds 50ms ceiling", p99)
	}
	b.Logf("applog bench: p50=%s p99=%s n=%d", p50, p99, len(latencies))
}
