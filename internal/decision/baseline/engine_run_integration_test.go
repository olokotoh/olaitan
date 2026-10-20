//go:build integration

package baseline

import (
	"context"
	"errors"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go/jetstream"

	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// Story 10.12: the engine no longer reads EVIDENCE. Run deletes the old
// durable so it does not linger on an upgraded cluster, and the
// production queue path (ObserveEvent -> Run -> Ingest) tracks the
// workload.
func TestIntegration_RunDeletesLegacyConsumerAndConsumesQueue(t *testing.T) {
	srv, err := natsserver.NewServer(&natsserver.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir(), NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	srv.Start()
	t.Cleanup(srv.Shutdown)
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats not ready")
	}
	nc, err := natsclient.NewClient(natsclient.ClientConfig{URL: srv.ClientURL(), Name: "baseline-run-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nc.Close(context.Background()) })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := natsclient.EnsureStreams(ctx, nc.JetStream(), []jetstream.StreamConfig{
		{Name: "EVIDENCE", Subjects: []string{subjects.EvidencePrefix + ">"}, MaxAge: time.Hour, Storage: jetstream.MemoryStorage},
	}); err != nil {
		t.Fatal(err)
	}
	stream, err := nc.JetStream().Stream(ctx, "EVIDENCE")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{Durable: legacyConsumerName, AckPolicy: jetstream.AckExplicitPolicy, FilterSubject: subjects.EvidencePackages}); err != nil {
		t.Fatal(err)
	}

	store, warmup := newRealStoreAndWarmup(t)
	e, err := New(Config{NATS: nc, Store: store, Warmup: warmup, Emitter: &recEmitter{}, Log: discardLog()})
	if err != nil {
		t.Fatal(err)
	}
	runCtx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- e.Run(runCtx) }()

	fx := loadReal(t)
	ev := fx.AuditOperatorExec
	ev.Timestamp = time.Now() // a live event, not a replayed one
	e.ObserveEvent(steadyWorkloadID, steadyIdentity, ev)
	deadline := time.Now().Add(5 * time.Second)
	for e.trackedWorkloads.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	stop()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := e.trackedWorkloads.Load(); got != 1 {
		t.Fatalf("tracked workloads = %d, want 1 (the queued observation was not ingested)", got)
	}
	if _, err := stream.Consumer(ctx, legacyConsumerName); !errors.Is(err, jetstream.ErrConsumerNotFound) {
		t.Fatalf("legacy consumer still present (err=%v)", err)
	}
}
