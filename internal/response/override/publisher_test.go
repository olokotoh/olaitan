package override

import (
	"context"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go/jetstream"

	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/schema"
)

// startNATS spins up an embedded JetStream NATS server and a client, ensures
// the OVERRIDES stream (reduced MaxBytes for the test server), and returns the
// client.
func startNATS(t *testing.T) *natsclient.Client {
	t.Helper()
	opts := &natsserver.Options{
		Host:      "127.0.0.1",
		Port:      -1, // random free port
		JetStream: true,
		StoreDir:  t.TempDir(),
		NoLog:     true,
		NoSigs:    true,
	}
	srv, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatalf("nats server: %v", err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats server not ready")
	}
	t.Cleanup(srv.Shutdown)

	cfg := natsclient.DefaultConfig()
	cfg.URL = srv.ClientURL()
	cli, err := natsclient.NewClient(cfg)
	if err != nil {
		t.Fatalf("nats client: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close(context.Background()) })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var overrideStream []jetstream.StreamConfig
	for _, sc := range natsclient.StreamConfigs() {
		if sc.Name == "OVERRIDES" {
			sc.MaxBytes = 1 * 1024 * 1024
			sc.Storage = jetstream.MemoryStorage
			overrideStream = append(overrideStream, sc)
		}
	}
	if err := natsclient.EnsureStreams(ctx, cli.JetStream(), overrideStream); err != nil {
		t.Fatalf("ensure OVERRIDES: %v", err)
	}
	return cli
}

func TestNATSPublisher_PublishesAppliedAndRejected(t *testing.T) {
	cli := startNATS(t)
	pub, err := NewNATSPublisher(cli)
	if err != nil {
		t.Fatalf("NewNATSPublisher: %v", err)
	}
	ctx := context.Background()

	applied := OverrideApplied{
		WorkloadID:     "default/Deployment/web",
		RequestedState: string(schema.StateRestricted),
		BeforeState:    string(schema.StateClean),
		TTLSeconds:     1800,
		Source:         SourcePod,
		AppliedAtNs:    time.Now().UnixNano(),
	}
	if err := pub.PublishOverride(ctx, applied); err != nil {
		t.Fatalf("publish applied: %v", err)
	}
	// Re-publishing the SAME applied event is server-side deduplicated by the
	// workload+applied_at WithMsgID, so the stream still holds one applied msg.
	if err := pub.PublishOverride(ctx, applied); err != nil {
		t.Fatalf("publish applied (dup): %v", err)
	}
	rejected := OverrideApplied{
		WorkloadID:     "default/Deployment/web",
		RequestedState: "PRESERVED_KILLED",
		Rejected:       true,
		Reason:         ReasonStateUnavailable,
	}
	if err := pub.PublishOverride(ctx, rejected); err != nil {
		t.Fatalf("publish rejected: %v", err)
	}

	js := cli.JetStream()
	stream, err := js.Stream(ctx, "OVERRIDES")
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	info, err := stream.Info(ctx)
	if err != nil {
		t.Fatalf("stream info: %v", err)
	}
	// One applied (the dup deduped) + one rejected = 2.
	if info.State.Msgs != 2 {
		t.Errorf("OVERRIDES messages = %d, want 2 (applied deduped + rejected)", info.State.Msgs)
	}
}
