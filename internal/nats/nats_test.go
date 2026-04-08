package nats_test

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go/jetstream"

	natsclient "github.com/olokotoh/olaitan/internal/nats"
)

// startTestServer spins up an in-process NATS server with JetStream enabled.
func startTestServer(t *testing.T) *natsserver.Server {
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
		t.Fatalf("start test nats server: %v", err)
	}
	srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats server not ready")
	}
	t.Cleanup(srv.Shutdown)
	return srv
}

// newTestClient creates a Client connected to the test server.
func newTestClient(t *testing.T, srv *natsserver.Server) *natsclient.Client {
	t.Helper()
	cfg := natsclient.ClientConfig{
		URL:           srv.ClientURL(),
		Name:          "test",
		MaxReconnects: 0,
		ReconnectWait: time.Second,
	}
	c, err := natsclient.NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestNewClient(t *testing.T) {
	srv := startTestServer(t)
	c := newTestClient(t, srv)

	if c.Conn() == nil {
		t.Fatal("expected non-nil connection")
	}
	if c.JetStream() == nil {
		t.Fatal("expected non-nil JetStream")
	}
}

func TestNewClientBadURL(t *testing.T) {
	cfg := natsclient.ClientConfig{
		URL:           "nats://127.0.0.1:1", // nothing listening
		Name:          "test",
		MaxReconnects: 0,
		ReconnectWait: time.Millisecond,
	}
	_, err := natsclient.NewClient(cfg)
	if err == nil {
		t.Fatal("expected error for bad URL")
	}
}

func TestPublishSubscribe(t *testing.T) {
	srv := startTestServer(t)
	c := newTestClient(t, srv)

	type msg struct {
		Value string `json:"value"`
	}

	var (
		mu       sync.Mutex
		received []byte
		done     = make(chan struct{})
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := c.Subscribe(ctx, "test.subject", func(data []byte) {
		mu.Lock()
		received = data
		mu.Unlock()
		close(done)
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	if err := c.Publish("test.subject", msg{Value: "hello"}); err != nil {
		t.Fatalf("publish: %v", err)
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for message")
	}

	mu.Lock()
	defer mu.Unlock()

	var got msg
	if err := json.Unmarshal(received, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Value != "hello" {
		t.Errorf("got %q, want %q", got.Value, "hello")
	}
}

func TestSubscribeContextCancel(t *testing.T) {
	srv := startTestServer(t)
	c := newTestClient(t, srv)

	ctx, cancel := context.WithCancel(context.Background())

	called := make(chan struct{}, 1)
	err := c.Subscribe(ctx, "test.cancel", func(data []byte) {
		called <- struct{}{}
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	// Cancel the subscription
	cancel()
	time.Sleep(100 * time.Millisecond) // let drain complete

	// Publish after cancel — should not be received
	if err := c.Publish("test.cancel", "after-cancel"); err != nil {
		t.Fatalf("publish: %v", err)
	}

	select {
	case <-called:
		t.Error("handler called after context cancellation")
	case <-time.After(200 * time.Millisecond):
		// expected
	}
}

func TestEnsureStreams(t *testing.T) {
	srv := startTestServer(t)
	c := newTestClient(t, srv)

	if err := natsclient.EnsureStreams(c.JetStream()); err != nil {
		t.Fatalf("ensure streams: %v", err)
	}

	// Verify all streams exist
	js := c.JetStream()
	ctx := context.Background()
	for _, cfg := range natsclient.StreamConfigs {
		s, err := js.Stream(ctx, cfg.Name)
		if err != nil {
			t.Errorf("stream %s not found: %v", cfg.Name, err)
			continue
		}
		info := s.CachedInfo()
		if len(info.Config.Subjects) == 0 {
			t.Errorf("stream %s has no subjects", cfg.Name)
		}
	}
}

func TestEnsureStreamsIdempotent(t *testing.T) {
	srv := startTestServer(t)
	c := newTestClient(t, srv)

	// Call twice — should not error
	if err := natsclient.EnsureStreams(c.JetStream()); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if err := natsclient.EnsureStreams(c.JetStream()); err != nil {
		t.Fatalf("second call: %v", err)
	}
}

func TestJetStreamPublishConsume(t *testing.T) {
	srv := startTestServer(t)
	c := newTestClient(t, srv)

	if err := natsclient.EnsureStreams(c.JetStream()); err != nil {
		t.Fatalf("ensure streams: %v", err)
	}

	// Publish a message to a JetStream subject
	type event struct {
		ID string `json:"id"`
	}
	if err := c.Publish(natsclient.SubjectRawFalco, event{ID: "evt-001"}); err != nil {
		t.Fatalf("publish: %v", err)
	}

	// Verify via JetStream consumer
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	js := c.JetStream()
	cons, err := js.CreateConsumer(ctx, "EVENTS", jetstream.ConsumerConfig{
		FilterSubject: natsclient.SubjectRawFalco,
	})
	if err != nil {
		t.Fatalf("create consumer: %v", err)
	}

	msg, err := cons.Next()
	if err != nil {
		t.Fatalf("next: %v", err)
	}

	var got event
	if err := json.Unmarshal(msg.Data(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ID != "evt-001" {
		t.Errorf("got %q, want %q", got.ID, "evt-001")
	}
}

func TestSubjectHelpers(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"correlated", natsclient.SubjectCorrelated("default", "nginx"), "olaitan.correlated.default.nginx"},
		{"state", natsclient.SubjectState("kube-system", "coredns"), "olaitan.state.kube-system.coredns"},
		{"health", natsclient.SubjectHealth("ring1"), "olaitan.health.ring1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := natsclient.DefaultConfig()
	if cfg.URL == "" {
		t.Error("URL should not be empty")
	}
	if cfg.Name != "olaitan" {
		t.Errorf("Name: got %q, want %q", cfg.Name, "olaitan")
	}
	if cfg.MaxReconnects != -1 {
		t.Errorf("MaxReconnects: got %d, want -1", cfg.MaxReconnects)
	}
}
