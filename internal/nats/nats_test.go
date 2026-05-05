package nats_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// startTestServer spins up an in-process NATS server with JetStream enabled.
func startTestServer(t *testing.T) *natsserver.Server {
	t.Helper()
	return startTestServerAt(t, -1)
}

// startTestServerAt spins up a NATS server on a specific port (or random if -1).
// When reusing a port, the caller is responsible for ensuring nothing else
// is bound to it.
func startTestServerAt(t *testing.T, port int) *natsserver.Server {
	t.Helper()
	opts := &natsserver.Options{
		Host:      "127.0.0.1",
		Port:      port,
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
		URL:              srv.ClientURL(),
		Name:             "test",
		MaxReconnects:    0,
		ReconnectWait:    time.Second,
		ReconnectBufSize: 1 * 1024 * 1024,
	}
	c, err := natsclient.NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
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

func TestNewClientConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     natsclient.ClientConfig
		wantSub string
	}{
		{"empty-url", natsclient.ClientConfig{}, "url is empty"},
		{"negative-reconnect-wait", natsclient.ClientConfig{URL: "nats://x", ReconnectWait: -1}, "reconnect-wait"},
		{"negative-buf-size", natsclient.ClientConfig{URL: "nats://x", ReconnectBufSize: -1}, "reconnect-buf-size"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := natsclient.NewClient(tt.cfg)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantSub)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("err %q does not contain %q", err, tt.wantSub)
			}
			if !strings.HasPrefix(err.Error(), "nats:") {
				t.Errorf("err %q does not have %q prefix", err, "nats:")
			}
		})
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
		once     sync.Once
		done     = make(chan struct{})
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := c.Subscribe(ctx, "test.subject", func(data []byte) {
		mu.Lock()
		received = data
		mu.Unlock()
		once.Do(func() { close(done) })
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

	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())

	err := c.Subscribe(ctx, "test.cancel", func(_ []byte) {
		calls.Add(1)
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	cancel()

	// Wait for drain — subscription count returns to zero.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && c.Conn().NumSubscriptions() > 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if c.Conn().NumSubscriptions() != 0 {
		t.Fatal("subscription did not drain within 2s")
	}

	// Publish after drain. Flush guarantees the server received it.
	if err := c.Publish("test.cancel", "after-cancel"); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if err := c.Conn().Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	// Grace for any stray delivery goroutine. With the sub gone, there is
	// no target — but allow a scheduler tick to be safe.
	time.Sleep(50 * time.Millisecond)
	if n := calls.Load(); n != 0 {
		t.Errorf("handler called %d time(s) after cancel, want 0", n)
	}
}

func TestSubscribeHandlerPanicIsRecovered(t *testing.T) {
	srv := startTestServer(t)
	c := newTestClient(t, srv)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	delivered := make(chan struct{}, 2)
	if err := c.Subscribe(ctx, "test.panic", func(_ []byte) {
		delivered <- struct{}{}
		panic("boom")
	}); err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	for i := 0; i < 2; i++ {
		if err := c.Publish("test.panic", "x"); err != nil {
			t.Fatalf("publish %d: %v", i, err)
		}
	}

	for i := 0; i < 2; i++ {
		select {
		case <-delivered:
		case <-time.After(2 * time.Second):
			t.Fatalf("did not receive delivery %d — handler panic likely killed dispatcher", i+1)
		}
	}
}

func TestEnsureStreams(t *testing.T) {
	srv := startTestServer(t)
	c := newTestClient(t, srv)

	if err := natsclient.EnsureStreams(context.Background(), c.JetStream(), testStreamConfigs()); err != nil {
		t.Fatalf("ensure streams: %v", err)
	}

	want := map[string][]string{
		"EVENTS":   {subjects.Normalised},
		"THREATS":  {subjects.ThreatsPrefix + ">"},
		"EVIDENCE": {subjects.EvidencePrefix + ">"},
	}

	js := c.JetStream()
	ctx := context.Background()
	for name, wantSubjects := range want {
		s, err := js.Stream(ctx, name)
		if err != nil {
			t.Errorf("stream %s not found: %v", name, err)
			continue
		}
		info := s.CachedInfo()
		if !reflect.DeepEqual(info.Config.Subjects, wantSubjects) {
			t.Errorf("stream %s subjects = %v, want %v", name, info.Config.Subjects, wantSubjects)
		}
	}
}

func TestEnsureStreamsIdempotent(t *testing.T) {
	srv := startTestServer(t)
	c := newTestClient(t, srv)

	if err := natsclient.EnsureStreams(context.Background(), c.JetStream(), testStreamConfigs()); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if err := natsclient.EnsureStreams(context.Background(), c.JetStream(), testStreamConfigs()); err != nil {
		t.Fatalf("second call: %v", err)
	}
}

func TestJetStreamPublishConsume(t *testing.T) {
	srv := startTestServer(t)
	c := newTestClient(t, srv)

	if err := natsclient.EnsureStreams(context.Background(), c.JetStream(), testStreamConfigs()); err != nil {
		t.Fatalf("ensure streams: %v", err)
	}

	type event struct {
		ID string `json:"id"`
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ack, err := c.PublishJS(ctx, subjects.Normalised, event{ID: "evt-001"})
	if err != nil {
		t.Fatalf("publish-js: %v", err)
	}
	if ack == nil || ack.Stream != "EVENTS" {
		t.Errorf("ack stream = %v, want EVENTS", ack)
	}

	js := c.JetStream()
	cons, err := js.CreateConsumer(ctx, "EVENTS", jetstream.ConsumerConfig{
		FilterSubject: subjects.Normalised,
	})
	if err != nil {
		t.Fatalf("create consumer: %v", err)
	}

	msg, err := cons.Next(jetstream.FetchMaxWait(3 * time.Second))
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

func TestPublishConcurrent(t *testing.T) {
	srv := startTestServer(t)
	c := newTestClient(t, srv)

	const n = 50
	var received atomic.Int32
	delivered := make(chan struct{}, n)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := c.Subscribe(ctx, "test.concurrent", func(_ []byte) {
		received.Add(1)
		delivered <- struct{}{}
	}); err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			if err := c.Publish("test.concurrent", map[string]int{"i": i}); err != nil {
				t.Errorf("publish %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	deadline := time.After(3 * time.Second)
	for i := 0; i < n; i++ {
		select {
		case <-delivered:
		case <-deadline:
			t.Fatalf("timed out after %d/%d deliveries", received.Load(), n)
		}
	}
	if got := received.Load(); got != n {
		t.Errorf("received %d, want %d", got, n)
	}
}

func TestErrorWrapPattern(t *testing.T) {
	srv := startTestServer(t)
	c := newTestClient(t, srv)

	// Marshal error path: functions are not JSON-marshallable.
	err := c.Publish("test.wrap", func() {})
	if err == nil {
		t.Fatal("expected marshal error, got nil")
	}
	if !strings.HasPrefix(err.Error(), "nats: ") {
		t.Errorf("marshal error %q does not have %q prefix", err, "nats: ")
	}

	// PublishJS marshal error path.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := c.PublishJS(ctx, "test.wrap", func() {}); err == nil {
		t.Error("expected publish-js marshal error, got nil")
	} else if !strings.HasPrefix(err.Error(), "nats: ") {
		t.Errorf("publish-js error %q does not have %q prefix", err, "nats: ")
	}
}

func TestPublishOnClosedClient(t *testing.T) {
	srv := startTestServer(t)
	c := newTestClient(t, srv)

	if err := c.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}

	err := c.Publish("x", "y")
	if err == nil {
		t.Fatal("expected error publishing on closed client")
	}
	// The conn is closed but not nil, so we get the wrapped nats.ErrConnectionClosed.
	if !strings.HasPrefix(err.Error(), "nats:") {
		t.Errorf("err %q does not have %q prefix", err, "nats:")
	}
}

func TestNilClientReturnsErrClosed(t *testing.T) {
	var c *natsclient.Client // nil

	if err := c.Publish("x", "y"); !errors.Is(err, natsclient.ErrClientClosed) {
		t.Errorf("Publish on nil client: got %v, want ErrClientClosed", err)
	}
	if _, err := c.PublishJS(context.Background(), "x", "y"); !errors.Is(err, natsclient.ErrClientClosed) {
		t.Errorf("PublishJS on nil client: got %v, want ErrClientClosed", err)
	}
	if err := c.Subscribe(context.Background(), "x", func([]byte) {}); !errors.Is(err, natsclient.ErrClientClosed) {
		t.Errorf("Subscribe on nil client: got %v, want ErrClientClosed", err)
	}
	if err := c.Close(context.Background()); err != nil {
		t.Errorf("Close on nil client: got %v, want nil", err)
	}
	if c.Conn() != nil {
		t.Error("Conn on nil client: expected nil")
	}
	if c.JetStream() != nil {
		t.Error("JetStream on nil client: expected nil")
	}
}

func TestReconnectSurvival(t *testing.T) {
	// Start srv1 on a random port, then read the actual bound port so we
	// can restart srv2 on the same one. Avoids a freePort()-then-bind
	// TOCTOU race where another process could claim the port in between.
	srv1 := startServerOnce(t, -1)
	addr, ok := srv1.Addr().(*net.TCPAddr)
	if !ok || addr == nil {
		t.Fatalf("srv1 addr: unexpected type %T", srv1.Addr())
	}
	port := addr.Port

	cfg := natsclient.ClientConfig{
		URL:              srv1.ClientURL(),
		Name:             "test-reconnect",
		MaxReconnects:    -1,
		ReconnectWait:    50 * time.Millisecond,
		ReconnectBufSize: 1 * 1024 * 1024,
	}
	c, err := natsclient.NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })

	delivered := make(chan []byte, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Subscribe(ctx, "test.reconnect", func(data []byte) {
		delivered <- data
	}); err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	// Initial delivery.
	if err := c.Publish("test.reconnect", "hello-1"); err != nil {
		t.Fatalf("publish 1: %v", err)
	}
	select {
	case <-delivered:
	case <-time.After(2 * time.Second):
		t.Fatal("first message not received")
	}

	// Tear down server and wait for client to notice.
	srv1.Shutdown()
	srv1.WaitForShutdown()
	waitFor(t, 2*time.Second, func() bool {
		return c.Conn().Status() != nats.CONNECTED
	}, "client did not detect disconnect")

	// Publish during disconnection — must buffer, not error.
	if err := c.Publish("test.reconnect", "hello-2"); err != nil {
		t.Fatalf("buffered publish: %v", err)
	}

	// Restart on same port. The client reconnects automatically.
	srv2 := startServerOnce(t, port)
	_ = srv2

	waitFor(t, 5*time.Second, func() bool {
		return c.Conn().Status() == nats.CONNECTED
	}, "client did not reconnect")

	// Buffered message is flushed and the re-established subscription
	// receives it.
	select {
	case data := <-delivered:
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			t.Fatalf("unmarshal buffered: %v", err)
		}
		if s != "hello-2" {
			t.Errorf("got %q, want %q", s, "hello-2")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("buffered message not delivered after reconnect")
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
	if cfg.ReconnectBufSize <= 0 {
		t.Errorf("ReconnectBufSize: got %d, want > 0", cfg.ReconnectBufSize)
	}
}

func TestStreamConfigsCoversRawSubjects(t *testing.T) {
	// Story 1.6 requires the EVENTS_RAW stream so per-source raw subjects
	// (subjects.RawFalco, RawAudit, RawRuntime, RawNetwork, RawAppLog)
	// gain JetStream at-least-once semantics. Guard against silent
	// regression: future edits to streams.go must keep the raw prefix in
	// some stream's Subjects.
	configs := natsclient.StreamConfigs()
	rawCovered := false
	for _, cfg := range configs {
		for _, subj := range cfg.Subjects {
			if subj == subjects.RawPrefix+">" || subj == "olaitan.events.raw.>" {
				rawCovered = true
				break
			}
		}
	}
	if !rawCovered {
		t.Fatalf("StreamConfigs: no stream covers %q", subjects.RawPrefix+">")
	}
}

func TestStreamConfigsDeepCopy(t *testing.T) {
	a := natsclient.StreamConfigs()
	b := natsclient.StreamConfigs()

	// Mutating one must not affect the other.
	a[0].Subjects[0] = "mutated"
	if b[0].Subjects[0] == "mutated" {
		t.Error("StreamConfigs returned shared Subjects slice")
	}

	// Mutating the returned slice must not affect package state.
	c := natsclient.StreamConfigs()
	if c[0].Subjects[0] == "mutated" {
		t.Error("package-level streamConfigs was mutated")
	}
}

// --- test helpers ---

// testStreamConfigs mirrors the production stream topology (names, subjects,
// retention policy) but with MemoryStorage and tiny MaxBytes so the in-process
// test server does not try to reserve the full production MaxBytes against
// the runner's real free disk (which would fail with err_code=10047 on
// CI). TestStreamConfigsMatchArchitectureContract guards the production
// values separately.
func testStreamConfigs() []jetstream.StreamConfig {
	return []jetstream.StreamConfig{
		{
			Name:      "EVENTS",
			Subjects:  []string{subjects.Normalised},
			MaxAge:    24 * time.Hour,
			MaxBytes:  1 * 1024 * 1024,
			Storage:   jetstream.MemoryStorage,
			Retention: jetstream.LimitsPolicy,
		},
		{
			Name:      "EVENTS_RAW",
			Subjects:  []string{subjects.RawPrefix + ">"},
			MaxAge:    6 * time.Hour,
			MaxBytes:  1 * 1024 * 1024,
			Storage:   jetstream.MemoryStorage,
			Retention: jetstream.LimitsPolicy,
		},
		{
			Name:      "THREATS",
			Subjects:  []string{subjects.ThreatsPrefix + ">"},
			MaxAge:    7 * 24 * time.Hour,
			MaxBytes:  1 * 1024 * 1024,
			Storage:   jetstream.MemoryStorage,
			Retention: jetstream.LimitsPolicy,
		},
		{
			Name:      "EVIDENCE",
			Subjects:  []string{subjects.EvidencePrefix + ">"},
			MaxAge:    0,
			MaxBytes:  1 * 1024 * 1024,
			Storage:   jetstream.MemoryStorage,
			Retention: jetstream.LimitsPolicy,
		},
	}
}

// startServerOnce starts a NATS server on the given port and registers it
// for shutdown at test end. Unlike startTestServerAt, the returned server is
// intended to be shut down mid-test; callers should retain the reference.
func startServerOnce(t *testing.T, port int) *natsserver.Server {
	t.Helper()
	opts := &natsserver.Options{
		Host:      "127.0.0.1",
		Port:      port,
		JetStream: true,
		StoreDir:  t.TempDir(),
		NoLog:     true,
		NoSigs:    true,
	}
	srv, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatalf("start nats server on port %d: %v", port, err)
	}
	srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatalf("nats server on port %d not ready", port)
	}
	t.Cleanup(srv.Shutdown)
	return srv
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(msg)
}
