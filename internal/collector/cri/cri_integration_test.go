//go:build integration

package cri

import (
	"context"
	"encoding/json"
	"net"
	"sort"
	"strings"
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
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// startTestNATS spins up an embedded NATS server with JetStream so the
// integration test exercises the real publish path (NFR36: no
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
// resource-constrained CI nodes stay reasonable.
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

// fixtureCRIServer is a hand-rolled implementation of the
// runtime.v1.RuntimeService gRPC service that streams a fixture
// sequence of ContainerEventResponse messages then blocks until ctx
// ends. The integration test drives it by feeding fixtures and
// counting the messages observed on the NATS side.
type fixtureCRIServer struct {
	runtimeapi.UnimplementedRuntimeServiceServer

	mu         sync.Mutex
	fixtures   []*runtimeapi.ContainerEventResponse
	emitted    chan struct{}
	disconnect chan struct{}
}

func newFixtureCRIServer(fixtures []*runtimeapi.ContainerEventResponse) *fixtureCRIServer {
	return &fixtureCRIServer{
		fixtures:   fixtures,
		emitted:    make(chan struct{}),
		disconnect: make(chan struct{}),
	}
}

func (s *fixtureCRIServer) GetContainerEvents(_ *runtimeapi.GetEventsRequest, stream runtimeapi.RuntimeService_GetContainerEventsServer) error {
	for _, f := range s.fixtures {
		if err := stream.Send(f); err != nil {
			return err
		}
	}
	close(s.emitted)
	select {
	case <-s.disconnect:
		return nil
	case <-stream.Context().Done():
		return stream.Context().Err()
	}
}

// startBufconnCRI starts the in-process gRPC server and returns the
// adapter dialFn that resolves the bufconn target.
func startBufconnCRI(t testing.TB, srv *fixtureCRIServer) func(context.Context, string) (*grpc.ClientConn, error) {
	t.Helper()
	const bufSize = 1024 * 1024
	lis := bufconn.Listen(bufSize)
	gsrv := grpc.NewServer()
	runtimeapi.RegisterRuntimeServiceServer(gsrv, srv)
	go func() { _ = gsrv.Serve(lis) }()
	t.Cleanup(gsrv.Stop)

	return func(ctx context.Context, _ string) (*grpc.ClientConn, error) {
		return grpc.NewClient(
			"passthrough:///bufconn",
			grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
				return lis.DialContext(ctx)
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
	}
}

// fixtureContainerEvent constructs a deterministic CRI event with a
// distinct created_at per index, so the resulting Event.ID values are
// also distinct and the post-publish set comparison is stable.
func fixtureContainerEvent(i int, when time.Time) *runtimeapi.ContainerEventResponse {
	containerID := []byte("0123456789abcdef0123456789abcdef")
	containerID[0] = byte('0' + (i % 10))
	return &runtimeapi.ContainerEventResponse{
		ContainerId:        string(containerID),
		ContainerEventType: runtimeapi.ContainerEventType_CONTAINER_STARTED_EVENT,
		CreatedAt:          when.UnixNano() + int64(i),
		PodSandboxStatus: &runtimeapi.PodSandboxStatus{
			Id:        "sandbox-id-001",
			State:     runtimeapi.PodSandboxState_SANDBOX_READY,
			CreatedAt: when.UnixNano(),
			Metadata: &runtimeapi.PodSandboxMetadata{
				Name:      "payments-7f8b9c-xyz",
				Namespace: "payments",
				Uid:       "00000000-0000-0000-0000-000000000001",
				Attempt:   0,
			},
		},
	}
}

func TestAdapter_EndToEnd_Bufconn(t *testing.T) {
	now := time.Date(2026, 5, 5, 14, 30, 0, 0, time.UTC)
	fixtures := []*runtimeapi.ContainerEventResponse{
		fixtureContainerEvent(1, now),
		fixtureContainerEvent(2, now.Add(time.Millisecond)),
		fixtureContainerEvent(3, now.Add(2*time.Millisecond)),
	}

	natsSrv := startTestNATS(t)
	natsCfg := natsclient.DefaultConfig()
	natsCfg.URL = natsSrv.ClientURL()
	natsCfg.Name = "cri-it-test"
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

	srv := newFixtureCRIServer(fixtures)
	dialFn := startBufconnCRI(t, srv)

	consumer, err := nc.JetStream().CreateOrUpdateConsumer(context.Background(), "EVENTS_RAW",
		natsjs.ConsumerConfig{
			Name:          "cri-it-test-consumer",
			FilterSubject: subjects.RawRuntime,
			AckPolicy:     natsjs.AckExplicitPolicy,
		})
	if err != nil {
		t.Fatalf("consumer: %v", err)
	}

	adapter, err := New(Config{
		SocketPath: "/run/containerd/containerd.sock",
		Hostname:   "node-test",
		ConnectRetry: retry.Strategy{
			Min: 10 * time.Millisecond, Max: 100 * time.Millisecond, Multiplier: 2.0, Jitter: 0,
			MaxAttempts: 0,
		},
		PublishRetry: retry.Strategy{
			Min: 10 * time.Millisecond, Max: 50 * time.Millisecond, Multiplier: 2.0, Jitter: 0,
			MaxAttempts: 3,
		},
		DialTimeout:      1 * time.Second,
		StalenessTimeout: 1 * time.Minute,
	}, nc, nil)
	if err != nil {
		t.Fatal(err)
	}
	adapter.dialFn = dialFn

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	runDone := make(chan error, 1)
	go func() { runDone <- adapter.Run(ctx) }()

	// Wait for the server to finish emitting fixtures.
	select {
	case <-srv.emitted:
	case <-time.After(5 * time.Second):
		t.Fatal("fixture server did not emit within timeout")
	}

	// Health should flip to true once the first event is consumed.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		healthy, _ := adapter.Health().Status()
		if healthy {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Collect every published fixture from the consumer.
	var got []schema.Event
	for len(got) < len(fixtures) {
		batch, err := consumer.Fetch(len(fixtures)-len(got), natsjs.FetchMaxWait(2*time.Second))
		if err != nil {
			t.Fatalf("consumer fetch: %v", err)
		}
		for msg := range batch.Messages() {
			var ev schema.Event
			if err := json.Unmarshal(msg.Data(), &ev); err != nil {
				t.Errorf("unmarshal: %v", err)
				continue
			}
			got = append(got, ev)
			_ = msg.Ack()
		}
	}

	cancel()
	if err := <-runDone; err != nil {
		t.Errorf("Run: returned non-nil after ctx cancel: %v", err)
	}

	if len(got) != len(fixtures) {
		t.Fatalf("got %d events, want %d", len(got), len(fixtures))
	}
	sort.Slice(got, func(i, j int) bool { return got[i].ID < got[j].ID })
	for _, ev := range got {
		if ev.Source != schema.SourceRuntime {
			t.Errorf("Source: got %q, want %q", ev.Source, schema.SourceRuntime)
		}
		if ev.Category != schema.CategoryLifecycle {
			t.Errorf("Category: got %q, want %q", ev.Category, schema.CategoryLifecycle)
		}
		if ev.Pod.Node != "node-test" {
			t.Errorf("Pod.Node: got %q, want node-test", ev.Pod.Node)
		}
		if ev.Pod.Namespace != "payments" {
			t.Errorf("Pod.Namespace: got %q, want payments", ev.Pod.Namespace)
		}
	}
}

func TestAdapter_DropsTranslateError_RealBoundary(t *testing.T) {
	now := time.Date(2026, 5, 5, 14, 30, 0, 0, time.UTC)
	bad := fixtureContainerEvent(1, now)
	bad.CreatedAt = 0 // forces ErrInvalidTimestamp at the translate boundary
	good := fixtureContainerEvent(2, now.Add(time.Second))
	fixtures := []*runtimeapi.ContainerEventResponse{bad, good}

	natsSrv := startTestNATS(t)
	natsCfg := natsclient.DefaultConfig()
	natsCfg.URL = natsSrv.ClientURL()
	natsCfg.Name = "cri-it-bad"
	nc, err := natsclient.NewClient(natsCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nc.Close(context.Background()) })
	if err := natsclient.EnsureStreams(context.Background(), nc.JetStream(), testStreamConfigs()); err != nil {
		t.Fatal(err)
	}

	srv := newFixtureCRIServer(fixtures)
	dialFn := startBufconnCRI(t, srv)

	consumer, err := nc.JetStream().CreateOrUpdateConsumer(context.Background(), "EVENTS_RAW",
		natsjs.ConsumerConfig{
			Name:          "cri-it-bad-consumer",
			FilterSubject: subjects.RawRuntime,
			AckPolicy:     natsjs.AckExplicitPolicy,
		})
	if err != nil {
		t.Fatal(err)
	}

	adapter, err := New(Config{
		SocketPath:       "/run/containerd/containerd.sock",
		Hostname:         "node-test",
		ConnectRetry:     retry.Strategy{Min: 10 * time.Millisecond, Max: 50 * time.Millisecond, Multiplier: 2.0, Jitter: 0, MaxAttempts: 0},
		PublishRetry:     retry.Strategy{Min: 10 * time.Millisecond, Max: 50 * time.Millisecond, Multiplier: 2.0, Jitter: 0, MaxAttempts: 3},
		DialTimeout:      1 * time.Second,
		StalenessTimeout: 1 * time.Minute,
	}, nc, nil)
	if err != nil {
		t.Fatal(err)
	}
	adapter.dialFn = dialFn

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	runDone := make(chan error, 1)
	go func() { runDone <- adapter.Run(ctx) }()

	// P15: synchronise on TranslateErrors() == 1 first. The pre-P15
	// shape did a single Fetch + count and asserted, which races on a
	// fast runner where the fetch returns before the adapter has even
	// read the malformed fixture: the test passed for the wrong
	// reason. Polling the typed counter ensures the malformed event
	// has actually traversed the adapter's translate boundary.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if adapter.TranslateErrors() == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := adapter.TranslateErrors(); got != 1 {
		t.Errorf("TranslateErrors: got %d, want 1 (the malformed fixture; counter never tripped)", got)
	}

	// Only one event (the good one) should reach the consumer.
	batch, err := consumer.Fetch(1, natsjs.FetchMaxWait(3*time.Second))
	if err != nil {
		t.Fatalf("consumer fetch: %v", err)
	}
	count := 0
	for msg := range batch.Messages() {
		count++
		_ = msg.Ack()
	}
	if count != 1 {
		t.Errorf("expected 1 event published, got %d", count)
	}

	cancel()
	<-runDone
}

// TestAdapter_AllFourEventTypesPlusOverstrip exercises Task 7.4 (story
// line 272) directly: the test substrate emits one event per CRI
// ContainerEventType (CREATED, STARTED, STOPPED, DELETED) plus one
// oversize fixture whose strip path must be visible at the publish
// boundary. Pre-P8 the integration test only covered STARTED.
func TestAdapter_AllFourEventTypesPlusOverstrip(t *testing.T) {
	now := time.Date(2026, 5, 5, 14, 30, 0, 0, time.UTC)

	// Build one event per type.
	build := func(idx int, kind runtimeapi.ContainerEventType) *runtimeapi.ContainerEventResponse {
		ev := fixtureContainerEvent(idx, now.Add(time.Duration(idx)*time.Millisecond))
		ev.ContainerEventType = kind
		return ev
	}
	created := build(1, runtimeapi.ContainerEventType_CONTAINER_CREATED_EVENT)
	started := build(2, runtimeapi.ContainerEventType_CONTAINER_STARTED_EVENT)
	stopped := build(3, runtimeapi.ContainerEventType_CONTAINER_STOPPED_EVENT)
	deleted := build(4, runtimeapi.ContainerEventType_CONTAINER_DELETED_EVENT)

	// Oversize: pad ContainersStatuses with a long ImageRef + a long
	// Message so the un-stripped marshal exceeds rawSizeBudget and
	// the strip path runs at publish time.
	oversize := build(5, runtimeapi.ContainerEventType_CONTAINER_STARTED_EVENT)
	oversize.ContainersStatuses = []*runtimeapi.ContainerStatus{}
	bigImage := strings.Repeat("a", 8*1024)
	bigMsg := strings.Repeat("b", 4*1024)
	for i := 0; i < 6; i++ {
		oversize.ContainersStatuses = append(oversize.ContainersStatuses,
			&runtimeapi.ContainerStatus{
				Id:       "container-" + string(rune('a'+i)),
				ImageRef: bigImage,
				Message:  bigMsg,
			},
		)
	}

	fixtures := []*runtimeapi.ContainerEventResponse{created, started, stopped, deleted, oversize}

	natsSrv := startTestNATS(t)
	natsCfg := natsclient.DefaultConfig()
	natsCfg.URL = natsSrv.ClientURL()
	natsCfg.Name = "cri-it-types"
	nc, err := natsclient.NewClient(natsCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nc.Close(context.Background()) })
	if err := natsclient.EnsureStreams(context.Background(), nc.JetStream(), testStreamConfigs()); err != nil {
		t.Fatal(err)
	}

	srv := newFixtureCRIServer(fixtures)
	dialFn := startBufconnCRI(t, srv)

	consumer, err := nc.JetStream().CreateOrUpdateConsumer(context.Background(), "EVENTS_RAW",
		natsjs.ConsumerConfig{
			Name:          "cri-it-types-consumer",
			FilterSubject: subjects.RawRuntime,
			AckPolicy:     natsjs.AckExplicitPolicy,
		})
	if err != nil {
		t.Fatal(err)
	}

	adapter, err := New(Config{
		SocketPath:       "/run/containerd/containerd.sock",
		Hostname:         "node-test",
		ConnectRetry:     retry.Strategy{Min: 10 * time.Millisecond, Max: 100 * time.Millisecond, Multiplier: 2.0, Jitter: 0, MaxAttempts: 0},
		PublishRetry:     retry.Strategy{Min: 10 * time.Millisecond, Max: 50 * time.Millisecond, Multiplier: 2.0, Jitter: 0, MaxAttempts: 3},
		DialTimeout:      1 * time.Second,
		StalenessTimeout: 1 * time.Minute,
	}, nc, nil)
	if err != nil {
		t.Fatal(err)
	}
	adapter.dialFn = dialFn

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	runDone := make(chan error, 1)
	go func() { runDone <- adapter.Run(ctx) }()

	got := make([]schema.Event, 0, len(fixtures))
	for len(got) < len(fixtures) {
		batch, ferr := consumer.Fetch(len(fixtures)-len(got), natsjs.FetchMaxWait(3*time.Second))
		if ferr != nil {
			t.Fatalf("consumer fetch: %v", ferr)
		}
		for msg := range batch.Messages() {
			var ev schema.Event
			if uerr := json.Unmarshal(msg.Data(), &ev); uerr != nil {
				t.Errorf("unmarshal: %v", uerr)
				continue
			}
			got = append(got, ev)
			_ = msg.Ack()
		}
	}

	cancel()
	<-runDone

	if len(got) != len(fixtures) {
		t.Fatalf("got %d events, want %d", len(got), len(fixtures))
	}

	// Assert one tag per type appears across the publish boundary.
	wantTags := map[string]bool{
		"event_type:created": false,
		"event_type:started": false,
		"event_type:stopped": false,
		"event_type:deleted": false,
	}
	sawStripped := false
	for _, ev := range got {
		for _, tag := range ev.Tags {
			if _, ok := wantTags[tag]; ok {
				wantTags[tag] = true
			}
		}
		// The oversize fixture's published Raw must be strip-marked.
		if strings.Contains(string(ev.Raw), `"_stripped":true`) {
			sawStripped = true
		}
	}
	for tag, seen := range wantTags {
		if !seen {
			t.Errorf("missing tag at publish boundary: %q", tag)
		}
	}
	if !sawStripped {
		t.Errorf("oversize fixture did not produce a _stripped:true event at the publish boundary")
	}
}
