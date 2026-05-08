package cri

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	natsjs "github.com/nats-io/nats.go/jetstream"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"

	"github.com/olokotoh/olaitan/internal/retry"
)

// stubRuntimeClient is an in-process implementation of the local
// runtimeClient interface. Tests inject it via Adapter.newClientFn so
// the dial+stream loop can be exercised without bufconn or real
// containerd.
type stubRuntimeClient struct {
	openFn func(ctx context.Context) (runtimeapi.RuntimeService_GetContainerEventsClient, error)
}

func (s *stubRuntimeClient) GetContainerEvents(ctx context.Context, _ *runtimeapi.GetEventsRequest, _ ...grpc.CallOption) (runtimeapi.RuntimeService_GetContainerEventsClient, error) {
	return s.openFn(ctx)
}

// stubStream is a hand-rolled implementation of the streaming Recv
// surface. It pulls events from a channel and surfaces channel
// closure as io.EOF (so the adapter's outer reconnect loop is
// exercised).
type stubStream struct {
	ctx    context.Context
	events <-chan stubEvent
}

type stubEvent struct {
	ev  *runtimeapi.ContainerEventResponse
	err error
}

func (s *stubStream) Recv() (*runtimeapi.ContainerEventResponse, error) {
	select {
	case e, ok := <-s.events:
		if !ok {
			return nil, errClosed
		}
		if e.err != nil {
			return nil, e.err
		}
		return e.ev, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}

func (s *stubStream) Header() (metadata.MD, error) { return metadata.MD{}, nil }
func (s *stubStream) Trailer() metadata.MD         { return metadata.MD{} }
func (s *stubStream) CloseSend() error             { return nil }
func (s *stubStream) Context() context.Context     { return s.ctx }
func (s *stubStream) SendMsg(_ any) error          { return nil }
func (s *stubStream) RecvMsg(_ any) error          { return nil }

var errClosed = errors.New("stub stream channel closed (io.EOF substitute)")

// stubPublisher captures publish calls for assertions and supports
// returning an error to drive retry / log+drop paths.
type stubPublisher struct {
	mu          sync.Mutex
	subjects    []string
	payloads    []any
	headers     []natsjs.PublishOpt
	publishErr  error
	publishOnce sync.Once
	publishedCh chan struct{}
}

func (p *stubPublisher) PublishJS(_ context.Context, subject string, data any, opts ...natsjs.PublishOpt) (*natsjs.PubAck, error) {
	p.mu.Lock()
	p.subjects = append(p.subjects, subject)
	p.payloads = append(p.payloads, data)
	p.headers = append(p.headers, opts...)
	p.mu.Unlock()
	if p.publishedCh != nil {
		p.publishOnce.Do(func() { close(p.publishedCh) })
	}
	if p.publishErr != nil {
		return nil, p.publishErr
	}
	return &natsjs.PubAck{Stream: "EVENTS_RAW"}, nil
}

func (p *stubPublisher) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.subjects)
}

// fakeDial returns a non-nil *grpc.ClientConn the adapter can call
// Close() on. We never speak over it because newClientFn returns the
// stubRuntimeClient, which short-circuits the Invoke / NewStream
// paths inside the connection.
func fakeDial(t testing.TB) func(context.Context, string) (*grpc.ClientConn, error) {
	t.Helper()
	return func(_ context.Context, _ string) (*grpc.ClientConn, error) {
		// The test seam never actually transmits over this connection
		// because newClientFn replaces the runtimeClient. We use the
		// production grpc.NewClient with an unreachable target so the
		// resulting *grpc.ClientConn closes cleanly without dialling.
		return grpc.NewClient("passthrough:///stub", grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
}

// errSyntheticDial is a synthetic terminal error used by the dial-failure tests.
var errSyntheticDial = errors.New("synthetic dial failure")

func TestNew_RejectsNilPublisher(t *testing.T) {
	_, err := New(Config{SocketPath: "/x", Hostname: "n"}, nil, nil)
	if err == nil || err.Error() != "cri: new: nats publisher is nil" {
		t.Errorf("New: got %v, want nats publisher nil error", err)
	}
}

func TestNew_RejectsEmptySocketPath(t *testing.T) {
	pub := &stubPublisher{}
	_, err := New(Config{SocketPath: "", Hostname: "n"}, pub, nil)
	if err == nil {
		t.Error("New: expected error for empty SocketPath")
	}
}

func TestNew_RejectsEmptyHostname(t *testing.T) {
	pub := &stubPublisher{}
	_, err := New(Config{SocketPath: "/x", Hostname: ""}, pub, nil)
	if err == nil {
		t.Error("New: expected error for empty Hostname")
	}
}

func TestNew_RejectsNegativeDialTimeout(t *testing.T) {
	pub := &stubPublisher{}
	_, err := New(Config{SocketPath: "/x", Hostname: "n", DialTimeout: -1}, pub, nil)
	if err == nil {
		t.Error("New: expected error for negative DialTimeout")
	}
}

func TestNew_RejectsNegativeStaleness(t *testing.T) {
	pub := &stubPublisher{}
	_, err := New(Config{SocketPath: "/x", Hostname: "n", StalenessTimeout: -1}, pub, nil)
	if err == nil {
		t.Error("New: expected error for negative StalenessTimeout")
	}
}

func TestNew_DefaultsApplied(t *testing.T) {
	pub := &stubPublisher{}
	a, err := New(Config{SocketPath: "/x", Hostname: "n"}, pub, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.cfg.DialTimeout != 10*time.Second {
		t.Errorf("DialTimeout: got %s, want 10s", a.cfg.DialTimeout)
	}
	if a.cfg.StalenessTimeout != 5*time.Minute {
		t.Errorf("StalenessTimeout: got %s, want 5m", a.cfg.StalenessTimeout)
	}
}

func TestRun_ContextCancelExitsCleanly(t *testing.T) {
	pub := &stubPublisher{}
	a, err := New(quickConfig(), pub, nil)
	if err != nil {
		t.Fatal(err)
	}
	a.dialFn = fakeDial(t)
	a.newClientFn = func(_ *grpc.ClientConn) runtimeClient {
		return &stubRuntimeClient{
			openFn: func(ctx context.Context) (runtimeapi.RuntimeService_GetContainerEventsClient, error) {
				return &stubStream{ctx: ctx, events: make(chan stubEvent)}, nil
			},
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- a.Run(ctx) }()
	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Errorf("Run: got %v on ctx-cancel, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within timeout after ctx-cancel")
	}
}

func TestRun_HealthFlipsOnConnectError(t *testing.T) {
	pub := &stubPublisher{}
	a, err := New(quickConfig(), pub, nil)
	if err != nil {
		t.Fatal(err)
	}
	a.dialFn = func(_ context.Context, _ string) (*grpc.ClientConn, error) {
		return nil, errSyntheticDial
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = a.Run(ctx)

	healthy, herr := a.Health().Status()
	if healthy {
		t.Error("Health: got healthy after persistent dial failure")
	}
	if herr == nil {
		t.Error("Health: got nil lastErr after dial failure")
	}
}

func TestRun_PublishesTranslateableEvent(t *testing.T) {
	pub := &stubPublisher{publishedCh: make(chan struct{})}
	a, err := New(quickConfig(), pub, nil)
	if err != nil {
		t.Fatal(err)
	}
	a.dialFn = fakeDial(t)
	events := make(chan stubEvent, 1)
	a.newClientFn = func(_ *grpc.ClientConn) runtimeClient {
		return &stubRuntimeClient{
			openFn: func(ctx context.Context) (runtimeapi.RuntimeService_GetContainerEventsClient, error) {
				return &stubStream{ctx: ctx, events: events}, nil
			},
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- a.Run(ctx) }()

	events <- stubEvent{ev: makeEvent(nil)}

	select {
	case <-pub.publishedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("publish did not happen within timeout")
	}

	if pub.count() != 1 {
		t.Errorf("publish count: got %d, want 1", pub.count())
	}
	if pub.subjects[0] != "olaitan.events.raw.runtime" {
		t.Errorf("publish subject: got %q, want olaitan.events.raw.runtime", pub.subjects[0])
	}
	healthy, _ := a.Health().Status()
	if !healthy {
		t.Error("Health: expected healthy after first successful publish")
	}

	cancel()
	<-runDone
}

func TestRun_DropsTranslateError_NoCrash(t *testing.T) {
	pub := &stubPublisher{publishedCh: make(chan struct{})}
	a, err := New(quickConfig(), pub, nil)
	if err != nil {
		t.Fatal(err)
	}
	a.dialFn = fakeDial(t)
	events := make(chan stubEvent, 2)
	a.newClientFn = func(_ *grpc.ClientConn) runtimeClient {
		return &stubRuntimeClient{
			openFn: func(ctx context.Context) (runtimeapi.RuntimeService_GetContainerEventsClient, error) {
				return &stubStream{ctx: ctx, events: events}, nil
			},
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- a.Run(ctx) }()

	// First event is malformed (zero CreatedAt) -- adapter must
	// log+drop and continue receiving.
	bad := makeEvent(func(e *runtimeapi.ContainerEventResponse) { e.CreatedAt = 0 })
	events <- stubEvent{ev: bad}
	// Second event is good and should publish.
	events <- stubEvent{ev: makeEvent(nil)}

	select {
	case <-pub.publishedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("good event was not published after dropping malformed event")
	}

	if got := a.TranslateErrors(); got != 1 {
		t.Errorf("TranslateErrors: got %d, want 1", got)
	}

	cancel()
	<-runDone
}

func TestRun_TerminalPublishErrorIsDropped(t *testing.T) {
	pub := &stubPublisher{
		publishErr:  fmt.Errorf("nats: maximum payload exceeded"),
		publishedCh: make(chan struct{}),
	}
	a, err := New(quickConfig(), pub, nil)
	if err != nil {
		t.Fatal(err)
	}
	a.dialFn = fakeDial(t)
	events := make(chan stubEvent, 1)
	a.newClientFn = func(_ *grpc.ClientConn) runtimeClient {
		return &stubRuntimeClient{
			openFn: func(ctx context.Context) (runtimeapi.RuntimeService_GetContainerEventsClient, error) {
				return &stubStream{ctx: ctx, events: events}, nil
			},
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- a.Run(ctx) }()

	events <- stubEvent{ev: makeEvent(nil)}

	select {
	case <-pub.publishedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("publish did not happen within timeout")
	}

	// Allow PublishDrops counter to settle (it increments after
	// publishWithRetry returns the permanent error to the loop body).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if a.PublishDrops() == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if a.PublishDrops() != 1 {
		t.Errorf("PublishDrops: got %d, want 1", a.PublishDrops())
	}

	cancel()
	<-runDone
}

func TestRun_StalenessWatchdog_QuietButConnected_DoesNotFlipUnhealthy(t *testing.T) {
	// This is the load-bearing design-difference test versus Story 1.7's
	// audit watchdog: CRI lifecycle events are quiet by design. With
	// the connection Ready and lastEvent in the past, staleness alone
	// must NOT trip the source unhealthy.
	cfg := quickConfig()
	cfg.StalenessTimeout = 100 * time.Millisecond
	pub := &stubPublisher{publishedCh: make(chan struct{})}
	a, err := New(cfg, pub, nil)
	if err != nil {
		t.Fatal(err)
	}
	a.dialFn = fakeDial(t)
	events := make(chan stubEvent, 1)
	a.newClientFn = func(_ *grpc.ClientConn) runtimeClient {
		return &stubRuntimeClient{
			openFn: func(ctx context.Context) (runtimeapi.RuntimeService_GetContainerEventsClient, error) {
				return &stubStream{ctx: ctx, events: events}, nil
			},
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- a.Run(ctx) }()

	events <- stubEvent{ev: makeEvent(nil)}
	select {
	case <-pub.publishedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("first event not published")
	}

	// Wait several watchdog ticks past the staleness threshold; the
	// source must remain healthy because the connection is Ready.
	time.Sleep(500 * time.Millisecond)

	healthy, herr := a.Health().Status()
	if !healthy {
		t.Errorf("Health: expected healthy after quiet-but-connected stretch (got healthy=%v err=%v)",
			healthy, herr)
	}

	cancel()
	<-runDone
}

func TestRun_StalenessWatchdog_DisconnectedAndStale_FlipsUnhealthy(t *testing.T) {
	// When the connection drops and stays down longer than
	// StalenessTimeout, the watchdog should flip MarkUnhealthy. With
	// our stub, dropping the connection happens by the stream
	// returning an error; the outer connect-loop will retry. We use a
	// dialFn that fails after the first successful open so the
	// reconnection attempt produces the dial-failure path.
	cfg := quickConfig()
	cfg.StalenessTimeout = 100 * time.Millisecond
	pub := &stubPublisher{publishedCh: make(chan struct{})}
	a, err := New(cfg, pub, nil)
	if err != nil {
		t.Fatal(err)
	}

	var dialCalls atomic.Int32
	a.dialFn = func(_ context.Context, _ string) (*grpc.ClientConn, error) {
		n := dialCalls.Add(1)
		if n == 1 {
			return grpc.NewClient("passthrough:///stub", grpc.WithTransportCredentials(insecure.NewCredentials()))
		}
		return nil, errSyntheticDial
	}

	events := make(chan stubEvent, 1)
	streamErr := make(chan struct{})
	a.newClientFn = func(_ *grpc.ClientConn) runtimeClient {
		return &stubRuntimeClient{
			openFn: func(ctx context.Context) (runtimeapi.RuntimeService_GetContainerEventsClient, error) {
				wrapper := &disconnectingStream{
					ctx:        ctx,
					events:     events,
					disconnect: streamErr,
				}
				return wrapper, nil
			},
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- a.Run(ctx) }()

	events <- stubEvent{ev: makeEvent(nil)}
	select {
	case <-pub.publishedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("first event not published")
	}

	// Trigger disconnect; reconnects will fail via dialFn.
	close(streamErr)

	// Wait for the watchdog to flip unhealthy after disconnect+stale.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		healthy, _ := a.Health().Status()
		if !healthy {
			cancel()
			<-runDone
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("Health did not flip unhealthy after disconnect+stale window")
}

// disconnectingStream is a stubStream variant whose Recv exits with
// an error once the disconnect channel closes, simulating a
// containerd restart that closes the gRPC stream.
type disconnectingStream struct {
	ctx        context.Context
	events     <-chan stubEvent
	disconnect <-chan struct{}
}

func (s *disconnectingStream) Recv() (*runtimeapi.ContainerEventResponse, error) {
	select {
	case e, ok := <-s.events:
		if !ok {
			return nil, errClosed
		}
		if e.err != nil {
			return nil, e.err
		}
		return e.ev, nil
	case <-s.disconnect:
		return nil, errors.New("synthetic stream disconnect")
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}

func (s *disconnectingStream) Header() (metadata.MD, error) { return metadata.MD{}, nil }
func (s *disconnectingStream) Trailer() metadata.MD         { return metadata.MD{} }
func (s *disconnectingStream) CloseSend() error             { return nil }
func (s *disconnectingStream) Context() context.Context     { return s.ctx }
func (s *disconnectingStream) SendMsg(_ any) error          { return nil }
func (s *disconnectingStream) RecvMsg(_ any) error          { return nil }

// quickConfig returns a Config with tiny retry intervals so tests do
// not spend seconds idling between attempts.
func quickConfig() Config {
	return Config{
		SocketPath: "/run/containerd/containerd.sock",
		Hostname:   "node-test",
		ConnectRetry: retry.Strategy{
			Min: 5 * time.Millisecond, Max: 20 * time.Millisecond, Multiplier: 2.0, Jitter: 0,
			MaxAttempts: 0,
		},
		PublishRetry: retry.Strategy{
			Min: 5 * time.Millisecond, Max: 20 * time.Millisecond, Multiplier: 2.0, Jitter: 0,
			MaxAttempts: 1,
		},
		DialTimeout:      100 * time.Millisecond,
		StalenessTimeout: 1 * time.Second,
	}
}
