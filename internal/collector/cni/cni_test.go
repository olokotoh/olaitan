package cni

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	natsjs "github.com/nats-io/nats.go/jetstream"

	"github.com/olokotoh/olaitan/internal/collector/cni/goldmanepb"
)

// stubPublisher records all PublishJS calls. Each call is appended
// to msgs; PublishJS is goroutine-safe under the adapter's single-
// goroutine consume loop.
type stubPublisher struct {
	mu     sync.Mutex
	msgs   []stubMsg
	failOn map[int]error // call index -> error
}

type stubMsg struct {
	subject string
	data    any
	optsLen int
}

func newStubPublisher() *stubPublisher {
	return &stubPublisher{failOn: map[int]error{}}
}

func (s *stubPublisher) PublishJS(_ context.Context, subject string, data any, opts ...natsjs.PublishOpt) (*natsjs.PubAck, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := len(s.msgs)
	if err, ok := s.failOn[idx]; ok {
		return nil, err
	}
	s.msgs = append(s.msgs, stubMsg{subject: subject, data: data, optsLen: len(opts)})
	return &natsjs.PubAck{Stream: "EVENTS_RAW", Sequence: uint64(idx + 1)}, nil
}

func (s *stubPublisher) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.msgs)
}

func (s *stubPublisher) snapshot() []stubMsg {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]stubMsg, len(s.msgs))
	copy(out, s.msgs)
	return out
}

// stubStream returns FlowResult values from a pre-set queue then
// optionally errors or blocks until ctx is cancelled. Mirrors the
// gRPC ServerStreamingClient surface the adapter consumes. When
// blockAfterQueue is true and the queue is empty (and err is nil),
// Recv blocks until ctx is cancelled (returning ctx.Err) so a test
// can assert a stable "consumed all queued flows and the connection
// is healthy" state without the io.EOF reconnect race flipping
// health back to false.
type stubStream struct {
	mu              sync.Mutex
	queue           []*goldmanepb.FlowResult
	err             error
	blockAfterQueue bool
	ctx             context.Context

	grpc.ServerStreamingClient[goldmanepb.FlowResult]
}

func (s *stubStream) Recv() (*goldmanepb.FlowResult, error) {
	for {
		s.mu.Lock()
		if len(s.queue) == 0 {
			if s.err != nil {
				s.mu.Unlock()
				return nil, s.err
			}
			if !s.blockAfterQueue {
				s.mu.Unlock()
				return nil, io.EOF
			}
			ctx := s.ctx
			s.mu.Unlock()
			if ctx != nil {
				select {
				case <-ctx.Done():
					return nil, status.FromContextError(ctx.Err()).Err()
				case <-time.After(5 * time.Millisecond):
					continue
				}
			}
			time.Sleep(5 * time.Millisecond)
			continue
		}
		fr := s.queue[0]
		s.queue = s.queue[1:]
		s.mu.Unlock()
		return fr, nil
	}
}

type stubFlowsClient struct {
	stream *stubStream
	openFn func(ctx context.Context, in *goldmanepb.FlowStreamRequest) (grpc.ServerStreamingClient[goldmanepb.FlowResult], error)
}

func (s *stubFlowsClient) Stream(ctx context.Context, in *goldmanepb.FlowStreamRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[goldmanepb.FlowResult], error) {
	if s.openFn != nil {
		return s.openFn(ctx, in)
	}
	if s.stream != nil {
		s.stream.mu.Lock()
		s.stream.ctx = ctx
		s.stream.mu.Unlock()
	}
	return s.stream, nil
}

func newAdapterWithStubs(t *testing.T, stream *stubStream, pub *stubPublisher) *Adapter {
	t.Helper()
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	for _, p := range []string{caPath, certPath, keyPath} {
		if err := os.WriteFile(p, []byte("placeholder"), 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	cfg := Config{
		GoldmaneAddr:        "stub:7443",
		CABundlePath:        caPath,
		ClientCertPath:      certPath,
		ClientKeyPath:       keyPath,
		StalenessTimeout:    100 * time.Millisecond,
		AggregationInterval: 15,
		StartTimeGte:        -60,
	}
	a, err := New(cfg, pub, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Substitute test seams.
	a.tlsLoaderFn = func() (*tls.Config, error) { return &tls.Config{}, nil }
	a.dialFn = func(_ context.Context, _ string, _ *tls.Config) (*grpc.ClientConn, error) {
		// Build a lazy gRPC client without dialling anything. The
		// stubFlowsClient ignores the connection; what we need is a
		// real *grpc.ClientConn so the adapter's deferred cc.Close
		// does not panic.
		return grpc.NewClient("passthrough:test", grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	a.newClientFn = func(_ grpc.ClientConnInterface) flowsClient {
		return &stubFlowsClient{stream: stream}
	}
	return a
}

func TestNew_ValidationErrors(t *testing.T) {
	pub := newStubPublisher()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	cases := []struct {
		name    string
		cfg     Config
		wantMsg string
	}{
		{"missing ca", Config{ClientCertPath: "c", ClientKeyPath: "k"}, "CABundlePath"},
		{"missing cert", Config{CABundlePath: "ca", ClientKeyPath: "k"}, "ClientCertPath"},
		{"missing key", Config{CABundlePath: "ca", ClientCertPath: "c"}, "ClientKeyPath"},
		{"negative dial", Config{CABundlePath: "ca", ClientCertPath: "c", ClientKeyPath: "k", DialTimeout: -1}, "dial timeout"},
		{"negative staleness", Config{CABundlePath: "ca", ClientCertPath: "c", ClientKeyPath: "k", StalenessTimeout: -1}, "staleness timeout"},
		{"max bytes below floor", Config{CABundlePath: "ca", ClientCertPath: "c", ClientKeyPath: "k", MaxEventBytes: 1024}, "max event bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.cfg, pub, log)
			if err == nil {
				t.Fatalf("got nil, want error containing %q", tc.wantMsg)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("err %q does not contain %q", err.Error(), tc.wantMsg)
			}
		})
	}
}

func TestNew_NilPublisher(t *testing.T) {
	_, err := New(Config{CABundlePath: "a", ClientCertPath: "b", ClientKeyPath: "c"}, nil, slog.Default())
	if err == nil || !strings.Contains(err.Error(), "publisher") {
		t.Fatalf("got %v, want publisher error", err)
	}
}

func TestNew_DefaultsApplied(t *testing.T) {
	pub := newStubPublisher()
	a, err := New(Config{CABundlePath: "ca", ClientCertPath: "c", ClientKeyPath: "k"}, pub, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.cfg.GoldmaneAddr != defaultGoldmaneAddr {
		t.Errorf("GoldmaneAddr default: got %q, want %q", a.cfg.GoldmaneAddr, defaultGoldmaneAddr)
	}
	if a.cfg.ServerName != defaultServerName {
		t.Errorf("ServerName default: got %q, want %q", a.cfg.ServerName, defaultServerName)
	}
	if a.cfg.DialTimeout != 10*time.Second {
		t.Errorf("DialTimeout default: got %s, want 10s", a.cfg.DialTimeout)
	}
	if a.cfg.StalenessTimeout != 10*time.Minute {
		t.Errorf("StalenessTimeout default: got %s, want 10m", a.cfg.StalenessTimeout)
	}
	if a.cfg.MaxEventBytes != DefaultMaxEventBytes {
		t.Errorf("MaxEventBytes default: got %d, want %d", a.cfg.MaxEventBytes, DefaultMaxEventBytes)
	}
	if a.cfg.AggregationInterval != 15 {
		t.Errorf("AggregationInterval default: got %d, want 15", a.cfg.AggregationInterval)
	}
	if a.cfg.StartTimeGte != -60 {
		t.Errorf("StartTimeGte default: got %d, want -60", a.cfg.StartTimeGte)
	}
}

func TestRun_FirstFlowFlipsHealthy(t *testing.T) {
	stream := &stubStream{queue: []*goldmanepb.FlowResult{validFixture()}, blockAfterQueue: true}
	pub := newStubPublisher()
	a := newAdapterWithStubs(t, stream, pub)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	// Wait for the adapter to consume the one fixture flow.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if pub.count() >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	healthy, _ := a.Health().Status()
	if !healthy {
		t.Errorf("Health: want healthy after first flow, got false")
	}

	cancel()
	if err := <-done; err != nil {
		t.Errorf("Run: %v", err)
	}

	if pub.count() < 1 {
		t.Fatalf("publish count: got %d, want >= 1", pub.count())
	}
	msg := pub.snapshot()[0]
	if msg.subject != "olaitan.events.raw.network" {
		t.Errorf("publish subject: got %q, want olaitan.events.raw.network", msg.subject)
	}
	if msg.optsLen < 1 {
		t.Errorf("publish opts: got %d, want >= 1 (WithMsgID must be passed)", msg.optsLen)
	}
}

func TestRun_DialFailureMarksUnhealthy(t *testing.T) {
	stream := &stubStream{}
	pub := newStubPublisher()
	a := newAdapterWithStubs(t, stream, pub)
	dialAttempts := atomic.Int32{}
	a.dialFn = func(_ context.Context, _ string, _ *tls.Config) (*grpc.ClientConn, error) {
		dialAttempts.Add(1)
		return nil, errors.New("dial: connection refused")
	}
	// Tight retry so the test stays fast.
	a.cfg.ConnectRetry.Min = 1 * time.Millisecond
	a.cfg.ConnectRetry.Max = 5 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if dialAttempts.Load() >= 3 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	healthy, _ := a.Health().Status()
	if healthy {
		t.Errorf("Health: want unhealthy on persistent dial failure")
	}

	cancel()
	if err := <-done; err != nil {
		t.Errorf("Run: %v", err)
	}
}

func TestRun_UnauthenticatedIsTerminal(t *testing.T) {
	stream := &stubStream{}
	pub := newStubPublisher()
	a := newAdapterWithStubs(t, stream, pub)
	a.dialFn = func(_ context.Context, _ string, _ *tls.Config) (*grpc.ClientConn, error) {
		return nil, status.Error(codes.Unauthenticated, "client cert rejected")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := a.Run(ctx)
	if err == nil || !strings.Contains(err.Error(), "terminal") {
		t.Errorf("Run: got %v, want terminal connect error", err)
	}
}

func TestRun_MissingTLSFileIsTerminal(t *testing.T) {
	stream := &stubStream{}
	pub := newStubPublisher()
	a := newAdapterWithStubs(t, stream, pub)
	a.tlsLoaderFn = func() (*tls.Config, error) {
		return nil, &os.PathError{Op: "open", Path: "/nope", Err: os.ErrNotExist}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := a.Run(ctx)
	if err == nil || !strings.Contains(err.Error(), "terminal") {
		t.Errorf("Run: got %v, want terminal tls error", err)
	}
}

func TestRun_TopLevelPanic_MarksUnhealthy_DoesNotPropagate(t *testing.T) {
	stream := &stubStream{}
	pub := newStubPublisher()
	a := newAdapterWithStubs(t, stream, pub)
	a.dialFn = func(_ context.Context, _ string, _ *tls.Config) (*grpc.ClientConn, error) {
		panic("synthetic dial-side panic")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := a.Run(ctx)
	if err == nil || !strings.Contains(err.Error(), "panic") {
		t.Errorf("Run: got %v, want panic recovered as error", err)
	}
	healthy, lastErr := a.Health().Status()
	if healthy {
		t.Errorf("Health: want unhealthy after panic")
	}
	if lastErr == nil || !strings.Contains(lastErr.Error(), "panic") {
		t.Errorf("Health lastErr: got %v, want panic info", lastErr)
	}
}

func TestRun_TranslateError_IncrementsCounterContinues(t *testing.T) {
	// First flow: malformed (pre-2010 timestamp -> ErrInvalidTimestamp).
	bad := validFixture()
	bad.Flow.StartTime = 1
	good := validFixture()
	stream := &stubStream{queue: []*goldmanepb.FlowResult{bad, good}, blockAfterQueue: true}
	pub := newStubPublisher()
	a := newAdapterWithStubs(t, stream, pub)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if pub.count() >= 1 && a.TranslateErrors() >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	<-done

	if a.TranslateErrors() < 1 {
		t.Errorf("TranslateErrors: got %d, want >= 1", a.TranslateErrors())
	}
	if pub.count() < 1 {
		t.Errorf("publish count: got %d, want >= 1 (good flow should publish)", pub.count())
	}
}

func TestRun_OversizeFlow_IncrementsOversizeCounter(t *testing.T) {
	// Configure a tiny MaxEventBytes so any flow trips the cap.
	huge := validFixture()
	huge.Flow.Key.SourceName = strings.Repeat("x", 4000)
	stream := &stubStream{queue: []*goldmanepb.FlowResult{huge}, blockAfterQueue: true}
	pub := newStubPublisher()
	a := newAdapterWithStubs(t, stream, pub)
	a.cfg.MaxEventBytes = 4096

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if a.OversizeDropped() >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	<-done

	if a.OversizeDropped() < 1 {
		t.Errorf("OversizeDropped: got %d, want >= 1", a.OversizeDropped())
	}
	if pub.count() != 0 {
		t.Errorf("publish count: got %d, want 0 (oversize should drop)", pub.count())
	}
}

func TestRun_WatchdogQuietWhenReady_DoesNotFlipUnhealthy(t *testing.T) {
	// One fixture flow then a long pause from the stream (it
	// returns io.EOF, which causes a reconnect loop -- the
	// watchdog must NOT flip the source unhealthy across the
	// transient gap because connReady toggles).
	//
	// More directly: prove the watchdog does not flip unhealthy
	// when conn is Ready and staleness is exceeded.
	stream := &stubStream{queue: []*goldmanepb.FlowResult{validFixture()}}
	pub := newStubPublisher()
	a := newAdapterWithStubs(t, stream, pub)

	// Pin the lastEventTime to "long ago" and force connReady=true.
	long := time.Now().Add(-1 * time.Hour)
	a.lastEventTime.Store(&long)
	a.connReady.Store(true)

	// Run the watchdog tick directly.
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	a.runStalenessWatchdog(ctx)

	healthy, _ := a.Health().Status()
	if !healthy {
		// The initial state of a fresh Tracker is unhealthy with no
		// error; we want to assert the watchdog did NOT push an
		// unhealthy-because-stale state. Use the lastErr signal.
		_, lastErr := a.Health().Status()
		if lastErr != nil && strings.Contains(lastErr.Error(), "no flow for") {
			t.Errorf("watchdog flipped unhealthy even though connReady=true: %v", lastErr)
		}
	}
}

func TestRun_WatchdogStaleAndNotReady_FlipsUnhealthy(t *testing.T) {
	stream := &stubStream{}
	pub := newStubPublisher()
	a := newAdapterWithStubs(t, stream, pub)

	long := time.Now().Add(-1 * time.Hour)
	a.lastEventTime.Store(&long)
	a.connReady.Store(false)
	a.cfg.StalenessTimeout = 10 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	a.runStalenessWatchdog(ctx)

	healthy, lastErr := a.Health().Status()
	if healthy {
		t.Errorf("Health: want unhealthy when stale AND not ready")
	}
	if lastErr == nil || !strings.Contains(lastErr.Error(), "no flow for") {
		t.Errorf("lastErr: got %v, want 'no flow for' staleness message", lastErr)
	}
}

func TestRun_WatchdogNeverReceivedFlow_DoesNotFabricate(t *testing.T) {
	stream := &stubStream{}
	pub := newStubPublisher()
	a := newAdapterWithStubs(t, stream, pub)
	// lastEventTime is nil; do NOT store.
	a.connReady.Store(false)
	a.cfg.StalenessTimeout = 5 * time.Millisecond

	// The fresh Tracker is unhealthy with no error (zero value);
	// the watchdog must NOT overwrite that with a staleness error.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	a.runStalenessWatchdog(ctx)

	_, lastErr := a.Health().Status()
	if lastErr != nil && strings.Contains(lastErr.Error(), "no flow for") {
		t.Errorf("watchdog fabricated staleness for never-connected: %v", lastErr)
	}
}

func TestIsTerminalConnectError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"random transient", errors.New("dial tcp: i/o timeout"), false},
		{"unauthenticated", status.Error(codes.Unauthenticated, "cert rejected"), true},
		{"permission denied", status.Error(codes.PermissionDenied, "rbac"), true},
		{"unavailable", status.Error(codes.Unavailable, "no upstream"), false},
		{"fs perm", os.ErrPermission, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTerminalConnectError(tc.err); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIsTerminalTLSError(t *testing.T) {
	if !isTerminalTLSError(&os.PathError{Op: "open", Path: "/nope", Err: os.ErrNotExist}) {
		t.Errorf("file-not-exist: want terminal")
	}
	if !isTerminalTLSError(&os.PathError{Op: "open", Path: "/nope", Err: os.ErrPermission}) {
		t.Errorf("file-perm: want terminal")
	}
	if isTerminalTLSError(errors.New("ca bundle contained no parseable certificates")) {
		t.Errorf("half-written PEM: want transient")
	}
	if isTerminalTLSError(nil) {
		t.Errorf("nil: want non-terminal")
	}
}

func TestConnectivityCheckInterval(t *testing.T) {
	if connectivityCheckInterval(10*time.Minute) != 5*time.Minute {
		t.Errorf("10m -> 5m")
	}
	if connectivityCheckInterval(100*time.Millisecond) != 50*time.Millisecond {
		t.Errorf("100ms -> 50ms")
	}
	if connectivityCheckInterval(0) != 30*time.Second {
		t.Errorf("0 -> 30s fallback")
	}
}
