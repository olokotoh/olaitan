package cni

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
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

	"github.com/nats-io/nats.go"
	natsjs "github.com/nats-io/nats.go/jetstream"

	"github.com/olokotoh/olaitan/internal/collector/cni/goldmanepb"
	"github.com/olokotoh/olaitan/internal/schema"
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
	stg := int64(-60)
	cfg := Config{
		GoldmaneAddr:        "stub:7443",
		CABundlePath:        caPath,
		ClientCertPath:      certPath,
		ClientKeyPath:       keyPath,
		StalenessTimeout:    100 * time.Millisecond,
		AggregationInterval: 15,
		StartTimeGte:        &stg,
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
	if a.cfg.StartTimeGte == nil || *a.cfg.StartTimeGte != DefaultStartTimeGteReplay {
		t.Errorf("StartTimeGte default: got %v, want pointer to -60", a.cfg.StartTimeGte)
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
	// Story 1.12: EventsTotal must reflect the successful publish so
	// the Prometheus counter advances exactly once per successful
	// stream.Recv+publish cycle.
	if got := a.EventsTotal(); got != 1 {
		t.Errorf("EventsTotal: got %d, want 1", got)
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

	healthy, lastErr := a.Health().Status()
	if !healthy && lastErr != nil && strings.Contains(lastErr.Error(), "no flow for") {
		// The initial state of a fresh Tracker is unhealthy with no
		// error; we want to assert the watchdog did NOT push an
		// unhealthy-because-stale state.
		t.Errorf("watchdog flipped unhealthy even though connReady=true: %v", lastErr)
	}
}

func TestRun_WatchdogStaleWithStreamOpen_FlipsUnhealthy(t *testing.T) {
	// Story 1.10 D1 (code-review patch P25): the gating signal is
	// streamOpen, not connReady. (streamOpen=true && lastEventTime
	// stale) is the actionable case: the stream is up at the gRPC
	// layer but Goldmane went silent after previously sending flows.
	stream := &stubStream{}
	pub := newStubPublisher()
	a := newAdapterWithStubs(t, stream, pub)

	long := time.Now().Add(-1 * time.Hour)
	a.lastEventTime.Store(&long)
	a.streamOpen.Store(true)
	a.cfg.StalenessTimeout = 10 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	a.runStalenessWatchdog(ctx)

	healthy, lastErr := a.Health().Status()
	if healthy {
		t.Errorf("Health: want unhealthy when streamOpen=true AND lastEventTime stale")
	}
	if lastErr == nil || !strings.Contains(lastErr.Error(), "no flow for") {
		t.Errorf("lastErr: got %v, want 'no flow for' staleness message", lastErr)
	}
}

func TestRun_WatchdogStaleButStreamNotOpen_DoesNotFlipUnhealthy(t *testing.T) {
	// Story 1.10 D1 (code-review patch P25): when streamOpen=false
	// the connect loop owns the operator signal; watchdog stays
	// silent regardless of lastEventTime staleness. Reconnects
	// must not double-flag the same outage.
	stream := &stubStream{}
	pub := newStubPublisher()
	a := newAdapterWithStubs(t, stream, pub)

	long := time.Now().Add(-1 * time.Hour)
	a.lastEventTime.Store(&long)
	a.streamOpen.Store(false)
	a.cfg.StalenessTimeout = 10 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	a.runStalenessWatchdog(ctx)

	_, lastErr := a.Health().Status()
	if lastErr != nil && strings.Contains(lastErr.Error(), "no flow for") {
		t.Errorf("watchdog flipped unhealthy on streamOpen=false reconnect path: %v", lastErr)
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

// TestNew_AggregationIntervalNon15_Rejected locks in the P32 fix:
// any non-15 AggregationInterval (other than 0, which defaults to
// 15) is rejected at New time per Goldmane proto contract line 100.
func TestNew_AggregationIntervalNon15_Rejected(t *testing.T) {
	pub := newStubPublisher()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, err := New(Config{
		CABundlePath:        "ca",
		ClientCertPath:      "c",
		ClientKeyPath:       "k",
		AggregationInterval: 30,
	}, pub, log)
	if err == nil {
		t.Fatalf("got nil, want aggregation-interval error")
	}
	if !strings.Contains(err.Error(), "must be 15s per Goldmane proto") {
		t.Errorf("err missing proto-contract message: %v", err)
	}
}

// TestNew_StartTimeGtePositive_Rejected locks in the P31 fix:
// a positive StartTimeGte against a streaming RPC is meaningless
// (it would request a future-only stream) and is rejected.
func TestNew_StartTimeGtePositive_Rejected(t *testing.T) {
	pub := newStubPublisher()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	positive := int64(60)
	_, err := New(Config{
		CABundlePath:        "ca",
		ClientCertPath:      "c",
		ClientKeyPath:       "k",
		AggregationInterval: 15,
		StartTimeGte:        &positive,
	}, pub, log)
	if err == nil {
		t.Fatalf("got nil, want start_time_gte error")
	}
	if !strings.Contains(err.Error(), "must be <= 0") {
		t.Errorf("err missing constraint message: %v", err)
	}
}

// TestNew_StartTimeGteExplicitZero_Preserved locks in the P31
// fix: an explicit 0 reaches Goldmane unchanged (per proto line
// 91: "A value of zero means 'now'").
func TestNew_StartTimeGteExplicitZero_Preserved(t *testing.T) {
	pub := newStubPublisher()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	zero := int64(0)
	a, err := New(Config{
		CABundlePath:        "ca",
		ClientCertPath:      "c",
		ClientKeyPath:       "k",
		AggregationInterval: 15,
		StartTimeGte:        &zero,
	}, pub, log)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.cfg.StartTimeGte == nil || *a.cfg.StartTimeGte != 0 {
		t.Errorf("StartTimeGte: got %v, want pointer to 0", a.cfg.StartTimeGte)
	}
}

// TestNew_StartTimeGteOmitted_DefaultsToReplay locks in the P31
// fix: omission (nil) defaults to DefaultStartTimeGteReplay (-60).
func TestNew_StartTimeGteOmitted_DefaultsToReplay(t *testing.T) {
	pub := newStubPublisher()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, err := New(Config{
		CABundlePath:        "ca",
		ClientCertPath:      "c",
		ClientKeyPath:       "k",
		AggregationInterval: 15,
	}, pub, log)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.cfg.StartTimeGte == nil || *a.cfg.StartTimeGte != DefaultStartTimeGteReplay {
		t.Errorf("StartTimeGte: got %v, want pointer to %d (DefaultStartTimeGteReplay)", a.cfg.StartTimeGte, DefaultStartTimeGteReplay)
	}
}

// TestIsTerminalTLSError_TypedClassifier locks in the P35 fix:
// the typed errors.As path replaces the substring fallback that
// the original code carried. Three sentinel cases exercise the
// tls.RecordHeaderError, x509.UnknownAuthorityError, and
// x509.CertificateInvalidError branches.
func TestIsTerminalTLSError_TypedClassifier(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"missing-file", &os.PathError{Op: "open", Path: "/x", Err: os.ErrNotExist}, true},
		{"perm-denied", &os.PathError{Op: "open", Path: "/x", Err: os.ErrPermission}, true},
		{"ca-bundle-unparseable", errCABundleUnparseable, true},
		{"ca-bundle-unparseable-wrapped", fmt.Errorf("ca bundle: %w", errCABundleUnparseable), true},
		{"tls record-header", tls.RecordHeaderError{Msg: "bad cert"}, true},
		{"tls record-header wrapped", fmt.Errorf("dial: %w", tls.RecordHeaderError{}), true},
		{"x509 unknown-authority", x509.UnknownAuthorityError{}, true},
		{"x509 cert-invalid", x509.CertificateInvalidError{Reason: x509.NotAuthorizedToSign}, true},
		{"half-written-pem msg (transient)", errors.New("ca bundle contained no parseable certificates"), false},
		{"generic transient", errors.New("dial tcp i/o timeout"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTerminalTLSError(tc.err); got != tc.want {
				t.Errorf("got %v, want %v (err=%v)", got, tc.want, tc.err)
			}
		})
	}
}

// TestIsTerminalConnectError_PermissionDeniedSubstring locks in
// the P36 fix: the falco-precedent "permission denied" substring
// fallback runs AFTER the typed checks and promotes string-only
// transport errors to terminal.
func TestIsTerminalConnectError_PermissionDeniedSubstring(t *testing.T) {
	err := status.Error(codes.Unavailable, "transport: connection refused: permission denied")
	if !isTerminalConnectError(err) {
		t.Errorf("got false, want true for unix-socket EACCES wrapped as Unavailable with 'permission denied' substring")
	}
}

// TestPublishWithRetry_PerAttemptDeadline_DoesNotCollapseBudget
// locks in the P17 fix: a per-attempt context.DeadlineExceeded
// while the outer ctx is alive must surface as a transient error
// so retry.Do honours MaxAttempts.
func TestPublishWithRetry_PerAttemptDeadline_DoesNotCollapseBudget(t *testing.T) {
	stream := &stubStream{}
	pub := newStubPublisher()
	a := newAdapterWithStubs(t, stream, pub)

	// Substitute the publisher with one that returns
	// context.DeadlineExceeded for the first two attempts then
	// succeeds. retry.Permanent shows up only if the strategy
	// short-circuits MaxAttempts due to ctx-cancelled propagation.
	calls := atomic.Int32{}
	failPub := &failingPublisher{
		failN: 2,
		calls: &calls,
		err:   context.DeadlineExceeded,
	}
	a.pub = failPub
	a.cfg.PublishRetry.Min = 1 * time.Millisecond
	a.cfg.PublishRetry.Max = 5 * time.Millisecond
	a.cfg.PublishRetry.MaxAttempts = 3

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ev := goldmaneFlowToTestEvent(t, validFixture())
	err := a.publishWithRetry(ctx, ev)
	if err != nil {
		t.Errorf("publishWithRetry: got %v, want nil after 2 fails + 1 success", err)
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("publish attempts: got %d, want 3 (proves per-attempt deadlines did not collapse the budget)", got)
	}
}

// TestRun_ConnReadyDeferredUntilFirstRecv locks in the P18 fix:
// connReady stays false until the first successful Recv arrives.
// We exercise this by running with a stream that blocks Recv;
// the watchdog must see connReady=false.
func TestRun_ConnReadyDeferredUntilFirstRecv(t *testing.T) {
	stream := &stubStream{blockAfterQueue: true} // empty queue, will block on Recv
	pub := newStubPublisher()
	a := newAdapterWithStubs(t, stream, pub)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	// Give the adapter a moment to dial and enter the Recv loop.
	time.Sleep(200 * time.Millisecond)

	// connReady must still be false because Recv has not yet
	// returned a flow.
	if a.connReady.Load() {
		t.Errorf("connReady prematurely true before first Recv")
	}

	cancel()
	<-done
}

// TestRun_LastEventTime_UpdatedOnRecvSuccess locks in the Story
// 1.10 P13 semantic: lastEventTime tracks UPSTREAM bus liveness
// (Goldmane → adapter via stream.Recv), not downstream publish
// throughput. A publish-drop must NOT reset lastEventTime back to
// nil — Goldmane sent us a flow, so the upstream is alive. Publish
// failures surface separately via publishDrops + MarkUnhealthy.
//
// This replaces the P19 semantic (lastEventTime advances only on
// publish success); see Review Findings in the Story 1.10 spec.
func TestRun_LastEventTime_UpdatedOnRecvSuccess(t *testing.T) {
	stream := &stubStream{queue: []*goldmanepb.FlowResult{validFixture()}, blockAfterQueue: true}
	pub := newStubPublisher()
	pub.failOn[0] = nats.ErrMaxPayload // permanent error -> publish-drop
	a := newAdapterWithStubs(t, stream, pub)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if a.PublishDrops() >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if got := a.lastEventTime.Load(); got == nil {
		t.Errorf("lastEventTime is nil after a successful Recv (P13: bus liveness must register regardless of publish outcome)")
	}

	cancel()
	<-done
}

// TestLoadTLSConfigFromDisk_CABundleNotPEM_Terminal locks in the
// P22 fix: a ca_bundle file with no PEM block at all (operator
// typo, e.g. caBundle: "foo") surfaces errCABundleUnparseable so
// isTerminalTLSError flips the failure to terminal.
func TestLoadTLSConfigFromDisk_CABundleNotPEM_Terminal(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, []byte("foo"), 0o644); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	// loadTLSConfigFromDisk also requires client cert/key paths;
	// supply real ones so the CA path is reached.
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	for _, p := range []string{certPath, keyPath} {
		if err := os.WriteFile(p, []byte("placeholder"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	a := &Adapter{cfg: Config{
		CABundlePath:   caPath,
		ClientCertPath: certPath,
		ClientKeyPath:  keyPath,
		ServerName:     "test",
	}}
	_, err := a.loadTLSConfigFromDisk()
	if err == nil {
		t.Fatal("expected error on non-PEM ca bundle")
	}
	if !errors.Is(err, errCABundleUnparseable) {
		t.Errorf("err is not errCABundleUnparseable: %v", err)
	}
	if !isTerminalTLSError(err) {
		t.Errorf("isTerminalTLSError: got false, want true for non-PEM ca bundle")
	}
}

// failingPublisher fails the first failN calls with err then
// succeeds for the rest. Used to exercise P17's per-attempt
// deadline distinction without spinning up a real stalled NATS
// partition.
type failingPublisher struct {
	failN int
	calls *atomic.Int32
	err   error
}

func (f *failingPublisher) PublishJS(_ context.Context, _ string, _ any, _ ...natsjs.PublishOpt) (*natsjs.PubAck, error) {
	n := f.calls.Add(1)
	if int(n) <= f.failN {
		return nil, f.err
	}
	return &natsjs.PubAck{Stream: "EVENTS_RAW", Sequence: uint64(n)}, nil
}

// goldmaneFlowToTestEvent converts a fixture FlowResult to a
// schema.Event via the production Translate path so the
// publishWithRetry test exercises a realistic event payload.
func goldmaneFlowToTestEvent(t *testing.T, fr *goldmanepb.FlowResult) schema.Event {
	t.Helper()
	ev, err := Translate(fr, "test-node", 0)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	return ev
}
