package cri

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/nats-io/nats.go"
	natsjs "github.com/nats-io/nats.go/jetstream"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"

	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/retry"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/sourcehealth"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// natsPublisher is the minimal NATS surface the adapter consumes.
// Mirrors internal/collector/falco and internal/collector/audit so a
// future SourceAdapter interface extraction has consistent surface
// area across all three concrete adapters.
type natsPublisher interface {
	PublishJS(ctx context.Context, subject string, data any, opts ...natsjs.PublishOpt) (*natsjs.PubAck, error)
}

// HealthReader aliases sourcehealth.Reader so callers in this
// package's namespace can speak the local name. The canonical
// interface is sourcehealth.Reader and is what Adapter.Health
// returns.
type HealthReader = sourcehealth.Reader

// runtimeClient is the narrow CRI surface the adapter consumes. The
// production type is k8s.io/cri-api's RuntimeServiceClient; declaring
// the interface locally lets tests inject a stub without dragging in
// the full upstream interface (which has dozens of methods we never
// call). The signature matches RuntimeServiceClient.GetContainerEvents
// so the production constructor can be assigned directly via the
// adapter's newClientFn test seam.
type runtimeClient interface {
	GetContainerEvents(ctx context.Context, in *runtimeapi.GetEventsRequest, opts ...grpc.CallOption) (runtimeapi.RuntimeService_GetContainerEventsClient, error)
}

// Config holds the runtime knobs for an Adapter. The shape mirrors
// falco.Config and audit.Config so a future SourceAdapter interface
// extraction has consistent surface area.
type Config struct {
	// SocketPath is the host-side path to the containerd CRI Unix
	// domain socket. Production default "/run/containerd/containerd.sock"
	// matches stock containerd 1.7 on a kubeadm cluster.
	SocketPath string

	// Hostname is the node-level identifier the adapter records on
	// every emitted Event.Pod.Node. The collector subcommand reads
	// K8S_NODE_NAME from the downward API and passes it here.
	Hostname string

	// DialTimeout caps the wait for the gRPC client to reach the
	// connectivity.Ready state before the connect attempt is treated
	// as a failure and the outer retry strategy backs off. Defaults
	// to 10s when zero-valued.
	DialTimeout time.Duration

	// ConnectRetry is the outer connect-loop backoff strategy used
	// when a dial or stream-open call fails or the stream tears down.
	// Defaults to DefaultConnectRetry() when zero-valued.
	ConnectRetry retry.Strategy

	// PublishRetry is the bounded inner retry for transient NATS
	// publish failures. Defaults to DefaultPublishRetry() when
	// zero-valued.
	PublishRetry retry.Strategy

	// StalenessTimeout is the staleness watchdog's threshold. CRI
	// lifecycle events are quiet by design: a stable cluster with no
	// Pod churn can go hours without an event. The watchdog only
	// flips MarkUnhealthy when staleness AND a non-Ready connection
	// state coincide -- "no events" alone never trips it. Defaults
	// to 5m when zero-valued.
	StalenessTimeout time.Duration
}

// DefaultConnectRetry returns the outer connect-loop backoff strategy
// used by the agent in production. 1s..30s with full equal-jitter and
// unlimited attempts is the right shape for a long-lived DaemonSet
// adapter: quick first reconnect, capped escalation while containerd
// restarts, and never a permanent give-up that would leave the source
// silently dead.
func DefaultConnectRetry() retry.Strategy {
	return retry.Strategy{
		Min:         1 * time.Second,
		Max:         30 * time.Second,
		Multiplier:  2.0,
		Jitter:      0.5,
		MaxAttempts: 0,
	}
}

// DefaultPublishRetry returns the per-publish bounded retry strategy.
// 100ms..1s, 3 attempts, low equal-jitter (0.1) -- combined with the
// per-attempt 2s deadline this caps total transient backoff at ~9s
// before the stream loop logs+drops and continues. The 0.1 jitter
// matches the config/olaitan.yaml default for
// detection.sources.containerd.publish_retry so the rendered runtime
// behaviour matches the code default; tuning either knob in isolation
// would silently desync the two. (Story 1.7 patch P29 precedent.)
func DefaultPublishRetry() retry.Strategy {
	return retry.Strategy{
		Min:         100 * time.Millisecond,
		Max:         1 * time.Second,
		Multiplier:  2.0,
		Jitter:      0.1,
		MaxAttempts: 3,
	}
}

// publishAttemptTimeout caps a single PublishJS attempt. JetStream's
// default publish-ack-wait is ~5s; without a per-attempt deadline a
// stalled NATS partition can stall a single PublishJS for ~5s before
// retry 2 starts. Mirrors falco.publishAttemptTimeout exactly.
const publishAttemptTimeout = 2 * time.Second

// connectivityCheckInterval is the watchdog's tick period. The
// watchdog reads the gRPC connection state, the last-event timestamp,
// and the configured StalenessTimeout to decide whether to
// MarkUnhealthy. Returns half the configured staleness timeout, with
// a 30s fallback applied ONLY when staleness is non-positive (zero or
// negative) -- a short staleness like 1s in tests therefore yields a
// 500ms tick, not a 30s tick. Production callers always set staleness
// well above the fallback threshold, so the floor never fires there.
func connectivityCheckInterval(staleness time.Duration) time.Duration {
	period := staleness / 2
	if period <= 0 {
		period = 30 * time.Second
	}
	return period
}

// Adapter is the containerd CRI lifecycle adapter. Construct with New;
// run the per-instance goroutine via Run; observe health via Health.
type Adapter struct {
	cfg    Config
	pub    natsPublisher
	log    *slog.Logger
	health sourcehealth.Tracker

	// lastEventTime is the wall-clock baseline of the most recent
	// successful Translate. Stored as *time.Time (atomic) so the
	// monotonic clock reading is preserved across reads -- a forward
	// NTP step would falsely trip the staleness watchdog if we used a
	// stripped Unix-nanosecond representation. Read by the staleness
	// watchdog; nil means "no event ever received".
	lastEventTime atomic.Pointer[time.Time]

	// connState is the current gRPC connection state, updated by the
	// stream loop on connect-success / connect-failure transitions.
	// The watchdog reads it to decide whether staleness is actionable
	// (true=Ready; staleness alone is not actionable when Ready).
	// Stored as atomic.Bool because the only states the watchdog
	// distinguishes are "Ready" vs "not Ready".
	connReady atomic.Bool

	// translateErrors is incremented every time Translate returns an
	// error and the stream loop log+drops the event. Story 1.12 will
	// bind this to a Prometheus counter via Adapter.TranslateErrors().
	translateErrors atomic.Int64

	// publishDrops is incremented every time publishWithRetry returns
	// a permanent error (oversize event, etc) and the stream loop
	// log+drops. Story 1.12 will bind this to a Prometheus counter.
	publishDrops atomic.Int64

	// eventsPublished is the Story 1.12 Prometheus reader-side counter,
	// incremented per successful publishWithRetry. Exposed via
	// EventsTotal as the int64 snapshot.
	eventsPublished atomic.Int64

	// dialFn is a test seam: the production grpc.NewClient cannot be
	// pointed at a bufconn dialer through public API alone. Tests
	// override this; production callers leave it nil and defaultDial
	// is used. The signature mirrors falco's adapter.
	dialFn func(ctx context.Context, target string) (*grpc.ClientConn, error)

	// newClientFn is the gRPC client-stub constructor. Production
	// uses runtimeapi.NewRuntimeServiceClient; tests inject a hand-
	// rolled stub via newClientFn so a fully in-process unit test
	// (without bufconn) can exercise the stream loop.
	newClientFn func(*grpc.ClientConn) runtimeClient

	// nowFn is a test seam for time-dependent assertions in
	// staleness-watchdog tests.
	nowFn func() time.Time
}

// New constructs an Adapter. nc and log are required; cfg is
// validated. nc may be a *natsclient.Client or any natsPublisher-
// satisfying type (for tests).
func New(cfg Config, nc natsPublisher, log *slog.Logger) (*Adapter, error) {
	if nc == nil {
		return nil, errors.New("cri: new: nats publisher is nil")
	}
	if log == nil {
		log = slog.Default()
	}
	if cfg.SocketPath == "" {
		return nil, errors.New("cri: new: config.SocketPath is empty")
	}
	if cfg.Hostname == "" {
		return nil, errors.New("cri: new: config.Hostname is empty")
	}
	if cfg.DialTimeout < 0 {
		return nil, fmt.Errorf("cri: new: dial timeout must be >= 0 (0 means default; got %s)", cfg.DialTimeout)
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	if cfg.StalenessTimeout < 0 {
		return nil, fmt.Errorf("cri: new: staleness timeout must be >= 0 (0 means default; got %s)", cfg.StalenessTimeout)
	}
	if cfg.StalenessTimeout == 0 {
		cfg.StalenessTimeout = 5 * time.Minute
	}
	if cfg.ConnectRetry.IsZero() {
		cfg.ConnectRetry = DefaultConnectRetry()
	}
	if err := cfg.ConnectRetry.Validate(); err != nil {
		return nil, fmt.Errorf("cri: new: connect retry: %w", err)
	}
	if cfg.PublishRetry.IsZero() {
		cfg.PublishRetry = DefaultPublishRetry()
	}
	if err := cfg.PublishRetry.Validate(); err != nil {
		return nil, fmt.Errorf("cri: new: publish retry: %w", err)
	}
	return &Adapter{
		cfg:         cfg,
		pub:         nc,
		log:         log,
		dialFn:      defaultDial,
		newClientFn: defaultNewClient,
		nowFn:       time.Now,
	}, nil
}

// Health returns the read-only source-health view. Story 1.12 binds
// this to the Prometheus gauge `source_healthy{source="runtime"}`
// (FR8). Returning the narrow sourcehealth.Reader interface (rather
// than the concrete *sourcehealth.Tracker) prevents callers outside
// this package from reaching the mutator methods.
func (a *Adapter) Health() sourcehealth.Reader {
	return &a.health
}

// TranslateErrors returns the cumulative count of events that failed
// translation and were log+dropped. Exposed for Story 1.12's
// Prometheus surface; callers expecting a stable counter across
// process lifetime must accept this is process-local (no persistent
// store).
func (a *Adapter) TranslateErrors() int64 { return a.translateErrors.Load() }

// PublishDrops returns the cumulative count of events whose publish
// attempt returned a permanent error (e.g. oversize). Exposed for
// Story 1.12's Prometheus surface.
func (a *Adapter) PublishDrops() int64 { return a.publishDrops.Load() }

// EventsTotal returns the cumulative count of CRI lifecycle events
// successfully published to subjects.RawRuntime. Story 1.12 binds this
// via prometheus.NewCounterFunc to olaitan_sensor_events_total{source="runtime"}.
func (a *Adapter) EventsTotal() int64 { return a.eventsPublished.Load() }

// Run blocks until ctx is cancelled. The connect-loop retry strategy
// supplied via Config governs reconnect cadence on containerd
// unavailability; it never returns to the caller on a transient
// error, only on ctx-driven cancellation. A non-transient
// configuration failure is surfaced immediately as a non-nil error.
func (a *Adapter) Run(ctx context.Context) error {
	a.log.Info("cri: adapter starting",
		"socket_path", a.cfg.SocketPath,
		"hostname", a.cfg.Hostname,
		"staleness_timeout", a.cfg.StalenessTimeout)
	defer a.log.Info("cri: adapter stopped")

	// Mark unhealthy at startup until the first successful Recv flips
	// it. Mirrors the audit adapter's startup contract.
	a.health.MarkUnhealthy(errors.New("cri: awaiting first event"))

	// Watchdog goroutine. Cancelled when Run returns.
	wdCtx, wdCancel := context.WithCancel(ctx)
	defer wdCancel()
	watchdogDone := make(chan struct{})
	go func() {
		defer close(watchdogDone)
		a.runStalenessWatchdog(wdCtx)
	}()

	err := a.cfg.ConnectRetry.Do(ctx, func(ctx context.Context) error {
		return a.connectAndConsume(ctx)
	})
	wdCancel()
	<-watchdogDone

	// Retry.Do returns ctx.Err() (wrapped) on cancellation, which we
	// treat as clean shutdown rather than an error.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	return err
}

// connectAndConsume runs one dial-stream-consume iteration. Returns a
// transient error when the stream tears down so the outer Retry.Do
// can re-enter; returns ctx.Err() (or a retry.Permanent wrap) to
// signal a terminal condition that should propagate out of Run.
func (a *Adapter) connectAndConsume(ctx context.Context) error {
	target := criDialTarget(a.cfg.SocketPath)

	dialCtx, cancel := context.WithTimeout(ctx, a.cfg.DialTimeout)
	defer cancel()
	cc, err := a.dialFn(dialCtx, target)
	if err != nil {
		a.connReady.Store(false)
		a.health.MarkUnhealthy(err)
		if isTerminalConnectError(err) {
			return retry.Permanent(fmt.Errorf("cri: dial %q (terminal, no retry): %w", target, err))
		}
		return fmt.Errorf("cri: dial %q: %w", target, err)
	}
	defer func() {
		a.connReady.Store(false)
		if cerr := cc.Close(); cerr != nil {
			a.log.Warn("cri: grpc conn close", "err", cerr)
		}
	}()

	client := a.newClientFn(cc)
	stream, err := client.GetContainerEvents(ctx, &runtimeapi.GetEventsRequest{})
	if err != nil {
		a.health.MarkUnhealthy(err)
		if isTerminalConnectError(err) {
			return retry.Permanent(fmt.Errorf("cri: get-container-events (terminal, no retry): %w", err))
		}
		return fmt.Errorf("cri: get-container-events: %w", err)
	}

	// Connection-readiness flips true once we have an open stream.
	// MarkHealthy is deferred to the first successful Recv so the
	// gauge reflects observed traffic rather than the lazy gRPC
	// connection's optimism.
	a.connReady.Store(true)
	firstEvent := true

	for {
		ev, err := stream.Recv()
		if err != nil {
			a.connReady.Store(false)
			// Clean shutdown: gRPC wraps a cancelled context as a
			// status error with codes.Canceled, which errors.Is does
			// NOT recognise as context.Canceled (grpc-go #6862).
			// Check ctx.Err and the gRPC status code so SIGTERM does
			// not look like a transient transport fault in logs.
			if ctx.Err() != nil || status.Code(err) == codes.Canceled {
				return ctx.Err()
			}
			if errors.Is(err, io.EOF) {
				a.health.MarkUnhealthy(io.EOF)
				return fmt.Errorf("cri: stream eof")
			}
			a.health.MarkUnhealthy(err)
			if isTerminalConnectError(err) {
				return retry.Permanent(fmt.Errorf("cri: stream recv (terminal, no retry): %w", err))
			}
			return fmt.Errorf("cri: stream recv: %w", err)
		}

		if firstEvent {
			a.health.MarkHealthy()
			a.log.Info("cri: stream connected", "socket_path", a.cfg.SocketPath)
			firstEvent = false
		}

		schemaEv, terr := Translate(ev, a.cfg.Hostname)
		if terr != nil {
			a.translateErrors.Add(1)
			a.log.Warn("cri: translate skipped malformed event",
				"err", terr,
				"container_id", ev.GetContainerId())
			continue
		}

		// Record the wall-clock time of the most recent successful
		// translate so the staleness watchdog can decide actionability.
		// Storing *time.Time (rather than UnixNano) preserves monotonic
		// clock reading so a forward NTP step does not trip the
		// watchdog instantly.
		now := a.nowFn()
		a.lastEventTime.Store(&now)

		if perr := a.publishWithRetry(ctx, schemaEv); perr != nil {
			if isPermanentPublishError(perr) {
				// Per-event terminal failure (oversize, malformed
				// envelope). Tearing down the stream and re-dialling
				// would just have containerd re-emit the same event
				// from its buffer (containerd does not re-emit
				// retroactive lifecycle events; this branch is the
				// safety net for a future stream that does). Stay on
				// the live stream.
				a.publishDrops.Add(1)
				a.log.Error("cri: publish dropped (permanent, per-event)",
					"err", perr,
					"event_id", schemaEv.ID,
					"summary_bytes", len(schemaEv.Summary))
				continue
			}
			// Persistent transient publish failure: tear the stream
			// so the outer dial loop re-enters. CRI events are
			// non-replayable from containerd's side, so this branch
			// loses the in-flight event; the at-least-once contract
			// holds across the transient-recovery window via
			// WithMsgID dedup, so successful in-flight retries are
			// not double-published when the stream resumes.
			a.health.MarkUnhealthy(perr)
			return fmt.Errorf("cri: publish: %w", perr)
		}
		a.eventsPublished.Add(1)
	}
}

// publishWithRetry attempts to publish ev to subjects.RawRuntime with
// bounded retry. Each attempt is wrapped in a 2s per-attempt deadline
// (publishAttemptTimeout) so a single PublishJS cannot stall past the
// strategy's between-attempts cap. ev.ID is forwarded as the
// JetStream Nats-Msg-Id header so a retry the server already
// persisted on a previous attempt is server-side deduplicated within
// the stream's 2-minute dedup window.
func (a *Adapter) publishWithRetry(ctx context.Context, ev schema.Event) error {
	return a.cfg.PublishRetry.Do(ctx, func(ctx context.Context) error {
		attemptCtx, cancel := context.WithTimeout(ctx, publishAttemptTimeout)
		defer cancel()
		_, err := a.pub.PublishJS(attemptCtx, subjects.RawRuntime, ev,
			natsjs.WithMsgID(ev.ID))
		if err == nil {
			return nil
		}
		if isPermanentPublishError(err) {
			return retry.Permanent(err)
		}
		return err
	})
}

// runStalenessWatchdog periodically checks whether the time since the
// last successful event exceeds StalenessTimeout AND the connection
// is not Ready. The "AND not Ready" gate is the critical design
// difference from Stories 1.6 (Falco) and 1.7 (audit): CRI lifecycle
// events are quiet by design, so staleness alone is uninformative.
//
// MarkUnhealthy is always overwritten when the staleness condition
// trips. The Story 1.7 P8 "only-if-healthy" precheck was advisory and
// race-prone (the stream loop's MarkHealthy can land between the
// watchdog's Status read and MarkUnhealthy write, clobbering fresh-
// good with stale-bad); reverting to the watchdog's documented always-
// overwrite behaviour is the simpler correct shape. Backward clock
// jumps (negative Sub) are treated as "not stale" so a transient NTP
// step does not falsely flip the source; forward jumps are similarly
// tolerated because lastEventTime preserves the monotonic clock
// reading.
//
// Panics inside this goroutine are caught and surfaced via
// MarkUnhealthy rather than crashing the agent process: a clock-
// dependency or nil-pointer regression should degrade the source, not
// take the whole DaemonSet pod down.
//
// Returns when ctx is cancelled.
func (a *Adapter) runStalenessWatchdog(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			a.health.MarkUnhealthy(fmt.Errorf("cri: watchdog panic: %v", r))
		}
	}()
	period := connectivityCheckInterval(a.cfg.StalenessTimeout)
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			lastPtr := a.lastEventTime.Load()
			if lastPtr == nil {
				// Never received an event. The startup MarkUnhealthy
				// is authoritative until the first successful Recv
				// flips it. Don't fabricate a staleness event.
				continue
			}
			if a.connReady.Load() {
				// Connection is Ready: by-design quiet stretches do
				// not flip unhealthy. This is the load-bearing
				// design-difference test
				// TestRun_StalenessWatchdog_QuietButConnected_DoesNotFlipUnhealthy.
				continue
			}
			// time.Since uses the stored monotonic reading when
			// available, so a forward NTP step that bumps wall clock
			// without elapsing actual time does not trip the watchdog.
			delta := a.nowFn().Sub(*lastPtr)
			if delta < 0 {
				// Backward clock jump (NTP step). Treat as fresh.
				continue
			}
			if delta <= a.cfg.StalenessTimeout {
				continue
			}
			a.health.MarkUnhealthy(fmt.Errorf("cri: no event for %s and connection not Ready", a.cfg.StalenessTimeout))
		}
	}
}

// criDialTarget returns the gRPC target string for a containerd CRI
// Unix socket path. The "unix://" scheme is required by grpc.NewClient
// for Unix domain sockets.
func criDialTarget(socketPath string) string {
	if strings.HasPrefix(socketPath, "unix://") || strings.HasPrefix(socketPath, "passthrough:") {
		return socketPath
	}
	return "unix://" + socketPath
}

// defaultDial dials target with insecure transport credentials and
// blocks (bounded by dialCtx) until the connection reaches
// connectivity.Ready. CRI uses a Unix domain socket protected by
// file-system permissions; mTLS does not apply (the remote is not
// network-reachable). The agent's pod-spec security context limits
// exposure: the host-socket mount is the privilege boundary, not the
// gRPC handshake.
//
// grpc.NewClient is intentionally lazy in modern grpc-go (>= 1.63):
// it does not connect until the first RPC. Without an explicit
// readiness wait the configured DialTimeout would be cosmetic and a
// wrong/missing socket would surface only as a stream error several
// seconds later, leaving the watchdog's "stale AND not Ready" gate to
// keep the source falsely healthy in the meantime. We therefore call
// cc.Connect to exit Idle and loop on cc.WaitForStateChange until the
// state reaches Ready (success), TransientFailure or Shutdown
// (terminal for this attempt), or dialCtx is done. On timeout the
// connection is closed and a wrapped error is returned to the outer
// retry loop. (grpc-go anti-patterns documentation, 2026.)
func defaultDial(dialCtx context.Context, target string) (*grpc.ClientConn, error) {
	cc, err := grpc.NewClient(
		target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, err
	}
	cc.Connect()
	for {
		state := cc.GetState()
		if state == connectivity.Ready {
			return cc, nil
		}
		if !cc.WaitForStateChange(dialCtx, state) {
			// dialCtx done before the state changed.
			_ = cc.Close()
			if cerr := dialCtx.Err(); cerr != nil {
				return nil, fmt.Errorf("dial wait-for-ready: %w", cerr)
			}
			return nil, fmt.Errorf("dial wait-for-ready: state=%s", state)
		}
	}
}

// defaultNewClient is the production constructor for the CRI
// RuntimeServiceClient. The local interface narrowing
// (runtimeClient) means tests can supply a stub without depending on
// the upstream interface's full surface area.
func defaultNewClient(cc *grpc.ClientConn) runtimeClient {
	return runtimeapi.NewRuntimeServiceClient(cc)
}

// isTerminalConnectError returns true when err represents a permanent
// configuration mistake that cannot be fixed by retrying:
//
//   - fs.ErrPermission: EACCES on the CRI Unix socket. The pod will
//     keep getting denied until an operator fixes the socket's
//     permissions or the container's UID/GID.
//   - gRPC codes.Unauthenticated: Auth failure (rare on a Unix socket
//     but defended for completeness).
//   - gRPC codes.PermissionDenied: server-side authorization denial.
//   - gRPC codes.ResourceExhausted: containerd's CRI rate-limiter
//     refused the connection. Treating this as permanent escalates
//     into the outer connect-loop's longer backoff rather than a
//     reconnect storm against a server that is asking us to back off.
//
// Mirrors falco.isTerminalConnectError. Detection is purely typed --
// a "permission denied" substring fallback is intentionally NOT
// included because gRPC error message text is not stable surface
// (locale-/version-fragile).
func isTerminalConnectError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, fs.ErrPermission) {
		return true
	}
	switch status.Code(err) {
	case codes.Unauthenticated, codes.PermissionDenied, codes.ResourceExhausted:
		return true
	}
	return false
}

// isPermanentPublishError reports whether err from a JetStream
// PublishJS call is a per-message terminal condition (the message
// itself violates a stream-level invariant or the cluster is in a
// shape where retrying will not succeed) rather than a transient
// transport hiccup. Caller is expected to log+drop the offending
// event and continue.
//
// Detection layers (in order, all typed -- no substring fallback):
//  1. errors.Is(err, nats.ErrMaxPayload) -- typed client-side
//     oversize cap.
//  2. errors.Is(err, nats.ErrNoResponders) -- no JetStream subscriber
//     answered the publish (subject has no bound stream). An
//     infinite reconnect loop would lose every event for the lifetime
//     of the misconfiguration; drop loudly instead.
//  3. errors.Is(err, natsjs.ErrStreamNotFound) -- the configured
//     stream was deleted out from under us.
//  4. *natsjs.APIError with one of the stream-message-size,
//     stream-not-found, or jetstream-not-enabled error codes (server-
//     side counterparts of the typed errors above, surfaced when the
//     client wraps an APIError before returning).
//
// Mirrors audit.isPermanentPublishError exactly so the three adapters
// converge on the same termination criterion.
func isPermanentPublishError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, nats.ErrMaxPayload) {
		return true
	}
	if errors.Is(err, nats.ErrNoResponders) {
		return true
	}
	if errors.Is(err, natsjs.ErrStreamNotFound) {
		return true
	}
	var apiErr *natsjs.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode {
		// 10054: stream message size exceeds maximum.
		// 10059: stream not found.
		// 10076: JetStream not enabled.
		// 10039: JetStream not enabled for account.
		case 10054, 10059, 10076, 10039:
			return true
		}
	}
	return false
}

// compile-time assertion: *natsclient.Client satisfies natsPublisher.
var _ natsPublisher = (*natsclient.Client)(nil)
