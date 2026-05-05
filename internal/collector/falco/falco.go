// Package falco implements the Olaitan agent's Falco gRPC sensor adapter.
//
// The adapter dials Falco's grpc_output service on a Unix or TCP socket,
// reads `outputs.service.Sub` Response messages continuously, translates
// each into a canonical schema.Event of source=falco / category=syscall,
// and publishes to subjects.RawFalco via the project's NATS client with
// JetStream at-least-once semantics.
//
// Concurrency model: a single goroutine per Adapter handles connect,
// stream consumption, translation, and publish. The architecture's
// per-source per-node throughput budget (NFR1: 1000 events/sec/source)
// fits comfortably into one goroutine; profiling-driven parallelism is
// deferred to a future story if it ever becomes warranted.
//
// Lifecycle: Adapter.Run blocks until ctx is cancelled or a non-retryable
// error escapes the retry loop. On any transient error (dial failure,
// stream Recv error, persistent publish failure) the adapter marks the
// source unhealthy via SourceHealth and re-enters the dial loop with the
// configured exponential backoff. Transient publish failures are retried
// inline (bounded) without tearing down the gRPC stream, so a brief NATS
// hiccup does not lose the events Falco is emitting during the recovery
// window. On ctx cancellation, Run returns nil promptly.
//
// Source health: the adapter exposes its in-process SourceHealth via
// Adapter.Health(). Story 1.12 binds this to the unified Prometheus
// gauge `source_healthy{source="falco"}` (FR8). Bringing in the
// Prometheus client library here would pre-empt Story 1.12's
// metric-naming and endpoint-routing decisions for all five sources at
// once, so this story stops at the in-process tracker per the FR8
// ownership split documented in architecture.md (§ "Observability
// surface").
package falco

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	natsjs "github.com/nats-io/nats.go/jetstream"

	"github.com/olokotoh/olaitan/internal/collector/falco/falcopb"
	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/retry"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// natsPublisher is the minimal NATS surface the adapter consumes.
// *natsclient.Client (the production type) satisfies this implicitly,
// and tests can supply a stub.
type natsPublisher interface {
	PublishJS(ctx context.Context, subject string, data any) (*natsjs.PubAck, error)
}

// Config holds the runtime knobs for an Adapter.
type Config struct {
	// Endpoint is the gRPC target Falco's grpc_output is listening on.
	// Defaults via the Helm chart to "unix:///run/falco/falco.sock".
	Endpoint string

	// Hostname is the node-level identifier the adapter records on every
	// emitted Event.Pod.Node. The collector subcommand reads
	// K8S_NODE_NAME from the downward API and passes it here.
	Hostname string

	// Retry is the backoff strategy used for connect / stream restart.
	// Defaults to DefaultRetry() when zero-valued.
	Retry retry.Strategy

	// PublishRetry is the bounded inner retry used when a NATS publish
	// fails transiently. The adapter retries the publish in place
	// (without tearing down the gRPC stream) up to MaxAttempts times so
	// a brief JetStream hiccup does not drop the events Falco is
	// emitting during the recovery window. Defaults to
	// DefaultPublishRetry() when zero-valued.
	PublishRetry retry.Strategy
}

// DefaultRetry returns the connect-loop backoff strategy used by the
// agent in production. 1s..60s with full equal-jitter and unlimited
// attempts is the right shape for a long-lived DaemonSet adapter:
// quick first reconnect, capped escalation to keep CPU at idle while
// Falco is restarting, and never a permanent give-up that would leave
// the source silently dead.
func DefaultRetry() retry.Strategy {
	return retry.Strategy{
		Min:         1 * time.Second,
		Max:         60 * time.Second,
		Multiplier:  2.0,
		Jitter:      1.0,
		MaxAttempts: 0,
	}
}

// DefaultPublishRetry returns the per-publish bounded retry strategy.
// 100ms..1s, 3 attempts: a transient JetStream hiccup costs at most
// ~2.1s of stream consumption before either the publish succeeds or the
// outer dial loop takes over. The cap keeps the adapter from stalling
// the gRPC Recv path indefinitely if NATS is genuinely down.
func DefaultPublishRetry() retry.Strategy {
	return retry.Strategy{
		Min:         100 * time.Millisecond,
		Max:         1 * time.Second,
		Multiplier:  2.0,
		Jitter:      1.0,
		MaxAttempts: 3,
	}
}

// Adapter is the Falco gRPC sensor adapter. Construct with New; run
// the per-instance goroutine via Run; observe health via Health.
type Adapter struct {
	cfg    Config
	pub    natsPublisher
	log    *slog.Logger
	health SourceHealth

	// dialFn is a test seam: the production grpc.NewClient cannot be
	// pointed at a bufconn dialer through public API alone. Tests
	// override this; production callers leave it nil and the default
	// dialer is used.
	dialFn func(ctx context.Context, target string) (*grpc.ClientConn, error)

	// newClientFn is the gRPC client-stub constructor. Tests inject a
	// hand-rolled implementation; production uses falcopb.NewServiceClient.
	// The signature accepts grpc.ClientConnInterface (the interface the
	// generated constructor takes); *grpc.ClientConn satisfies it.
	newClientFn func(grpc.ClientConnInterface) falcopb.ServiceClient
}

// New constructs an Adapter. nc and log are required; cfg is validated.
// nc may be a *natsclient.Client or any natsPublisher-satisfying type
// (for tests).
func New(cfg Config, nc natsPublisher, log *slog.Logger) (*Adapter, error) {
	if nc == nil {
		return nil, errors.New("falco: new: nats publisher is nil")
	}
	if log == nil {
		log = slog.Default()
	}
	if cfg.Endpoint == "" {
		return nil, errors.New("falco: new: config.Endpoint is empty")
	}
	if cfg.Hostname == "" {
		return nil, errors.New("falco: new: config.Hostname is empty")
	}
	// Substitute defaults when the corresponding strategy is the zero
	// value, then validate the full struct so a partial misconfiguration
	// (Min set, Multiplier unset, etc.) surfaces at New time rather than
	// 1s into Run when the first Strategy.Do call would otherwise reject
	// it.
	if cfg.Retry.IsZero() {
		cfg.Retry = DefaultRetry()
	}
	if err := cfg.Retry.Validate(); err != nil {
		return nil, fmt.Errorf("falco: new: connect retry: %w", err)
	}
	if cfg.PublishRetry.IsZero() {
		cfg.PublishRetry = DefaultPublishRetry()
	}
	if err := cfg.PublishRetry.Validate(); err != nil {
		return nil, fmt.Errorf("falco: new: publish retry: %w", err)
	}
	return &Adapter{
		cfg:         cfg,
		pub:         nc,
		log:         log,
		dialFn:      defaultDial,
		newClientFn: falcopb.NewServiceClient,
	}, nil
}

// Health returns the in-process source-health tracker. Story 1.12 binds
// this to the Prometheus gauge `source_healthy{source="falco"}` (FR8).
func (a *Adapter) Health() *SourceHealth {
	return &a.health
}

// Run blocks until ctx is cancelled. The retry strategy supplied via
// Config governs reconnect cadence on Falco unavailability; it never
// returns to the caller on a transient error, only on ctx-driven
// cancellation. A non-transient configuration failure is surfaced
// immediately as a non-nil error.
func (a *Adapter) Run(ctx context.Context) error {
	a.log.Info("falco: adapter starting",
		"endpoint", a.cfg.Endpoint,
		"hostname", a.cfg.Hostname)
	defer a.log.Info("falco: adapter stopped")

	err := a.cfg.Retry.Do(ctx, func(ctx context.Context) error {
		return a.connectAndConsume(ctx)
	})
	// Retry.Do returns ctx.Err() for ctx cancellation, which we treat as
	// a clean shutdown rather than an error.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	return err
}

// connectAndConsume runs one dial-stream-consume iteration. Returns a
// transient error when the stream tears down so the outer Retry.Do can
// re-enter; returns ctx.Err() to signal clean shutdown.
func (a *Adapter) connectAndConsume(ctx context.Context) error {
	cc, err := a.dialFn(ctx, a.cfg.Endpoint)
	if err != nil {
		a.health.MarkUnhealthy(err)
		return fmt.Errorf("falco: dial %q: %w", a.cfg.Endpoint, err)
	}
	defer func() {
		if cerr := cc.Close(); cerr != nil {
			a.log.Warn("falco: grpc conn close", "err", cerr)
		}
	}()

	client := a.newClientFn(cc)
	stream, err := client.Sub(ctx)
	if err != nil {
		a.health.MarkUnhealthy(err)
		return fmt.Errorf("falco: sub: %w", err)
	}
	// Falco's Sub is bidi-streaming; the server starts emitting only
	// after the client sends an initial Request. The Request message is
	// empty (TODO upstream re: tags) but its arrival is the kickoff.
	if err := stream.Send(&falcopb.Request{}); err != nil {
		a.health.MarkUnhealthy(err)
		return fmt.Errorf("falco: stream send: %w", err)
	}

	// Note: MarkHealthy is deferred to the first successful Recv below,
	// not called here. grpc.NewClient is lazy; a successful Send onto a
	// fresh connection only buffers the message locally, so flipping the
	// gauge to healthy at this point would lie about whether Falco is
	// actually reachable. The first non-error Recv is the earliest
	// moment we have evidence of byte traffic in both directions.

	firstMessage := true
	// ctxCheckEvery bounds how often the watchdog kicks in if Recv
	// becomes wedged on a half-open transport. The grpc-go contract is
	// that Recv honours ctx-cancel, but in practice certain transport
	// states (TCP half-open after NIC drop) can stall it past
	// terminationGracePeriodSeconds. The watchdog runs alongside Recv
	// and signals a transient error when ctx is done so the dial loop
	// can re-enter promptly.
	for {
		// Watchdog: if ctx is already done, surface it now rather than
		// committing to another (potentially blocking) Recv.
		if err := ctx.Err(); err != nil {
			return err
		}

		resp, err := stream.Recv()
		if err != nil {
			// io.EOF means Falco closed its side cleanly; we still want
			// to retry to handle Falco restarts. Mark unhealthy and let
			// the outer retry loop dial again. (Smoothing the brief
			// healthy=0 window during expected restarts is the
			// alerting layer's job; see Story 1.12 alert-rule notes.)
			if errors.Is(err, io.EOF) {
				a.health.MarkUnhealthy(io.EOF)
				return fmt.Errorf("falco: stream eof")
			}
			a.health.MarkUnhealthy(err)
			return fmt.Errorf("falco: stream recv: %w", err)
		}

		if firstMessage {
			a.health.MarkHealthy()
			a.log.Info("falco: stream connected", "endpoint", a.cfg.Endpoint)
			firstMessage = false
		} else {
			// Each subsequent successful Recv is evidence the stream is
			// alive; refresh the healthy state so a transient
			// MarkUnhealthy from a publish-retry below cannot leave the
			// gauge stuck false after recovery.
			a.health.MarkHealthy()
		}

		ev, err := Translate(resp, a.cfg.Hostname)
		if err != nil {
			// A single malformed message must not break the stream;
			// log and skip. The source stays healthy because the
			// connection is still alive.
			a.log.Warn("falco: translate skipped malformed message",
				"err", err, "rule", resp.GetRule())
			continue
		}

		if err := a.publishWithRetry(ctx, ev); err != nil {
			// Persistent publish failure: NATS is genuinely
			// unavailable. Tear the stream down so the outer dial
			// loop can re-enter (during which Falco is the lossy
			// component, but at-least-once is preserved across
			// transient hiccups by publishWithRetry above).
			a.health.MarkUnhealthy(err)
			return fmt.Errorf("falco: publish: %w", err)
		}
	}
}

// publishWithRetry attempts to publish ev to subjects.RawFalco with
// bounded retry. A transient JetStream error is retried inline so the
// gRPC stream stays open and Falco's emissions during the recovery
// window are not lost. Returns nil on success, ctx.Err() on
// cancellation, or the last publish error wrapped after the configured
// MaxAttempts is exhausted.
func (a *Adapter) publishWithRetry(ctx context.Context, ev any) error {
	return a.cfg.PublishRetry.Do(ctx, func(ctx context.Context) error {
		_, err := a.pub.PublishJS(ctx, subjects.RawFalco, ev)
		return err
	})
}

// defaultDial dials target with insecure transport credentials (Falco's
// gRPC plugin defaults to plaintext over a Unix socket); TLS for tcp://
// targets is tracked as future work in deferred-decisions.md. Keepalive
// parameters force the gRPC client to detect a half-open transport
// (NIC drop, peer kernel-panic) by pinging every 30s with a 10s
// timeout; without this a wedged TCP connection appears healthy
// indefinitely because Recv produces neither an error nor a message.
//
// grpc.NewClient is intentionally lazy in modern grpc-go (>= 1.63);
// connection establishment happens on the first RPC. Any apparent
// "dial success" here is therefore not evidence the endpoint is
// reachable; that determination lives in connectAndConsume's first
// Recv.
func defaultDial(_ context.Context, target string) (*grpc.ClientConn, error) {
	return grpc.NewClient(
		target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: false,
		}),
	)
}

// compile-time assertion: *natsclient.Client satisfies natsPublisher.
var _ natsPublisher = (*natsclient.Client)(nil)
