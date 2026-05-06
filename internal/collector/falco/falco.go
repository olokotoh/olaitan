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
// Terminal errors: configuration mistakes that cannot be recovered by
// retrying (EACCES on a Unix socket, gRPC Unauthenticated /
// PermissionDenied) short-circuit the retry loop via retry.Permanent and
// surface as a non-nil error from Run, so the parent process exits and
// kubelet restarts the pod with a clear CrashLoopBackOff signal. Loud
// failure for misconfig is the contract.
//
// Source health: the adapter exposes its in-process source-health view
// via Adapter.Health(). Story 1.12 binds this to the unified Prometheus
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
	"io/fs"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	natsjs "github.com/nats-io/nats.go/jetstream"

	"github.com/olokotoh/olaitan/internal/collector/falco/falcopb"
	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/retry"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// natsPublisher is the minimal NATS surface the adapter consumes.
// *natsclient.Client (the production type) satisfies this implicitly,
// and tests can supply a stub. The variadic opts let callers pass
// jetstream.WithMsgID for server-side dedup on retry; an empty opts
// slice matches the old call shape exactly.
type natsPublisher interface {
	PublishJS(ctx context.Context, subject string, data any, opts ...natsjs.PublishOpt) (*natsjs.PubAck, error)
}

// HealthReader is the read-only view of the adapter's source-health
// tracker. Story 1.12's Prometheus collector only needs Status(); we
// expose this narrow interface from Adapter.Health() so callers cannot
// reach MarkHealthy / MarkUnhealthy from outside the package.
type HealthReader interface {
	Status() (bool, error)
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
// 100ms..1s, 3 attempts: combined with the per-attempt 2s deadline that
// publishWithRetry now wraps around each PublishJS call, a transient
// JetStream hiccup costs at most ~9s of stream consumption (3 attempts ×
// 2s deadline + ~2.5s of jittered backoff between them) before the
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

// publishAttemptTimeout caps a single PublishJS attempt. JetStream's
// default publish-ack-wait is ~5s; without a per-attempt deadline a NATS
// partition can stall a single PublishJS for ~5s before retry 2 starts.
// The 2s ceiling keeps the bounded inner-retry path's worst case
// predictable for the architecture's NFR1 budget.
const publishAttemptTimeout = 2 * time.Second

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

// Health returns the read-only source-health view. Story 1.12 binds
// this to the Prometheus gauge `source_healthy{source="falco"}` (FR8).
// Returning the narrow HealthReader interface (rather than the concrete
// *SourceHealth) prevents callers outside this package from reaching
// the mutator methods MarkHealthy / MarkUnhealthy.
func (a *Adapter) Health() HealthReader {
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
// re-enter; returns ctx.Err() (or a retry.Permanent wrap) to signal a
// terminal condition that should propagate out of Run.
func (a *Adapter) connectAndConsume(ctx context.Context) error {
	cc, err := a.dialFn(ctx, a.cfg.Endpoint)
	if err != nil {
		a.health.MarkUnhealthy(err)
		if isTerminalConnectError(err) {
			return retry.Permanent(fmt.Errorf("falco: dial %q (terminal, no retry): %w", a.cfg.Endpoint, err))
		}
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
		if isTerminalConnectError(err) {
			return retry.Permanent(fmt.Errorf("falco: sub (terminal, no retry): %w", err))
		}
		return fmt.Errorf("falco: sub: %w", err)
	}
	// Falco's Sub is bidi-streaming; the server starts emitting only
	// after the client sends an initial Request. The Request message is
	// empty (TODO upstream re: tags) but its arrival is the kickoff.
	if err := stream.Send(&falcopb.Request{}); err != nil {
		a.health.MarkUnhealthy(err)
		if isTerminalConnectError(err) {
			return retry.Permanent(fmt.Errorf("falco: stream send (terminal, no retry): %w", err))
		}
		return fmt.Errorf("falco: stream send: %w", err)
	}
	// The client side of the bidi stream sends exactly one Request
	// message; closing it lets a strict server release request-side
	// resources without affecting the server-to-client Recv path.
	if err := stream.CloseSend(); err != nil {
		// CloseSend failure is operationally non-fatal; the stream's
		// Recv direction can still deliver. Log and continue so a
		// transport quirk on this seam does not abort an otherwise-
		// healthy adapter.
		a.log.Debug("falco: stream close-send", "err", err)
	}

	// Note: MarkHealthy is deferred to the first successful Recv below,
	// not called here. grpc.NewClient is lazy; a successful Send onto a
	// fresh connection only buffers the message locally, so flipping the
	// gauge to healthy at this point would lie about whether Falco is
	// actually reachable. The first non-error Recv is the earliest
	// moment we have evidence of byte traffic in both directions.

	firstMessage := true
	// Half-open transport detection is provided entirely by gRPC
	// keepalive (see defaultDial: 30s ping + 10s timeout). The previous
	// implementation also pre-checked ctx.Err before each Recv, but
	// Recv itself honours ctx-cancel, so the pre-check only saved a
	// couple of microseconds on the next iteration after cancellation
	// has been observed. There is no concurrent watchdog goroutine.
	for {
		resp, err := stream.Recv()
		if err != nil {
			// Clean shutdown: gRPC wraps a cancelled context as a
			// status error with codes.Canceled, which errors.Is does
			// NOT recognise as context.Canceled (grpc-go #6862).
			// Check ctx.Err and the gRPC status code so SIGTERM does
			// not look like a transient transport fault in logs or
			// the SourceHealth lastErr surface.
			if ctx.Err() != nil || status.Code(err) == codes.Canceled {
				return ctx.Err()
			}
			// io.EOF means Falco closed its side cleanly; retry so
			// Falco restarts are handled. Mark unhealthy and let the
			// outer retry loop dial again. (Smoothing the brief
			// healthy=0 window during expected restarts is the
			// alerting layer's job; see Story 1.12 alert-rule notes.)
			if errors.Is(err, io.EOF) {
				a.health.MarkUnhealthy(io.EOF)
				return fmt.Errorf("falco: stream eof")
			}
			a.health.MarkUnhealthy(err)
			if isTerminalConnectError(err) {
				return retry.Permanent(fmt.Errorf("falco: stream recv (terminal, no retry): %w", err))
			}
			if status.Code(err) == codes.ResourceExhausted {
				// A leftover collector instance still holding the
				// gRPC subscription returns ResourceExhausted; let
				// the dial loop sleep and re-enter so the old pod's
				// terminationGracePeriodSeconds expires and clears
				// the slot.
				a.log.Warn("falco: stream recv resource-exhausted; backing off",
					"err", err)
			}
			return fmt.Errorf("falco: stream recv: %w", err)
		}

		if firstMessage {
			a.health.MarkHealthy()
			a.log.Info("falco: stream connected", "endpoint", a.cfg.Endpoint)
			firstMessage = false
		}
		// MarkHealthy on subsequent Recvs was previously called here
		// to "defend against a transient MarkUnhealthy from publish-
		// retry leaving the gauge stuck false after recovery." That
		// defence is fiction in the single-goroutine pipeline:
		// publishWithRetry runs synchronously below, so MarkHealthy
		// could not fire while a publish stalls. The bounded inner
		// retry only flips the gauge unhealthy on persistent failure
		// (which tears the stream and re-enters this connect path),
		// at which point the next firstMessage flips it back. No
		// per-Recv refresh is needed.

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
			if isPermanentPublishError(err) {
				// Per-message terminal failure (e.g. payload too
				// large for the EVENTS_RAW MaxMsgSize cap). Tearing
				// the stream and re-dialling would just receive the
				// same oversize message again from Falco's emitter
				// and tight-loop; instead log+skip this single event
				// and stay on the live stream. The gauge stays
				// healthy because the connection is intact.
				a.log.Error("falco: publish dropped (permanent, per-message)",
					"err", err, "event_id", ev.ID, "summary_bytes", len(ev.Summary))
				continue
			}
			// Persistent transient publish failure: NATS is genuinely
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
// bounded retry. Each attempt is wrapped in a 2s per-attempt deadline
// (publishAttemptTimeout) so a single PublishJS cannot stall past the
// strategy's between-attempts cap. ev.ID is forwarded as the JetStream
// Nats-Msg-Id header so a retry that the server already persisted on a
// previous attempt is server-side deduplicated within the stream's
// dedup window (default 2 min). A permanent server-side error (e.g.
// "Maximum Payload Violation" / "message size exceeded") is wrapped in
// retry.Permanent so the inner-retry exits immediately and the caller
// can log+skip without tearing down the gRPC stream.
func (a *Adapter) publishWithRetry(ctx context.Context, ev schema.Event) error {
	return a.cfg.PublishRetry.Do(ctx, func(ctx context.Context) error {
		attemptCtx, cancel := context.WithTimeout(ctx, publishAttemptTimeout)
		defer cancel()
		_, err := a.pub.PublishJS(attemptCtx, subjects.RawFalco, ev,
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

// isTerminalConnectError returns true when err represents a permanent
// configuration mistake that cannot be fixed by retrying:
//
//   - fs.ErrPermission: EACCES on the Falco Unix socket. The pod will
//     keep getting denied until an operator fixes the socket's
//     permissions or the container's UID/GID.
//   - gRPC codes.Unauthenticated: TLS auth failure on a tcp:// target.
//   - gRPC codes.PermissionDenied: server-side RBAC denial.
//
// codes.ResourceExhausted is intentionally NOT terminal: a leftover
// collector pod still holding the Falco gRPC subscription clears once
// it terminates within terminationGracePeriodSeconds, so the new pod
// should keep dialing with backoff. See connectAndConsume's explicit
// log on ResourceExhausted for that path.
//
// errors.Is unwraps the gRPC status error chain to find a wrapped
// fs.ErrPermission; status.Code reads the gRPC code directly. Both
// checks tolerate nil err (returning false) so callers can use this
// unconditionally on the failure branch.
func isTerminalConnectError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, fs.ErrPermission) {
		return true
	}
	switch status.Code(err) {
	case codes.Unauthenticated, codes.PermissionDenied:
		return true
	}
	// gRPC sometimes surfaces unix-socket EACCES as Unavailable with
	// "permission denied" in the message; substring-match as a last
	// line of defence so the pod CrashLoops loudly instead of looping
	// silently at 60s cadence.
	if strings.Contains(strings.ToLower(err.Error()), "permission denied") {
		return true
	}
	return false
}

// isPermanentPublishError returns true when err from a JetStream
// PublishJS call is a per-message terminal condition (the message
// itself violates a stream-level invariant) rather than a transient
// transport hiccup. The caller is expected to log+drop the offending
// event and continue; tearing down the stream and re-dialing would
// just have Falco re-emit the same oversize message and tight-loop.
//
// JetStream surfaces "maximum payload violation" / "message size
// exceeded" / "max msgs per subject" with text bodies that vary across
// nats-server versions; substring-match the lowercase message body
// against the stable phrase fragments. nats.ErrMaxPayload is the
// client-side guard for the connection's max_payload setting.
func isPermanentPublishError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "maximum payload") ||
		strings.Contains(msg, "max payload") ||
		strings.Contains(msg, "message size exceeded") ||
		strings.Contains(msg, "max msg size") ||
		strings.Contains(msg, "payload too big") {
		return true
	}
	return false
}

// compile-time assertion: *natsclient.Client satisfies natsPublisher.
var _ natsPublisher = (*natsclient.Client)(nil)
