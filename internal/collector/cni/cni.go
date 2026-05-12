package cni

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	"github.com/nats-io/nats.go"
	natsjs "github.com/nats-io/nats.go/jetstream"

	"github.com/olokotoh/olaitan/internal/collector/cni/goldmanepb"
	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/retry"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/sourcehealth"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// natsPublisher is the minimal NATS surface the adapter consumes.
// Mirrors internal/collector/falco / audit / cri / applog so a future
// SourceAdapter interface extraction has consistent surface area
// across all five concrete adapters.
type natsPublisher interface {
	PublishJS(ctx context.Context, subject string, data any, opts ...natsjs.PublishOpt) (*natsjs.PubAck, error)
}

// HealthReader aliases sourcehealth.Reader so callers in this
// package's namespace can speak the local name. The canonical
// interface is sourcehealth.Reader and is what Adapter.Health
// returns.
type HealthReader = sourcehealth.Reader

// flowsClient is the narrow Goldmane Flows surface the adapter
// consumes. Declaring the interface locally lets tests inject a stub
// without depending on the upstream generated client (which has three
// RPC methods); the production type goldmanepb.FlowsClient
// satisfies it via Go's structural typing because Go interface
// satisfaction is structural rather than nominal.
type flowsClient interface {
	Stream(ctx context.Context, in *goldmanepb.FlowStreamRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[goldmanepb.FlowResult], error)
}

// Config holds the runtime knobs for an Adapter. The shape mirrors
// falco.Config / audit.Config / cri.Config / applog.Config so a
// future SourceAdapter interface extraction has consistent surface
// area across all five concrete adapters.
type Config struct {
	// GoldmaneAddr is the Goldmane gRPC target. Production default
	// for an operator-installed Calico cluster:
	// "goldmane.calico-system.svc:7443". The Service DNS name is
	// documented in Calico v3.31.5 release manifests.
	GoldmaneAddr string

	// ServerName is the TLS server name presented during handshake.
	// Defaults to "goldmane.calico-system.svc" if empty; operators
	// can override for non-default install paths.
	ServerName string

	// TLS material. Goldmane enforces mTLS; the agent must present
	// a client cert signed by the Tigera operator's CA. Paths are
	// file paths to mounted Secret contents (the Helm chart wires
	// these from a Secret under /etc/olaitan/cni/).
	//
	// All three paths are loaded fresh on every connect-loop
	// iteration (Story 1.10 guardrail 20). The chart rotates the
	// Secret via cert-manager; the kubelet remounts the file path;
	// the next connect picks up the new material without an
	// adapter restart.
	CABundlePath   string
	ClientCertPath string
	ClientKeyPath  string

	// DialTimeout caps the wait for the gRPC client to reach the
	// connectivity.Ready state before the connect attempt is
	// treated as a failure and the outer retry strategy backs off.
	// Defaults to 10s when zero-valued.
	DialTimeout time.Duration

	// StalenessTimeout is the staleness watchdog's threshold.
	// Goldmane flows are quiet by design: a stable cluster with no
	// east-west traffic produces no FlowResults for long stretches.
	// The watchdog only flips MarkUnhealthy when staleness AND a
	// non-Ready connection state coincide -- "no events" alone
	// never trips it. Defaults to 10m when zero-valued.
	StalenessTimeout time.Duration

	// ConnectRetry is the outer connect-loop backoff strategy used
	// when a dial, mTLS handshake, or stream open fails or the
	// stream tears down. Defaults to DefaultConnectRetry() when
	// zero-valued.
	ConnectRetry retry.Strategy

	// PublishRetry is the bounded inner retry for transient NATS
	// publish failures. Defaults to DefaultPublishRetry() when
	// zero-valued.
	PublishRetry retry.Strategy

	// MaxEventBytes caps a marshalled schema.Event at publish time.
	// Marshalled events exceeding this cap are log+dropped via
	// retry.Permanent at translate time. Defaults to
	// DefaultMaxEventBytes (192 KiB) when zero-valued, leaving 64
	// KiB of envelope headroom under JetStream's 256 KiB
	// MaxMsgSize ceiling (Story 1.9 P22 precedent).
	MaxEventBytes int

	// StartTimeGte is the FlowStreamRequest.StartTimeGte value the
	// adapter sends at stream open. Negative values are relative
	// to "now" in seconds (Goldmane convention); zero means "oldest
	// available". Defaults to -60 (last 60 seconds) when
	// zero-valued, matching the spike's capture mode.
	StartTimeGte int64

	// AggregationInterval is the FlowStreamRequest.AggregationInterval.
	// Goldmane's minimum is 15s. Defaults to 15 when zero-valued.
	AggregationInterval int64

	// Hostname is the node-level identifier the adapter records on
	// every emitted Event.Pod.Node. Sourced from the K8S_NODE_NAME
	// env var the Helm chart's downward API injects.
	Hostname string
}

// DefaultConnectRetry returns the outer connect-loop backoff strategy
// used by the agent in production. 1s..60s with full equal-jitter and
// unlimited attempts: quick first reconnect, capped escalation while
// Goldmane is restarting (Tigera operator rolls), and never a
// permanent give-up that would leave the source silently dead.
func DefaultConnectRetry() retry.Strategy {
	return retry.Strategy{
		Min:         1 * time.Second,
		Max:         60 * time.Second,
		Multiplier:  2.0,
		Jitter:      1.0,
		MaxAttempts: 0,
	}
}

// DefaultPublishRetry returns the per-publish bounded retry strategy.
// 100ms..1s, 3 attempts, equal jitter. Combined with the per-attempt
// 2s deadline this caps total transient backoff at ~9s before the
// stream loop log+drops. Mirrors falco / audit / cri / applog exactly
// so the five adapters converge on the same retry shape.
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
// default publish-ack-wait is ~5s; without a per-attempt deadline a
// stalled NATS partition can stall a single PublishJS for ~5s before
// retry 2 starts. Mirrors falco / audit / cri / applog exactly.
const publishAttemptTimeout = 2 * time.Second

// defaultGoldmaneAddr is the production Service DNS for Goldmane on
// a Tigera-operator-installed Calico cluster.
const defaultGoldmaneAddr = "goldmane.calico-system.svc:7443"

// defaultServerName is the TLS SNI presented to Goldmane when the
// operator does not configure a non-default cluster install path.
const defaultServerName = "goldmane.calico-system.svc"

// connectivityCheckInterval is the watchdog's tick period. Returns
// half the configured staleness timeout, with a 30s fallback applied
// ONLY when staleness is non-positive. Production callers always set
// staleness well above the fallback threshold; the floor exists so
// tests can pass a short staleness without dragging the tick period
// to a fixed 30s.
func connectivityCheckInterval(staleness time.Duration) time.Duration {
	period := staleness / 2
	if period <= 0 {
		period = 30 * time.Second
	}
	return period
}

// Adapter is the Calico CNI flow adapter. Construct with New; run the
// per-instance goroutine via Run; observe health via Health.
type Adapter struct {
	cfg    Config
	pub    natsPublisher
	log    *slog.Logger
	health sourcehealth.Tracker

	// lastEventTime is the wall-clock baseline of the most recent
	// successful Translate. Stored as *time.Time (atomic) so the
	// monotonic clock reading is preserved across reads -- a forward
	// NTP step would falsely trip the staleness watchdog if a
	// stripped Unix-nanosecond representation were used. Read by
	// the staleness watchdog; nil means "no event ever received".
	lastEventTime atomic.Pointer[time.Time]

	// connReady reflects whether the gRPC connection has been
	// observed in connectivity.Ready since the last reconnect.
	// Watchdog reads it to decide whether staleness is actionable.
	connReady atomic.Bool

	// translateErrors / publishDrops / oversizeDropped are
	// per-event counters exposed for Story 1.12's Prometheus
	// surface via the getters below.
	translateErrors atomic.Int64
	publishDrops    atomic.Int64
	oversizeDropped atomic.Int64

	// dialFn is a test seam: the production grpc.NewClient cannot be
	// pointed at a bufconn dialer through public API alone. Tests
	// override this; production callers leave it nil and defaultDial
	// is used.
	dialFn func(ctx context.Context, target string, tlsCfg *tls.Config) (*grpc.ClientConn, error)

	// newClientFn is the gRPC client-stub constructor. Production
	// uses goldmanepb.NewFlowsClient; tests inject a hand-rolled
	// stub.
	newClientFn func(grpc.ClientConnInterface) flowsClient

	// tlsLoaderFn is a test seam for the per-connect TLS material
	// load. Production reads from disk; tests inject pre-built
	// tls.Config values.
	tlsLoaderFn func() (*tls.Config, error)

	// nowFn is a test seam for time-dependent assertions in
	// staleness-watchdog tests.
	nowFn func() time.Time
}

// New constructs an Adapter. nc and log are required; cfg is
// validated. nc may be a *natsclient.Client or any natsPublisher-
// satisfying type (for tests).
func New(cfg Config, nc natsPublisher, log *slog.Logger) (*Adapter, error) {
	if nc == nil {
		return nil, errors.New("cni: new: nats publisher is nil")
	}
	if log == nil {
		log = slog.Default()
	}
	if cfg.GoldmaneAddr == "" {
		cfg.GoldmaneAddr = defaultGoldmaneAddr
	}
	if cfg.ServerName == "" {
		cfg.ServerName = defaultServerName
	}
	if cfg.CABundlePath == "" {
		return nil, errors.New("cni: new: config.CABundlePath is empty")
	}
	if cfg.ClientCertPath == "" {
		return nil, errors.New("cni: new: config.ClientCertPath is empty")
	}
	if cfg.ClientKeyPath == "" {
		return nil, errors.New("cni: new: config.ClientKeyPath is empty")
	}
	if cfg.DialTimeout < 0 {
		return nil, fmt.Errorf("cni: new: dial timeout must be >= 0 (0 means default; got %s)", cfg.DialTimeout)
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	if cfg.StalenessTimeout < 0 {
		return nil, fmt.Errorf("cni: new: staleness timeout must be >= 0 (0 means default; got %s)", cfg.StalenessTimeout)
	}
	if cfg.StalenessTimeout == 0 {
		cfg.StalenessTimeout = 10 * time.Minute
	}
	if cfg.MaxEventBytes < 0 {
		return nil, fmt.Errorf("cni: new: max event bytes must be >= 0 (0 means default; got %d)", cfg.MaxEventBytes)
	}
	if cfg.MaxEventBytes == 0 {
		cfg.MaxEventBytes = DefaultMaxEventBytes
	}
	// 4 KiB minimum guards against an operator typo setting
	// MaxEventBytes=192 when they meant 192_000. A flow event with a
	// non-trivial Raw blob hovers around 1 KiB; 4 KiB leaves
	// headroom for the JSON envelope.
	if cfg.MaxEventBytes < 4096 {
		return nil, fmt.Errorf("cni: new: max event bytes must be >= 4096 when set (got %d)", cfg.MaxEventBytes)
	}
	if cfg.AggregationInterval < 0 {
		return nil, fmt.Errorf("cni: new: aggregation interval must be >= 0 (0 means default; got %d)", cfg.AggregationInterval)
	}
	if cfg.AggregationInterval == 0 {
		cfg.AggregationInterval = 15
	}
	if cfg.StartTimeGte == 0 {
		cfg.StartTimeGte = -60
	}
	if cfg.ConnectRetry.IsZero() {
		cfg.ConnectRetry = DefaultConnectRetry()
	}
	if err := cfg.ConnectRetry.Validate(); err != nil {
		return nil, fmt.Errorf("cni: new: connect retry: %w", err)
	}
	if cfg.PublishRetry.IsZero() {
		cfg.PublishRetry = DefaultPublishRetry()
	}
	if err := cfg.PublishRetry.Validate(); err != nil {
		return nil, fmt.Errorf("cni: new: publish retry: %w", err)
	}

	a := &Adapter{
		cfg:         cfg,
		pub:         nc,
		log:         log,
		dialFn:      defaultDial,
		newClientFn: defaultNewClient,
		nowFn:       time.Now,
	}
	// tlsLoaderFn defaults to the on-disk loader so the production
	// adapter picks up cert-manager rotations without restart. Tests
	// override before calling Run.
	a.tlsLoaderFn = a.loadTLSConfigFromDisk
	return a, nil
}

// Health returns the read-only source-health view. Story 1.12 binds
// this to the Prometheus gauge `source_healthy{source="calico"}`
// (FR8). Returning the narrow sourcehealth.Reader interface (rather
// than the concrete *sourcehealth.Tracker) prevents callers outside
// this package from reaching the mutator methods. Note the source
// label is "calico" (the human-facing provider name) while the
// schema enum is "network" (the abstract category) -- see package
// docstring on the intentional asymmetry.
func (a *Adapter) Health() sourcehealth.Reader {
	return &a.health
}

// TranslateErrors returns the cumulative count of FlowResults that
// failed translation and were log+dropped. Exposed for Story 1.12's
// Prometheus surface.
func (a *Adapter) TranslateErrors() int64 { return a.translateErrors.Load() }

// PublishDrops returns the cumulative count of events whose publish
// attempt returned a permanent error. Exposed for Story 1.12's
// Prometheus surface.
func (a *Adapter) PublishDrops() int64 { return a.publishDrops.Load() }

// OversizeDropped returns the cumulative count of events rejected at
// translate time because the marshalled form exceeded MaxEventBytes.
// Exposed for Story 1.12's Prometheus surface so operators can
// distinguish translate-malformed (TranslateErrors) from event-size-
// over-cap (OversizeDropped) drop reasons.
func (a *Adapter) OversizeDropped() int64 { return a.oversizeDropped.Load() }

// Run blocks until ctx is cancelled. The connect-loop retry strategy
// supplied via Config governs reconnect cadence on Goldmane
// unavailability; it never returns to the caller on a transient
// error, only on ctx-driven cancellation. A non-transient
// configuration failure is surfaced immediately as a non-nil error.
//
// Top-level defer recover() mirrors Story 1.9 guardrail 18: a sensor
// panic must not cascade-cancel the parent errgroup. A recovered
// panic flips the source unhealthy and returns the recovered value
// wrapped as an error; the caller (collector ring orchestrator) can
// decide whether to restart the adapter or surface the failure.
func (a *Adapter) Run(ctx context.Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			a.log.Error("cni: top-level panic", "panic", r)
			a.health.MarkUnhealthy(fmt.Errorf("cni: panic: %v", r))
			// Story 1.9 guardrail 18 / Story 1.10 carry-over: do
			// not re-raise; surface as an error so the errgroup
			// records the failure but does not cancel sibling
			// goroutines.
			err = fmt.Errorf("cni: panic recovered: %v", r)
		}
	}()

	a.log.Info("cni: adapter starting",
		"goldmane_addr", a.cfg.GoldmaneAddr,
		"server_name", a.cfg.ServerName,
		"staleness_timeout", a.cfg.StalenessTimeout)
	defer a.log.Info("cni: adapter stopped")

	// Mark unhealthy at startup until the first successful Recv
	// flips it.
	a.health.MarkUnhealthy(errors.New("cni: awaiting first flow"))

	// Watchdog goroutine. Cancelled when Run returns.
	wdCtx, wdCancel := context.WithCancel(ctx)
	defer wdCancel()
	watchdogDone := make(chan struct{})
	go func() {
		defer close(watchdogDone)
		a.runStalenessWatchdog(wdCtx)
	}()

	runErr := a.cfg.ConnectRetry.Do(ctx, func(ctx context.Context) error {
		return a.connectAndStream(ctx)
	})
	wdCancel()
	<-watchdogDone

	if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) {
		return nil
	}
	return runErr
}

// connectAndStream runs one connect-stream-consume iteration. Returns
// a transient error when the stream tears down so the outer Retry.Do
// can re-enter; returns ctx.Err() (or a retry.Permanent wrap) to
// signal a terminal condition that should propagate out of Run.
//
// TLS material is loaded from disk on entry, so cert-manager
// rotations are picked up on the next connect (Story 1.10 guardrail
// 20). A malformed PEM file produces a wrapped error; treat it as
// transient by default (cert-manager rotations are atomic but a
// half-written file during the swap window is possible), and let the
// outer connect retry escalate.
func (a *Adapter) connectAndStream(ctx context.Context) error {
	tlsCfg, err := a.tlsLoaderFn()
	if err != nil {
		a.connReady.Store(false)
		a.health.MarkUnhealthy(err)
		if isTerminalTLSError(err) {
			return retry.Permanent(fmt.Errorf("cni: tls load (terminal, no retry): %w", err))
		}
		return fmt.Errorf("cni: tls load: %w", err)
	}

	dialCtx, cancel := context.WithTimeout(ctx, a.cfg.DialTimeout)
	defer cancel()
	cc, err := a.dialFn(dialCtx, a.cfg.GoldmaneAddr, tlsCfg)
	if err != nil {
		a.connReady.Store(false)
		a.health.MarkUnhealthy(err)
		if isTerminalConnectError(err) {
			return retry.Permanent(fmt.Errorf("cni: dial %q (terminal, no retry): %w", a.cfg.GoldmaneAddr, err))
		}
		return fmt.Errorf("cni: dial %q: %w", a.cfg.GoldmaneAddr, err)
	}
	defer func() {
		a.connReady.Store(false)
		if cerr := cc.Close(); cerr != nil {
			a.log.Warn("cni: grpc conn close", "err", cerr)
		}
	}()

	client := a.newClientFn(cc)
	stream, err := client.Stream(ctx, &goldmanepb.FlowStreamRequest{
		StartTimeGte:        a.cfg.StartTimeGte,
		AggregationInterval: a.cfg.AggregationInterval,
	})
	if err != nil {
		a.health.MarkUnhealthy(err)
		if isTerminalConnectError(err) {
			return retry.Permanent(fmt.Errorf("cni: stream open (terminal, no retry): %w", err))
		}
		return fmt.Errorf("cni: stream open: %w", err)
	}

	a.connReady.Store(true)
	firstFlow := true

	for {
		fr, err := stream.Recv()
		if err != nil {
			a.connReady.Store(false)
			// Clean shutdown: gRPC wraps a cancelled context as a
			// status error with codes.Canceled, which errors.Is
			// does NOT recognise as context.Canceled (grpc-go
			// #6862). Check ctx.Err and the gRPC status code so
			// SIGTERM does not look like a transient transport
			// fault in logs.
			if ctx.Err() != nil || status.Code(err) == codes.Canceled {
				return ctx.Err()
			}
			if errors.Is(err, io.EOF) {
				a.health.MarkUnhealthy(io.EOF)
				return fmt.Errorf("cni: stream eof")
			}
			a.health.MarkUnhealthy(err)
			if isTerminalConnectError(err) {
				return retry.Permanent(fmt.Errorf("cni: stream recv (terminal, no retry): %w", err))
			}
			return fmt.Errorf("cni: stream recv: %w", err)
		}

		if firstFlow {
			a.health.MarkHealthy()
			a.log.Info("cni: stream connected", "goldmane_addr", a.cfg.GoldmaneAddr)
			firstFlow = false
		}

		ev, terr := Translate(fr, a.cfg.MaxEventBytes)
		if terr != nil {
			if errors.Is(terr, ErrEventTooLarge) {
				a.oversizeDropped.Add(1)
				a.log.Error("cni: oversize flow dropped",
					"err", terr,
					"flow_id", fr.GetId())
				continue
			}
			a.translateErrors.Add(1)
			a.log.Warn("cni: translate skipped malformed flow",
				"err", terr,
				"flow_id", fr.GetId())
			continue
		}

		// Record the wall-clock time of the most recent successful
		// translate so the staleness watchdog can decide
		// actionability. Storing *time.Time (rather than UnixNano)
		// preserves the monotonic clock reading.
		now := a.nowFn()
		a.lastEventTime.Store(&now)

		if perr := a.publishWithRetry(ctx, ev); perr != nil {
			if isPermanentPublishError(perr) {
				a.publishDrops.Add(1)
				a.log.Error("cni: publish dropped (permanent, per-event)",
					"err", perr,
					"event_id", ev.ID,
					"summary_bytes", len(ev.Summary))
				continue
			}
			a.health.MarkUnhealthy(perr)
			return fmt.Errorf("cni: publish: %w", perr)
		}
	}
}

// publishWithRetry attempts to publish ev to subjects.RawNetwork with
// bounded retry. Each attempt is wrapped in publishAttemptTimeout so
// a single PublishJS cannot stall past the strategy's between-
// attempts cap. ev.ID is forwarded as the JetStream Nats-Msg-Id
// header so a retry the server already persisted on a previous
// attempt is server-side deduplicated within the stream's 2-minute
// dedup window. Permanent server-side errors are wrapped in
// retry.Permanent so the inner-retry exits immediately and the
// caller log+drops the event.
func (a *Adapter) publishWithRetry(ctx context.Context, ev schema.Event) error {
	return a.cfg.PublishRetry.Do(ctx, func(ctx context.Context) error {
		attemptCtx, cancel := context.WithTimeout(ctx, publishAttemptTimeout)
		defer cancel()
		_, err := a.pub.PublishJS(attemptCtx, subjects.RawNetwork, ev,
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

// runStalenessWatchdog periodically checks whether the time since
// the last successful translate exceeds StalenessTimeout AND the
// connection is not Ready. The "AND not Ready" gate is the critical
// design difference from Stories 1.6 (Falco) and 1.7 (audit):
// Goldmane flow records are quiet by design (Story 1.10 inherits
// Story 1.8 / 1.9 quiet-by-design pattern), so staleness alone is
// uninformative.
//
// Backward clock jumps (negative Sub) are treated as "not stale" so
// a transient NTP step does not falsely flip the source; forward
// jumps are tolerated because lastEventTime preserves the monotonic
// clock reading.
//
// Panics inside this goroutine are caught and surfaced via
// MarkUnhealthy rather than crashing the agent process (Story 1.8
// patch P19 precedent).
//
// Returns when ctx is cancelled.
func (a *Adapter) runStalenessWatchdog(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			a.health.MarkUnhealthy(fmt.Errorf("cni: watchdog panic: %v", r))
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
				// Never received a flow. The startup MarkUnhealthy
				// is authoritative until the first successful
				// Recv flips it. Don't fabricate a staleness event.
				continue
			}
			if a.connReady.Load() {
				// Connection is Ready: by-design quiet stretches
				// do not flip unhealthy. This is the load-bearing
				// design difference Story 1.10 inherits from
				// Stories 1.8 / 1.9.
				continue
			}
			delta := a.nowFn().Sub(*lastPtr)
			if delta < 0 {
				// Backward clock jump (NTP step). Treat as fresh.
				continue
			}
			if delta <= a.cfg.StalenessTimeout {
				continue
			}
			a.health.MarkUnhealthy(fmt.Errorf("cni: no flow for %s and connection not Ready", a.cfg.StalenessTimeout))
		}
	}
}

// loadTLSConfigFromDisk reads the three TLS files and assembles a
// fresh *tls.Config. Called on every connect-loop iteration so a
// cert-manager-driven Secret rotation is picked up without an
// adapter restart (Story 1.10 guardrail 20).
//
// The caller (connectAndStream) wraps the returned error and decides
// whether to treat the failure as transient (retry with backoff) or
// terminal (retry.Permanent so the pod CrashLoops with a clear
// signal). isTerminalTLSError below codifies the policy.
func (a *Adapter) loadTLSConfigFromDisk() (*tls.Config, error) {
	caBytes, err := os.ReadFile(a.cfg.CABundlePath)
	if err != nil {
		return nil, fmt.Errorf("read ca bundle %q: %w", a.cfg.CABundlePath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("ca bundle %q contained no parseable certificates", a.cfg.CABundlePath)
	}
	clientCert, err := tls.LoadX509KeyPair(a.cfg.ClientCertPath, a.cfg.ClientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}
	return &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{clientCert},
		ServerName:   a.cfg.ServerName,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// defaultDial dials target with the supplied mTLS credentials,
// blocks (bounded by dialCtx) until the connection reaches
// connectivity.Ready, and returns the established *grpc.ClientConn.
//
// Keepalive parameters force the gRPC client to detect a half-open
// transport by pinging every 30s with a 10s timeout (Story 1.6
// Falco precedent); without these knobs a wedged TCP connection
// appears healthy indefinitely because Recv produces neither an
// error nor a message.
//
// grpc.NewClient is intentionally lazy in modern grpc-go (>= 1.63):
// it does not connect until the first RPC. Without an explicit
// readiness wait the configured DialTimeout would be cosmetic and
// a wrong address or mis-signed cert would surface only as a
// stream error several seconds later. We therefore call cc.Connect
// to exit Idle and loop on cc.WaitForStateChange until the state
// reaches Ready (success), TransientFailure or Shutdown (terminal
// for this attempt), or dialCtx is done. (grpc-go anti-patterns
// documentation, 2026.)
func defaultDial(dialCtx context.Context, target string, tlsCfg *tls.Config) (*grpc.ClientConn, error) {
	creds := credentials.NewTLS(tlsCfg)
	cc, err := grpc.NewClient(
		target,
		grpc.WithTransportCredentials(creds),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: false,
		}),
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
			_ = cc.Close()
			if cerr := dialCtx.Err(); cerr != nil {
				return nil, fmt.Errorf("dial wait-for-ready: %w", cerr)
			}
			return nil, fmt.Errorf("dial wait-for-ready: state=%s", state)
		}
	}
}

// defaultNewClient is the production constructor for the Goldmane
// FlowsClient. The local flowsClient interface narrowing means
// tests can supply a stub without depending on the full generated
// surface area.
func defaultNewClient(cc grpc.ClientConnInterface) flowsClient {
	return goldmanepb.NewFlowsClient(cc)
}

// isTerminalConnectError returns true when err represents a
// permanent configuration mistake that cannot be fixed by retrying:
//
//   - fs.ErrPermission: file-system permission denial on the TLS
//     material. Mirrors falco / cri precedent.
//   - gRPC codes.Unauthenticated: mTLS cert rejected by Goldmane.
//   - gRPC codes.PermissionDenied: server-side authorization
//     denial.
//
// Detection is purely typed; no string-substring fallback. Story
// 1.7 patch P7 + Story 1.8 P28 explicitly deleted the substring
// fallback because gRPC error message text is locale-/version-
// fragile.
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
	return false
}

// isTerminalTLSError returns true when err from loadTLSConfigFromDisk
// represents a configuration mistake that cannot be fixed by
// retrying. fs.ErrNotExist on any of the three TLS file paths means
// the chart did not mount the Secret, which is a render-time
// misconfiguration the operator must fix; retrying would burn CPU
// against a stable error. fs.ErrPermission means the file is mounted
// but readable; the same logic applies.
//
// A half-written PEM file during a cert-manager rotation produces a
// "ca bundle contained no parseable certificates" error which is
// surfaced via fmt.Errorf wrap and falls through to the transient
// path so the next connect-loop iteration retries.
func isTerminalTLSError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, fs.ErrNotExist) {
		return true
	}
	if errors.Is(err, fs.ErrPermission) {
		return true
	}
	// "tls: bad certificate" surfaces when the operator pasted a
	// non-PEM client cert into the Helm values; the resulting
	// LoadX509KeyPair error wraps it. errors.Is unwraps the chain.
	if strings.Contains(strings.ToLower(err.Error()), "tls: bad certificate") {
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
// Detection is typed -- no substring fallback. Mirrors
// cri.isPermanentPublishError / audit.isPermanentPublishError
// exactly so the four typed adapters (falco uses a substring
// fallback as a legacy carry-over, see Story 1.6) converge on the
// same termination criterion.
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
