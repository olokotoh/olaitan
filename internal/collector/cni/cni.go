package cni

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"runtime/debug"
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
	// to "now" in seconds (Goldmane convention; see
	// projectcalico/calico v3.31.5 goldmane/proto/api.proto line
	// 89-94). An explicit zero means "now" per the proto's
	// documented semantic (line 91: "A value of zero means 'now'")
	// and reaches Goldmane unchanged. Nil means "use
	// DefaultStartTimeGteReplay (-60, replay last minute)", which
	// preserves the chart's quiet-start default.
	StartTimeGte *int64

	// AggregationInterval is the FlowStreamRequest.AggregationInterval.
	// Goldmane requires exactly 15s per the v3.31.5 proto contract
	// (goldmane/proto/api.proto line 100: "It must always be 15s.").
	// Defaults to 15 when zero-valued; any non-zero value other than
	// 15 is rejected at New time.
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

// oversizeLogInterval rate-limits the "oversize flow dropped" ERROR
// log: emit at most once per interval per Adapter so a Goldmane-side
// bug producing a stream of oversize flows cannot flood the log
// volume. Story 1.10 code-review patch P18 (Story 1.9 P22 precedent).
// The OversizeDropped() counter remains the authoritative per-drop
// signal for the Story 1.12 metrics surface.
const oversizeLogInterval = 10 * time.Second

// DefaultStartTimeGteReplay is the StartTimeGte value used when
// Config.StartTimeGte is nil. -60 means "replay the last 60 seconds
// of flow records", matching the spike's capture mode and the
// chart's quiet-start default. An operator who explicitly sets
// start_time_gte: 0 in the chart values reaches Goldmane's
// documented "now" semantic instead.
const DefaultStartTimeGteReplay int64 = -60

// errCABundleUnparseable is returned by loadTLSConfigFromDisk when
// the CA bundle file is present but x509.NewCertPool.AppendCertsFromPEM
// could not extract a single PEM block. Distinguishing this from a
// missing-file or permission-denied error lets isTerminalTLSError flip
// the failure terminal: a "caBundle: foo" misconfiguration is a
// render-time mistake the operator must fix, not a transient
// half-written-file race during cert-manager rotation.
var errCABundleUnparseable = errors.New("cni: ca bundle is not parseable PEM")

// errTLSNoPEMData is returned when the client cert or key file is
// present but contains no PEM block of the expected type. Typed
// detection (pem.Decode + block.Type check) avoids the substring-match
// path that Stories 1.7/1.8 explicitly retired. Surfaces as terminal
// so the operator notices a paste-into-wrong-field typo via CrashLoop
// instead of an infinite transient-retry loop.
var errTLSNoPEMData = errors.New("cni: tls material contains no PEM block of expected type")

// errTLSCertKeyMismatch is returned when the parsed client cert's
// public key does not match the parsed private key's public key.
// Operator paired a cert from CA-A with a key from CA-B (or vice
// versa). Typed detection via crypto.PublicKey equality avoids the
// substring-match path on the stdlib's "private key does not match
// public key" message. Terminal so the operator notices via CrashLoop.
var errTLSCertKeyMismatch = errors.New("cni: tls cert and key public keys do not match")

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

	// streamOpen reflects whether the FlowsClient.Stream RPC has
	// returned successfully since the last reconnect. Set true
	// inside connectAndStream immediately after Stream() returns,
	// reset false in the deferred cleanup. Watchdog uses this to
	// distinguish (streamOpen=false → silent reconnect),
	// (streamOpen=true && lastEventTime=nil → stale-no-flows,
	// info-only), (streamOpen=true && lastEventTime stale →
	// MarkUnhealthy). Story 1.10 D1 (code-review patch P25):
	// resolves the half-open-stream blind spot where TCP was up
	// but Goldmane never sent a flow.
	streamOpen atomic.Bool

	// consecutiveEOFs counts EOFs returned by stream.Recv() since
	// the last successful Recv. Story 1.10 D2 (code-review patch
	// P26): emit a log-once WARN at N=5 so a Goldmane-side stream
	// EOF storm is observable without escalating to retry.Permanent
	// (the adapter keeps reconnecting; quiet-by-design preserved).
	// Resets to 0 on first successful Recv. Exposed for Story 1.12.
	consecutiveEOFs       atomic.Int64
	consecutiveEOFsLogged atomic.Bool

	// translateErrors / publishDrops / oversizeDropped are
	// per-event counters exposed for Story 1.12's Prometheus
	// surface via the getters below.
	translateErrors atomic.Int64
	publishDrops    atomic.Int64
	oversizeDropped atomic.Int64

	// eventsPublished is the Story 1.12 Prometheus reader-side
	// counter, incremented per successful publishWithRetry.
	// Exposed via EventsTotal as the int64 snapshot.
	eventsPublished atomic.Int64

	// lastOversizeLog is the wall-clock time of the most recent
	// oversize-drop ERROR log. Story 1.10 code-review patch P18
	// rate-limits the log so a stream of oversize flows does not
	// flood the log volume; the counter (oversizeDropped) still
	// increments per drop so the metrics surface is accurate.
	lastOversizeLog atomic.Pointer[time.Time]

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
	if strings.TrimSpace(cfg.GoldmaneAddr) != cfg.GoldmaneAddr {
		return nil, fmt.Errorf("cni: new: goldmane_addr has leading/trailing whitespace; got %q (heredoc / values.yaml typo?)", cfg.GoldmaneAddr)
	}
	if cfg.ServerName == "" {
		cfg.ServerName = defaultServerName
	}
	if strings.TrimSpace(cfg.ServerName) != cfg.ServerName {
		return nil, fmt.Errorf("cni: new: server_name has leading/trailing whitespace; got %q (heredoc / values.yaml typo?)", cfg.ServerName)
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
	// JetStream MaxMsgSize for EVENTS_RAW is 256 KiB (see
	// internal/nats/streams.go); the chart's calicoSensor block
	// documents this ceiling. Reject configs that would always
	// fail at publish time so the operator sees the misconfig at
	// New rather than at first publish.
	if cfg.MaxEventBytes > 256*1024 {
		return nil, fmt.Errorf("cni: new: max event bytes must be <= %d (JetStream EVENTS_RAW MaxMsgSize ceiling); got %d", 256*1024, cfg.MaxEventBytes)
	}
	if cfg.AggregationInterval < 0 {
		return nil, fmt.Errorf("cni: new: aggregation interval must be >= 0 (0 means default; got %d)", cfg.AggregationInterval)
	}
	if cfg.AggregationInterval == 0 {
		cfg.AggregationInterval = 15
	}
	if cfg.AggregationInterval != 15 {
		return nil, fmt.Errorf("cni: new: aggregation interval must be 15s per Goldmane proto (goldmane/proto/api.proto line 100); got %d", cfg.AggregationInterval)
	}
	if cfg.StartTimeGte == nil {
		v := DefaultStartTimeGteReplay
		cfg.StartTimeGte = &v
	} else if *cfg.StartTimeGte > 0 {
		return nil, fmt.Errorf("cni: new: start_time_gte must be <= 0 (negative is relative seconds, zero is 'now' per Goldmane proto goldmane/proto/api.proto line 91); got %d", *cfg.StartTimeGte)
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

// ConsecutiveEOFs returns the count of EOFs from stream.Recv since the
// last successful Recv. Reset to 0 on the next successful Recv. Story
// 1.10 D2 (code-review patch P26): exposed for Story 1.12's Prometheus
// surface so operators can detect a Goldmane-side EOF storm without
// the adapter escalating to CrashLoop.
func (a *Adapter) ConsecutiveEOFs() int64 { return a.consecutiveEOFs.Load() }

// EventsTotal returns the cumulative count of flow events successfully
// published to subjects.RawNetwork. Story 1.12 binds this via
// prometheus.NewCounterFunc to olaitan_sensor_events_total{source="network"}.
func (a *Adapter) EventsTotal() int64 { return a.eventsPublished.Load() }

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
	// panicErr is set by the recover defer below (registered SECOND)
	// and read by the stop-log defer (registered FIRST). Defers run
	// LIFO: stop-log was registered first → runs last → sees the
	// panicErr value the recover defer wrote. Story 1.10 code-review
	// patch P21.
	var panicErr any
	a.log.Info("cni: adapter starting",
		"goldmane_addr", a.cfg.GoldmaneAddr,
		"server_name", a.cfg.ServerName,
		"staleness_timeout", a.cfg.StalenessTimeout)
	// Stop-log defer registered FIRST so it runs LAST on unwind,
	// after the recover defer has populated panicErr.
	defer func() {
		if panicErr != nil {
			a.log.Info("cni: adapter stopped after panic", "panic", panicErr)
		} else {
			a.log.Info("cni: adapter stopped")
		}
	}()
	// Recover defer registered SECOND so it runs FIRST on unwind,
	// sets panicErr, then the stop-log defer above reads it.
	defer func() {
		if r := recover(); r != nil {
			panicErr = r
			a.log.Error("cni: top-level panic",
				"panic", r,
				"stack", string(debug.Stack()))
			a.health.MarkUnhealthy(fmt.Errorf("cni: panic: %v", r))
			// Story 1.9 guardrail 18 / Story 1.10 carry-over: do
			// not re-raise; surface as an error so the errgroup
			// records the failure but does not cancel sibling
			// goroutines.
			err = fmt.Errorf("cni: panic recovered: %v", r)
		}
	}()

	// Mark unhealthy at startup until the first successful Recv
	// flips it.
	a.health.MarkUnhealthy(errors.New("cni: awaiting first flow"))

	// Watchdog goroutine. Cancelled when Run returns. The defer
	// order matters: wdCancel runs first (signals goroutine to
	// exit), then <-watchdogDone awaits actual shutdown. Both run
	// on normal exit AND on panic-recovered exit, so the watchdog
	// never outlives Run regardless of unwind path. Story 1.10
	// code-review patch P12.
	wdCtx, wdCancel := context.WithCancel(ctx)
	watchdogDone := make(chan struct{})
	defer func() { <-watchdogDone }()
	defer wdCancel()
	go func() {
		defer close(watchdogDone)
		a.runStalenessWatchdog(wdCtx)
	}()

	runErr := a.cfg.ConnectRetry.Do(ctx, func(ctx context.Context) error {
		return a.connectAndStream(ctx)
	})

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
	// Bound the stream-open RPC by DialTimeout. The outer ctx is the
	// long-lived adapter context; without a per-open bound a
	// Goldmane in an odd state (TCP up, no stream-server response)
	// would stall the open phase for up to the keepalive window
	// (40s) before recovery. Story 1.10 code-review patches P4 + P5:
	//   - Derive streamCtx from outer ctx and pass to client.Stream
	//     so the timer-fires branch can call streamCancel() and the
	//     in-flight Stream RPC unblocks immediately. The comment
	//     below previously claimed "abandoned via a derived cancel"
	//     but no derived cancel existed; this lands the contract.
	//   - On happy-path stream-open success, the derived cancel is
	//     NOT triggered (stream lifetime spans the full session);
	//     streamCancel is held for cleanup on the error path only.
	//   - Use time.NewTimer + Stop() so the timer is released on the
	//     happy path; time.After leaked a runtime channel per
	//     reconnect.
	type streamResult struct {
		s   grpc.ServerStreamingClient[goldmanepb.FlowResult]
		err error
	}
	streamCtx, streamCancel := context.WithCancel(ctx)
	resultCh := make(chan streamResult, 1)
	go func() {
		s, e := client.Stream(streamCtx, &goldmanepb.FlowStreamRequest{
			StartTimeGte:        *a.cfg.StartTimeGte,
			AggregationInterval: a.cfg.AggregationInterval,
		}, grpc.WaitForReady(true))
		resultCh <- streamResult{s: s, err: e}
	}()
	openTimer := time.NewTimer(a.cfg.DialTimeout)
	var stream grpc.ServerStreamingClient[goldmanepb.FlowResult]
	select {
	case res := <-resultCh:
		if !openTimer.Stop() {
			// Drain if already fired; safe even after a successful
			// stop because a non-stopped timer always has a value
			// pending on the channel.
			select {
			case <-openTimer.C:
			default:
			}
		}
		stream = res.s
		err = res.err
	case <-openTimer.C:
		streamCancel()
		a.health.MarkUnhealthy(fmt.Errorf("cni: stream open timeout after %s", a.cfg.DialTimeout))
		return fmt.Errorf("cni: stream open timeout after %s", a.cfg.DialTimeout)
	case <-ctx.Done():
		if !openTimer.Stop() {
			select {
			case <-openTimer.C:
			default:
			}
		}
		streamCancel()
		return ctx.Err()
	}
	if err != nil {
		streamCancel()
		a.health.MarkUnhealthy(err)
		if isTerminalConnectError(err) {
			return retry.Permanent(fmt.Errorf("cni: stream open (terminal, no retry): %w", err))
		}
		return fmt.Errorf("cni: stream open: %w", err)
	}
	// P25: signal that stream open succeeded so the watchdog can
	// distinguish (streamOpen=false → reconnecting) from
	// (streamOpen=true && lastEventTime=nil → stale-no-flows).
	// Cleared in the deferred cleanup below.
	a.streamOpen.Store(true)
	defer func() {
		a.streamOpen.Store(false)
		// streamCancel is safe to call after a successful stream-open;
		// it ends the stream on Run-ctx unwind. Idempotent.
		streamCancel()
	}()

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
				// Story 1.10 D2 (code-review patch P26): track
				// consecutive EOFs across reconnects. A Goldmane
				// that EOFs every stream is detectable via the
				// counter + log-once WARN, without escalating to
				// retry.Permanent (the adapter keeps reconnecting;
				// quiet-by-design preserved).
				n := a.consecutiveEOFs.Add(1)
				if n >= 5 && a.consecutiveEOFsLogged.CompareAndSwap(false, true) {
					a.log.Warn("cni: consecutive stream EOFs suggest Goldmane is unhealthy",
						"consecutive_eofs", n,
						"goldmane_addr", a.cfg.GoldmaneAddr)
				}
				a.health.MarkUnhealthy(io.EOF)
				return fmt.Errorf("cni: stream eof")
			}
			a.health.MarkUnhealthy(err)
			if isTerminalConnectError(err) {
				return retry.Permanent(fmt.Errorf("cni: stream recv (terminal, no retry): %w", err))
			}
			return fmt.Errorf("cni: stream recv: %w", err)
		}

		// Story 1.10 D2 (P26): any successful Recv resets the EOF
		// counter and re-arms the log-once latch.
		a.consecutiveEOFs.Store(0)
		a.consecutiveEOFsLogged.Store(false)

		// Story 1.10 code-review patch P13: advance lastEventTime on
		// ANY successful Recv, not only after a successful publish.
		// A stream of consistently oversize flows previously left
		// lastEventTime stale, leaving the watchdog blind to the
		// fact that Goldmane is alive. The variable name keeps its
		// "lastEventTime" identity for backwards-compat with metrics
		// readers; semantically it now tracks UPSTREAM bus liveness
		// (Goldmane → adapter), not downstream (adapter → JetStream)
		// publish throughput. Publish failures surface separately
		// via MarkUnhealthy + publishDrops counter.
		nowRecv := a.nowFn()
		a.lastEventTime.Store(&nowRecv)

		if firstFlow {
			// Defer connReady flip until after the first successful
			// Recv. A half-open stream where the TCP handshake
			// completes but Goldmane never sends a flow would
			// otherwise appear Ready to the staleness watchdog.
			a.connReady.Store(true)
			a.health.MarkHealthy()
			a.log.Info("cni: stream connected", "goldmane_addr", a.cfg.GoldmaneAddr)
			firstFlow = false
		}

		ev, terr := Translate(fr, a.cfg.Hostname, a.cfg.MaxEventBytes)
		if terr != nil {
			if errors.Is(terr, ErrEventTooLarge) {
				count := a.oversizeDropped.Add(1)
				// Story 1.10 code-review patch P18 (Story 1.9 P22
				// precedent): rate-limit the ERROR log so a stream
				// of oversize flows does not flood the log volume.
				// Always emit the first drop; thereafter only once
				// per oversizeLogInterval. The counter still
				// increments per drop and the Story 1.12 metrics
				// surface (OversizeDropped()) gives the full picture.
				nowTs := a.nowFn()
				lastTs := a.lastOversizeLog.Load()
				if lastTs == nil || nowTs.Sub(*lastTs) >= oversizeLogInterval {
					a.lastOversizeLog.Store(&nowTs)
					a.log.Error("cni: oversize flow dropped",
						"err", terr,
						"flow_id", fr.GetId(),
						"oversize_dropped_total", count)
				}
				continue
			}
			a.translateErrors.Add(1)
			a.log.Warn("cni: translate skipped malformed flow",
				"err", terr,
				"flow_id", fr.GetId())
			continue
		}

		if perr := a.publishWithRetry(ctx, ev); perr != nil {
			if isPermanentPublishError(perr) {
				a.publishDrops.Add(1)
				a.log.Error("cni: publish dropped (permanent, per-event)",
					"err", perr,
					"event_id", ev.ID,
					"summary_bytes", len(ev.Summary),
					"raw_bytes", len(ev.Raw))
				continue
			}
			a.health.MarkUnhealthy(perr)
			return fmt.Errorf("cni: publish: %w", perr)
		}
		a.eventsPublished.Add(1)

		// Note: lastEventTime now advances on stream.Recv success
		// above (P13). The publish-side update that used to live
		// here was removed because (a) it overwrites the more
		// authoritative Recv-side timestamp and (b) Recv-side
		// tracking is what the staleness watchdog actually wants —
		// "did Goldmane send a flow recently". Downstream publish
		// failures surface via publishDrops + MarkUnhealthy, not
		// via lastEventTime staleness.
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
	return a.cfg.PublishRetry.Do(ctx, func(attemptCtx context.Context) error {
		perAttempt, cancel := context.WithTimeout(attemptCtx, publishAttemptTimeout)
		defer cancel()
		_, err := a.pub.PublishJS(perAttempt, subjects.RawNetwork, ev,
			natsjs.WithMsgID(ev.ID))
		if err == nil {
			return nil
		}
		if isPermanentPublishError(err) {
			return retry.Permanent(err)
		}
		// If the err chain reports DeadlineExceeded but the outer
		// context is still live, the failure is a per-attempt
		// stall (publishAttemptTimeout window fired, or the NATS
		// client returned DeadlineExceeded from its own internal
		// timer). Surface as a non-%w transient error so retry.Do
		// does NOT short-circuit via its errors.Is(... DeadlineExceeded)
		// terminal check. This preserves the strategy's
		// MaxAttempts budget when JetStream stalls a single
		// PublishJS for the full publishAttemptTimeout window.
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			return fmt.Errorf("cni: publish attempt timed out after %s: %v", publishAttemptTimeout, err)
		}
		return err
	})
}

// runStalenessWatchdog distinguishes three states using streamOpen +
// lastEventTime. Story 1.10 D1 (code-review patch P25) refines the
// quiet-by-design pattern from Stories 1.8 / 1.9 so a half-open stream
// (TCP up, no flows ever received) is observable separately from a
// reconnecting source.
//
//   - streamOpen == false                  → reconnecting; no flag.
//     The dial loop owns the operator signal here.
//   - streamOpen == true && lastEventTime
//     == nil && elapsed > Staleness     → info-log "stale-no-flows"
//     (RBAC denial, quiet cluster pre-traffic). NOT MarkUnhealthy:
//     the stream is healthy at the gRPC layer; Goldmane is simply
//     not emitting flows. Logged once per cycle so an operator
//     looking at the source can correlate.
//   - streamOpen == true && lastEventTime
//     stale by > Staleness               → MarkUnhealthy. Goldmane
//     went silent after previously sending flows; this is actionable.
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
	noFlowsLogged := false // log-once latch for stale-no-flows
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !a.streamOpen.Load() {
				// Reconnect path: the connect loop owns the operator
				// signal. Reset the log-once latch so a fresh stream
				// can emit the warning if it goes silent.
				noFlowsLogged = false
				continue
			}
			lastPtr := a.lastEventTime.Load()
			if lastPtr == nil {
				// Stream is open but Goldmane has never sent a flow.
				// On a quiet cluster this is normal; on a misconfigured
				// RBAC it is the only signal we have. Info-log once
				// per stream so the operator can correlate without
				// MarkUnhealthy fighting with the connect-loop signal.
				if !noFlowsLogged {
					a.log.Info("cni: stream open but no flows received within staleness window",
						"staleness", a.cfg.StalenessTimeout,
						"hint", "expected on quiet clusters; check Goldmane RBAC and Calico flow-emission policy if persistent")
					noFlowsLogged = true
				}
				continue
			}
			delta := a.nowFn().Sub(*lastPtr)
			if delta < 0 {
				// Backward clock jump (NTP step). Treat as fresh.
				continue
			}
			if delta <= a.cfg.StalenessTimeout {
				// Reset the no-flows latch once flows resume so a
				// subsequent stall re-arms it.
				noFlowsLogged = false
				continue
			}
			a.health.MarkUnhealthy(fmt.Errorf("cni: no flow for %s after previous flow at %s", a.cfg.StalenessTimeout, lastPtr.Format(time.RFC3339)))
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
		// Distinguish "no PEM block at all" (operator typo, e.g.
		// caBundle: foo) from "PEM block present but malformed"
		// (half-written file during cert-manager rotation). The
		// former is terminal via errCABundleUnparseable so the pod
		// CrashLoops with a clear signal; the latter is transient
		// and the next connect-loop iteration retries.
		if block, _ := pem.Decode(caBytes); block == nil {
			return nil, fmt.Errorf("ca bundle %q: %w", a.cfg.CABundlePath, errCABundleUnparseable)
		}
		return nil, fmt.Errorf("ca bundle %q contained no parseable certificates", a.cfg.CABundlePath)
	}
	certBytes, err := os.ReadFile(a.cfg.ClientCertPath)
	if err != nil {
		return nil, fmt.Errorf("read client cert %q: %w", a.cfg.ClientCertPath, err)
	}
	keyBytes, err := os.ReadFile(a.cfg.ClientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read client key %q: %w", a.cfg.ClientKeyPath, err)
	}
	// Pre-validate PEM-block presence and type. tls.LoadX509KeyPair
	// would surface "tls: failed to find any PEM data" as a generic
	// error; pre-validation gives us a typed sentinel
	// (errTLSNoPEMData) without falling back to substring matching.
	if certBlock, _ := pem.Decode(certBytes); certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("client cert %q: %w", a.cfg.ClientCertPath, errTLSNoPEMData)
	}
	if keyBlock, _ := pem.Decode(keyBytes); keyBlock == nil || !strings.Contains(keyBlock.Type, "PRIVATE KEY") {
		return nil, fmt.Errorf("client key %q: %w", a.cfg.ClientKeyPath, errTLSNoPEMData)
	}
	clientCert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		// tls.X509KeyPair surfaces public-key-mismatch as a generic
		// error with the text "tls: private key does not match
		// public key". Cross-check by parsing the leaf and comparing
		// public keys via x509.MarshalPKIXPublicKey bytes, which is
		// typed-only per the Story 1.7/1.8 invariant.
		leafBlock, _ := pem.Decode(certBytes)
		leaf, lerr := x509.ParseCertificate(leafBlock.Bytes)
		if lerr == nil {
			keyBlock, _ := pem.Decode(keyBytes)
			priv, perr := parsePrivateKey(keyBlock.Bytes, keyBlock.Type)
			if perr == nil {
				leafPubBytes, lerr := x509.MarshalPKIXPublicKey(leaf.PublicKey)
				privPubBytes, perr := x509.MarshalPKIXPublicKey(privPublicKey(priv))
				if lerr == nil && perr == nil && !bytes.Equal(leafPubBytes, privPubBytes) {
					return nil, fmt.Errorf("client cert %q / key %q: %w", a.cfg.ClientCertPath, a.cfg.ClientKeyPath, errTLSCertKeyMismatch)
				}
			}
		}
		return nil, fmt.Errorf("load client cert: %w", err)
	}
	return &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{clientCert},
		ServerName:   a.cfg.ServerName,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// parsePrivateKey decodes a PEM-DER private key, trying PKCS#8 then
// PKCS#1 (RSA) then SEC1 (EC) — mirrors what tls.X509KeyPair tries
// internally. blockType is the PEM block.Type ("PRIVATE KEY", "RSA
// PRIVATE KEY", or "EC PRIVATE KEY"). Returns the parsed key (any) so
// the caller can extract its PublicKey via privPublicKey.
func parsePrivateKey(der []byte, blockType string) (any, error) {
	switch blockType {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(der)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(der)
	default:
		return x509.ParsePKCS8PrivateKey(der)
	}
}

// privPublicKey extracts the public key from an *rsa.PrivateKey,
// *ecdsa.PrivateKey, or ed25519.PrivateKey. Returns nil for unknown
// types (the caller bails out on the bytes.Equal mismatch).
func privPublicKey(priv any) crypto.PublicKey {
	type pubKeyer interface {
		Public() crypto.PublicKey
	}
	if p, ok := priv.(pubKeyer); ok {
		return p.Public()
	}
	return nil
}

// defaultDial dials target with the supplied mTLS credentials,
// blocks (bounded by dialCtx) until the connection reaches
// connectivity.Ready, and returns the established *grpc.ClientConn.
//
// Keepalive parameters force the gRPC client to detect a half-open
// transport by pinging every 30s with a 10s timeout (Story 1.6
// Falco precedent); without these knobs a wedged TCP connection
// appears healthy indefinitely once a stream is open. Note that
// keepalive is dormant between TCP-established and stream-open: the
// gRPC client only pings while at least one RPC is in flight (or
// PermitWithoutStream is true, which it is not here). The dialCtx
// timeout covers the connect / wait-for-ready window where keepalive
// cannot help.
//
// grpc.NewClient is intentionally lazy in modern grpc-go (>= 1.63):
// it does not connect until the first RPC. Without an explicit
// readiness wait the configured DialTimeout would be cosmetic and
// a wrong address or mis-signed cert would surface only as a
// stream error several seconds later. We therefore call cc.Connect
// to exit Idle and loop on cc.WaitForStateChange until the state
// reaches Ready (success), TransientFailure or Shutdown (terminal
// for this attempt), or dialCtx is done. See
// https://github.com/grpc/grpc-go/blob/master/Documentation/anti-patterns.md
// for the grpc-go-maintained list of dial-time mistakes.
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
		// connectivity.Shutdown is terminal: cc.WaitForStateChange
		// returns false immediately on a Shutdown conn, which would
		// loop hot against a closed connection. Surface it as a dial
		// error so the outer connect-loop backs off cleanly.
		if state == connectivity.Shutdown {
			_ = cc.Close()
			return nil, fmt.Errorf("dial: connection shutdown")
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
// The typed checks above are the primary signal. As a last-resort
// fallback (mirroring internal/collector/falco/falco.go:472-475
// across the five adapters), a substring match on "permission
// denied" promotes a transient-coded error to terminal so a wedged
// permission failure CrashLoops loudly instead of looping silently
// at 60s cadence. The substring path runs AFTER the typed checks so
// the typed paths win when both apply.
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
	// gRPC sometimes surfaces unix-socket EACCES or filesystem
	// EACCES as Unavailable with "permission denied" in the message.
	// Mirror the falco / Story 1.6 last-resort substring fallback
	// for cross-adapter parity.
	if strings.Contains(strings.ToLower(err.Error()), "permission denied") {
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
// but not readable; the same logic applies.
//
// Detection is purely typed via errors.As against the three
// stdlib-defined TLS / x509 error types (tls.RecordHeaderError,
// x509.UnknownAuthorityError, x509.CertificateInvalidError) plus
// the package-defined errCABundleUnparseable sentinel. Story 1.7
// patch P7 / Story 1.8 P28 deleted the substring-match path on the
// other adapters because gRPC / TLS error message text is
// locale-/version-fragile.
//
// A half-written PEM file during a cert-manager rotation produces a
// "ca bundle contained no parseable certificates" error WITHOUT the
// errCABundleUnparseable sentinel (because pem.Decode found a block
// header); that case falls through to the transient path so the
// next connect-loop iteration retries.
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
	if errors.Is(err, errCABundleUnparseable) {
		return true
	}
	if errors.Is(err, errTLSNoPEMData) {
		return true
	}
	if errors.Is(err, errTLSCertKeyMismatch) {
		return true
	}
	var rhe tls.RecordHeaderError
	if errors.As(err, &rhe) {
		return true
	}
	var uae x509.UnknownAuthorityError
	if errors.As(err, &uae) {
		return true
	}
	var cie x509.CertificateInvalidError
	return errors.As(err, &cie)
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
