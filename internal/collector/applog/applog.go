package applog

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	natsjs "github.com/nats-io/nats.go/jetstream"
	"golang.org/x/sync/errgroup"

	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/retry"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/sourcehealth"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// natsPublisher is the minimal NATS surface the adapter consumes.
// Mirrors falco / audit / cri so a future SourceAdapter interface
// extraction has consistent surface area.
type natsPublisher interface {
	PublishJS(ctx context.Context, subject string, data any, opts ...natsjs.PublishOpt) (*natsjs.PubAck, error)
}

// HealthReader aliases sourcehealth.Reader so callers in this package's
// namespace can speak the local name. The canonical interface is
// sourcehealth.Reader and is what Adapter.Health returns.
type HealthReader = sourcehealth.Reader

// Config holds the runtime knobs for an Adapter. The shape mirrors
// falco.Config / audit.Config / cri.Config so a future SourceAdapter
// interface extraction has consistent surface area.
type Config struct {
	// StdoutPath is the cooperating application's stdout log file
	// (typically /var/log/app/stdout.log on the shared emptyDir).
	StdoutPath string

	// StderrPath is the cooperating application's stderr log file
	// (typically /var/log/app/stderr.log on the shared emptyDir).
	StderrPath string

	// Pod identifies the workload pod the sidecar is attached to.
	// Populated by the cmd/olaitan/main.go applog-sidecar dispatcher
	// from the downward API at startup; constant per-process.
	Pod schema.PodRef

	// Container is the application (peer) container name. Populated
	// from the OLAITAN_TARGET_CONTAINER env var injected by the
	// admission webhook with the peer container name selected at
	// admission time (see internal/admission/applog.selectPeerContainer).
	// Required and non-empty: New() rejects zero-value Container.
	Container string

	// Labels are the workload pod's labels for the tag-forwarding
	// step. Translate forwards only those under the
	// labelPrefixesAllowed whitelist; the rest are silently dropped.
	// Populated from /etc/podinfo/labels (downward-API projected
	// volume) at startup; nil is legal.
	Labels map[string]string

	// ChannelBuffer is the bounded LineRecord channel capacity. Larger
	// values absorb more burst before shed-mode engages; smaller
	// values are stricter back-pressure under a slow consumer. Default
	// 1024 when zero-valued.
	ChannelBuffer int

	// PublishStallTimeout is the timeout used internally by the
	// shed-state high-water trigger; logging emits a WARN once the
	// trigger fires. Stored on Config for completeness even though
	// the high-water mark itself is computed from ChannelBuffer.
	// Default 5s when zero-valued.
	PublishStallTimeout time.Duration

	// MaxLineBytesOverride lets the operator tune the per-event line
	// cap. Zero uses the default MaxLineBytes (64 KiB). Validate
	// rejects values above MaxLineBytesAbsoluteCap (192 KiB), leaving
	// 64 KiB of headroom below the EVENTS_RAW stream's 256 KiB
	// MaxMsgSize for the Pod, Tags, Summary, and timestamp envelope.
	// effectiveMaxLineBytes also clamps defensively at the same cap.
	MaxLineBytesOverride int

	// PublishRetry is the bounded inner retry for transient NATS
	// publish failures. Defaults to DefaultPublishRetry() when
	// zero-valued.
	PublishRetry retry.Strategy

	// StalenessTimeout is the staleness watchdog's threshold. App-log
	// streams are quiet by design (a stable batch job can run for
	// hours without emitting log lines) so the watchdog only flips
	// MarkUnhealthy when staleness AND a non-EOF reader error coincide
	// in the same window. Defaults to 30m when zero-valued.
	StalenessTimeout time.Duration
}

// DefaultPublishRetry returns the per-publish bounded retry strategy.
// 100ms..1s, 3 attempts, low equal-jitter (0.1) -- combined with the
// per-attempt 2s deadline this caps total transient backoff at ~9s
// before the consumer log+drops and continues. Mirrors
// cri.DefaultPublishRetry exactly.
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
// stalled NATS partition stalls a single PublishJS for ~5s before
// retry 2 starts. Mirrors cri.publishAttemptTimeout exactly.
const publishAttemptTimeout = 2 * time.Second

// Adapter is the application log sidecar adapter. Construct with New;
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
	// stripped Unix-nanosecond representation. Read by the watchdog;
	// nil means "no event ever received".
	lastEventTime atomic.Pointer[time.Time]

	// readerErrAt records the wall-clock time of the most recent
	// non-EOF reader error. The watchdog uses this together with
	// lastEventTime to decide whether staleness is actionable: app-log
	// streams are quiet by design, so staleness alone never trips the
	// watchdog -- only "stale AND a recent reader error" does.
	readerErrAt atomic.Pointer[time.Time]

	// translateErrors counts events that failed translation and were
	// log+dropped. Story 1.12 will bind to a Prometheus counter via
	// Adapter.TranslateErrors().
	translateErrors atomic.Int64

	// publishDrops counts events whose publish attempt returned a
	// permanent error (oversize, JetStream-disabled) OR exhausted the
	// bounded transient retry budget. Either disposition is "this
	// event was dropped, the adapter continues" so the operator
	// surface treats them uniformly. Story 1.12 will bind to a
	// Prometheus counter.
	publishDrops atomic.Int64

	// lostOnShutdown counts events whose publishWithRetry was
	// cancelled mid-flight by ctx.Done() before NATS persisted them.
	// Distinct from publishDrops (which is a per-event terminal
	// decision) because lostOnShutdown is a one-shot shutdown-time
	// loss the operator may want to alarm on separately. Story 1.12
	// will bind to a Prometheus counter.
	lostOnShutdown atomic.Int64

	// shed is the back-pressure shed-state tracker for the line
	// channel. Both reader goroutines share it; the consumer drains
	// the channel.
	shed *shedState

	// nowFn is a test seam.
	nowFn func() time.Time

	// stdoutTailFn / stderrTailFn are test seams: tests substitute
	// runReaderTail with a pipe-backed implementation. Production
	// uses runFileTail with the cooperating application's log files.
	stdoutTailFn func(ctx context.Context, sink chan<- LineRecord) error
	stderrTailFn func(ctx context.Context, sink chan<- LineRecord) error
}

// New constructs an Adapter. nc and log are required; cfg is
// validated. nc may be a *natsclient.Client or any natsPublisher-
// satisfying type (for tests).
func New(cfg Config, nc natsPublisher, log *slog.Logger) (*Adapter, error) {
	if nc == nil {
		return nil, errors.New("applog: new: nats publisher is nil")
	}
	if log == nil {
		log = slog.Default()
	}
	if cfg.StdoutPath == "" {
		return nil, errors.New("applog: new: config.StdoutPath is empty")
	}
	if cfg.StderrPath == "" {
		return nil, errors.New("applog: new: config.StderrPath is empty")
	}
	if cfg.StdoutPath == cfg.StderrPath {
		return nil, errors.New("applog: new: stdout and stderr paths must differ")
	}
	if cfg.Container == "" {
		return nil, errors.New("applog: new: config.Container is empty")
	}
	if cfg.ChannelBuffer < 0 {
		return nil, fmt.Errorf("applog: new: channel buffer must be >= 0 (0 means default; got %d)", cfg.ChannelBuffer)
	}
	if cfg.ChannelBuffer == 0 {
		cfg.ChannelBuffer = 1024
	}
	if cfg.MaxLineBytesOverride < 0 {
		return nil, fmt.Errorf("applog: new: max line bytes must be >= 0 (0 means default; got %d)", cfg.MaxLineBytesOverride)
	}
	if cfg.MaxLineBytesOverride != 0 && cfg.MaxLineBytesOverride < 1024 {
		return nil, fmt.Errorf("applog: new: max line bytes must be >= 1024 when set (got %d)", cfg.MaxLineBytesOverride)
	}
	if cfg.MaxLineBytesOverride > MaxLineBytesAbsoluteCap {
		return nil, fmt.Errorf("applog: new: max line bytes must be <= %d (got %d); the cap leaves envelope headroom below EVENTS_RAW MaxMsgSize", MaxLineBytesAbsoluteCap, cfg.MaxLineBytesOverride)
	}
	if cfg.PublishStallTimeout < 0 {
		return nil, fmt.Errorf("applog: new: publish stall timeout must be >= 0 (got %s)", cfg.PublishStallTimeout)
	}
	if cfg.PublishStallTimeout == 0 {
		cfg.PublishStallTimeout = 5 * time.Second
	}
	if cfg.StalenessTimeout < 0 {
		return nil, fmt.Errorf("applog: new: staleness timeout must be >= 0 (got %s)", cfg.StalenessTimeout)
	}
	if cfg.StalenessTimeout == 0 {
		cfg.StalenessTimeout = 30 * time.Minute
	}
	if cfg.PublishRetry.IsZero() {
		cfg.PublishRetry = DefaultPublishRetry()
	}
	if err := cfg.PublishRetry.Validate(); err != nil {
		return nil, fmt.Errorf("applog: new: publish retry: %w", err)
	}

	a := &Adapter{
		cfg: cfg,
		pub: nc,
		log: log,
		shed: newShedState(cfg.ChannelBuffer).
			withLogger(log).
			withStallTimeout(cfg.PublishStallTimeout),
		nowFn: time.Now,
	}
	// Default tail functions point at runFileTail with the configured
	// paths; tests can replace either via the Adapter's exported
	// hooks.
	a.stdoutTailFn = a.defaultFileTail("stdout", cfg.StdoutPath)
	a.stderrTailFn = a.defaultFileTail("stderr", cfg.StderrPath)
	return a, nil
}

// defaultFileTail returns a closure that invokes runFileTail with the
// configured path and the adapter's per-stream offset counter,
// recBuilder, and shedding state. The closure also threads
// recordReaderErr into runFileTail so per-line tail errors stamp the
// watchdog's recent-error baseline (otherwise only function-return
// errors would stamp, which never fires while t.Lines stays open).
func (a *Adapter) defaultFileTail(stream, path string) func(ctx context.Context, sink chan<- LineRecord) error {
	off := &atomic.Int64{}
	rb := a.recBuilder()
	return func(ctx context.Context, sink chan<- LineRecord) error {
		err := runFileTail(ctx, path, stream, sink, a.shed, off, a.nowFn, rb, a.log, a.recordReaderErr)
		if err != nil {
			a.recordReaderErr()
		}
		return err
	}
}

// recBuilder returns a closure that wraps line bytes into a LineRecord
// using the adapter's configured Pod, Container, and Labels. The
// closure is constructed once and reused for the lifetime of the
// adapter (its captures are constant per process).
func (a *Adapter) recBuilder() func(stream string, line []byte, ts time.Time, offset int64) LineRecord {
	pod := a.cfg.Pod
	container := a.cfg.Container
	labels := a.cfg.Labels
	maxLine := a.cfg.MaxLineBytesOverride
	return func(stream string, line []byte, ts time.Time, offset int64) LineRecord {
		return LineRecord{
			Line:         append([]byte(nil), line...),
			Stream:       stream,
			Timestamp:    ts,
			Pod:          pod,
			Container:    container,
			Offset:       offset,
			Labels:       labels,
			MaxLineBytes: maxLine,
		}
	}
}

// recordReaderErr stamps readerErrAt to the current wall-clock time so
// the staleness watchdog has a recent-error signal to combine with
// staleness. Called from the tail wrappers on non-EOF errors.
func (a *Adapter) recordReaderErr() {
	t := a.nowFn()
	a.readerErrAt.Store(&t)
}

// Health returns the read-only source-health view. Story 1.12 binds
// this to the Prometheus gauge `source_healthy{source="applog"}`
// (FR8). Returning the narrow sourcehealth.Reader interface (rather
// than the concrete *sourcehealth.Tracker) prevents callers outside
// this package from reaching the mutator methods.
func (a *Adapter) Health() sourcehealth.Reader {
	return &a.health
}

// TranslateErrors returns the cumulative count of events that failed
// translation and were log+dropped. Exposed for Story 1.12's
// Prometheus surface.
func (a *Adapter) TranslateErrors() int64 { return a.translateErrors.Load() }

// PublishDrops returns the cumulative count of events whose publish
// attempt returned a permanent error (e.g. oversize). Exposed for
// Story 1.12's Prometheus surface.
func (a *Adapter) PublishDrops() int64 { return a.publishDrops.Load() }

// LinesShed returns the cumulative count of LineRecords dropped due to
// back-pressure shedding under a stalled consumer. Exposed for Story
// 1.12's Prometheus surface.
func (a *Adapter) LinesShed() int64 {
	if a.shed == nil {
		return 0
	}
	return a.shed.LinesShed()
}

// LostOnShutdown returns the cumulative count of events whose
// publishWithRetry was cancelled mid-flight by ctx.Done. Exposed for
// Story 1.12's Prometheus surface.
func (a *Adapter) LostOnShutdown() int64 { return a.lostOnShutdown.Load() }

// Run blocks until ctx is cancelled or every reader goroutine has
// exited. The adapter owns three goroutines under an errgroup: one
// tailer per stream (stdout, stderr) plus a consumer that drains the
// LineRecord channel and publishes.
//
// The top-level defer recover() is the Story 1.9 guardrail (item 18):
// a panicking sidecar must NOT take down the workload pod. A recovered
// panic flips the source unhealthy and Run returns nil so the process
// exits cleanly (exit code 0). The native-sidecar restartPolicy:
// Always then restarts the sidecar without affecting the workload.
func (a *Adapter) Run(ctx context.Context) (runErr error) {
	defer func() {
		if r := recover(); r != nil {
			a.log.Error("applog: top-level panic", "panic", r)
			a.health.MarkUnhealthy(fmt.Errorf("applog: panic: %v", r))
			runErr = nil
		}
	}()

	a.log.Info("applog: adapter starting",
		"stdout_path", a.cfg.StdoutPath,
		"stderr_path", a.cfg.StderrPath,
		"container", a.cfg.Container,
		"pod_name", a.cfg.Pod.Name,
		"pod_namespace", a.cfg.Pod.Namespace,
		"channel_buffer", a.cfg.ChannelBuffer,
		"staleness_timeout", a.cfg.StalenessTimeout)
	defer a.log.Info("applog: adapter stopped")

	// Mark unhealthy at startup until the first successful publish
	// flips it. Mirrors the audit / cri startup contract.
	a.health.MarkUnhealthy(errors.New("applog: awaiting first event"))

	lineCh := make(chan LineRecord, a.cfg.ChannelBuffer)

	g, gctx := errgroup.WithContext(ctx)

	// Watchdog goroutine. Derived from gctx (NOT the outer ctx) so a
	// sibling consume / tail panic that fires errgroup cancellation
	// stops the watchdog atomically. If the watchdog ran off the outer
	// ctx, it could MarkUnhealthy AFTER the panic-recovery's
	// MarkUnhealthy, overwriting the more informative panic message.
	wdCtx, wdCancel := context.WithCancel(gctx)
	defer wdCancel()
	watchdogDone := make(chan struct{})
	go func() {
		defer close(watchdogDone)
		a.runStalenessWatchdog(wdCtx)
	}()

	g.Go(func() error {
		return a.runWithRecover("stdout-tail", func() error { return a.stdoutTailFn(gctx, lineCh) })
	})
	g.Go(func() error {
		return a.runWithRecover("stderr-tail", func() error { return a.stderrTailFn(gctx, lineCh) })
	})
	g.Go(func() error { return a.runWithRecover("consume", func() error { return a.consume(gctx, lineCh) }) })

	err := g.Wait()
	wdCancel()
	<-watchdogDone

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	if errors.Is(err, errPanic) {
		// Panic was already recovered + MarkUnhealthy'd inside
		// runWithRecover; surface a clean nil so the sidecar exits
		// gracefully (Story 1.9 guardrail 18).
		return nil
	}
	if err != nil {
		a.health.MarkUnhealthy(err)
	}
	return err
}

// errPanic is the sentinel error returned from runWithRecover when a
// goroutine panic was caught. Run translates it to nil at the top
// level so the sidecar exits with code 0 (graceful) rather than
// surfacing the panic as a runtime fault. The errgroup uses the
// returned error to cancel sibling goroutines so the whole adapter
// unwinds together.
var errPanic = errors.New("applog: goroutine panic recovered")

// runWithRecover wraps fn so a panic inside any of the adapter's
// goroutines is converted into MarkUnhealthy + a sentinel errPanic
// error, rather than crashing the sidecar process. This is the Story
// 1.9 guardrail item 18 implementation: a sidecar shares the
// workload's failure domain, so a panic in any tail or consume
// goroutine must not take the workload pod down. Returning the
// sentinel from a g.Go body cancels the errgroup's gctx so the other
// goroutines observe cancellation and unwind; Run translates errPanic
// to nil so the process exit code remains 0.
func (a *Adapter) runWithRecover(label string, fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			a.log.Error("applog: goroutine panic", "where", label, "panic", r)
			a.health.MarkUnhealthy(fmt.Errorf("applog: %s panic: %v", label, r))
			err = errPanic
		}
	}()
	return fn()
}

// consume drains the channel; for each LineRecord, calls Translate.
// On Translate error: log at debug level, increment translate_errors,
// continue. On success: call publishWithRetry. The consumer continues
// running until the channel is closed (which happens only on adapter
// shutdown via ctx cancellation; reader goroutines never close the
// channel themselves).
func (a *Adapter) consume(ctx context.Context, lineCh <-chan LineRecord) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case rec, ok := <-lineCh:
			if !ok {
				return nil
			}
			ev, err := Translate(rec)
			if err != nil {
				a.translateErrors.Add(1)
				a.log.Debug("applog: translate skipped malformed line",
					"err", err,
					"stream", rec.Stream,
					"container", rec.Container)
				continue
			}
			if perr := a.publishWithRetry(ctx, ev); perr != nil {
				// Distinguish three failure shapes:
				//  1. ctx already cancelled -- shutdown loss; count
				//     separately and exit the loop cleanly.
				//  2. retry.Permanent terminal -- per-event drop.
				//  3. retry budget exhausted on transient errors --
				//     also drop+continue (treating retry-exhaustion as
				//     a tear-down failure-mode would amplify a
				//     short-lived NATS hiccup into a full sidecar
				//     bounce, losing every in-flight line for the
				//     duration of the restart).
				if errors.Is(perr, context.Canceled) || errors.Is(perr, context.DeadlineExceeded) {
					a.lostOnShutdown.Add(1)
					a.log.Warn("applog: publish lost on shutdown",
						"err", perr,
						"event_id", ev.ID,
						"stream", rec.Stream)
					return nil
				}
				if isPermanentPublishError(perr) {
					a.publishDrops.Add(1)
					a.log.Error("applog: publish dropped (permanent, per-event)",
						"err", perr,
						"event_id", ev.ID,
						"stream", rec.Stream)
					continue
				}
				// Retry budget exhausted on transient errors. Drop and
				// continue. A persistent NATS outage will surface to
				// the operator via the staleness watchdog when no
				// successful publish has stamped lastEventTime for the
				// staleness window AND readerErrAt is also stale.
				a.publishDrops.Add(1)
				a.log.Error("applog: publish dropped (retry budget exhausted)",
					"err", perr,
					"event_id", ev.ID,
					"stream", rec.Stream)
				continue
			}
			// Stamp lastEventTime ONLY after a successful publish so
			// the watchdog cannot be fooled by a sustained permanent
			// error stream (every translate stamping a fresh
			// lastEventTime even though no event reaches JetStream).
			t := a.nowFn()
			a.lastEventTime.Store(&t)
			// First successful publish: flip healthy. Subsequent
			// publishes are no-op-equivalent at the tracker layer
			// (MarkHealthy is idempotent).
			a.health.MarkHealthy()
		}
	}
}

// publishWithRetry attempts to publish ev to subjects.RawAppLog with
// bounded retry. Each attempt is wrapped in a 2s per-attempt deadline
// (publishAttemptTimeout) so a single PublishJS cannot stall past the
// strategy's between-attempts cap. ev.ID is forwarded as the JetStream
// Nats-Msg-Id header so a retry the server already persisted on a
// previous attempt is server-side deduplicated within the stream's
// 2-minute dedup window.
func (a *Adapter) publishWithRetry(ctx context.Context, ev schema.Event) error {
	return a.cfg.PublishRetry.Do(ctx, func(ctx context.Context) error {
		attemptCtx, cancel := context.WithTimeout(ctx, publishAttemptTimeout)
		defer cancel()
		_, err := a.pub.PublishJS(attemptCtx, subjects.RawAppLog, ev,
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
// last successful event exceeds StalenessTimeout AND a non-EOF reader
// error has been recorded within the same window. The "AND" gate is
// the critical design difference from Stories 1.6 (Falco) and 1.7
// (audit): app-log streams are quiet by design, so staleness alone is
// uninformative. This mirrors Story 1.8 (CRI) which has the same
// quiet-by-design contract.
//
// Panics inside this goroutine are caught and surfaced via
// MarkUnhealthy rather than crashing the agent process: a clock-
// dependency or nil-pointer regression should degrade the source, not
// take the whole sidecar pod down.
//
// Returns when ctx is cancelled.
func (a *Adapter) runStalenessWatchdog(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			a.health.MarkUnhealthy(fmt.Errorf("applog: watchdog panic: %v", r))
		}
	}()
	// Period policy: half the staleness window so a flip happens at
	// most one period after the threshold is crossed, but capped at
	// 30 s so an operator-tuned StalenessTimeout above 60 s does not
	// stretch the period beyond useful reactivity, and floored at
	// 100 ms so sub-second StalenessTimeout values (test rigs) still
	// drive the ticker.
	period := a.cfg.StalenessTimeout / 2
	if period <= 0 || period > 30*time.Second {
		period = 30 * time.Second
	}
	if period < 100*time.Millisecond {
		period = 100 * time.Millisecond
	}
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			lastPtr := a.lastEventTime.Load()
			if lastPtr == nil {
				// Never received an event. The startup MarkUnhealthy is
				// authoritative until the first successful publish flips
				// it. Don't fabricate a staleness event.
				continue
			}
			errPtr := a.readerErrAt.Load()
			if errPtr == nil {
				// No reader error has ever been recorded: by-design
				// quiet stretches do not flip unhealthy. This is the
				// load-bearing design-difference test
				// TestRun_StalenessWatchdog_QuietButHealthy_DoesNotFlipUnhealthy.
				continue
			}
			now := a.nowFn()
			delta := now.Sub(*lastPtr)
			if delta < 0 {
				continue
			}
			if delta <= a.cfg.StalenessTimeout {
				continue
			}
			errDelta := now.Sub(*errPtr)
			if errDelta < 0 || errDelta > a.cfg.StalenessTimeout {
				// Reader error is older than the staleness window: not
				// recent enough to indicate a current problem.
				continue
			}
			a.health.MarkUnhealthy(fmt.Errorf("applog: no event for %s and recent reader error", a.cfg.StalenessTimeout))
		}
	}
}

// isPermanentPublishError reports whether err from a JetStream
// PublishJS call is a per-message terminal condition (the message
// itself violates a stream-level invariant or the cluster is in a
// shape where retrying will not succeed) rather than a transient
// transport hiccup. Caller is expected to log+drop the offending
// event and continue.
//
// Detection layers (in order, all typed -- no substring fallback):
//  1. errors.Is(err, nats.ErrMaxPayload) -- typed client-side oversize
//     cap.
//  2. errors.Is(err, nats.ErrNoResponders) -- no JetStream subscriber
//     answered the publish.
//  3. errors.Is(err, natsjs.ErrStreamNotFound) -- the configured
//     stream was deleted out from under us.
//  4. *natsjs.APIError with one of the stream-message-size,
//     stream-not-found, or jetstream-not-enabled error codes.
//
// Mirrors cri.isPermanentPublishError exactly so the four adapters
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
