// Package falco implements the Olaitan agent's Falco sensor adapter.
//
// Falco POSTs every alert to this adapter over HTTP (Falco's `http_output`
// with `json_output: true`). The adapter authenticates the request,
// decodes the body into the falcopb.Response model, translates it into a
// canonical schema.Event of source=falco / category=syscall, and publishes
// it to subjects.RawFalco with JetStream at-least-once semantics.
//
// Why HTTP and not gRPC: until Story 10.2 the adapter dialled Falco's gRPC
// output over a Unix socket. Falco 0.44.0 removed the gRPC output and
// server (falcosecurity/falco#3798), and every Falco release that runs on
// kernel 7.x is newer than that (falcosecurity/falco#3955). http_output is
// the upstream transport that remains. It also removes the hostPath socket
// mount and the socket-permission sidecar the gRPC path needed.
//
// Authentication: Falco's http_output cannot send custom headers, so the
// shared secret rides in the URL path, /falco/<token>. The chart generates
// the token into the release Secret and hands it to Falco through an
// environment variable that Falco expands inside its config file, so the
// token never appears in a ConfigMap. Comparison is constant-time and the
// token is never logged or echoed.
//
// Liveness: a gRPC stream told the adapter when Falco went away; a series of
// HTTP requests does not. Falco's periodic metrics snapshot (`metrics.enabled`
// with `output_rule: true`) arrives through the same http_output. The adapter
// treats it, and any real alert, as proof Falco is alive, and marks the source
// unhealthy when neither has arrived within HeartbeatTimeout. Snapshots are
// never published as security events.
//
// Health is the AND of two things: Falco is alive, and alerts are getting
// through. A transient publish failure keeps the source unhealthy until a
// publish succeeds; a heartbeat alone cannot clear it, or a NATS outage would
// read healthy between alerts while every alert was lost.
//
// Delivery (issue #135): Falco does not retry a failed POST, so the handler
// must not tie an alert's fate to NATS being up at that moment. It answers
// 204 once the alert is in a bounded in-memory queue (BufferMaxAlerts and
// BufferMaxBytes, 4096 alerts and 16 MiB by default). One worker drains the
// queue in arrival order and retries each alert with backoff until NATS takes
// it. When a new alert does not fit, the oldest queued alerts are dropped and
// counted (BufferDropped). On shutdown the listener stops first, then the
// worker drains for up to ShutdownDrain and whatever is left is logged and
// counted (ShutdownLost). The queue is in memory, so a collector crash still
// loses what it holds; a disk-backed queue would be the next step.
package falco

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	natsjs "github.com/nats-io/nats.go/jetstream"

	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/ratelimit"
	"github.com/olokotoh/olaitan/internal/retry"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/sourcehealth"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// pathPrefix is the route Falco posts to; the token follows it.
const pathPrefix = "/falco/"

// MinTokenLength is the shortest shared secret New accepts. The chart
// generates 32 characters; anything under 16 is a placeholder.
const MinTokenLength = 16

// ResponseCodes is every status code the handler writes. The metrics layer
// registers one series per code up front, so a code that has not happened
// yet reads 0 rather than being absent.
var ResponseCodes = []string{"204", "400", "401", "404", "405", "413", "415", "503"}

// natsPublisher is the minimal NATS surface the adapter consumes.
// *natsclient.Client (the production type) satisfies this implicitly,
// and tests can supply a stub. The variadic opts let callers pass
// jetstream.WithMsgID for server-side dedup on retry.
type natsPublisher interface {
	PublishJS(ctx context.Context, subject string, data any, opts ...natsjs.PublishOpt) (*natsjs.PubAck, error)
}

// HealthReader is preserved as an alias for callers that already speak
// the falco-package name. The canonical interface is sourcehealth.Reader,
// which Adapter.Health returns directly.
type HealthReader = sourcehealth.Reader

// Config holds the runtime knobs for an Adapter.
type Config struct {
	// ListenAddr is the host:port the receiver binds. The chart sets it
	// from falcoIngest.containerPort.
	ListenAddr string

	// Token is the shared secret Falco puts in the URL path. Required,
	// at least MinTokenLength characters, and must not contain '/'.
	Token string

	// Hostname is the node-level identifier the adapter records on every
	// emitted Event.Pod.Node. The collector subcommand reads
	// K8S_NODE_NAME from the downward API and passes it here.
	Hostname string

	// MaxPayloadBytes caps one request body. A Falco alert is a few KiB
	// and a metrics snapshot about 4 KiB; the 1 MiB default fails a
	// runaway rule loudly (413) instead of buffering it. The EVENTS_RAW
	// stream enforces its own per-message cap after translation.
	MaxPayloadBytes int64

	// HeartbeatTimeout is how long without a metrics snapshot or an
	// alert before the source is marked unhealthy. Default 3m, three
	// times the chart's 1m Falco metrics interval.
	HeartbeatTimeout time.Duration

	// PublishRetry is the worker's backoff between publish attempts for
	// one alert. Defaults to DefaultPublishRetry() when zero-valued. With
	// MaxAttempts > 0 the worker still does not give up on the alert: it
	// waits Max and runs the strategy again. Only a permanent error or
	// shutdown ends the retries.
	PublishRetry retry.Strategy

	// BufferMaxAlerts and BufferMaxBytes bound the queue between the
	// handler and the publish worker (issue #135). Bytes are the
	// marshalled event size. Defaults 4096 and 16 MiB. The alert the
	// worker is publishing is outside both bounds.
	BufferMaxAlerts int
	BufferMaxBytes  int

	// ShutdownDrain is how long shutdown keeps publishing what the queue
	// holds after the listener has stopped. Default 10s, so 5s HTTP grace
	// plus this plus main.go's 10s NATS drain fits the pod's 30s
	// termination grace.
	ShutdownDrain time.Duration

	// HTTP server timeouts. Defaults: 10s header, 30s read and write,
	// 90s idle (longer than Falco's keep-alive reuse gap), 5s shutdown
	// grace (handlers only enqueue, so they finish at once).
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownGrace     time.Duration

	// RateLimit is the Story 1.13 per-source per-node circuit breaker the
	// adapter consults before every publish. Nil means a disabled
	// fallback limiter is constructed in New(); main.go owns the
	// production instance so the hot-reload callback can retune it.
	RateLimit *ratelimit.Limiter
}

// DefaultPublishRetry returns the worker's retry strategy: 100ms doubling
// to 2s with full jitter, no attempt limit. The 2s cap means the queue
// starts draining within about 2s of NATS coming back.
func DefaultPublishRetry() retry.Strategy {
	return retry.Strategy{
		Min:         100 * time.Millisecond,
		Max:         2 * time.Second,
		Multiplier:  2.0,
		Jitter:      1.0,
		MaxAttempts: 0,
	}
}

// Buffer defaults (issue #135).
const (
	DefaultBufferMaxAlerts = 4096
	DefaultBufferMaxBytes  = 16 << 20
)

// publishAttemptTimeout caps a single PublishJS attempt so a NATS
// partition cannot hold one attempt for JetStream's ~5s ack wait.
const publishAttemptTimeout = 2 * time.Second

// Adapter is the Falco http_output receiver. Construct with New, run with
// Run, observe with Health and the counter readers.
type Adapter struct {
	cfg    Config
	pub    natsPublisher
	log    *slog.Logger
	health SourceHealth

	limiter *ratelimit.Limiter

	// Counters are the single source of truth the metrics layer reads
	// (guardrail 26: the metrics layer never owns a writeable counter).
	eventsPublished   atomic.Int64
	alertsReceived    atomic.Int64
	heartbeats        atomic.Int64
	droppedBySampling atomic.Int64
	publishDrops      atomic.Int64
	bufferDropped     atomic.Int64
	shutdownLost      atomic.Int64
	requests          map[string]*atomic.Uint64

	// buf is the bounded queue the handler fills and the worker drains.
	buf *alertBuffer

	// dropEpisode is set by the first buffer drop after a successful
	// publish, so a full buffer logs once per outage, not once per alert.
	dropEpisode atomic.Bool

	// lastSeenUnixNano is when Falco last proved it was alive. Zero
	// means never.
	lastSeenUnixNano atomic.Int64

	// publishFailing is set by a transient publish failure and cleared
	// only by a successful publish, so a heartbeat cannot mask a NATS
	// outage.
	publishFailing atomic.Bool

	addrMu sync.Mutex
	addr   string

	// seq serialises everything after decode: the liveness mark, the rate
	// limiter and the enqueue, so alerts queue in the order the breaker
	// saw them. Health after a publish is written only by the single
	// worker, so a late failure cannot overwrite a later success.
	seq sync.Mutex

	nowFn func() time.Time
}

// New constructs an Adapter. nc is required; cfg is validated.
func New(cfg Config, nc natsPublisher, log *slog.Logger) (*Adapter, error) {
	if nc == nil {
		return nil, errors.New("falco: new: nats publisher is nil")
	}
	if log == nil {
		log = slog.Default()
	}
	if cfg.ListenAddr == "" {
		return nil, errors.New("falco: new: config.ListenAddr is empty")
	}
	if cfg.Hostname == "" {
		return nil, errors.New("falco: new: config.Hostname is empty")
	}
	if len(cfg.Token) < MinTokenLength {
		return nil, fmt.Errorf("falco: new: config.Token must be at least %d characters (got %d)", MinTokenLength, len(cfg.Token))
	}
	if strings.ContainsAny(cfg.Token, "/?#% \t\r\n") {
		return nil, errors.New("falco: new: config.Token must be a single URL path segment")
	}
	if cfg.MaxPayloadBytes <= 0 {
		cfg.MaxPayloadBytes = 1 << 20
	}
	if cfg.HeartbeatTimeout <= 0 {
		cfg.HeartbeatTimeout = 3 * time.Minute
	}
	if cfg.BufferMaxAlerts < 0 || cfg.BufferMaxBytes < 0 {
		return nil, errors.New("falco: new: buffer bounds must not be negative")
	}
	if cfg.BufferMaxAlerts == 0 {
		cfg.BufferMaxAlerts = DefaultBufferMaxAlerts
	}
	if cfg.BufferMaxBytes == 0 {
		cfg.BufferMaxBytes = DefaultBufferMaxBytes
	}
	if cfg.ShutdownDrain <= 0 {
		cfg.ShutdownDrain = 10 * time.Second
	}
	if cfg.ReadHeaderTimeout <= 0 {
		cfg.ReadHeaderTimeout = 10 * time.Second
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = 30 * time.Second
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = 30 * time.Second
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 90 * time.Second
	}
	if cfg.ShutdownGrace <= 0 {
		cfg.ShutdownGrace = 5 * time.Second
	}
	if cfg.PublishRetry.IsZero() {
		cfg.PublishRetry = DefaultPublishRetry()
	}
	if err := cfg.PublishRetry.Validate(); err != nil {
		return nil, fmt.Errorf("falco: new: publish retry: %w", err)
	}
	limiter := cfg.RateLimit
	if limiter == nil {
		fallback, err := ratelimit.New(ratelimit.Options{
			Source:  string(schema.SourceFalco),
			Enabled: false,
		})
		if err != nil {
			return nil, fmt.Errorf("falco: new: rate-limit fallback: %w", err)
		}
		limiter = fallback
	}
	requests := make(map[string]*atomic.Uint64, len(ResponseCodes))
	for _, c := range ResponseCodes {
		requests[c] = new(atomic.Uint64)
	}
	a := &Adapter{
		cfg:      cfg,
		pub:      nc,
		log:      log,
		limiter:  limiter,
		requests: requests,
		buf:      newAlertBuffer(cfg.BufferMaxAlerts, cfg.BufferMaxBytes),
		nowFn:    time.Now,
	}
	a.health.MarkUnhealthy(errors.New("falco: no heartbeat or alert received from Falco yet"))
	return a, nil
}

// Health returns the read-only source-health view, bound by the metrics
// layer to source_healthy{source="falco"} (FR8).
func (a *Adapter) Health() sourcehealth.Reader { return &a.health }

// EventsTotal is the cumulative count of events published to
// subjects.RawFalco (olaitan_sensor_events_total{source="falco"}).
func (a *Adapter) EventsTotal() int64 { return a.eventsPublished.Load() }

// AlertsReceivedTotal is the cumulative count of authenticated, decodable
// alerts, published or not. The gap to EventsTotal is what sampling and
// publish failures cost.
func (a *Adapter) AlertsReceivedTotal() int64 { return a.alertsReceived.Load() }

// HeartbeatsTotal is the cumulative count of Falco metrics snapshots.
func (a *Adapter) HeartbeatsTotal() int64 { return a.heartbeats.Load() }

// EngagedTotal is the cumulative count of rate-limit breaker engagements.
func (a *Adapter) EngagedTotal() int64 { return a.limiter.EngagedTotal() }

// DroppedBySampling is the cumulative count of alerts the engaged breaker
// dropped.
func (a *Adapter) DroppedBySampling() int64 { return a.droppedBySampling.Load() }

// PublishDrops is the cumulative count of alerts dropped on a permanent
// publish error (for example over the stream's per-message cap).
func (a *Adapter) PublishDrops() int64 { return a.publishDrops.Load() }

// BufferDropped is the cumulative count of alerts dropped because the
// queue was full (the oldest go first) or because one alert was larger
// than the whole byte bound.
func (a *Adapter) BufferDropped() int64 { return a.bufferDropped.Load() }

// BufferDepth is the number of alerts queued for publish, not counting
// the one the worker is publishing.
func (a *Adapter) BufferDepth() int64 { n, _ := a.buf.stats(); return int64(n) }

// BufferBytes is the marshalled size of the queued alerts.
func (a *Adapter) BufferBytes() int64 { _, b := a.buf.stats(); return int64(b) }

// ShutdownLost is how many queued alerts shutdown could not publish
// within ShutdownDrain. They are also logged at Error.
func (a *Adapter) ShutdownLost() int64 { return a.shutdownLost.Load() }

// RequestsByCode is the cumulative count of responses with the given
// status code. Codes outside ResponseCodes read 0.
func (a *Adapter) RequestsByCode(code string) uint64 {
	if c := a.requests[code]; c != nil {
		return c.Load()
	}
	return 0
}

// Limiter returns the rate-limit breaker so main.go's hot-reload callback
// can retune it without a restart (FR49).
func (a *Adapter) Limiter() *ratelimit.Limiter { return a.limiter }

// Addr is the bound listen address once Run has started, or "".
func (a *Adapter) Addr() string {
	a.addrMu.Lock()
	defer a.addrMu.Unlock()
	return a.addr
}

// Handler returns the adapter's HTTP handler. Run serves it; tests call
// it directly.
func (a *Adapter) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(pathPrefix, a.handleAlert)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		a.respond(w, http.StatusNotFound, "not found")
	})
	return mux
}

// Run binds ListenAddr, starts the publish worker, and serves until ctx is
// cancelled. Shutdown stops the listener (ShutdownGrace), closes the queue,
// then lets the worker drain it for up to ShutdownDrain; the remainder is
// counted in ShutdownLost. A bind failure is returned.
func (a *Adapter) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", a.cfg.ListenAddr)
	if err != nil {
		a.health.MarkUnhealthy(err)
		return fmt.Errorf("falco: listen %q: %w", a.cfg.ListenAddr, err)
	}
	a.addrMu.Lock()
	a.addr = ln.Addr().String()
	a.addrMu.Unlock()
	a.log.Info("falco: http_output receiver listening",
		"addr", a.addr,
		"hostname", a.cfg.Hostname,
		"heartbeat_timeout", a.cfg.HeartbeatTimeout,
		"buffer_max_alerts", a.cfg.BufferMaxAlerts,
		"buffer_max_bytes", a.cfg.BufferMaxBytes)
	defer a.log.Info("falco: adapter stopped")

	// The worker gets its own context: it must outlive ctx to drain the
	// queue after the listener stops.
	workerCtx, stopWorker := context.WithCancel(context.Background())
	defer stopWorker()
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		a.runWorker(workerCtx)
	}()

	srv := &http.Server{
		Handler:           a.Handler(),
		ReadHeaderTimeout: a.cfg.ReadHeaderTimeout,
		ReadTimeout:       a.cfg.ReadTimeout,
		WriteTimeout:      a.cfg.WriteTimeout,
		IdleTimeout:       a.cfg.IdleTimeout,
		// Keep the default server's "http: TLS handshake error" noise
		// and friends out of stderr; route it through the adapter log.
		ErrorLog: slog.NewLogLogger(a.log.Handler(), slog.LevelWarn),
	}

	wdCtx, wdCancel := context.WithCancel(ctx)
	defer wdCancel()
	go a.runStalenessWatchdog(wdCtx)

	serveErr := make(chan error, 1)
	go func() {
		err := srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()

	select {
	case err := <-serveErr:
		a.drainOnShutdown(stopWorker, workerDone)
		if err != nil {
			a.health.MarkUnhealthy(err)
			return fmt.Errorf("falco: serve: %w", err)
		}
		return nil
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), a.cfg.ShutdownGrace)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			a.log.Warn("falco: shutdown grace expired", "err", err)
		}
		<-serveErr
		a.drainOnShutdown(stopWorker, workerDone)
		return nil
	}
}

// drainOnShutdown closes the queue so no new alert is accepted, gives the
// worker ShutdownDrain to publish what is left, then counts and logs any
// alert it could not publish. It returns once the worker has exited, so
// main.go never closes NATS under a publish.
func (a *Adapter) drainOnShutdown(stopWorker context.CancelFunc, workerDone <-chan struct{}) {
	a.buf.close()
	queued, _ := a.buf.stats()
	timer := time.AfterFunc(a.cfg.ShutdownDrain, stopWorker)
	<-workerDone
	timer.Stop()
	var lost int64
	for {
		if _, ok := a.buf.tryTake(); !ok {
			break
		}
		lost++
	}
	if lost > 0 {
		a.shutdownLost.Add(lost)
		a.log.Error("falco: shutdown lost buffered alerts that NATS did not accept in time",
			"lost", lost, "drain_budget", a.cfg.ShutdownDrain)
		return
	}
	if queued > 0 {
		a.log.Info("falco: shutdown drained the alert buffer", "alerts", queued)
	}
}

// handleAlert serves POST /falco/<token>.
func (a *Adapter) handleAlert(w http.ResponseWriter, r *http.Request) {
	// Authenticate before looking at anything else, so an unauthenticated
	// caller learns nothing about how the body would have been handled.
	got := strings.TrimPrefix(r.URL.Path, pathPrefix)
	if subtle.ConstantTimeCompare([]byte(got), []byte(a.cfg.Token)) != 1 {
		a.log.Warn("falco: rejected request with a missing or wrong token",
			"remote", r.RemoteAddr)
		a.respond(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if r.Method != http.MethodPost {
		a.respond(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		// Falco sends text/plain when json_output is off. The chart
		// turns it on; this names the fix if someone turns it off.
		a.log.Warn("falco: rejected non-JSON alert; is Falco's json_output enabled?",
			"content_type", r.Header.Get("Content-Type"))
		a.respond(w, http.StatusUnsupportedMediaType, "unsupported media type")
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, a.cfg.MaxPayloadBytes))
	_ = r.Body.Close()
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			a.log.Warn("falco: rejected oversize alert", "max_bytes", a.cfg.MaxPayloadBytes)
			a.respond(w, http.StatusRequestEntityTooLarge, "payload too large")
			return
		}
		a.respond(w, http.StatusBadRequest, "bad request")
		return
	}

	resp, err := DecodeHTTPOutput(body)
	if err != nil {
		a.log.Warn("falco: rejected undecodable alert", "err", err)
		a.respond(w, http.StatusBadRequest, "bad request")
		return
	}

	a.seq.Lock()
	defer a.seq.Unlock()

	// Anything well-formed from Falco proves it is alive.
	a.sawFalco()
	if resp.GetSource() == internalSource && resp.GetRule() == metricsSnapshotRule {
		a.heartbeats.Add(1)
		a.respond(w, http.StatusNoContent, "")
		return
	}
	a.alertsReceived.Add(1)

	ev, err := Translate(resp, a.cfg.Hostname)
	if err != nil {
		a.log.Warn("falco: translate rejected alert", "err", err, "rule", resp.GetRule())
		a.respond(w, http.StatusBadRequest, "bad request")
		return
	}

	// Story 1.13: per-source rate-limit circuit breaker. Sampled-out
	// alerts are counted and acknowledged; Falco has nothing to retry.
	d := a.limiter.Allow(ev.ID)
	if !d.Publish {
		a.droppedBySampling.Add(1)
		a.respond(w, http.StatusNoContent, "")
		return
	}
	if d.Sampled {
		ev.Sampled = true
		ev.SamplingRate = d.SamplingRate
	}

	size, err := marshalledSize(ev)
	if err != nil {
		a.log.Error("falco: alert does not marshal", "err", err, "rule", resp.GetRule())
		a.respond(w, http.StatusBadRequest, "bad request")
		return
	}
	if size > a.cfg.BufferMaxBytes {
		// Can never fit, even in an empty queue. Counted with the other
		// buffer drops; the queue is left alone.
		a.bufferDropped.Add(1)
		a.log.Error("falco: alert larger than the whole buffer byte bound, dropped",
			"event_id", ev.ID, "bytes", size, "max_bytes", a.cfg.BufferMaxBytes, "rule", resp.GetRule())
		a.respond(w, http.StatusNoContent, "")
		return
	}
	dropped, ok := a.buf.push(bufferedAlert{ev: ev, size: size})
	if !ok {
		// Shutdown has begun. Falco logs the 503, so the loss is visible
		// on both sides.
		a.respond(w, http.StatusServiceUnavailable, "shutting down")
		return
	}
	if dropped > 0 {
		a.bufferDropped.Add(int64(dropped))
		if a.dropEpisode.CompareAndSwap(false, true) {
			depth, bytes := a.buf.stats()
			a.log.Error("falco: alert buffer full, dropping the oldest alerts; is NATS down? (logged once per outage, see olaitan_sensor_falco_buffer_dropped_total)",
				"depth", depth, "bytes", bytes,
				"max_alerts", a.cfg.BufferMaxAlerts, "max_bytes", a.cfg.BufferMaxBytes)
		}
	}
	a.respond(w, http.StatusNoContent, "")
}

// marshalledSize is the size of ev as PublishJS will send it.
func marshalledSize(ev schema.Event) (int, error) {
	b, err := json.Marshal(ev)
	return len(b), err
}

// runWorker publishes queued alerts one at a time, in order, until ctx
// ends or the queue is closed and empty. An alert it was holding when ctx
// ended goes back to the head of the queue so shutdown can count it.
func (a *Adapter) runWorker(ctx context.Context) {
	for {
		it, ok := a.buf.take(ctx)
		if !ok {
			return
		}
		if !a.deliver(ctx, it.ev) {
			a.buf.requeue(it)
			return
		}
	}
}

// deliver publishes ev until NATS takes it or rejects it permanently (both
// return true), or ctx ends (false). A transient failure marks the source
// unhealthy at once; only a success clears it.
func (a *Adapter) deliver(ctx context.Context, ev schema.Event) bool {
	for {
		err := a.publishWithRetry(ctx, ev)
		switch {
		case err == nil:
			// Health first, then the counter, so a reader that sees the
			// count also sees the health it implies.
			if a.publishFailing.Swap(false) {
				depth, _ := a.buf.stats()
				a.log.Info("falco: publishing again after a NATS failure", "queued", depth)
			}
			a.dropEpisode.Store(false)
			a.health.MarkHealthy()
			a.eventsPublished.Add(1)
			return true
		case isPermanentPublishError(err):
			a.publishDrops.Add(1)
			a.log.Error("falco: publish dropped (permanent, per-alert)",
				"err", err, "event_id", ev.ID, "summary_bytes", len(ev.Summary))
			return true
		case ctx.Err() != nil:
			return false
		}
		// A strategy with MaxAttempts gave up on this round. The alert
		// is not dropped; wait the backoff cap and go again.
		select {
		case <-ctx.Done():
			return false
		case <-time.After(a.cfg.PublishRetry.Max):
		}
	}
}

// markPublishFailing records a transient publish failure. It logs only on
// the transition, so an outage is one Warn, not one per retry.
func (a *Adapter) markPublishFailing(err error, ev schema.Event) {
	a.health.MarkUnhealthy(fmt.Errorf("falco: publish: %w", err))
	if !a.publishFailing.Swap(true) {
		depth, _ := a.buf.stats()
		a.log.Warn("falco: publish failing, holding alerts in the buffer and retrying",
			"err", err, "event_id", ev.ID, "queued", depth)
	}
}

// sawFalco records that Falco is alive. It marks the source healthy only
// when publishes are not failing: Falco being up says nothing about
// whether its alerts reach NATS.
func (a *Adapter) sawFalco() {
	a.lastSeenUnixNano.Store(a.nowFn().UnixNano())
	if !a.publishFailing.Load() {
		a.health.MarkHealthy()
	}
}

func (a *Adapter) respond(w http.ResponseWriter, code int, msg string) {
	if c := a.requests[strconv.Itoa(code)]; c != nil {
		c.Add(1)
	}
	if code == http.StatusNoContent {
		w.WriteHeader(code)
		return
	}
	http.Error(w, msg, code)
}

// runStalenessWatchdog calls checkStaleness every quarter timeout until
// ctx is cancelled.
func (a *Adapter) runStalenessWatchdog(ctx context.Context) {
	t := time.NewTicker(a.cfg.HeartbeatTimeout / 4)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.checkStaleness()
		}
	}
}

// checkStaleness marks the source unhealthy when Falco has been silent
// for longer than HeartbeatTimeout. It only overrides a healthy state, so
// a more specific reason (a failing publish) is not replaced. A backward
// clock step reads as fresh rather than fabricating an outage.
func (a *Adapter) checkStaleness() {
	last := a.lastSeenUnixNano.Load()
	if last == 0 {
		return
	}
	silent := a.nowFn().Sub(time.Unix(0, last))
	if silent <= a.cfg.HeartbeatTimeout {
		return
	}
	if healthy, _ := a.health.Status(); !healthy {
		return
	}
	a.health.MarkUnhealthy(fmt.Errorf("falco: no heartbeat or alert for %s (timeout %s); is Falco running and is http_output pointed at this collector?",
		silent.Round(time.Second), a.cfg.HeartbeatTimeout))
}

// publishWithRetry publishes ev to subjects.RawFalco with the retry strategy.
// ev.ID travels as the Nats-Msg-Id header, so a retry the server already
// persisted is deduplicated within the stream's window. A permanent
// server-side error exits the retry loop at once.
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
		if ctx.Err() == nil {
			a.markPublishFailing(err, ev)
		}
		return err
	})
}

// isPermanentPublishError returns true when err from a JetStream
// PublishJS call is a per-message terminal condition (the message
// itself violates a stream-level invariant) rather than a transient
// transport hiccup. JetStream's wording varies across nats-server
// versions, so match the stable phrase fragments.
func isPermanentPublishError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "maximum payload") ||
		strings.Contains(msg, "max payload") ||
		strings.Contains(msg, "message size exceeded") ||
		strings.Contains(msg, "max msg size") ||
		strings.Contains(msg, "payload too big")
}

// compile-time assertion: *natsclient.Client satisfies natsPublisher.
var _ natsPublisher = (*natsclient.Client)(nil)
