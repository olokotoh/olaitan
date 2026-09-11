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
// Delivery: Falco does not retry a failed POST, so an alert that arrives
// while NATS is down is lost at Falco. The handler still answers 503 so the
// failure shows up in Falco's own log and in the request metrics here.
package falco

import (
	"context"
	"crypto/subtle"
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

	// PublishRetry is the bounded retry for transient NATS publish
	// failures. Defaults to DefaultPublishRetry() when zero-valued.
	PublishRetry retry.Strategy

	// PublishWallClockBudget caps the total time one alert may spend in
	// publishWithRetry. Default 12s.
	PublishWallClockBudget time.Duration

	// HTTP server timeouts. Defaults: 10s header, 30s read and write,
	// 90s idle (longer than Falco's keep-alive reuse gap). ShutdownGrace
	// is at least PublishWallClockBudget + 1s (13s by default).
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

// DefaultPublishRetry returns the per-publish bounded retry strategy:
// 100ms..1s, 3 attempts. With the 2s per-attempt deadline a transient
// JetStream hiccup costs at most ~9s before the handler answers 503.
func DefaultPublishRetry() retry.Strategy {
	return retry.Strategy{
		Min:         100 * time.Millisecond,
		Max:         1 * time.Second,
		Multiplier:  2.0,
		Jitter:      1.0,
		MaxAttempts: 3,
	}
}

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
	requests          map[string]*atomic.Uint64

	// lastSeenUnixNano is when Falco last proved it was alive. Zero
	// means never.
	lastSeenUnixNano atomic.Int64

	// publishFailing is set by a transient publish failure and cleared
	// only by a successful publish, so a heartbeat cannot mask a NATS
	// outage.
	publishFailing atomic.Bool

	addrMu sync.Mutex
	addr   string

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
	if cfg.PublishWallClockBudget <= 0 {
		cfg.PublishWallClockBudget = 12 * time.Second
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
	// Shutdown must outlast the detached publish budget: Run returning
	// while a handler is still inside PublishJS lets main.go drain NATS
	// under it. A shorter grace is raised rather than honoured.
	if minGrace := cfg.PublishWallClockBudget + time.Second; cfg.ShutdownGrace < minGrace {
		cfg.ShutdownGrace = minGrace
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

// Run binds ListenAddr, serves until ctx is cancelled, then drains
// in-flight requests for ShutdownGrace. A bind failure is returned.
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
		"heartbeat_timeout", a.cfg.HeartbeatTimeout)
	defer a.log.Info("falco: adapter stopped")

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
		return nil
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

	// Detached from the request so Falco hanging up does not abort a
	// publish already in its retry budget; bounded so a stuck NATS
	// cannot orphan the goroutine.
	pubCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), a.cfg.PublishWallClockBudget)
	defer cancel()
	if err := a.publishWithRetry(pubCtx, ev); err != nil {
		if isPermanentPublishError(err) {
			a.publishDrops.Add(1)
			a.log.Error("falco: publish dropped (permanent, per-alert)",
				"err", err, "event_id", ev.ID, "summary_bytes", len(ev.Summary))
			a.respond(w, http.StatusNoContent, "")
			return
		}
		a.publishFailing.Store(true)
		a.health.MarkUnhealthy(fmt.Errorf("falco: publish: %w", err))
		a.log.Warn("falco: publish failed transiently", "err", err, "event_id", ev.ID)
		a.respond(w, http.StatusServiceUnavailable, "publish failed")
		return
	}
	a.eventsPublished.Add(1)
	a.publishFailing.Store(false)
	a.health.MarkHealthy()
	a.respond(w, http.StatusNoContent, "")
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

// publishWithRetry publishes ev to subjects.RawFalco with bounded retry.
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
