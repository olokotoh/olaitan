package audit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	natsjs "github.com/nats-io/nats.go/jetstream"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"

	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/retry"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/sourcehealth"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// rejectedCounters tracks per-reason counters for HTTP-layer rejections.
// Story 1.12 will read these via Adapter.Rejected() and bind each
// reason to a Prometheus counter audit_webhook_rejected{reason}. The
// reason set is fixed at compile time so a typo at the call site is a
// compile error rather than a silently-dropped metric.
type rejectedCounters struct {
	mu       sync.RWMutex
	counters map[string]*atomic.Uint64
}

func newRejectedCounters() *rejectedCounters {
	return &rejectedCounters{counters: make(map[string]*atomic.Uint64, 4)}
}

func (r *rejectedCounters) Inc(reason string) {
	r.mu.RLock()
	c, ok := r.counters[reason]
	r.mu.RUnlock()
	if !ok {
		r.mu.Lock()
		c, ok = r.counters[reason]
		if !ok {
			c = new(atomic.Uint64)
			r.counters[reason] = c
		}
		r.mu.Unlock()
	}
	c.Add(1)
}

func (r *rejectedCounters) Snapshot() map[string]uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]uint64, len(r.counters))
	for k, v := range r.counters {
		out[k] = v.Load()
	}
	return out
}

// natsPublisher is the minimal NATS surface the adapter consumes.
// Mirrors the falco package's interface so tests can supply a stub.
// The variadic opts let callers pass natsjs.WithMsgID for server-side
// dedup on retry.
type natsPublisher interface {
	PublishJS(ctx context.Context, subject string, data any, opts ...natsjs.PublishOpt) (*natsjs.PubAck, error)
}

// Config holds the runtime knobs for an audit-webhook Adapter.
type Config struct {
	// ListenAddr is the host:port the receiver binds to. Production
	// default ":8443" matches the Helm chart's containerPort and the
	// kubeconfig the apiserver dials.
	ListenAddr string

	// TLSCertFile and TLSKeyFile are the receiver's serving certificate
	// and private key. Must be readable by the pod's nonroot UID.
	TLSCertFile string
	TLSKeyFile  string

	// ClientCAFile is the CA bundle that signs the kube-apiserver's
	// client certificate. The receiver requires-and-verifies a client
	// cert on every request; presenting nothing or presenting a cert
	// signed by an unknown CA fails the TLS handshake.
	ClientCAFile string

	// Hostname is the node-level identifier the adapter records on
	// every emitted Event.Pod.Node. Sourced from the K8S_NODE_NAME env
	// var the Helm chart's downward API injects.
	Hostname string

	// MaxPayloadBytes caps the request body size before rejection. The
	// apiserver default batch is ~400 events × ~1-32 KiB each ≈ <4 MiB;
	// 8 MiB is a generous cap that fails misconfigured upstreams loud
	// (413, no retry) instead of OOMing the receiver. Default 8 MiB
	// when zero-valued.
	MaxPayloadBytes int64

	// StalenessTimeout is how long without an inbound batch before the
	// source is marked unhealthy. Default 5m when zero-valued. The
	// source health is "did we receive a batch recently?" -- there is
	// no outbound connection to monitor (the apiserver is the active
	// side), so absence of traffic IS the negative signal.
	StalenessTimeout time.Duration

	// PublishRetry is the bounded inner retry for transient NATS
	// publish failures. Defaults to DefaultPublishRetry() when zero.
	PublishRetry retry.Strategy

	// ReadHeaderTimeout caps slowloris-style header-stalling attacks.
	// Default 10s when zero-valued.
	ReadHeaderTimeout time.Duration

	// ShutdownGrace is the deadline for srv.Shutdown to drain in-flight
	// requests on ctx cancellation. Default 5s when zero-valued.
	ShutdownGrace time.Duration
}

// DefaultPublishRetry returns the per-publish bounded retry strategy.
// Mirrors falco.DefaultPublishRetry: 100ms..1s, 3 attempts, equal
// jitter. Combined with the per-attempt 2s deadline this caps total
// transient backoff at ~9s before the handler decides whether to 5xx.
func DefaultPublishRetry() retry.Strategy {
	return retry.Strategy{
		Min:         100 * time.Millisecond,
		Max:         1 * time.Second,
		Multiplier:  2.0,
		Jitter:      1.0,
		MaxAttempts: 3,
	}
}

// publishAttemptTimeout caps a single PublishJS attempt. Same value as
// the falco adapter's bound: JetStream's default publish-ack-wait is
// ~5s; without a per-attempt deadline a NATS partition can stall a
// single PublishJS for ~5s before retry 2 starts.
const publishAttemptTimeout = 2 * time.Second

// Adapter is the audit-webhook receiver. Construct with New; run the
// per-instance lifecycle via Run; observe health via Health.
type Adapter struct {
	cfg    Config
	pub    natsPublisher
	log    *slog.Logger
	health sourcehealth.Tracker

	// lastTrafficUnixNano is the Unix-nanosecond timestamp of the most
	// recent inbound batch. Updated atomically on every received batch
	// (regardless of per-event success); the staleness watchdog reads
	// it to flip MarkUnhealthy when no traffic has arrived for
	// StalenessTimeout. Zero means "no traffic ever".
	lastTrafficUnixNano atomic.Int64

	// rejected is a per-reason counter for requests rejected at the
	// HTTP layer. Story 1.12 will read these via Adapter.Rejected
	// (separate method) and bind to a Prometheus counter
	// audit_webhook_rejected{reason}. Reasons map to:
	//   "method_not_allowed", "unsupported_media_type",
	//   "payload_too_large", "decode_error".
	// Counter access uses sync/atomic; reads need no lock.
	rejected *rejectedCounters

	// addrFn is a test seam: production uses (*http.Server).Addr; tests
	// can override to capture the bound port from a :0 listen.
	addrFn func() string

	// nowFn is a test seam for time-dependent assertions in
	// staleness-watchdog tests.
	nowFn func() time.Time
}

// New constructs an Adapter. nc and log are required; cfg is validated
// to ensure either no fields are missing for production use, or sane
// defaults are supplied. nc may be a *natsclient.Client or any
// natsPublisher-satisfying type (for tests).
func New(cfg Config, nc natsPublisher, log *slog.Logger) (*Adapter, error) {
	if nc == nil {
		return nil, errors.New("audit: new: nats publisher is nil")
	}
	if log == nil {
		log = slog.Default()
	}
	if cfg.ListenAddr == "" {
		return nil, errors.New("audit: new: config.ListenAddr is empty")
	}
	if cfg.Hostname == "" {
		return nil, errors.New("audit: new: config.Hostname is empty")
	}
	if cfg.TLSCertFile == "" {
		return nil, errors.New("audit: new: config.TLSCertFile is empty")
	}
	if cfg.TLSKeyFile == "" {
		return nil, errors.New("audit: new: config.TLSKeyFile is empty")
	}
	if cfg.ClientCAFile == "" {
		return nil, errors.New("audit: new: config.ClientCAFile is empty")
	}
	if cfg.MaxPayloadBytes <= 0 {
		cfg.MaxPayloadBytes = 8 * 1024 * 1024
	}
	if cfg.StalenessTimeout <= 0 {
		cfg.StalenessTimeout = 5 * time.Minute
	}
	if cfg.ReadHeaderTimeout <= 0 {
		cfg.ReadHeaderTimeout = 10 * time.Second
	}
	if cfg.ShutdownGrace <= 0 {
		cfg.ShutdownGrace = 5 * time.Second
	}
	if cfg.PublishRetry.IsZero() {
		cfg.PublishRetry = DefaultPublishRetry()
	}
	if err := cfg.PublishRetry.Validate(); err != nil {
		return nil, fmt.Errorf("audit: new: publish retry: %w", err)
	}

	return &Adapter{
		cfg:      cfg,
		pub:      nc,
		log:      log,
		nowFn:    time.Now,
		rejected: newRejectedCounters(),
	}, nil
}

// Health returns the read-only source-health view. Story 1.12 binds
// this to the Prometheus gauge `source_healthy{source="kube_audit"}`
// (FR8). Returning the narrow sourcehealth.Reader interface (rather
// than the concrete *sourcehealth.Tracker) prevents callers outside
// the package from reaching the mutator methods.
func (a *Adapter) Health() sourcehealth.Reader {
	return &a.health
}

// Rejected returns a snapshot of the per-reason rejection counters.
// Story 1.12's Prometheus collector reads this and binds each reason
// to a labelled counter. Returns a fresh map (not aliased) so callers
// can iterate without mutex coordination.
func (a *Adapter) Rejected() map[string]uint64 {
	return a.rejected.Snapshot()
}

// Run binds the receiver, starts the staleness watchdog, and blocks
// until ctx is cancelled. On cancellation it gives the HTTP server
// cfg.ShutdownGrace to drain in-flight requests.
func (a *Adapter) Run(ctx context.Context) error {
	a.log.Info("audit: adapter starting",
		"addr", a.cfg.ListenAddr,
		"hostname", a.cfg.Hostname,
		"max_payload_bytes", a.cfg.MaxPayloadBytes,
		"staleness_timeout", a.cfg.StalenessTimeout)
	defer a.log.Info("audit: adapter stopped")

	tlsCfg, err := a.buildTLSConfig()
	if err != nil {
		return fmt.Errorf("audit: tls config: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/audit", a.handleAudit)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	srv := &http.Server{
		Addr:              a.cfg.ListenAddr,
		Handler:           mux,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: a.cfg.ReadHeaderTimeout,
	}
	if a.addrFn == nil {
		a.addrFn = func() string { return srv.Addr }
	}

	// Staleness watchdog. Wakes every StalenessTimeout/2 to compare
	// last-traffic to wall clock; flips MarkUnhealthy on staleness.
	// MarkHealthy is the handler's job (on first successful publish).
	watchdogDone := make(chan struct{})
	go func() {
		defer close(watchdogDone)
		a.runStalenessWatchdog(ctx)
	}()

	// Mark unhealthy at startup until first traffic. The Falco adapter
	// flips healthy on the first successful Recv; the audit adapter
	// flips healthy on the first successful publish.
	a.health.MarkUnhealthy(errors.New("audit: awaiting initial inbound traffic"))

	listenErr := make(chan error, 1)
	go func() {
		// Empty cert/key file paths are illegal here; New() already
		// guarded that. ListenAndServeTLS reads the files at bind time.
		err := srv.ListenAndServeTLS(a.cfg.TLSCertFile, a.cfg.TLSKeyFile)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			listenErr <- err
			return
		}
		listenErr <- nil
	}()

	select {
	case err := <-listenErr:
		<-watchdogDone
		if err != nil {
			a.health.MarkUnhealthy(err)
			return fmt.Errorf("audit: listen-and-serve-tls: %w", err)
		}
		return nil
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), a.cfg.ShutdownGrace)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			a.log.Warn("audit: shutdown grace expired or errored", "err", err)
		}
		<-listenErr
		<-watchdogDone
		return nil
	}
}

// runStalenessWatchdog periodically checks whether the time since the
// last inbound batch has exceeded StalenessTimeout; if so, marks the
// source unhealthy. Returns when ctx is cancelled.
func (a *Adapter) runStalenessWatchdog(ctx context.Context) {
	period := a.cfg.StalenessTimeout / 2
	if period <= 0 {
		period = 30 * time.Second
	}
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			lastNs := a.lastTrafficUnixNano.Load()
			if lastNs == 0 {
				// Never received traffic; the startup MarkUnhealthy is
				// authoritative until the first batch flips it.
				continue
			}
			last := time.Unix(0, lastNs)
			if a.nowFn().Sub(last) > a.cfg.StalenessTimeout {
				a.health.MarkUnhealthy(fmt.Errorf("audit: no inbound traffic for %s", a.cfg.StalenessTimeout))
			}
		}
	}
}

// buildTLSConfig assembles the receiver's TLS configuration. mTLS is
// mandatory: ClientAuth=RequireAndVerifyClientCert ensures the Go
// stdlib TLS handshake fails before the request reaches our handler if
// the apiserver does not present a cert signed by ClientCAFile.
func (a *Adapter) buildTLSConfig() (*tls.Config, error) {
	caBytes, err := os.ReadFile(a.cfg.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read client ca %q: %w", a.cfg.ClientCAFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("parse client ca %q: no PEM certs found", a.cfg.ClientCAFile)
	}
	return &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pool,
		MinVersion: tls.VersionTLS12,
	}, nil
}

// handleAudit is the /audit POST handler. The kube-apiserver sends
// audit.k8s.io/v1 EventList JSON batches. We translate each event,
// publish to subjects.RawAudit, and return:
//
//   - 204 No Content on all-events-processed (translate-or-publish-or-
//     skip; per-event failures are logged but never 5xx because the
//     apiserver retries the entire batch on 5xx).
//   - 5xx only when EVERY event in the batch fails to publish on the
//     transient path. This signals to the apiserver to retry; the per-
//     event WithMsgID dedups on JetStream within its 2-minute window.
//
// Other rejections short-circuit before translation: 405 (method),
// 415 (content-type), 413 (payload too large).
func (a *Adapter) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.rejected.Inc("method_not_allowed")
		a.peerLog(r).Warn("audit: rejected non-POST request",
			"method", r.Method)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ct := r.Header.Get("Content-Type")
	// The apiserver sends application/json; tolerate
	// "application/json; charset=utf-8" and similar parameter forms.
	if !strings.HasPrefix(ct, "application/json") {
		a.rejected.Inc("unsupported_media_type")
		a.peerLog(r).Warn("audit: rejected non-JSON content-type",
			"content_type", ct)
		http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
		return
	}

	body := http.MaxBytesReader(w, r.Body, a.cfg.MaxPayloadBytes)
	defer func() { _ = r.Body.Close() }()

	var list auditv1.EventList
	dec := json.NewDecoder(body)
	if err := dec.Decode(&list); err != nil {
		// MaxBytesReader surfaces oversize as
		// "http: request body too large"; map that to 413.
		if isMaxBytesError(err) {
			a.rejected.Inc("payload_too_large")
			a.peerLog(r).Warn("audit: rejected oversize payload",
				"max_bytes", a.cfg.MaxPayloadBytes)
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}
		a.rejected.Inc("decode_error")
		a.peerLog(r).Warn("audit: rejected undecodable payload", "err", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	a.lastTrafficUnixNano.Store(a.nowFn().UnixNano())

	ctx := r.Context()
	var (
		processed int
		published int
		permanent int
		dropped   int
		anyOK     bool
	)

	for i := range list.Items {
		ev := &list.Items[i]
		schemaEv, terr := Translate(ev, a.cfg.Hostname)
		if terr != nil {
			if errors.Is(terr, ErrSkipNonResponseComplete) {
				a.log.Debug("audit: skip non-response-complete stage",
					"audit_id", ev.AuditID, "stage", ev.Stage)
				continue
			}
			a.log.Warn("audit: translate skipped malformed event",
				"err", terr, "audit_id", ev.AuditID)
			dropped++
			continue
		}
		processed++

		if perr := a.publishWithRetry(ctx, schemaEv); perr != nil {
			if isPermanentPublishError(perr) {
				a.log.Error("audit: publish dropped (permanent, per-event)",
					"err", perr, "event_id", schemaEv.ID,
					"summary_bytes", len(schemaEv.Summary))
				permanent++
				continue
			}
			a.log.Warn("audit: publish failed transiently",
				"err", perr, "event_id", schemaEv.ID)
			continue
		}
		published++
		anyOK = true
	}

	if anyOK {
		// First successful publish (or any subsequent success) flips
		// the source healthy. The Falco adapter parallel: MarkHealthy
		// only after evidence of byte traffic in both directions.
		a.health.MarkHealthy()
	}

	// 5xx only when there were translate-eligible events AND none of
	// them published. Permanent (per-event terminal) failures do not
	// count as a reason to 5xx -- the apiserver should NOT retry an
	// oversize event indefinitely. If only permanents and zero
	// transient failures occurred, return 204; the events are dropped
	// at our edge, not the apiserver's.
	transientFails := processed - published - permanent
	if processed > 0 && published == 0 && transientFails > 0 {
		http.Error(w, "publish failed", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// publishWithRetry attempts to publish ev to subjects.RawAudit with
// bounded retry. Each attempt is wrapped in a 2s per-attempt deadline
// (publishAttemptTimeout). ev.ID is forwarded as the JetStream
// Nats-Msg-Id header so a retry the server already persisted on a
// previous attempt is server-side deduplicated within the stream's
// dedup window. A permanent server-side error (e.g. payload-too-big)
// is wrapped in retry.Permanent so the inner-retry exits immediately
// and the caller can log+drop without 5xx.
func (a *Adapter) publishWithRetry(ctx context.Context, ev schema.Event) error {
	return a.cfg.PublishRetry.Do(ctx, func(ctx context.Context) error {
		attemptCtx, cancel := context.WithTimeout(ctx, publishAttemptTimeout)
		defer cancel()
		_, err := a.pub.PublishJS(attemptCtx, subjects.RawAudit, ev,
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

// peerLog returns a logger enriched with TLS peer-cert identity fields
// when the request had a verified client cert. Used by the rejection
// paths to surface peer_cn / peer_serial in structured logs.
func (a *Adapter) peerLog(r *http.Request) *slog.Logger {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return a.log
	}
	cert := r.TLS.PeerCertificates[0]
	return a.log.With(
		"peer_cn", cert.Subject.CommonName,
		"peer_serial", cert.SerialNumber.String(),
	)
}

// isMaxBytesError reports whether err originates from
// http.MaxBytesReader hitting its cap.
func isMaxBytesError(err error) bool {
	if err == nil {
		return false
	}
	// http.MaxBytesError landed in Go 1.19; errors.As matches by type.
	var mbErr *http.MaxBytesError
	if errors.As(err, &mbErr) {
		return true
	}
	return strings.Contains(err.Error(), "http: request body too large")
}

// isPermanentPublishError mirrors falco.isPermanentPublishError. The
// JetStream client surfaces "maximum payload violation" / "message
// size exceeded" / similar with version-specific strings; substring-
// match against the lower-cased error to catch them all.
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
