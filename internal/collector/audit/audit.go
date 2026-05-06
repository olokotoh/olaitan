package audit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	natsjs "github.com/nats-io/nats.go/jetstream"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"

	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/retry"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/sourcehealth"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// rejectedCounters tracks per-reason counters for HTTP-layer
// rejections plus translate-layer drops. Story 1.12 will read these via
// Adapter.Rejected() and bind each reason to a Prometheus counter
// audit_webhook_rejected{reason}. The reason set is open-ended at the
// type level but the production reasons are:
//
//	method_not_allowed
//	unsupported_media_type
//	payload_too_large
//	decode_error
//	trailing_json
//	translate_failed
type rejectedCounters struct {
	mu       sync.RWMutex
	counters map[string]*atomic.Uint64
}

func newRejectedCounters() *rejectedCounters {
	return &rejectedCounters{counters: make(map[string]*atomic.Uint64, 6)}
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
type natsPublisher interface {
	PublishJS(ctx context.Context, subject string, data any, opts ...natsjs.PublishOpt) (*natsjs.PubAck, error)
}

// defaultClientCNs is the allow-list of leaf-cert CommonNames the
// receiver accepts when no explicit ClientCNAllow is configured.
// "kube-apiserver" is the canonical CN the kubeadm-issued
// apiserver-kubelet-client cert uses; operators with a custom client
// cert override via ClientCNAllow.
//
// The post-review D2 binding interpretation (see Story 1.7 Review
// Findings) requires this pinning because on kubeadm clusters the
// cluster CA at /etc/kubernetes/pki/ca.crt signs every control-plane
// component (kubelet, controller-manager, scheduler, ...) -- a CA
// trust pool alone is not enough to identify the apiserver.
var defaultClientCNs = []string{"kube-apiserver"}

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

	// ClientCNAllow is the list of leaf-cert CommonNames the receiver
	// accepts after CA validation. Empty means "use defaultClientCNs".
	// Set to a single-element list when the operator's apiserver client
	// cert uses a non-standard CN. Defence-in-depth on top of the CA
	// trust pool: prevents any other workload pod with a CA-signed cert
	// from posting forged audit events.
	ClientCNAllow []string

	// Hostname is the node-level identifier the adapter records on
	// every emitted Event.Pod.Node. Sourced from the K8S_NODE_NAME env
	// var the Helm chart's downward API injects.
	Hostname string

	// MaxPayloadBytes caps the request body size before rejection. The
	// apiserver default batch is ~400 events x ~1-32 KiB each ~ <4 MiB;
	// 8 MiB is a generous cap that fails misconfigured upstreams loud
	// (413, no retry) instead of OOMing the receiver. Default 8 MiB
	// when zero-valued.
	MaxPayloadBytes int64

	// StalenessTimeout is how long without an inbound batch before the
	// source is marked unhealthy. Default 5m when zero-valued.
	//
	// Health semantics: source health flips to healthy on the first
	// successful PublishJS PubAck, NOT on the first received batch.
	// "Received but every event failed to translate" stays unhealthy
	// because it indicates a real upstream contract break. The
	// staleness watchdog flips back to unhealthy only after the source
	// has previously been marked healthy AND no successful publish has
	// landed within StalenessTimeout (preserves a more specific
	// MarkUnhealthy reason posted by the listen-fail or publish-loop
	// paths).
	StalenessTimeout time.Duration

	// PublishRetry is the bounded inner retry for transient NATS
	// publish failures. Defaults to DefaultPublishRetry() when zero.
	PublishRetry retry.Strategy

	// ReadHeaderTimeout caps slowloris-style header-stalling attacks.
	// Default 10s when zero-valued.
	ReadHeaderTimeout time.Duration

	// ReadTimeout caps total-body-read time. Without this a post-mTLS
	// hostile client can keep the body trickling within
	// MaxPayloadBytes indefinitely. Default 30s when zero-valued.
	ReadTimeout time.Duration

	// WriteTimeout caps response-write time. Default 30s when
	// zero-valued. Mostly a defence-in-depth knob; our handler writes
	// 204/4xx/5xx promptly.
	WriteTimeout time.Duration

	// IdleTimeout caps keep-alive reuse. Default 60s when zero-valued.
	IdleTimeout time.Duration

	// ShutdownGrace is the deadline for srv.Shutdown to drain in-flight
	// requests on ctx cancellation. Default 5s when zero-valued.
	ShutdownGrace time.Duration

	// PublishWallClockBudget caps the total wall-clock time
	// publishWithRetry can spend on a single event, including retries.
	// Default = PublishRetry.MaxAttempts * publishAttemptTimeout +
	// retry-backoffs (~9s for the production strategy). The retry path
	// uses context.WithoutCancel so an apiserver client disconnect does
	// not abort an in-flight retry budget; this knob bounds the
	// detached path so a stuck NATS does not orphan a goroutine.
	PublishWallClockBudget time.Duration
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

// publishAttemptTimeout caps a single PublishJS attempt. JetStream's
// default publish-ack-wait is ~5s; without a per-attempt deadline a
// NATS partition can stall a single PublishJS for ~5s before retry 2
// starts. Same value as the falco adapter's bound.
const publishAttemptTimeout = 2 * time.Second

// defaultPublishWallClockBudget bounds the detached retry context the
// publish path uses (see D6 in Story 1.7 Review Findings). 12s covers
// 3 attempts x 2s deadline + ~6s of jittered backoff between them with
// generous slack.
const defaultPublishWallClockBudget = 12 * time.Second

// Adapter is the audit-webhook receiver. Construct with New; run the
// per-instance lifecycle via Run; observe health via Health.
type Adapter struct {
	cfg    Config
	pub    natsPublisher
	log    *slog.Logger
	health sourcehealth.Tracker

	// lastPublishOKUnixNano is the Unix-nanosecond timestamp of the
	// most recent successful PublishJS PubAck. The staleness watchdog
	// reads it to decide whether to flip MarkUnhealthy. Zero means "no
	// successful publish ever".
	lastPublishOKUnixNano atomic.Int64

	rejected *rejectedCounters

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
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = 30 * time.Second
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = 30 * time.Second
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 60 * time.Second
	}
	if cfg.ShutdownGrace <= 0 {
		cfg.ShutdownGrace = 5 * time.Second
	}
	if cfg.PublishWallClockBudget <= 0 {
		cfg.PublishWallClockBudget = defaultPublishWallClockBudget
	}
	if cfg.PublishRetry.IsZero() {
		cfg.PublishRetry = DefaultPublishRetry()
	}
	if err := cfg.PublishRetry.Validate(); err != nil {
		return nil, fmt.Errorf("audit: new: publish retry: %w", err)
	}
	if len(cfg.ClientCNAllow) == 0 {
		cfg.ClientCNAllow = append([]string(nil), defaultClientCNs...)
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
// cfg.ShutdownGrace to drain in-flight requests. On a listen failure
// (cert rotation surprise, transient bind error, panic in the listen
// goroutine) the watchdog is also cancelled so Run does not deadlock
// waiting on the watchdogDone channel.
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
		ReadTimeout:       a.cfg.ReadTimeout,
		WriteTimeout:      a.cfg.WriteTimeout,
		IdleTimeout:       a.cfg.IdleTimeout,
	}

	// Derive a watchdog ctx from the parent so listen-failure can
	// cancel the watchdog without waiting on the parent shutdown.
	wdCtx, wdCancel := context.WithCancel(ctx)
	watchdogDone := make(chan struct{})
	go func() {
		defer close(watchdogDone)
		a.runStalenessWatchdog(wdCtx)
	}()

	// Mark unhealthy at startup until first successful publish.
	a.health.MarkUnhealthy(errors.New("audit: awaiting initial inbound traffic"))

	listenErr := make(chan error, 1)
	go func() {
		// Defensive: a panic in ListenAndServeTLS-driven handler stack
		// must not orphan Run waiting on listenErr forever.
		defer func() {
			if r := recover(); r != nil {
				select {
				case listenErr <- fmt.Errorf("audit: listen goroutine panic: %v", r):
				default:
				}
			}
		}()
		err := srv.ListenAndServeTLS(a.cfg.TLSCertFile, a.cfg.TLSKeyFile)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			listenErr <- err
			return
		}
		listenErr <- nil
	}()

	select {
	case err := <-listenErr:
		// Cancel the watchdog so we don't wait forever on watchdogDone
		// just because the parent ctx is still live.
		wdCancel()
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
		wdCancel()
		<-watchdogDone
		return nil
	}
}

// runStalenessWatchdog periodically checks whether the time since the
// last successful publish has exceeded StalenessTimeout. Only flips
// MarkUnhealthy when the source is currently healthy: this preserves
// any more-specific error a publish-loop or listen-fail path stored.
// Backward clock jumps (negative Sub) are treated as "not stale" so a
// transient NTP step does not falsely flip the source.
//
// Returns when ctx is cancelled.
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
			lastNs := a.lastPublishOKUnixNano.Load()
			if lastNs == 0 {
				// Never had a successful publish; the startup
				// MarkUnhealthy is authoritative until the first OK
				// publish flips it.
				continue
			}
			last := time.Unix(0, lastNs)
			delta := a.nowFn().Sub(last)
			if delta < 0 {
				// Backward clock jump (NTP step). Treat as "fresh"
				// rather than fabricating a staleness signal.
				continue
			}
			if delta <= a.cfg.StalenessTimeout {
				continue
			}
			// Only override health if we are currently healthy. If a
			// listen-fail or publish-loop has already stored a more
			// specific error, leave it alone.
			if healthy, _ := a.health.Status(); !healthy {
				continue
			}
			a.health.MarkUnhealthy(fmt.Errorf("audit: no successful publish for %s", a.cfg.StalenessTimeout))
		}
	}
}

// buildTLSConfig assembles the receiver's TLS configuration. mTLS is
// mandatory: ClientAuth=RequireAndVerifyClientCert ensures the Go
// stdlib TLS handshake fails before the request reaches the handler if
// the apiserver does not present a cert signed by ClientCAFile, AND
// VerifyPeerCertificate adds CN-pinning so a cluster-CA-signed cert
// from another workload (kubelet, controller-manager, ...) cannot
// authenticate as "the apiserver".
//
// AC3 binding interpretation (see Story 1.7 Review Findings D4):
// rejection at the TLS layer is operationally stronger than an HTTP
// 403 but does not run through the Go handler stack, so per-request
// HTTP-403 / `audit_webhook_rejected{reason}` / structured-log fields
// for cert-failure paths are not emitted; instead, mTLS rejections
// surface in the apiserver's own audit-webhook backoff logs and
// (post-Story-1.12) in the `tls_handshake_failed_total` counter
// derived from `crypto/tls.Config.GetConfigForClient` instrumentation.
// Story 1.12 will add the latter; this story stops at the in-process
// CN-pinning.
func (a *Adapter) buildTLSConfig() (*tls.Config, error) {
	caBytes, err := os.ReadFile(a.cfg.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read client ca %q: %w", a.cfg.ClientCAFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("parse client ca %q: no PEM certs found", a.cfg.ClientCAFile)
	}
	allow := make(map[string]struct{}, len(a.cfg.ClientCNAllow))
	for _, cn := range a.cfg.ClientCNAllow {
		allow[cn] = struct{}{}
	}
	return &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pool,
		// TLS 1.3 is the floor on kubeadm 1.29 (apiserver supports it
		// universally); TLS 1.2 + no CipherSuites left a CBC-padding
		// surface that adds nothing for an in-cluster hop.
		MinVersion: tls.VersionTLS13,
		// Defence-in-depth on top of the CA pool: VerifyPeerCertificate
		// runs after Go's chain validation when ClientAuth is
		// RequireAndVerifyClientCert, so any verifiedChains[0][0] is
		// already CA-signed. We additionally require its CN to be in
		// the configured allow-list.
		VerifyPeerCertificate: func(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
				return errors.New("audit: tls: no verified peer chain")
			}
			leaf := verifiedChains[0][0]
			if _, ok := allow[leaf.Subject.CommonName]; ok {
				return nil
			}
			return fmt.Errorf("audit: tls: peer CN %q not in client_cn_allow", leaf.Subject.CommonName)
		},
	}, nil
}

// handleAudit is the /audit POST handler. The kube-apiserver sends
// audit.k8s.io/v1 EventList JSON batches. We translate each event,
// publish to subjects.RawAudit, and return:
//
//   - 204 No Content when every translate-eligible event publishes
//     successfully (or every failure is permanent / per-event terminal,
//     which the apiserver should NOT retry).
//   - 5xx (Internal Server Error) when ANY translate-eligible event
//     fails transiently. WithMsgID dedup on the subsequent retry means
//     the events that did publish will not duplicate. This is the
//     post-D5 binding: at-least-once is the contract WithMsgID was
//     added to honour, so partial-success ergonomics yield to it.
//
// Other rejections short-circuit before translation: 405 (method),
// 415 (content-type), 413 (payload too large), 400 (decode error).
func (a *Adapter) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.rejected.Inc("method_not_allowed")
		a.peerLog(r).Warn("audit: rejected non-POST request",
			"method", r.Method)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		a.rejected.Inc("unsupported_media_type")
		a.peerLog(r).Warn("audit: rejected non-JSON content-type",
			"content_type", r.Header.Get("Content-Type"))
		http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
		return
	}

	body := http.MaxBytesReader(w, r.Body, a.cfg.MaxPayloadBytes)
	defer func() { _ = r.Body.Close() }()

	var list auditv1.EventList
	dec := json.NewDecoder(body)
	if err := dec.Decode(&list); err != nil {
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
	// Reject trailing JSON after the EventList: a spec-violating
	// upstream that sends a second top-level value after the EventList
	// would otherwise be silently truncated.
	if dec.More() {
		a.rejected.Inc("trailing_json")
		a.peerLog(r).Warn("audit: rejected trailing JSON after EventList")
		http.Error(w, "trailing json", http.StatusBadRequest)
		return
	}

	// publishCtx is detached from r.Context() so an apiserver-side
	// disconnect mid-batch does not abort the bounded retry budget.
	// We bound the detached path with a wall-clock deadline so a
	// stuck NATS cannot orphan a goroutine.
	publishCtx, cancel := context.WithTimeout(
		context.WithoutCancel(r.Context()),
		a.cfg.PublishWallClockBudget,
	)
	defer cancel()

	var (
		processed      int
		published      int
		permanent      int
		transientFails int
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
			a.rejected.Inc("translate_failed")
			continue
		}
		processed++

		if perr := a.publishWithRetry(publishCtx, schemaEv); perr != nil {
			if isPermanentPublishError(perr) {
				a.log.Error("audit: publish dropped (permanent, per-event)",
					"err", perr, "event_id", schemaEv.ID,
					"summary_bytes", len(schemaEv.Summary))
				permanent++
				continue
			}
			a.log.Warn("audit: publish failed transiently",
				"err", perr, "event_id", schemaEv.ID)
			transientFails++
			continue
		}
		published++
	}

	if published > 0 {
		a.lastPublishOKUnixNano.Store(a.nowFn().UnixNano())
		a.health.MarkHealthy()
	}

	// Post-D5: 5xx on ANY transient failure so the apiserver retries
	// the batch; WithMsgID(ev.ID) on each publish dedups the events
	// that already landed within the JetStream 2-minute window. This
	// preserves the at-least-once contract end-to-end.
	if transientFails > 0 {
		http.Error(w, "publish failed (transient)", http.StatusInternalServerError)
		return
	}
	_ = processed
	_ = permanent
	w.WriteHeader(http.StatusNoContent)
}

// publishWithRetry attempts to publish ev to subjects.RawAudit with
// bounded retry. Each attempt is wrapped in a 2s per-attempt deadline
// (publishAttemptTimeout). ev.ID is forwarded as the JetStream
// Nats-Msg-Id header so a retry the server already persisted on a
// previous attempt is server-side deduplicated within the stream's
// 2-minute dedup window. A permanent server-side error (e.g.
// payload-too-big) is wrapped in retry.Permanent so the inner-retry
// exits immediately and the caller can log+drop without 5xx.
//
// The supplied ctx is the caller-managed publish context (detached
// from the HTTP request context per D6); each attempt derives its own
// 2s sub-context.
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
	serial := ""
	if cert.SerialNumber != nil {
		serial = cert.SerialNumber.String()
	}
	return a.log.With(
		"peer_cn", cert.Subject.CommonName,
		"peer_serial", serial,
	)
}

// isJSONContentType returns true when ct is exactly application/json
// (with optional parameters per RFC 7231). Avoids the false-positive
// HasPrefix match that would accept "application/json-seq" or
// "application/jsonp".
func isJSONContentType(ct string) bool {
	if ct == "" {
		return false
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return mt == "application/json"
}

// isMaxBytesError reports whether err originates from
// http.MaxBytesReader hitting its cap. http.MaxBytesError is the
// typed error since Go 1.19; the substring fallback is removed
// because errors.As(*http.MaxBytesError) is the only path
// MaxBytesReader produces.
func isMaxBytesError(err error) bool {
	if err == nil {
		return false
	}
	var mbErr *http.MaxBytesError
	return errors.As(err, &mbErr)
}

// isPermanentPublishError reports whether err from a JetStream
// PublishJS call is a per-message terminal condition (the message
// itself violates a stream-level invariant). Caller is expected to
// log+drop the offending event and return a permanent retry signal.
//
// Detection layers (in order):
//  1. errors.Is(err, nats.ErrMaxPayload) -- the typed client-side cap.
//  2. *jetstream.APIError with a payload/size error code, when
//     upstream surfaces one.
//  3. Substring fallback against the lower-cased message body for
//     server-side errors that come through as plain wrapped strings;
//     mirrors the falco adapter's pragmatic shape.
//
// Layer (1) is the preferred path; (3) is the safety net for
// server-side variants that don't surface as a typed APIError.
func isPermanentPublishError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, nats.ErrMaxPayload) {
		return true
	}
	var apiErr *natsjs.APIError
	if errors.As(err, &apiErr) {
		// Code 10054: stream message size exceeds maximum (NATS server
		// constant; not exported by nats.go yet, hence the literal).
		if apiErr.ErrorCode == 10054 {
			return true
		}
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
