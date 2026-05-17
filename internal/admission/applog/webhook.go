// Package applog implements the Olaitan MutatingAdmissionWebhook that
// injects the application log sidecar (Story 1.9 / FR5) into opt-in
// workload pods. The webhook decodes admissionv1.AdmissionReview
// requests from the apiserver, inspects each Pod-create payload for
// the olaitan.io/log-sidecar="enabled" annotation, and (when present)
// emits a JSON Patch that adds the sidecar container, the shared
// emptyDir log volume, and the peer container's volumeMount.
//
// Topology: a separate Deployment from the agent DaemonSet, replica
// count default 2 for HA per the K8s admission-webhook good-practice
// guidance. The webhook listens on TLS only (HTTPS port 8443 by
// default) because the apiserver requires TLS for admission webhook
// connections.
//
// Failure mode: failurePolicy: Ignore is configured at the
// MutatingWebhookConfiguration layer (see the Helm chart's
// templates/applog-webhook-mutatingconfiguration.yaml). A webhook
// outage therefore does NOT block Pod admission cluster-wide; pods
// without the sidecar still admit successfully. This trades some
// missed sidecar injections for cluster-wide availability, which is
// the correct trade-off for a non-critical admission path.
//
// Idempotency: the webhook scans spec.initContainers and spec.containers
// for an existing container with name "olaitan-applog-sidecar". If
// found, the patch returned is empty and the Pod is admitted
// unchanged. This makes the webhook safe to re-fire after another
// mutating webhook (e.g. Istio's sidecar injector) rewrites the spec.
//
// Security boundary: the webhook is on the apiserver path and can
// mutate every Pod cluster-wide. Mitigations layered at deploy time:
// failurePolicy: Ignore (no cluster-wide block on outage),
// namespaceSelector excluding kube-system / kube-public,
// reinvocationPolicy: Never (we have idempotency, no need to re-fire),
// sideEffects: None (the webhook performs no I/O outside the request).
package applog

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"sync/atomic"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
)

// AnnotationEnable is the Pod-level annotation that opts a workload
// in to sidecar injection. The AC's "olaitan.io/log-sidecar" key is
// the canonical form; the deprecated alias "olaitan.io/log-monitor"
// (from architecture.md:463 placeholder) is also accepted with a WARN
// log on every hit and will be removed in a future hardening story.
const (
	AnnotationEnable           = "olaitan.io/log-sidecar"
	AnnotationEnableDeprecated = "olaitan.io/log-monitor"
	AnnotationTargetContainer  = "olaitan.io/log-sidecar-container"
	AnnotationValueEnabled     = "enabled"
)

// SidecarContainerName is the fixed name applied to the injected
// sidecar container. The webhook scans for this name to enforce
// idempotency on re-injection.
const SidecarContainerName = "olaitan-applog-sidecar"

// SharedVolumeName is the emptyDir volume mounted into both the
// sidecar and the peer application container at /var/log/app. The
// peer application is responsible for arranging to write its
// stdout/stderr to /var/log/app/stdout.log and /var/log/app/stderr.log
// (the cooperation contract documented in deploy/helm/olaitan/APPLOG.md).
const SharedVolumeName = "olaitan-applog-shared"

// SharedVolumeMountPath is the in-container path the shared emptyDir
// is mounted at on both the sidecar and the peer.
const SharedVolumeMountPath = "/var/log/app"

// SystemNamespaces lists namespaces the webhook never injects into,
// independent of the namespaceSelector configured at the
// MutatingWebhookConfiguration layer. The selector defends at the
// admission-routing layer; this list defends in code so a
// mis-configured chart cannot accidentally inject into kube-system.
var SystemNamespaces = map[string]struct{}{
	"kube-system": {},
	"kube-public": {},
}

// WebhookConfig holds runtime knobs for the webhook server.
type WebhookConfig struct {
	// ListenAddr is the TLS listener bind address. Defaults to :8443.
	ListenAddr string

	// TLSCertFile / TLSKeyFile are filesystem paths to the server's
	// TLS material. The chart-managed cert-manager Certificate (or the
	// manually-provided kubernetes.io/tls Secret) lands here.
	TLSCertFile string
	TLSKeyFile  string

	// UseNativeSidecar selects KEP-753 native sidecar mode (sidecar
	// goes into spec.initContainers with restartPolicy: Always; the
	// SidecarContainers feature gate is on by default in K8s 1.29).
	// When false, the sidecar is injected into spec.containers
	// instead, with the documented trade-off that pod-termination
	// semantics differ.
	UseNativeSidecar bool

	// SidecarImage is the image:tag string for the injected sidecar
	// container. The chart populates it from .Values.image at deploy
	// time (passed via env var to this binary). Required.
	SidecarImage string

	// SidecarCPURequest, SidecarMemoryRequest, SidecarCPULimit,
	// SidecarMemoryLimit are the sidecar's resource knobs. Empty
	// strings fall back to the chart defaults (10m cpu / 32Mi memory
	// requests; 100m cpu / 128Mi memory limits).
	SidecarCPURequest    string
	SidecarMemoryRequest string
	SidecarCPULimit      string
	SidecarMemoryLimit   string

	// SidecarStdoutPath / SidecarStderrPath override the sidecar's
	// default cooperating-app stdout / stderr file paths. Empty falls
	// back to the adapter's compiled defaults (/var/log/app/stdout.log,
	// /var/log/app/stderr.log). The webhook plumbs these through to the
	// injected sidecar container as OLAITAN_APPLOG_STDOUT_PATH /
	// OLAITAN_APPLOG_STDERR_PATH env vars.
	SidecarStdoutPath string
	SidecarStderrPath string

	// SidecarChannelBuffer is the bounded LineRecord channel capacity
	// the sidecar runs with. Empty falls back to the adapter default.
	// Stringly-typed because the chart values pass via env var; the
	// adapter's New() parses int and rejects invalid forms.
	SidecarChannelBuffer string

	// SidecarMaxLineBytes is the per-event line cap the sidecar applies
	// at translate time. Empty falls back to the adapter default
	// (MaxLineBytes constant, 64 KiB). Operator can tune to trade
	// JetStream payload size against context-richness for the Sigma
	// engine.
	SidecarMaxLineBytes string

	// SidecarPublishStallTimeout configures the back-pressure shed-mode
	// stall-time gate. Empty falls back to the adapter default (5 s).
	// The value is a Go time.Duration string (e.g. "3s", "500ms").
	SidecarPublishStallTimeout string

	// SidecarStalenessTimeout configures the watchdog's staleness
	// threshold. Empty falls back to the adapter default (30 m). Go
	// time.Duration string.
	SidecarStalenessTimeout string

	// SidecarRateLimit* forwards the cluster-wide Story 1.13
	// rate-limit knobs into injected applog sidecars. Empty values
	// fall back to the sidecar's compiled defaults.
	SidecarRateLimitEnabled   string
	SidecarRateLimitThreshold string
	SidecarRateLimitCooldown  string
	SidecarRateLimitSampling  string
}

// Webhook is the HTTPS admission server.
type Webhook struct {
	cfg WebhookConfig
	log *slog.Logger
	srv *http.Server

	// mutateHandler exposed for tests via the ServeHTTP entry-point on
	// the dedicated ServeMux.
	mux *http.ServeMux

	// counters for tests / Prometheus binding (Story 1.12).
	//
	// skippedTotal is preserved as the umbrella "no-mutation" counter
	// for backward compatibility with the Story 1.9 first-pass tests
	// that asserted it. Three sub-counters split out:
	//   - idempotentTotal: container already present on the Pod (the
	//     normal re-fire path under stacked mutating webhooks).
	//   - injectErrorTotal: Inject() returned an error (an internal
	//     regression that warrants a separate alarm).
	//   - unsupportedShapeTotal: the Pod shape is not supported (e.g.
	//     init-only Pods per D5). Distinct so an operator can quantify
	//     how many workloads are being skipped because of the
	//     non-support contract.
	//   - dryRunTotal: AdmissionReview.DryRun=true requests; these do
	//     NOT bump requestsTotal / injectedTotal so the per-cluster
	//     "real injection" rate is not polluted by API-server dry runs.
	requestsTotal         atomic.Int64
	injectedTotal         atomic.Int64
	deprecatedKeyHits     atomic.Int64
	skippedTotal          atomic.Int64
	idempotentTotal       atomic.Int64
	injectErrorTotal      atomic.Int64
	unsupportedShapeTotal atomic.Int64
	dryRunTotal           atomic.Int64
}

// NewWebhook constructs a Webhook. cfg is validated; nil log is
// accepted (defaults to slog.Default).
func NewWebhook(cfg WebhookConfig, log *slog.Logger) (*Webhook, error) {
	if log == nil {
		log = slog.Default()
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8443"
	}
	if cfg.TLSCertFile == "" {
		return nil, errors.New("applog/webhook: TLSCertFile is empty")
	}
	if cfg.TLSKeyFile == "" {
		return nil, errors.New("applog/webhook: TLSKeyFile is empty")
	}
	if cfg.SidecarImage == "" {
		return nil, errors.New("applog/webhook: SidecarImage is empty (chart must inject .Values.image)")
	}
	w := &Webhook{
		cfg: cfg,
		log: log,
		mux: http.NewServeMux(),
	}
	w.mux.HandleFunc("/mutate", w.handleMutate)
	w.mux.HandleFunc("/healthz", w.handleHealthz)
	w.srv = &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           w.mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	return w, nil
}

// Run blocks until ctx is cancelled. Returns nil on graceful
// shutdown. Returns the underlying ListenAndServeTLS error on a
// startup failure (port already bound, cert/key files missing).
func (w *Webhook) Run(ctx context.Context) error {
	serveErr := make(chan error, 1)
	go func() {
		err := w.srv.ListenAndServeTLS(w.cfg.TLSCertFile, w.cfg.TLSKeyFile)
		if errors.Is(err, http.ErrServerClosed) {
			serveErr <- nil
			return
		}
		serveErr <- err
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = w.srv.Shutdown(shutdownCtx)
		// Bounded receive: if Shutdown's 10 s window expires while a
		// long-running in-flight admission call is still draining,
		// ListenAndServeTLS may not return immediately. Block for at
		// most 5 s on serveErr; if nothing arrives, log and proceed
		// to caller cleanup so the Run goroutine cannot deadlock.
		select {
		case <-serveErr:
		case <-time.After(5 * time.Second):
			w.log.Warn("applog/webhook: serveErr did not arrive within 5s of Shutdown; proceeding")
		}
		return nil
	case err := <-serveErr:
		return err
	}
}

// Mux exposes the underlying ServeMux for tests that drive the
// handler in-process via httptest without spinning up a TLS listener.
func (w *Webhook) Mux() *http.ServeMux { return w.mux }

// RequestsTotal / InjectedTotal / DeprecatedKeyHits / SkippedTotal
// expose the per-request counters for tests and Story 1.12.
func (w *Webhook) RequestsTotal() int64         { return w.requestsTotal.Load() }
func (w *Webhook) InjectedTotal() int64         { return w.injectedTotal.Load() }
func (w *Webhook) DeprecatedKeyHits() int64     { return w.deprecatedKeyHits.Load() }
func (w *Webhook) SkippedTotal() int64          { return w.skippedTotal.Load() }
func (w *Webhook) IdempotentTotal() int64       { return w.idempotentTotal.Load() }
func (w *Webhook) InjectErrorTotal() int64      { return w.injectErrorTotal.Load() }
func (w *Webhook) UnsupportedShapeTotal() int64 { return w.unsupportedShapeTotal.Load() }
func (w *Webhook) DryRunTotal() int64           { return w.dryRunTotal.Load() }

// handleHealthz is a trivial liveness probe. Returns 200 OK for any
// GET; the apiserver does not probe this endpoint -- kubelet does for
// liveness/readiness on the webhook Deployment.
func (w *Webhook) handleHealthz(rw http.ResponseWriter, _ *http.Request) {
	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write([]byte("ok\n"))
}

// maxAdmissionReviewBody is the upper bound on an AdmissionReview
// request body the webhook is willing to read. The apiserver default
// max-request-size is ~3 MiB; matching it via http.MaxBytesReader
// makes oversized POSTs return 413 deterministically rather than
// silently truncating mid-decode.
const maxAdmissionReviewBody = 3 << 20

// handleMutate is the AdmissionReview HTTP handler.
func (w *Webhook) handleMutate(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		http.Error(rw, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	// MaxBytesReader returns http.MaxBytesError once the limit is
	// reached, which surfaces a 413 to the client; below that ceiling
	// io.ReadAll completes normally.
	r.Body = http.MaxBytesReader(rw, r.Body, maxAdmissionReviewBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(rw, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		w.log.Warn("applog/webhook: read body", "err", err)
		http.Error(rw, "read body", http.StatusBadRequest)
		return
	}

	var review admissionv1.AdmissionReview
	if err := json.Unmarshal(body, &review); err != nil {
		w.log.Warn("applog/webhook: decode AdmissionReview", "err", err)
		http.Error(rw, "decode AdmissionReview", http.StatusBadRequest)
		return
	}
	if review.Request == nil {
		http.Error(rw, "AdmissionReview.Request is nil", http.StatusBadRequest)
		return
	}
	if review.Request.UID == "" {
		// Apiserver protocol requires response UID echo request UID;
		// an empty request UID would round-trip an empty response UID
		// which the apiserver may reject. Surface as 400 so the
		// apiserver retries with a well-formed request.
		http.Error(rw, "AdmissionReview.Request.UID is empty", http.StatusBadRequest)
		return
	}
	// Resource defence-in-depth: even though the MWC rules scope to
	// pods, a misconfigured rules block could route non-pod resources
	// here. Reject anything other than `pods` rather than attempt to
	// json.Unmarshal a non-Pod object.
	if review.Request.Resource.Resource != "" && review.Request.Resource.Resource != "pods" {
		http.Error(rw, "AdmissionReview.Request.Resource must be pods", http.StatusBadRequest)
		return
	}
	// DryRun short-circuit: the apiserver issues dry-run admission for
	// `kubectl --dry-run=server` and similar. We allow the pod through
	// without mutation, count separately, and DO NOT bump injectedTotal
	// so the per-cluster injection rate is not polluted by dry-runs.
	if review.Request.DryRun != nil && *review.Request.DryRun {
		w.dryRunTotal.Add(1)
		out := admissionv1.AdmissionReview{
			TypeMeta: review.TypeMeta,
			Response: &admissionv1.AdmissionResponse{
				UID:     review.Request.UID,
				Allowed: true,
			},
		}
		rw.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(rw).Encode(&out); err != nil {
			w.log.Warn("applog/webhook: encode dryRun AdmissionReview", "err", err)
		}
		return
	}

	w.requestsTotal.Add(1)
	resp := w.review(&review)
	out := admissionv1.AdmissionReview{
		TypeMeta: review.TypeMeta,
		Response: resp,
	}
	rw.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(rw).Encode(&out); err != nil {
		w.log.Warn("applog/webhook: encode AdmissionReview", "err", err)
	}
}

// isJSONContentType returns true when ct is application/json, with or
// without RFC-2616 media-type parameters (charset=utf-8 etc.). Mirrors
// internal/collector/audit/audit.go:isJSONContentType.
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

// review decides how to mutate the incoming Pod. Returns an
// AdmissionResponse with Allowed=true and (optionally) a JSON Patch.
// Failure to inject is NEVER a deny; failurePolicy at the
// configuration layer is Ignore so we always allow the pod.
func (w *Webhook) review(review *admissionv1.AdmissionReview) *admissionv1.AdmissionResponse {
	resp := &admissionv1.AdmissionResponse{
		UID:     review.Request.UID,
		Allowed: true,
	}

	// Defend in code against system-namespace injection even if the
	// chart's namespaceSelector were misconfigured.
	if _, isSystem := SystemNamespaces[review.Request.Namespace]; isSystem {
		w.skippedTotal.Add(1)
		return resp
	}

	// Empty Object.Raw is the apiserver's signal that the admission
	// request carries no Pod content (e.g. a CONNECT-mode admission).
	// Skip silently; bumping WARN here at apiserver rate would spam
	// the log with no operator-actionable signal.
	if len(review.Request.Object.Raw) == 0 {
		w.skippedTotal.Add(1)
		return resp
	}

	pod := corev1.Pod{}
	if err := json.Unmarshal(review.Request.Object.Raw, &pod); err != nil {
		w.log.Warn("applog/webhook: decode pod", "err", err)
		// failurePolicy: Ignore means we still allow the Pod through;
		// just don't inject. The reviewer can debug via webhook logs.
		w.skippedTotal.Add(1)
		w.injectErrorTotal.Add(1)
		return resp
	}

	// Always probe both keys for presence so the deprecated-alias
	// counter reflects actual operator-side usage even when the
	// canonical key also fires (annotationEnabled returns
	// deprecated=false in that case because the canonical key wins).
	if v, ok := pod.Annotations[AnnotationEnableDeprecated]; ok && v == AnnotationValueEnabled {
		w.deprecatedKeyHits.Add(1)
		w.log.Warn("applog/webhook: deprecated annotation key present",
			"deprecated_key", AnnotationEnableDeprecated,
			"canonical_key", AnnotationEnable,
			"namespace", review.Request.Namespace,
			"pod_name", pod.Name)
	}

	enabled, _ := annotationEnabled(pod.Annotations)
	if !enabled {
		w.skippedTotal.Add(1)
		return resp
	}

	// D5: init-only Pods (zero spec.containers) are explicitly not
	// supported. Report distinctly so an operator-visible counter
	// captures the volume of skipped non-support shapes without
	// conflating with idempotent re-fires.
	if len(pod.Spec.Containers) == 0 {
		w.unsupportedShapeTotal.Add(1)
		w.skippedTotal.Add(1)
		w.log.Warn("applog/webhook: unsupported pod shape (init-only, zero containers)",
			"namespace", review.Request.Namespace,
			"pod_name", pod.Name)
		return resp
	}

	patchBytes, err := Inject(&pod, InjectOptions{
		UseNativeSidecar:           w.cfg.UseNativeSidecar,
		SidecarImage:               w.cfg.SidecarImage,
		SidecarCPURequest:          w.cfg.SidecarCPURequest,
		SidecarMemoryRequest:       w.cfg.SidecarMemoryRequest,
		SidecarCPULimit:            w.cfg.SidecarCPULimit,
		SidecarMemoryLimit:         w.cfg.SidecarMemoryLimit,
		SidecarStdoutPath:          w.cfg.SidecarStdoutPath,
		SidecarStderrPath:          w.cfg.SidecarStderrPath,
		SidecarChannelBuffer:       w.cfg.SidecarChannelBuffer,
		SidecarMaxLineBytes:        w.cfg.SidecarMaxLineBytes,
		SidecarPublishStallTimeout: w.cfg.SidecarPublishStallTimeout,
		SidecarStalenessTimeout:    w.cfg.SidecarStalenessTimeout,
		SidecarRateLimitEnabled:    w.cfg.SidecarRateLimitEnabled,
		SidecarRateLimitThreshold:  w.cfg.SidecarRateLimitThreshold,
		SidecarRateLimitCooldown:   w.cfg.SidecarRateLimitCooldown,
		SidecarRateLimitSampling:   w.cfg.SidecarRateLimitSampling,
	})
	if err != nil {
		w.log.Warn("applog/webhook: inject", "err", err)
		w.skippedTotal.Add(1)
		w.injectErrorTotal.Add(1)
		return resp
	}
	if len(patchBytes) == 0 {
		// Already injected (idempotent re-fire) or no peer container
		// matched the target annotation. Bumping idempotentTotal
		// separately keeps the umbrella skippedTotal meaningful while
		// still distinguishing the normal re-fire path from inject
		// errors.
		w.idempotentTotal.Add(1)
		w.skippedTotal.Add(1)
		return resp
	}
	w.injectedTotal.Add(1)
	pt := admissionv1.PatchTypeJSONPatch
	resp.PatchType = &pt
	resp.Patch = patchBytes
	return resp
}

// annotationEnabled returns (enabled, deprecated). enabled=true when
// either AnnotationEnable or AnnotationEnableDeprecated is set to
// AnnotationValueEnabled. deprecated=true only when the deprecated
// alias was used (the canonical key takes precedence; if both are
// present, deprecated=false).
func annotationEnabled(ann map[string]string) (enabled, deprecated bool) {
	if v, ok := ann[AnnotationEnable]; ok && v == AnnotationValueEnabled {
		return true, false
	}
	if v, ok := ann[AnnotationEnableDeprecated]; ok && v == AnnotationValueEnabled {
		return true, true
	}
	return false, false
}
