package forensics

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/schema"
)

// defaults for the bounded queue and per-leg deadlines.
const (
	defaultQueueSize = 256
	// defaultCaptureTimeout bounds the capture leg (logs + spec + events).
	defaultCaptureTimeout = 6 * time.Second
	// defaultUploadTimeout bounds a single S3 PUT attempt.
	defaultUploadTimeout = 3 * time.Second
	// defaultDeleteTimeout bounds the pod delete leg.
	defaultDeleteTimeout = 2 * time.Second
	// defaultUploadRetries is the number of additional upload attempts after the
	// first failure before the write is deferred (AC5). The full retry/deferred
	// queue is Story 4.7; 4.2 does a small in-line retry then defers.
	defaultUploadRetries = 1
)

// errNilClientset is returned by New when cs is nil.
var errNilClientset = errors.New("forensics: nil clientset")

// errNilUploader is returned by New when the uploader is nil.
var errNilUploader = errors.New("forensics: nil uploader")

// StateOracle is the optional FSM-state query seam (mirrors netpol.StateOracle,
// BI-5). When non-nil the controller confirms a workload is genuinely in
// PRESERVED_KILLED before deleting its pods, so a stale queued transition cannot
// drive a delete after an operator released the workload. A nil oracle skips the
// confirmation (the ToState filter on Publish already gates entry), so the seam
// is fully optional. *fsm.Machine satisfies it via CurrentState.
type StateOracle interface {
	CurrentState(workloadID string) (schema.PodSecurityState, bool)
}

// Config configures a Controller.
type Config struct {
	// KMSKeyAlias is the SSE-KMS key alias applied to every forensic upload
	// (NFR17). Empty leaves SSE to the bucket default.
	KMSKeyAlias string
	// ExcludedNamespaces are never captured/deleted (e.g. kube-system, the
	// Olaitan namespace); mirrors netpol.
	ExcludedNamespaces []string
	// QueueSize bounds the Publish buffer; defaults to 256.
	QueueSize int
	// CaptureTimeout/UploadTimeout/DeleteTimeout bound each leg; zero -> default.
	CaptureTimeout time.Duration
	UploadTimeout  time.Duration
	DeleteTimeout  time.Duration
	// UploadRetries is the number of additional upload attempts after the first
	// failure before deferring; zero -> default (1).
	UploadRetries int
}

// Controller is the forensic capture sink + background drainer (BI-3/BI-4). It
// is a fsm.TransitionSink fanned out via fsm.MultiSink: Publish is NON-BLOCKING
// and filters to ToState == PRESERVED_KILLED, enqueuing onto a bounded channel;
// the background Run worker performs capture -> upload -> delete OFF the FSM hot
// path.
type Controller struct {
	cs       kubernetes.Interface
	uploader Uploader
	log      *slog.Logger
	now      func() time.Time

	kmsKeyAlias    string
	excluded       map[string]struct{}
	queue          chan schema.StateTransition
	captureTimeout time.Duration
	uploadTimeout  time.Duration
	deleteTimeout  time.Duration
	uploadRetries  int

	// oracle is the optional PRESERVED_KILLED confirmation seam (BI-5). Set once
	// via SetStateOracle before Run; read-only for the worker thereafter.
	oracle StateOracle

	captureSeconds prometheus.Histogram
	captureTotal   *prometheus.CounterVec
	writesDeferred prometheus.Counter
}

// New constructs a Controller. cs and uploader must be non-nil. registry may be
// nil to skip metric registration (test fixtures).
func New(cfg Config, cs kubernetes.Interface, uploader Uploader, registry *metrics.Registry, log *slog.Logger) (*Controller, error) {
	if cs == nil {
		return nil, errNilClientset
	}
	if uploader == nil {
		return nil, errNilUploader
	}
	if log == nil {
		log = slog.Default()
	}
	excluded := make(map[string]struct{}, len(cfg.ExcludedNamespaces))
	for _, ns := range cfg.ExcludedNamespaces {
		excluded[ns] = struct{}{}
	}
	qsize := cfg.QueueSize
	if qsize <= 0 {
		qsize = defaultQueueSize
	}
	captureTimeout := cfg.CaptureTimeout
	if captureTimeout <= 0 {
		captureTimeout = defaultCaptureTimeout
	}
	uploadTimeout := cfg.UploadTimeout
	if uploadTimeout <= 0 {
		uploadTimeout = defaultUploadTimeout
	}
	deleteTimeout := cfg.DeleteTimeout
	if deleteTimeout <= 0 {
		deleteTimeout = defaultDeleteTimeout
	}
	uploadRetries := cfg.UploadRetries
	if uploadRetries < 0 {
		uploadRetries = 0
	} else if cfg.UploadRetries == 0 {
		uploadRetries = defaultUploadRetries
	}

	c := &Controller{
		cs:             cs,
		uploader:       uploader,
		log:            log,
		now:            time.Now,
		kmsKeyAlias:    cfg.KMSKeyAlias,
		excluded:       excluded,
		queue:          make(chan schema.StateTransition, qsize),
		captureTimeout: captureTimeout,
		uploadTimeout:  uploadTimeout,
		deleteTimeout:  deleteTimeout,
		uploadRetries:  uploadRetries,
	}
	if registry != nil {
		if err := c.registerMetrics(registry); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// SetStateOracle installs the optional PRESERVED_KILLED confirmation seam (BI-5).
// Like netpol's setter it is called once before Run, while the controller is
// single-threaded; the field is then read-only for the worker.
func (c *Controller) SetStateOracle(o StateOracle) {
	c.oracle = o
}

// registerMetrics registers the three Story 4.2 metric families, pre-initialising
// the labelled counter series to 0 (mirror netpol manager.go:355-361) so alert
// PromQL has a stable zero series from process startup.
func (c *Controller) registerMetrics(r *metrics.Registry) error {
	h, err := r.RegisterHistogram(
		"olaitan_forensic_capture_seconds",
		"",
		"End-to-end latency from the FSM PRESERVED_KILLED transition timestamp to forensic capture + S3 upload-ack + pod delete completion, observed only on the success path (Story 4.2, NFR7 p99 <= 10s).",
		nil,
		[]float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 7.5, 10, 15},
	)
	if err != nil {
		return err
	}
	c.captureSeconds = h

	cv, err := r.RegisterCounterVec(
		"olaitan_forensic_capture_total",
		"Cumulative forensic capture outcomes labelled by result: captured (full success: capture+upload+delete), deferred (upload failed after retry; pod NOT deleted), skipped (excluded namespace, no pods, or no longer PRESERVED_KILLED), error (capture or delete failure), dropped (Publish queue full) (Story 4.2, FR36/AC5).",
		[]string{"result"},
	)
	if err != nil {
		return err
	}
	c.captureTotal = cv
	for _, result := range []string{"captured", "deferred", "skipped", "error", "dropped"} {
		cv.WithLabelValues(result).Add(0)
	}

	dc, err := r.RegisterCounterVec(
		"olaitan_forensic_writes_deferred_total",
		"Cumulative forensic writes deferred because the S3 upload failed after retry; the pod was NOT deleted (forensic preservation has priority over the kill) and remains QUARANTINED until Story 4.7's deferred queue catches up (Story 4.2, AC5, NFR28 increment clause).",
		nil,
	)
	if err != nil {
		return err
	}
	c.writesDeferred = dc.WithLabelValues()
	c.writesDeferred.Add(0)
	return nil
}

// count increments the capture-outcome counter when metrics are registered.
func (c *Controller) count(result string) {
	if c.captureTotal != nil {
		c.captureTotal.WithLabelValues(result).Inc()
	}
}

// Publish is the fsm.TransitionSink seam (BI-4). It acts ONLY on a transition
// INTO PRESERVED_KILLED, enqueuing for the async worker without blocking the FSM
// goroutine; on a full queue it drops with a metric rather than stalling the hot
// path. Every other ToState is intentionally ignored: the forensic controller
// captures only the terminal kill.
func (c *Controller) Publish(st schema.StateTransition) {
	if st.ToState != schema.StatePreservedKilled {
		return
	}
	select {
	case c.queue <- st:
	default:
		c.log.Warn("forensics: capture queue full; dropping kill transition", "workload_id", st.WorkloadID)
		c.count("dropped")
	}
}

// Run is the background worker (BI-4). It drains queued PRESERVED_KILLED
// transitions and performs capture -> upload -> delete for each. Wire it into
// the errgroup; it returns nil on graceful context cancellation.
func (c *Controller) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case st := <-c.queue:
			c.handle(ctx, st)
		}
	}
}

// handle performs the capture-before-delete cycle for a single PRESERVED_KILLED
// transition (AC3): resolve workload_id -> concrete pods, capture each pod's
// forensic bundle, upload it KMS-encrypted under a content-addressed key, and
// ONLY AFTER a confirmed upload-ack delete the pod. On upload failure after
// retry the pod is NOT deleted and the write is deferred (AC5). NFR7: the
// success-path latency from the transition timestamp to the final delete is
// observed against the histogram (BI-10).
func (c *Controller) handle(ctx context.Context, st schema.StateTransition) {
	ref, err := parseWorkloadID(st.WorkloadID)
	if err != nil {
		c.log.Warn("forensics: cannot parse workload id; skipping", "workload_id", st.WorkloadID, "err", err)
		c.count("error")
		return
	}
	if _, skip := c.excluded[ref.namespace]; skip {
		c.count("skipped")
		return
	}

	// BI-5: confirm the workload is still PRESERVED_KILLED before destroying its
	// pod. A queued kill that an operator has since released (or that the FSM no
	// longer tracks as terminal) must not trigger a delete. A nil oracle skips
	// the check (the Publish ToState filter already gated entry).
	if c.oracle != nil {
		if state, ok := c.oracle.CurrentState(st.WorkloadID); ok && state != schema.StatePreservedKilled {
			c.log.Info("forensics: workload no longer PRESERVED_KILLED; skipping capture",
				"workload_id", st.WorkloadID, "current_state", state)
			c.count("skipped")
			return
		}
	}

	pods, err := c.resolvePods(ctx, ref)
	if err != nil {
		c.log.Warn("forensics: cannot resolve pods; skipping", "workload_id", st.WorkloadID, "err", err)
		c.count("error")
		return
	}
	if len(pods) == 0 {
		// Nothing to capture or delete (the pods may already be gone). This is a
		// benign skip, not a deferral: there is no evidence left to preserve.
		c.log.Info("forensics: no pods resolved for kill; nothing to capture", "workload_id", st.WorkloadID)
		c.count("skipped")
		return
	}

	for _, pod := range pods {
		c.captureUploadDelete(ctx, st, ref.namespace, pod)
	}
}

// captureUploadDelete runs the per-pod capture-before-delete cycle. It is split
// out so each pod in a multi-pod workload is independently captured and deleted,
// and one pod's deferral does not block another's capture.
func (c *Controller) captureUploadDelete(ctx context.Context, st schema.StateTransition, namespace, podName string) {
	// Leg 1: capture (bounded).
	capCtx, capCancel := context.WithTimeout(ctx, c.captureTimeout)
	bundle, err := captureFallback(capCtx, c.cs, namespace, podName)
	capCancel()
	if err != nil {
		if apierrors.IsNotFound(err) {
			// The pod vanished before capture; no evidence to preserve, and the
			// delete is moot. Treat as an already-gone skip.
			c.log.Info("forensics: pod gone before capture; skipping", "namespace", namespace, "pod", podName)
			c.count("skipped")
			return
		}
		c.log.Warn("forensics: capture failed; pod NOT deleted (preserving evidence target)",
			"namespace", namespace, "pod", podName, "err", err)
		c.count("error")
		return
	}

	key, sum := bundleKey(bundle)

	// Leg 2: upload with a small in-line retry. AFTER the final failure the
	// write is DEFERRED (AC5): the pod is NOT deleted, the deferred counter
	// increments, and the pod stays QUARANTINED (Story 4.1 retains the deny-all).
	if !c.uploadWithRetry(ctx, key, bundle) {
		c.log.Warn("forensics: S3 upload failed after retry; deferring write and retaining pod",
			"namespace", namespace, "pod", podName, "key", key, "sha256", sum)
		if c.writesDeferred != nil {
			c.writesDeferred.Inc()
		}
		c.count("deferred")
		return
	}

	// Leg 3: delete the pod, STRICTLY after the upload ack (BI-6). NotFound is
	// already-gone success.
	delCtx, delCancel := context.WithTimeout(ctx, c.deleteTimeout)
	delErr := c.cs.CoreV1().Pods(namespace).Delete(delCtx, podName, metav1.DeleteOptions{})
	delCancel()
	if delErr != nil && !apierrors.IsNotFound(delErr) {
		// The forensic record is durably preserved (upload acked), but the pod
		// delete failed. The evidence is safe; the undeleted pod stays
		// QUARANTINED. Count as error so the alert fires; do NOT double-count as
		// deferred (the write succeeded).
		c.log.Warn("forensics: pod delete failed after successful forensic upload",
			"namespace", namespace, "pod", podName, "key", key, "err", delErr)
		c.count("error")
		return
	}

	// NFR7 (BI-10): observe capture-to-S3-to-delete latency only on the full
	// success path, against the injectable clock, never on the error/deferred
	// paths (so failed-attempt durations do not skew the histogram).
	if c.captureSeconds != nil && !st.Timestamp.IsZero() {
		c.captureSeconds.Observe(c.now().Sub(st.Timestamp).Seconds())
	}
	c.count("captured")
	c.log.Info("forensics: bundle captured, uploaded, pod deleted",
		"namespace", namespace, "pod", podName, "key", key, "sha256", sum, "bytes", len(bundle))
}

// uploadWithRetry attempts the upload up to 1 + uploadRetries times, each with a
// fresh per-attempt deadline. It returns true on the first acknowledged write.
// Each attempt re-reads the bundle from a fresh bytes.Reader so a retried PUT
// starts from the bundle head.
func (c *Controller) uploadWithRetry(ctx context.Context, key string, bundle []byte) bool {
	attempts := 1 + c.uploadRetries
	opts := UploadOptions{KMSKeyAlias: c.kmsKeyAlias}
	for i := 0; i < attempts; i++ {
		if ctx.Err() != nil {
			return false
		}
		upCtx, upCancel := context.WithTimeout(ctx, c.uploadTimeout)
		_, err := c.uploader.Upload(upCtx, key, newBundleReader(bundle), int64(len(bundle)), opts)
		upCancel()
		if err == nil {
			return true
		}
		c.log.Warn("forensics: S3 upload attempt failed",
			"key", key, "attempt", i+1, "attempts", attempts, "err", err)
	}
	return false
}

// workloadRef is the parsed canonical workload identity (mirror netpol).
type workloadRef struct {
	namespace string
	ownerKind string
	ownerName string
	podName   string
}

// parseWorkloadID inverts keys.WorkloadID / keys.PodFallbackID, identical to the
// netpol parser (the canonical id is "<namespace>/<owner-kind>/<owner-name>"
// with each segment url.PathEscape'd; the "Pod" sentinel marks the orphan-pod
// fallback whose third segment is the pod name). It is duplicated here rather
// than imported so the forensics package gains no dependency on netpol's
// internals (Ring-clean), exactly as netpol duplicates nothing it does not own.
func parseWorkloadID(id string) (workloadRef, error) {
	parts := strings.Split(id, "/")
	if len(parts) != 3 {
		return workloadRef{}, fmt.Errorf("forensics: malformed workload id %q: want 3 segments", id)
	}
	ns, err := url.PathUnescape(parts[0])
	if err != nil {
		return workloadRef{}, fmt.Errorf("forensics: workload id %q namespace segment: %w", id, err)
	}
	kind, err := url.PathUnescape(parts[1])
	if err != nil {
		return workloadRef{}, fmt.Errorf("forensics: workload id %q owner-kind segment: %w", id, err)
	}
	name, err := url.PathUnescape(parts[2])
	if err != nil {
		return workloadRef{}, fmt.Errorf("forensics: workload id %q name segment: %w", id, err)
	}
	if ns == "" || kind == "" || name == "" {
		return workloadRef{}, fmt.Errorf("forensics: workload id %q has an empty segment", id)
	}
	if kind == "Pod" {
		return workloadRef{namespace: ns, ownerKind: "Pod", podName: name}, nil
	}
	return workloadRef{namespace: ns, ownerKind: kind, ownerName: name}, nil
}
