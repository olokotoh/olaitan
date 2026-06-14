package forensics

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
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
	// defaultNFR7Budget is the aggregate ceiling for one capture->upload->delete
	// cycle (NFR7 p99 <= 10s). The per-leg timeouts above are sub-deadlines; this
	// caps their SUM so the aggregate can never exceed the NFR7 ceiling even if
	// the per-leg budgets are retuned upward (LOW, round-1 review).
	defaultNFR7Budget = 10 * time.Second
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
	// NFR7Budget is the aggregate ceiling for one capture->upload->delete cycle
	// (NFR7 p99 <= 10s). The per-leg timeouts are sub-deadlines of this; zero ->
	// default (10s).
	NFR7Budget time.Duration
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
	nfr7Budget     time.Duration

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
	nfr7Budget := cfg.NFR7Budget
	if nfr7Budget <= 0 {
		nfr7Budget = defaultNFR7Budget
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
		nfr7Budget:     nfr7Budget,
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
		"Cumulative forensic capture outcomes labelled by result: captured (full success: capture+upload+delete), deferred (upload failed after retry; pod NOT deleted), skipped (excluded namespace, no pods, or no longer PRESERVED_KILLED), error (capture failure or workload-id parse error), delete_failed (upload acked but the pod delete failed; pod alive + QUARANTINED, deferred to Story 4.7 delete-retry), dropped (Publish queue full) (Story 4.2, FR36/AC5).",
		[]string{"result"},
	)
	if err != nil {
		return err
	}
	c.captureTotal = cv
	for _, result := range []string{"captured", "deferred", "skipped", "error", "delete_failed", "dropped"} {
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
		// MED (round-1): a dropped PRESERVED_KILLED transition leaves the pod
		// undeleted (it was never captured), so the workload remains alive and
		// QUARANTINED with no capture. That is the same contract as a deferred
		// write, so we ALSO increment the deferred counter: Story 4.7's
		// deferred-replay mechanism owns recovering both dropped and deferred
		// captures, and without this a drop would be invisible to 4.7 (the pod
		// would stay alive with no replay signal). The queue is sized for the
		// expected PK rate (defaultQueueSize), so a drop indicates either a PK
		// burst beyond that sizing or a stalled worker.
		c.log.Warn("forensics: capture queue full; dropping kill transition (pod remains QUARANTINED, deferred to Story 4.7 replay)", "workload_id", st.WorkloadID)
		c.count("dropped")
		if c.writesDeferred != nil {
			c.writesDeferred.Inc()
		}
	}
}

// Run is the background worker (BI-4). It drains queued PRESERVED_KILLED
// transitions and performs capture -> upload -> delete for each. Wire it into
// the errgroup; it returns nil on graceful context cancellation.
func (c *Controller) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			// NIT (round-1): on shutdown any captures still buffered in c.queue are
			// ABANDONED (not drained): their pods stay QUARANTINED (Story 4.1
			// retains the deny-all) with no capture this run. Story 4.7's deferred-
			// replay re-drives them after restart; we do not block shutdown to drain
			// (forensic preservation is safe because the pod is left alive+isolated).
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
		// NIT (round-1): ok==false (the FSM no longer tracks this workload) is a
		// deliberate FAIL-OPEN-TO-PROCEED: we still capture+delete. The Publish
		// ToState filter already gated entry on a genuine PRESERVED_KILLED edge,
		// and a workload the FSM has forgotten is most likely already terminal/
		// evicted; refusing to capture there would silently drop evidence. We only
		// veto on an explicit, currently-tracked non-PK state (an operator release).
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
	// NFR7 (LOW, round-1 review): wrap the WHOLE capture->upload->delete cycle in
	// a single aggregate-budget deadline so the sum of the per-leg timeouts can
	// never exceed the NFR7 ceiling (p99 <= 10s), even if a future retune pushes
	// the per-leg budgets higher. context.WithTimeout takes the earlier of the
	// parent and child deadline, so each per-leg WithTimeout below stays a
	// sub-deadline of this aggregate budget.
	ctx, budgetCancel := context.WithTimeout(ctx, c.nfr7Budget)
	defer budgetCancel()

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
	switch c.uploadWithRetry(ctx, key, bundle) {
	case uploadOK:
		// fall through to the delete leg below.
	case uploadAborted:
		// LOW (round-1 review): the context was cancelled (shutdown/abort) rather
		// than a genuine S3 failure. The pod is left in place (it stays
		// QUARANTINED), but this is NOT a real deferred write: do NOT increment
		// writes_deferred_total / count "deferred" (that metric must reflect only
		// real S3 failures, else a clean shutdown would inflate the alert series).
		// Story 4.7 re-drives buffered/abandoned captures on restart.
		c.log.Info("forensics: upload aborted on context cancellation; pod left QUARANTINED (not a deferred write)",
			"namespace", namespace, "pod", podName, "key", key, "sha256", sum)
		return
	case uploadFailed:
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
		// MED (round-1): the forensic record is durably preserved (upload acked),
		// but the pod delete failed. The undeleted pod is alive and QUARANTINED,
		// i.e. a DEFERRED kill: increment olaitan_forensic_writes_deferred_total
		// so Story 4.7 has a replay signal to retry the delete (without this the
		// pod stays alive with no recovery hook). Emit the distinct
		// result="delete_failed" label (not the generic "error") so the
		// upload-succeeded-but-delete-failed case is observable on its own and an
		// operator can act on it (see docs/runbook.md). The write itself
		// succeeded, so this is a delete-side deferral, not an upload deferral.
		c.log.Warn("forensics: pod delete failed after successful forensic upload (pod alive + QUARANTINED, deferred to Story 4.7 delete-retry)",
			"namespace", namespace, "pod", podName, "key", key, "err", delErr)
		c.count("delete_failed")
		if c.writesDeferred != nil {
			c.writesDeferred.Inc()
		}
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

// uploadOutcome is the result of uploadWithRetry. It distinguishes a genuine
// S3 failure (uploadFailed, which defers the write) from a context cancellation
// (uploadAborted, a shutdown/abort that must NOT inflate the deferred metric).
type uploadOutcome int

const (
	uploadOK uploadOutcome = iota
	uploadFailed
	uploadAborted
)

// uploadWithRetry attempts the upload up to 1 + uploadRetries times, each with a
// fresh per-attempt deadline. It returns uploadOK on the first acknowledged
// write. Each attempt re-reads the bundle from a fresh bytes.Reader so a retried
// PUT starts from the bundle head.
//
// LOW (round-1 review): on context cancellation (shutdown/abort) it returns
// uploadAborted rather than uploadFailed, so the caller skips the deferred
// metric (which must reflect only real S3 failures). It also fast-fails clearly
// TERMINAL S3 errors (AccessDenied, NoSuchBucket, InvalidArgument incl. KMS
// directive errors): retrying those cannot succeed, so the write is deferred
// immediately rather than burning the retry budget and the per-leg timeouts.
func (c *Controller) uploadWithRetry(ctx context.Context, key string, bundle []byte) uploadOutcome {
	attempts := 1 + c.uploadRetries
	opts := UploadOptions{KMSKeyAlias: c.kmsKeyAlias}
	for i := 0; i < attempts; i++ {
		if ctx.Err() != nil {
			return uploadAborted
		}
		upCtx, upCancel := context.WithTimeout(ctx, c.uploadTimeout)
		_, err := c.uploader.Upload(upCtx, key, newBundleReader(bundle), int64(len(bundle)), opts)
		upCancel()
		if err == nil {
			return uploadOK
		}
		// Distinguish a cancellation of the parent ctx (shutdown/abort) from a
		// real upload error: a per-attempt deadline expiry leaves ctx.Err() nil
		// (only upCtx expired) and is a genuine transient failure worth retrying.
		if ctx.Err() != nil {
			return uploadAborted
		}
		if isTerminalUploadError(err) {
			c.log.Warn("forensics: S3 upload failed with a terminal error; deferring without retry",
				"key", key, "attempt", i+1, "attempts", attempts, "err", err)
			return uploadFailed
		}
		c.log.Warn("forensics: S3 upload attempt failed",
			"key", key, "attempt", i+1, "attempts", attempts, "err", err)
	}
	return uploadFailed
}

// isTerminalUploadError reports whether err is a clearly non-retryable S3 error
// (the request can never succeed by retrying): access denied, a missing bucket,
// or an invalid argument (which covers a malformed/denied SSE-KMS directive).
// Transient errors (timeouts, 5xx, connection refused) are NOT terminal and are
// retried. minio.ToErrorResponse extracts the S3 error code from a minio-go
// error; a non-S3 error (e.g. a dial failure) has an empty Code and is treated
// as transient.
func isTerminalUploadError(err error) bool {
	switch minio.ToErrorResponse(err).Code {
	case "AccessDenied", "NoSuchBucket", "InvalidArgument", "KMS.NotFoundException", "KMSKeyNotFoundException":
		return true
	default:
		return false
	}
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
