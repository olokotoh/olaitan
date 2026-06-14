// Package deferq holds the Story 4.7 Redis-backed deferred-report queue and its
// background drain worker (AC2/AC3). It is the resilience layer wrapped around
// the Story 4.6 durable report writer (internal/report/archive): when an inline
// S3 PUT fails transiently beyond the short inline retry budget, the DFIR agent
// ENQUEUES the (already-redacted, content-addressed) report bytes here, and the
// drain worker re-PUTs them via the SAME archive.ReportArchive when S3 recovers,
// in FIFO order, idempotently via the content-addressed key + the 4.6 HEAD-dedup.
//
// # Trust boundary and Ring discipline (BI-11)
//
// The deferred report is a downstream post-mortem artifact. This package adds NO
// score-fold path and imports NO FSM package: it only re-PUTs bytes and moves a
// gauge. It depends on the backend-neutral archive.ReportArchive INTERFACE and
// the internal/redis wrapper, not on minio-go or go-redis directly.
//
// # Scope fence (BI-11)
//
// This package does the deferred queue + the drain worker + the bounded-queue
// drop policy ONLY. The transient/permanent S3 classifier lives beside the 4.6
// minio-error helpers (archive.IsTransientS3); the inline short retry lives on
// the DFIR Generate span (internal/report/dfir); the metric family is owned by
// the DFIR agent and the handles are injected here (one family, no duplicate
// registration). The notification webhook is Story 4.8; the dashboards are 4.9.
package deferq

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/olokotoh/olaitan/internal/redis"
	"github.com/olokotoh/olaitan/internal/report/archive"
)

// envelopeSchemaVersion stamps the deferred-queue envelope shape (BI-4) so a
// future shape change is detectable; the drain dead-letters an undecodable or
// unknown-version head rather than blocking the queue (BI-6).
const envelopeSchemaVersion = 1

// DefaultDrainEvery is the drain worker's tick cadence (Open Assumption 5): the
// RedactionAuditSink.DrainEvery default of 5s, with a wake-on-enqueue channel
// for promptness so a recovery is observed quickly.
const DefaultDrainEvery = 5 * time.Second

// DefaultMaxLen is the bounded-queue cap (PO ratification 7 / Open Assumption 3):
// when reports:deferred reaches 1000 entries the enqueuer drops the OLDEST and
// counts it loudly. A 1000-report backlog is a very long S3 outage.
const DefaultMaxLen = 1000

// envelope is the JSON item stored in the reports:deferred Redis LIST (BI-4). It
// carries the redacted report BYTES (the bytes only exist in-process at the DFIR
// writeReport seam: the wire REPORTS.generated carries only the SHA + key) plus
// the content-addressed key and the PutOptions-shaped fields the drain needs to
// reconstruct archive.PutOptions and re-call archive.Put without re-generating
// the report.
type envelope struct {
	SchemaVersion          int    `json:"schema_version"`
	Key                    string `json:"key"`
	Body                   []byte `json:"body"` // encoding/json base64-encodes a []byte
	KMSKeyAlias            string `json:"kms_key_alias,omitempty"`
	RetentionMode          string `json:"retention_mode,omitempty"`
	RetentionPeriodSeconds int64  `json:"retention_period_seconds,omitempty"`
	IncidentID             string `json:"incident_id,omitempty"`
	EnqueuedAt             string `json:"enqueued_at"`
}

// listClient is the minimal internal/redis seam the queue + drainer depend on:
// exactly the deferred-LIST operations. *redis.Client satisfies it directly; a
// fake satisfies it in unit tests (miniredis is used through the real client in
// the package tests, but the seam keeps the dependency narrow and explicit).
type listClient interface {
	EnqueueDeferredReport(ctx context.Context, envelope []byte, maxLen int64) (int64, error)
	PeekDeferredReport(ctx context.Context) ([]byte, bool, error)
	CommitDeferredReport(ctx context.Context) error
	DeferredReportLen(ctx context.Context) (int64, error)
}

// Metrics carries the report-write metric handles the DFIR agent registered (one
// family, no duplicate registration, BI-5). The queue and the drainer move these
// rather than registering their own:
//
//   - Deferred is the live deferred-queue depth gauge
//     (olaitan_report_writes_deferred_count): Inc on enqueue, Dec on a drained or
//     dead-lettered head, Set on startup seed.
//   - Dropped counts entries dropped to honour the bounded-queue cap
//     (olaitan_report_writes_dropped_total{reason}).
//   - Writes is the shared olaitan_report_writes_total{result} counter; the drain
//     records deduped on a HEAD-dedup and error on a dead-lettered permanent
//     failure. (Story 4.9 BI-5: result="drained" is RETIRED here; a successful
//     re-PUT now increments the dedicated Drained counter instead.)
//   - Drained is the dedicated olaitan_report_writes_deferred_drained_total
//     counter (Story 4.9 AC2/BI-5): the SINGLE source of truth for a successfully
//     re-PUT deferred report. A confirmed (non-deduped) drain increments this and
//     no longer touches the shared writes counter, so a drain is never
//     double-counted.
type Metrics struct {
	Deferred prometheus.Gauge
	Dropped  *prometheus.CounterVec
	Writes   *prometheus.CounterVec
	Drained  prometheus.Counter
}

// Write-outcome label values the drain worker records on the shared
// olaitan_report_writes_total{result} counter. deduped marks a HEAD-dedup no-op;
// error a dead-lettered permanent failure. (Story 4.9 BI-5: the "drained" value
// is RETIRED from the shared counter; a confirmed re-PUT increments the dedicated
// Drained counter instead, so a drain is counted in exactly one place.)
const (
	writeResultDeduped = "deduped"
	writeResultError   = "error"
)

// droppedReasonCap is the only drop reason today: the bounded-queue cap was
// reached on enqueue and the oldest entry was dropped (PO ratification 7).
const droppedReasonCap = "queue_full"

// DeferredQueue is the enqueue seam the DFIR agent holds (BI-3). On a
// transient-beyond-budget inline write it builds the envelope and RPUSHes it,
// incrementing the deferred-depth gauge and (on a cap overflow) the dropped
// counter. A failed/slow enqueue surfaces an error the caller falls back on (the
// 4.6 fail-loud last resort, BI-7); the gauge is incremented on a confirmed
// enqueue only.
type DeferredQueue struct {
	client listClient
	maxLen int64
	metric Metrics
	log    *slog.Logger
	now    func() time.Time
	// wake is signalled on a successful enqueue so a Run loop drains promptly on
	// recovery rather than waiting a full tick. Buffered length 1, never blocks.
	wake chan struct{}
}

// NewDeferredQueue constructs the enqueue seam. client and the metric handles
// must be non-nil; maxLen <= 0 falls back to DefaultMaxLen; log defaults to
// slog.Default. The concrete *redis.Client is pinned so callers cannot pass an
// arbitrary type (the listClient seam is unexported and used only by the package
// tests' fake).
func NewDeferredQueue(client *redis.Client, maxLen int, metric Metrics, log *slog.Logger) (*DeferredQueue, error) {
	if client == nil {
		// Guard the typed-nil-into-interface pitfall: a nil *redis.Client wrapped
		// in the listClient interface is non-nil, so reject it here.
		return nil, errors.New("deferq: nil redis client")
	}
	return newDeferredQueue(client, maxLen, metric, log)
}

// newDeferredQueue is the seam-typed constructor (the exported one pins the
// concrete *redis.Client so callers cannot pass an arbitrary type; tests use this
// with a fake listClient).
func newDeferredQueue(client listClient, maxLen int, metric Metrics, log *slog.Logger) (*DeferredQueue, error) {
	if client == nil {
		return nil, errors.New("deferq: nil redis client")
	}
	if metric.Deferred == nil || metric.Dropped == nil || metric.Writes == nil {
		return nil, errors.New("deferq: nil metric handle (Deferred, Dropped, and Writes are all required)")
	}
	if log == nil {
		log = slog.Default()
	}
	ml := int64(maxLen)
	if ml <= 0 {
		ml = DefaultMaxLen
	}
	return &DeferredQueue{
		client: client,
		maxLen: ml,
		metric: metric,
		log:    log,
		now:    func() time.Time { return time.Now().UTC() },
		wake:   make(chan struct{}, 1),
	}, nil
}

// Enqueue marshals the deferred-report envelope from the report key, the
// redacted bytes, the resolved PutOptions, and the incident id, then RPUSHes it
// onto reports:deferred (BI-3/BI-4). On a successful enqueue it increments the
// deferred-depth gauge and, when the bounded-queue cap dropped the oldest
// entries, the dropped counter (a loud operator signal, BI-6). It returns an
// error ONLY when the enqueue itself failed (Redis down / slow): the caller then
// falls back to the 4.6 fail-loud path (BI-7). The gauge is incremented on a
// confirmed enqueue only.
//
// The caller MUST pass a SHORT-deadline ctx (the redis WriteTimeout) so a slow
// Redis is treated like a Redis failure rather than blocking the synchronous
// Generate span (BI-8).
func (q *DeferredQueue) Enqueue(ctx context.Context, key string, body []byte, opts archive.PutOptions, incidentID string) error {
	if q == nil {
		return errors.New("deferq: nil deferred queue")
	}
	env := envelope{
		SchemaVersion:          envelopeSchemaVersion,
		Key:                    key,
		Body:                   body,
		KMSKeyAlias:            opts.KMSKeyAlias,
		RetentionMode:          string(opts.RetentionMode),
		RetentionPeriodSeconds: int64(opts.RetentionPeriod / time.Second),
		IncidentID:             incidentID,
		EnqueuedAt:             q.now().Format(time.RFC3339Nano),
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("deferq: marshal envelope for key %q: %w", key, err)
	}
	dropped, err := q.client.EnqueueDeferredReport(ctx, raw, q.maxLen)
	if err != nil {
		return fmt.Errorf("deferq: enqueue key %q: %w", key, err)
	}
	q.metric.Deferred.Inc()
	if dropped > 0 {
		// The bounded queue dropped the oldest entries to keep the freshest
		// reports (PO ratification 7). This is a loud operator signal: a very long
		// S3 outage has backed the queue past its cap.
		q.metric.Dropped.WithLabelValues(droppedReasonCap).Add(float64(dropped))
		q.metric.Deferred.Sub(float64(dropped))
		q.log.Error("deferq: deferred-report queue full, dropped oldest reports (very long S3 outage; freshest reports kept)",
			"dropped", dropped, "max_len", q.maxLen, "incident_id", incidentID)
	}
	q.signalWake()
	return nil
}

func (q *DeferredQueue) signalWake() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

// DeferredDrainer is the background drain worker (AC3). It mirrors the Story 3.1
// RedactionAuditSink.Run ticker + wake + ctx-cancel lifecycle: a 5s tick (with a
// wake-on-enqueue channel) re-PUTs the head of reports:deferred via the injected
// archive.ReportArchive, FIFO, committing the LPOP only after a confirmed re-PUT
// (crash-safe, BI-9), and decrementing the deferred-depth gauge per committed
// head. Launch Run(ctx) in the errgroup adjacent to the other report wiring.
type DeferredDrainer struct {
	queue      *DeferredQueue
	arch       archive.ReportArchive
	drainEvery time.Duration
	log        *slog.Logger
}

// NewDeferredDrainer constructs the drain worker over the same queue (for the
// wake channel + the metric handles) and the injected archive. arch must be
// non-nil; drainEvery <= 0 falls back to DefaultDrainEvery.
func NewDeferredDrainer(queue *DeferredQueue, arch archive.ReportArchive, drainEvery time.Duration, log *slog.Logger) (*DeferredDrainer, error) {
	if queue == nil {
		return nil, errors.New("deferq: nil deferred queue for drainer")
	}
	if arch == nil {
		return nil, errors.New("deferq: nil archive for drainer")
	}
	if log == nil {
		log = slog.Default()
	}
	if drainEvery <= 0 {
		drainEvery = DefaultDrainEvery
	}
	return &DeferredDrainer{queue: queue, arch: arch, drainEvery: drainEvery, log: log}, nil
}

// SeedGauge sets the deferred-depth gauge to the current Redis LIST length so a
// process restart with a non-empty backlog reports the true depth (AC4). It is
// best-effort: a Redis error is logged and the gauge left at zero.
func (d *DeferredDrainer) SeedGauge(ctx context.Context) {
	n, err := d.queue.client.DeferredReportLen(ctx)
	if err != nil {
		d.log.Warn("deferq: could not seed deferred-depth gauge from redis", "err", err)
		return
	}
	d.queue.metric.Deferred.Set(float64(n))
}

// Run is the background drainer (AC3). It drains on a wake signal or a periodic
// tick and returns nil on ctx cancellation (no best-effort flush: a still-down S3
// cannot be drained at shutdown, and the backlog persists durably in Redis for
// the next process to drain). Wire it into the errgroup.
func (d *DeferredDrainer) Run(ctx context.Context) error {
	d.SeedGauge(ctx)
	ticker := time.NewTicker(d.drainEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-d.queue.wake:
			d.drain(ctx)
		case <-ticker.C:
			d.drain(ctx)
		}
	}
}

// DrainOnce runs a single drain pass (the Run loop's per-tick body) and returns.
// It is exported so callers in other packages (and tests) can drive a
// deterministic drain on demand (e.g. immediately after declaring S3 recovery)
// without waiting for the Run ticker. Run uses the same pass internally.
func (d *DeferredDrainer) DrainOnce(ctx context.Context) { d.drain(ctx) }

// drain re-PUTs the head of reports:deferred via the injected archive, FIFO,
// until the queue is empty or S3 is still down. The LPOP commit happens AFTER a
// confirmed (or HEAD-deduped) re-PUT, so a crash mid-drain re-attempts the same
// content-addressed key on restart, which the archive dedups (BI-9). On a
// still-transient error it STOPS this drain pass (leaving the head in place,
// FIFO preserved) and waits for the next tick. On a PERMANENT error it
// dead-letters the head (logs loudly, commits the LPOP, decrements the gauge) so
// a poison 4xx never loops forever (BI-6). An undecodable head is likewise
// dead-lettered (BI-4).
func (d *DeferredDrainer) drain(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		raw, ok, err := d.queue.client.PeekDeferredReport(ctx)
		if err != nil {
			// Redis read failed (Redis down / slow): stop this pass, retry next
			// tick. The backlog persists durably.
			d.log.Warn("deferq: peek of deferred-report head failed; will retry", "err", err)
			return
		}
		if !ok {
			// Queue empty: nothing to drain.
			return
		}
		var env envelope
		if derr := json.Unmarshal(raw, &env); derr != nil || env.SchemaVersion != envelopeSchemaVersion || env.Key == "" {
			// Undecodable or unknown-version head: dead-letter it (commit the LPOP,
			// decrement the gauge) so it never blocks the drain (BI-4/BI-6).
			d.deadLetter(ctx, "undecodable or unknown-version deferred-report envelope", env.Key, env.IncidentID, derr)
			continue
		}
		opts := archive.PutOptions{
			KMSKeyAlias:     env.KMSKeyAlias,
			RetentionMode:   archive.RetentionMode(env.RetentionMode),
			RetentionPeriod: time.Duration(env.RetentionPeriodSeconds) * time.Second,
		}
		receipt, perr := d.arch.Put(ctx, env.Key, env.Body, opts)
		if perr != nil {
			if archive.IsTransientS3(perr) {
				// S3 still down: leave the head in place (FIFO preserved), retry on
				// the next tick. Do NOT commit the LPOP, do NOT decrement.
				d.log.Info("deferq: deferred-report re-PUT still failing transiently; leaving head queued",
					"key", env.Key, "incident_id", env.IncidentID, "err", perr)
				return
			}
			// Permanent (4xx misconfig): a re-PUT will never succeed. Dead-letter
			// the poison head (BI-6).
			d.deadLetter(ctx, "permanent S3 error re-PUTting deferred report (4xx misconfiguration; dead-lettered)", env.Key, env.IncidentID, perr)
			continue
		}
		// Re-PUT confirmed (or HEAD-deduped): commit the LPOP AFTER the durable
		// write, then decrement the gauge (BI-9).
		if cerr := d.queue.client.CommitDeferredReport(ctx); cerr != nil {
			// The re-PUT succeeded but the LPOP failed: do NOT decrement (the head
			// is still in Redis). A re-drain re-PUTs the same content-addressed key,
			// which the archive dedups (BI-9). Stop this pass; retry next tick.
			d.log.Warn("deferq: deferred-report re-PUT succeeded but LPOP commit failed; will re-drain (deduped no-op)",
				"key", env.Key, "incident_id", env.IncidentID, "err", cerr)
			return
		}
		// Story 4.9 (AC2, BI-5): a confirmed (non-deduped) re-PUT increments the
		// dedicated Drained counter (the single source of truth for drains); the
		// retired result="drained" value is NO LONGER recorded on the shared writes
		// counter. A HEAD-deduped drain stays result="deduped" on the shared counter
		// (a distinct outcome, not a drain).
		result := "drained"
		if receipt.Deduped {
			result = writeResultDeduped
			d.queue.metric.Writes.WithLabelValues(writeResultDeduped).Inc()
		} else {
			d.queue.metric.Drained.Inc()
		}
		d.queue.metric.Deferred.Dec()
		d.log.Info("deferq: deferred report drained to durable archive",
			"key", receipt.Key, "incident_id", env.IncidentID, "result", result)
	}
}

// deadLetter commits the LPOP for a poison head (undecodable envelope or a
// permanent 4xx re-PUT error), logs loudly for operator alerting, counts the
// result=error on the shared write counter, and decrements the deferred-depth
// gauge so the queue makes forward progress (BI-6). A failed LPOP leaves the head
// in place (it is retried next pass); the gauge is decremented on a committed
// removal only.
func (d *DeferredDrainer) deadLetter(ctx context.Context, reason, key, incidentID string, cause error) {
	d.log.Error("deferq: dead-lettering poison deferred-report head ("+reason+")",
		"key", key, "incident_id", incidentID, "err", cause)
	if cerr := d.queue.client.CommitDeferredReport(ctx); cerr != nil {
		d.log.Warn("deferq: LPOP of poison deferred-report head failed; will retry", "key", key, "err", cerr)
		return
	}
	d.queue.metric.Writes.WithLabelValues(writeResultError).Inc()
	d.queue.metric.Deferred.Dec()
}
