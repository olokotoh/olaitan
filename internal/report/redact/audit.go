package redact

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// SchemaVersionRedactions is the AUDIT.redactions wire schema_version, per the
// architecture's schema-versioning ADR (architecture.md:244), registered in
// docs/schema-versioning.md beside the Story 2.8 audit.*.v1 rows.
const SchemaVersionRedactions = "audit.redactions.v1"

// AuditRedaction is the AUDIT.redactions wire event (schema_version
// audit.redactions.v1, BI-5.2): the SIEM projection of a single RedactionEvent.
// It records that a field at field_path was redacted for reason, NOT the secret
// that was redacted: there is deliberately NO value/before field, so the audit
// trail is safe to ship to a SIEM (NFR18, BI-5.3). Both redacted_at (the
// redaction decision time) and published_at (the audit-emission time) are
// carried, deliberately distinct (BI-3.4).
//
// Authoritative validation source: docs/schemas/audit/redactions.json.
type AuditRedaction struct {
	SchemaVersion string `json:"schema_version"`
	// PackageID is EvidencePackage.PackageID, threaded onto every event in the
	// redaction batch (AC4).
	PackageID string `json:"package_id"`
	// FieldPath is the dotted/indexed location of the redacted field within the
	// EvidencePackage (BI-4.4).
	FieldPath string `json:"field_path"`
	// Reason is one of the closed Reason* enum values (BI-4.3).
	Reason string `json:"reason"`
	// WorkloadID is carried for SIEM correlation when known (omitempty).
	WorkloadID string `json:"workload_id,omitempty"`
	// RedactedAt is the redaction decision time (BI-3.4).
	RedactedAt time.Time `json:"redacted_at"`
	// PublishedAt is when the audit event was emitted onto NATS (BI-3.4),
	// stamped by the sink at emit time.
	PublishedAt time.Time `json:"published_at"`
}

// auditFromEvent builds the AuditRedaction wire event from an in-process
// RedactionEvent, stamping schema_version and the package id and carrying NO
// secret value on the wire (NFR18, BI-5.3). published_at is stamped later by the
// sink at emit time; redacted_at carries the decision time from the event.
func auditFromEvent(evt RedactionEvent, packageID string, now time.Time) AuditRedaction {
	return AuditRedaction{
		SchemaVersion: SchemaVersionRedactions,
		PackageID:     packageID,
		FieldPath:     evt.FieldPath,
		Reason:        evt.Reason,
		WorkloadID:    evt.WorkloadID,
		RedactedAt:    evt.RedactedAt,
		PublishedAt:   now,
	}
}

// AuditRedactionPublisher is the one-method publish seam (BI-3.3) so the sink's
// tests inject a capturing fake without a real NATS connection, mirroring the
// Story 2.8 AuditTransitionPublisher precedent.
type AuditRedactionPublisher interface {
	PublishAuditRedaction(ctx context.Context, evt AuditRedaction) error
}

// natsAuditRedactionPublisher publishes AuditRedaction events to
// subjects.AuditRedactions via PublishJS with a per-(workload, package,
// field_path, redacted_at) dedup id, so a drainer re-publish of the same
// redaction is server-side deduplicated inside the AUDIT_REDACTIONS stream's
// dedup window (the natsAuditTransitionPublisher precedent).
type natsAuditRedactionPublisher struct {
	nc *natsclient.Client
}

// NewNATSRedactionPublisher returns an AuditRedactionPublisher backed by the
// shared NATS client. A nil client is a construction error.
func NewNATSRedactionPublisher(nc *natsclient.Client) (AuditRedactionPublisher, error) {
	if nc == nil {
		return nil, fmt.Errorf("redact: nil nats client for redaction publisher")
	}
	return &natsAuditRedactionPublisher{nc: nc}, nil
}

// PublishAuditRedaction publishes evt to AUDIT.redactions with WithMsgID dedup.
func (p *natsAuditRedactionPublisher) PublishAuditRedaction(ctx context.Context, evt AuditRedaction) error {
	if _, err := p.nc.PublishJS(ctx, subjects.AuditRedactions, evt, jetstream.WithMsgID(redactionMsgID(evt))); err != nil {
		return fmt.Errorf("redact: publish redaction: %w", err)
	}
	return nil
}

// redactionMsgID derives the dedup message id for an AUDIT.redactions event:
// the package, field path, and redaction decision time, which is stable across a
// drainer re-publish of the same buffered redaction but distinct per real
// redaction (the transitionMsgID precedent, BI-4.2).
func redactionMsgID(evt AuditRedaction) string {
	return evt.PackageID + ":" + evt.FieldPath + ":" + strconv.FormatInt(evt.RedactedAt.UnixNano(), 10)
}

// RedactionAuditSink is the Story 3.1 AUDIT.redactions sink (BI-3.3/BI-6.2). It
// mirrors the Story 2.8 TransitionAuditSink shape: a bounded in-memory buffer, a
// non-blocking Enqueue that drops the oldest on overflow and bumps an
// atomic.Int64 dropped counter, a background Run(ctx) drainer that PublishJSes
// with WithMsgID dedup, a best-effort shutdown flush, and a Dropped() accessor.
//
// Redaction is NOT on the FSM hot path but IS on the synchronous pre-LLM path,
// so the buffered+drainer shape keeps a NATS stall from adding latency to the
// LLM call: a redaction-audit failure NEVER blocks or fails the redaction
// itself (BI-6.2).
type RedactionAuditSink struct {
	pub          AuditRedactionPublisher
	log          *slog.Logger
	writeTimeout time.Duration
	drainEvery   time.Duration
	now          func() time.Time

	bufMu   sync.Mutex
	buffer  []AuditRedaction
	bufCap  int
	dropped atomic.Int64

	wake chan struct{}
}

// RedactionAuditSinkConfig configures a RedactionAuditSink. Zero values fall
// back to production defaults.
type RedactionAuditSinkConfig struct {
	BufferCap    int           // max buffered events during a NATS outage (default 4096)
	WriteTimeout time.Duration // per-publish NATS write budget (default 2s)
	DrainEvery   time.Duration // background drain cadence (default 5s)
}

// NewRedactionAuditSink builds a RedactionAuditSink. pub must be non-nil; log
// defaults to slog.Default when nil.
func NewRedactionAuditSink(pub AuditRedactionPublisher, log *slog.Logger, cfg RedactionAuditSinkConfig) (*RedactionAuditSink, error) {
	if pub == nil {
		return nil, fmt.Errorf("redact: nil publisher for redaction sink")
	}
	if log == nil {
		log = slog.Default()
	}
	if cfg.BufferCap <= 0 {
		cfg.BufferCap = 4096
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = 2 * time.Second
	}
	if cfg.DrainEvery <= 0 {
		cfg.DrainEvery = 5 * time.Second
	}
	return &RedactionAuditSink{
		pub:          pub,
		log:          log,
		writeTimeout: cfg.WriteTimeout,
		drainEvery:   cfg.DrainEvery,
		now:          func() time.Time { return time.Now().UTC() },
		buffer:       make([]AuditRedaction, 0, 64),
		bufCap:       cfg.BufferCap,
		wake:         make(chan struct{}, 1),
	}, nil
}

// Enqueue projects each RedactionEvent to an AuditRedaction (stamping
// published_at at now, BI-3.4) and enqueues it for the background drainer. It is
// best-effort and NEVER blocks: a full buffer drops the oldest event and bumps
// the dropped counter, so a NATS outage can never add latency to or fail the
// redaction / LLM call (BI-6.2). A nil sink (off-by-default) is handled by the
// caller, which simply does not invoke Enqueue.
func (s *RedactionAuditSink) Enqueue(events []RedactionEvent, packageID string) {
	if s == nil || len(events) == 0 {
		return
	}
	now := s.now()
	s.bufMu.Lock()
	for _, evt := range events {
		if len(s.buffer) >= s.bufCap {
			s.buffer = s.buffer[1:]
			s.dropped.Add(1)
		}
		s.buffer = append(s.buffer, auditFromEvent(evt, packageID, now))
	}
	s.bufMu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Run is the background drainer. It publishes buffered events whenever Enqueue
// signals one or on a periodic tick, and flushes best-effort on context
// cancellation. Wire it into the errgroup.
func (s *RedactionAuditSink) Run(ctx context.Context) error {
	ticker := time.NewTicker(s.drainEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			s.flushBestEffort()
			return nil
		case <-s.wake:
			s.drain(ctx)
		case <-ticker.C:
			s.drain(ctx)
		}
	}
}

// drain publishes buffered events in order with a single attempt each. On the
// first publish failure it re-prepends the unpublished remainder (preserving
// order) so events are retried on the next tick rather than lost while NATS is
// still down. The msgID dedup makes a retry of an already-accepted event a
// server-side no-op.
func (s *RedactionAuditSink) drain(ctx context.Context) {
	s.bufMu.Lock()
	batch := s.buffer
	s.buffer = make([]AuditRedaction, 0, 64)
	s.bufMu.Unlock()
	if len(batch) == 0 {
		return
	}
	i := 0
	for ; i < len(batch); i++ {
		pctx, cancel := context.WithTimeout(ctx, s.writeTimeout)
		err := s.pub.PublishAuditRedaction(pctx, batch[i])
		cancel()
		if err != nil {
			s.log.Warn("redaction audit sink: publish failed; will retry",
				"err", err, "package_id", batch[i].PackageID, "field_path", batch[i].FieldPath)
			break
		}
	}
	if i < len(batch) {
		remainder := batch[i:]
		s.bufMu.Lock()
		s.buffer = append(remainder, s.buffer...)
		if over := len(s.buffer) - s.bufCap; over > 0 {
			// Drop from the TAIL (the newest events that arrived during the
			// drain) so the older un-published remainder is preserved.
			s.dropped.Add(int64(over))
			s.buffer = s.buffer[:len(s.buffer)-over]
		}
		s.bufMu.Unlock()
	}
}

// flushBestEffort attempts a single bounded drain on shutdown so an in-flight
// buffer is not silently lost when the context is cancelled.
func (s *RedactionAuditSink) flushBestEffort() {
	ctx, cancel := context.WithTimeout(context.Background(), s.writeTimeout)
	defer cancel()
	s.drain(ctx)
	if d := s.dropped.Load(); d > 0 {
		s.log.Warn("redaction audit sink: dropped buffered events over the buffer cap", "dropped", d)
	}
}

// Dropped reports how many redaction audit events were dropped due to buffer
// overflow. Exposed for tests and operational logging (the TransitionAuditSink
// .Dropped precedent; the Prometheus surface is deferred to the Epic 3
// observability story, matching the Story 2.8/2.9 boundary).
func (s *RedactionAuditSink) Dropped() int64 { return s.dropped.Load() }
