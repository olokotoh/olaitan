package audit

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
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// AuditTransitionPublisher is the Story 2.8 one-method publish seam (BI-1/BI-5)
// so the sink's tests inject a capturing fake without a real NATS connection,
// mirroring the override OverridePublisher precedent.
type AuditTransitionPublisher interface {
	PublishAuditTransition(ctx context.Context, evt AuditTransition) error
}

// natsAuditTransitionPublisher publishes AuditTransition events to
// subjects.AuditTransitions via PublishJS with a per-(workload, decided_at)
// dedup id, so a drainer re-publish of the same transition is server-side
// deduplicated inside the AUDIT_TRANSITIONS stream's dedup window (mirroring
// the override publisher's WithMsgID derivation, BI-7).
type natsAuditTransitionPublisher struct {
	nc *natsclient.Client
}

// NewNATSTransitionPublisher returns an AuditTransitionPublisher backed by the
// shared NATS client. A nil client is a construction error.
func NewNATSTransitionPublisher(nc *natsclient.Client) (AuditTransitionPublisher, error) {
	if nc == nil {
		return nil, fmt.Errorf("audit: nil nats client for transition publisher")
	}
	return &natsAuditTransitionPublisher{nc: nc}, nil
}

// PublishAuditTransition publishes evt to AUDIT.transitions with WithMsgID
// dedup keyed on the workload and the FSM decision time (decided_at), which is
// stable across a drainer re-publish of the same buffered transition.
func (p *natsAuditTransitionPublisher) PublishAuditTransition(ctx context.Context, evt AuditTransition) error {
	if _, err := p.nc.PublishJS(ctx, subjects.AuditTransitions, evt, jetstream.WithMsgID(transitionMsgID(evt))); err != nil {
		return fmt.Errorf("audit: publish transition: %w", err)
	}
	return nil
}

// transitionMsgID derives the dedup message id for an AUDIT.transitions event:
// the workload plus the FSM decision time, which is stable across a drainer
// re-publish of the same buffered transition but distinct per real transition.
func transitionMsgID(evt AuditTransition) string {
	return evt.WorkloadID + ":" + strconv.FormatInt(evt.DecidedAt.UnixNano(), 10)
}

// TransitionAuditSink is the Story 2.8 AUDIT.transitions sink (BI-1/BI-5). It
// satisfies fsm.TransitionSink and is appended to the existing fsm.MultiSink,
// so every ACTUAL FSM state change (From != To), including operator-pin
// transitions, is projected to an AuditTransition and emitted on the
// append-only AUDIT.transitions subject.
//
// Publish is NON-BLOCKING (BI-5.1): the FSM goroutine fans out to every
// MultiSink member, so the sink MUST NOT do a synchronous PublishJS on that
// path. It therefore mirrors the RedisSink shape - Publish only enqueues onto a
// bounded in-memory buffer (dropping the oldest on overflow, bumping a dropped
// counter) and signals the background Run drainer, which performs the actual
// PublishJS off the hot path. A NATS outage drops audit events with a warning
// rather than ever stalling the FSM.
type TransitionAuditSink struct {
	pub          AuditTransitionPublisher
	log          *slog.Logger
	writeTimeout time.Duration
	drainEvery   time.Duration
	now          func() time.Time

	bufMu   sync.Mutex
	buffer  []AuditTransition
	bufCap  int
	dropped atomic.Int64

	wake chan struct{}
}

// TransitionAuditSinkConfig configures a TransitionAuditSink. Zero values fall
// back to production defaults.
type TransitionAuditSinkConfig struct {
	BufferCap    int           // max buffered events during a NATS outage (default 4096)
	WriteTimeout time.Duration // per-publish NATS write budget (default 2s)
	DrainEvery   time.Duration // background drain cadence (default 5s)
}

// NewTransitionAuditSink builds a TransitionAuditSink. pub must be non-nil; log
// defaults to slog.Default when nil.
func NewTransitionAuditSink(pub AuditTransitionPublisher, log *slog.Logger, cfg TransitionAuditSinkConfig) (*TransitionAuditSink, error) {
	if pub == nil {
		return nil, fmt.Errorf("audit: nil publisher for transition sink")
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
	return &TransitionAuditSink{
		pub:          pub,
		log:          log,
		writeTimeout: cfg.WriteTimeout,
		drainEvery:   cfg.DrainEvery,
		now:          func() time.Time { return time.Now().UTC() },
		buffer:       make([]AuditTransition, 0, 64),
		bufCap:       cfg.BufferCap,
		wake:         make(chan struct{}, 1),
	}, nil
}

// Publish projects the transition to an AuditTransition (stamping published_at
// at now and decided_at from the FSM Timestamp, BI-1.3) and enqueues it for the
// background drainer. It is called by the FSM only on an actual state change
// (From != To, BI-1.2), and NEVER blocks: a full buffer drops the oldest event
// and bumps the dropped counter so the FSM goroutine cannot stall on a NATS
// outage (BI-5.1).
func (s *TransitionAuditSink) Publish(st schema.StateTransition) {
	evt := transitionFromState(st, s.now())
	s.enqueue(evt)
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// enqueue appends to the bounded buffer, dropping the oldest entry (and bumping
// the dropped counter) when full so Publish never blocks.
func (s *TransitionAuditSink) enqueue(evt AuditTransition) {
	s.bufMu.Lock()
	defer s.bufMu.Unlock()
	if len(s.buffer) >= s.bufCap {
		s.buffer = s.buffer[1:]
		s.dropped.Add(1)
	}
	s.buffer = append(s.buffer, evt)
}

// Run is the background drainer. It publishes buffered events whenever Publish
// signals one or on a periodic tick, and flushes best-effort on context
// cancellation. Wire it into the errgroup.
func (s *TransitionAuditSink) Run(ctx context.Context) error {
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
func (s *TransitionAuditSink) drain(ctx context.Context) {
	s.bufMu.Lock()
	batch := s.buffer
	s.buffer = make([]AuditTransition, 0, 64)
	s.bufMu.Unlock()
	if len(batch) == 0 {
		return
	}
	i := 0
	for ; i < len(batch); i++ {
		pctx, cancel := context.WithTimeout(ctx, s.writeTimeout)
		err := s.pub.PublishAuditTransition(pctx, batch[i])
		cancel()
		if err != nil {
			s.log.Warn("audit transition sink: publish failed; will retry",
				"err", err, "workload_id", batch[i].WorkloadID, "after_state", batch[i].AfterState)
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
func (s *TransitionAuditSink) flushBestEffort() {
	ctx, cancel := context.WithTimeout(context.Background(), s.writeTimeout)
	defer cancel()
	s.drain(ctx)
	if d := s.dropped.Load(); d > 0 {
		s.log.Warn("audit transition sink: dropped buffered events over the buffer cap", "dropped", d)
	}
}

// Dropped reports how many transition audit events were dropped due to buffer
// overflow. Exposed for tests and operational logging (the RedisSink.Dropped
// precedent; the Prometheus surface is Story 2.9).
func (s *TransitionAuditSink) Dropped() int64 { return s.dropped.Load() }
