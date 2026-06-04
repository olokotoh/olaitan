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
	"github.com/olokotoh/olaitan/internal/response/netpol"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// AuditPolicyPublisher is the Story 2.8 one-method publish seam (BI-3/BI-5) so
// the adapter's tests inject a capturing fake without a real NATS connection.
type AuditPolicyPublisher interface {
	PublishAuditPolicy(ctx context.Context, evt AuditPolicy) error
}

// natsAuditPolicyPublisher publishes AuditPolicy events to
// subjects.AuditPolicies via PublishJS with a per-mutation dedup id (workload,
// policy, action, published_at) that is stable across a drainer re-publish but
// distinct per real mutation, so the SIEM record is neither inflated by a
// retry nor collapsed across distinct mutations.
type natsAuditPolicyPublisher struct {
	nc *natsclient.Client
}

// NewNATSPolicyPublisher returns an AuditPolicyPublisher backed by the shared
// NATS client. A nil client is a construction error.
func NewNATSPolicyPublisher(nc *natsclient.Client) (AuditPolicyPublisher, error) {
	if nc == nil {
		return nil, fmt.Errorf("audit: nil nats client for policy publisher")
	}
	return &natsAuditPolicyPublisher{nc: nc}, nil
}

// PublishAuditPolicy publishes evt to AUDIT.policies with WithMsgID dedup.
func (p *natsAuditPolicyPublisher) PublishAuditPolicy(ctx context.Context, evt AuditPolicy) error {
	if _, err := p.nc.PublishJS(ctx, subjects.AuditPolicies, evt, jetstream.WithMsgID(policyMsgID(evt))); err != nil {
		return fmt.Errorf("audit: publish policy: %w", err)
	}
	return nil
}

// policyMsgID derives the dedup message id for an AUDIT.policies event: the
// workload, policy, action, and emission time, stable across a drainer
// re-publish but distinct per real mutation.
func policyMsgID(evt AuditPolicy) string {
	return evt.WorkloadID + ":" + evt.PolicyName + ":" + evt.Action + ":" + strconv.FormatInt(evt.PublishedAt.UnixNano(), 10)
}

// PolicyAuditSink is the Story 2.8 AUDIT.policies adapter (BI-3/BI-5.3). It
// satisfies netpol.PolicyAuditPublisher (PublishPolicyAudit), so the netpol
// Manager can record each real NetworkPolicy mutation on the append-only
// AUDIT.policies subject WITHOUT importing internal/nats or internal/subjects -
// the NATS dependency lives here, keeping netpol Ring-clean (BI-12).
//
// PublishPolicyAudit is NON-BLOCKING (BI-5.3): it projects the netpol mutation
// fact to an AuditPolicy (stamping published_at) and enqueues it onto a bounded
// buffer (dropping the oldest on overflow), then the background Run drainer does
// the actual PublishJS off the netpol apply worker. A NATS stall can therefore
// never wedge an NFR6-critical NetworkPolicy apply, and an audit-publish failure
// never changes the apply result.
type PolicyAuditSink struct {
	pub          AuditPolicyPublisher
	log          *slog.Logger
	writeTimeout time.Duration
	drainEvery   time.Duration
	now          func() time.Time

	bufMu   sync.Mutex
	buffer  []AuditPolicy
	bufCap  int
	dropped atomic.Int64

	wake chan struct{}
}

// PolicyAuditSinkConfig configures a PolicyAuditSink. Zero values fall back to
// production defaults.
type PolicyAuditSinkConfig struct {
	BufferCap    int           // max buffered events during a NATS outage (default 4096)
	WriteTimeout time.Duration // per-publish NATS write budget (default 2s)
	DrainEvery   time.Duration // background drain cadence (default 5s)
}

// NewPolicyAuditSink builds a PolicyAuditSink. pub must be non-nil; log defaults
// to slog.Default when nil.
func NewPolicyAuditSink(pub AuditPolicyPublisher, log *slog.Logger, cfg PolicyAuditSinkConfig) (*PolicyAuditSink, error) {
	if pub == nil {
		return nil, fmt.Errorf("audit: nil publisher for policy sink")
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
	return &PolicyAuditSink{
		pub:          pub,
		log:          log,
		writeTimeout: cfg.WriteTimeout,
		drainEvery:   cfg.DrainEvery,
		now:          func() time.Time { return time.Now().UTC() },
		buffer:       make([]AuditPolicy, 0, 64),
		bufCap:       cfg.BufferCap,
		wake:         make(chan struct{}, 1),
	}, nil
}

// PublishPolicyAudit satisfies netpol.PolicyAuditPublisher. It projects the
// netpol mutation event to an AuditPolicy (stamping published_at at enqueue
// time) and enqueues it for the background drainer. It NEVER blocks: a full
// buffer drops the oldest event and bumps the dropped counter so the netpol
// apply worker cannot stall on a NATS outage (BI-5.3).
func (s *PolicyAuditSink) PublishPolicyAudit(evt netpol.PolicyAuditEvent) {
	wire := policyFromEvent(evt, s.now())
	s.enqueue(wire)
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// enqueue appends to the bounded buffer, dropping the oldest entry (and bumping
// the dropped counter) when full so PublishPolicyAudit never blocks.
func (s *PolicyAuditSink) enqueue(evt AuditPolicy) {
	s.bufMu.Lock()
	defer s.bufMu.Unlock()
	if len(s.buffer) >= s.bufCap {
		s.buffer = s.buffer[1:]
		s.dropped.Add(1)
	}
	s.buffer = append(s.buffer, evt)
}

// Run is the background drainer (the RedisSink.Run precedent). Wire it into the
// errgroup.
func (s *PolicyAuditSink) Run(ctx context.Context) error {
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

// drain publishes buffered events in order with a single attempt each,
// re-prepending the unpublished remainder on the first failure so events are
// retried on the next tick. The msgID dedup makes a retry of an
// already-accepted event a server-side no-op.
func (s *PolicyAuditSink) drain(ctx context.Context) {
	s.bufMu.Lock()
	batch := s.buffer
	s.buffer = make([]AuditPolicy, 0, 64)
	s.bufMu.Unlock()
	if len(batch) == 0 {
		return
	}
	i := 0
	for ; i < len(batch); i++ {
		pctx, cancel := context.WithTimeout(ctx, s.writeTimeout)
		err := s.pub.PublishAuditPolicy(pctx, batch[i])
		cancel()
		if err != nil {
			s.log.Warn("audit policy sink: publish failed; will retry",
				"err", err, "workload_id", batch[i].WorkloadID, "action", batch[i].Action, "policy", batch[i].PolicyName)
			break
		}
	}
	if i < len(batch) {
		remainder := batch[i:]
		s.bufMu.Lock()
		s.buffer = append(remainder, s.buffer...)
		if over := len(s.buffer) - s.bufCap; over > 0 {
			s.dropped.Add(int64(over))
			s.buffer = s.buffer[:len(s.buffer)-over]
		}
		s.bufMu.Unlock()
	}
}

// flushBestEffort attempts a single bounded drain on shutdown.
func (s *PolicyAuditSink) flushBestEffort() {
	ctx, cancel := context.WithTimeout(context.Background(), s.writeTimeout)
	defer cancel()
	s.drain(ctx)
	if d := s.dropped.Load(); d > 0 {
		s.log.Warn("audit policy sink: dropped buffered events over the buffer cap", "dropped", d)
	}
}

// Dropped reports how many policy audit events were dropped due to buffer
// overflow. Exposed for tests and operational logging (the Prometheus surface
// is Story 2.9).
func (s *PolicyAuditSink) Dropped() int64 { return s.dropped.Load() }
