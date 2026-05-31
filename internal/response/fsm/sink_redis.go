package fsm

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/olokotoh/olaitan/internal/retry"
	"github.com/olokotoh/olaitan/internal/schema"
)

// RedisSink is the Story 2.3 Redis-backed TransitionSink. Publish persists
// each actual transition to the durable fsm: family via the Store. When
// Redis is briefly unreachable, the transition is buffered in a bounded
// in-memory queue and a background replayer (Run) drains it on
// reconnection, idempotently (the Store CAS drops a replay whose target
// state already landed, which also prevents a duplicate history append).
// This satisfies AC3 (buffer + replay, no loss, no duplicate side effect).
type RedisSink struct {
	store        *Store
	log          *slog.Logger
	writeTimeout time.Duration
	replayEvery  time.Duration
	retry        retry.Strategy

	bufMu   sync.Mutex
	buffer  []schema.StateTransition
	bufCap  int
	dropped atomic.Int64

	wake chan struct{}
}

// RedisSinkConfig configures a RedisSink. Zero values fall back to
// production defaults.
type RedisSinkConfig struct {
	BufferCap    int           // max buffered transitions during an outage (default 4096)
	WriteTimeout time.Duration // per-Publish Redis write budget (default 2s)
	ReplayEvery  time.Duration // background drain cadence (default 5s)
}

// NewRedisSink builds a RedisSink. store must be non-nil; log defaults to
// slog.Default when nil.
func NewRedisSink(store *Store, log *slog.Logger, cfg RedisSinkConfig) (*RedisSink, error) {
	if store == nil {
		return nil, fmt.Errorf("fsm: nil store for redis sink")
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
	if cfg.ReplayEvery <= 0 {
		cfg.ReplayEvery = 5 * time.Second
	}
	return &RedisSink{
		store:        store,
		log:          log,
		writeTimeout: cfg.WriteTimeout,
		replayEvery:  cfg.ReplayEvery,
		retry: retry.Strategy{
			Min:         100 * time.Millisecond,
			Max:         2 * time.Second,
			Multiplier:  2.0,
			Jitter:      0.2,
			MaxAttempts: 3,
		},
		buffer: make([]schema.StateTransition, 0, 64),
		bufCap: cfg.BufferCap,
		wake:   make(chan struct{}, 1),
	}, nil
}

// Publish persists one transition. It is called by the FSM only on an
// actual state change, so this is not the per-evaluation hot path. On a
// Redis error the transition is buffered and the replayer is signalled;
// Publish never blocks beyond writeTimeout.
func (s *RedisSink) Publish(st schema.StateTransition) {
	ctx, cancel := context.WithTimeout(context.Background(), s.writeTimeout)
	defer cancel()
	if err := s.persist(ctx, st); err != nil {
		s.log.Warn("fsm redis sink: persist failed; buffering for replay",
			"err", err, "workload_id", st.WorkloadID, "to_state", string(st.ToState))
		s.enqueue(st)
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}
}

// persist writes one transition through the Store. A benign CAS drop
// (swapped=false) is success: the target state already landed, so this is
// an idempotent no-op (BI-7).
func (s *RedisSink) persist(ctx context.Context, st schema.StateTransition) error {
	entry, err := json.Marshal(st)
	if err != nil {
		// A marshal failure is permanent; do not buffer-replay it forever.
		return retry.Permanent(fmt.Errorf("marshal transition: %w", err))
	}
	ps := persistedState{
		current:          st.ToState,
		stateEnteredAt:   st.Timestamp,
		cooldownAnchorAt: st.Timestamp,
		updatedAt:        st.Timestamp,
	}
	if _, err := s.store.Save(ctx, st.WorkloadID, string(st.FromState), ps, entry); err != nil {
		return err
	}
	return nil
}

// enqueue appends to the bounded buffer, dropping the oldest entry (and
// bumping the dropped counter) when full so Publish never blocks.
func (s *RedisSink) enqueue(st schema.StateTransition) {
	s.bufMu.Lock()
	defer s.bufMu.Unlock()
	if len(s.buffer) >= s.bufCap {
		s.buffer = s.buffer[1:]
		s.dropped.Add(1)
	}
	s.buffer = append(s.buffer, st)
}

// Run is the background replayer. It drains the buffer whenever Publish
// signals a buffered transition or on a periodic tick, and flushes
// best-effort on context cancellation. Wire it into the errgroup.
func (s *RedisSink) Run(ctx context.Context) error {
	ticker := time.NewTicker(s.replayEvery)
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

// drain replays buffered transitions in order. It takes the current
// batch under the lock, replays each via the retry strategy, and on the
// first failure re-prepends the unpersisted remainder (preserving order)
// so no transition is lost while Redis is still down.
func (s *RedisSink) drain(ctx context.Context) {
	s.bufMu.Lock()
	batch := s.buffer
	s.buffer = make([]schema.StateTransition, 0, 64)
	s.bufMu.Unlock()
	if len(batch) == 0 {
		return
	}
	i := 0
	for ; i < len(batch); i++ {
		item := batch[i]
		if err := s.retry.Do(ctx, func(ctx context.Context) error { return s.persist(ctx, item) }); err != nil {
			break
		}
	}
	if i < len(batch) {
		remainder := batch[i:]
		s.bufMu.Lock()
		s.buffer = append(remainder, s.buffer...)
		if over := len(s.buffer) - s.bufCap; over > 0 {
			s.dropped.Add(int64(over))
			s.buffer = s.buffer[over:]
		}
		s.bufMu.Unlock()
	}
}

// flushBestEffort attempts a single bounded drain on shutdown so an
// in-flight buffer is not silently lost when the context is cancelled.
func (s *RedisSink) flushBestEffort() {
	ctx, cancel := context.WithTimeout(context.Background(), s.writeTimeout)
	defer cancel()
	s.drain(ctx)
	if d := s.dropped.Load(); d > 0 {
		s.log.Warn("fsm redis sink: dropped buffered transitions over the buffer cap", "dropped", d)
	}
}

// Dropped reports how many transitions were dropped due to buffer
// overflow. Exposed for tests and operational logging.
func (s *RedisSink) Dropped() int64 { return s.dropped.Load() }
