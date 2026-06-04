package audit

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/schema"
)

// captureTransitionPublisher is a capturing fake AuditTransitionPublisher.
type captureTransitionPublisher struct {
	mu   sync.Mutex
	got  []AuditTransition
	fail bool
}

func (c *captureTransitionPublisher) PublishAuditTransition(_ context.Context, evt AuditTransition) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail {
		return fmt.Errorf("boom")
	}
	c.got = append(c.got, evt)
	return nil
}

func (c *captureTransitionPublisher) events() []AuditTransition {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]AuditTransition(nil), c.got...)
}

func newTestTransitionSink(t *testing.T, pub AuditTransitionPublisher) *TransitionAuditSink {
	t.Helper()
	s, err := NewTransitionAuditSink(pub, nil, TransitionAuditSinkConfig{})
	if err != nil {
		t.Fatalf("NewTransitionAuditSink: %v", err)
	}
	// Deterministic clock for published_at.
	fixed := time.Date(2026, 6, 4, 9, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return fixed }
	return s
}

func TestTransitionSink_PublishThenDrain(t *testing.T) {
	pub := &captureTransitionPublisher{}
	s := newTestTransitionSink(t, pub)

	decided := time.Date(2026, 6, 4, 8, 59, 0, 0, time.UTC)
	s.Publish(schema.StateTransition{
		FromState: schema.StateClean, ToState: schema.StateRestricted,
		Confidence: 71, WorkloadID: "ns/Deployment/web", PackageID: "pkg",
		TriggerType: "automated", Reason: schema.ReasonEscalationThresholdCrossed,
		Timestamp: decided,
	})
	s.drain(context.Background())

	got := pub.events()
	if len(got) != 1 {
		t.Fatalf("want 1 published event, got %d", len(got))
	}
	e := got[0]
	if e.BeforeState != "CLEAN" || e.AfterState != "RESTRICTED" || e.WorkloadID != "ns/Deployment/web" {
		t.Errorf("unexpected projection: %+v", e)
	}
	if !e.DecidedAt.Equal(decided) {
		t.Errorf("decided_at = %v, want %v (the FSM Timestamp)", e.DecidedAt, decided)
	}
	if e.PublishedAt.Equal(e.DecidedAt) || e.PublishedAt.IsZero() {
		t.Errorf("published_at must be stamped distinct from decided_at, got %v", e.PublishedAt)
	}
}

func TestTransitionSink_OverrideTransitionCaptured(t *testing.T) {
	pub := &captureTransitionPublisher{}
	s := newTestTransitionSink(t, pub)
	s.Publish(schema.StateTransition{
		FromState: schema.StateClean, ToState: schema.StateQuarantined,
		WorkloadID: "ns/Deployment/api", TriggerType: "override",
		Reason: schema.ReasonOperatorOverride, OperatorID: "alice",
	})
	s.drain(context.Background())
	got := pub.events()
	if len(got) != 1 {
		t.Fatalf("want 1, got %d", len(got))
	}
	if got[0].TriggerType != "override" || got[0].OperatorID != "alice" || got[0].Reason != schema.ReasonOperatorOverride {
		t.Errorf("override transition not captured faithfully: %+v", got[0])
	}
}

func TestTransitionSink_DropOnFullNeverBlocks(t *testing.T) {
	pub := &captureTransitionPublisher{}
	s, err := NewTransitionAuditSink(pub, nil, TransitionAuditSinkConfig{BufferCap: 2})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		s.Publish(schema.StateTransition{FromState: schema.StateClean, ToState: schema.StateRestricted, WorkloadID: "w"})
	}
	if s.Dropped() != 3 {
		t.Errorf("want 3 dropped (cap 2, 5 enqueued), got %d", s.Dropped())
	}
}

func TestTransitionSink_PublishErrorRebuffers(t *testing.T) {
	pub := &captureTransitionPublisher{fail: true}
	s := newTestTransitionSink(t, pub)
	s.Publish(schema.StateTransition{FromState: schema.StateClean, ToState: schema.StateRestricted, WorkloadID: "w"})
	s.drain(context.Background())
	if len(pub.events()) != 0 {
		t.Fatalf("publish failed; nothing should be captured")
	}
	// The event is re-buffered for retry; a successful drain then delivers it.
	pub.mu.Lock()
	pub.fail = false
	pub.mu.Unlock()
	s.drain(context.Background())
	if len(pub.events()) != 1 {
		t.Fatalf("want 1 after recovery, got %d", len(pub.events()))
	}
}

func TestTransitionSink_NilPublisherErrors(t *testing.T) {
	if _, err := NewTransitionAuditSink(nil, nil, TransitionAuditSinkConfig{}); err == nil {
		t.Fatal("want error for nil publisher")
	}
}

func TestTransitionSink_RunFlushesOnCancel(t *testing.T) {
	pub := &captureTransitionPublisher{}
	s := newTestTransitionSink(t, pub)
	s.Publish(schema.StateTransition{FromState: schema.StateClean, ToState: schema.StateRestricted, WorkloadID: "w"})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned %v", err)
	}
	if len(pub.events()) != 1 {
		t.Fatalf("best-effort flush on cancel should publish the buffered event, got %d", len(pub.events()))
	}
}
