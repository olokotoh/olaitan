package audit

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/response/netpol"
	"github.com/olokotoh/olaitan/internal/schema"
)

type capturePolicyPublisher struct {
	mu  sync.Mutex
	got []AuditPolicy
}

func (c *capturePolicyPublisher) PublishAuditPolicy(_ context.Context, evt AuditPolicy) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, evt)
	return nil
}

func (c *capturePolicyPublisher) events() []AuditPolicy {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]AuditPolicy(nil), c.got...)
}

func TestPolicySink_PublishThenDrainMapsEvent(t *testing.T) {
	pub := &capturePolicyPublisher{}
	s, err := NewPolicyAuditSink(pub, nil, PolicyAuditSinkConfig{})
	if err != nil {
		t.Fatal(err)
	}
	fixed := time.Date(2026, 6, 4, 9, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return fixed }

	s.PublishPolicyAudit(netpol.PolicyAuditEvent{
		Action: netpol.AuditActionApply, WorkloadID: "ns/Deployment/web", Namespace: "ns",
		PolicyName: "olaitan-restricted-abc", PolicyKind: netpol.AuditPolicyKindRestricted,
		FSMState: string(schema.StateRestricted), Result: "applied",
		SpecSummary: netpol.AuditSpecEgressAllowlist, PackageID: "pkg",
	})
	s.drain(context.Background())

	got := pub.events()
	if len(got) != 1 {
		t.Fatalf("want 1, got %d", len(got))
	}
	e := got[0]
	if e.SchemaVersion != SchemaVersionPolicies || e.Action != "apply" || e.Namespace != "ns" {
		t.Errorf("unexpected mapping: %+v", e)
	}
	if !e.PublishedAt.Equal(fixed) {
		t.Errorf("published_at = %v, want stamped %v", e.PublishedAt, fixed)
	}
}

func TestPolicySink_DropOnFull(t *testing.T) {
	pub := &capturePolicyPublisher{}
	s, err := NewPolicyAuditSink(pub, nil, PolicyAuditSinkConfig{BufferCap: 1})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		s.PublishPolicyAudit(netpol.PolicyAuditEvent{Action: netpol.AuditActionApply, WorkloadID: "w"})
	}
	if s.Dropped() != 3 {
		t.Errorf("want 3 dropped (cap 1, 4 enqueued), got %d", s.Dropped())
	}
}

func TestPolicySink_NilPublisherErrors(t *testing.T) {
	if _, err := NewPolicyAuditSink(nil, nil, PolicyAuditSinkConfig{}); err == nil {
		t.Fatal("want error for nil publisher")
	}
}

func TestPolicySink_RunFlushesOnCancel(t *testing.T) {
	pub := &capturePolicyPublisher{}
	s, err := NewPolicyAuditSink(pub, nil, PolicyAuditSinkConfig{})
	if err != nil {
		t.Fatal(err)
	}
	s.PublishPolicyAudit(netpol.PolicyAuditEvent{Action: netpol.AuditActionApply, WorkloadID: "w"})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned %v", err)
	}
	if len(pub.events()) != 1 {
		t.Fatalf("flush on cancel should publish the buffered event, got %d", len(pub.events()))
	}
}

func TestPolicyMsgID_StableAndDistinct(t *testing.T) {
	now := time.Unix(0, 12345)
	a := policyMsgID(AuditPolicy{WorkloadID: "w", PolicyName: "p", Action: "apply", PublishedAt: now})
	b := policyMsgID(AuditPolicy{WorkloadID: "w", PolicyName: "p", Action: "apply", PublishedAt: now})
	if a != b {
		t.Errorf("msgID must be stable across re-publish: %q != %q", a, b)
	}
	c := policyMsgID(AuditPolicy{WorkloadID: "w", PolicyName: "p", Action: "gc_delete", PublishedAt: now})
	if a == c {
		t.Errorf("distinct actions must yield distinct msgIDs")
	}
}

func TestTransitionMsgID_StableAndDistinct(t *testing.T) {
	d := time.Unix(0, 999)
	a := transitionMsgID(AuditTransition{WorkloadID: "w", DecidedAt: d})
	b := transitionMsgID(AuditTransition{WorkloadID: "w", DecidedAt: d})
	if a != b {
		t.Errorf("stable: %q != %q", a, b)
	}
	if transitionMsgID(AuditTransition{WorkloadID: "w2", DecidedAt: d}) == a {
		t.Errorf("distinct workloads must differ")
	}
}
