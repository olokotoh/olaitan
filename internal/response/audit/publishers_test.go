package audit

import (
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/response/netpol"
	"github.com/olokotoh/olaitan/internal/schema"
)

func TestNATSPublisherConstructors_NilClient(t *testing.T) {
	if _, err := NewNATSTransitionPublisher(nil); err == nil {
		t.Error("NewNATSTransitionPublisher(nil) should error")
	}
	if _, err := NewNATSPolicyPublisher(nil); err == nil {
		t.Error("NewNATSPolicyPublisher(nil) should error")
	}
}

func TestTransitionSinkConstructorDefaults(t *testing.T) {
	s, err := NewTransitionAuditSink(&captureTransitionPublisher{}, nil, TransitionAuditSinkConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if s.bufCap != 4096 || s.writeTimeout != 2*time.Second || s.drainEvery != 5*time.Second {
		t.Errorf("defaults not applied: cap=%d wt=%v de=%v", s.bufCap, s.writeTimeout, s.drainEvery)
	}
}

func TestPolicySinkConstructorDefaults(t *testing.T) {
	s, err := NewPolicyAuditSink(&capturePolicyPublisher{}, nil, PolicyAuditSinkConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if s.bufCap != 4096 || s.writeTimeout != 2*time.Second || s.drainEvery != 5*time.Second {
		t.Errorf("defaults not applied: cap=%d wt=%v de=%v", s.bufCap, s.writeTimeout, s.drainEvery)
	}
}

// TestPolicySink_FlushBestEffortDrainsAndWarns exercises the shutdown flush
// path (including the dropped-counter warn branch) and confirms the surviving
// buffered event is still delivered.
func TestPolicySink_FlushBestEffortDrainsAndWarns(t *testing.T) {
	pub := &capturePolicyPublisher{}
	s, err := NewPolicyAuditSink(pub, nil, PolicyAuditSinkConfig{BufferCap: 1})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		s.PublishPolicyAudit(netpol.PolicyAuditEvent{Action: netpol.AuditActionApply, WorkloadID: "w"})
	}
	if s.Dropped() == 0 {
		t.Fatal("expected drops to set the counter for the warn path")
	}
	s.flushBestEffort()
	if len(pub.events()) != 1 {
		t.Fatalf("flush should deliver the surviving buffered event, got %d", len(pub.events()))
	}
}

// TestTransitionSink_FlushBestEffortDrainsAndWarns mirrors the above for the
// transitions sink.
func TestTransitionSink_FlushBestEffortDrainsAndWarns(t *testing.T) {
	pub := &captureTransitionPublisher{}
	s, err := NewTransitionAuditSink(pub, nil, TransitionAuditSinkConfig{BufferCap: 1})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		s.Publish(schema.StateTransition{FromState: schema.StateClean, ToState: schema.StateRestricted, WorkloadID: "w"})
	}
	if s.Dropped() == 0 {
		t.Fatal("expected drops")
	}
	s.flushBestEffort()
	if len(pub.events()) != 1 {
		t.Fatalf("flush should deliver the surviving buffered event, got %d", len(pub.events()))
	}
}
