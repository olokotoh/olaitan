package audit

import (
	"context"
	"testing"

	"github.com/olokotoh/olaitan/internal/response/fsm"
	"github.com/olokotoh/olaitan/internal/schema"
)

// TestTransitionSink_RealMachineCapturesAutomatedAndOverride drives a REAL
// *fsm.Machine through the TransitionAuditSink (the sink wired as the Machine's
// TransitionSink, exactly as main.go wires it into the MultiSink) and confirms
// BI-1: an automated escalation AND an operator Pin both reach the audit sink,
// the pin carrying trigger_type=override + operator_id "for free" (BI-1.1).
// This is the end-to-end proof that the projection rides the shipped fan-out,
// not just a hand-built StateTransition.
func TestTransitionSink_RealMachineCapturesAutomatedAndOverride(t *testing.T) {
	pub := &captureTransitionPublisher{}
	sink := newTestTransitionSink(t, pub)

	// nil manager -> Story 2.2 default thresholds (20/40/70); the audit sink is
	// the Machine's only TransitionSink.
	m, err := fsm.New(nil, nil, sink, nil)
	if err != nil {
		t.Fatalf("fsm.New: %v", err)
	}
	ctx := context.Background()

	// Automated escalation: a high score from CLEAN crosses the thresholds and
	// emits at least one actual transition.
	m.Evaluate("ns/Deployment/auto", 100, "pkg-auto")
	sink.drain(ctx)
	auto := pub.events()
	if len(auto) == 0 {
		t.Fatal("expected at least one automated transition captured from a real Machine.Evaluate")
	}
	for _, e := range auto {
		if e.TriggerType != "automated" {
			t.Errorf("automated escalation produced trigger_type=%q, want automated", e.TriggerType)
		}
	}

	// Operator pin: must reach the SAME sink with trigger_type=override and the
	// operator id, captured for free (BI-1.1).
	if err := m.Pin("ns/Deployment/pinned", fsm.PodState(schema.StateQuarantined), "alice"); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	sink.drain(ctx)
	var pin *AuditTransition
	for i := range pub.events() {
		if pub.events()[i].WorkloadID == "ns/Deployment/pinned" {
			e := pub.events()[i]
			pin = &e
		}
	}
	if pin == nil {
		t.Fatal("operator Pin did not reach the audit sink (BI-1.1 violated)")
	}
	if pin.TriggerType != "override" || pin.OperatorID != "alice" || pin.AfterState != "QUARANTINED" {
		t.Errorf("override pin not captured faithfully: %+v", *pin)
	}
}
