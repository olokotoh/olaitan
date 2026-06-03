package fsm

import (
	"testing"

	"github.com/olokotoh/olaitan/internal/schema"
)

func TestMultiSink_FansOutToEveryMember(t *testing.T) {
	a := &RecordingSink{}
	b := &RecordingSink{}
	ms := MultiSink{a, b}

	st := schema.StateTransition{
		WorkloadID: "ns/Deployment/web",
		FromState:  schema.StateSuspicious,
		ToState:    schema.StateRestricted,
	}
	ms.Publish(st)

	if a.count() != 1 {
		t.Fatalf("member a: want 1 transition, got %d", a.count())
	}
	if b.count() != 1 {
		t.Fatalf("member b: want 1 transition, got %d", b.count())
	}
	if a.transitions[0].WorkloadID != st.WorkloadID || b.transitions[0].ToState != st.ToState {
		t.Fatalf("members received a different transition than published")
	}
}

func TestMultiSink_EmptyIsNoOp(t *testing.T) {
	var ms MultiSink
	// Must not panic on a nil/empty slice (the aggregator falls back to
	// an empty MultiSink when no real sink is enabled).
	ms.Publish(schema.StateTransition{ToState: schema.StateRestricted})
	ms = MultiSink{}
	ms.Publish(schema.StateTransition{ToState: schema.StateRestricted})
}

func TestMultiSink_SkipsNilMembers(t *testing.T) {
	a := &RecordingSink{}
	ms := MultiSink{nil, a, nil}
	ms.Publish(schema.StateTransition{ToState: schema.StateRestricted})
	if a.count() != 1 {
		t.Fatalf("want 1 transition delivered to the non-nil member, got %d", a.count())
	}
}

// TestMultiSink_ImplementsTransitionSink pins that MultiSink satisfies the
// seam the FSM expects, so it can be passed straight to New.
func TestMultiSink_ImplementsTransitionSink(t *testing.T) {
	var _ TransitionSink = MultiSink{}
}
