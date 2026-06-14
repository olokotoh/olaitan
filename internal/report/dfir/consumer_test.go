package dfir

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/olokotoh/olaitan/internal/agent/provider"
	"github.com/olokotoh/olaitan/internal/response/settling"
)

// TestHandleData_Success drives the ack-agnostic consumer core on a valid event:
// it generates and announces a report.
func TestHandleData_Success(t *testing.T) {
	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8", resp: provider.Response{Raw: validReportJSON, StopReason: "end_turn"}}
	rp := &fakeReportPublisher{}
	a := newAgent(t, fp, rp, nil)

	evt := settling.IncidentFinalised{
		SchemaVersion: settling.SchemaVersionIncidentFinalised,
		PackageID:     "pkg-h",
		WorkloadID:    "wl-h",
		FinalState:    "RESTRICTED",
		ThreatScore:   9,
	}
	b, _ := json.Marshal(evt)
	a.handleData(context.Background(), b)
	if len(rp.events) != 1 || rp.events[0].IncidentID != "pkg-h" {
		t.Errorf("handleData did not generate the report: %+v", rp.events)
	}
}

// TestHandleData_MalformedDropped: malformed bytes are dropped (no panic, no
// report).
func TestHandleData_MalformedDropped(t *testing.T) {
	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8", resp: provider.Response{Raw: validReportJSON, StopReason: "end_turn"}}
	rp := &fakeReportPublisher{}
	a := newAgent(t, fp, rp, nil)
	a.handleData(context.Background(), []byte("{not json"))
	if fp.calls != 0 || len(rp.events) != 0 {
		t.Error("a malformed event must be dropped without a provider call or report")
	}
}

// TestHandleData_GenerationFailureSwallowed: a fail-closed generation failure is
// swallowed (the caller acks); no report is announced.
func TestHandleData_GenerationFailureSwallowed(t *testing.T) {
	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8", err: errors.New("boom")}
	rp := &fakeReportPublisher{}
	ar := &fakeAuditRecorder{}
	a := newAgent(t, fp, rp, ar)
	evt := settling.IncidentFinalised{PackageID: "pkg-f", WorkloadID: "wl-f", FinalState: "RESTRICTED"}
	b, _ := json.Marshal(evt)
	a.handleData(context.Background(), b)
	if len(rp.events) != 0 {
		t.Error("a fail-closed failure must announce no report")
	}
	if len(ar.records) != 1 || ar.records[0].Status != statusUnavailable {
		t.Errorf("the failure must be audited, got %+v", ar.records)
	}
}

// TestIsExpectedFetchTimeout covers the consumer-loop timeout classifier.
func TestIsExpectedFetchTimeout(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"no-messages-sentinel", jetstream.ErrNoMessages, true},
		{"deadline", context.DeadlineExceeded, true},
		{"bare-string", errors.New("nats: no messages"), true},
		{"other", errors.New("connection reset"), false},
	}
	for _, c := range cases {
		if got := isExpectedFetchTimeout(c.err); got != c.want {
			t.Errorf("%s: isExpectedFetchTimeout = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestSetPromptAndProviderName covers the small accessors.
func TestSetPromptAndProviderName(t *testing.T) {
	fp := &fakeProvider{name: "claude", model: "m", resp: provider.Response{Raw: validReportJSON, StopReason: "end_turn"}}
	a := newAgent(t, fp, &fakeReportPublisher{}, nil)
	if a.ProviderName() != "claude" {
		t.Errorf("ProviderName = %q", a.ProviderName())
	}
	a.SetPrompt(PromptSpec{System: "new", Version: "new.v2"})
	if got := a.currentSpec(); got.Version != "new.v2" || got.System != "new" {
		t.Errorf("SetPrompt did not swap the spec: %+v", got)
	}
}

// TestNewNATSReportPublisher_NilClient covers the nil-client construction guard.
func TestNewNATSReportPublisher_NilClient(t *testing.T) {
	if _, err := NewNATSReportPublisher(nil); err == nil {
		t.Fatal("a nil nats client must be a construction error")
	}
}

// TestNewDFIR_NilProvider covers the nil-provider construction guard.
func TestNewDFIR_NilProvider(t *testing.T) {
	if _, err := NewDFIR(nil, PromptSpec{}, nil, nil, nil, nil, nil, nil); err == nil {
		t.Fatal("a nil provider must be a construction error")
	}
}
