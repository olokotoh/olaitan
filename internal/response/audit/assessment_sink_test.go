package audit

import (
	"context"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/schema"
)

func TestAssessmentFromChain(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	a := schema.ThreatAssessment{
		ThreatType:          "cryptomining",
		AgentsAvailable:     []string{"l1", "l2"},
		RawConfidence:       66,
		LLMCappedConfidence: 30,
	}
	evt := AssessmentFromChain("pkg-1", "wl-1", "l1_l2", a, now)
	if evt.SchemaVersion != SchemaVersionAssessments {
		t.Errorf("schema_version = %q", evt.SchemaVersion)
	}
	if evt.PackageID != "pkg-1" || evt.WorkloadID != "wl-1" || evt.Mode != "l1_l2" {
		t.Errorf("ids/mode = %q/%q/%q", evt.PackageID, evt.WorkloadID, evt.Mode)
	}
	if got := len(evt.AgentsAvailable); got != 2 {
		t.Errorf("agents_available len = %d, want 2 (records the ablation)", got)
	}
	if evt.RawConfidence != 66 || evt.LLMCappedConfidence != 30 {
		t.Errorf("confidence = %d/%d, want 66/30", evt.RawConfidence, evt.LLMCappedConfidence)
	}
	if !evt.DecidedAt.Equal(now) {
		t.Errorf("decided_at = %v, want %v", evt.DecidedAt, now)
	}
}

// fakeAssessmentPublisher captures the events published through the seam.
type fakeAssessmentPublisher struct {
	got []AuditAssessment
	err error
}

func (f *fakeAssessmentPublisher) PublishAuditAssessment(_ context.Context, evt AuditAssessment) error {
	f.got = append(f.got, evt)
	return f.err
}

func TestAssessmentPublisherSeam(t *testing.T) {
	fp := &fakeAssessmentPublisher{}
	evt := AssessmentFromChain("pkg-2", "wl-2", "full", schema.ThreatAssessment{}, time.Unix(0, 0).UTC())
	if err := fp.PublishAuditAssessment(context.Background(), evt); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if len(fp.got) != 1 || fp.got[0].PackageID != "pkg-2" {
		t.Errorf("publisher did not capture the event: %+v", fp.got)
	}
}

func TestNewNATSAssessmentPublisherNilClient(t *testing.T) {
	if _, err := NewNATSAssessmentPublisher(nil); err == nil {
		t.Error("nil nats client: err = nil, want construction error")
	}
}
