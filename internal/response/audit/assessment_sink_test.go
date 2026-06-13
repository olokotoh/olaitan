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
		AgentsAvailable:     []string{"l1", "l2", "senior"},
		RawConfidence:       66,
		LLMCappedConfidence: 30,
	}
	hyp := schema.L1Hypothesis{Hypothesis: "miner"}
	ver := schema.L2Verification{Verdict: "confirmed"}
	in := AssessmentInput{
		PackageID:        "pkg-1",
		WorkloadID:       "wl-1",
		Mode:             "full",
		AgentsAvailable:  a.AgentsAvailable,
		PromptVersions:   map[string]string{"l1": "h1", "l2": "h2", "senior": "h3"},
		Providers:        map[string]string{"l1": "claude", "l2": "claude", "senior": "claude"},
		Models:           map[string]string{"l1": "haiku", "l2": "haiku", "senior": "opus"},
		RawConfidence:    a.RawConfidence,
		CappedConfidence: a.LLMCappedConfidence,
		L1Hypothesis:     &hyp,
		L2Verification:   &ver,
		ThreatAssessment: &a,
		RedactedEvidence: schema.EvidencePackage{PackageID: "pkg-1"},
		RedactionApplied: true,
		Now:              now,
	}
	evt := AssessmentFromChain(in)
	if evt.SchemaVersion != "audit.assessments.v2" {
		t.Errorf("schema_version = %q, want audit.assessments.v2", evt.SchemaVersion)
	}
	if evt.PackageID != "pkg-1" || evt.WorkloadID != "wl-1" || evt.Mode != "full" {
		t.Errorf("ids/mode = %q/%q/%q", evt.PackageID, evt.WorkloadID, evt.Mode)
	}
	if evt.ThreatType != "cryptomining" {
		t.Errorf("threat_type = %q, want cryptomining (from the assessment)", evt.ThreatType)
	}
	if evt.PromptVersions["senior"] != "h3" || evt.Providers["l1"] != "claude" || evt.Models["senior"] != "opus" {
		t.Errorf("per-role maps wrong: %+v %+v %+v", evt.PromptVersions, evt.Providers, evt.Models)
	}
	if evt.L1Hypothesis == nil || evt.L2Verification == nil || evt.ThreatAssessment == nil {
		t.Error("structured verdicts must be carried")
	}
	if !evt.RedactionApplied {
		t.Error("redaction_applied must be true")
	}
	if evt.RawConfidence != 66 || evt.LLMCappedConfidence != 30 {
		t.Errorf("confidence = %d/%d, want 66/30", evt.RawConfidence, evt.LLMCappedConfidence)
	}
	if !evt.DecidedAt.Equal(now) || !evt.PublishedAt.Equal(now) {
		t.Errorf("decided/published = %v/%v, want %v", evt.DecidedAt, evt.PublishedAt, now)
	}
}

// TestAssessmentFromChainAblationOmitsRoles proves an l1_only input omits the
// l2/senior per-role entries and the L2/Senior verdicts.
func TestAssessmentFromChainAblationOmitsRoles(t *testing.T) {
	a := schema.ThreatAssessment{AgentsAvailable: []string{"l1"}, RawConfidence: 40, LLMCappedConfidence: 25}
	hyp := schema.L1Hypothesis{Hypothesis: "suspicious exec"}
	evt := AssessmentFromChain(AssessmentInput{
		PackageID:        "pkg-3",
		Mode:             "l1_only",
		PromptVersions:   map[string]string{"l1": "h1"},
		Providers:        map[string]string{"l1": "claude"},
		Models:           map[string]string{"l1": "haiku"},
		L1Hypothesis:     &hyp,
		ThreatAssessment: &a,
		RedactionApplied: true,
		Now:              time.Unix(1, 0).UTC(),
	})
	if _, ok := evt.PromptVersions["l2"]; ok {
		t.Error("l1_only must omit l2 prompt version")
	}
	if _, ok := evt.PromptVersions["senior"]; ok {
		t.Error("l1_only must omit senior prompt version")
	}
	if evt.L2Verification != nil {
		t.Error("l1_only must omit l2_verification")
	}
	if evt.ThreatType != "" {
		t.Errorf("l1_only threat_type = %q, want empty", evt.ThreatType)
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
	evt := AssessmentFromChain(AssessmentInput{PackageID: "pkg-2", WorkloadID: "wl-2", Mode: "full", RedactionApplied: true, Now: time.Unix(0, 0).UTC()})
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
