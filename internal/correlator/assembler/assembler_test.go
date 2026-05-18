package assembler

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"

	"github.com/olokotoh/olaitan/internal/collector/posture"
	"github.com/olokotoh/olaitan/internal/correlator/trigger"
	"github.com/olokotoh/olaitan/internal/correlator/window"
	"github.com/olokotoh/olaitan/internal/schema"
)

func TestAssemblerBuildsPackageWithPosture(t *testing.T) {
	now := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "api-pod", Namespace: "payments", UID: "pod-uid"}}
	kube := kubefake.NewSimpleClientset(pod)
	posture := &fakePosture{posture: &schema.WorkloadPosture{
		Identity:   schema.WorkloadIdentity{Namespace: "payments", OwnerKind: "Pod", OwnerName: "api-pod", PodName: "api-pod"},
		OrphanPod:  true,
		CapturedAt: now,
	}}
	asm := New(Config{Kube: kube, Posture: posture, MaxPackageBytes: 128 * 1024, Now: func() time.Time { return now }})
	snap := window.Snapshot{
		WorkloadID: "payments/Pod/api-pod",
		Start:      now.Add(-30 * time.Second),
		End:        now,
		Events: []schema.Event{
			{ID: "evt-1", Timestamp: now, Source: schema.SourceAudit, Pod: schema.PodRef{Name: "api-pod", Namespace: "payments", UID: "pod-uid"}, Category: schema.CategoryAudit, Summary: "secret read"},
		},
	}

	pkg, err := asm.Assemble(context.Background(), trigger.RuleMatch("payments/Pod/api-pod", schema.RuleMatch{RuleID: "OLT-1", EventID: "evt-1"}, now), snap)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if pkg.WorkloadID != "payments/Pod/api-pod" {
		t.Errorf("WorkloadID: got %q", pkg.WorkloadID)
	}
	if pkg.WorkloadPosture == nil || pkg.WorkloadPosture.Identity.OwnerName != "api-pod" {
		t.Errorf("posture: %+v", pkg.WorkloadPosture)
	}
	if len(pkg.DegradedSources) != 0 {
		t.Errorf("DegradedSources: got %v", pkg.DegradedSources)
	}
	if len(pkg.RuleMatches) != 1 || pkg.Trigger.RuleMatch == nil {
		t.Errorf("rule trigger not preserved: %+v", pkg.Trigger)
	}
}

func TestAssemblerMarksPostureDegradedWhenUnavailable(t *testing.T) {
	now := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	asm := New(Config{
		Kube:            kubefake.NewSimpleClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "api-pod", Namespace: "payments"}}),
		Posture:         &fakePosture{err: errors.New("api down")},
		MaxPackageBytes: 128 * 1024,
		Now:             func() time.Time { return now },
	})
	snap := window.Snapshot{Events: []schema.Event{{ID: "evt-1", Timestamp: now, Source: schema.SourceAudit, Pod: schema.PodRef{Name: "api-pod", Namespace: "payments"}, Category: schema.CategoryAudit}}}
	pkg, err := asm.Assemble(context.Background(), trigger.BaselineDeviation("payments/Pod/api-pod", schema.BaselineDeviation{PodUID: "pod-uid", Sigma: 3.2}, now), snap)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if len(pkg.DegradedSources) != 1 || pkg.DegradedSources[0] != "posture" {
		t.Errorf("DegradedSources: got %v, want [posture]", pkg.DegradedSources)
	}
	if pkg.WorkloadPosture == nil || !pkg.WorkloadPosture.Unavailable {
		t.Errorf("expected unavailable posture, got %+v", pkg.WorkloadPosture)
	}
}

func TestEnforceSizeCapDeterministic(t *testing.T) {
	now := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	events := make([]schema.Event, 0, 200)
	for i := 0; i < 200; i++ {
		severity := "informational"
		if i%10 == 0 {
			severity = "warning"
		}
		events = append(events, schema.Event{
			ID:        strings.Repeat("x", 16) + string(rune(i)),
			Timestamp: now.Add(time.Duration(i) * time.Millisecond),
			Source:    schema.SourceFalco,
			Category:  schema.CategorySyscall,
			Severity:  severity,
			Summary:   strings.Repeat("large summary ", 20),
			Raw:       json.RawMessage(`{"payload":"` + strings.Repeat("x", 1024) + `"}`),
		})
	}
	pkg := &schema.EvidencePackage{
		SchemaVersion: "evidence.v1",
		PackageID:     "pkg",
		WorkloadID:    "payments/Pod/api-pod",
		Trigger:       schema.EvidenceTrigger{Type: trigger.TypeMultiSignal, FiredAt: now},
		Events:        events,
	}
	if err := EnforceSizeCap(pkg, 8*1024); err != nil {
		t.Fatalf("EnforceSizeCap: %v", err)
	}
	data, err := json.Marshal(pkg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(data) > 8*1024 {
		t.Fatalf("package size = %d, want <= 8192", len(data))
	}
	if pkg.Overflow == nil || pkg.Overflow.DroppedEventCount == 0 {
		t.Fatalf("expected overflow summary, got %+v", pkg.Overflow)
	}
	for _, ev := range pkg.Events {
		if ev.Raw != nil {
			t.Fatalf("overflow event retained raw payload")
		}
		if severityScore(ev.Severity) < 50 {
			t.Fatalf("low-priority event survived overflow: %+v", ev)
		}
	}
}

type fakePosture struct {
	posture *schema.WorkloadPosture
	err     error
}

func (f *fakePosture) Get(context.Context, *corev1.Pod, ...posture.Option) (*schema.WorkloadPosture, error) {
	return f.posture, f.err
}
