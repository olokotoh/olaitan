package assembler

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"

	"github.com/olokotoh/olaitan/internal/collector/posture"
	"github.com/olokotoh/olaitan/internal/correlator/trigger"
	"github.com/olokotoh/olaitan/internal/correlator/window"
	"github.com/olokotoh/olaitan/internal/schema"
)

// Story 12.8 (#226), the 2026-10-20 live-run case: a baseline deviation on
// olt-bl/Deployment/steady whose window starts with a Goldmane flow named
// "steady-6c8f4c97cc-*". FireBaselineDeviation attaches the baseline engine's
// Deployment identity (no PodName) and no pod, so the assembler hands the
// real posture client a stub carrying the aggregate name. With a live pod of
// the set the package must carry a full, non-degraded posture.
func TestAssemblerBaselineOnGoldmaneFirstWindowGetsPosture(t *testing.T) {
	now := time.Date(2026, 10, 20, 14, 2, 0, 0, time.UTC)
	yes := true
	kube := kubefake.NewSimpleClientset(
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "steady", Namespace: "olt-bl"}},
		&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "steady-6c8f4c97cc", Namespace: "olt-bl",
			OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "steady", Controller: &yes}}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "steady-6c8f4c97cc-q2w9z", GenerateName: "steady-6c8f4c97cc-", Namespace: "olt-bl",
			OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "steady-6c8f4c97cc", Controller: &yes}}},
			Spec: corev1.PodSpec{ServiceAccountName: "steady"}},
	)
	pc, err := posture.New(posture.DefaultConfig(), kube, nil)
	if err != nil {
		t.Fatal(err)
	}
	asm := New(Config{Kube: kube, Posture: pc, Now: func() time.Time { return now }})
	const wid = "olt-bl/Deployment/steady"
	identity := schema.WorkloadIdentity{Namespace: "olt-bl", OwnerKind: "Deployment", OwnerName: "steady"}
	tr := trigger.BaselineDeviation(wid, schema.BaselineDeviation{Metric: "outbound_unique_dst_ips", Value: 9, Mean: 2.9, StdDev: 1, Sigma: 6.06}, now)
	tr.ResolvedIdentity = &identity
	snap := window.Snapshot{WorkloadID: wid, Start: now.Add(-time.Minute), End: now, Events: []schema.Event{
		{ID: "flow-1", Timestamp: now, Source: schema.SourceNetwork, Category: schema.CategoryFlow, Pod: schema.PodRef{Name: "steady-6c8f4c97cc-*", Namespace: "olt-bl"}},
	}}
	pkg, err := asm.Assemble(context.Background(), tr, snap)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if containsString(pkg.DegradedSources, "posture") {
		t.Errorf("posture degraded on a Goldmane-led baseline package although a pod of the set is live: %+v", pkg.WorkloadPosture)
	}
	if pkg.WorkloadPosture == nil || pkg.WorkloadPosture.ServiceAccount != "steady" || pkg.WorkloadPosture.Identity.OwnerName != "steady" {
		t.Errorf("posture = %+v, want the steady Deployment's posture", pkg.WorkloadPosture)
	}
	if pkg.WorkloadID != wid {
		t.Errorf("WorkloadID = %q, want %q", pkg.WorkloadID, wid)
	}
}
