package netpol

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

// TestActiveGauge_ReflectsManagedPolicyKinds (Story 2.9, AC3/BI-4): the
// network_policy_active gauge is set from the managed-policy list each
// reconcile pass, bucketed restricted vs quarantined by AnnFSMState.
func TestActiveGauge_ReflectsManagedPolicyKinds(t *testing.T) {
	reg := metricsRegistryForTest(t)
	// Two restricted + one quarantined managed policy, all orphaned (no owner),
	// plus their owners absent so the list is what we seed.
	r1 := m_buildManagedPolicy("ns", "r1", "ns/Deployment/a")
	r2 := m_buildManagedPolicy("ns", "r2", "ns/Deployment/b")
	q1 := m_buildManagedQuarantinePolicy("ns", "q1", "ns/Deployment/c")
	cs := fake.NewSimpleClientset(runtime.Object(r1), runtime.Object(r2), runtime.Object(q1))
	m, err := New(Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, cs, reg, discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	m.reconcileGC(context.Background())

	if got := testutil.ToFloat64(m.active.WithLabelValues(AuditPolicyKindRestricted)); got != 2 {
		t.Errorf("active{restricted} = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.active.WithLabelValues(AuditPolicyKindQuarantined)); got != 1 {
		t.Errorf("active{quarantined} = %v, want 1", got)
	}
}

// TestActiveGauge_ResetsToZeroWhenEmpty confirms the gauge self-corrects: with
// no managed policies the reconcile sets both kinds to 0.
func TestActiveGauge_ResetsToZeroWhenEmpty(t *testing.T) {
	reg := metricsRegistryForTest(t)
	cs := fake.NewSimpleClientset()
	m, err := New(Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, cs, reg, discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.reconcileGC(context.Background())
	if got := testutil.ToFloat64(m.active.WithLabelValues(AuditPolicyKindRestricted)); got != 0 {
		t.Errorf("active{restricted} = %v, want 0", got)
	}
}
