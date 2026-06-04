package netpol

import (
	"context"
	"sync"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// capturePolicyAudit is a capturing PolicyAuditPublisher for the Story 2.8
// emit-point tests (BI-9).
type capturePolicyAudit struct {
	mu  sync.Mutex
	got []PolicyAuditEvent
}

func (c *capturePolicyAudit) PublishPolicyAudit(evt PolicyAuditEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, evt)
}

func (c *capturePolicyAudit) events() []PolicyAuditEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]PolicyAuditEvent(nil), c.got...)
}

func (c *capturePolicyAudit) byAction(action string) []PolicyAuditEvent {
	var out []PolicyAuditEvent
	for _, e := range c.events() {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

func TestAudit_ApplyEmitsOnceNotOnNoop(t *testing.T) {
	sel := map[string]string{"app": "web"}
	m := newTestManager(t, Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, deployment("ns", "web", sel))
	cap := &capturePolicyAudit{}
	m.SetPolicyAuditPublisher(cap)
	ctx := context.Background()
	st := restrictedTransition("ns/Deployment/web", "pkg-1")

	m.handle(ctx, st) // create -> applied
	m.handle(ctx, st) // idempotent re-apply -> noop (must NOT emit)

	applies := cap.byAction(AuditActionApply)
	if len(applies) != 1 {
		t.Fatalf("want exactly 1 apply audit (noop suppressed), got %d", len(applies))
	}
	e := applies[0]
	if e.Result != "applied" || e.PolicyKind != AuditPolicyKindRestricted || e.SpecSummary != AuditSpecEgressAllowlist || e.FSMState != "RESTRICTED" || e.PackageID != "pkg-1" {
		t.Errorf("unexpected apply audit event: %+v", e)
	}
}

func TestAudit_QuarantineApplyAndSupersedeDelete(t *testing.T) {
	sel := map[string]string{"app": "web"}
	m := newTestManager(t, Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, deployment("ns", "web", sel))
	cap := &capturePolicyAudit{}
	m.SetPolicyAuditPublisher(cap)
	ctx := context.Background()

	// First RESTRICTED so there is a restricted policy to supersede.
	m.handle(ctx, restrictedTransition("ns/Deployment/web", "pkg-1"))
	// Then QUARANTINED: applies the deny-all AND supersede-deletes the restricted.
	m.handle(ctx, quarantinedTransition("ns/Deployment/web", "pkg-2"))

	if got := len(cap.byAction(AuditActionApply)); got != 2 {
		t.Errorf("want 2 apply audits (restricted + quarantined), got %d", got)
	}
	sd := cap.byAction(AuditActionSupersedeDelete)
	if len(sd) != 1 {
		t.Fatalf("want 1 supersede_delete audit, got %d", len(sd))
	}
	if sd[0].PolicyKind != AuditPolicyKindRestricted || sd[0].FSMState != "QUARANTINED" {
		t.Errorf("supersede_delete should record the restricted policy removed under QUARANTINED target: %+v", sd[0])
	}
}

func TestAudit_DeescalationRemoveEmitsOnce(t *testing.T) {
	sel := map[string]string{"app": "web"}
	m := newTestManager(t, Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, deployment("ns", "web", sel))
	cap := &capturePolicyAudit{}
	m.SetPolicyAuditPublisher(cap)
	ctx := context.Background()

	m.handle(ctx, restrictedTransition("ns/Deployment/web", "pkg-1"))
	cap.mu.Lock()
	cap.got = nil // drop the apply event; focus on the removal
	cap.mu.Unlock()

	m.handle(ctx, cleanTransition("ns/Deployment/web", "pkg-2")) // de-escalation removal

	rm := cap.byAction(AuditActionDeescalationRemove)
	if len(rm) != 1 {
		t.Fatalf("want exactly 1 deescalation_remove audit (one per workload set), got %d", len(rm))
	}
	if rm[0].FSMState != "CLEAN" || rm[0].PolicyName != "" || rm[0].PolicyKind != "" {
		t.Errorf("deescalation_remove should be a set removal at CLEAN with no single name/kind: %+v", rm[0])
	}
}

func TestAudit_NilPublisherNoPanic(t *testing.T) {
	sel := map[string]string{"app": "web"}
	m := newTestManager(t, Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, deployment("ns", "web", sel))
	// No SetPolicyAuditPublisher: m.audit is nil; handle must not panic.
	m.handle(context.Background(), restrictedTransition("ns/Deployment/web", "pkg-1"))
}

// TestAudit_GCEmitsValidEventForWellFormedPolicy confirms a normal orphan GC
// emits a gc_delete audit event with the policy's own fsm_state.
func TestAudit_GCEmitsValidEventForWellFormedPolicy(t *testing.T) {
	orphan := m_buildManagedPolicy("ns", "orphan", "ns/Deployment/ghost") // owner absent -> orphan
	m := newTestManager(t, Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, orphan)
	cap := &capturePolicyAudit{}
	m.SetPolicyAuditPublisher(cap)

	m.reconcileGC(context.Background())

	gc := cap.byAction(AuditActionGCDelete)
	if len(gc) != 1 {
		t.Fatalf("want 1 gc_delete audit, got %d", len(gc))
	}
	if gc[0].FSMState != "RESTRICTED" || gc[0].PolicyName != "orphan" {
		t.Errorf("unexpected gc_delete audit: %+v", gc[0])
	}
}

// TestAudit_GCSkipsEmitForMissingFSMState pins the round-1 fix: a managed
// policy whose AnnFSMState annotation is absent/corrupt is still GC'd (mutation
// happens) but produces NO AUDIT.policies event, because an empty fsm_state
// would violate the committed schema's closed enum (AC6 "every payload
// validates"). The GC loop only requires AnnWorkloadID, so this is reachable.
func TestAudit_GCSkipsEmitForMissingFSMState(t *testing.T) {
	orphan := m_buildManagedPolicy("ns", "orphan", "ns/Deployment/ghost")
	delete(orphan.Annotations, AnnFSMState) // strip the fsm-state annotation
	m := newTestManager(t, Config{ClusterCIDRs: []string{"10.96.0.0/12"}}, orphan)
	cap := &capturePolicyAudit{}
	m.SetPolicyAuditPublisher(cap)
	ctx := context.Background()

	m.reconcileGC(ctx)

	// The mutation still happened: the orphan is gone.
	if _, err := m.cs.NetworkingV1().NetworkPolicies("ns").Get(ctx, "orphan", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("orphan should still be GC'd, err=%v", err)
	}
	// But NO audit event, since fsm_state would be empty/invalid.
	if got := len(cap.events()); got != 0 {
		t.Fatalf("want 0 audit events for missing fsm-state policy, got %d: %+v", got, cap.events())
	}
}
