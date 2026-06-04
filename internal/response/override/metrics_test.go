package override

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/olokotoh/olaitan/internal/metrics"
)

// TestOverrideMetrics_AppliedAndActive (Story 2.9, AC2/BI-3): an applied
// override increments applied_total{state} and the active{state} gauge reflects
// the FSM pin set after the reconcile tick.
func TestOverrideMetrics_AppliedAndActive(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	store, _ := newRedisStore(t, mr)
	machine := newMachine(t)
	pub := &fakePublisher{}
	reg := metrics.NewRegistry()

	_, objs := deploymentPod("default", "web", map[string]string{
		AnnotationState: "RESTRICTED",
		AnnotationTTL:   "30m",
	})
	c := newController(t, objs, store, machine, pub, reg)
	c.reconcile(ctx)

	if got := testutil.ToFloat64(c.applied.WithLabelValues("RESTRICTED")); got != 1 {
		t.Errorf("applied_total{RESTRICTED} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(c.active.WithLabelValues("RESTRICTED")); got != 1 {
		t.Errorf("active{RESTRICTED} = %v, want 1 (workload pinned)", got)
	}
	// A state with no pins reads 0 (gauge reset each tick).
	if got := testutil.ToFloat64(c.active.WithLabelValues("QUARANTINED")); got != 0 {
		t.Errorf("active{QUARANTINED} = %v, want 0", got)
	}
}
