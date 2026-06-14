package settling

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"

	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/schema"
)

// newWhiteBoxWithMetrics is newWhiteBox plus the Story 4.9 gauge registration so
// the per-state active-window depth is assertable. It returns the controller and
// the registry it registered on.
func newWhiteBoxWithMetricsReg(t *testing.T) (*Controller, *metrics.Registry) {
	t.Helper()
	c := newWhiteBox(t, &fakePublisher{})
	reg := metricsRegistry(t)
	if err := c.RegisterMetrics(reg); err != nil {
		t.Fatalf("RegisterMetrics: %v", err)
	}
	return c, reg
}

func newWhiteBoxWithMetrics(t *testing.T) *Controller {
	t.Helper()
	c, _ := newWhiteBoxWithMetricsReg(t)
	return c
}

// windowGauge reads the olaitan_report_settling_window_active{state} series.
func windowGauge(t *testing.T, c *Controller, state schema.PodSecurityState) float64 {
	t.Helper()
	return testutil.ToFloat64(c.windowActive.WithLabelValues(string(state)))
}

// TestWindowGauge_Registration asserts the Story 4.9 gauge is registered with the
// canonical name, the {state} label, and the GAUGE type (BI-4/BI-7).
func TestWindowGauge_Registration(t *testing.T) {
	_, reg := newWhiteBoxWithMetricsReg(t)
	mfs, err := reg.Gatherer().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	var mf *dto.MetricFamily
	for _, m := range mfs {
		if m.GetName() == "olaitan_report_settling_window_active" {
			mf = m
		}
	}
	if mf == nil {
		t.Fatalf("olaitan_report_settling_window_active not registered")
	}
	if mf.GetType() != dto.MetricType_GAUGE {
		t.Fatalf("type = %v, want GAUGE", mf.GetType())
	}
	if len(mf.GetMetric()) == 0 {
		t.Fatalf("no pre-init series; want the bounded non-CLEAN states seeded to 0")
	}
	for _, m := range mf.GetMetric() {
		if len(m.GetLabel()) != 1 || m.GetLabel()[0].GetName() != "state" {
			t.Fatalf("series label set = %v, want a single {state} label", m.GetLabel())
		}
	}
}

// TestWindowGauge_ArmThenFinalise: arming one window Inc's the gauge at the
// candidate state; finalisation Dec's it back to zero (BI-4).
func TestWindowGauge_ArmThenFinalise(t *testing.T) {
	c := newWhiteBoxWithMetrics(t)
	timers := map[string]*time.Timer{}
	pendings := map[string]*pending{}
	finalised := map[string]struct{}{}

	c.onTransition(nonClean("w1", schema.StateQuarantined, 91), timers, pendings, finalised)
	if got := windowGauge(t, c, schema.StateQuarantined); got != 1 {
		t.Fatalf("gauge after arm = %v, want 1 at QUARANTINED", got)
	}

	c.onFire(context.Background(), firedSignal{wid: "w1", gen: pendings["w1"].gen}, timers, pendings, finalised)
	if got := windowGauge(t, c, schema.StateQuarantined); got != 0 {
		t.Fatalf("gauge after finalise = %v, want 0", got)
	}
}

// TestWindowGauge_ReArmSameStateNoDoubleCount: a re-arm of the same workload at
// the SAME state does not double-Inc (still one active window, BI-4).
func TestWindowGauge_ReArmSameStateNoDoubleCount(t *testing.T) {
	c := newWhiteBoxWithMetrics(t)
	timers := map[string]*time.Timer{}
	pendings := map[string]*pending{}
	finalised := map[string]struct{}{}

	c.onTransition(nonClean("w1", schema.StateQuarantined, 91), timers, pendings, finalised)
	c.onTransition(nonClean("w1", schema.StateQuarantined, 92), timers, pendings, finalised)
	if got := windowGauge(t, c, schema.StateQuarantined); got != 1 {
		t.Fatalf("gauge after re-arm = %v, want 1 (same active window)", got)
	}
}

// TestWindowGauge_ReArmChangesStateMovesCount: a re-arm that changes the
// candidate final_state moves the count from the old state series to the new
// (Dec old, Inc new), so the per-state depth stays accurate (BI-4/OA2).
func TestWindowGauge_ReArmChangesStateMovesCount(t *testing.T) {
	c := newWhiteBoxWithMetrics(t)
	timers := map[string]*time.Timer{}
	pendings := map[string]*pending{}
	finalised := map[string]struct{}{}

	c.onTransition(nonClean("w1", schema.StateRestricted, 55), timers, pendings, finalised)
	if got := windowGauge(t, c, schema.StateRestricted); got != 1 {
		t.Fatalf("gauge at RESTRICTED = %v, want 1", got)
	}
	c.onTransition(nonClean("w1", schema.StateQuarantined, 91), timers, pendings, finalised)
	if got := windowGauge(t, c, schema.StateRestricted); got != 0 {
		t.Fatalf("gauge at RESTRICTED after escalation = %v, want 0 (count moved)", got)
	}
	if got := windowGauge(t, c, schema.StateQuarantined); got != 1 {
		t.Fatalf("gauge at QUARANTINED after escalation = %v, want 1", got)
	}
}

// TestWindowGauge_CleanCancelDecrements: a CLEAN cancel of a live pending Dec's
// the gauge to zero (BI-4).
func TestWindowGauge_CleanCancelDecrements(t *testing.T) {
	c := newWhiteBoxWithMetrics(t)
	timers := map[string]*time.Timer{}
	pendings := map[string]*pending{}
	finalised := map[string]struct{}{}

	c.onTransition(nonClean("w1", schema.StateQuarantined, 91), timers, pendings, finalised)
	clean := nonClean("w1", schema.StateClean, 0)
	clean.FromState = schema.StateQuarantined
	c.onTransition(clean, timers, pendings, finalised)
	if got := windowGauge(t, c, schema.StateQuarantined); got != 0 {
		t.Fatalf("gauge after CLEAN cancel = %v, want 0", got)
	}
}

// TestWindowGauge_TwoWorkloadsPerStateDepth: two workloads armed at different
// states each contribute one to their own per-state series (BI-4).
func TestWindowGauge_TwoWorkloadsPerStateDepth(t *testing.T) {
	c := newWhiteBoxWithMetrics(t)
	timers := map[string]*time.Timer{}
	pendings := map[string]*pending{}
	finalised := map[string]struct{}{}

	c.onTransition(nonClean("w1", schema.StateQuarantined, 91), timers, pendings, finalised)
	c.onTransition(nonClean("w2", schema.StatePreservedKilled, 99), timers, pendings, finalised)
	if got := windowGauge(t, c, schema.StateQuarantined); got != 1 {
		t.Errorf("QUARANTINED depth = %v, want 1", got)
	}
	if got := windowGauge(t, c, schema.StatePreservedKilled); got != 1 {
		t.Errorf("PRESERVED_KILLED depth = %v, want 1", got)
	}
}

// TestWindowGauge_NilRegistryNoPanic: a controller with no metrics registry (the
// unit-test default) does not panic on arm/finalise (the nil-guard, BI-4).
func TestWindowGauge_NilRegistryNoPanic(t *testing.T) {
	c := newWhiteBox(t, &fakePublisher{}) // no RegisterMetrics, windowActive is nil
	timers := map[string]*time.Timer{}
	pendings := map[string]*pending{}
	finalised := map[string]struct{}{}

	c.onTransition(nonClean("w1", schema.StateQuarantined, 91), timers, pendings, finalised)
	c.onFire(context.Background(), firedSignal{wid: "w1", gen: pendings["w1"].gen}, timers, pendings, finalised)
}
