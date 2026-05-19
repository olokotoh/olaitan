package trigger

import (
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/correlator/window"
	"github.com/olokotoh/olaitan/internal/schema"
)

func TestEvaluateMultiSignalRequiresDistinctSources(t *testing.T) {
	snap := window.Snapshot{
		WorkloadID: "payments/Deployment/api",
		Events: []schema.Event{
			{ID: "falco-1", Source: schema.SourceFalco, Timestamp: time.Unix(1, 0)},
			{ID: "falco-2", Source: schema.SourceFalco, Timestamp: time.Unix(2, 0)},
		},
	}
	if _, ok := EvaluateMultiSignal(snap, 2, time.Unix(3, 0)); ok {
		t.Fatal("same-source events triggered multi-signal convergence")
	}

	snap.Events = append(snap.Events, schema.Event{ID: "audit-1", Source: schema.SourceAudit, Timestamp: time.Unix(3, 0)})
	got, ok := EvaluateMultiSignal(snap, 2, time.Unix(4, 0))
	if !ok {
		t.Fatal("expected convergence with falco+audit")
	}
	if got.Type != TypeMultiSignal {
		t.Errorf("Type: got %q want %q", got.Type, TypeMultiSignal)
	}
	if len(got.DistinctSources) != 2 || got.DistinctSources[0] != schema.SourceAudit || got.DistinctSources[1] != schema.SourceFalco {
		t.Errorf("DistinctSources: got %v", got.DistinctSources)
	}
}

func TestExternalTriggerConstructors(t *testing.T) {
	rm := schema.RuleMatch{RuleID: "OLT-1", EventID: "evt-1"}
	rule := RuleMatch("workload", rm, time.Unix(1, 0))
	if rule.Type != TypeRuleMatch || rule.RuleMatch == nil || rule.RuleMatch.RuleID != "OLT-1" {
		t.Errorf("rule trigger: %+v", rule)
	}

	dev := schema.BaselineDeviation{Metric: "exec_rate", Sigma: 3.5, PodUID: "pod-1"}
	baseline := BaselineDeviation("workload", dev, time.Unix(2, 0))
	if baseline.Type != TypeBaselineDeviation || baseline.BaselineDeviation == nil || baseline.BaselineDeviation.Sigma != 3.5 {
		t.Errorf("baseline trigger: %+v", baseline)
	}
}
