package main

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/olokotoh/olaitan/internal/decision/analyst"
	"github.com/olokotoh/olaitan/internal/response/risk"
	"github.com/olokotoh/olaitan/internal/schema"
)

// Story 11.2b: the correlator's per-event path publishes a rule_match package
// labelled Origin=late_event (one OLT rule, one event). These tests pin how
// the merged Story 7.4 FSM driver treats it.

func latePkg(wl, id, ruleID, severity string) schema.EvidencePackage {
	return schema.EvidencePackage{
		PackageID:   id,
		WorkloadID:  wl,
		Trigger:     schema.EvidenceTrigger{Type: "rule_match", Origin: schema.TriggerOriginLateEvent},
		RuleMatches: []schema.RuleMatch{{RuleID: ruleID, Severity: severity, EventID: "evt-" + id}},
		Events:      []schema.Event{{ID: "evt-" + id, Source: schema.SourceNetwork}},
	}
}

// The same rule ID twice in one risk window does not inflate the score: the
// window keeps the strongest match, it does not sum repeats.
func TestFSMDriver_LateRuleRepeatDoesNotInflateScore(t *testing.T) {
	f := newDriverFixture(t, nil, risk.New(60*time.Second), 0, 0)
	wl := "tenant-acme/Deployment/web"
	f.handle(latePkg(wl, "late-1", "OLT-NET-002", "50"))
	first := f.d.last.Total
	if first <= 0 {
		t.Fatalf("late OLT-NET-002 package scored %v; it must contribute to the score", first)
	}
	f.handle(latePkg(wl, "late-2", "OLT-NET-002", "50"))
	if f.d.last.Total != first {
		t.Fatalf("repeat of OLT-NET-002 moved the score %v -> %v; the risk window must keep the max, not sum", first, f.d.last.Total)
	}
	if !f.acked.has("late-1") || !f.acked.has("late-2") {
		t.Fatal("late packages must be acked")
	}
}

// A late_event rule_match package arriving while the workload's analyst chain
// is in flight is coalesced (no second chain) but NEVER dropped: it is scored
// and drives the FSM at once, and is acked.
func TestFSMDriver_LatePackageDuringInFlightChainIsCoalescedNotDropped(t *testing.T) {
	br := newBlockingRunner(0)
	f := newDriverFixture(t, br.run, risk.New(60*time.Second), 2, 4)
	wl := "tenant-acme/Deployment/web"
	f.handle(pkgFor(wl, "p-1", "50")) // 0.4*50 = 20: SUSPICIOUS, and dispatches the chain
	awaitStarted(t, br)
	before := len(f.sink.all())

	f.handle(latePkg(wl, "late-1", "OLT-TEST-LATE", "100")) // 0.4*100 = 40: RESTRICTED

	if !f.acked.has("late-1") {
		t.Fatal("late package left un-acked while another chain was in flight")
	}
	got := f.sink.all()
	if len(got) != before+1 || got[len(got)-1].PackageID != "late-1" || got[len(got)-1].ToState != schema.StateRestricted {
		t.Fatalf("late package was not scored into the FSM while the chain ran: %+v", got)
	}
	if n := br.calls.Load(); n != 1 {
		t.Fatalf("chain runs = %d, want 1 (the late package is coalesced)", n)
	}
	if v := testutil.ToFloat64(f.cnt.WithLabelValues(analyst.ChainDispatchCoalesced)); v != 1 {
		t.Fatalf("coalesced = %v, want 1", v)
	}
	close(br.release)
	f.awaitResult(t)
}
