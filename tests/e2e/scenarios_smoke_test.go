//go:build e2e

// Story 5.2 AC8 + AC7: the kind integration test for the five attack
// scenario harnesses (S1-S5). It reuses the Story-1.19 rs_smoke kind
// bring-up VERBATIM (the chart installs healthy under evaluation.config=RS,
// Falco-off, single-node kind, synthetic raw events injected directly to
// NATS) and, for EACH scenario, fires the scenario's deterministic stimulus
// and asserts -- within the scenario's target.yaml target_time_to_detect_
// seconds poll budget -- that AT LEAST ONE rule match OR baseline deviation
// reaches EVIDENCE.packages (subject olaitan.evidence.packages):
//
//	olaitan_decision_rules_matches_by_attribute_total{rule_id=<one of the
//	  scenario's triggering_rules>} >= 1  OR
//	olaitan_decision_baseline_deviations_total >= 1
//	AND olaitan_correlator_evidence_packages_total >= 1
//
// HONEST SCOPE (BI-8): AC8 asserts the EVIDENCE-package SIGNAL (the rule-
// match / baseline-deviation half), NOT the full FSM-state attainment of
// AC2-AC6 (the QUARANTINED / RESTRICTED / SUSPICIOUS targets + the measured
// time-to-detect are Story 5.4 + the carry-forward A1 RSLT-full-kind gate).
// The synthetic-event field shapes come from the SINGLE SOURCE OF TRUTH in the
// non-main package internal/eval/scenario, which BOTH cmd/olaitan-eval AND this
// e2e test import directly -- so there is no hand-copy to drift against (the
// main package itself still cannot be imported here, but the recipe data is no
// longer in main).
//
// CI placement (OQ4): mirrors eval-smoke. `make scenarios-smoke` reuses the
// SAME RS bring-up; it SKIPS gracefully when the kind cluster is absent so
// `go test -tags=e2e ./...` on a bare host does not hard-fail. It is wired
// into the existing CI e2e job alongside the RS + eval smokes (it reuses the
// RS bring-up, so the marginal CI cost is the per-scenario injection +
// poll). The live full-scenario FSM-attainment run folds into the carry-
// forward A1 gate, disclosed honestly.
package e2e_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"gopkg.in/yaml.v3"

	evalscenario "github.com/olokotoh/olaitan/internal/eval/scenario"
)

// scenarioSmokeTarget mirrors the fields the AC8 assertion reads off a
// harness target.yaml (Story 5.2, BI-2).
type scenarioSmokeTarget struct {
	ScenarioID                string   `yaml:"scenario_id"`
	TargetTimeToDetectSeconds int      `yaml:"target_time_to_detect_seconds"`
	TriggeringRules           []string `yaml:"triggering_rules"`
}

// scenarioSlugs maps the short id to the committed harness slug (mirrors the
// cmd/olaitan-eval/scenario.go factory map, BI-1).
var scenarioSmokeSlugs = map[string]string{
	"s1": "s1-container-escape",
	"s2": "s2-credential-exfil",
	"s3": "s3-lateral-movement",
	"s4": "s4-c2-beaconing",
	"s5": "s5-cryptomining",
}

// loadScenarioSmokeTarget reads a harness target.yaml from the committed tree
// (resolved relative to tests/e2e/).
func loadScenarioSmokeTarget(t *testing.T, scenarioID string) scenarioSmokeTarget {
	t.Helper()
	slug, ok := scenarioSmokeSlugs[scenarioID]
	if !ok {
		t.Fatalf("scenario %q has no harness slug", scenarioID)
	}
	path := filepath.Join(repoRoot(), "deploy", "demo", "scenarios", slug, "target.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read target.yaml %q: %v", path, err)
	}
	var tgt scenarioSmokeTarget
	if err := yaml.Unmarshal(raw, &tgt); err != nil {
		t.Fatalf("parse target.yaml %q: %v", path, err)
	}
	if tgt.ScenarioID != scenarioID || tgt.TargetTimeToDetectSeconds <= 0 || len(tgt.TriggeringRules) == 0 {
		t.Fatalf("target.yaml %q is malformed: %+v", path, tgt)
	}
	return tgt
}

// injectScenario fires scenario scenarioID's deterministic synthetic-event
// stimulus against the warmed cluster (BI-3) and returns the counter snapshot
// captured immediately BEFORE the rule-match events were published, so the
// caller can assert a per-scenario DELTA (the deviation/evidence counters are
// cumulative + shared across the sequential subtests). The event recipes come
// from the SINGLE SOURCE OF TRUTH evalscenario.Events (shared with
// cmd/olaitan-eval), so the e2e injection and the in-process binary cannot
// drift. For S4 it ALSO pre-seeds the per-workload baseline with the rs_smoke
// 10-priming-plus-1-spike EvidencePackage pattern so the outbound_unique_dst_ips
// deviation half can fire (BI-4) BEFORE the rule-match events are published; the
// snapshot is taken BEFORE the pre-seed so the pre-seed spike's deviation (the
// one S4 actually relies on per BI-4) lands INSIDE the per-scenario delta rather
// than being folded into `before` and leaving the deviation half inert. All
// recipe events share one injection
// timestamp so the correlator's 60s window cannot straddle a boundary (the
// rs_smoke precedent).
func injectScenario(t *testing.T, js jetstream.JetStream, scenarioID, podName string) scenarioCounterSnapshot {
	t.Helper()
	if _, ok := scenarioSmokeSlugs[scenarioID]; !ok {
		t.Fatalf("injectScenario: unknown scenario %q", scenarioID)
	}
	// Snapshot the cumulative counters BEFORE any of this scenario's stimuli
	// (including the S4 baseline pre-seed) so the per-scenario delta captures
	// every signal THIS scenario produces. For S4 the deviation it relies on
	// (BI-4) is fired by the pre-seed spike itself, so the snapshot must precede
	// the pre-seed or that deviation would be folded into `before` and the delta
	// would be inert.
	before := snapshotScenarioCounters(t)
	// S4 rests partly on a baseline deviation: pre-seed the per-workload
	// baseline so outbound_unique_dst_ips crosses 3 sigma and let the baseline
	// consumer drain BEFORE the rule-match flow events arrive (BI-4).
	if evalscenario.BaselinePreseed(scenarioID) {
		publishSyntheticEvidencePackages(t, js, podName)
		waitForBaselineConsumerDrained(t, js)
	}
	events := evalscenario.Events(scenarioID, podName, time.Now().UTC())
	if len(events) == 0 {
		t.Fatalf("injectScenario: no recipe events for scenario %q", scenarioID)
	}
	for _, ev := range events {
		publishJS(t, js, ev.Subject, ev.Payload)
	}
	return before
}

// smokePollCeiling caps the per-scenario smoke poll budget. The EVIDENCE-
// package signal arrives near-instantly on kind; a scenario's full
// target_time_to_detect_seconds window (up to S4=300s) is the Story-5.4 /
// A1-gate time-to-detect concern, NOT this smoke. Without the cap a single
// stuck scenario could burn its whole target window (and the suite ~600s
// cumulatively). We poll for min(target, ceiling) instead. The ceiling matches
// the sibling rs_smoke assertionTimeout (90s) since the scenarios drive the same
// correlator+rules+baseline pipeline on the same kind bring-up; tightening below
// that proven budget would risk a flake on a loaded CI runner.
const smokePollCeiling = 90 * time.Second

// scenarioCounterSnapshot is the per-scenario baseline of the cumulative _total
// counters, captured immediately BEFORE the scenario's inject. assertScenario
// Signal asserts a per-scenario DELTA against it so each scenario proves its
// OWN signal (the counters are cumulative + shared across the sequential
// subtests, so an absolute >= 1 check could pass on an EARLIER scenario's
// residue rather than this scenario's own rule/deviation/package).
type scenarioCounterSnapshot struct {
	deviations float64
	evidence   float64
}

// snapshotScenarioCounters captures the cumulative counters the delta-based
// AC8 assertion is taken against. injectScenario calls it at the very start,
// before any of the scenario's stimuli (including the S4 pre-seed).
// The rule-match half is already scenario-scoped by rule_id (each scenario's
// triggering rules are distinct), so it does not need a delta; the deviation
// and evidence-package halves DO, because they are read unlabelled and are
// shared across the sequential subtests.
func snapshotScenarioCounters(t *testing.T) scenarioCounterSnapshot {
	t.Helper()
	metrics := scrapeMetrics(t)
	return scenarioCounterSnapshot{
		deviations: metrics["olaitan_decision_baseline_deviations_total"].sumWhere(nil),
		evidence:   metrics["olaitan_correlator_evidence_packages_total"].sumWhere(nil),
	}
}

// assertScenarioSignal polls the aggregator's Prometheus surface until AT
// LEAST ONE of the scenario's triggering rules matches OR a baseline deviation
// fires, AND a correlator EvidencePackage reaches EVIDENCE.packages -- within
// a capped poll budget (AC8, BI-8). The rule-match half is scenario-scoped by
// rule_id; the baseline-deviation and evidence-package halves are asserted as
// a per-scenario DELTA over `before` (captured at inject time) so each scenario
// proves its OWN signal rather than passing on an earlier scenario's residue.
// It returns nil on success and the last error on timeout.
func assertScenarioSignal(t *testing.T, tgt scenarioSmokeTarget, before scenarioCounterSnapshot) error {
	t.Helper()
	budget := time.Duration(tgt.TargetTimeToDetectSeconds) * time.Second
	if budget > smokePollCeiling {
		budget = smokePollCeiling
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	var lastErr error
	tick := 0
	for {
		metrics := scrapeMetrics(t)
		var ruleMatches float64
		for _, ruleID := range tgt.TriggeringRules {
			ruleMatches += metrics["olaitan_decision_rules_matches_by_attribute_total"].sumWhere(map[string]string{"rule_id": ruleID})
		}
		// Per-scenario DELTAs over the inject-time baseline (the counters are
		// cumulative + shared across the sequential subtests).
		deviations := metrics["olaitan_decision_baseline_deviations_total"].sumWhere(nil) - before.deviations
		evidence := metrics["olaitan_correlator_evidence_packages_total"].sumWhere(nil) - before.evidence
		if tick%4 == 0 {
			t.Logf("scenario %s poll tick=%d: rule_matches(%v)=%v baseline_deviations(delta)=%v correlator_packages(delta)=%v",
				tgt.ScenarioID, tick, tgt.TriggeringRules, ruleMatches, deviations, evidence)
		}
		tick++
		// AC8: this scenario's OWN rule match OR baseline-deviation delta,
		// AND this scenario's OWN EVIDENCE-package delta reached the bus.
		if (ruleMatches >= 1 || deviations >= 1) && evidence >= 1 {
			return nil
		}
		switch {
		case ruleMatches < 1 && deviations < 1:
			lastErr = fmt.Errorf("no rule match for %v and no baseline-deviation delta yet", tgt.TriggeringRules)
		case evidence < 1:
			lastErr = fmt.Errorf("correlator evidence-package delta = %v; want >= 1", evidence)
		}
		select {
		case <-ctx.Done():
			final := scrapeMetrics(t)
			t.Logf("scenario %s final snapshot: rule_matches_by_attribute=%s baseline_deviations=%s correlator_packages=%s",
				tgt.ScenarioID,
				formatFamily(final, "olaitan_decision_rules_matches_by_attribute_total"),
				formatFamily(final, "olaitan_decision_baseline_deviations_total"),
				formatFamily(final, "olaitan_correlator_evidence_packages_total"))
			return fmt.Errorf("scenario %s: EVIDENCE-package signal did not arrive within %s: %v", tgt.ScenarioID, budget, lastErr)
		case <-time.After(assertionPollInterval):
		}
	}
}

// connectJS brings up the NATS + metrics port-forwards and returns a
// JetStream context (shared by the per-scenario subtests).
func connectScenarioJS(t *testing.T) jetstream.JetStream {
	t.Helper()
	waitForNATSReady(t)
	portForward(t, "svc/"+defaultReleaseName+"-nats", natsLocalPort, "4222")
	portForward(t, "deploy/"+defaultReleaseName+"-aggregator", metricsLocalPort, "9090")
	nc, err := nats.Connect("nats://localhost:" + natsLocalPort)
	if err != nil {
		t.Fatalf("NATS connect: %v", err)
	}
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatalf("JetStream context: %v", err)
	}
	return js
}

// TestKindSmoke_Scenarios_S1toS5_ReachEvidence is the Story 5.2 AC8 pin: each
// scenario S1-S5 fires its deterministic stimulus and at least one rule match
// or baseline deviation reaches EVIDENCE.packages within the scenario's
// target_time_to_detect_seconds window. The cluster bring-up is the rs_smoke
// RS arm (Falco-off, NO LLM); the per-scenario stimulus mirrors
// cmd/olaitan-eval/scenario.go.
func TestKindSmoke_Scenarios_S1toS5_ReachEvidence(t *testing.T) {
	requireKindCluster(t)
	waitForPodsReady(t)
	// One real Deployment-owned pod in tenant-acme so the correlator's
	// posture resolver returns OwnerKind=Deployment + namespace=tenant-acme
	// (the workload identity every scenario's rules key on). Reused across
	// the per-scenario subtests so the warmed baseline is shared.
	podName := applySyntheticWorkload(t)
	js := connectScenarioJS(t)

	for _, scenarioID := range []string{"s1", "s2", "s3", "s4", "s5"} {
		scenarioID := scenarioID
		t.Run(scenarioID, func(t *testing.T) {
			tgt := loadScenarioSmokeTarget(t, scenarioID)
			before := injectScenario(t, js, scenarioID, podName)
			if err := assertScenarioSignal(t, tgt, before); err != nil {
				dumpEvidenceStream(t, js)
				dumpRuleMatchSamples(t)
				t.Fatal(err)
			}
		})
	}
}

// TestKindSmoke_Scenarios_Idempotency is the Story 5.2 AC7 pin: re-running a
// scenario's stimulus against the warmed cluster reaches EVIDENCE.packages
// identically on the second run (the stimulus is deterministic + idempotent;
// the per-run namespace teardown returns the cluster to the warmed-baseline,
// BI-7). It runs S1 (the proven rs_smoke path) twice consecutively and
// asserts both runs reach the EVIDENCE-package signal.
//
// IDEMPOTENCY-TEARDOWN HOME (BI-7, OQ3): 5.2 does NOT over-reach the
// 5.1-owned ClusterController.Reset seam. The scenario harness's
// applySyntheticWorkload registers a t.Cleanup that deletes the tenant-acme
// namespace (cascading the Deployment/ReplicaSet/Pod), so no scenario
// workload state leaks across test runs; the second in-test run reuses the
// SAME warmed pod, proving the stimulus itself is re-runnable without manual
// cleanup.
func TestKindSmoke_Scenarios_Idempotency(t *testing.T) {
	requireKindCluster(t)
	waitForPodsReady(t)
	podName := applySyntheticWorkload(t)
	js := connectScenarioJS(t)
	tgt := loadScenarioSmokeTarget(t, "s1")

	for run := 1; run <= 2; run++ {
		before := injectScenario(t, js, "s1", podName)
		if err := assertScenarioSignal(t, tgt, before); err != nil {
			dumpEvidenceStream(t, js)
			dumpRuleMatchSamples(t)
			t.Fatalf("idempotency run %d: %v", run, err)
		}
		t.Logf("idempotency run %d reached EVIDENCE.packages", run)
	}
}
