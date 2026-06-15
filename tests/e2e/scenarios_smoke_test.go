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
// The synthetic-event field shapes mirror the SINGLE SOURCE OF TRUTH in
// cmd/olaitan-eval/scenario.go (scenarioEvents); this package cannot import
// the main package, so the shapes are replicated here exactly as rs_smoke
// replicates its own event shapes inline.
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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"gopkg.in/yaml.v3"
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
// stimulus against the warmed cluster (BI-3). It mirrors the field shapes in
// cmd/olaitan-eval/scenario.go scenarioEvents: a priming event of a DIFFERENT
// source than the match event (so the correlator's two-distinct-source
// rising edge fires and assembles a package), then the rule-matching
// event(s). For S4 it ALSO pre-seeds the per-workload baseline with the
// rs_smoke 10-priming-plus-1-spike EvidencePackage pattern so the
// outbound_unique_dst_ips deviation half can fire (BI-4). All events share
// one injection timestamp so the correlator's 60s window cannot straddle a
// boundary (the rs_smoke precedent).
func injectScenario(t *testing.T, js jetstream.JetStream, scenarioID, podName string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	pod := map[string]any{"name": podName, "namespace": "tenant-acme", "uid": "scenario-" + scenarioID + "-uid-1"}

	primingNetwork := func() {
		raw, _ := json.Marshal(map[string]any{"dst_ip": "10.0.0.1"})
		ev, _ := json.Marshal(map[string]any{
			"id": "scenario-" + scenarioID + "-priming", "timestamp": now,
			"source": "network", "category": "flow",
			"summary": "scenario " + scenarioID + " priming flow",
			"raw":     json.RawMessage(raw), "pod": pod,
		})
		publishJS(t, js, "olaitan.events.raw.network", ev)
	}
	primingFalco := func() {
		raw, _ := json.Marshal(map[string]any{"process.exe": "/usr/bin/true"})
		ev, _ := json.Marshal(map[string]any{
			"id": "scenario-" + scenarioID + "-priming", "timestamp": now,
			"source": "falco", "category": "process",
			"summary": "scenario " + scenarioID + " priming process",
			"raw":     json.RawMessage(raw), "pod": pod,
		})
		publishJS(t, js, "olaitan.events.raw.falco", ev)
	}
	mk := func(id, subject, source, category, severity string, raw map[string]any) {
		rawJSON, _ := json.Marshal(raw)
		fields := map[string]any{
			"id": id, "timestamp": now, "source": source, "category": category,
			"raw": json.RawMessage(rawJSON), "pod": pod,
		}
		if severity != "" {
			fields["severity"] = severity
		}
		payload, _ := json.Marshal(fields)
		publishJS(t, js, subject, payload)
	}

	switch scenarioID {
	case "s1":
		primingNetwork()
		mk("scenario-s1-falco-1", "olaitan.events.raw.falco", "falco", "syscall", "CRITICAL", map[string]any{
			"process.exe":           "/host/bin/sh",
			"process.cap_effective": "CAP_NET_BIND_SERVICE CAP_SYS_ADMIN CAP_SETUID",
		})
	case "s2":
		primingNetwork()
		mk("scenario-s2-falco-1", "olaitan.events.raw.falco", "falco", "file", "WARNING", map[string]any{
			"file.path":   "/run/secrets/kubernetes.io/serviceaccount/token",
			"process.exe": "/usr/bin/curl",
		})
		mk("scenario-s2-net-1", "olaitan.events.raw.network", "network", "flow", "", map[string]any{
			"dst_ip":         "169.254.169.254",
			"network.dst_ip": "169.254.169.254",
		})
	case "s3":
		primingNetwork()
		mk("scenario-s3-falco-1", "olaitan.events.raw.falco", "falco", "process", "WARNING", map[string]any{
			"process.exe": "/usr/local/bin/kubectl",
		})
	case "s4":
		// Baseline-deviation half (BI-4): pre-seed the per-workload
		// baseline so outbound_unique_dst_ips crosses 3 sigma. Then drive
		// the rule-match half with a benign falco priming + the OLT-NET
		// flow match (two distinct sources for the rising edge).
		publishSyntheticEvidencePackages(t, js, podName)
		waitForBaselineConsumerDrained(t, js)
		primingFalco()
		mk("scenario-s4-net-1", "olaitan.events.raw.network", "network", "flow", "", map[string]any{
			"dst_ip":            "203.0.113.10",
			"network.dst_ip":    "203.0.113.10",
			"network.bytes_out": "512",
			"network.dst_port":  8443,
			"network.protocol":  "TCP",
		})
	case "s5":
		primingNetwork()
		mk("scenario-s5-falco-1", "olaitan.events.raw.falco", "falco", "process", "WARNING", map[string]any{
			"process.exe":      "/tmp/xmrig",
			"network.dst_port": 3333,
		})
		mk("scenario-s5-net-1", "olaitan.events.raw.network", "network", "flow", "WARNING", map[string]any{
			"network.dst_port": 4444,
		})
	default:
		t.Fatalf("injectScenario: unknown scenario %q", scenarioID)
	}
}

// assertScenarioSignal polls the aggregator's Prometheus surface until AT
// LEAST ONE of the scenario's triggering rules matches OR a baseline
// deviation fires, AND a correlator EvidencePackage reaches EVIDENCE.packages
// -- within the scenario's target_time_to_detect_seconds budget (AC8, BI-8).
// It returns nil on success and the last error on timeout.
func assertScenarioSignal(t *testing.T, tgt scenarioSmokeTarget) error {
	t.Helper()
	budget := time.Duration(tgt.TargetTimeToDetectSeconds) * time.Second
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
		deviations := metrics["olaitan_decision_baseline_deviations_total"].sumWhere(nil)
		evidence := metrics["olaitan_correlator_evidence_packages_total"].sumWhere(nil)
		if tick%4 == 0 {
			t.Logf("scenario %s poll tick=%d: rule_matches(%v)=%v baseline_deviations=%v correlator_packages=%v",
				tgt.ScenarioID, tick, tgt.TriggeringRules, ruleMatches, deviations, evidence)
		}
		tick++
		// AC8: a rule match OR a baseline deviation, AND the EVIDENCE
		// package reached the bus.
		if (ruleMatches >= 1 || deviations >= 1) && evidence >= 1 {
			return nil
		}
		switch {
		case ruleMatches < 1 && deviations < 1:
			lastErr = fmt.Errorf("no rule match for %v and no baseline deviation yet", tgt.TriggeringRules)
		case evidence < 1:
			lastErr = fmt.Errorf("correlator evidence packages = %v; want >= 1", evidence)
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
			injectScenario(t, js, scenarioID, podName)
			if err := assertScenarioSignal(t, tgt); err != nil {
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
		injectScenario(t, js, "s1", podName)
		if err := assertScenarioSignal(t, tgt); err != nil {
			dumpEvidenceStream(t, js)
			dumpRuleMatchSamples(t)
			t.Fatalf("idempotency run %d: %v", run, err)
		}
		t.Logf("idempotency run %d reached EVIDENCE.packages", run)
	}
}
