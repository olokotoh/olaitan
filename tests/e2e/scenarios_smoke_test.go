//go:build e2e

// Story 5.2 AC8 + AC7: the kind integration test for the five attack
// scenario harnesses (S1-S5). It reuses the Story-1.19 rs_smoke kind
// bring-up (the chart installs under evaluation.config=RS on single-node kind
// with Falco ON, Story 10.4) and, for EACH scenario, fires the scenario's
// stimulus and asserts, within the scenario's target.yaml
// target_time_to_detect_seconds poll budget (capped), a per-scenario DELTA:
//
//	olaitan_decision_rules_matches_by_attribute_total{rule_id=<one of the
//	  scenario's triggering_rules>} +1  OR
//	olaitan_decision_baseline_deviations_total +1
//	AND olaitan_correlator_evidence_packages_total +1
//
// Story 11.2a (AC5, decision L2 2026-09-30): S1-S3 are REAL in-cluster
// attacks. The test drives the same executor olaitan-eval runs
// (internal/eval/attack): it applies the Story 11.1 target, runs the
// technique inside the pod with kubectl exec, and Falco's real alerts carry
// the signal through the chart's rules to the OLT rules. Nothing is published
// to NATS for S1-S3. S4 and S5 still inject synthetic events until Story
// 11.2b (#192) gives them real attacker-side infrastructure; the file stays
// on tests/e2e/nats-injection-allowlist.yaml for them only.
//
// HONEST SCOPE (BI-8): AC8 asserts the EVIDENCE-package SIGNAL (the rule-
// match / baseline-deviation half), NOT the FSM-state attainment of AC2-AC6
// or a measured time-to-detect (Story 5.4, Story 7.4 #186).
//
// CI placement (OQ4): mirrors eval-smoke. `make scenarios-smoke` reuses the
// SAME RS bring-up; it SKIPS gracefully when the kind cluster is absent so
// `go test -tags=e2e ./...` on a bare host does not hard-fail.
package e2e_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"gopkg.in/yaml.v3"

	"github.com/olokotoh/olaitan/internal/eval/attack"
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

// correlatorWindow is the chart default correlator.windowDuration (60s),
// which the RS install does not override. A real Falco alert opens an
// investigation once per (workload, Falco rule) per window
// (internal/correlator/correlator.go, claimFalcoTrigger), and every S1-S3
// target is the Deployment tenant-acme/web, so a repeat of the same scenario
// inside the window is folded into the first investigation: no new
// EvidencePackage, so no OLT rule is evaluated. Waiting the window out
// between repeats makes each run a fresh detection.
const correlatorWindow = 60*time.Second + 10*time.Second

// lastRealAttack records when each real scenario last ran, so a repeat waits
// out the correlator window (see correlatorWindow). lastRealAttackMu guards it
// (review round 3, C8): the subtests are sequential today, but the map is
// package state and a future t.Parallel must not race it.
var (
	lastRealAttack   = map[string]time.Time{}
	lastRealAttackMu sync.Mutex
)

// requireKindContext refuses to drive a REAL in-cluster attack anywhere but the
// ephemeral kind e2e cluster (review round 3, C8). A real attack applies a
// privileged workload and execs into it; running it against the wrong context
// (a dev's default kubeconfig, a shared cluster) would be an attack on a real
// system. kind's context is always `kind-<clusterName>`.
func requireKindContext(t *testing.T) {
	t.Helper()
	want := "kind-" + kindClusterName()
	got := strings.TrimSpace(kubectl(t, "config", "current-context"))
	if got != want {
		t.Fatalf("refusing to run a real in-cluster attack: current kube-context is %q, not the e2e kind context %q; a real attack must only ever target the ephemeral kind e2e cluster", got, want)
	}
}

// logWriter sends the executor's structured log lines to t.Log.
type logWriter struct{ t *testing.T }

func (w logWriter) Write(p []byte) (int, error) {
	w.t.Helper()
	w.t.Log(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// runRealAttack applies scenarioID's Story 11.1 target and runs its real
// technique through the shared executor (internal/eval/attack), the exact
// code olaitan-eval runs. It returns the counter snapshot taken just before
// the attack and the executor's Cleanup, which the caller runs AFTER the
// signal assertion so the pod is alive while the correlator resolves its
// posture (the executor's own settle is zeroed: the poll replaces it).
func runRealAttack(t *testing.T, tgt scenarioSmokeTarget) (scenarioCounterSnapshot, func()) {
	t.Helper()
	scenarioID := tgt.ScenarioID
	// Refuse to attack anything but the kind e2e cluster (C8).
	requireKindContext(t)
	lastRealAttackMu.Lock()
	last, ok := lastRealAttack[scenarioID]
	lastRealAttackMu.Unlock()
	if ok {
		if wait := correlatorWindow - time.Since(last); wait > 0 {
			t.Logf("scenario %s ran %s ago; waiting %s for the correlator window to close", scenarioID, time.Since(last).Round(time.Second), wait.Round(time.Second))
			time.Sleep(wait)
		}
	}
	dir := filepath.Join(repoRoot(), "deploy", "demo", "scenarios", scenarioSmokeSlugs[scenarioID])
	executor, err := attack.New(scenarioID, dir, attack.ExecCmd, slog.New(slog.NewTextHandler(logWriter{t}, nil)))
	if err != nil {
		t.Fatalf("attack executor for %s: %v", scenarioID, err)
	}
	executor.SettleWait = 0
	cleanup := func() {
		if err := executor.Cleanup(context.Background()); err != nil {
			t.Errorf("scenario %s cleanup: %v", scenarioID, err)
		}
	}
	before := snapshotScenarioCounters(t, tgt)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := executor.Execute(ctx); err != nil {
		cleanup()
		t.Fatalf("scenario %s real attack: %v", scenarioID, err)
	}
	// Stamp the attack time AFTER the primitive ran (C8), so the correlator-
	// window wait before the next repeat is measured from the real attack, not
	// from before target bring-up (which could be minutes earlier on a slow pull).
	lastRealAttackMu.Lock()
	lastRealAttack[scenarioID] = time.Now()
	lastRealAttackMu.Unlock()
	return before, cleanup
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
	ruleMatches float64
	deviations  float64
	evidence    float64
}

// snapshotScenarioCounters captures the cumulative counters the delta-based
// AC8 assertion is taken against, before any of the scenario's stimuli
// (including the S4 pre-seed). All three halves are deltas: the counters are
// cumulative and shared across tests, and with real attacks an earlier test
// (or the rs_smoke synthetic trigger) can already have matched the same rule
// on the same tenant-acme/web workload, so an absolute rule-match count could
// pass on residue (Story 11.2a).
func snapshotScenarioCounters(t *testing.T, tgt scenarioSmokeTarget) scenarioCounterSnapshot {
	t.Helper()
	metrics := scrapeMetrics(t)
	var ruleMatches float64
	for _, ruleID := range tgt.TriggeringRules {
		ruleMatches += metrics["olaitan_decision_rules_matches_by_attribute_total"].sumWhere(map[string]string{"rule_id": ruleID})
	}
	return scenarioCounterSnapshot{
		ruleMatches: ruleMatches,
		deviations:  metrics["olaitan_decision_baseline_deviations_total"].sumWhere(nil),
		evidence:    metrics["olaitan_correlator_evidence_packages_total"].sumWhere(nil),
	}
}

// scenarioNeedsCalicoFlows reports whether a scenario is detected through the
// Calico Goldmane CNI flow path (S4 C2 beaconing, S5 cryptomining). Those
// flows exist only on a Calico-enabled cluster; on plain kindnet the real
// attack still runs and reverses, but no flow record is produced to detect.
func scenarioNeedsCalicoFlows(scenarioID string) bool {
	return scenarioID == "s4" || scenarioID == "s5"
}

// calicoFlowsAvailable reports whether the cluster runs the Calico Goldmane
// flow collector, i.e. whether the CNI flow path that S4/S5 detection depends
// on can emit flow records at all. It probes for the Goldmane (or Whisker)
// Deployment itself rather than the calico-system namespace, so a Calico
// cluster with flow export disabled, or Calico installed by manifest outside
// calico-system, is classified by the component that actually matters
// (review round 1, Edge Case Hunter). Absent it, kindnet is the CNI and no
// Goldmane flow is produced, so S4/S5 detection is skipped.
func calicoFlowsAvailable(t *testing.T) bool {
	t.Helper()
	out := kubectl(t, "get", "deploy", "-A", "-o", "name")
	return strings.Contains(out, "goldmane") || strings.Contains(out, "whisker")
}

// assertScenarioSignal polls the aggregator's Prometheus surface until AT
// LEAST ONE of the scenario's triggering rules matches OR a baseline deviation
// fires, AND (when requireFreshPackage is true) a correlator EvidencePackage
// reaches EVIDENCE.packages -- within a capped poll budget (AC8, BI-8). The
// rule-match half is scenario-scoped by rule_id; the baseline-deviation and
// evidence-package halves are asserted as a per-scenario DELTA over `before`
// (captured at inject time) so each scenario proves its OWN signal rather than
// passing on an earlier scenario's residue.
//
// requireFreshPackage gates the evidence-package half. The PRIMARY AC8 pin
// (a first detection on a freshly-warmed workload) passes true: the correlator
// MUST emit a fresh package. A same-workload IDEMPOTENCY repeat passes false:
// the correlator's per-workload sliding window legitimately COALESCES the
// repeat stimulus (the rising-edge `fired` flag in
// internal/correlator/window/window.go:171-185 only transitions false->true
// once per workload until the distinct-source set drops below minSources or the
// buffer empties), so AddEvent returns transitioned=false
// (internal/correlator/correlator.go:255-257) and publishTrigger never runs.
// A fresh package on a same-workload repeat requires the Story-5.1-owned
// ClusterController.Reset between runs (BI-7/OQ3); 5.2 does not over-reach it,
// so the repeat assertion is scoped to re-detection only.
// It returns nil on success and the last error on timeout.
func assertScenarioSignal(t *testing.T, tgt scenarioSmokeTarget, before scenarioCounterSnapshot, requireFreshPackage bool) error {
	t.Helper()
	// Flow-detected scenarios (S4/S5) go through Calico Goldmane, whose ~15s
	// aggregation window plus the 60s correlator window can legitimately land
	// a real detection past the 90s smoke ceiling; let them poll their own
	// target budget so the smoke is never stricter than the scenario contract
	// it enforces (Story 11.2b, D-PLATFORM/CI). Other scenarios keep the
	// proven 90s cap.
	budget := time.Duration(tgt.TargetTimeToDetectSeconds) * time.Second
	if !scenarioNeedsCalicoFlows(tgt.ScenarioID) && budget > smokePollCeiling {
		budget = smokePollCeiling
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	// Story 11.2b (D-S4-BASELINE): the synthetic baseline pre-seed is retired,
	// so EVERY scenario must now show its OWN rule-match delta. A global
	// baseline deviation elsewhere on the cluster never passes a scenario.
	var lastErr error
	tick := 0
	for {
		metrics := scrapeMetrics(t)
		var ruleMatches float64
		for _, ruleID := range tgt.TriggeringRules {
			ruleMatches += metrics["olaitan_decision_rules_matches_by_attribute_total"].sumWhere(map[string]string{"rule_id": ruleID})
		}
		ruleMatches -= before.ruleMatches
		// Per-scenario DELTAs over the inject-time baseline (the counters are
		// cumulative + shared across the sequential subtests).
		deviations := metrics["olaitan_decision_baseline_deviations_total"].sumWhere(nil) - before.deviations
		evidence := metrics["olaitan_correlator_evidence_packages_total"].sumWhere(nil) - before.evidence
		if tick%4 == 0 {
			t.Logf("scenario %s poll tick=%d: rule_matches(%v)(delta)=%v baseline_deviations(delta)=%v correlator_packages(delta)=%v",
				tgt.ScenarioID, tick, tgt.TriggeringRules, ruleMatches, deviations, evidence)
		}
		tick++
		// AC8: this scenario's OWN rule match OR baseline-deviation delta,
		// AND (when requireFreshPackage) this scenario's OWN EVIDENCE-package
		// delta reached the bus. The idempotency repeat passes
		// requireFreshPackage=false because the correlator legitimately
		// coalesces a same-workload repeat (see the helper doc comment).
		redetected := ruleMatches >= 1
		freshPackage := !requireFreshPackage || evidence >= 1
		if redetected && freshPackage {
			return nil
		}
		switch {
		case !redetected:
			lastErr = fmt.Errorf("no own rule-match delta for %v yet (a global baseline deviation does not pass a real-attack scenario)", tgt.TriggeringRules)
		case !freshPackage:
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
// scenario S1-S5 fires its stimulus and at least one rule match or baseline
// deviation reaches EVIDENCE.packages within the scenario's
// target_time_to_detect_seconds window (capped). S1-S3 are the real
// in-cluster attacks (Story 11.2a); S4-S5 inject synthetic events until
// Story 11.2b.
func TestKindSmoke_Scenarios_S1toS5_ReachEvidence(t *testing.T) {
	requireKindCluster(t)
	waitForPodsReady(t)

	// Every scenario applies its own real Story 11.1 target (tenant-acme/web)
	// through the executor and deletes it again; S1-S3 (Story 11.2a) and now
	// S4-S5 (Story 11.2b) each fire a different chart rule, so each opens its
	// own investigation on that workload. No scenario injects synthetic NATS
	// events any more.
	scenarioIDs := []string{"s1", "s2", "s3", "s4", "s5"}

	js := connectScenarioJS(t)

	for _, scenarioID := range scenarioIDs {
		scenarioID := scenarioID
		t.Run(scenarioID, func(t *testing.T) {
			tgt := loadScenarioSmokeTarget(t, scenarioID)
			// Every scenario S1-S5 is a REAL in-cluster attack through
			// internal/eval/attack (Story 11.2a for S1-S3; Story 11.2b adds
			// S4's beacon-to-sink and S5's miner + stratum-pool connection).
			before, cleanup := runRealAttack(t, tgt)
			defer cleanup()
			// S4/S5 detect through the Calico Goldmane CNI flow path, which a
			// plain-kindnet smoke cluster does not run. The real attack still
			// executes and reverses here (exercising the executor + cleanup),
			// but the flow-based detection assertion is the reserved live gate
			// on a Calico-capable cluster (kind+Calico / full profile /
			// kubeadm). Skip it when Goldmane is absent rather than fail a
			// signal the cluster cannot physically produce.
			if scenarioNeedsCalicoFlows(scenarioID) && !calicoFlowsAvailable(t) {
				t.Skipf("scenario %s detects via Calico Goldmane flows; this cluster has no Calico - the real attack ran and reversed, detection is asserted on the Calico live gate", scenarioID)
			}
			// PRIMARY AC8 pin: a first detection MUST emit a fresh EVIDENCE
			// package (requireFreshPackage = true). This is the full-signal
			// assertion and must not weaken.
			if err := assertScenarioSignal(t, tgt, before, true); err != nil {
				dumpEvidenceStream(t, js)
				dumpRuleMatchSamples(t)
				t.Fatal(err)
			}
		})
	}
}

// TestKindSmoke_Scenarios_Idempotency is the Story 5.2 AC7 pin, on the real
// S1 attack since Story 11.2a: running the attack twice against the warmed
// cluster reaches EVIDENCE.packages both times. The executor applies the
// target, runs the technique and deletes exactly what it applied, so the
// second run starts from the same state (BI-7) with no manual cleanup.
//
// Both runs assert the FULL signal, including a fresh EVIDENCE package. The
// synthetic version could only claim re-detection on run 2, because the
// correlator folds a same-workload repeat inside its window into the first
// investigation (claimFalcoTrigger, and the rising-edge `fired` flag in
// internal/correlator/window/window.go). runRealAttack waits that window out
// before a repeat, so run 2 is a fresh detection, which is the stronger
// re-runnability claim.
func TestKindSmoke_Scenarios_Idempotency(t *testing.T) {
	requireKindCluster(t)
	waitForPodsReady(t)
	js := connectScenarioJS(t)
	tgt := loadScenarioSmokeTarget(t, "s1")

	for run := 1; run <= 2; run++ {
		before, cleanup := runRealAttack(t, tgt)
		err := assertScenarioSignal(t, tgt, before, true)
		cleanup()
		if err != nil {
			dumpEvidenceStream(t, js)
			dumpRuleMatchSamples(t)
			t.Fatalf("idempotency run %d: %v", run, err)
		}
		t.Logf("idempotency run %d reached EVIDENCE.packages (full signal)", run)
	}
}
