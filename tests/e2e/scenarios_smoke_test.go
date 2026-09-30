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
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"gopkg.in/yaml.v3"

	"github.com/olokotoh/olaitan/internal/eval/attack"
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

// scenarioWorkloadName returns the per-scenario Deployment name in tenant-acme.
// Each scenario gets its OWN Deployment (Review Round 2, CI-caught): the
// correlator derives workloadID = `tenant-acme/Deployment/<name>` and keys its
// rising-edge `fired` flag on it (internal/correlator/window/window.go:171-185),
// so a distinct Deployment per scenario gives each scenario INDEPENDENT
// rising-edge state. This makes each scenario's first multi-signal convergence
// emit a fresh EvidencePackage regardless of rs_smoke (which uses `web`) or the
// sibling scenarios, instead of being suppressed by a `fired` flag the FIRST
// converger set on the shared `tenant-acme/Deployment/web` workload within the
// still-open 60s window. The OLT rules key on namespace + owner_kind, NOT the
// Deployment name, so every scenario's rule still matches under its own name.
func scenarioWorkloadName(scenarioID string) string {
	return "scenario-" + scenarioID
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

// realAttackScenarios are driven by the real in-cluster attack (Story 11.2a).
// S4 and S5 are not yet: they need attacker-side sink / pool infrastructure
// (Story 11.2b, #192) and still inject synthetic events.
var realAttackScenarios = map[string]bool{"s1": true, "s2": true, "s3": true}

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
// out the correlator window (see correlatorWindow).
var lastRealAttack = map[string]time.Time{}

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
	if last, ok := lastRealAttack[scenarioID]; ok {
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
	lastRealAttack[scenarioID] = time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := executor.Execute(ctx); err != nil {
		cleanup()
		t.Fatalf("scenario %s real attack: %v", scenarioID, err)
	}
	return before, cleanup
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
func injectScenario(t *testing.T, js jetstream.JetStream, scenarioID, podName, deployName string) scenarioCounterSnapshot {
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
	before := snapshotScenarioCounters(t, loadScenarioSmokeTarget(t, scenarioID))
	// S4 rests partly on a baseline deviation: pre-seed the per-workload
	// baseline so outbound_unique_dst_ips crosses 3 sigma and let the baseline
	// consumer drain BEFORE the rule-match flow events arrive (BI-4).
	if evalscenario.BaselinePreseed(scenarioID) {
		// The pre-seed Welford history MUST land on the SAME workload key the
		// scenario's rule-match/trigger packages use, so it carries the
		// scenario's own Deployment name (owner_name) rather than the rs_smoke
		// default `web` -- otherwise the primed baseline and the live deviation
		// would split across two keys and the deviation half would never fire.
		publishSyntheticEvidencePackagesFor(t, js, podName, deployName)
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
		redetected := ruleMatches >= 1 || deviations >= 1
		freshPackage := !requireFreshPackage || evidence >= 1
		if redetected && freshPackage {
			return nil
		}
		switch {
		case !redetected:
			lastErr = fmt.Errorf("no rule-match delta for %v and no baseline-deviation delta yet", tgt.TriggeringRules)
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

	// S4 and S5 each get their OWN synthetic Deployment in tenant-acme so the
	// correlator's rising-edge `fired` flag (keyed on workloadID =
	// tenant-acme/Deployment/<name>) is independent per scenario (Review
	// Round 2, CI-caught). They are created on the parent test so a finishing
	// subtest's namespace-teardown cleanup cannot delete a later subtest's
	// workload. S1-S3 apply their own real Story 11.1 target (tenant-acme/web)
	// through the executor and delete it again; each fires a different chart
	// Falco rule, so each opens its own investigation on that workload.
	scenarioIDs := []string{"s1", "s2", "s3", "s4", "s5"}
	pods := map[string]string{}
	for _, scenarioID := range scenarioIDs {
		if !realAttackScenarios[scenarioID] {
			pods[scenarioID] = applyScenarioWorkload(t, scenarioWorkloadName(scenarioID))
		}
	}

	js := connectScenarioJS(t)

	for _, scenarioID := range scenarioIDs {
		scenarioID := scenarioID
		t.Run(scenarioID, func(t *testing.T) {
			tgt := loadScenarioSmokeTarget(t, scenarioID)
			var before scenarioCounterSnapshot
			if realAttackScenarios[scenarioID] {
				var cleanup func()
				before, cleanup = runRealAttack(t, tgt)
				defer cleanup()
			} else {
				before = injectScenario(t, js, scenarioID, pods[scenarioID], scenarioWorkloadName(scenarioID))
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
