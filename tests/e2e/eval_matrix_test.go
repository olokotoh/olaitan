//go:build e2e

package e2e_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"gopkg.in/yaml.v3"

	"github.com/olokotoh/olaitan/internal/eval/capture"
	evalscenario "github.com/olokotoh/olaitan/internal/eval/scenario"
	olnats "github.com/olokotoh/olaitan/internal/nats"
)

// TestEvalMatrix drives the thesis evaluation matrix for ONE already-deployed
// configuration arm: for each scenario in OLT_EVAL_SCENARIOS it fires the
// scenario's deterministic synthetic stimulus OLT_EVAL_RUNS times and captures
// the Story-5.4 six-artefact run dir + the measured metadata trio
// (success_criterion_met / measured_time_to_detect / measured_final_fsm_state)
// per run, so analysis/analyse.py can consume runs/<run_id>/ downstream.
//
// It is the batch inject->settle->capture->measure loop the standalone
// olaitan-eval binary leaves to the injector (its Scenario phase is a no-op;
// the injection is here, against the SAME shared recipe source of truth
// internal/eval/scenario). Gated on OLT_EVAL_MATRIX so normal e2e runs skip it.
//
// PER-RUN ISOLATION: each run uses a UNIQUE workload identity (pod name), so a
// never-seen workload_id has no prior FSM state anywhere (in-memory or redis),
// and the pipeline streams are purged before each inject, so the capturer
// drains ONLY the current run's messages. The arm itself is deployed once
// (externally, by the driver script) and reused across all its runs.
func TestEvalMatrix(t *testing.T) {
	if os.Getenv("OLT_EVAL_MATRIX") == "" {
		t.Skip("eval matrix skipped; set OLT_EVAL_MATRIX=1 to run")
	}
	config := mustEnv(t, "OLT_EVAL_CONFIG") // arm label recorded in metadata (f|rs|rsl|rslt-full)
	runs := envInt("OLT_EVAL_RUNS", 10)
	scenarios := envList("OLT_EVAL_SCENARIOS", "s1,s2,s3,s4,s5")
	// A zero-trial matrix must FAIL, not pass: OLT_EVAL_RUNS=0 or an empty
	// OLT_EVAL_SCENARIOS list would otherwise execute nothing, write nothing,
	// and report PASS, indistinguishable from a successful campaign (PR #92
	// review).
	if runs <= 0 {
		t.Fatalf("OLT_EVAL_RUNS must be positive, got %d", runs)
	}
	if len(scenarios) == 0 {
		t.Fatalf("OLT_EVAL_SCENARIOS resolved to an empty list")
	}
	outRoot := envStr("OLT_EVAL_OUT", "runs")
	manifestSHA := envStr("OLT_EVAL_MANIFEST_SHA", "")
	evalVersion := envStr("OLT_EVAL_VERSION", "eval-matrix")
	ceiling := envDur("OLT_EVAL_CEILING", 45*time.Second)
	scenariosRoot := envStr("OLT_EVAL_SCENARIOS_ROOT", "deploy/demo/scenarios")

	requireKindCluster(t)
	waitForPodsReady(t)
	waitForNATSReady(t)
	portForward(t, "svc/"+defaultReleaseName+"-nats", natsLocalPort, "4222")

	nc, err := nats.Connect("nats://localhost:" + natsLocalPort)
	if err != nil {
		t.Fatalf("NATS connect: %v", err)
	}
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatalf("JetStream: %v", err)
	}

	// The capturer drains the run's subjects through the importable
	// internal/eval/capture package (the same code olaitan-eval's richCapturer
	// uses), over its own internal/nats client on the port-forward.
	capClient, err := olnats.NewClient(olnats.ClientConfig{
		URL:  "nats://localhost:" + natsLocalPort,
		Name: "eval-matrix-capture",
	})
	if err != nil {
		t.Fatalf("capture NATS client: %v", err)
	}
	t.Cleanup(func() { _ = capClient.Close(context.Background()) })
	capturer := capture.New(capture.Config{Client: capClient})

	if err := os.MkdirAll(outRoot, 0o755); err != nil {
		t.Fatalf("mkdir out %q: %v", outRoot, err)
	}

	t.Logf("matrix: config=%s scenarios=%v runs=%d ceiling=%s", config, scenarios, runs, ceiling)
	for _, sc := range scenarios {
		// The benign sweep (Story 7.3) has no attack target file and its own
		// observation flow; the attack scenarios read their target.yaml.
		var tgt evalScenarioTarget
		if sc != evalscenario.BenignScenarioID {
			tgt = readScenarioTarget(t, scenariosRoot, sc)
		}
		for run := 0; run < runs; run++ {
			tr := evalTrial{
				config:      config,
				scenario:    sc,
				run:         run,
				target:      tgt,
				outRoot:     outRoot,
				manifestSHA: manifestSHA,
				evalVersion: evalVersion,
				ceiling:     ceiling,
			}
			// One subtest per trial: a single failed capture/size/metadata
			// write fails THAT trial and the matrix continues, instead of a
			// t.Fatalf aborting every remaining scenario and run (PR #92
			// review). A failed subtest still fails the overall test.
			t.Run(fmt.Sprintf("%s-%s-r%02d", config, sc, run), func(t *testing.T) {
				if tr.scenario == evalscenario.BenignScenarioID {
					runOneBenignSweep(t, js, capturer, tr)
					return
				}
				runOneEvalTrial(t, js, capturer, tr)
			})
		}
	}
}

// runOneBenignSweep runs one benign false-positive observation (Story 7.3): it
// primes the workload's baseline, then injects the benign event stream at a
// steady rate for OLT_EVAL_BENIGN_MINUTES of real time, capturing every FSM
// transition. Zero transitions is the good (and expected) result; the analysis
// pipeline reads escalations-past-CLEAN over the wall window as the FPR. The
// injected-event count is recorded so a zero-escalation run is distinguishable
// from a broken (no-injection) one.
func runOneBenignSweep(t *testing.T, js jetstream.JetStream, capturer *capture.Capturer, tr evalTrial) {
	t.Helper()
	podName := fmt.Sprintf("web-%s-benign-r%02d", tr.config, tr.run)
	deployName := podName
	if os.Getenv("OLT_EVAL_REAL_WORKLOAD") != "" {
		podName = applyScenarioWorkload(t, deployName)
	}

	waitForPipelineQuiescent(t, js, 90*time.Second)
	purgeEvalStreams(t, js)

	// Prime the baseline so a benign observation is judged against an
	// established profile (else warm-up would suppress deviations anyway, but
	// priming makes the sweep test the STEADY-STATE FPR).
	publishSyntheticEvidencePackagesFor(t, js, podName, deployName)
	waitForBaselineConsumerDrained(t, js)
	waitForPipelineQuiescent(t, js, 60*time.Second)
	purgeEvalStreams(t, js)

	minutes := envInt("OLT_EVAL_BENIGN_MINUTES", 10)
	if minutes <= 0 {
		t.Fatalf("OLT_EVAL_BENIGN_MINUTES must be positive, got %d", minutes)
	}
	ratePerMin := envInt("OLT_EVAL_BENIGN_RATE_PER_MIN", 30)
	if ratePerMin <= 0 {
		t.Fatalf("OLT_EVAL_BENIGN_RATE_PER_MIN must be positive, got %d", ratePerMin)
	}
	interval := time.Minute / time.Duration(ratePerMin)

	startedAt := time.Now().UTC()
	window := time.Duration(minutes) * time.Minute
	deadline := time.Now().Add(window)
	injected := 0
	for tick := 0; time.Now().Before(deadline); tick++ {
		for _, ev := range evalscenario.BenignEvents(podName, time.Now(), tick) {
			publishJS(t, js, ev.Subject, ev.Payload)
			injected++
		}
		select {
		case <-time.After(interval):
		case <-time.After(time.Until(deadline)):
		}
	}
	// Let the last events settle through the pipeline before capture. Trailing
	// benign escalations (if any) land during this settle window, so the FPR
	// observation window MUST include it; it MUST NOT include the subsequent
	// capture-drain dead time, during which nothing is injected and no
	// escalation can newly fire. Anchor finished_at here, before Capture, so
	// the FPR denominator (finished_at - started_at) is the true observation
	// window and the rate is not biased downward (PR #93 review).
	waitForPipelineQuiescent(t, js, 60*time.Second)
	finishedAt := time.Now().UTC()

	runID := fmt.Sprintf("%s-%s-benign-r%02d",
		startedAt.Format("20060102T150405.000Z"), tr.config, tr.run)
	runDir := filepath.Join(tr.outRoot, runID)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	res, err := capturer.Capture(ctx, runDir)
	cancel()
	if err != nil {
		t.Fatalf("capture benign %s: %v", runID, err)
	}
	sz, err := capture.CheckSize(runDir, capture.DefaultMaxRunSizeBytes)
	if err != nil {
		t.Fatalf("size check %s: %v", runID, err)
	}

	meta := evalRunMetadata{
		RunID:                runID,
		ManifestSHA256:       tr.manifestSHA,
		Scenario:             evalscenario.BenignScenarioID,
		Config:               tr.config,
		Runs:                 1,
		StartedAt:            startedAt.Format(time.RFC3339Nano),
		FinishedAt:           finishedAt.Format(time.RFC3339Nano),
		OlaitanEvalVersion:   tr.evalVersion,
		ScenarioInstance:     tr.run,
		ResourceUsage:        capture.SnapshotResourceUsage(),
		SizeBytes:            sz.SizeBytes,
		SizeCapExceeded:      sz.SizeCapExceeded,
		RiskWindowSeconds:    envInt("OLT_RISK_WINDOW_SECONDS", 0),
		RealWorkload:         os.Getenv("OLT_EVAL_REAL_WORKLOAD") != "",
		PreseedDirectPublish: true,
		BenignSweep:          true,
		BenignMinutes:        minutes,
		BenignRatePerMin:     ratePerMin,
		BenignInjectedEvents: injected,
	}
	writeEvalMetadata(t, runDir, meta)
	t.Logf("benign sweep %s: injected=%d fsm_transitions=%d over %dm", runID, injected, res.Counts.FSM, minutes)
}

type evalScenarioTarget struct {
	ScenarioID          string `yaml:"scenario_id"`
	TargetFSMState      string `yaml:"target_fsm_state"`
	TargetTimeToDetectS int    `yaml:"target_time_to_detect_seconds"`
	Floor               bool   `yaml:"floor"`
	MitreTechnique      string `yaml:"mitre_technique"`
}

type evalTrial struct {
	config      string
	scenario    string
	run         int
	target      evalScenarioTarget
	outRoot     string
	manifestSHA string
	evalVersion string
	ceiling     time.Duration
}

// evalRunMetadata mirrors the Story-5.4 metadata.yaml schema analyse.py reads.
type evalRunMetadata struct {
	RunID                 string                `yaml:"run_id"`
	ManifestSHA256        string                `yaml:"manifest_sha256"`
	Scenario              string                `yaml:"scenario"`
	Config                string                `yaml:"config"`
	Runs                  int                   `yaml:"runs"`
	StartedAt             string                `yaml:"started_at"`
	FinishedAt            string                `yaml:"finished_at"`
	OlaitanEvalVersion    string                `yaml:"olaitan_eval_version"`
	SuccessCriterionMet   bool                  `yaml:"success_criterion_met"`
	MeasuredTimeToDetect  int                   `yaml:"measured_time_to_detect"`
	MeasuredFinalFSMState string                `yaml:"measured_final_fsm_state"`
	FSMStateSource        string                `yaml:"fsm_state_source"`
	ScenarioInstance      int                   `yaml:"scenario_instance"`
	ResourceUsage         capture.ResourceUsage `yaml:"resource_usage"`
	SizeBytes             int64                 `yaml:"size_bytes"`
	SizeCapExceeded       bool                  `yaml:"size_cap_exceeded"`
	// Harness-configuration provenance (PR #92 review): without these fields a
	// captured run cannot be distinguished from a run under different harness
	// flags, yet the reported numbers depend on them.
	RiskWindowSeconds    int  `yaml:"risk_window_seconds"`
	RealWorkload         bool `yaml:"real_workload"`
	ForcePreseed         bool `yaml:"force_preseed"`
	StrongStimulus       bool `yaml:"strong_stimulus"`
	WaitAssess           bool `yaml:"wait_assess"`
	PreseedDirectPublish bool `yaml:"preseed_direct_publish"`
	PreseedTransitions   int  `yaml:"preseed_transitions"`
	Staged               bool `yaml:"staged"`
	// Benign false-positive sweep (Story 7.3).
	BenignSweep          bool `yaml:"benign_sweep,omitempty"`
	BenignMinutes        int  `yaml:"benign_minutes,omitempty"`
	BenignRatePerMin     int  `yaml:"benign_rate_per_min,omitempty"`
	BenignInjectedEvents int  `yaml:"benign_injected_events,omitempty"`
}

func runOneEvalTrial(t *testing.T, js jetstream.JetStream, capturer *capture.Capturer, tr evalTrial) {
	t.Helper()
	// Fresh workload identity per run: a unique pod name resolves (via the
	// correlator's NotFound fallback) to a unique workload_id with no prior
	// FSM state, so runs never contaminate one another.
	podName := fmt.Sprintf("web-%s-%s-r%02d", tr.config, tr.scenario, tr.run)
	deployName := podName
	if os.Getenv("OLT_EVAL_REAL_WORKLOAD") != "" {
		// Create a REAL Deployment-owned pod so the rule's falco event resolves
		// (via the correlator) to tenant-acme/Deployment/<deployName>, the SAME
		// key the preseed baseline uses. Without a real pod the rule falls back
		// to a tenant-acme/Pod/<name> key while the preseed baseline sits on the
		// Deployment key, so the two signals never co-locate and the risk window
		// has nothing to sum. applyScenarioWorkload returns the actual pod name.
		podName = applyScenarioWorkload(t, deployName)
	}

	// Wait for the previous trial's in-flight pipeline work (including a slow
	// inline LLM chain run) to finish BEFORE purging: a package still inside
	// the FSM consumer at purge time would publish its transition/assessment
	// AFTER the purge and be attributed to this run (PR #92 review).
	waitForPipelineQuiescent(t, js, 90*time.Second)

	// Clean the pipeline streams so the capturer drains ONLY this run.
	purgeEvalStreams(t, js)

	// S4 rests partly on a baseline deviation: pre-seed the per-workload
	// baseline (the rs_smoke 10-priming-plus-1-spike EvidencePackage pattern)
	// before the rule-match events, on THIS run's workload key.
	//
	// HONESTY NOTE (PR #92 review): the preseed publishes EvidencePackages
	// directly to the evidence subject with a hand-built workload key; it
	// primes the baseline engine but does not traverse the correlator's
	// identity resolution. This is recorded in metadata.yaml as
	// preseed_direct_publish so analysis can see it.
	preseeded := evalscenario.BaselinePreseed(tr.scenario) || os.Getenv("OLT_EVAL_FORCE_PRESEED") != ""
	preseedTransitions := 0
	if preseeded {
		publishSyntheticEvidencePackagesFor(t, js, podName, deployName)
		waitForBaselineConsumerDrained(t, js)
		// The preseed's spike package can itself fire a live deviation and an
		// FSM transition during SETUP. Drain the pipeline, RECORD whether the
		// harness itself escalated the workload (the FSM state in Redis is
		// per-workload and survives the purge, so a preseed-escalated run
		// starts non-CLEAN; metadata carries the count so analysis can see
		// it), then re-purge the measurement streams so the settle wait and
		// the capture see only scenario-driven signals, and startedAt (below)
		// measures the scenario, not the harness (PR #92 review:
		// measured_time_to_detect otherwise measured the preseed artefact).
		waitForPipelineQuiescent(t, js, 60*time.Second)
		preseedTransitions = streamMsgCount(t, js, "AUDIT_TRANSITIONS")
		purgeEvalStreams(t, js)
	}

	staged := os.Getenv("OLT_EVAL_STAGED") != ""
	// ONE anchor for both re-stamping and scheduling (PR #93 Copilot review):
	// events are stamped at anchor+offset AND published at anchor+offset, and
	// startedAt (the measurement base) is anchor, so the embedded timestamps,
	// the schedule, and the MTTD base cannot drift apart. anchor keeps its
	// monotonic reading for the schedule waits; startedAt is its wall-clock
	// form for the recipe and metadata.
	anchor := time.Now()
	startedAt := anchor.UTC()

	if staged {
		// Staged injection (Story 7.2): publish each event at its per-run
		// offset so the stimulus unfolds over the attack's real temporal shape
		// and measured_time_to_detect is a non-degenerate latency. Each event's
		// embedded timestamp is re-stamped to anchor+offset by StagedEvents so
		// it is not evicted as stale by the correlator's 60s window (PR #93
		// review); measurement still derives solely from captured timestamps.
		sev := evalscenario.StagedEvents(tr.scenario, podName, startedAt, tr.run)
		if len(sev) == 0 {
			t.Fatalf("no staged recipe events for scenario %q", tr.scenario)
		}
		for _, ev := range sev {
			// Sleep until this event's scheduled instant, anchored to the SAME
			// base used for the embedded timestamps. A slow machine can slip
			// the schedule; that is fine (measurement is from captured
			// timestamps, and the effective settle ceiling below absorbs it).
			if d := time.Until(anchor.Add(ev.Offset)); d > 0 {
				time.Sleep(d)
			}
			publishJS(t, js, ev.Subject, ev.Payload)
		}
	} else {
		events := evalscenario.Events(tr.scenario, podName, startedAt)
		if len(events) == 0 {
			t.Fatalf("no recipe events for scenario %q", tr.scenario)
		}
		for _, ev := range events {
			publishJS(t, js, ev.Subject, ev.Payload)
		}
	}
	// OLT_EVAL_STRONG (option-2 prototype): co-inject anomalous distinct-IP
	// network flows into the SAME correlator window as the rule-match event,
	// so the assembled EvidencePackage carries BOTH the rule match AND a
	// >=3sigma baseline deviation. This models a SUSTAINED attack (a real
	// intrusion both trips a rule and behaves anomalously) rather than a
	// single deterministic event, letting the ThreatScore sum the rule +
	// baseline terms and cross the RESTRICTED/QUARANTINED thresholds.
	if os.Getenv("OLT_EVAL_STRONG") != "" {
		stamp := startedAt.Format(time.RFC3339Nano)
		for i := 0; i < 14; i++ {
			ip := fmt.Sprintf("203.0.113.%d", 20+i) // distinct non-RFC1918 dsts
			payload := fmt.Sprintf(`{"id":"strong-%s-%d","timestamp":%q,"source":"network","category":"flow","raw":{"dst_ip":%q,"network.dst_ip":%q,"network.bytes_out":"4096"},"pod":{"name":%q,"namespace":"tenant-acme","uid":"strong-uid"}}`,
				tr.scenario, i, stamp, ip, ip, podName)
			publishJS(t, js, evalscenario.RawNetworkSubject, []byte(payload))
		}
	}

	// Settle: wait for the pipeline (correlator -> rules/baseline -> [L1/L2/
	// Senior for the LLM arms] -> FSM) to publish its terminal signal, up to
	// the ceiling. Because the streams were purged, ANY transition now belongs
	// to this run. We wait for a transition (the terminal FSM signal) and fall
	// through on the ceiling so an at-or-below-threshold run is still captured
	// (recorded honestly as a detection-signal-only or clean run).
	// For LLM arms the terminal signal is the (slow, ~tens of seconds)
	// AUDIT.assessments verdict, which lands well after the fast rule-only
	// FSM transition; waiting on AUDIT_TRANSITIONS alone would capture before
	// the assessment and leave assessments.jsonl empty (the kappa needs it).
	// OLT_EVAL_WAIT_ASSESS makes the settle wait on the assessment instead.
	waitStream := "AUDIT_TRANSITIONS"
	if os.Getenv("OLT_EVAL_WAIT_ASSESS") != "" {
		if armHasLLM(tr.config) {
			waitStream = "AUDIT_ASSESSMENTS"
		} else {
			// A non-LLM arm never publishes assessments, so waiting on them
			// would silently burn the full ceiling on every trial (PR #92
			// review). Fall back to the transition wait and say so.
			t.Logf("OLT_EVAL_WAIT_ASSESS ignored for non-LLM arm %q; waiting on AUDIT_TRANSITIONS", tr.config)
		}
	}
	// Effective ceiling accounts for the staged injection span (AC5): a staged
	// s4 run spreads events over ~100s, so a ceiling calibrated for
	// instantaneous injection would truncate it.
	effectiveCeiling := tr.ceiling
	if staged {
		// Include the jitter margin: an event's jittered offset can exceed the
		// nominal StaggerSpan by up to MaxStagedJitter, so widen the settle
		// ceiling by that margin too or a late-scheduled event could truncate
		// the wait (PR #93 Copilot review).
		effectiveCeiling = tr.ceiling + evalscenario.StaggerSpan(tr.scenario) + evalscenario.MaxStagedJitter
	}
	waitForEvalSettle(t, js, waitStream, effectiveCeiling)

	runID := fmt.Sprintf("%s-%s-%s-r%02d",
		startedAt.Format("20060102T150405.000Z"), tr.config, tr.scenario, tr.run)
	runDir := filepath.Join(tr.outRoot, runID)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	res, err := capturer.Capture(ctx, runDir)
	cancel()
	if err != nil {
		t.Fatalf("capture run %s: %v", runID, err)
	}

	m := capture.Measure(res.Transitions, res.Evidence, capture.Target{
		FSMState:            tr.target.TargetFSMState,
		TimeToDetectSeconds: tr.target.TargetTimeToDetectS,
		Floor:               tr.target.Floor,
	}, startedAt)

	sz, err := capture.CheckSize(runDir, capture.DefaultMaxRunSizeBytes)
	if err != nil {
		t.Fatalf("size check %s: %v", runID, err)
	}

	meta := evalRunMetadata{
		RunID:                 runID,
		ManifestSHA256:        tr.manifestSHA,
		Scenario:              tr.scenario,
		Config:                tr.config,
		Runs:                  1,
		StartedAt:             startedAt.Format(time.RFC3339Nano),
		FinishedAt:            time.Now().UTC().Format(time.RFC3339Nano),
		OlaitanEvalVersion:    tr.evalVersion,
		SuccessCriterionMet:   m.SuccessCriterionMet,
		MeasuredTimeToDetect:  m.MeasuredTimeToDetect,
		MeasuredFinalFSMState: m.MeasuredFinalFSMState,
		FSMStateSource:        m.FSMStateSource,
		ScenarioInstance:      tr.run,
		ResourceUsage:         capture.SnapshotResourceUsage(),
		SizeBytes:             sz.SizeBytes,
		SizeCapExceeded:       sz.SizeCapExceeded,
		RiskWindowSeconds:     envInt("OLT_RISK_WINDOW_SECONDS", 0),
		RealWorkload:          os.Getenv("OLT_EVAL_REAL_WORKLOAD") != "",
		ForcePreseed:          os.Getenv("OLT_EVAL_FORCE_PRESEED") != "",
		StrongStimulus:        os.Getenv("OLT_EVAL_STRONG") != "",
		WaitAssess:            os.Getenv("OLT_EVAL_WAIT_ASSESS") != "",
		PreseedDirectPublish:  preseeded,
		PreseedTransitions:    preseedTransitions,
		Staged:                staged,
	}
	writeEvalMetadata(t, runDir, meta)

	t.Logf("run %s: success=%v mttd=%d final=%s src=%s (ev=%d fsm=%d assess=%d)",
		runID, m.SuccessCriterionMet, m.MeasuredTimeToDetect, m.MeasuredFinalFSMState,
		m.FSMStateSource, res.Counts.Evidence, res.Counts.FSM, res.Counts.Assessments)
}

// purgeEvalStreams purges the pipeline streams so each run captures only its
// own messages. Streams genuinely absent for a given arm are skipped; ANY
// other error (a transient NATS hiccup, a timed-out context, a failed purge)
// fails the trial loudly, because a silently-unpurged stream breaks the
// per-run isolation guarantee and attributes the previous run's messages to
// this one (PR #92 review).
func purgeEvalStreams(t *testing.T, js jetstream.JetStream) {
	t.Helper()
	streams := []string{
		"EVENTS_RAW", "EVENTS", "EVIDENCE", "AUDIT_ASSESSMENTS",
		"AUDIT_TRANSITIONS", "THREATS", "INCIDENTS", "INVESTIGATIONS", "REPORTS",
	}
	for _, name := range streams {
		// Per-stream context so one slow stream cannot starve the rest of the
		// shared budget into spurious deadline errors.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		s, err := js.Stream(ctx, name)
		if err != nil {
			cancel()
			if errors.Is(err, jetstream.ErrStreamNotFound) {
				continue // genuinely not provisioned for this arm
			}
			t.Fatalf("purge: stream %s lookup failed (isolation cannot be guaranteed): %v", name, err)
		}
		if perr := s.Purge(ctx); perr != nil {
			cancel()
			t.Fatalf("purge: stream %s purge failed (isolation cannot be guaranteed): %v", name, perr)
		}
		cancel()
	}
}

// armHasLLM reports whether the arm label runs the investigation chain (rsl,
// rslt-full, rslt-l1-only, rslt-l1-l2). f and rs are deterministic-only.
func armHasLLM(config string) bool {
	return strings.HasPrefix(config, "rsl")
}

// streamMsgCount returns the stream's current message count, or 0 when the
// stream is absent.
func streamMsgCount(t *testing.T, js jetstream.JetStream, name string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := js.Stream(ctx, name)
	if err != nil {
		return 0
	}
	info, err := s.Info(ctx)
	if err != nil {
		return 0
	}
	return int(info.State.Msgs)
}

// waitForPipelineQuiescent waits until the FSM consumer (which runs the
// investigation chain INLINE, so an in-flight LLM call shows as an
// unacknowledged message) has no pending and no ack-pending messages on the
// EVIDENCE stream, or the bound elapses. Called before each purge so work
// still in flight from the previous trial cannot publish after the purge and
// contaminate the next trial's capture (PR #92 review).
func waitForPipelineQuiescent(t *testing.T, js jetstream.JetStream, bound time.Duration) {
	t.Helper()
	deadline := time.Now().Add(bound)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		s, err := js.Stream(ctx, "EVIDENCE")
		if err != nil {
			cancel()
			return // no evidence stream, nothing to drain
		}
		c, err := s.Consumer(ctx, "olaitan-response-fsm")
		if err != nil {
			cancel()
			return // consumer not provisioned (arm without the FSM consumer)
		}
		info, err := c.Info(ctx)
		cancel()
		if err == nil && info.NumPending == 0 && info.NumAckPending == 0 {
			return
		}
		time.Sleep(time.Second)
	}
	t.Logf("pipeline still busy after %s; proceeding (cross-run bleed possible)", bound)
}

// waitForEvalSettle polls until an FSM transition has been published (the
// terminal detection signal) or the ceiling elapses. Streams are per-run
// purged, so a non-empty AUDIT_TRANSITIONS means THIS run escalated.
func waitForEvalSettle(t *testing.T, js jetstream.JetStream, stream string, ceiling time.Duration) {
	t.Helper()
	deadline := time.Now().Add(ceiling)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		s, err := js.Stream(ctx, stream)
		if err == nil {
			info, ierr := s.Info(ctx)
			if ierr == nil && info.State.Msgs > 0 {
				cancel()
				// Small grace so a late second transition (de-escalation or a
				// higher state) also lands before capture.
				time.Sleep(2 * time.Second)
				return
			}
		}
		cancel()
		time.Sleep(1 * time.Second)
	}
}

func readScenarioTarget(t *testing.T, root, scenario string) evalScenarioTarget {
	t.Helper()
	// scenario dirs are sN-<slug>; find the one whose target.yaml scenario_id matches.
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read scenarios root %q: %v", root, err)
	}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), scenario+"-") {
			continue
		}
		path := filepath.Join(root, e.Name(), "target.yaml")
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			t.Fatalf("read %q: %v", path, rerr)
		}
		var tgt evalScenarioTarget
		if uerr := yaml.Unmarshal(raw, &tgt); uerr != nil {
			t.Fatalf("parse %q: %v", path, uerr)
		}
		if tgt.ScenarioID != scenario {
			t.Fatalf("%q: scenario_id %q != %q", path, tgt.ScenarioID, scenario)
		}
		return tgt
	}
	t.Fatalf("no scenario dir for %q under %q", scenario, root)
	return evalScenarioTarget{}
}

func writeEvalMetadata(t *testing.T, runDir string, meta evalRunMetadata) {
	t.Helper()
	out, err := yaml.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal metadata: %v", err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "metadata.yaml"), out, 0o644); err != nil {
		t.Fatalf("write metadata: %v", err)
	}
}

func mustEnv(t *testing.T, key string) string {
	t.Helper()
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		t.Fatalf("%s is required", key)
	}
	return v
}

func envStr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envDur(key string, def time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func envList(key, def string) []string {
	raw := envStr(key, def)
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
