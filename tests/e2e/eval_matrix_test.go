//go:build e2e

package e2e_test

import (
	"context"
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

	for _, sc := range scenarios {
		tgt := readScenarioTarget(t, scenariosRoot, sc)
		for run := 0; run < runs; run++ {
			runOneEvalTrial(t, js, capturer, evalTrial{
				config:      config,
				scenario:    sc,
				run:         run,
				target:      tgt,
				outRoot:     outRoot,
				manifestSHA: manifestSHA,
				evalVersion: evalVersion,
				ceiling:     ceiling,
			})
		}
	}
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
}

func runOneEvalTrial(t *testing.T, js jetstream.JetStream, capturer *capture.Capturer, tr evalTrial) {
	t.Helper()
	// Fresh workload identity per run: a unique pod name resolves (via the
	// correlator's NotFound fallback) to a unique workload_id with no prior
	// FSM state, so runs never contaminate one another.
	podName := fmt.Sprintf("web-%s-%s-r%02d", tr.config, tr.scenario, tr.run)
	deployName := podName

	// Clean the pipeline streams so the capturer drains ONLY this run.
	purgeEvalStreams(t, js)

	startedAt := time.Now().UTC()

	// S4 rests partly on a baseline deviation: pre-seed the per-workload
	// baseline (the rs_smoke 10-priming-plus-1-spike EvidencePackage pattern)
	// before the rule-match events, on THIS run's workload key.
	if evalscenario.BaselinePreseed(tr.scenario) || os.Getenv("OLT_EVAL_FORCE_PRESEED") != "" {
		publishSyntheticEvidencePackagesFor(t, js, podName, deployName)
		waitForBaselineConsumerDrained(t, js)
	}

	events := evalscenario.Events(tr.scenario, podName, startedAt)
	if len(events) == 0 {
		t.Fatalf("no recipe events for scenario %q", tr.scenario)
	}
	for _, ev := range events {
		publishJS(t, js, ev.Subject, ev.Payload)
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
		waitStream = "AUDIT_ASSESSMENTS"
	}
	waitForEvalSettle(t, js, waitStream, tr.ceiling)

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
	}
	writeEvalMetadata(t, runDir, meta)

	t.Logf("run %s: success=%v mttd=%d final=%s src=%s (ev=%d fsm=%d assess=%d)",
		runID, m.SuccessCriterionMet, m.MeasuredTimeToDetect, m.MeasuredFinalFSMState,
		m.FSMStateSource, res.Counts.Evidence, res.Counts.FSM, res.Counts.Assessments)
}

// purgeEvalStreams purges the pipeline streams so each run captures only its
// own messages. Streams absent for a given arm are skipped.
func purgeEvalStreams(t *testing.T, js jetstream.JetStream) {
	t.Helper()
	streams := []string{
		"EVENTS_RAW", "EVENTS", "EVIDENCE", "AUDIT_ASSESSMENTS",
		"AUDIT_TRANSITIONS", "THREATS", "INCIDENTS", "INVESTIGATIONS", "REPORTS",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, name := range streams {
		s, err := js.Stream(ctx, name)
		if err != nil {
			continue // stream not present for this arm
		}
		_ = s.Purge(ctx)
	}
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
