package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/olokotoh/olaitan/internal/eval/capture"
	evalscenario "github.com/olokotoh/olaitan/internal/eval/scenario"
)

// Story 5.2 fills the FROZEN Scenario seam (runner.go) WITHOUT reshaping the
// interface or the Runner loop (the Story 5.1 PO-Ratification-1 freeze). It
// supplies the five MITRE-annotated S1-S5 harnesses under
// deploy/demo/scenarios/ and a factory that maps the short --scenario sN id
// to the matching descriptive-slug harness directory.

// scenarioSlugs maps the short --scenario id (validateScenario accepts
// s1..s5) to the architecture's descriptive directory slug under
// deploy/demo/scenarios/ (BI-1: the architecture names the same directories
// with self-documenting slugs; each is resolvable from the short id via this
// deterministic map). This is the ONE deviation from the verbatim epic
// `{s1..s5}` shorthand, surfaced in the PR body.
var scenarioSlugs = map[string]string{
	"s1": "s1-container-escape",
	"s2": "s2-credential-exfil",
	"s3": "s3-lateral-movement",
	"s4": "s4-c2-beaconing",
	"s5": "s5-cryptomining",
}

// defaultScenariosRoot is the committed harness root the factory resolves
// scenario directories under. It is relative to the repository root (the
// olaitan-eval binary is run from the repo root, the eval-smoke / scenarios
// -smoke precedent).
const defaultScenariosRoot = "deploy/demo/scenarios"

// validFSMStates is the set of target_fsm_state values target.yaml may
// declare. It mirrors the escalation-capable FSM states an attack scenario
// can target (internal/schema/state.go); CLEAN is excluded because no attack
// targets the clean baseline.
var validFSMStates = map[string]bool{
	"SUSPICIOUS":       true,
	"RESTRICTED":       true,
	"QUARANTINED":      true,
	"PRESERVED_KILLED": true,
}

// scenarioTarget is the machine-readable target.yaml contract Story 5.2 OWNS
// and Story 5.4's metadata writer CONSUMES (BI-2). It declares the target
// FSM state + time-to-detect the run's measured outcome is scored against.
type scenarioTarget struct {
	ScenarioID                string   `yaml:"scenario_id"`
	MitreTechnique            string   `yaml:"mitre_technique"`
	TargetFSMState            string   `yaml:"target_fsm_state"`
	TargetTimeToDetectSeconds int      `yaml:"target_time_to_detect_seconds"`
	Floor                     bool     `yaml:"floor"`
	TriggeringRules           []string `yaml:"triggering_rules"`
	// AttackSteps (Story 11.2a, AC3) maps each in-cluster primitive the
	// real attack runner executes to its MITRE ATT&CK for Containers ID(s).
	// It is additive and optional: the scalar MitreTechnique above stays the
	// Story 5.2 primary-technique contract the factory + goldens key on, and
	// AttackSteps records the full, cited mapping of what actually runs. Only
	// the S1-S3 harnesses carry it in Story 11.2a; S4/S5 add theirs in 11.2b.
	AttackSteps []attackStep `yaml:"attack_steps,omitempty"`
}

// attackStep is one MITRE-mapped primitive the attack runner executes
// (Story 11.2a, AC3). Every id in Mitre is a real ATT&CK for Containers
// technique/sub-technique, cited from the repo rule corpus or the ATT&CK for
// Containers matrix; none is invented.
type attackStep struct {
	ID        string   `yaml:"id"`
	Mitre     []string `yaml:"mitre"`
	Primitive string   `yaml:"primitive"`
}

// scenarioHarness is the rich Scenario impl Story 5.2 wires behind the frozen
// seam, one per S1-S5. It carries the resolved harness directory and the
// parsed target.yaml so the in-process Run can dispatch the matching harness
// honestly (BI-1, BI-2).
type scenarioHarness struct {
	id     string
	dir    string
	target scenarioTarget
	logger *slog.Logger
	// attackRun is the injectable kubectl shell-out the Story 11.2a attack
	// executor drives (threaded from run(); main wires the real
	// execAttackCmd, a unit test injects a recorder). A nil value defaults to
	// execAttackCmd inside newAttackExecutor.
	attackRun attackRunFunc
}

// newScenario is the scenario FACTORY (Story 5.2, Task 3.2). It maps the
// short --scenario id (s1..s5) to the matching descriptive-slug harness under
// scenariosRoot (BI-1), loads + validates that harness's target.yaml, and
// returns the rich Scenario impl. A nil scenarioSlugs entry, a missing
// harness directory, or an invalid target.yaml is a hard error so a
// mis-wired scenario fails loudly rather than silently no-opping (the BI-3
// "no silent no-op" discipline). scenariosRoot is a parameter so tests can
// point it at the committed tree from any working directory.
func newScenario(scenarioID, scenariosRoot string, attackRun attackRunFunc, logger *slog.Logger) (Scenario, error) {
	slug, ok := scenarioSlugs[scenarioID]
	if !ok {
		return nil, fmt.Errorf("scenario %q has no harness mapping (want one of %s)", scenarioID, knownScenarioIDs())
	}
	dir := filepath.Join(scenariosRoot, slug)
	target, err := loadScenarioTarget(filepath.Join(dir, "target.yaml"))
	if err != nil {
		return nil, fmt.Errorf("scenario %q (%s): %w", scenarioID, slug, err)
	}
	if target.ScenarioID != scenarioID {
		return nil, fmt.Errorf("scenario %q harness %s declares scenario_id %q; the id and the harness must agree", scenarioID, slug, target.ScenarioID)
	}
	// Defensively default a nil logger so the Scenario's Run cannot panic on
	// s.logger.Info even if a future caller passes nil (the Runner guards
	// r.Logger, but the Scenario carries its own logger).
	if logger == nil {
		logger = slog.Default()
	}
	return &scenarioHarness{id: scenarioID, dir: dir, target: target, logger: logger, attackRun: attackRun}, nil
}

// captureTarget projects the resolved scenarioTarget onto the
// capture.Target the Story-5.4 metadata measurement scores against (BI-9).
// 5.2 OWNS the declaration; 5.4 OWNS the measurement, so this is a read-only
// projection of the already-loaded, already-validated target. A scenario that
// is not the rich scenarioHarness (no resolved target) yields the zero Target,
// which the measurement treats as never-met.
func captureTarget(s Scenario) capture.Target {
	h, ok := s.(*scenarioHarness)
	if !ok {
		return capture.Target{}
	}
	return capture.Target{
		FSMState:            h.target.TargetFSMState,
		TimeToDetectSeconds: h.target.TargetTimeToDetectSeconds,
		Floor:               h.target.Floor,
	}
}

// knownScenarioIDs returns the sorted s1..s5 ids the factory maps, for error
// messages.
func knownScenarioIDs() string {
	ids := make([]string, 0, len(scenarioSlugs))
	for id := range scenarioSlugs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := ""
	for i, id := range ids {
		if i > 0 {
			out += ", "
		}
		out += id
	}
	return out
}

// loadScenarioTarget parses + validates a harness target.yaml (BI-2). It
// fails fast on a missing file or any required field that is empty / invalid
// so a malformed contract cannot reach Story 5.4's metadata writer.
func loadScenarioTarget(path string) (scenarioTarget, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return scenarioTarget{}, fmt.Errorf("read target.yaml %q: %w", path, err)
	}
	var t scenarioTarget
	if err := yaml.Unmarshal(raw, &t); err != nil {
		return scenarioTarget{}, fmt.Errorf("parse target.yaml %q: %w", path, err)
	}
	if t.ScenarioID == "" {
		return scenarioTarget{}, fmt.Errorf("target.yaml %q: scenario_id is required", path)
	}
	if t.MitreTechnique == "" {
		return scenarioTarget{}, fmt.Errorf("target.yaml %q: mitre_technique is required", path)
	}
	if !validFSMStates[t.TargetFSMState] {
		return scenarioTarget{}, fmt.Errorf("target.yaml %q: target_fsm_state %q is not a valid escalation state (want one of SUSPICIOUS, RESTRICTED, QUARANTINED, PRESERVED_KILLED)", path, t.TargetFSMState)
	}
	if t.TargetTimeToDetectSeconds <= 0 {
		return scenarioTarget{}, fmt.Errorf("target.yaml %q: target_time_to_detect_seconds must be > 0 (got %d)", path, t.TargetTimeToDetectSeconds)
	}
	if len(t.TriggeringRules) == 0 {
		return scenarioTarget{}, fmt.Errorf("target.yaml %q: triggering_rules must list at least one OLT rule id", path)
	}
	return t, nil
}

// Run drives the scenario harness's REAL in-cluster attack against the
// warmed cluster (Story 11.2a, replacing the Story 5.2 log-only Run and all
// synthetic NATS-event injection). It builds the per-scenario attack
// executor (attack.go), applies the Story 11.1 target, runs the technique
// primitive(s) via kubectl exec, and reverses the technique via a deferred
// Cleanup so teardown runs even when a primitive errors (AC2, the Runner-loop
// BI-2 discipline). The attack produces genuine syscalls Falco observes, so
// the signal flows through the real bus (Falco -> gRPC -> NATS -> correlator)
// and the Story 5.4 Capturer drains it; nothing is fabricated. S4/S5 need
// attacker-side sink / pool infrastructure and land in Story 11.2b (#192), so
// newAttackExecutor rejects them here with a loud error rather than a silent
// no-op.
func (s *scenarioHarness) Run(ctx context.Context) (err error) {
	executor, err := newAttackExecutor(s.id, s.dir, s.attackRun, s.logger)
	if err != nil {
		return err
	}
	s.logger.Info("scenario harness dispatched (real in-cluster attack)",
		"scenario", s.id,
		"harness_dir", s.dir,
		"mitre_technique", s.target.MitreTechnique,
		"target_fsm_state", s.target.TargetFSMState,
		"triggering_rules", s.target.TriggeringRules,
		"stimulus", "real attack executed in-cluster via kubectl exec (Story 11.2a)")

	// Cleanup is deferred so the technique is reversed even when a primitive
	// errors. A cleanup error is surfaced only when the attack otherwise
	// succeeded, so it never masks the real failure.
	defer func() {
		if cerr := executor.Cleanup(ctx); cerr != nil {
			if err == nil {
				err = fmt.Errorf("scenario %s cleanup: %w", s.id, cerr)
			} else {
				s.logger.Error("cleanup failed after an attack error", "cleanup_err", cerr, "attack_err", err)
			}
		}
	}()

	if err = executor.Execute(ctx); err != nil {
		return fmt.Errorf("scenario %s attack: %w", s.id, err)
	}
	return nil
}

// --- deterministic synthetic-event recipes (BI-3, AC7) -----------------
//
// The recipes themselves now live in the non-main package
// internal/eval/scenario so they are a TRUE single source of truth: both this
// binary AND the e2e kind injector (tests/e2e, which cannot import package
// main) import that package, so there is no hand-copy to drift against. The
// thin aliases below preserve cmd/olaitan-eval's local names + the unit-test
// call sites while delegating to the one real definition.

// The raw-event subjects the synthetic injection targets (the subjects the
// production Falco / CNI exporters publish to).
const (
	rawFalcoSubject   = evalscenario.RawFalcoSubject
	rawNetworkSubject = evalscenario.RawNetworkSubject
)

// scenarioEvent is one synthetic raw event in a scenario's deterministic
// stimulus. It aliases the shared recipe type so the recipes have one home.
type scenarioEvent = evalscenario.Event

// scenarioBaselinePreseed reports whether the scenario's AC8 detection rests
// (partly) on a baseline deviation that must be pre-seeded with the rs_smoke
// 10-priming-plus-1-spike EvidencePackage pattern (BI-4). Only S4 (C2
// beaconing) does; the others fire on a rule match alone.
func scenarioBaselinePreseed(scenarioID string) bool {
	return evalscenario.BaselinePreseed(scenarioID)
}

// scenarioEvents returns the ordered deterministic raw-event stimulus for a
// scenario (AC7), delegating to the shared single-source-of-truth recipe table.
func scenarioEvents(scenarioID, podName string, ts time.Time) []scenarioEvent {
	return evalscenario.Events(scenarioID, podName, ts)
}
