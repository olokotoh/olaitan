package fr55

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/olokotoh/olaitan/internal/schema"
)

// TestRun_BoundHolds is the BI-2 OFFLINE proof obligation that ships NOW:
// it drives the FULL harness with the fake provider returning the MAXIMAL
// raw confidence (100) on benign input and asserts the trust-bound holds
// deterministically in CI with NO cluster, for BOTH provider caps (Claude
// 35 -> 10.5, Ollama 25 -> 7.5, BI-6) and BOTH configs (RSL single-LLM,
// RSLT-full chain). A failing assertion here is a PRODUCTION DEFECT, not a
// test to weaken (BI-5).
func TestRun_BoundHolds(t *testing.T) {
	cases := []struct {
		name      string
		cfg       Config
		shape     ProviderShape
		scoreCap  int
		wantBound float64
	}{
		{"claude-rsl", ConfigRSL, ShapeClaude, 35, 10.5},
		{"claude-rslt-full", ConfigRSLTFull, ShapeClaude, 35, 10.5},
		{"ollama-rsl", ConfigRSL, ShapeOllama, 25, 7.5},
		{"ollama-rslt-full", ConfigRSLTFull, ShapeOllama, 25, 7.5},
	}
	const trials = 8
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Run(context.Background(), RunOptions{
				Config:        tc.cfg,
				ScoreCap:      tc.scoreCap,
				Trials:        trials,
				ProviderLabel: OfflineProviderLabel,
				Shape:         tc.shape,
			})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			sum := result.Summary

			if sum.NTrials != trials {
				t.Fatalf("NTrials = %d, want %d", sum.NTrials, trials)
			}
			if sum.Bound != tc.wantBound {
				t.Errorf("Bound = %v, want %v (LLMWeight * ScoreCap)", sum.Bound, tc.wantBound)
			}
			// AC4(i): ZERO trials past SUSPICIOUS.
			if sum.NPastSuspicious != 0 {
				t.Errorf("NPastSuspicious = %d, want 0 (no trial may transition past SUSPICIOUS)", sum.NPastSuspicious)
			}
			// AC4(ii) / AC6: max ThreatScore within the per-provider bound.
			if sum.MaxThreatScore > sum.Bound {
				t.Errorf("MaxThreatScore = %v exceeds bound %v", sum.MaxThreatScore, sum.Bound)
			}
			// AC4(iii) / BI-8: the ACTUAL registered cap-violation counter is 0.
			if sum.CapViolationTotal != 0 {
				t.Errorf("CapViolationTotal = %d, want 0", sum.CapViolationTotal)
			}
			if !sum.Holds() {
				t.Errorf("bound does not hold: %+v", sum)
			}

			// Every trial: the fake returned the maximal raw confidence, the
			// cap clamped it to ScoreCap, the score folded to the bound, and
			// the FSM state stayed at or below SUSPICIOUS.
			//
			// LOAD-BEARING-ASSERTION NOTE (Trust-Bound F2): the strict per-trial
			// EQUALITY checks below (LLMCappedConfidence == scoreCap, ThreatScore
			// == wantBound) are the toothy assertions that prove the cap is
			// actually doing the work. The NPastSuspicious == 0 count ALONE is
			// insufficient at raw=100: 0.3*100 = 30 lands in SUSPICIOUS, NOT past
			// it, so a broken cap (no clamp) could still show 0 past SUSPICIOUS
			// while the ThreatScore blew past the bound. The equality + the
			// MaxThreatScore <= bound check above compensate: they pin the score
			// to the EXACT capped value, so weakening the cap fails the test.
			for _, tr := range result.Trials {
				if tr.RawConfidence != MaxRawConfidence {
					t.Errorf("trial %d RawConfidence = %d, want %d", tr.TrialIndex, tr.RawConfidence, MaxRawConfidence)
				}
				if tr.LLMCappedConfidence != tc.scoreCap {
					t.Errorf("trial %d LLMCappedConfidence = %d, want cap %d", tr.TrialIndex, tr.LLMCappedConfidence, tc.scoreCap)
				}
				if tr.ThreatScore != tc.wantBound {
					t.Errorf("trial %d ThreatScore = %v, want %v", tr.TrialIndex, tr.ThreatScore, tc.wantBound)
				}
				if pastSuspicious(tr.FinalFSMState) {
					t.Errorf("trial %d FinalFSMState = %s is past SUSPICIOUS", tr.TrialIndex, tr.FinalFSMState)
				}
				if tr.FinalFSMState != schema.StateClean {
					t.Errorf("trial %d FinalFSMState = %s, want CLEAN (bound %v < SUSPICIOUS %v)", tr.TrialIndex, tr.FinalFSMState, tc.wantBound, SuspiciousThreshold)
				}
				if tr.Provider != OfflineProviderLabel {
					t.Errorf("trial %d Provider = %q, want %q (honest offline label, BI-2)", tr.TrialIndex, tr.Provider, OfflineProviderLabel)
				}
			}
		})
	}
}

// TestEmit_ShapeDistinguishesProviders is the Story 5.6 R2 regression guard
// for the offline emitter-collision defect: claude (cap 35) and ollama
// (cap 25) for the SAME config emit to DISTINCT run dirs, so emitting BOTH
// into ONE parent dir leaves BOTH artefact sets intact instead of the second
// silently overwriting the first. Before the shape was encoded in the dir
// name both wrote to fr55-offline-fake-<config> and collided (BI-2 honesty).
func TestEmit_ShapeDistinguishesProviders(t *testing.T) {
	const cfg = ConfigRSL
	claude, err := Run(context.Background(), RunOptions{
		Config: cfg, ScoreCap: 35, Trials: 4, ProviderLabel: OfflineProviderLabel, Shape: ShapeClaude,
	})
	if err != nil {
		t.Fatalf("Run claude: %v", err)
	}
	ollama, err := Run(context.Background(), RunOptions{
		Config: cfg, ScoreCap: 25, Trials: 4, ProviderLabel: OfflineProviderLabel, Shape: ShapeOllama,
	})
	if err != nil {
		t.Fatalf("Run ollama: %v", err)
	}

	claudeDir := RunDirName(claude.Summary)
	ollamaDir := RunDirName(ollama.Summary)
	if claudeDir == ollamaDir {
		t.Fatalf("collision: claude and ollama for config %q share run dir %q", cfg, claudeDir)
	}
	if claudeDir != "fr55-offline-fake-claude-rsl" {
		t.Errorf("claude run dir = %q, want fr55-offline-fake-claude-rsl", claudeDir)
	}
	if ollamaDir != "fr55-offline-fake-ollama-rsl" {
		t.Errorf("ollama run dir = %q, want fr55-offline-fake-ollama-rsl", ollamaDir)
	}

	// Emit BOTH into ONE parent dir: with the un-shaped name the second Emit
	// overwrote the first; with the shape both survive side by side.
	dir := t.TempDir()
	if err := Emit(dir, claude); err != nil {
		t.Fatalf("Emit claude: %v", err)
	}
	if err := Emit(dir, ollama); err != nil {
		t.Fatalf("Emit ollama: %v", err)
	}
	for _, name := range []string{claudeDir, ollamaDir} {
		if _, err := os.Stat(filepath.Join(dir, name, "trials.jsonl")); err != nil {
			t.Errorf("run dir %q did not survive co-emission (collision): %v", name, err)
		}
	}

	// The two artefact sets carry their distinct bounds (10.5 vs 7.5), proving
	// they are not the same bytes under two names.
	claudeMeta, err := os.ReadFile(filepath.Join(dir, claudeDir, "metadata.yaml"))
	if err != nil {
		t.Fatalf("read claude metadata: %v", err)
	}
	ollamaMeta, err := os.ReadFile(filepath.Join(dir, ollamaDir, "metadata.yaml"))
	if err != nil {
		t.Fatalf("read ollama metadata: %v", err)
	}
	if !strings.Contains(string(claudeMeta), "bound: 10.5") || !strings.Contains(string(claudeMeta), "shape: claude") {
		t.Errorf("claude metadata missing bound 10.5 / shape claude:\n%s", claudeMeta)
	}
	if !strings.Contains(string(ollamaMeta), "bound: 7.5") || !strings.Contains(string(ollamaMeta), "shape: ollama") {
		t.Errorf("ollama metadata missing bound 7.5 / shape ollama:\n%s", ollamaMeta)
	}
}

// TestRun_Deterministic proves two runs of the same options produce
// byte-identical trial records (BI-2): seeded generator + fake provider +
// no wall-clock in the records.
func TestRun_Deterministic(t *testing.T) {
	opts := RunOptions{Config: ConfigRSLTFull, ScoreCap: 35, Trials: 5, ProviderLabel: OfflineProviderLabel}
	a, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run a: %v", err)
	}
	b, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run b: %v", err)
	}
	aBytes, err := marshalTrials(a.Trials)
	if err != nil {
		t.Fatalf("marshal a: %v", err)
	}
	bBytes, err := marshalTrials(b.Trials)
	if err != nil {
		t.Fatalf("marshal b: %v", err)
	}
	if string(aBytes) != string(bBytes) {
		t.Errorf("trial records not byte-deterministic across two runs")
	}
}

// TestRun_RejectsBadConfig proves the harness rejects an unknown config
// rather than silently running the wrong chain.
func TestRun_RejectsBadConfig(t *testing.T) {
	if _, err := Run(context.Background(), RunOptions{Config: "f", ScoreCap: 35, Trials: 1}); err == nil {
		t.Fatal("expected error for unknown config")
	}
}

// TestEmit_StoryConsumerShape proves the emitter writes the EXACT artefact
// shape Story 5.5's io.load_run_set + build_fr55_rows consume (AC5, BI-7,
// OQ1): a runs/fr55/<provider>-<config>/ dir with a trials.jsonl
// (fr55.trial.v1 lines) and a metadata.yaml carrying the join keys
// (scenario: benign-adversarial, config, manifest_sha256) plus the
// bound-proof summary fields.
func TestEmit_StoryConsumerShape(t *testing.T) {
	result, err := Run(context.Background(), RunOptions{
		Config:        ConfigRSL,
		ScoreCap:      35,
		Trials:        4,
		ProviderLabel: OfflineProviderLabel,
		Shape:         ShapeClaude,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	dir := t.TempDir()
	if err := Emit(dir, result); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	runDir := filepath.Join(dir, "fr55-offline-fake-claude-rsl")
	if _, err := os.Stat(runDir); err != nil {
		t.Fatalf("run dir not created: %v", err)
	}

	// trials.jsonl: one fr55.trial.v1 line per trial.
	trialsRaw, err := os.ReadFile(filepath.Join(runDir, "trials.jsonl"))
	if err != nil {
		t.Fatalf("read trials.jsonl: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(trialsRaw), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("trials.jsonl has %d lines, want 4", len(lines))
	}
	for i, line := range lines {
		var tr Trial
		if err := json.Unmarshal([]byte(line), &tr); err != nil {
			t.Fatalf("line %d not valid json: %v", i, err)
		}
		if tr.SchemaVersion != TrialSchemaVersion {
			t.Errorf("line %d schema_version = %q, want %q", i, tr.SchemaVersion, TrialSchemaVersion)
		}
		if tr.TrialIndex != i {
			t.Errorf("line %d trial_index = %d, want %d (index order)", i, tr.TrialIndex, i)
		}
		if tr.Provider != OfflineProviderLabel {
			t.Errorf("line %d provider = %q, want %q", i, tr.Provider, OfflineProviderLabel)
		}
	}

	// Assert the raw JSON field names the Story-5.5 reader keys off are
	// present (snake_case), not just the Go struct round-trip.
	var firstLine map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &firstLine); err != nil {
		t.Fatalf("unmarshal first line to map: %v", err)
	}
	for _, key := range []string{
		"schema_version", "trial_index", "config", "provider",
		"raw_confidence", "llm_capped_confidence", "threat_score",
		"final_fsm_state", "cap_violation_total",
	} {
		if _, ok := firstLine[key]; !ok {
			t.Errorf("trials.jsonl line missing required key %q", key)
		}
	}

	// metadata.yaml: the join keys + the FR55 summary fields.
	metaRaw, err := os.ReadFile(filepath.Join(runDir, "metadata.yaml"))
	if err != nil {
		t.Fatalf("read metadata.yaml: %v", err)
	}
	meta := string(metaRaw)
	for _, want := range []string{
		"scenario: benign-adversarial",
		"config: rsl",
		"provider: fake",
		"shape: claude",
		"manifest_sha256: ",
		"n_trials: 4",
		"max_threat_score: 10.5",
		"n_past_suspicious: 0",
		"cap_violation_total: 0",
		"bound: 10.5",
		"bound_holds: true",
	} {
		if !strings.Contains(meta, want) {
			t.Errorf("metadata.yaml missing %q\n--- got ---\n%s", want, meta)
		}
	}
}

// TestEmit_Deterministic proves the emitted artefacts are byte-identical
// across two emissions of the same RunResult (BI-2): a fixed RunResult
// yields a fixed manifest hash and fixed bytes.
func TestEmit_Deterministic(t *testing.T) {
	result, err := Run(context.Background(), RunOptions{Config: ConfigRSLTFull, ScoreCap: 25, Trials: 6, ProviderLabel: OfflineProviderLabel, Shape: ShapeOllama})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	a, b := t.TempDir(), t.TempDir()
	if err := Emit(a, result); err != nil {
		t.Fatalf("Emit a: %v", err)
	}
	if err := Emit(b, result); err != nil {
		t.Fatalf("Emit b: %v", err)
	}
	name := "fr55-offline-fake-ollama-rslt-full"
	for _, f := range []string{"trials.jsonl", "metadata.yaml"} {
		aBytes, err := os.ReadFile(filepath.Join(a, name, f))
		if err != nil {
			t.Fatalf("read a/%s: %v", f, err)
		}
		bBytes, err := os.ReadFile(filepath.Join(b, name, f))
		if err != nil {
			t.Fatalf("read b/%s: %v", f, err)
		}
		if string(aBytes) != string(bBytes) {
			t.Errorf("%s not byte-deterministic across two emissions", f)
		}
	}
}
