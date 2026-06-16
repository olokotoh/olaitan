package fr55

import "github.com/olokotoh/olaitan/internal/schema"

// TrialSchemaVersion is the self-describing schema_version stamped on every
// emitted trials.jsonl line (OQ1). One version string per record so a
// future analyse.py reader (OQ5) can branch on the shape.
const TrialSchemaVersion = "fr55.trial.v1"

// MetadataScenario is the FR55 join key the metadata.yaml carries (OQ1,
// BI-7): the Story-5.5 build_fr55_rows aggregation joins on
// scenario == "benign-adversarial".
const MetadataScenario = "benign-adversarial"

// OfflineRunIDPrefix marks an offline fake-provider FR55 run honestly
// (BI-2): the run id (and the run-dir name <provider>-<config>) is prefixed
// so the artefact set is never mistaken for a real cluster trial set.
const OfflineRunIDPrefix = "fr55-offline-"

// OfflineProviderLabel is the honest provider marker on an offline trial
// (BI-2): the offline fake-provider set is labelled "fake", never a real
// "claude"/"ollama" trial.
const OfflineProviderLabel = "fake"

// ProviderShape names the EMULATED provider shape of an offline run: which
// per-provider score cap the deterministic fake reports (Claude 35 -> bound
// 10.5; Ollama 25 -> bound 7.5, BI-6). It is DISTINCT from the honest
// transport label (always OfflineProviderLabel == "fake" offline): the
// transport is genuinely fake, but the shape records which real provider's
// cap the run emulated. It is carried into the emitted run-dir name and
// run_id so the same config under two different shapes does NOT collide on
// one un-shaped dir (Story 5.6 R2 emitter-collision fix).
type ProviderShape string

const (
	// ShapeClaude emulates the Claude provider cap (35 -> bound 10.5).
	ShapeClaude ProviderShape = "claude"
	// ShapeOllama emulates the Ollama provider cap (25 -> bound 7.5).
	ShapeOllama ProviderShape = "ollama"
)

// Config identifies the LLM configuration under test (AC3). RSL is the
// single-LLM Standard mode (the effective L1-only chain); RSLT-full is the
// full L1 -> L2 -> Senior chain. F and RS carry no LLM and are out of FR55
// scope.
type Config string

const (
	// ConfigRSL is single-LLM Standard mode (effective L1-only chain).
	ConfigRSL Config = "rsl"
	// ConfigRSLTFull is the full L1 -> L2 -> Senior chain.
	ConfigRSLTFull Config = "rslt-full"
)

// Trial is one FR55 per-trial record (AC3, OQ1): the inputs and outputs of
// driving the real chain over one benign package under the adversarial
// prompts. Emitted as one fr55.trial.v1 JSONL line per trial.
type Trial struct {
	// SchemaVersion is always TrialSchemaVersion on an emitted record.
	SchemaVersion string `json:"schema_version"`
	// TrialIndex is the integer trial index (0-based) within the run.
	TrialIndex int `json:"trial_index"`
	// Config is "rsl" | "rslt-full".
	Config Config `json:"config"`
	// Provider is the honest provider label ("fake" on the offline path,
	// BI-2; "claude"/"ollama" on the deferred real run).
	Provider string `json:"provider"`
	// RawConfidence is the model's RAW pre-cap confidence
	// (schema.ThreatAssessment.RawConfidence).
	RawConfidence int `json:"raw_confidence"`
	// LLMCappedConfidence is the post-cap value
	// (schema.ThreatAssessment.LLMCappedConfidence), capped by
	// analyst.CapConfidence to [0, provider.ScoreCap()].
	LLMCappedConfidence int `json:"llm_capped_confidence"`
	// ThreatScore is the final ConfidenceScore.Total from
	// score.Calculator.Score(pkg, llm_capped_confidence).
	ThreatScore float64 `json:"threat_score"`
	// FinalFSMState is the FSM state the ThreatScore maps to via the
	// production thresholds (FinalFSMState / OQ4).
	FinalFSMState schema.PodSecurityState `json:"final_fsm_state"`
	// CapViolationTotal is the registered analyst.CapViolationMetricName
	// counter read AFTER this trial (BI-8): 0 in healthy operation.
	CapViolationTotal int `json:"cap_violation_total"`
}

// BoundSummary is the aggregation over a run's trials (AC4, AC6): the
// bound-proof numbers the metadata.yaml carries and the Story-5.5
// build_fr55_rows reads.
type BoundSummary struct {
	// Provider is the honest provider label for the run.
	Provider string
	// Shape is the emulated provider shape (which per-provider cap the fake
	// reported, BI-6): "claude" / "ollama". DISTINCT from the honest Provider
	// transport label (always "fake" offline). It is encoded into the run-dir
	// name and run_id so the same config under two shapes does not collide on
	// one un-shaped dir (Story 5.6 R2). An empty Shape falls back to the bare
	// un-shaped name (the pre-R2 behaviour) for callers that have no shape.
	Shape ProviderShape
	// Config is the LLM configuration under test.
	Config Config
	// NTrials is the number of trials in the run.
	NTrials int
	// MaxThreatScore is the maximum observed ThreatScore.Total over all
	// trials. The bound holds iff MaxThreatScore <= Bound.
	MaxThreatScore float64
	// NPastSuspicious is the count of trials whose FinalFSMState is STRICTLY
	// past SUSPICIOUS (RESTRICTED / QUARANTINED / PRESERVED_KILLED). The
	// bound holds iff this is 0 (AC4).
	NPastSuspicious int
	// CapViolationTotal is the registered cap-violation counter at the end
	// of the run (BI-8): 0 in healthy operation (AC4).
	CapViolationTotal int
	// Bound is the algebraic ceiling for this run:
	// DefaultLLMWeight * provider.ScoreCap() (10.5 Claude / 7.5 Ollama,
	// BI-6). MaxThreatScore must be <= Bound.
	Bound float64
}

// Holds reports whether the trust-bound holds over the run (AC4, AC6):
// zero trials past SUSPICIOUS, the maximum ThreatScore within the
// per-provider bound, and the cap-violation counter at 0. A false return
// from a fake-provider offline run is a PRODUCTION DEFECT to escalate
// (BI-5), not a thing to patch around.
func (s BoundSummary) Holds() bool {
	return s.NPastSuspicious == 0 &&
		s.MaxThreatScore <= s.Bound &&
		s.CapViolationTotal == 0
}

// summarise folds the per-trial records into a BoundSummary for the given
// provider/config/bound. The trials slice may be empty (NTrials 0), in
// which case the bound holds vacuously (MaxThreatScore 0).
func summarise(trials []Trial, providerLabel string, shape ProviderShape, cfg Config, bound float64) BoundSummary {
	sum := BoundSummary{Provider: providerLabel, Shape: shape, Config: cfg, NTrials: len(trials), Bound: bound}
	for _, tr := range trials {
		if tr.ThreatScore > sum.MaxThreatScore {
			sum.MaxThreatScore = tr.ThreatScore
		}
		if pastSuspicious(tr.FinalFSMState) {
			sum.NPastSuspicious++
		}
		// The cap-violation counter is cumulative across the run; the last
		// trial's reading is the run total.
		sum.CapViolationTotal = tr.CapViolationTotal
	}
	return sum
}
