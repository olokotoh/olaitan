package schema

// AnalysisMode indicates whether the LLM was active during assessment.
type AnalysisMode string

const (
	ModeLLM       AnalysisMode = "llm"
	ModeRulesOnly AnalysisMode = "rules_only"
)

// ThreatContext is the input to the LLM analyst — everything it needs to reason about a potential threat.
type ThreatContext struct {
	Pod             PodRef              `json:"pod"`
	Events          []Event             `json:"events"`
	RuleMatches     []RuleMatch         `json:"rule_matches,omitempty"`
	Deviations      []BaselineDeviation `json:"deviations,omitempty"`
	CurrentState    PodSecurityState    `json:"current_state"`
	PodAge          string              `json:"pod_age,omitempty"`
	PriorAssessment *ThreatAssessment   `json:"prior_assessment,omitempty"`
}

// ThreatAssessmentSchemaVersion is the canonical schema_version of the
// SENIOR MODEL-FACING verdict (Story 3.7 BI-5), stamped by the Senior
// runner after validation. It versions the model response contract
// (docs/schemas/threat_assessment.json), not this persisted struct.
const ThreatAssessmentSchemaVersion = "threat_assessment.v1"

// ThreatAssessment is the output of the detection engine (rules + baselines + LLM).
//
// Story 3.7 added the four omitempty audit fields below (all zero on
// the pre-3.7 wire form, so existing payloads are byte-identical):
// NotedDisagreements (FR24 explicit L1-vs-L2 disagreement record),
// RawConfidence and LLMCappedConfidence (AC2: the Senior's raw model
// confidence and its min(raw, score_cap[senior_provider]) cap, both
// recorded for audit traceability), and AgentsAvailable (AC4: which
// sub-agents contributed; bounded values "l1", "l2", "senior").
// Confidence (the composite ConfidenceScore fold) and RecommendedState
// remain ZERO in Story 3.7: the score fold and the state derivation are
// Story 3.11/FSM scope.
type ThreatAssessment struct {
	ThreatType          string           `json:"threat_type"`
	Confidence          ConfidenceScore  `json:"confidence"`
	RecommendedState    PodSecurityState `json:"recommended_state"`
	Reasoning           string           `json:"reasoning"`
	MitreTechniques     []string         `json:"mitre_techniques,omitempty"`
	KillChainStage      string           `json:"kill_chain_stage,omitempty"`
	EvidenceToPreserve  []string         `json:"evidence_to_preserve,omitempty"`
	RequestedSubTasks   []string         `json:"requested_sub_tasks,omitempty"`
	Mode                AnalysisMode     `json:"mode"`
	NotedDisagreements  []string         `json:"noted_disagreements,omitempty"`
	RawConfidence       int              `json:"raw_confidence,omitempty"`
	LLMCappedConfidence int              `json:"llm_capped_confidence,omitempty"`
	AgentsAvailable     []string         `json:"agents_available,omitempty"`
	// LLMUnavailable records that the investigation chain could not obtain
	// a usable verdict for the boundary role after the Story 3.10 retry +
	// Ollama-fallback ladder exhausted (FR26/FR28): the role's
	// llm_capped_confidence is forced to 0 and the FSM proceeds on the
	// deterministic ThreatScore only. Additive omitempty: the pre-3.10 wire
	// form is byte-identical for the false zero value.
	LLMUnavailable bool `json:"llm_unavailable,omitempty"`
}
