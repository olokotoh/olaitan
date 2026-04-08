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

// ThreatAssessment is the output of the detection engine (rules + baselines + LLM).
type ThreatAssessment struct {
	ThreatType        string           `json:"threat_type"`
	Confidence        ConfidenceScore  `json:"confidence"`
	RecommendedState  PodSecurityState `json:"recommended_state"`
	Reasoning         string           `json:"reasoning"`
	MitreTechniques   []string         `json:"mitre_techniques,omitempty"`
	KillChainStage    string           `json:"kill_chain_stage,omitempty"`
	EvidenceToPreserve []string        `json:"evidence_to_preserve,omitempty"`
	RequestedSubTasks []string         `json:"requested_sub_tasks,omitempty"`
	Mode              AnalysisMode     `json:"mode"`
}
