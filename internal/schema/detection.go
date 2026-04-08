package schema

// RuleMatch records when a Sigma-style rule matches an event.
type RuleMatch struct {
	RuleID    string   `json:"rule_id"`
	RuleName  string   `json:"rule_name"`
	Severity  string   `json:"severity"`
	MitreTags []string `json:"mitre_tags,omitempty"`
	EventID   string   `json:"event_id"`
}

// BaselineDeviation records when a metric deviates from a workload's baseline.
type BaselineDeviation struct {
	Metric string  `json:"metric"`
	Value  float64 `json:"value"`
	Mean   float64 `json:"mean"`
	StdDev float64 `json:"std_dev"`
	Sigma  float64 `json:"sigma"`
	PodUID string  `json:"pod_uid"`
}

// ConfidenceScore breaks down the weighted contributions to a threat score.
type ConfidenceScore struct {
	Total    float64 `json:"total"`
	Rules    float64 `json:"rules"`
	Baseline float64 `json:"baseline"`
	LLM      float64 `json:"llm"`
	LLMCap   float64 `json:"llm_cap"`
}
