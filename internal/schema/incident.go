package schema

import "time"

// Incident ties together everything about a detected threat — events, assessment, transitions, and evidence.
type Incident struct {
	ID          string               `json:"id"`
	CreatedAt   time.Time            `json:"created_at"`
	Pod         PodRef               `json:"pod"`
	Events      []Event              `json:"events"`
	Assessment  ThreatAssessment     `json:"assessment"`
	Transitions []StateTransition    `json:"transitions"`
	Evidence    *ContainmentEvidence `json:"evidence,omitempty"`
}

// ContainmentEvidence contains forensic data captured during containment.
type ContainmentEvidence struct {
	IncidentID    string    `json:"incident_id"`
	CapturedAt    time.Time `json:"captured_at"`
	OverlayDiff   string    `json:"overlay_diff,omitempty"`
	PodSpec       string    `json:"pod_spec,omitempty"`
	ProcessList   string    `json:"process_list,omitempty"`
	NetworkConns  string    `json:"network_conns,omitempty"`
	PodEvents     string    `json:"pod_events,omitempty"`
	PodLogs       string    `json:"pod_logs,omitempty"`
	IntegrityHash string    `json:"integrity_hash,omitempty"`
}
