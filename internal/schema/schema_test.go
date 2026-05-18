package schema

import (
	"encoding/json"
	"testing"
	"time"
)

func TestEventRoundTrip(t *testing.T) {
	original := Event{
		ID:        "01961234-5678-7abc-def0-123456789abc",
		Timestamp: time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC),
		Source:    SourceFalco,
		Pod: PodRef{
			Name:      "nginx-abc123",
			Namespace: "default",
			Node:      "worker-1",
			UID:       "pod-uid-001",
		},
		Severity: "high",
		Category: CategorySyscall,
		Summary:  "unexpected execve from nginx container",
		Raw:      json.RawMessage(`{"output":"test"}`),
		Tags:     []string{"T1059", "execution"},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Event
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.ID != original.ID {
		t.Errorf("ID: got %q, want %q", decoded.ID, original.ID)
	}
	if decoded.Source != original.Source {
		t.Errorf("Source: got %q, want %q", decoded.Source, original.Source)
	}
	if decoded.Pod.Name != original.Pod.Name {
		t.Errorf("Pod.Name: got %q, want %q", decoded.Pod.Name, original.Pod.Name)
	}
	if decoded.Category != original.Category {
		t.Errorf("Category: got %q, want %q", decoded.Category, original.Category)
	}
	if len(decoded.Tags) != len(original.Tags) {
		t.Errorf("Tags length: got %d, want %d", len(decoded.Tags), len(original.Tags))
	}
}

func TestThreatAssessmentRoundTrip(t *testing.T) {
	original := ThreatAssessment{
		ThreatType: "container_escape",
		Confidence: ConfidenceScore{
			Total:    72.5,
			Rules:    30,
			Baseline: 15,
			LLM:      27.5,
			LLMCap:   35,
		},
		RecommendedState: StateRestricted,
		Reasoning:        "Multiple indicators suggest container escape attempt",
		MitreTechniques:  []string{"T1611", "T1059.004"},
		KillChainStage:   "exploitation",
		Mode:             ModeLLM,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded ThreatAssessment
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.ThreatType != original.ThreatType {
		t.Errorf("ThreatType: got %q, want %q", decoded.ThreatType, original.ThreatType)
	}
	if decoded.Confidence.Total != original.Confidence.Total {
		t.Errorf("Confidence.Total: got %v, want %v", decoded.Confidence.Total, original.Confidence.Total)
	}
	if decoded.Confidence.LLM != original.Confidence.LLM {
		t.Errorf("Confidence.LLM: got %v, want %v", decoded.Confidence.LLM, original.Confidence.LLM)
	}
	if decoded.RecommendedState != original.RecommendedState {
		t.Errorf("RecommendedState: got %q, want %q", decoded.RecommendedState, original.RecommendedState)
	}
	if decoded.Mode != original.Mode {
		t.Errorf("Mode: got %q, want %q", decoded.Mode, original.Mode)
	}
}

func TestIncidentRoundTrip(t *testing.T) {
	original := Incident{
		ID:        "incident-001",
		CreatedAt: time.Date(2026, 4, 8, 12, 30, 0, 0, time.UTC),
		Pod: PodRef{
			Name:      "victim-pod",
			Namespace: "default",
			UID:       "pod-uid-002",
		},
		Events: []Event{
			{
				ID:       "evt-001",
				Source:   SourceFalco,
				Category: CategorySyscall,
				Summary:  "ptrace attach detected",
			},
			{
				ID:       "evt-002",
				Source:   SourceAudit,
				Category: CategoryAPI,
				Summary:  "secret read by unknown SA",
			},
		},
		Assessment: ThreatAssessment{
			ThreatType:       "privilege_escalation",
			RecommendedState: StateQuarantined,
			Mode:             ModeLLM,
		},
		Transitions: []StateTransition{
			{
				Timestamp:     time.Date(2026, 4, 8, 12, 15, 0, 0, time.UTC),
				Pod:           PodRef{Name: "victim-pod", Namespace: "default", UID: "pod-uid-002"},
				FromState:     StateClean,
				ToState:       StateSuspicious,
				TriggerType:   "automated",
				Confidence:    45.0,
				TriggerEvents: []string{"evt-001"},
			},
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Incident
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.ID != original.ID {
		t.Errorf("ID: got %q, want %q", decoded.ID, original.ID)
	}
	if len(decoded.Events) != 2 {
		t.Errorf("Events count: got %d, want 2", len(decoded.Events))
	}
	if decoded.Events[0].Source != SourceFalco {
		t.Errorf("Events[0].Source: got %q, want %q", decoded.Events[0].Source, SourceFalco)
	}
	if decoded.Events[1].Source != SourceAudit {
		t.Errorf("Events[1].Source: got %q, want %q", decoded.Events[1].Source, SourceAudit)
	}
	if len(decoded.Transitions) != 1 {
		t.Errorf("Transitions count: got %d, want 1", len(decoded.Transitions))
	}
}

func TestStateTransitionRoundTrip(t *testing.T) {
	original := StateTransition{
		Timestamp:     time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC),
		Pod:           PodRef{Name: "test", Namespace: "default", UID: "uid-1"},
		FromState:     StateSuspicious,
		ToState:       StateRestricted,
		TriggerType:   "automated",
		Confidence:    75.0,
		TriggerEvents: []string{"evt-001", "evt-002"},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded StateTransition
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.FromState != original.FromState {
		t.Errorf("FromState: got %q, want %q", decoded.FromState, original.FromState)
	}
	if decoded.ToState != original.ToState {
		t.Errorf("ToState: got %q, want %q", decoded.ToState, original.ToState)
	}
	if decoded.TriggerType != original.TriggerType {
		t.Errorf("TriggerType: got %q, want %q", decoded.TriggerType, original.TriggerType)
	}
}

func TestValidTransition(t *testing.T) {
	tests := []struct {
		name string
		from PodSecurityState
		to   PodSecurityState
		want bool
	}{
		{"clean to suspicious", StateClean, StateSuspicious, true},
		{"suspicious to restricted", StateSuspicious, StateRestricted, true},
		{"restricted to quarantined", StateRestricted, StateQuarantined, true},
		{"quarantined to preserved", StateQuarantined, StatePreservedKilled, true},
		{"clean to restricted (skip)", StateClean, StateRestricted, false},
		{"clean to quarantined (skip)", StateClean, StateQuarantined, false},
		{"suspicious to preserved (skip)", StateSuspicious, StatePreservedKilled, false},
		{"restricted to clean (de-escalate)", StateRestricted, StateClean, true},
		{"quarantined to suspicious (de-escalate)", StateQuarantined, StateSuspicious, true},
		{"preserved to clean (de-escalate)", StatePreservedKilled, StateClean, true},
		{"same state", StateClean, StateClean, false},
		{"invalid state", PodSecurityState("BOGUS"), StateClean, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidTransition(tt.from, tt.to)
			if got != tt.want {
				t.Errorf("ValidTransition(%q, %q) = %v, want %v", tt.from, tt.to, got, tt.want)
			}
		})
	}
}

func TestContainmentEvidenceRoundTrip(t *testing.T) {
	original := ContainmentEvidence{
		IncidentID:    "incident-001",
		CapturedAt:    time.Date(2026, 4, 8, 13, 0, 0, 0, time.UTC),
		OverlayDiff:   "diff content here",
		PodSpec:       `{"kind":"Pod"}`,
		ProcessList:   "PID 1 /bin/sh",
		NetworkConns:  "tcp 10.0.0.1:80 -> 10.0.0.2:443",
		IntegrityHash: "sha256:abc123",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded ContainmentEvidence
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.IncidentID != original.IncidentID {
		t.Errorf("IncidentID: got %q, want %q", decoded.IncidentID, original.IncidentID)
	}
	if decoded.IntegrityHash != original.IntegrityHash {
		t.Errorf("IntegrityHash: got %q, want %q", decoded.IntegrityHash, original.IntegrityHash)
	}
}

func TestEvidencePackageRoundTrip(t *testing.T) {
	original := EvidencePackage{
		SchemaVersion: "evidence.v1",
		PackageID:     "pkg-001",
		WorkloadID:    "payments/Deployment/api",
		WorkloadIdentity: WorkloadIdentity{
			Namespace: "payments",
			OwnerKind: "Deployment",
			OwnerName: "api",
		},
		AssembledAt: time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC),
		WindowStart: time.Date(2026, 5, 18, 9, 59, 0, 0, time.UTC),
		WindowEnd:   time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC),
		Trigger: EvidenceTrigger{
			Type:            "multi_signal",
			DistinctSources: []EventSource{SourceAudit, SourceFalco},
			FiredAt:         time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC),
		},
		Events: []Event{
			{ID: "evt-1", Source: SourceAudit, Category: CategoryAudit, Summary: "secret read"},
			{ID: "evt-2", Source: SourceFalco, Category: CategorySyscall, Summary: "shell"},
		},
		WorkloadPosture: &WorkloadPosture{
			Identity: WorkloadIdentity{Namespace: "payments", OwnerKind: "Deployment", OwnerName: "api"},
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(data)
	for _, key := range []string{"schema_version", "package_id", "workload_id", "workload_identity", "window_start", "window_end", "workload_posture"} {
		if !contains(got, key) {
			t.Errorf("EvidencePackage JSON missing snake_case key %q: %s", key, got)
		}
	}

	var decoded EvidencePackage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.PackageID != original.PackageID {
		t.Errorf("PackageID: got %q, want %q", decoded.PackageID, original.PackageID)
	}
	if len(decoded.Events) != 2 {
		t.Errorf("Events: got %d, want 2", len(decoded.Events))
	}
	if decoded.WorkloadPosture == nil {
		t.Fatal("WorkloadPosture: got nil, want non-nil")
	}
}

func TestConfidenceScoreJSON(t *testing.T) {
	original := ConfidenceScore{
		Total:    67.5,
		Rules:    30,
		Baseline: 15,
		LLM:      22.5,
		LLMCap:   35,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Verify snake_case keys in JSON
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	for _, key := range []string{"total", "rules", "baseline", "llm", "llm_cap"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q not found", key)
		}
	}

	var decoded ConfidenceScore
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Total != original.Total {
		t.Errorf("Total: got %v, want %v", decoded.Total, original.Total)
	}
}

func TestRuleMatchRoundTrip(t *testing.T) {
	original := RuleMatch{
		RuleID:    "OLT-EXEC-001",
		RuleName:  "Unexpected Shell in Container",
		Severity:  "high",
		MitreTags: []string{"T1059.004"},
		EventID:   "evt-001",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded RuleMatch
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.RuleID != original.RuleID {
		t.Errorf("RuleID: got %q, want %q", decoded.RuleID, original.RuleID)
	}
	if decoded.RuleName != original.RuleName {
		t.Errorf("RuleName: got %q, want %q", decoded.RuleName, original.RuleName)
	}
	if len(decoded.MitreTags) != 1 || decoded.MitreTags[0] != "T1059.004" {
		t.Errorf("MitreTags: got %v, want [T1059.004]", decoded.MitreTags)
	}
}

func TestBaselineDeviationRoundTrip(t *testing.T) {
	original := BaselineDeviation{
		Metric: "syscall_frequency",
		Value:  450.0,
		Mean:   100.0,
		StdDev: 25.0,
		Sigma:  14.0,
		PodUID: "pod-uid-001",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded BaselineDeviation
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Metric != original.Metric {
		t.Errorf("Metric: got %q, want %q", decoded.Metric, original.Metric)
	}
	if decoded.Sigma != original.Sigma {
		t.Errorf("Sigma: got %v, want %v", decoded.Sigma, original.Sigma)
	}
	if decoded.PodUID != original.PodUID {
		t.Errorf("PodUID: got %q, want %q", decoded.PodUID, original.PodUID)
	}
}

func TestThreatContextRoundTrip(t *testing.T) {
	original := ThreatContext{
		Pod: PodRef{
			Name:      "suspicious-pod",
			Namespace: "default",
			Node:      "worker-1",
			UID:       "pod-uid-003",
		},
		Events: []Event{
			{
				ID:       "evt-010",
				Source:   SourceFalco,
				Category: CategorySyscall,
				Summary:  "execve /bin/sh",
			},
		},
		RuleMatches: []RuleMatch{
			{
				RuleID:   "OLT-EXEC-001",
				RuleName: "Unexpected Shell",
				Severity: "high",
				EventID:  "evt-010",
			},
		},
		Deviations: []BaselineDeviation{
			{
				Metric: "process_count",
				Value:  12,
				Mean:   3,
				StdDev: 2,
				Sigma:  4.5,
				PodUID: "pod-uid-003",
			},
		},
		CurrentState: StateSuspicious,
		PodAge:       "2h30m",
		PriorAssessment: &ThreatAssessment{
			ThreatType:       "reconnaissance",
			RecommendedState: StateSuspicious,
			Mode:             ModeLLM,
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded ThreatContext
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Pod.UID != original.Pod.UID {
		t.Errorf("Pod.UID: got %q, want %q", decoded.Pod.UID, original.Pod.UID)
	}
	if len(decoded.Events) != 1 {
		t.Errorf("Events count: got %d, want 1", len(decoded.Events))
	}
	if len(decoded.RuleMatches) != 1 {
		t.Errorf("RuleMatches count: got %d, want 1", len(decoded.RuleMatches))
	}
	if len(decoded.Deviations) != 1 {
		t.Errorf("Deviations count: got %d, want 1", len(decoded.Deviations))
	}
	if decoded.CurrentState != StateSuspicious {
		t.Errorf("CurrentState: got %q, want %q", decoded.CurrentState, StateSuspicious)
	}
	if decoded.PriorAssessment == nil {
		t.Fatal("PriorAssessment: got nil, want non-nil")
	}
	if decoded.PriorAssessment.ThreatType != "reconnaissance" {
		t.Errorf("PriorAssessment.ThreatType: got %q, want %q", decoded.PriorAssessment.ThreatType, "reconnaissance")
	}
}

func TestWorkloadPosturePopulatedRoundTrip(t *testing.T) {
	runAsNonRoot := true
	allowEsc := false
	readOnlyRootFS := true
	runAsUser := int64(1000)
	posture := WorkloadPosture{
		Identity: WorkloadIdentity{
			Namespace: "payments",
			OwnerKind: "Deployment",
			OwnerName: "payments-api",
		},
		CapturedAt:     time.Date(2026, 5, 12, 22, 0, 0, 0, time.UTC),
		ServiceAccount: "payments-sa",
		RoleBindings: []RoleBindingRef{
			{Name: "payments-rb", RoleKind: "Role", RoleName: "payments-role", Verbs: []string{"get", "list"}, Resources: []string{"secrets"}},
		},
		ClusterRoleBindings: []ClusterRoleBindingRef{
			{Name: "payments-crb", RoleName: "node-reader", Verbs: []string{"get"}, Resources: []string{"nodes"}},
		},
		NetworkPolicies: []NetworkPolicyRef{
			{Name: "allow-frontend", PolicyTypes: []string{"Ingress"}, IngressRules: 1, EgressRules: 0},
		},
		PodSecurityContext: &PodSecurityContextSummary{
			RunAsUser:    &runAsUser,
			RunAsNonRoot: &runAsNonRoot,
		},
		ContainerSecurityContexts: []ContainerSecurityContextSummary{
			{
				ContainerName:            "api",
				Kind:                     ContainerKindRegular,
				AllowPrivilegeEscalation: &allowEsc,
				ReadOnlyRootFilesystem:   &readOnlyRootFS,
				DroppedCapabilities:      []string{"ALL"},
			},
		},
	}

	data, err := json.Marshal(posture)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded WorkloadPosture
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Identity.OwnerKind != "Deployment" || decoded.Identity.OwnerName != "payments-api" {
		t.Errorf("Identity: got %+v, want owner Deployment/payments-api", decoded.Identity)
	}
	if decoded.ServiceAccount != "payments-sa" {
		t.Errorf("ServiceAccount: got %q, want %q", decoded.ServiceAccount, "payments-sa")
	}
	if len(decoded.RoleBindings) != 1 || decoded.RoleBindings[0].RoleKind != "Role" {
		t.Errorf("RoleBindings: got %+v", decoded.RoleBindings)
	}
	if len(decoded.ClusterRoleBindings) != 1 {
		t.Errorf("ClusterRoleBindings: got %d, want 1", len(decoded.ClusterRoleBindings))
	}
	if len(decoded.NetworkPolicies) != 1 || decoded.NetworkPolicies[0].IngressRules != 1 {
		t.Errorf("NetworkPolicies: got %+v", decoded.NetworkPolicies)
	}
	if decoded.PodSecurityContext == nil || decoded.PodSecurityContext.RunAsNonRoot == nil || !*decoded.PodSecurityContext.RunAsNonRoot {
		t.Errorf("PodSecurityContext.RunAsNonRoot: got %+v, want non-nil true", decoded.PodSecurityContext)
	}
	if len(decoded.ContainerSecurityContexts) != 1 {
		t.Fatalf("ContainerSecurityContexts: got %d, want 1", len(decoded.ContainerSecurityContexts))
	}
	csc := decoded.ContainerSecurityContexts[0]
	if csc.AllowPrivilegeEscalation == nil || *csc.AllowPrivilegeEscalation {
		t.Errorf("AllowPrivilegeEscalation: got %+v, want non-nil false", csc.AllowPrivilegeEscalation)
	}
	if decoded.OrphanPod || decoded.Unavailable {
		t.Errorf("OrphanPod/Unavailable: got %v/%v, want both false", decoded.OrphanPod, decoded.Unavailable)
	}
}

func TestWorkloadPostureOrphanFallbackRoundTrip(t *testing.T) {
	posture := WorkloadPosture{
		Identity: WorkloadIdentity{
			Namespace: "scratch",
			OwnerKind: "Pod",
			OwnerName: "lone-pod",
			PodName:   "lone-pod",
		},
		OrphanPod:  true,
		CapturedAt: time.Date(2026, 5, 12, 22, 5, 0, 0, time.UTC),
	}

	data, err := json.Marshal(posture)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded WorkloadPosture
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !decoded.OrphanPod {
		t.Errorf("OrphanPod: got false, want true")
	}
	if decoded.Identity.PodName != "lone-pod" {
		t.Errorf("Identity.PodName: got %q, want lone-pod", decoded.Identity.PodName)
	}
	if decoded.Identity.OwnerKind != "Pod" {
		t.Errorf("Identity.OwnerKind: got %q, want Pod", decoded.Identity.OwnerKind)
	}
}

func TestWorkloadPostureUnavailableRoundTrip(t *testing.T) {
	posture := WorkloadPosture{
		Identity: WorkloadIdentity{
			Namespace: "payments",
			OwnerKind: "Deployment",
			OwnerName: "payments-api",
		},
		Unavailable:       true,
		UnavailableReason: PostureUnavailableTransient,
		CapturedAt:        time.Date(2026, 5, 12, 22, 10, 0, 0, time.UTC),
	}
	data, err := json.Marshal(posture)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded WorkloadPosture
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !decoded.Unavailable || decoded.UnavailableReason != PostureUnavailableTransient {
		t.Errorf("unavailable: got (%v,%q), want (true,%q)", decoded.Unavailable, decoded.UnavailableReason, PostureUnavailableTransient)
	}
}

func TestWorkloadPostureOmitemptyDropsZeroFields(t *testing.T) {
	posture := WorkloadPosture{
		Identity: WorkloadIdentity{
			Namespace: "ns",
			OwnerKind: "Deployment",
			OwnerName: "app",
		},
		CapturedAt: time.Date(2026, 5, 12, 22, 15, 0, 0, time.UTC),
	}
	data, err := json.Marshal(posture)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(data)
	for _, banned := range []string{"orphan_pod", "unavailable", "unavailable_reason", "service_account", "role_bindings", "cluster_role_bindings", "network_policies", "pod_security_context", "container_security_contexts"} {
		if contains(got, banned) {
			t.Errorf("zero-value posture serialised contained %q; expected omitempty drop. JSON: %s", banned, got)
		}
	}
	if !contains(got, "captured_at") {
		t.Errorf("captured_at missing from serialised posture: %s", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestEventSampledOmitemptyBackwardsCompatible locks in the Story 1.13
// invariant that an unsampled event's JSON wire form is byte-identical
// to the pre-1.13 form. Both Sampled (bool zero) and SamplingRate
// (float64 zero) carry json:"omitempty" tags so the additive schema
// change does not eat into the EVENTS_RAW MaxMsgSize budget for the
// steady-state case.
func TestEventSampledOmitemptyBackwardsCompatible(t *testing.T) {
	ev := Event{
		ID:        "01ABCDEF-1234-7890-ABCD-1234567890AB",
		Timestamp: time.Date(2026, 5, 15, 10, 0, 0, 0, time.UTC),
		Source:    SourceFalco,
		Pod:       PodRef{Name: "p", Namespace: "ns", UID: "u"},
		Category:  CategorySyscall,
		Summary:   "test",
	}
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(data)
	if contains(got, "\"sampled\"") {
		t.Errorf("zero-value Sampled rendered: %s", got)
	}
	if contains(got, "\"sampling_rate\"") {
		t.Errorf("zero-value SamplingRate rendered: %s", got)
	}
}

// TestEventSampledExplicitlySet confirms Sampled=true with a non-zero
// SamplingRate marshals both keys; the Sampled field is included even
// at boolean true so dashboards can detect the engagement boundary.
func TestEventSampledExplicitlySet(t *testing.T) {
	ev := Event{
		ID:           "01ABCDEF-1234-7890-ABCD-1234567890AB",
		Timestamp:    time.Date(2026, 5, 15, 10, 0, 0, 0, time.UTC),
		Source:       SourceFalco,
		Pod:          PodRef{Name: "p", Namespace: "ns", UID: "u"},
		Category:     CategorySyscall,
		Summary:      "test",
		Sampled:      true,
		SamplingRate: 0.1,
	}
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(data)
	if !contains(got, "\"sampled\":true") {
		t.Errorf("Sampled=true not rendered: %s", got)
	}
	if !contains(got, "\"sampling_rate\":0.1") {
		t.Errorf("SamplingRate=0.1 not rendered: %s", got)
	}
}

// TestEventPre113WireFormUnmarshals confirms a JSON payload produced
// before Story 1.13 (no sampled/sampling_rate keys) unmarshals cleanly
// with Sampled=false and SamplingRate=0.0; the unknown-fields decoder
// does not reject the absence of the new keys.
func TestEventPre113WireFormUnmarshals(t *testing.T) {
	pre := `{"id":"01A","timestamp":"2026-05-15T10:00:00Z","source":"falco","pod":{"name":"p","namespace":"ns","uid":"u"},"category":"syscall","summary":"test"}`
	var ev Event
	if err := json.Unmarshal([]byte(pre), &ev); err != nil {
		t.Fatalf("unmarshal pre-1.13 form: %v", err)
	}
	if ev.Sampled {
		t.Errorf("Sampled: got true, want false")
	}
	if ev.SamplingRate != 0.0 {
		t.Errorf("SamplingRate: got %v, want 0.0", ev.SamplingRate)
	}
}
