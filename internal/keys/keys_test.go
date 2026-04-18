package keys_test

import (
	"strings"
	"testing"

	"github.com/olokotoh/olaitan/internal/keys"
)

func TestBuildersValidate(t *testing.T) {
	cases := []struct {
		name    string
		build   func() (string, error)
		wantSub string
	}{
		{"baseline-metrics-empty-ns", func() (string, error) { return keys.BaselineMetrics("", "nginx") }, "empty"},
		{"baseline-metrics-space-pod", func() (string, error) { return keys.BaselineMetrics("default", "ngi nx") }, "disallowed"},
		{"baseline-metrics-colon-ns", func() (string, error) { return keys.BaselineMetrics("a:b", "nginx") }, "disallowed"},
		{"baseline-metrics-star-pod", func() (string, error) { return keys.BaselineMetrics("default", "n*ginx") }, "disallowed"},
		{"baseline-metrics-q-pod", func() (string, error) { return keys.BaselineMetrics("default", "n?ginx") }, "disallowed"},
		{"baseline-metrics-bracket-pod", func() (string, error) { return keys.BaselineMetrics("default", "n[ginx") }, "disallowed"},
		{"baseline-window-tab-pod", func() (string, error) { return keys.BaselineWindow("default", "ngi\tnx") }, "disallowed"},
		{"state-cr-ns", func() (string, error) { return keys.State("def\rault", "nginx") }, "disallowed"},
		{"state-lf-pod", func() (string, error) { return keys.State("default", "nginx\n") }, "disallowed"},
		{"state-nul-pod", func() (string, error) { return keys.State("default", "ngi\x00nx") }, "disallowed"},
		{"state-zwj-ns", func() (string, error) { return keys.State("defau\u200Dlt", "nginx") }, "disallowed"},
		{"evidence-incident-empty", func() (string, error) { return keys.EvidenceIncident("") }, "empty"},
		{"evidence-incident-colon", func() (string, error) { return keys.EvidenceIncident("INC:1") }, "disallowed"},
		{"evidence-incident-dash-sentinel", func() (string, error) { return keys.EvidenceIncident("-") }, "XRANGE sentinel"},
		{"evidence-incident-plus-sentinel", func() (string, error) { return keys.EvidenceIncident("+") }, "XRANGE sentinel"},
		{"evidence-transitions-empty-ns", func() (string, error) { return keys.EvidenceTransitions("", "nginx") }, "empty"},
		{"health-empty", func() (string, error) { return keys.Health("") }, "empty"},
		{"health-wildcard", func() (string, error) { return keys.Health("ring*") }, "disallowed"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.build()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("err %q does not contain %q", err, tc.wantSub)
			}
			if !strings.HasPrefix(err.Error(), "keys:") {
				t.Errorf("err %q does not start with %q", err, "keys:")
			}
		})
	}
}

func TestBuildersHappyPath(t *testing.T) {
	cases := []struct {
		name  string
		build func() (string, error)
		want  string
	}{
		{"baseline-metrics", func() (string, error) { return keys.BaselineMetrics("default", "nginx") }, "baseline:default:nginx:metrics"},
		{"baseline-window", func() (string, error) { return keys.BaselineWindow("kube-system", "coredns") }, "baseline:kube-system:coredns:window"},
		{"state", func() (string, error) { return keys.State("default", "nginx") }, "state:default:nginx"},
		{"evidence-incident", func() (string, error) { return keys.EvidenceIncident("INC-2026-0001") }, "evidence:incident:INC-2026-0001"},
		{"evidence-transitions", func() (string, error) { return keys.EvidenceTransitions("default", "nginx") }, "evidence:transitions:default:nginx"},
		{"health-ring-1", func() (string, error) { return keys.Health("ring-1") }, "health:ring-1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.build()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestConstants(t *testing.T) {
	cases := []struct {
		got, want string
	}{
		{keys.BaselinePrefix, "baseline:"},
		{keys.CheckpointPrefix, "checkpoint:"},
		{keys.StatePrefix, "state:"},
		{keys.EvidencePrefix, "evidence:"},
		{keys.HealthPrefix, "health:"},
		{keys.CheckpointCorrelatorStreamSeq, "checkpoint:correlator:stream_seq"},
		{keys.CheckpointCorrelatorWindowState, "checkpoint:correlator:window_state"},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("got %q, want %q", tc.got, tc.want)
		}
	}
}

func TestFamily(t *testing.T) {
	cases := []struct {
		key  string
		want keys.Family
	}{
		{"baseline:default:nginx:metrics", keys.FamilyBaseline},
		{"checkpoint:correlator:stream_seq", keys.FamilyCheckpoint},
		{"state:default:nginx", keys.FamilyState},
		{"evidence:incident:INC-1", keys.FamilyEvidence},
		{"health:ring-1", keys.FamilyHealth},
		{"unknown:x:y", keys.FamilyUnknown},
		{"", keys.FamilyUnknown},
	}
	for _, tc := range cases {
		if got := keys.FamilyOf(tc.key); got != tc.want {
			t.Errorf("FamilyOf(%q) = %v, want %v", tc.key, got, tc.want)
		}
	}
}
