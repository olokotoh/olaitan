package subjects_test

import (
	"strings"
	"testing"

	"github.com/olokotoh/olaitan/internal/subjects"
)

func TestCorrelated(t *testing.T) {
	tests := []struct {
		name       string
		namespace  string
		pod        string
		want       string
		wantErrSub string
	}{
		{"valid", "default", "nginx", "olaitan.correlated.default.nginx", ""},
		{"valid-hyphen", "kube-system", "coredns", "olaitan.correlated.kube-system.coredns", ""},
		{"empty-ns", "", "nginx", "", "empty token"},
		{"empty-pod", "default", "", "", "empty token"},
		{"dot-in-ns", "a.b", "pod", "", "reserved character"},
		{"wildcard-in-pod", "ns", "pod*", "", "reserved character"},
		{"gt-in-ns", "ns>", "pod", "", "reserved character"},
		{"space", "ns x", "pod", "", "whitespace"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := subjects.Correlated(tt.namespace, tt.pod)
			if tt.wantErrSub != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErrSub)
				}
				if !strings.Contains(err.Error(), tt.wantErrSub) {
					t.Errorf("err %q does not contain %q", err, tt.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestState(t *testing.T) {
	got, err := subjects.State("default", "nginx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "olaitan.state.default.nginx" {
		t.Errorf("got %q", got)
	}
	if _, err := subjects.State("*", "pod"); err == nil {
		t.Error("expected error for wildcard namespace")
	}
}

func TestHealth(t *testing.T) {
	got, err := subjects.Health("ring1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "olaitan.health.ring1" {
		t.Errorf("got %q, want olaitan.health.ring1", got)
	}
	if _, err := subjects.Health("heartbeat"); err == nil {
		t.Error(`expected error for reserved ring "heartbeat"`)
	}
	if _, err := subjects.Health(""); err == nil {
		t.Error("expected error for empty ring")
	}
}

func TestEvidence(t *testing.T) {
	got, err := subjects.Evidence("incident-42")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "olaitan.evidence.incident-42" {
		t.Errorf("got %q", got)
	}
	if _, err := subjects.Evidence(""); err == nil {
		t.Error("expected error for empty kind")
	}
}

func TestInvestigationSubjects(t *testing.T) {
	l1, err := subjects.InvestigationL1("pkg-42")
	if err != nil {
		t.Fatalf("InvestigationL1: %v", err)
	}
	if l1 != "INVESTIGATIONS.pkg-42.l1" {
		t.Errorf("InvestigationL1 = %q", l1)
	}
	l2, err := subjects.InvestigationL2("pkg-42")
	if err != nil {
		t.Fatalf("InvestigationL2: %v", err)
	}
	if l2 != "INVESTIGATIONS.pkg-42.l2" {
		t.Errorf("InvestigationL2 = %q", l2)
	}
	// Both fall under INVESTIGATIONS.> (the stream filter).
	if !strings.HasPrefix(l1, subjects.InvestigationPrefix) || !strings.HasPrefix(l2, subjects.InvestigationPrefix) {
		t.Errorf("subjects not under %q", subjects.InvestigationPrefix)
	}
	// A hostile package_id (dot, wildcard, whitespace, empty) is rejected
	// so it cannot inject extra subject tokens.
	for _, bad := range []string{"", "a.b", "a*", "a>", "a b", "a\t"} {
		if _, err := subjects.InvestigationL1(bad); err == nil {
			t.Errorf("InvestigationL1(%q): expected error", bad)
		}
		if _, err := subjects.InvestigationL2(bad); err == nil {
			t.Errorf("InvestigationL2(%q): expected error", bad)
		}
	}
}

func TestEvidencePackagesConstant(t *testing.T) {
	got, err := subjects.Evidence("packages")
	if err != nil {
		t.Fatalf("Evidence(packages): %v", err)
	}
	if subjects.EvidencePackages != got {
		t.Errorf("EvidencePackages: got %q, want %q", got, subjects.EvidencePackages)
	}
}

func TestConstants(t *testing.T) {
	want := map[string]string{
		"RawFalco":          "olaitan.events.raw.falco",
		"RawAudit":          "olaitan.events.raw.audit",
		"RawRuntime":        "olaitan.events.raw.runtime",
		"RawNetwork":        "olaitan.events.raw.network",
		"RawAppLog":         "olaitan.events.raw.applog",
		"Normalised":        "olaitan.events.normalised",
		"ThreatsWatch":      "olaitan.threats.watch",
		"ThreatsAlert":      "olaitan.threats.alert",
		"ThreatsAct":        "olaitan.threats.act",
		"ThreatsIsolate":    "olaitan.threats.isolate",
		"EvidencePackages":  "olaitan.evidence.packages",
		"HealthHeartbeat":   "olaitan.health.heartbeat",
		"AuditTransitions":  "AUDIT.transitions",
		"AuditOverrides":    "AUDIT.overrides",
		"AuditPolicies":     "AUDIT.policies",
		"AuditRedactions":   "AUDIT.redactions",
		"IncidentFinalised": "INCIDENTS.finalised",
		"ReportsGenerated":  "REPORTS.generated",
	}
	got := map[string]string{
		"RawFalco":          subjects.RawFalco,
		"RawAudit":          subjects.RawAudit,
		"RawRuntime":        subjects.RawRuntime,
		"RawNetwork":        subjects.RawNetwork,
		"RawAppLog":         subjects.RawAppLog,
		"Normalised":        subjects.Normalised,
		"ThreatsWatch":      subjects.ThreatsWatch,
		"ThreatsAlert":      subjects.ThreatsAlert,
		"ThreatsAct":        subjects.ThreatsAct,
		"ThreatsIsolate":    subjects.ThreatsIsolate,
		"EvidencePackages":  subjects.EvidencePackages,
		"HealthHeartbeat":   subjects.HealthHeartbeat,
		"AuditTransitions":  subjects.AuditTransitions,
		"AuditOverrides":    subjects.AuditOverrides,
		"AuditPolicies":     subjects.AuditPolicies,
		"AuditRedactions":   subjects.AuditRedactions,
		"IncidentFinalised": subjects.IncidentFinalised,
		"ReportsGenerated":  subjects.ReportsGenerated,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}
