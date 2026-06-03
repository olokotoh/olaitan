package keys_test

import (
	"testing"

	"github.com/olokotoh/olaitan/internal/keys"
)

func TestOverride_RoundTrip(t *testing.T) {
	got, err := keys.Override("default/Deployment/web")
	if err != nil {
		t.Fatalf("Override: %v", err)
	}
	if want := "override:default/Deployment/web"; got != want {
		t.Errorf("Override = %q, want %q", got, want)
	}
	if fam := keys.FamilyOf(got); fam != keys.FamilyOverride {
		t.Errorf("FamilyOf(%q) = %v, want FamilyOverride", got, fam)
	}
}

func TestOverride_AcceptsPodFallbackID(t *testing.T) {
	got, err := keys.Override("default/Pod/orphan-xyz")
	if err != nil {
		t.Fatalf("Override(pod-fallback): %v", err)
	}
	if want := "override:default/Pod/orphan-xyz"; got != want {
		t.Errorf("Override = %q, want %q", got, want)
	}
}

// TestOverride_DistinctFromFSMFamily pins the deliberate Story 2.7
// divergence: the override: family is NOT the no-TTL fsm: family, so a
// key built by Override must never classify as FamilyFSM.
func TestOverride_DistinctFromFSMFamily(t *testing.T) {
	ovr, err := keys.Override("default/Deployment/web")
	if err != nil {
		t.Fatalf("Override: %v", err)
	}
	if fam := keys.FamilyOf(ovr); fam == keys.FamilyFSM {
		t.Errorf("FamilyOf(%q) = FamilyFSM, want FamilyOverride (families must be disjoint)", ovr)
	}
	fsmKey, err := keys.FSMState("default/Deployment/web")
	if err != nil {
		t.Fatalf("FSMState: %v", err)
	}
	if fam := keys.FamilyOf(fsmKey); fam == keys.FamilyOverride {
		t.Errorf("FamilyOf(%q) = FamilyOverride, want FamilyFSM", fsmKey)
	}
}

func TestOverride_RejectsBadWorkloadID(t *testing.T) {
	cases := map[string]string{
		"empty":         "",
		"two segments":  "default/web",
		"four segments": "default/Deployment/web/extra",
		"colon in seg":  "default/Dep:loy/web",
		"glob in seg":   "default/Deployment/we*b",
		"space in seg":  "default/Deployment/we b",
		"empty segment": "default//web",
	}
	for name, id := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := keys.Override(id); err == nil {
				t.Errorf("Override(%q) = nil error, want rejection", id)
			}
		})
	}
}
