package keys_test

import (
	"testing"

	"github.com/olokotoh/olaitan/internal/keys"
)

func TestFSMState_RoundTrip(t *testing.T) {
	got, err := keys.FSMState("default/Deployment/web")
	if err != nil {
		t.Fatalf("FSMState: %v", err)
	}
	if want := "fsm:default/Deployment/web"; got != want {
		t.Errorf("FSMState = %q, want %q", got, want)
	}
	if fam := keys.FamilyOf(got); fam != keys.FamilyFSM {
		t.Errorf("FamilyOf(%q) = %v, want FamilyFSM", got, fam)
	}
}

func TestFSMHistory_RoundTrip(t *testing.T) {
	got, err := keys.FSMHistory("default/Deployment/web")
	if err != nil {
		t.Fatalf("FSMHistory: %v", err)
	}
	if want := "fsm:default/Deployment/web:history"; got != want {
		t.Errorf("FSMHistory = %q, want %q", got, want)
	}
	// A history key is still in the fsm family.
	if fam := keys.FamilyOf(got); fam != keys.FamilyFSM {
		t.Errorf("FamilyOf(history) = %v, want FamilyFSM", fam)
	}
}

func TestFSMState_AcceptsPodFallbackID(t *testing.T) {
	got, err := keys.FSMState("default/Pod/orphan-xyz")
	if err != nil {
		t.Fatalf("FSMState(pod-fallback): %v", err)
	}
	if want := "fsm:default/Pod/orphan-xyz"; got != want {
		t.Errorf("FSMState = %q, want %q", got, want)
	}
}

func TestFSMState_RejectsBadWorkloadID(t *testing.T) {
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
			if _, err := keys.FSMState(id); err == nil {
				t.Errorf("FSMState(%q) = nil error, want rejection", id)
			}
		})
	}
}
