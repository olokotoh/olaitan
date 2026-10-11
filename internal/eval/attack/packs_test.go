package attack

import (
	"strings"
	"testing"
)

// TestTechniqueValidate_RejectsBadShapes proves the validator itself fails on
// every malformed MITRE citation, so a green table test means the citations
// are well formed, not that the check is blind (the Story 12.6 guard's own
// "prove the classifier rejects bad shapes" discipline, applied to AC3).
func TestTechniqueValidate_RejectsBadShapes(t *testing.T) {
	cases := map[string]struct {
		tech Technique
		want string
	}{
		"empty id": {
			Technique{MitreTactics: []string{"Persistence"}, Organ: OrganAudit},
			"empty ID",
		},
		"no tactic": {
			Technique{ID: "x", Organ: OrganAudit},
			"no MITRE tactic",
		},
		"minted bare number": {
			Technique{ID: "x", MitreTactics: []string{"Persistence"}, MitreTechniqueID: "1611", Organ: OrganAudit},
			"malformed MITRE technique ID",
		},
		"minted lowercase": {
			Technique{ID: "x", MitreTactics: []string{"Persistence"}, MitreTechniqueID: "t1611", Organ: OrganAudit},
			"malformed MITRE technique ID",
		},
		"no organ": {
			Technique{ID: "x", MitreTactics: []string{"Persistence"}},
			"no Olaitan sensor organ",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := tc.tech.validate()
			if err == nil {
				t.Fatalf("validate() = nil, want an error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("validate() = %q, want it to contain %q", err.Error(), tc.want)
			}
		})
	}

	// A well-formed technique with a cited technique ID, and one with only a
	// tactic (the honest common case), must BOTH pass.
	good := []Technique{
		{ID: "k8s.privilege-escalation.hostpath-volume", MitreTactics: []string{"Privilege Escalation"}, MitreTechniqueID: "T1611", Organ: OrganAudit},
		{ID: "k8s.credential-access.dump-secrets", MitreTactics: []string{"Credential Access"}, Organ: OrganAudit},
	}
	for _, g := range good {
		if err := g.validate(); err != nil {
			t.Errorf("validate(%q) = %v, want ok", g.ID, err)
		}
	}
}

// TestStratusTechniques_MitreCitedNotMinted walks the curated Stratus subset
// and enforces AC3's anti-minting rule: every technique validates, no ID is
// duplicated, each is bound to an organ Olaitan has, and - the honest part -
// ONLY k8s.privilege-escalation.hostpath-volume carries a technique ID (T1611),
// because that is the only k8s technique Stratus's own docs pin to a T-number.
// If a future edit mints a T-number Stratus does not advertise, the contract
// test (D6) catches it against the pinned catalogue; this test catches a
// malformed or duplicated one with no cluster at all.
func TestStratusTechniques_MitreCitedNotMinted(t *testing.T) {
	techs := StratusTechniques()
	if len(techs) == 0 {
		t.Fatal("StratusTechniques() is empty; the curated Stratus subset must be non-empty (AC: 3)")
	}

	seen := map[string]bool{}
	for _, tc := range techs {
		if tc.Pack != PackStratus {
			t.Errorf("%q: Pack = %q, want %q", tc.ID, tc.Pack, PackStratus)
		}
		if err := tc.validate(); err != nil {
			t.Errorf("%q: %v", tc.ID, err)
		}
		if seen[tc.ID] {
			t.Errorf("%q: duplicate technique ID in the table", tc.ID)
		}
		seen[tc.ID] = true
		// Every Stratus k8s technique ID is namespaced "k8s.".
		if !strings.HasPrefix(tc.ID, "k8s.") {
			t.Errorf("%q: not a Stratus Kubernetes technique ID (want a k8s. prefix)", tc.ID)
		}
	}

	// The anti-minting invariant, pinned to the tool's own docs (2026-10-11):
	// hostpath-volume cites T1611; every other curated technique cites a
	// tactic only (empty technique ID). This is the test that would go red if
	// someone "helpfully" filled in T-numbers the tool never advertised.
	wantTechniqueID := map[string]string{
		"k8s.credential-access.dump-secrets":               "",
		"k8s.credential-access.steal-serviceaccount-token": "",
		"k8s.persistence.create-admin-clusterrole":         "",
		"k8s.persistence.create-token":                     "",
		"k8s.privilege-escalation.hostpath-volume":         "T1611",
		"k8s.privilege-escalation.privileged-pod":          "",
	}
	for _, tc := range techs {
		want, known := wantTechniqueID[tc.ID]
		if !known {
			t.Errorf("%q: technique not in the pinned-citation map; add it with its tool-advertised MITRE ID (or \"\")", tc.ID)
			continue
		}
		if tc.MitreTechniqueID != want {
			t.Errorf("%q: MitreTechniqueID = %q, want %q (cited from the tool, not minted - AC3)", tc.ID, tc.MitreTechniqueID, want)
		}
	}
}
