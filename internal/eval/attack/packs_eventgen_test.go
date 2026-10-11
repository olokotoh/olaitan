package attack

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// falcoCatalogue is the committed citation fixture (D6): the MITRE mapping for
// each event-generator action, extracted from the pinned Falco rules package.
type falcoCatalogue struct {
	Version string `json:"version"`
	Actions map[string]struct {
		FalcoRule   string   `json:"falco_rule"`
		Tactics     []string `json:"tactics"`
		TechniqueID string   `json:"technique_id"`
	} `json:"actions"`
}

func loadFalcoCatalogue(t *testing.T) falcoCatalogue {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	path := filepath.Join(filepath.Dir(thisFile), "testdata", "falco-rules-catalogue-5.2.0.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read catalogue fixture: %v", err)
	}
	var c falcoCatalogue
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatalf("unmarshal catalogue fixture: %v", err)
	}
	return c
}

// TestEventGenMitreMatchesFalcoCatalogue is the offline contract test (D6,
// Murat): it holds the event-generator table in packs_eventgen.go in exact
// agreement with the citation fixture extracted from the pinned Falco rules.
// The table "testing itself" is a tautology; this test breaks the tautology by
// asserting against the EXTERNAL tool's own advertised mapping. A Falco-rules
// bump that renames a rule or changes a technique ID fails HERE, on the PR that
// bumps the pin - exactly where a human is already looking. (The stronger live
// form execs the pinned image; this offline form is the CI gate.)
func TestEventGenMitreMatchesFalcoCatalogue(t *testing.T) {
	cat := loadFalcoCatalogue(t)
	if cat.Version != FalcoRulesVersion {
		t.Fatalf("fixture version %q != FalcoRulesVersion %q; the citation pin drifted", cat.Version, FalcoRulesVersion)
	}
	techs := EventGenTechniques()
	if len(techs) == 0 {
		t.Fatal("EventGenTechniques() is empty; event-generator is the required spine (AC: 3)")
	}
	for _, tc := range techs {
		entry, ok := cat.Actions[tc.ID]
		if !ok {
			t.Errorf("%q: not in the pinned Falco catalogue fixture; cite it (regenerate the fixture from the pinned rules) or remove the technique", tc.ID)
			continue
		}
		if tc.MitreTechniqueID != entry.TechniqueID {
			t.Errorf("%q: MitreTechniqueID = %q, but the pinned Falco catalogue says %q (cite, do not mint - AC3)", tc.ID, tc.MitreTechniqueID, entry.TechniqueID)
		}
		if len(tc.MitreTactics) != len(entry.Tactics) {
			t.Errorf("%q: %d tactics, catalogue has %d", tc.ID, len(tc.MitreTactics), len(entry.Tactics))
			continue
		}
		for i := range tc.MitreTactics {
			if tc.MitreTactics[i] != entry.Tactics[i] {
				t.Errorf("%q: tactic[%d] = %q, catalogue says %q", tc.ID, i, tc.MitreTactics[i], entry.Tactics[i])
			}
		}
	}

	// Every event-generator technique must validate and be Falco-organ bound
	// (D5): event-generator exists to exercise Falco.
	seen := map[string]bool{}
	for _, tc := range techs {
		if tc.Pack != PackFalcoEventGen {
			t.Errorf("%q: Pack = %q, want %q", tc.ID, tc.Pack, PackFalcoEventGen)
		}
		if tc.Organ != OrganFalco {
			t.Errorf("%q: Organ = %q, want %q (event-generator targets Falco)", tc.ID, tc.Organ, OrganFalco)
		}
		if err := tc.validate(); err != nil {
			t.Errorf("%q: %v", tc.ID, err)
		}
		if seen[tc.ID] {
			t.Errorf("%q: duplicate action ID", tc.ID)
		}
		seen[tc.ID] = true
	}
}

// TestEventGenImageIsPinned asserts the event-generator image carries a tag
// AND a sha256 digest (AC2) - the same rule the Story 12.6 guard enforces on
// the chart, checked here at the source so the pack cannot ship unpinned.
func TestEventGenImageIsPinned(t *testing.T) {
	if p := imagePinShape(EventGenImage); p != "" {
		t.Errorf("EventGenImage %q: %s", EventGenImage, p)
	}
}
