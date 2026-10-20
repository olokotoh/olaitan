package attack

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

// repoDemoPacksRoot resolves deploy/demo/packs from this test's location
// (internal/eval/attack -> three dirs up to the repo root).
func repoDemoPacksRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "deploy", "demo", "packs")
}

// TestDefaultRenderJob_EventGen proves the real renderer reads the COMMITTED
// event-generator Job template, substitutes the concrete action, leaves no
// placeholder behind, and keeps the pinned image (AC2). This exercises Task 5
// offline: the template the pack actually applies at the live gate is the one
// under test.
func TestDefaultRenderJob_EventGen(t *testing.T) {
	p, err := NewPackRunner(PackFalcoEventGen, func(context.Context, string, ...string) (string, error) { return "", nil }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewPackRunner: %v", err)
	}
	p.PacksRoot = repoDemoPacksRoot(t)

	path, err := p.renderJob(Technique{ID: "syscall.ReadSensitiveFileUntrusted", Pack: PackFalcoEventGen}, "olt-pack-test")
	if err != nil {
		t.Fatalf("renderJob: %v", err)
	}
	defer func() { _ = os.Remove(path) }()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read rendered: %v", err)
	}
	got := string(body)
	if strings.Contains(got, eventGenActionPlaceholder) {
		t.Errorf("rendered manifest still contains the %s placeholder", eventGenActionPlaceholder)
	}
	if !strings.Contains(got, "syscall.ReadSensitiveFileUntrusted") {
		t.Errorf("rendered manifest does not carry the substituted action")
	}
	if !strings.Contains(got, EventGenImage) {
		t.Errorf("rendered manifest does not carry the pinned event-generator image %q", EventGenImage)
	}
}

// TestDefaultRenderJob_StratusDeferred proves the renderer returns an explicit
// deferral (not a silent miss) for Stratus until its wrapper image manifest is
// committed at the supervised build step - the honest handling of the one AC
// piece that cannot be done offline.
func TestDefaultRenderJob_StratusDeferred(t *testing.T) {
	p, err := NewPackRunner(PackStratus, func(context.Context, string, ...string) (string, error) { return "", nil }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewPackRunner: %v", err)
	}
	p.PacksRoot = repoDemoPacksRoot(t)
	_, err = p.renderJob(StratusTechniques()[0], "olt-pack-test")
	if err == nil || !strings.Contains(err.Error(), "deferred") {
		t.Fatalf("renderJob(stratus) = %v, want an explicit deferral error until the wrapper image is built", err)
	}
}

// TestImagePinShape_RejectsBadShapes proves imagePinShape fails on every bad
// shape (not just that one good image passes), mirroring the
// TestTechniqueValidate discipline so a green pin check is not blind.
func TestImagePinShape_RejectsBadShapes(t *testing.T) {
	const d = "@sha256:1cfc36e2e5e638243d8c722f72c954cd0ec4b15ee82fadbc718ce12e2b3c1652"
	bad := map[string]string{
		"":                                "empty",
		"busybox":                         "untagged",
		"busybox:1.37.0":                  "tag without a digest",
		"busybox:latest" + d:              ":latest",
		"busybox" + d:                     "digest without a tag",
		"busybox:1.37.0@sha256:deadbeef":  "malformed digest",
		"docker.io/falcosecurity/x:1" + d: "", // good: registry/path:tag@sha256
	}
	for ref, want := range bad {
		got := imagePinShape(ref)
		if want == "" {
			if got != "" {
				t.Errorf("imagePinShape(%q) = %q, want ok", ref, got)
			}
			continue
		}
		if !strings.Contains(got, want) {
			t.Errorf("imagePinShape(%q) = %q, want a problem containing %q", ref, got, want)
		}
	}
}
