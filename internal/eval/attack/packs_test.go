package attack

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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

// cmdRecorder is a fake RunFunc that records every kubectl invocation (in
// order) and can be told to fail a specific one, keyed by the space-joined
// args after the binary name. It is how the pack tests prove command
// construction and revert ordering WITHOUT a cluster.
type cmdRecorder struct {
	calls [][]string
	// fail maps a SUBSTRING of a call's joined args to the error it should
	// return (substring so a test is not broken by an added flag).
	fail map[string]error
	// stdout maps a SUBSTRING of a call's joined args to canned stdout.
	stdout map[string]string
}

func (r *cmdRecorder) run(_ context.Context, name string, args ...string) (string, error) {
	full := append([]string{name}, args...)
	r.calls = append(r.calls, full)
	joined := strings.Join(args, " ")
	// Default: a `get job ... status.succeeded` poll reports one succeeded Job
	// so waitForJob terminates; a test can override via stdout.
	out := ""
	if strings.Contains(joined, "status.succeeded") {
		out = "1"
	}
	for sub, v := range r.stdout {
		if strings.Contains(joined, sub) {
			out = v
		}
	}
	for sub, e := range r.fail {
		if strings.Contains(joined, sub) {
			return out, e
		}
	}
	return out, nil
}

// indexOf returns the index of the first recorded call whose args contain all
// of needles in order of first appearance, or -1. Good enough to assert "the
// delete ran after the apply" without pinning the exact argv twice.
func (r *cmdRecorder) indexOf(needles ...string) int {
	for i, c := range r.calls {
		joined := strings.Join(c, " ")
		ok := true
		for _, n := range needles {
			if !strings.Contains(joined, n) {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}

// newTestStratusRunner builds a PackRunner over the real Stratus table but
// with a deterministic namespace and a stub renderer, so Detonate is exercised
// end to end against the recorder.
func newTestStratusRunner(t *testing.T, rec *cmdRecorder) *PackRunner {
	t.Helper()
	p, err := NewPackRunner(PackStratus, rec.run, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewPackRunner: %v", err)
	}
	p.newRunID = func() string { return "test" }
	p.waitTimeout = time.Second
	p.renderJob = func(_ Technique, ns string) (string, error) { return "/fake/" + ns + "/job.yaml", nil }
	return p
}

// TestPackRunner_DetonateHappyPath asserts the kubectl sequence for a clean
// run: create namespace, label it privileged (PSA), apply the pinned Job, poll
// the Job to completion, then delete the namespace (the guaranteed teardown).
func TestPackRunner_DetonateHappyPath(t *testing.T) {
	rec := &cmdRecorder{}
	p := newTestStratusRunner(t, rec)

	if err := p.Detonate(context.Background(), "k8s.credential-access.dump-secrets"); err != nil {
		t.Fatalf("Detonate() = %v, want nil", err)
	}
	create := rec.indexOf("create", "namespace", "olt-pack-test")
	label := rec.indexOf("label", "namespace", "olt-pack-test", "pod-security.kubernetes.io/enforce=privileged")
	apply := rec.indexOf("apply", "-n", "olt-pack-test", "-f")
	poll := rec.indexOf("get", "job", "-n", "olt-pack-test", "status.succeeded")
	del := rec.indexOf("delete", "namespace", "olt-pack-test")
	if create < 0 || label < 0 || apply < 0 || poll < 0 || del < 0 {
		t.Fatalf("missing a step: create=%d label=%d apply=%d poll=%d delete=%d\ncalls=%v", create, label, apply, poll, del, rec.calls)
	}
	if create >= label || label >= apply || apply >= poll || poll >= del {
		t.Errorf("steps out of order: create=%d label=%d apply=%d poll=%d delete=%d", create, label, apply, poll, del)
	}
}

// TestPackRunner_WaitFailsFastOnFailedJob proves a Failed Job surfaces its
// status immediately instead of burning the whole timeout (review round 1,
// Edge Case Hunter).
func TestPackRunner_WaitFailsFastOnFailedJob(t *testing.T) {
	rec := &cmdRecorder{stdout: map[string]string{
		"status.failed":    "1",
		"status.succeeded": "", // never completes
	}}
	p := newTestStratusRunner(t, rec)
	p.waitTimeout = 10 * time.Second // generous; the test should return well under this
	start := time.Now()
	err := p.Detonate(context.Background(), "k8s.credential-access.dump-secrets")
	if err == nil || !strings.Contains(err.Error(), "failed") {
		t.Fatalf("Detonate() = %v, want a job-failed error", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("Detonate took %s on a failed job; it should fail fast, not wait out the timeout", time.Since(start))
	}
	if rec.indexOf("delete", "namespace", "olt-pack-test") < 0 {
		t.Errorf("revert did not run after a failed job")
	}
}

// TestPackRunner_RevertAlwaysRuns is THE safety test (Amelia: write it first):
// when detonation fails, the namespace is still deleted, and when the revert
// ALSO fails the returned error wraps both failures.
func TestPackRunner_RevertAlwaysRuns(t *testing.T) {
	// (a) detonate fails at apply -> revert (delete) still runs.
	rec := &cmdRecorder{fail: map[string]error{
		"apply -n olt-pack-test -f /fake/olt-pack-test/job.yaml": errors.New("boom-apply"),
	}}
	p := newTestStratusRunner(t, rec)
	err := p.Detonate(context.Background(), "k8s.credential-access.dump-secrets")
	if err == nil || !strings.Contains(err.Error(), "boom-apply") {
		t.Fatalf("Detonate() = %v, want an error wrapping boom-apply", err)
	}
	if rec.indexOf("delete", "namespace", "olt-pack-test") < 0 {
		t.Errorf("revert did not run after a failed detonation; calls=%v", rec.calls)
	}

	// (b) both detonate AND revert fail -> error wraps both.
	rec2 := &cmdRecorder{fail: map[string]error{
		"apply -n olt-pack-test -f /fake/olt-pack-test/job.yaml": errors.New("boom-apply"),
		"delete namespace olt-pack-test":                         errors.New("boom-revert"),
	}}
	p2 := newTestStratusRunner(t, rec2)
	err2 := p2.Detonate(context.Background(), "k8s.credential-access.dump-secrets")
	if err2 == nil || !strings.Contains(err2.Error(), "boom-apply") || !strings.Contains(err2.Error(), "boom-revert") {
		t.Fatalf("Detonate() = %v, want an error wrapping BOTH boom-apply and boom-revert", err2)
	}
}

// TestPackRunner_UnknownTechnique proves an unknown technique returns before
// anything is created on the cluster (the defer never registers, so no stray
// namespace to clean up).
func TestPackRunner_UnknownTechnique(t *testing.T) {
	rec := &cmdRecorder{}
	p := newTestStratusRunner(t, rec)
	err := p.Detonate(context.Background(), "k8s.not-a-real-technique")
	if err == nil || !strings.Contains(err.Error(), "unknown technique") {
		t.Fatalf("Detonate() = %v, want an unknown-technique error", err)
	}
	if len(rec.calls) != 0 {
		t.Errorf("unknown technique issued %d kubectl calls, want 0: %v", len(rec.calls), rec.calls)
	}
}

// stratusCatalogue is the committed Stratus citation fixture (D6).
type stratusCatalogue struct {
	Version    string `json:"version"`
	Techniques map[string]struct {
		Tactics     []string `json:"tactics"`
		TechniqueID string   `json:"technique_id"`
	} `json:"techniques"`
}

// TestStratusMitreMatchesCatalogue is the offline contract test for the
// Stratus pack (D6, Murat): it holds the Go table in agreement with the
// citation fixture extracted from the pinned Stratus docs, so a Stratus
// version bump that re-tactics a technique or renames one fails HERE rather
// than drifting silently. It is the anti-tautology check - the table is
// asserted against the EXTERNAL tool's advertised mapping, not itself.
func TestStratusMitreMatchesCatalogue(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	path := filepath.Join(filepath.Dir(thisFile), "testdata", "stratus-catalogue-v2.37.0.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read stratus catalogue fixture: %v", err)
	}
	var cat stratusCatalogue
	if err := json.Unmarshal(data, &cat); err != nil {
		t.Fatalf("unmarshal stratus catalogue: %v", err)
	}
	if cat.Version != StratusVersion {
		t.Fatalf("fixture version %q != StratusVersion %q; the citation pin drifted", cat.Version, StratusVersion)
	}

	techs := StratusTechniques()
	for _, tc := range techs {
		entry, ok := cat.Techniques[tc.ID]
		if !ok {
			t.Errorf("%q: not in the pinned Stratus catalogue fixture; cite it from the pinned docs or remove it", tc.ID)
			continue
		}
		if tc.MitreTechniqueID != entry.TechniqueID {
			t.Errorf("%q: MitreTechniqueID = %q, catalogue says %q (cite, do not mint - AC3)", tc.ID, tc.MitreTechniqueID, entry.TechniqueID)
		}
		if len(tc.MitreTactics) != len(entry.Tactics) {
			t.Errorf("%q: %d tactics, catalogue has %d (%v vs %v)", tc.ID, len(tc.MitreTactics), len(entry.Tactics), tc.MitreTactics, entry.Tactics)
			continue
		}
		for i := range tc.MitreTactics {
			if tc.MitreTactics[i] != entry.Tactics[i] {
				t.Errorf("%q: tactic[%d] = %q, catalogue says %q", tc.ID, i, tc.MitreTactics[i], entry.Tactics[i])
			}
		}
	}

	// And every catalogue technique must be represented in the table (no
	// silent drop): the fixture and the curated set are the same universe.
	table := map[string]bool{}
	for _, tc := range techs {
		table[tc.ID] = true
	}
	for id := range cat.Techniques {
		if !table[id] {
			t.Errorf("catalogue technique %q is not in the curated Stratus table", id)
		}
	}
}

// TestPackFilesDoNotInjectEvents is the Story 11.2c AC4 guard for the pack
// code path. The Story 11.2a grep guard scans tests/e2e; it does NOT scan
// internal/eval/attack, so this test closes that gap for the pack files: they
// must drive REAL in-cluster detonation through the kubectl/RunFunc seam and
// NEVER publish a synthetic attack event onto NATS as a stand-in. It fails if
// a pack source file acquires a forbidden event-injection token.
func TestPackFilesDoNotInjectEvents(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(thisFile)
	packFiles := []string{"packs.go", "packs_eventgen.go"}
	forbidden := []string{"nats", "jetstream", "JetStream", "raw.falco", "raw.network", ".Publish("}
	for _, f := range packFiles {
		raw, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Errorf("read %s: %v", f, err)
			continue
		}
		body := string(raw)
		for _, tok := range forbidden {
			if strings.Contains(body, tok) {
				t.Errorf("%s contains forbidden event-injection token %q: packs must detonate REAL attacks in-cluster, never publish a synthetic event (AC4)", f, tok)
			}
		}
	}
}
