//go:build helm

package helm_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Story 11.1: every S1-S5 scenario deploys a REAL, attackable target
// workload, pinned by tag AND digest, and no scenario uses `pause` as its
// target.
//
// Epic 11 (#110) evidence item 5: every scenario S1-S5 shipped its target as
// a `registry.k8s.io/pause:3.10` container, so Story 11.2's real attack runner
// had nothing to attack (pause has no shell, no network tools, no writable
// userland). This guard is the AC gate: it walks the committed target
// manifests, reuses Story 12.6's imagePinProblem classifier (tag@sha256), and
// fails on any unpinned image or any image whose repository is `pause`.
//
// It runs in the existing helm CI job (`go test ./deploy/helm/... -tags=helm`),
// alongside TestEveryRenderedImageIsPinned, so a regression to pause or to a
// floating tag fails a required check.

// scenarioSlugs is the S1-S5 set every run must find a target manifest for. A
// missing entry means a scenario lost its workload, which the walker would
// otherwise pass over in silence.
var scenarioSlugs = []string{
	"s1-container-escape",
	"s2-credential-exfil",
	"s3-lateral-movement",
	"s4-c2-beaconing",
	"s5-cryptomining",
}

// scenariosDir is deploy/demo/scenarios under the repo root.
func scenariosDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "deploy", "demo", "scenarios")
}

// targetImageProblem returns "" for a real, pinned target image and a reason
// otherwise. It layers the "no pause" rule (AC3) on top of Story 12.6's
// tag@sha256 pin rule (AC1/AC2), so both AC failures are one predicate.
func targetImageProblem(ref string) string {
	name, _, _ := strings.Cut(ref, "@")
	// Repository is everything before the tag (the last ':' after the last
	// '/'), so a registry port is not mistaken for a tag.
	repo := name
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		repo = name[:i]
	}
	base := repo
	if i := strings.LastIndex(repo, "/"); i >= 0 {
		base = repo[i+1:]
	}
	if base == "pause" {
		return "uses pause as the target (pause has no shell or tools to attack)"
	}
	return imagePinProblem(ref)
}

// TestTargetImageClassifier proves the predicate itself rejects every bad
// shape, so a green suite means the targets are real and pinned, not that the
// check is blind.
func TestTargetImageClassifier(t *testing.T) {
	const d = "sha256:1cfc36e2e5e638243d8c722f72c954cd0ec4b15ee82fadbc718ce12e2b3c1652"
	good := []string{
		"busybox:1.37.0@" + d,
		"docker.io/curlimages/curl:8.11.1@" + d,
	}
	bad := map[string]string{
		"registry.k8s.io/pause:3.10":      "pause",
		"registry.k8s.io/pause:3.10@" + d: "pause",
		"busybox":                         "untagged",
		"busybox:1.37.0":                  "tag without a digest",
		"busybox:latest@" + d:             ":latest",
		"":                                "empty",
	}
	for _, ref := range good {
		if p := targetImageProblem(ref); p != "" {
			t.Errorf("targetImageProblem(%q) = %q, want ok", ref, p)
		}
	}
	for ref, want := range bad {
		if p := targetImageProblem(ref); !strings.Contains(p, want) {
			t.Errorf("targetImageProblem(%q) = %q, want a problem containing %q", ref, p, want)
		}
	}
}

// TestScenarioTargetsArePinnedAndReal is the Story 11.1 guard (AC1, AC3).
func TestScenarioTargetsArePinnedAndReal(t *testing.T) {
	root := scenariosDir(t)
	for _, slug := range scenarioSlugs {
		manifest := filepath.Join(root, slug, "manifests", "workload.yaml")
		raw, err := os.ReadFile(manifest)
		if err != nil {
			t.Errorf("%s: read target manifest: %v", slug, err)
			continue
		}
		imgs, err := parseImages(string(raw))
		if err != nil {
			t.Errorf("%s: image walker: %v", slug, err)
			continue
		}
		if len(imgs) == 0 {
			t.Errorf("%s: no container image found in %s; a scenario must deploy a real workload", slug, manifest)
			continue
		}
		for _, img := range imgs {
			if p := targetImageProblem(img.ref); p != "" {
				t.Errorf("%s: %s: %q: %s", slug, img.where, img.ref, p)
			}
		}
	}
}

// TestScenarioManifestsPassKubeconform is the Story 11.1 schema/policy gate
// (AC2): every target manifest passes the SAME kubeconform strict check the
// chart is held to (CI: -strict, kubernetes-version 1.29.0, default schemas,
// CRDs skipped). It skips when kubeconform is not on PATH so a local
// `go test` without the tool still runs the pin guard; the helm CI job
// installs kubeconform, so the gate is real there.
func TestScenarioManifestsPassKubeconform(t *testing.T) {
	bin, err := exec.LookPath("kubeconform")
	if err != nil {
		t.Skip("kubeconform not on PATH; the helm CI job installs it and enforces this")
	}
	root := scenariosDir(t)
	var manifests []string
	for _, slug := range scenarioSlugs {
		manifests = append(manifests, filepath.Join(root, slug, "manifests", "workload.yaml"))
	}
	sort.Strings(manifests)
	args := append([]string{
		"-strict", "-summary",
		"-kubernetes-version", "1.29.0",
		"-schema-location", "default",
		"-skip", "CustomResourceDefinition",
	}, manifests...)
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("kubeconform rejected a scenario target manifest: %v\n%s", err, out)
	}
	t.Logf("kubeconform:\n%s", out)
}
