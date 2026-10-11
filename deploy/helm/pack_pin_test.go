//go:build helm

package helm_test

import (
	"os"
	"path/filepath"
	"testing"
)

// Story 11.2c (AC2): every image an attack PACK deploys is pinned by tag AND
// digest, exactly like the Story 11.1 scenario targets and the Story 12.6
// chart images. The packs run third-party attacker tooling in-cluster, so an
// unpinned or :latest image there is the same reproducibility and
// supply-chain hole the chart guard exists to close - held to the same bar.
//
// It runs in the existing helm CI job (go test ./deploy/helm/... -tags=helm).
// It globs committed pack manifests, so a pack whose image is not yet built
// and pinned (the Stratus wrapper, built at the supervised step) simply has no
// manifest here yet and is not falsely reported; the moment its manifest lands
// it is held to tag@sha256 like the rest.

// packManifestsDir is deploy/demo/packs under the repo root.
func packManifestsDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "deploy", "demo", "packs")
}

// TestPackImagesArePinned walks every committed pack Job manifest and asserts
// each container image is a real, tag@sha256-pinned reference (reusing the
// Story 12.6 predicate). It requires at least one pack manifest to exist, so a
// mis-globbed path cannot make the guard vacuously pass.
func TestPackImagesArePinned(t *testing.T) {
	root := packManifestsDir(t)
	matches, err := filepath.Glob(filepath.Join(root, "*", "manifests", "*.y*ml"))
	if err != nil {
		t.Fatalf("glob pack manifests: %v", err)
	}
	if len(matches) == 0 {
		t.Fatalf("no pack manifests found under %s; Story 11.2c must commit at least the event-generator Job", root)
	}
	checked := 0
	for _, m := range matches {
		raw, err := os.ReadFile(m)
		if err != nil {
			t.Errorf("%s: read: %v", m, err)
			continue
		}
		imgs, err := parseImages(string(raw))
		if err != nil {
			t.Errorf("%s: image walker: %v", m, err)
			continue
		}
		if len(imgs) == 0 {
			t.Errorf("%s: no container image found; a pack Job must deploy a real image", m)
			continue
		}
		for _, img := range imgs {
			if p := imagePinProblem(img.ref); p != "" {
				t.Errorf("%s: %s: %q: %s", m, img.where, img.ref, p)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("pack pin guard checked zero images")
	}
}
