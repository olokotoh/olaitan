//go:build helm

package helm_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The chart does not ship MinIO. MinIO is test infrastructure only: the
// forensics-integration and report-archive-integration CI jobs start it with
// `docker run`, and the forensics e2e fixture deploys it into kind. Those
// references sit outside the chart renders TestEveryRenderedImageIsPinned
// walks, so this test holds them to the same Story 12.6 rule: tag AND digest.
//
// MinIO archived its community edition. quay.io/minio/minio and
// quay.io/minio/mc no longer allow anonymous pulls, Docker Hub minio/minio is
// gone, and dl.min.io answers 410 for every community release. A tag-only
// reference to any of them fails before a test runs, so they are refused
// here by name as well.

// minioImageFiles are the files that start a MinIO server image, and how
// many references each one must contain (so the scan cannot pass blind).
var minioImageFiles = map[string]int{
	".github/workflows/ci.yml":      2,
	"tests/e2e/fixtures/minio.yaml": 1,
}

// withdrawnMinIORepos no longer serve anonymous pulls.
var withdrawnMinIORepos = []string{
	"quay.io/minio/minio",
	"docker.io/minio/minio",
	"minio/minio",
}

// minioImageRE matches an image reference whose last path component is
// minio, followed by a tag or digest. A URL such as
// http://localhost:9000/minio/health/live and a Service address such as
// minio:9000 do not match.
var minioImageRE = regexp.MustCompile(`(?:^|[\s"'])((?:[a-z0-9.-]+(?::[0-9]+)?/)(?:[a-z0-9._-]+/)*minio[:@][^\s"'\\]+)`)

func TestMinIOTestImageIsPinned(t *testing.T) {
	root := repoRoot(t)
	seen := map[string][]string{}
	for rel, want := range minioImageFiles {
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		var refs []string
		for i, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			for _, m := range minioImageRE.FindAllStringSubmatch(line, -1) {
				ref := m[1]
				refs = append(refs, ref)
				seen[ref] = append(seen[ref], rel)
				if p := imagePinProblem(ref); p != "" {
					t.Errorf("%s:%d: MinIO image %q: %s", rel, i+1, ref, p)
				}
				name, _, _ := strings.Cut(ref, "@")
				if j := strings.LastIndex(name, ":"); j > strings.LastIndex(name, "/") {
					name = name[:j]
				}
				for _, w := range withdrawnMinIORepos {
					if name == w {
						t.Errorf("%s:%d: MinIO image %q: %s no longer serves anonymous pulls", rel, i+1, ref, w)
					}
				}
			}
		}
		if len(refs) != want {
			t.Errorf("%s: found %d MinIO image references %q, want %d", rel, len(refs), refs, want)
		}
	}
	if len(seen) > 1 {
		t.Errorf("CI and the e2e fixture must run one MinIO image, found %d: %v", len(seen), seen)
	}
}
