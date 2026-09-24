//go:build helm

package helm_test

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestReadmeInstallsTheChartVersion (Story 12.1). The README told people to
// install 1.0.0-rc3 for weeks after main had moved on, and rc3 did not start
// on a default cluster (#96). Chart.yaml's version is the release the tree is
// heading for, so every `--version` in the README's install commands must be
// that version: bumping one without the other fails here.
func TestReadmeInstallsTheChartVersion(t *testing.T) {
	chart, err := os.ReadFile(filepath.Join(chartDir(t), "Chart.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		Version string `yaml:"version"`
	}
	if err := yaml.Unmarshal(chart, &meta); err != nil {
		t.Fatal(err)
	}
	readme, err := os.ReadFile(filepath.Join(chartDir(t), "..", "..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`oci://ghcr\.io/olokotoh/charts/olaitan[ \\\n]+--version ([^ \\\n]+)`)
	got := re.FindAllStringSubmatch(string(readme), -1)
	if len(got) == 0 {
		t.Fatal("README has no `helm install oci://ghcr.io/olokotoh/charts/olaitan --version X` command")
	}
	for _, m := range got {
		if m[1] != meta.Version {
			t.Errorf("README installs chart version %s, Chart.yaml is %s", m[1], meta.Version)
		}
	}
	if !t.Failed() {
		t.Logf("%d README install commands, all at %s", len(got), meta.Version)
	}
}
