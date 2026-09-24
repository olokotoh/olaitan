//go:build helm

package helm_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// publishedChartRef is the chart a stranger installs without a clone.
const publishedChartRef = "oci://ghcr.io/olokotoh/charts/olaitan"

// chartVersion reads the version the tree is heading for from Chart.yaml.
func chartVersion(t *testing.T) string {
	t.Helper()
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
	return meta.Version
}

// installCommand is one `helm install|upgrade ... oci://.../olaitan` command
// found in a file, with its continuation lines joined.
type installCommand struct {
	where   string // file:line
	command string
}

var (
	versionFlag = regexp.MustCompile(`--version[ =]+([0-9A-Za-z.+-]+)`)
	helmInstall = regexp.MustCompile(`helm (install|upgrade)`)
)

// publishedInstallCommands finds every helm install or upgrade of the
// published chart in text. A command runs on while its line ends in a
// backslash; comment markers (`#`) and shell `echo "..."` wrappers around the
// line are ignored for that test, so the commands in the overlay headers and
// in hack/preflight.sh's closing hint are read the same way as the README's.
func publishedInstallCommands(name, text string) []installCommand {
	lines := strings.Split(text, "\n")
	continues := func(l string) bool {
		l = strings.TrimRight(l, " \t")
		l = strings.TrimSuffix(l, `"`)
		return strings.HasSuffix(l, `\`)
	}
	var out []installCommand
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		if !strings.Contains(l, publishedChartRef) || !helmInstall.MatchString(l) {
			continue
		}
		cmd := []string{l}
		j := i
		for continues(lines[j]) && j+1 < len(lines) {
			j++
			cmd = append(cmd, lines[j])
		}
		out = append(out, installCommand{where: name + ":" + strconv.Itoa(i+1), command: strings.Join(cmd, "\n")})
		i = j
	}
	return out
}

// TestReadmeInstallsTheChartVersion (Story 12.1). The README told people to
// install 1.0.0-rc3 for weeks after main had moved on, and rc3 did not start
// on a default cluster (#96). Chart.yaml's version is the release the tree is
// heading for, so every install of the published chart that the project
// prints (the README, hack/preflight.sh's closing hint, the platform overlay
// headers) must name that version. A command with no --version fails too:
// with only prerelease tags in the registry, helm's default constraint skips
// them all and the command cannot resolve a chart.
func TestReadmeInstallsTheChartVersion(t *testing.T) {
	want := chartVersion(t)
	root := filepath.Join(chartDir(t), "..", "..", "..")
	files := []string{"README.md", filepath.Join("hack", "preflight.sh")}
	overlays, err := filepath.Glob(filepath.Join(chartDir(t), "values-*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range overlays {
		rel, err := filepath.Rel(root, o)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, rel)
	}

	perFile := map[string]int{}
	total := 0
	for _, f := range files {
		raw, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range publishedInstallCommands(f, string(raw)) {
			total++
			perFile[f]++
			m := versionFlag.FindStringSubmatch(c.command)
			switch {
			case m == nil:
				t.Errorf("%s installs %s with no --version (helm skips prereleases, so it resolves nothing):\n%s", c.where, publishedChartRef, c.command)
			case m[1] != want:
				t.Errorf("%s installs chart version %s, Chart.yaml is %s", c.where, m[1], want)
			}
		}
	}
	if perFile["README.md"] == 0 {
		t.Fatal("README has no `helm install " + publishedChartRef + " --version X` command")
	}
	if perFile[filepath.Join("hack", "preflight.sh")] == 0 {
		t.Error("hack/preflight.sh no longer prints an install command of the published chart; this test would stop covering it")
	}
	if !t.Failed() {
		t.Logf("%d install commands in %d files, all at %s", total, len(perFile), want)
	}
}

// TestInstallCommandScannerBites proves the scanner reads the shapes it has
// to: an echo-wrapped command with no --version, and a commented overlay
// header with the wrong one.
func TestInstallCommandScannerBites(t *testing.T) {
	echo := "echo \"Install:  ${B}helm install olaitan " + publishedChartRef + " \\\\\"\n" +
		"echo \"            --namespace olaitan --create-namespace${X}\"\n"
	got := publishedInstallCommands("preflight", echo)
	if len(got) != 1 || versionFlag.MatchString(got[0].command) {
		t.Errorf("echo-wrapped command without --version not seen as such: %+v", got)
	}
	header := "#   helm install olaitan " + publishedChartRef + " \\\n" +
		"#     --version 0.0.1 \\\n" +
		"#     -f values-kind.yaml --namespace olaitan --create-namespace\n"
	got = publishedInstallCommands("overlay", header)
	if len(got) != 1 {
		t.Fatalf("overlay header command not found: %+v", got)
	}
	if m := versionFlag.FindStringSubmatch(got[0].command); m == nil || m[1] != "0.0.1" {
		t.Errorf("overlay header --version not read across the continuation: %+v", got)
	}
}

// TestReleaseRefusesATagThatIsNotTheChartVersion (Story 12.1 review, D1).
// The README's --version is tied to Chart.yaml (the test above). The release
// has to be tied to it too, or a tag that differs from Chart.yaml publishes
// a chart the README never names. release.yml's preflight runs
// hack/check-release-version.sh with the tag; it must pass for the tree's
// version and refuse anything else.
func TestReleaseRefusesATagThatIsNotTheChartVersion(t *testing.T) {
	root := filepath.Join(chartDir(t), "..", "..", "..")
	script := filepath.Join(root, "hack", "check-release-version.sh")
	want := chartVersion(t)
	run := func(tag string) (string, error) {
		cmd := exec.Command("bash", script, tag)
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	if out, err := run("v" + want); err != nil {
		t.Errorf("tag v%s refused although Chart.yaml is %s: %v\n%s", want, want, err, out)
	}
	for _, bad := range []string{"v9.9.9", "v" + want + ".1", want, ""} {
		if out, err := run(bad); err == nil {
			t.Errorf("tag %q accepted although Chart.yaml is %s:\n%s", bad, want, out)
		}
	}
	wf, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(wf), "hack/check-release-version.sh") {
		t.Error("release.yml does not run hack/check-release-version.sh, so a tag can differ from Chart.yaml")
	}
}
