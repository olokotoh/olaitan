//go:build helm

package helm_test

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// --- Story 10.1: Falco pinned to a release that runs on kernel 7.x ------
//
// Falco 0.43.1 (chart 8.0.2) exits every few minutes on kernel 7.x with
// "could not parse param ... type 223 (clone)" / "type 307 (openat)". The
// cause is the modern_bpf per-CPU auxmap being overwritten when a BPF
// program is preempted (falcosecurity/libs#2719), fixed by
// falcosecurity/libs#3086 and first shipped in Falco 0.45.0-rc1
// (falcosecurity/falco#3955). hack/falco-support.env records the pin once;
// these tests hold the chart, the docs and preflight to it.

func repoRoot(t *testing.T) string {
	t.Helper()
	return filepath.Dir(filepath.Dir(filepath.Dir(chartDir(t))))
}

// falcoSupport parses hack/falco-support.env (KEY=VALUE, # comments).
func falcoSupport(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.Open(filepath.Join(repoRoot(t), "hack", "falco-support.env"))
	if err != nil {
		t.Fatalf("open hack/falco-support.env: %v", err)
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		ln := strings.TrimSpace(sc.Text())
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		k, v, ok := strings.Cut(ln, "=")
		if !ok {
			t.Fatalf("falco-support.env: malformed line %q", ln)
		}
		out[k] = strings.Trim(v, `"`)
	}
	for _, k := range []string{"FALCO_CHART_VERSION", "FALCO_PINNED_VERSION", "FALCO_MIN_KERNEL", "FALCO_MAX_TESTED_KERNEL", "FALCO_PREEMPT_FIX_VERSION"} {
		if out[k] == "" {
			t.Fatalf("falco-support.env has no %s", k)
		}
	}
	return out
}

func TestFalcoPinIsTheOneRecorded(t *testing.T) {
	sup := falcoSupport(t)
	rendered := helmTemplate(t, nil)

	falcoDS := docByKindName(t, rendered, "DaemonSet", "falco")
	var image string
	for _, c := range falcoDS["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any) {
		if cm := c.(map[string]any); cm["name"] == "falco" {
			image, _ = cm["image"].(string)
		}
	}
	if want := "docker.io/falcosecurity/falco:" + sup["FALCO_PINNED_VERSION"]; image != want {
		t.Errorf("Falco image = %q, want %q (hack/falco-support.env)", image, want)
	}

	// Review of #133: the kmod/driver-loader fallback (for nodes without
	// BTF) must build the driver from the same pinned release, or it runs
	// the pre-fix driver under the pinned userspace.
	kmod := helmTemplate(t, []string{"falco.driver.kind=kmod"})
	kmodDS := docByKindName(t, kmod, "DaemonSet", "falco")
	var loader string
	for _, c := range kmodDS["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["initContainers"].([]any) {
		cm := c.(map[string]any)
		if strings.Contains(fmt.Sprint(cm["image"]), "falco-driver-loader") {
			loader, _ = cm["image"].(string)
		}
	}
	if want := "docker.io/falcosecurity/falco-driver-loader:" + sup["FALCO_PINNED_VERSION"]; loader != want {
		t.Errorf("driver-loader image with kind=kmod = %q, want %q", loader, want)
	}

	raw, err := os.ReadFile(filepath.Join(chartDir(t), "Chart.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var chart struct {
		Dependencies []struct{ Name, Version string } `yaml:"dependencies"`
	}
	if err := yaml.Unmarshal(raw, &chart); err != nil {
		t.Fatal(err)
	}
	var dep string
	for _, d := range chart.Dependencies {
		if d.Name == "falco" {
			dep = d.Version
		}
	}
	if dep != sup["FALCO_CHART_VERSION"] {
		t.Errorf("Chart.yaml falco dependency = %q, want %q", dep, sup["FALCO_CHART_VERSION"])
	}

	// The evaluation envelope records the rule corpus Falco ships, which
	// moves with the chart (eval/manifest.yaml says so).
	man, err := os.ReadFile(filepath.Join(repoRoot(t), "eval", "manifest.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "falco_rule_corpus_tag: falco-chart-" + sup["FALCO_CHART_VERSION"]; !strings.Contains(string(man), want) {
		t.Errorf("eval/manifest.yaml does not pin %q", want)
	}

	// The pin carries its evidence where operators look for it.
	doc, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "platform-support-matrix.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{sup["FALCO_PINNED_VERSION"], "falcosecurity/libs#3086", "falcosecurity/falco#3955"} {
		if !strings.Contains(string(doc), want) {
			t.Errorf("docs/platform-support-matrix.md does not record %q", want)
		}
	}
}

// TestFalcoConfigHasNoGRPC closes the loop Story 10.2 left open: chart 8.x
// still rendered disabled grpc keys. From chart 9.x they must be gone.
func TestFalcoConfigHasNoGRPC(t *testing.T) {
	cfg := renderedFalcoConfig(t, helmTemplate(t, nil))
	for _, k := range []string{"grpc", "grpc_output"} {
		if _, ok := cfg[k]; ok {
			t.Errorf("rendered falco.yaml still has a %s block", k)
		}
	}
	if d, _ := cfg["engine"].(map[string]any); d == nil || d["kind"] != "modern_ebpf" {
		t.Errorf("engine = %v, want kind modern_ebpf", cfg["engine"])
	}
}

// verdict runs preflight's kernel check on its own, with the support file
// values optionally overridden.
func verdict(t *testing.T, kernel string, env ...string) (string, int) {
	t.Helper()
	root := repoRoot(t)
	cmd := exec.Command("bash", "-c", `source hack/lib/falco-kernel.sh && falco_kernel_verdict "$1"`, "_", kernel)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run verdict: %v", err)
	}
	return string(out), code
}

// Exit codes mirror preflight's buckets: 0 ok, 1 blocker, 3 caveat.
func TestPreflightFalcoKernelVerdict(t *testing.T) {
	sup := falcoSupport(t)
	cases := []struct {
		name, kernel string
		env          []string
		code         int
		want         string
	}{
		{"pinned Falco on the kernel we soaked", "7.0.0-31-generic", nil, 0, sup["FALCO_PINNED_VERSION"]},
		{"older mainstream kernel", "6.8.0-45-generic", nil, 0, "supported"},
		{"known crash: pre-fix Falco on 7.x", "7.0.0-31-generic", []string{"FALCO_PINNED_VERSION=0.43.1"}, 1, "BLOCKER"},
		{"known crash names the fix", "7.1.2-1-default", []string{"FALCO_PINNED_VERSION=0.44.1"}, 1, "libs#3086"},
		{"pre-fix Falco is fine below 7.0", "6.12.94", []string{"FALCO_PINNED_VERSION=0.43.1"}, 0, "supported"},
		{"GA of the fix release counts as fixed", "7.0.0-31-generic", []string{"FALCO_PINNED_VERSION=0.45.0"}, 0, "supported"},
		{"newer than anything tested", "7.4.0-1-generic", nil, 3, "not been tested"},
		{"below the modern_ebpf floor", "4.18.0-553.el8_10.x86_64", nil, 3, "bpftool"},
		{"unparseable", "", nil, 3, "could not read"},
	}
	// Review of #133: without the support file the verdict must be a
	// caveat, never exit 1 (which preflight counts as a BLOCKER).
	t.Run("support file missing", func(t *testing.T) {
		dir := t.TempDir()
		lib, _ := os.ReadFile(filepath.Join(repoRoot(t), "hack", "lib", "falco-kernel.sh"))
		if err := os.MkdirAll(filepath.Join(dir, "lib"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "lib", "falco-kernel.sh"), lib, 0o644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("bash", "-uc", `source lib/falco-kernel.sh && falco_kernel_verdict 6.8.0-45-generic`)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
		if code != 3 || !strings.Contains(string(out), "falco-support.env") {
			t.Errorf("missing support file: exit %d, output %q; want exit 3 naming the file", code, out)
		}
	})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, code := verdict(t, tc.kernel, tc.env...)
			if code != tc.code {
				t.Errorf("exit %d, want %d; output:\n%s", code, tc.code, out)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("output does not mention %q:\n%s", tc.want, out)
			}
			if tc.code != 1 && strings.Contains(out, "BLOCKER") {
				t.Errorf("non-blocking case printed BLOCKER:\n%s", out)
			}
		})
	}
}

// TestPreflightRunsTheKernelCheck: the verdict only helps if preflight.sh
// calls it on the node kernel and counts a blocker as a blocker.
func TestPreflightRunsTheKernelCheck(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "hack", "preflight.sh"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{"lib/falco-kernel.sh", `falco_kernel_verdict "$KERNEL"`, "BLOCKERS=$((BLOCKERS+1))"} {
		if !strings.Contains(s, want) {
			t.Errorf("hack/preflight.sh does not contain %q", want)
		}
	}
}

// --- Story 10.4: Falco is never disabled to make a test pass ------------

// TestNoTestPathDisablesFalco is the CI guard for Story 10.4. Every e2e
// target used to install with falco.enabled=false, on the stated grounds
// that Falco's eBPF probe cannot load inside kind. That was false on any
// BTF kernel (Falco's modern_ebpf runs in kind; it has on every run since
// Story 10.1), and it meant the Falco -> collector -> aggregator path was
// never exercised by a test. The rule (olaitan CLAUDE.local.md): if Falco
// breaks, fix Falco.
func TestNoTestPathDisablesFalco(t *testing.T) {
	root := repoRoot(t)
	disable := regexp.MustCompile(`falco\.enabled\s*[=:]\s*false`)
	falseClaims := []string{
		"eBPF probe is unavailable inside kind",
		"eBPF is host-scoped",
		"cannot load inside kind",
		"does not have the\n// eBPF subsystem mounted",
	}
	var files []string
	add := func(glob string) {
		m, err := filepath.Glob(filepath.Join(root, glob))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	add("Makefile")
	add(".github/workflows/*.yml")
	add("tests/e2e/*.go")
	add("tests/e2e/fixtures/*")
	add("hack/*.yaml")
	add("hack/*.sh")
	if len(files) < 5 {
		t.Fatalf("scanned only %d files; the guard is not looking where the tests live", len(files))
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		rel, _ := filepath.Rel(root, f)
		for i, line := range strings.Split(string(raw), "\n") {
			// preflight.sh tells an operator on a locked-down platform to
			// run their own Falco; that is advice, not a test disabling it.
			if rel == "hack/preflight.sh" {
				continue
			}
			if disable.MatchString(line) {
				t.Errorf("%s:%d disables Falco: %s", rel, i+1, strings.TrimSpace(line))
			}
		}
		for _, claim := range falseClaims {
			if strings.Contains(string(raw), claim) {
				t.Errorf("%s repeats the false claim %q", rel, claim)
			}
		}
	}
}
