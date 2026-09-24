//go:build helm

package helm_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Story 12.5 (#122): a CI job installs each published release the way the
// README tells a stranger to, on a fresh kind, and requires a real attack to
// be detected. rc3 shipped broken because nothing did. These tests pin the
// parts that can be checked without a cluster: the job runs README.md's own
// blocks (read at run time, not copied), it asserts pods Ready and a real
// detection without injecting anything, and the Release workflow cannot pass
// or move `latest` when it fails.

// The README blocks each leg runs: heading, and which ```bash block under it.
const (
	strangerHelmHeading    = "### Try it on kind"
	strangerKubectlHeading = "## Install"
)

func strangerScript(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "hack", "stranger.sh")
}

// strangerEnv is os.Environ() without STRANGER_* settings, plus extra.
func strangerEnv(extra ...string) []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "STRANGER_") {
			env = append(env, kv)
		}
	}
	return append(env, extra...)
}

// strangerRun runs the script in plan mode (prints, touches nothing).
func strangerRun(t *testing.T, leg string, env ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", strangerScript(t), leg)
	cmd.Dir = repoRoot(t)
	cmd.Env = strangerEnv(append([]string{"STRANGER_PLAN=1"}, env...)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func strangerPlan(t *testing.T, leg string, env ...string) string {
	t.Helper()
	out, err := strangerRun(t, leg, env...)
	if err != nil {
		t.Fatalf("stranger plan %s (%v) failed: %v\n%s", leg, env, err, out)
	}
	return out
}

func readmeText(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// writeReadme writes a README variant to a temp file and returns its path.
func writeReadme(t *testing.T, text string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "README.md")
	if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// readmeBashBlock is an extraction written independently of the script's:
// the n-th ```bash block after the line equal to heading, before the next
// heading. Lines inside fences are never headings (a shell comment is not).
func readmeBashBlock(text, heading string, n int) (string, error) {
	lines := strings.Split(text, "\n")
	start := -1
	for i, l := range lines {
		if l == heading {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return "", fmt.Errorf("no heading %q", heading)
	}
	inFence, isBash, count := false, false, 0
	var body []string
	for _, l := range lines[start:] {
		if !inFence {
			if strings.HasPrefix(l, "#") {
				break
			}
			if strings.HasPrefix(l, "```") {
				inFence = true
				isBash = strings.TrimSpace(strings.TrimPrefix(l, "```")) == "bash"
				if isBash {
					count++
				}
			}
			continue
		}
		if strings.HasPrefix(l, "```") {
			if isBash && count == n {
				return strings.Join(body, "\n"), nil
			}
			inFence = false
			continue
		}
		if isBash && count == n {
			body = append(body, l)
		}
	}
	return "", fmt.Errorf("no bash block %d under %q", n, heading)
}

// planBlock returns what the plan says it runs from the README.
func planBlock(t *testing.T, plan string) string {
	t.Helper()
	const begin, end = "--- README block begin\n", "\n--- README block end"
	b := strings.Index(plan, begin)
	e := strings.Index(plan, end)
	if b < 0 || e < b {
		t.Fatalf("plan does not show the README block it runs:\n%s", plan)
	}
	return plan[b+len(begin) : e]
}

// TestStrangerRunsTheReadmeHelmBlockVerbatim (AC1): the helm leg runs the
// "Try it on kind" block of README.md exactly, including its kind create.
func TestStrangerRunsTheReadmeHelmBlockVerbatim(t *testing.T) {
	want, err := readmeBashBlock(readmeText(t), strangerHelmHeading, 1)
	if err != nil {
		t.Fatal(err)
	}
	plan := strangerPlan(t, "helm")
	if got := planBlock(t, plan); got != want {
		t.Errorf("helm leg does not run the README block verbatim.\nREADME:\n%s\nplan:\n%s", want, got)
	}
	for _, must := range []string{"kind create cluster", "helm install olaitan " + publishedChartRef, "--version " + chartVersion(t)} {
		if !strings.Contains(want, must) {
			t.Errorf("README %q block no longer has %q; the job would not be the stranger path", strangerHelmHeading, must)
		}
	}
}

// TestStrangerRunsTheReadmeKubectlBlockVerbatim (AC1, D2): the kubectl leg
// runs `## Install` block 2 on a kind cluster the script creates. rc4 has no
// install.yaml, so the check uses a README naming a later version.
func TestStrangerRunsTheReadmeKubectlBlockVerbatim(t *testing.T) {
	later := strings.ReplaceAll(readmeText(t), "/releases/download/v"+chartVersion(t)+"/install.yaml", "/releases/download/v9.9.9-test/install.yaml")
	p := writeReadme(t, later)
	want, err := readmeBashBlock(later, strangerKubectlHeading, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(want, "kubectl apply -f https://github.com/olokotoh/olaitan/releases/download/v9.9.9-test/install.yaml") {
		t.Fatalf("`## Install` block 2 is not the kubectl path any more:\n%s", want)
	}
	plan := strangerPlan(t, "kubectl", "STRANGER_README="+p)
	if got := planBlock(t, plan); got != want {
		t.Errorf("kubectl leg does not run the README block verbatim.\nREADME:\n%s\nplan:\n%s", want, got)
	}
	kind := strings.Index(plan, "+ kind create cluster --name olaitan")
	if kind < 0 || kind > strings.Index(plan, "--- README block begin") {
		t.Errorf("kubectl leg must create a fresh kind cluster before the README block:\n%s", plan)
	}
	if strings.Contains(plan, "skipped") {
		t.Errorf("kubectl leg skipped for 9.9.9-test, a version after install.yaml exists:\n%s", plan)
	}
}

// TestStrangerReadsTheReadmeAtRunTime (AC1): a README change reaches the job.
// A broken command in the README is the command the job runs.
func TestStrangerReadsTheReadmeAtRunTime(t *testing.T) {
	v := chartVersion(t)
	broken := strings.Replace(readmeText(t), "  --version "+v+" \\\n  --namespace olaitan --create-namespace --wait", "  --version 0.0.0-broken \\\n  --namespace olaitan --create-namespace --wait", 1)
	if broken == readmeText(t) {
		t.Fatal("could not find the Try it on kind --version line to break")
	}
	plan := strangerPlan(t, "helm", "STRANGER_README="+writeReadme(t, broken))
	if !strings.Contains(planBlock(t, plan), "--version 0.0.0-broken") {
		t.Errorf("a broken README command did not reach the job:\n%s", plan)
	}
}

// TestStrangerRefusesAnotherVersion (D3): on a tag run the README must name
// the tag's version.
func TestStrangerRefusesAnotherVersion(t *testing.T) {
	if out, err := strangerRun(t, "helm", "STRANGER_EXPECT_VERSION="+chartVersion(t)); err != nil {
		t.Errorf("expected version %s refused: %v\n%s", chartVersion(t), err, out)
	}
	for _, leg := range []string{"helm", "kubectl"} {
		out, err := strangerRun(t, leg, "STRANGER_EXPECT_VERSION=9.9.9")
		if err == nil {
			t.Errorf("%s leg accepted a README at %s when 9.9.9 was expected:\n%s", leg, chartVersion(t), out)
		}
	}
}

// TestStrangerKubectlSkipsOnlyReleasesWithoutTheAsset (D2): releases before
// Story 12.4 have no install.yaml. Only those are skipped.
func TestStrangerKubectlSkipsOnlyReleasesWithoutTheAsset(t *testing.T) {
	for _, old := range []string{"1.0.0-rc1", "1.0.0-rc2", "1.0.0-rc3", "1.0.0-rc4"} {
		text := regexp.MustCompile(`/releases/download/v[^/]+/install\.yaml`).ReplaceAllString(readmeText(t), "/releases/download/v"+old+"/install.yaml")
		plan := strangerPlan(t, "kubectl", "STRANGER_README="+writeReadme(t, text))
		if !strings.Contains(plan, "skipped") || strings.Contains(plan, "+ kind create cluster") {
			t.Errorf("kubectl leg for %s (no install.yaml) must be skipped before any cluster:\n%s", old, plan)
		}
	}
	for _, later := range []string{"1.0.0-rc5", "1.0.0", "1.0.0-rc40"} {
		text := regexp.MustCompile(`/releases/download/v[^/]+/install\.yaml`).ReplaceAllString(readmeText(t), "/releases/download/v"+later+"/install.yaml")
		plan := strangerPlan(t, "kubectl", "STRANGER_README="+writeReadme(t, text))
		if strings.Contains(plan, "skipped") {
			t.Errorf("kubectl leg skipped for %s:\n%s", later, plan)
		}
	}
}

// TestStrangerFailsWithoutTheBlock (D1): a moved or renamed block fails the
// job instead of running something else.
func TestStrangerFailsWithoutTheBlock(t *testing.T) {
	gone := strings.Replace(readmeText(t), strangerHelmHeading+"\n", "### Try it somewhere\n", 1)
	if out, err := strangerRun(t, "helm", "STRANGER_README="+writeReadme(t, gone)); err == nil {
		t.Errorf("helm leg passed with no %q heading:\n%s", strangerHelmHeading, out)
	}
	// The heading is there but its block is not the published helm install.
	swapped := strings.Replace(readmeText(t), "helm install olaitan "+publishedChartRef+" \\\n  --version "+chartVersion(t)+" \\\n  --namespace olaitan --create-namespace --wait",
		"helm install olaitan ./deploy/helm/olaitan \\\n  --version "+chartVersion(t)+" \\\n  --namespace olaitan --create-namespace --wait", 1)
	if swapped == readmeText(t) {
		t.Fatal("could not rewrite the Try it on kind helm command")
	}
	if out, err := strangerRun(t, "helm", "STRANGER_README="+writeReadme(t, swapped)); err == nil {
		t.Errorf("helm leg ran a block that does not install the published chart:\n%s", out)
	}
	if out, err := strangerRun(t, "nope"); err == nil {
		t.Errorf("unknown leg accepted:\n%s", out)
	}
}

// TestStrangerExtractorSkipsCommentsInFences: a `# comment` inside a code
// block is not a heading, and only bash blocks count.
func TestStrangerExtractorSkipsCommentsInFences(t *testing.T) {
	text := "## Here\n\n```\nnot bash\n```\n\n```bash\n# a comment\necho one\n```\n\n```bash\necho two\n```\n\n## Next\n\n```bash\necho three\n```\n"
	p := writeReadme(t, text)
	for n, want := range map[string]string{"1": "# a comment\necho one", "2": "echo two"} {
		cmd := exec.Command("bash", "-c", `source "$1"; shift; "$@"`, "stranger-test", strangerScript(t), "stranger_readme_block", p, "## Here", n)
		cmd.Env = strangerEnv("STRANGER_PLAN=1")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("block %s: %v", n, err)
		}
		if got := strings.TrimSuffix(string(out), "\n"); got != want {
			t.Errorf("block %s = %q, want %q", n, got, want)
		}
	}
	cmd := exec.Command("bash", "-c", `source "$1"; shift; "$@"`, "stranger-test", strangerScript(t), "stranger_readme_block", p, "## Here", "3")
	cmd.Env = strangerEnv("STRANGER_PLAN=1")
	if out, err := cmd.Output(); err == nil {
		t.Errorf("block 3 under ## Here (it is under ## Next) was found: %q", out)
	}
}

var (
	strangerRollout = regexp.MustCompile(`(?m)^\+ kubectl -n olaitan rollout status (daemonset|deployment|statefulset)`)
	strangerWaitAll = regexp.MustCompile(`(?m)^\+ kubectl -n olaitan wait pod --all --for=condition=Ready`)
	strangerFalco   = regexp.MustCompile(`(?m)^\+ kubectl -n olaitan wait pod -l app\.kubernetes\.io/name=falco --for=condition=Ready`)
	strangerExec    = regexp.MustCompile(`(?m)^\+ kubectl -n (\S+) exec \S+ -- cat /etc/shadow$`)
)

// TestStrangerAssertsReadyAndARealAttack (AC2): after the README block, the
// job waits for every workload and pod on its own (the kubectl path has no
// wait in the README), requires a Ready Falco pod, and runs a real read of
// /etc/shadow in a namespace the agent scores, from a pinned image.
func TestStrangerAssertsReadyAndARealAttack(t *testing.T) {
	for _, leg := range []string{"helm", "kubectl"} {
		text := readmeText(t)
		if leg == "kubectl" {
			text = regexp.MustCompile(`/releases/download/v[^/]+/install\.yaml`).ReplaceAllString(text, "/releases/download/v9.9.9-test/install.yaml")
		}
		plan := strangerPlan(t, leg, "STRANGER_README="+writeReadme(t, text))
		after := plan[strings.Index(plan, "--- README block end"):]
		if n := len(strangerRollout.FindAllString(after, -1)); n != 3 {
			t.Errorf("%s leg: want rollout status for daemonset, deployment and statefulset after the README block, got %d:\n%s", leg, n, after)
		}
		for name, re := range map[string]*regexp.Regexp{"every pod Ready": strangerWaitAll, "a Ready Falco pod": strangerFalco} {
			if !re.MatchString(after) {
				t.Errorf("%s leg does not assert %s after the README block:\n%s", leg, name, after)
			}
		}
		e := strangerExec.FindStringSubmatch(after)
		if e == nil {
			t.Fatalf("%s leg runs no `kubectl -n <ns> exec <pod> -- cat /etc/shadow`:\n%s", leg, after)
		}
		for _, ex := range shippedExclusions(t) {
			if e[1] == ex {
				t.Errorf("%s leg attacks in %s, which the shipped config excludes or never scores", leg, e[1])
			}
		}
		img := planPodImg.FindStringSubmatch(after)
		if img == nil || !regexp.MustCompile(`^[^@\s]+:[^@\s]+@sha256:[0-9a-f]{64}$`).MatchString(img[1]) {
			t.Errorf("%s leg attack pod image is not pinned by tag and digest: %v", leg, img)
		}
		if !strings.Contains(after, "Falco alert on /etc/shadow") || !strings.Contains(after, "FSM transition") {
			t.Errorf("%s leg does not say it requires both the Falco alert and the transition:\n%s", leg, after)
		}
	}
}

// TestStrangerHasNoInjection (AC2): same rule as the quickstart. The job
// cannot fake the detection or turn Falco off.
func TestStrangerHasNoInjection(t *testing.T) {
	files := []string{filepath.Join("hack", "stranger.sh"), filepath.Join(".github", "workflows", "stranger.yml")}
	forbidden := []*regexp.Regexp{
		regexp.MustCompile(`(?i)nats\s+(pub|publish|req|request|stream\s+add)`),
		regexp.MustCompile(`(?i)jetstream`),
		regexp.MustCompile(`port-forward`),
		regexp.MustCompile(`:4222`),
		regexp.MustCompile(`olaitan\.events\.`),
		regexp.MustCompile(`falco\.enabled\s*=\s*false`),
		regexp.MustCompile(`endpoints\.falco`),
		regexp.MustCompile(`\bgo (run|build)\b`),
		regexp.MustCompile(`--set\b`),
		regexp.MustCompile(`deploy/helm/olaitan`),
	}
	for _, f := range files {
		raw, err := os.ReadFile(filepath.Join(repoRoot(t), f))
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			for _, re := range forbidden {
				if re.MatchString(line) {
					t.Errorf("%s:%d matches %s (the stranger job must not inject, turn Falco off or use the checkout's chart): %s", f, i+1, re, strings.TrimSpace(line))
				}
			}
		}
	}
}

// workflowDoc is the part of a workflow file these tests read.
type workflowDoc struct {
	On   map[string]yaml.Node   `yaml:"on"`
	Jobs map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	Needs    yaml.Node         `yaml:"needs"`
	If       string            `yaml:"if"`
	Uses     string            `yaml:"uses"`
	With     map[string]string `yaml:"with"`
	Strategy struct {
		FailFast *bool `yaml:"fail-fast"`
		Matrix   struct {
			Leg []string `yaml:"leg"`
		} `yaml:"matrix"`
	} `yaml:"strategy"`
	Permissions yaml.Node `yaml:"permissions"`
	Steps       []struct {
		Name string            `yaml:"name"`
		Uses string            `yaml:"uses"`
		Run  string            `yaml:"run"`
		With map[string]string `yaml:"with"`
		If   string            `yaml:"if"`
	} `yaml:"steps"`
}

func readWorkflow(t *testing.T, name string) (workflowDoc, string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", name))
	if err != nil {
		t.Fatal(err)
	}
	var wf workflowDoc
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return wf, string(raw)
}

func needsList(n yaml.Node) []string {
	switch n.Kind {
	case yaml.ScalarNode:
		return []string{n.Value}
	case yaml.SequenceNode:
		var out []string
		for _, c := range n.Content {
			out = append(out, c.Value)
		}
		return out
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// TestStrangerWorkflow (AC1, D5, D6): nightly, callable from the release,
// dispatchable, both legs on a fresh kind with inotify raised.
func TestStrangerWorkflow(t *testing.T) {
	wf, raw := readWorkflow(t, "stranger.yml")
	for _, trig := range []string{"schedule", "workflow_call", "workflow_dispatch"} {
		if _, ok := wf.On[trig]; !ok {
			t.Errorf("stranger.yml has no %s trigger", trig)
		}
	}
	if pr, ok := wf.On["pull_request"]; ok {
		var spec struct {
			Paths []string `yaml:"paths"`
		}
		if err := pr.Decode(&spec); err != nil || len(spec.Paths) == 0 {
			t.Errorf("stranger.yml pull_request trigger must be limited to the job's own files: %v %+v", err, spec)
		}
		for _, p := range spec.Paths {
			if p == "README.md" || p == "**" {
				t.Errorf("stranger.yml runs on PRs touching %s; a release-cut PR names an unpublished version and would go red", p)
			}
		}
	}
	job, ok := wf.Jobs["stranger"]
	if !ok {
		t.Fatal("stranger.yml has no `stranger` job")
	}
	if !contains(job.Strategy.Matrix.Leg, "helm") || !contains(job.Strategy.Matrix.Leg, "kubectl") {
		t.Errorf("stranger job must run both legs, got %v", job.Strategy.Matrix.Leg)
	}
	if job.Strategy.FailFast == nil || *job.Strategy.FailFast {
		t.Error("stranger job must set fail-fast: false so one leg's failure still shows the other's result")
	}
	var kindOK, inotify, runs, runsAfterKind bool
	for _, s := range job.Steps {
		if strings.HasPrefix(s.Uses, "helm/kind-action@") {
			kindOK = s.With["install_only"] == "true" && s.With["version"] == "v0.30.0"
		}
		if strings.Contains(s.Run, "fs.inotify.max_user_instances=1024") && strings.Contains(s.Run, "fs.inotify.max_user_watches=1048576") {
			inotify = true
		}
		if strings.Contains(s.Run, "hack/stranger.sh") {
			runs = true
			runsAfterKind = kindOK && inotify
		}
	}
	if !kindOK {
		t.Error("stranger job must install kind v0.30.0 only (helm/kind-action install_only: true); the README block creates the cluster")
	}
	if !inotify {
		t.Error("stranger job does not raise inotify to the README's verification values (1024 / 1048576)")
	}
	if !runs || !runsAfterKind {
		t.Error("stranger job must run hack/stranger.sh after installing kind and raising inotify")
	}
	if !strings.Contains(raw, "STRANGER_EXPECT_VERSION") {
		t.Error("stranger.yml does not pass the expected version to the script")
	}
}

// TestReleaseIsMarkedFailedWithoutTheStrangerJob (AC3, D4): the Release
// workflow runs the stranger job after the GitHub Release exists, `latest`
// waits for it, and a failure edits the release to say so.
func TestReleaseIsMarkedFailedWithoutTheStrangerJob(t *testing.T) {
	wf, _ := readWorkflow(t, "release.yml")
	s, ok := wf.Jobs["stranger"]
	if !ok {
		t.Fatal("release.yml has no `stranger` job")
	}
	if s.Uses != "./.github/workflows/stranger.yml" {
		t.Errorf("release.yml stranger job uses %q, want ./.github/workflows/stranger.yml", s.Uses)
	}
	if !contains(needsList(s.Needs), "release") {
		t.Errorf("stranger job must run after `release` (the kubectl leg downloads its install.yaml), needs %v", needsList(s.Needs))
	}
	if !strings.Contains(s.With["expect_version"], "needs.preflight.outputs.version") || !strings.Contains(s.With["ref"], "github.ref_name") {
		t.Errorf("stranger job must test the tag's README at the tag's version, with: %v", s.With)
	}
	if p, ok := wf.Jobs["promote"]; !ok || !contains(needsList(p.Needs), "stranger") {
		t.Error("promote (moves `latest`) must need the stranger job")
	}
	var marker string
	for name, j := range wf.Jobs {
		if strings.Contains(j.If, "needs.stranger.result == 'failure'") {
			marker = name
			var edits bool
			for _, st := range j.Steps {
				if strings.Contains(st.Run, "gh release edit") && strings.Contains(st.Run, "--prerelease") && strings.Contains(st.Run, "FAILED stranger-path check") {
					edits = true
				}
			}
			if !edits {
				t.Errorf("job %s runs on a stranger failure but does not edit the release (gh release edit --prerelease, title FAILED stranger-path check)", name)
			}
			if !contains(needsList(j.Needs), "stranger") {
				t.Errorf("job %s must need stranger", name)
			}
		}
	}
	if marker == "" {
		t.Error("release.yml has no job that runs when needs.stranger.result == 'failure'")
	}
}
