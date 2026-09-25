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
	broken := strings.Replace(readmeText(t), "  --version "+v+" \\\n  -f "+kindOverlayURL(v)+" \\\n", "  --version 0.0.0-broken \\\n  -f "+kindOverlayURL(v)+" \\\n", 1)
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
	swapped := strings.Replace(readmeText(t), "helm install olaitan "+publishedChartRef+" \\\n  --version "+chartVersion(t)+" \\\n  -f ",
		"helm install olaitan ./deploy/helm/olaitan \\\n  --version "+chartVersion(t)+" \\\n  -f ", 1)
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
		end := strings.Index(plan, "--- README block end")
		if end == -1 {
			t.Fatalf("%s leg plan has no README block end marker:\n%s", leg, plan)
		}
		after := plan[end:]
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
	Needs           yaml.Node         `yaml:"needs"`
	If              string            `yaml:"if"`
	Uses            string            `yaml:"uses"`
	With            map[string]string `yaml:"with"`
	ContinueOnError *yaml.Node        `yaml:"continue-on-error"`
	Strategy        struct {
		FailFast *bool `yaml:"fail-fast"`
		Matrix   struct {
			Leg []string `yaml:"leg"`
		} `yaml:"matrix"`
	} `yaml:"strategy"`
	Permissions map[string]string `yaml:"permissions"`
	Steps       []workflowStep    `yaml:"steps"`
}

type workflowStep struct {
	Name            string            `yaml:"name"`
	Uses            string            `yaml:"uses"`
	Run             string            `yaml:"run"`
	With            map[string]string `yaml:"with"`
	Env             map[string]string `yaml:"env"`
	If              string            `yaml:"if"`
	ContinueOnError *yaml.Node        `yaml:"continue-on-error"`
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
		// hack/stranger.sh sources hack/quickstart.sh (parsers, demo image),
		// so a change there changes this job too (review F10).
		for _, want := range []string{".github/workflows/stranger.yml", "hack/stranger.sh", "hack/quickstart.sh"} {
			if !contains(spec.Paths, want) {
				t.Errorf("stranger.yml pull_request paths miss %s: %v", want, spec.Paths)
			}
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

// ---------------------------------------------------------------------------
// GitHub Actions `if:` semantics, enough to evaluate the release job graph.
// The review (F3) found that string matching let three mutations through
// (always() removed from mark-failed, always() added to promote, `|| true`
// on the stranger step). These tests decide what each job DOES for a given
// stranger result instead of what its text contains.
// ---------------------------------------------------------------------------

// ghaStatusFn is a status check function; a job `if:` without one gets an
// implicit success() && in front (GitHub's rule).
var ghaStatusFn = regexp.MustCompile(`\b(always|success|failure|cancelled)\(\)`)

// ghaCtx is what an `if:` can see: status functions and context values.
type ghaCtx struct {
	success, failure, cancelled bool
	values                      map[string]string // e.g. needs.stranger.result
}

type ghaVal struct {
	isBool bool
	b      bool
	s      string
}

func (v ghaVal) truthy() bool {
	if v.isBool {
		return v.b
	}
	return v.s != ""
}

func (v ghaVal) str() string {
	if v.isBool {
		return fmt.Sprint(v.b)
	}
	return v.s
}

var ghaToken = regexp.MustCompile(`\s*(\$\{\{|\}\}|==|!=|&&|\|\||!|\(|\)|'(?:[^']|'')*'|[A-Za-z_][A-Za-z0-9_.-]*)`)

type ghaParser struct {
	toks []string
	pos  int
	ctx  ghaCtx
	err  error
}

func (p *ghaParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *ghaParser) next() string {
	t := p.peek()
	p.pos++
	return t
}

func (p *ghaParser) fail(format string, a ...any) ghaVal {
	if p.err == nil {
		p.err = fmt.Errorf(format, a...)
	}
	return ghaVal{}
}

func (p *ghaParser) or() ghaVal {
	v := p.and()
	for p.peek() == "||" {
		p.next()
		r := p.and()
		v = ghaVal{isBool: true, b: v.truthy() || r.truthy()}
	}
	return v
}

func (p *ghaParser) and() ghaVal {
	v := p.cmp()
	for p.peek() == "&&" {
		p.next()
		r := p.cmp()
		v = ghaVal{isBool: true, b: v.truthy() && r.truthy()}
	}
	return v
}

func (p *ghaParser) cmp() ghaVal {
	v := p.unary()
	if op := p.peek(); op == "==" || op == "!=" {
		p.next()
		r := p.unary()
		eq := strings.EqualFold(v.str(), r.str())
		return ghaVal{isBool: true, b: eq == (op == "==")}
	}
	return v
}

func (p *ghaParser) unary() ghaVal {
	if p.peek() == "!" {
		p.next()
		return ghaVal{isBool: true, b: !p.unary().truthy()}
	}
	return p.primary()
}

func (p *ghaParser) primary() ghaVal {
	t := p.next()
	switch {
	case t == "(":
		v := p.or()
		if p.next() != ")" {
			return p.fail("missing )")
		}
		return v
	case strings.HasPrefix(t, "'"):
		return ghaVal{s: strings.ReplaceAll(t[1:len(t)-1], "''", "'")}
	case t == "true" || t == "false":
		return ghaVal{isBool: true, b: t == "true"}
	case p.peek() == "(":
		p.next()
		if p.next() != ")" {
			return p.fail("function %s takes no arguments here", t)
		}
		switch t {
		case "always":
			return ghaVal{isBool: true, b: true}
		case "success":
			return ghaVal{isBool: true, b: p.ctx.success}
		case "failure":
			return ghaVal{isBool: true, b: p.ctx.failure}
		case "cancelled":
			return ghaVal{isBool: true, b: p.ctx.cancelled}
		}
		return p.fail("unknown function %s()", t)
	case t != "":
		v, ok := p.ctx.values[t]
		if !ok {
			return p.fail("unknown context value %s", t)
		}
		return ghaVal{s: v}
	}
	return p.fail("unexpected end of expression")
}

// ghaRuns reports whether a job or step with this `if:` runs in ctx.
func ghaRuns(expr string, ctx ghaCtx) (bool, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return ctx.success, nil
	}
	var toks []string
	rest := expr
	for strings.TrimSpace(rest) != "" {
		m := ghaToken.FindStringSubmatchIndex(rest)
		if m == nil || m[0] != 0 {
			return false, fmt.Errorf("cannot tokenize %q at %q", expr, rest)
		}
		tok := rest[m[2]:m[3]]
		rest = rest[m[1]:]
		if tok == "${{" || tok == "}}" {
			continue
		}
		toks = append(toks, tok)
	}
	p := &ghaParser{toks: toks, ctx: ctx}
	v := p.or()
	if p.err == nil && p.pos != len(toks) {
		p.err = fmt.Errorf("trailing tokens in %q", expr)
	}
	if p.err != nil {
		return false, p.err
	}
	if !ghaStatusFn.MatchString(expr) {
		return ctx.success && v.truthy(), nil
	}
	return v.truthy(), nil
}

// jobRunsFor evaluates job `name` of release.yml when every job before the
// stranger check succeeded and the stranger job ended with `stranger`.
func jobRunsFor(t *testing.T, wf workflowDoc, name, stranger, promoteLatest string) bool {
	t.Helper()
	j, ok := wf.Jobs[name]
	if !ok {
		t.Fatalf("release.yml has no job %q", name)
	}
	results := map[string]string{"stranger": stranger}
	ctx := ghaCtx{success: true, cancelled: stranger == "cancelled", values: map[string]string{}}
	for _, n := range needsList(j.Needs) {
		r, ok := results[n]
		if !ok {
			r = "success"
		}
		ctx.values["needs."+n+".result"] = r
		if r != "success" {
			ctx.success = false
		}
		if r == "failure" {
			ctx.failure = true
		}
	}
	if contains(needsList(j.Needs), "preflight") {
		ctx.values["needs.preflight.outputs.promote_latest"] = promoteLatest
		ctx.values["needs.preflight.outputs.prerelease"] = map[string]string{"true": "false", "false": "true"}[promoteLatest]
	}
	run, err := ghaRuns(j.If, ctx)
	if err != nil {
		t.Fatalf("release.yml job %s if %q: %v", name, j.If, err)
	}
	return run
}

// TestGhaIfEvaluator pins the evaluator itself against GitHub's documented
// rules, so the graph tests below cannot pass because it is wrong.
func TestGhaIfEvaluator(t *testing.T) {
	ok := ghaCtx{success: true, values: map[string]string{"needs.a.result": "success"}}
	bad := ghaCtx{failure: true, values: map[string]string{"needs.a.result": "failure"}}
	cases := []struct {
		expr string
		ctx  ghaCtx
		want bool
	}{
		{"", ok, true},
		{"", bad, false},
		{"needs.a.result == 'failure'", bad, false}, // implicit success() &&
		{"always() && needs.a.result == 'failure'", bad, true},
		{"${{ always() && needs.a.result != 'success' }}", bad, true},
		{"always() && needs.a.result != 'success'", ok, false},
		{"failure() || cancelled()", bad, true},
		{"failure() || cancelled()", ok, false},
		{"!cancelled() && (needs.a.result == 'SUCCESS')", ok, true},
	}
	for _, c := range cases {
		got, err := ghaRuns(c.expr, c.ctx)
		if err != nil || got != c.want {
			t.Errorf("ghaRuns(%q) = %v, %v; want %v", c.expr, got, err, c.want)
		}
	}
	if _, err := ghaRuns("needs.b.result == 'x'", ok); err == nil {
		t.Error("an unknown context value must be an error, not an empty string")
	}
}

// TestReleaseGatesOnTheStrangerResult (AC3, D4; review F1, F3): for each way
// the stranger job can end, which release jobs run. mark-failed must run on
// failure AND on cancellation or timeout; promote (moves `latest`) and
// unmark-failed must run only on success.
func TestReleaseGatesOnTheStrangerResult(t *testing.T) {
	wf, _ := readWorkflow(t, "release.yml")
	for _, name := range []string{"promote", "mark-failed", "unmark-failed"} {
		if !contains(needsList(wf.Jobs[name].Needs), "stranger") {
			t.Errorf("job %s must need stranger, needs %v", name, needsList(wf.Jobs[name].Needs))
		}
	}
	if !strings.Contains(wf.Jobs["mark-failed"].If, "always()") {
		t.Errorf("mark-failed must use always() so it runs after a failed or cancelled stranger job: %q", wf.Jobs["mark-failed"].If)
	}
	if m := ghaStatusFn.FindString(wf.Jobs["promote"].If); m != "" && m != "success()" {
		t.Errorf("promote must not use %s: `latest` would move after a failed stranger check: %q", m, wf.Jobs["promote"].If)
	}
	for _, r := range []string{"success", "failure", "cancelled"} {
		pass := r == "success"
		if got := jobRunsFor(t, wf, "mark-failed", r, "true"); got == pass {
			t.Errorf("stranger %s: mark-failed runs=%v, want %v", r, got, !pass)
		}
		if got := jobRunsFor(t, wf, "promote", r, "true"); got != pass {
			t.Errorf("stranger %s: promote (moves `latest`) runs=%v, want %v", r, got, pass)
		}
		if got := jobRunsFor(t, wf, "unmark-failed", r, "true"); got != pass {
			t.Errorf("stranger %s: unmark-failed runs=%v, want %v", r, got, pass)
		}
	}
	// A backport or an rc never takes `latest`, stranger green or not.
	if jobRunsFor(t, wf, "promote", "success", "false") {
		t.Error("promote runs when preflight said this tag may not take `latest` (backport or pre-release)")
	}
	s := wf.Jobs["stranger"]
	if s.Uses != "./.github/workflows/stranger.yml" {
		t.Errorf("release.yml stranger job uses %q, want ./.github/workflows/stranger.yml", s.Uses)
	}
	if !contains(needsList(s.Needs), "release") {
		t.Errorf("stranger job must run after `release` (the kubectl leg downloads its install.yaml), needs %v", needsList(s.Needs))
	}
	// Review F2: the tagged commit itself, not a name that can be re-pointed.
	if strings.TrimSpace(s.With["ref"]) != "${{ github.sha }}" || !strings.Contains(s.With["expect_version"], "needs.preflight.outputs.version") {
		t.Errorf("stranger job must test the tagged commit (ref: ${{ github.sha }}) at the tag's version, with: %v", s.With)
	}
	if s.ContinueOnError != nil {
		t.Error("release.yml stranger job has continue-on-error; its failure must fail the release run")
	}
}

// TestStrangerCannotBeSwallowed (review F3): nothing that decides the
// stranger job's result may ignore a failure. A step that runs while the
// job is still green is a deciding step; the diagnostics step (failure or
// cancellation only) is not.
func TestStrangerCannotBeSwallowed(t *testing.T) {
	wf, _ := readWorkflow(t, "stranger.yml")
	job := wf.Jobs["stranger"]
	if job.ContinueOnError != nil {
		t.Error("stranger job has continue-on-error")
	}
	swallow := regexp.MustCompile(`\|\|\s*(true|:|exit 0)\b|set \+e|\|\|\s*:\s*$`)
	var diag bool
	for i, st := range job.Steps {
		green, err := ghaRuns(st.If, ghaCtx{success: true, values: map[string]string{}})
		if err != nil {
			t.Fatalf("step %d (%s) if %q: %v", i, st.Name, st.If, err)
		}
		failed, _ := ghaRuns(st.If, ghaCtx{failure: true, values: map[string]string{}})
		cancelled, _ := ghaRuns(st.If, ghaCtx{cancelled: true, values: map[string]string{}})
		if !green {
			if strings.Contains(st.Run, "kubectl") {
				// Review F9: diagnostics on failure AND on cancel/timeout, and
				// for the attack namespace too.
				diag = failed && cancelled && strings.Contains(st.Run, "olaitan-stranger")
			}
			continue
		}
		if st.ContinueOnError != nil {
			t.Errorf("step %d (%s) decides the job's result and has continue-on-error", i, st.Name)
		}
		if loc := swallow.FindString(st.Run); loc != "" {
			t.Errorf("step %d (%s) decides the job's result and swallows a failure with %q:\n%s", i, st.Name, loc, st.Run)
		}
	}
	if !diag {
		t.Error("stranger.yml needs a diagnostics step that runs on failure() || cancelled() and covers olaitan-stranger")
	}
	raw, err := os.ReadFile(strangerScript(t))
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if loc := swallow.FindString(line); loc != "" {
			t.Errorf("hack/stranger.sh:%d swallows a failure with %q: %s", i+1, loc, strings.TrimSpace(line))
		}
		// Review F5: kubectl's own error is the evidence of an infra fault.
		if strings.Contains(line, "kubectl") && strings.Contains(line, "2>/dev/null") {
			t.Errorf("hack/stranger.sh:%d hides kubectl's stderr: %s", i+1, strings.TrimSpace(line))
		}
	}
}

// strangerFn sources hack/stranger.sh (main does not run), defines shell
// functions (a kubectl shim, say) and runs body; it returns output and err.
func strangerFn(t *testing.T, prelude, body string, env ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", "-c", `source "$1"; `+prelude+"\n"+body, "stranger-test", strangerScript(t))
	cmd.Env = strangerEnv(env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestStrangerRolloutFailsWhenKubectlGetFails (review F7): a failing
// `kubectl get` must stop the check, not be an empty list of workloads.
func TestStrangerRolloutFailsWhenKubectlGetFails(t *testing.T) {
	out, err := strangerFn(t, `kubectl() { echo "kubectl: connection refused" >&2; return 3; }`, `st_rollout daemonset; echo REACHED`)
	if err == nil || strings.Contains(out, "REACHED") {
		t.Errorf("st_rollout carried on after kubectl get failed (err %v):\n%s", err, out)
	}
	if !strings.Contains(out, "infra: rollout") || !strings.Contains(out, "connection refused") {
		t.Errorf("st_rollout failure must name its phase (infra: rollout) and keep kubectl's error:\n%s", out)
	}
}

// TestStrangerKeepsKubectlLogErrors (review F5): a failing `kubectl logs`
// is an infra fault, reported as one with kubectl's error and exit code,
// never read as "no alert yet".
func TestStrangerKeepsKubectlLogErrors(t *testing.T) {
	shim := `kubectl() { echo "error: You must be logged in to the server" >&2; return 7; }`
	for _, fn := range []string{"st_aggregator_logs", "st_falco_logs"} {
		out, err := strangerFn(t, shim, `set +e; `+fn+`; echo "rc=$?"`)
		if err != nil {
			t.Fatalf("%s: %v\n%s", fn, err, out)
		}
		if !strings.Contains(out, "rc=7") || !strings.Contains(out, "You must be logged in") {
			t.Errorf("%s swallowed kubectl's error or exit code:\n%s", fn, out)
		}
	}
	raw, err := os.ReadFile(strangerScript(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"infra: cluster", "infra: rollout", "infra: pull", "infra: kubectl logs", "product: no Falco alert", "product: no FSM transition"} {
		if !strings.Contains(string(raw), phase) {
			t.Errorf("hack/stranger.sh has no failure message for phase %q", phase)
		}
	}
}

// TestStrangerWarnsWhenKubectlLegIsSkipped (review F4): a skip is visible
// in the run's annotations and summary, not only in the log.
func TestStrangerWarnsWhenKubectlLegIsSkipped(t *testing.T) {
	text := regexp.MustCompile(`/releases/download/v[^/]+/install\.yaml`).ReplaceAllString(readmeText(t), "/releases/download/v1.0.0-rc4/install.yaml")
	summary := filepath.Join(t.TempDir(), "summary.md")
	out := strangerPlan(t, "kubectl", "STRANGER_README="+writeReadme(t, text), "GITHUB_STEP_SUMMARY="+summary)
	if !strings.Contains(out, "::warning") || !strings.Contains(out, "skipped") {
		t.Errorf("kubectl skip for rc4 emits no ::warning:: annotation:\n%s", out)
	}
	got, err := os.ReadFile(summary)
	if err != nil || !strings.Contains(string(got), "skipped") {
		t.Errorf("kubectl skip for rc4 wrote nothing to $GITHUB_STEP_SUMMARY (%v): %q", err, got)
	}
	// Without GITHUB_STEP_SUMMARY (a local run) it still works.
	strangerPlan(t, "kubectl", "STRANGER_README="+writeReadme(t, text))
}

// TestStrangerReadsTheVersionFromTheHelmInstallOnly (review F6): a
// `--version` in a comment or another command is not the version installed.
func TestStrangerReadsTheVersionFromTheHelmInstallOnly(t *testing.T) {
	v := chartVersion(t)
	install := "helm install olaitan " + publishedChartRef + " \\\n"
	unpinned := strings.Replace(readmeText(t),
		"kind create cluster --name olaitan\n"+install+"  --version "+v+" \\\n",
		"kind create cluster --name olaitan\n# pin it with --version "+v+" if you like\n"+install, 1)
	block, err := readmeBashBlock(unpinned, strangerHelmHeading, 1)
	if err != nil || !strings.Contains(block, "# pin it with --version") || strings.Contains(block, "  --version "+v) {
		t.Fatalf("could not build the unpinned README variant (%v):\n%s", err, block)
	}
	if out, err := strangerRun(t, "helm", "STRANGER_README="+writeReadme(t, unpinned)); err == nil {
		t.Errorf("an unpinned helm install passed because a comment names --version:\n%s", out)
	}
	// The pinned README still reads its version from the install line.
	if out := strangerPlan(t, "helm"); !strings.Contains(out, "version "+v) {
		t.Errorf("helm leg does not report version %s:\n%s", v, out)
	}
}

// ghShim is a fake `gh` for the mark/unmark scripts: one release, held in
// files under dir (body, name, pre), and a log of every edit.
const ghShim = `#!/usr/bin/env bash
set -euo pipefail
d="$GH_SHIM_DIR"
[ "$1 $2" = "release view" ] && {
	case "$*" in
	*"--json body"*) cat "$d/body"; echo ;;
	*"--json name"*) cat "$d/name"; echo ;;
	*"--json isPrerelease"*) cat "$d/pre"; echo ;;
	*) echo "shim: unsupported view: $*" >&2; exit 2 ;;
	esac
	exit 0
}
[ "$1 $2" = "release edit" ] || { echo "shim: unsupported: $*" >&2; exit 2; }
echo "edit $*" >> "$d/edits"
shift 3
while [ $# -gt 0 ]; do
	case "$1" in
	-R) shift ;;
	--prerelease|--prerelease=true) echo -n true > "$d/pre" ;;
	--prerelease=false) echo -n false > "$d/pre" ;;
	--latest|--latest=true|--latest=false) ;;
	--title) shift; printf '%s' "$1" > "$d/name" ;;
	--notes-file) shift; cp "$1" "$d/body" ;;
	*) echo "shim: unsupported flag $1" >&2; exit 2 ;;
	esac
	shift
done
`

// releaseStepScript returns the run script of the step in job that edits the
// release, and that step's env keys.
func releaseStepScript(t *testing.T, wf workflowDoc, job string) (string, map[string]string) {
	t.Helper()
	for _, st := range wf.Jobs[job].Steps {
		if strings.Contains(st.Run, "gh release edit") {
			return st.Run, st.Env
		}
	}
	t.Fatalf("release.yml job %s has no step that runs gh release edit", job)
	return "", nil
}

type shimRelease struct{ dir string }

func newShimRelease(t *testing.T, name, body, pre string) shimRelease {
	t.Helper()
	d := t.TempDir()
	for f, v := range map[string]string{"name": name, "body": body, "pre": pre} {
		if err := os.WriteFile(filepath.Join(d, f), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	bin := filepath.Join(d, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(ghShim), 0o755); err != nil {
		t.Fatal(err)
	}
	return shimRelease{dir: d}
}

func (r shimRelease) get(t *testing.T, f string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(r.dir, f))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(b)
}

// runErr runs a mark/unmark script against the fake release and returns its
// output and error. Both steps must get TAG, REPO and PRERELEASE (the
// preflight value, which a missing or garbled banner falls back to) through
// their env.
func (r shimRelease) runErr(t *testing.T, script string, env map[string]string, prerelease string) (string, error) {
	t.Helper()
	for _, k := range []string{"TAG", "REPO", "PRERELEASE"} {
		if _, ok := env[k]; !ok {
			t.Fatalf("release edit step has no env %s", k)
		}
	}
	work := t.TempDir()
	cmd := exec.Command("bash", "-e", "-o", "pipefail", "-c", script)
	cmd.Dir = work
	cmd.Env = append(os.Environ(),
		"PATH="+filepath.Join(r.dir, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GH_SHIM_DIR="+r.dir, "TAG=v9.9.9", "REPO=o/r", "PRERELEASE="+prerelease,
		"RUN_URL=https://github.com/o/r/actions/runs/1", "GH_TOKEN=unused")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (r shimRelease) run(t *testing.T, script string, env map[string]string, prerelease string) {
	t.Helper()
	if out, err := r.runErr(t, script, env, prerelease); err != nil {
		t.Fatalf("release edit script failed: %v\n%s\n--- script\n%s", err, out, script)
	}
}

// TestReleaseMarkAndUnmarkAreIdempotent (review F11): marking twice leaves
// one banner and one title suffix; a later green rerun restores title and
// notes, and clears the pre-release flag only when the mark set it (a real
// rc stays a pre-release). Both scripts run against a fake `gh`.
func TestReleaseMarkAndUnmarkAreIdempotent(t *testing.T) {
	wf, _ := readWorkflow(t, "release.yml")
	mark, markEnv := releaseStepScript(t, wf, "mark-failed")
	unmark, unmarkEnv := releaseStepScript(t, wf, "unmark-failed")
	const notes = "## Install\n\nhelm install ...\n\n## Verify\n"
	for _, c := range []struct{ pre, prerelease string }{{"false", "false"}, {"true", "true"}} {
		r := newShimRelease(t, "v9.9.9", notes, c.pre)
		r.run(t, mark, markEnv, c.prerelease)
		r.run(t, mark, markEnv, c.prerelease) // a second failed attempt
		body, name := r.get(t, "body"), r.get(t, "name")
		if n := strings.Count(body, "FAILED the stranger-path check"); n != 1 {
			t.Errorf("pre=%s: after two marks the notes carry %d banners, want 1:\n%s", c.pre, n, body)
		}
		if name != "v9.9.9 (FAILED stranger-path check)" {
			t.Errorf("pre=%s: after two marks the title is %q", c.pre, name)
		}
		if r.get(t, "pre") != "true" || !strings.HasSuffix(strings.TrimRight(body, "\n"), strings.TrimRight(notes, "\n")) {
			t.Errorf("pre=%s: a marked release must be a pre-release that keeps its notes: pre=%s\n%s", c.pre, r.get(t, "pre"), body)
		}
		if strings.Contains(r.get(t, "edits"), "--latest ") || strings.HasSuffix(strings.TrimSpace(r.get(t, "edits")), "--latest") {
			t.Errorf("pre=%s: mark-failed must never set latest: %s", c.pre, r.get(t, "edits"))
		}
		r.run(t, unmark, unmarkEnv, c.prerelease)
		if got := r.get(t, "name"); got != "v9.9.9" {
			t.Errorf("pre=%s: unmark left title %q", c.pre, got)
		}
		if got := strings.TrimRight(r.get(t, "body"), "\n"); got != strings.TrimRight(notes, "\n") {
			t.Errorf("pre=%s: unmark left notes:\n%q\nwant\n%q", c.pre, got, notes)
		}
		if got := r.get(t, "pre"); got != c.pre {
			t.Errorf("pre=%s: after unmark the pre-release flag is %s; unmark must restore what was there before the mark", c.pre, got)
		}
		// Unmarking a release that was never marked changes nothing.
		edits := r.get(t, "edits")
		r.run(t, unmark, unmarkEnv, c.prerelease)
		if r.get(t, "edits") != edits {
			t.Errorf("pre=%s: unmark edited a release that was not marked", c.pre)
		}
	}
}

// TestReleaseMarkAndUnmarkEdgeCases (review round 3, N1 to N5): the notes a
// human edited, a banner cut short or garbled, a marker quoted inside the
// notes, a backport, and "Re-run all jobs" after a mark. The scripts never
// drop notes outside the banner, never guess a pre-release state they did
// not record (they fall back to preflight's), and never leave a FAILED title
// on a release whose stranger check passed.
func TestReleaseMarkAndUnmarkEdgeCases(t *testing.T) {
	wf, _ := readWorkflow(t, "release.yml")
	mark, markEnv := releaseStepScript(t, wf, "mark-failed")
	unmark, unmarkEnv := releaseStepScript(t, wf, "unmark-failed")
	const (
		notes   = "## Install\n\nhelm install ...\n\n## Verify\n"
		failed  = "v9.9.9 (FAILED stranger-path check)"
		caution = "> [!CAUTION]\n> **This release FAILED the stranger-path check.** Do not install it.\n"
		endMark = "<!-- stranger-check: end -->\n"
	)
	trim := func(s string) string { return strings.TrimRight(s, "\n") }

	// N1: the web UI saves notes with CRLF. The end marker must still be
	// found, and nothing after the banner may be lost.
	t.Run("crlf notes", func(t *testing.T) {
		crlf := func(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }
		body := crlf("<!-- stranger-check: FAILED; prerelease-before=false -->\n" + caution + endMark + "\n" + notes)
		r := newShimRelease(t, failed, body, "true")
		r.run(t, unmark, unmarkEnv, "false")
		if got := strings.ReplaceAll(trim(r.get(t, "body")), "\r", ""); got != trim(notes) {
			t.Errorf("unmark of CRLF notes left:\n%q\nwant\n%q", got, notes)
		}
		if r.get(t, "name") != "v9.9.9" || r.get(t, "pre") != "false" {
			t.Errorf("unmark of CRLF notes: title %q pre %s, want v9.9.9 false", r.get(t, "name"), r.get(t, "pre"))
		}
		r2 := newShimRelease(t, failed, body, "true")
		r2.run(t, mark, markEnv, "false")
		got := strings.ReplaceAll(r2.get(t, "body"), "\r", "")
		if strings.Count(got, "FAILED the stranger-path check") != 1 || !strings.HasSuffix(trim(got), trim(notes)) {
			t.Errorf("re-mark of CRLF notes lost the notes or doubled the banner:\n%s", got)
		}
	})

	// N1: a begin marker with no end marker. Rewriting would drop every line
	// after it, so both scripts must fail and leave the release untouched.
	t.Run("missing end marker", func(t *testing.T) {
		body := "<!-- stranger-check: FAILED; prerelease-before=false -->\n" + caution + "\n" + notes
		for name, script := range map[string]string{"mark": mark, "unmark": unmark} {
			env := markEnv
			if name == "unmark" {
				env = unmarkEnv
			}
			r := newShimRelease(t, failed, body, "true")
			out, err := r.runErr(t, script, env, "false")
			if err == nil {
				t.Errorf("%s succeeded on a banner with no end marker:\n%s", name, out)
			} else if !strings.Contains(out, "::error::") {
				t.Errorf("%s failed without a ::error:: line:\n%s", name, out)
			}
			if r.get(t, "body") != body || r.get(t, "name") != failed || r.get(t, "edits") != "" {
				t.Errorf("%s changed a release whose banner has no end marker:\nbody %q\nname %q\nedits %q", name, r.get(t, "body"), r.get(t, "name"), r.get(t, "edits"))
			}
		}
	})

	// N2: a human edited the header, so the recorded state is gone. Fall
	// back to preflight's value instead of an empty one.
	t.Run("garbled header", func(t *testing.T) {
		for _, header := range []string{
			"<!-- stranger-check: FAILED -->",
			"<!-- stranger-check: FAILED; prerelease-before= -->",
			"<!-- stranger-check: FAILED; prerelease-before=maybe -->",
		} {
			body := header + "\n" + caution + endMark + "\n" + notes
			r := newShimRelease(t, failed, body, "true")
			r.run(t, unmark, unmarkEnv, "false")
			if r.get(t, "pre") != "false" || r.get(t, "name") != "v9.9.9" || trim(r.get(t, "body")) != trim(notes) {
				t.Errorf("header %q: unmark left pre=%s title %q body %q; want false, v9.9.9, the notes", header, r.get(t, "pre"), r.get(t, "name"), r.get(t, "body"))
			}
			r2 := newShimRelease(t, failed, body, "true")
			r2.run(t, mark, markEnv, "false")
			if !strings.Contains(r2.get(t, "body"), "prerelease-before=false -->") {
				t.Errorf("header %q: re-mark recorded no pre-release state:\n%s", header, r2.get(t, "body"))
			}
		}
	})

	// N4: notes that quote the marker mid-line are not a mark.
	t.Run("quoted marker mid-line", func(t *testing.T) {
		quoted := notes + "\nA failed release starts with `<!-- stranger-check: FAILED` in its notes.\n"
		r := newShimRelease(t, "v9.9.9", quoted, "false")
		r.run(t, unmark, unmarkEnv, "false")
		if r.get(t, "edits") != "" {
			t.Errorf("unmark edited a release that only quotes the marker: %s", r.get(t, "edits"))
		}
		r.run(t, mark, markEnv, "false")
		if !strings.Contains(r.get(t, "body"), "prerelease-before=false -->") {
			t.Errorf("mark read the quoted marker as an earlier mark:\n%s", r.get(t, "body"))
		}
		r.run(t, unmark, unmarkEnv, "false")
		if r.get(t, "pre") != "false" || r.get(t, "name") != "v9.9.9" || trim(r.get(t, "body")) != trim(quoted) {
			t.Errorf("mark then unmark with a quoted marker: pre=%s title %q body %q", r.get(t, "pre"), r.get(t, "name"), r.get(t, "body"))
		}
	})

	// A backport (stable, not the highest tag): marked, then unmarked, it is
	// stable again, and neither script ever makes it Latest.
	t.Run("backport", func(t *testing.T) {
		r := newShimRelease(t, "v9.9.9", notes, "false")
		r.run(t, mark, markEnv, "false")
		if r.get(t, "pre") != "true" || !strings.Contains(r.get(t, "edits"), "--latest=false") {
			t.Errorf("mark of a backport: pre=%s edits %q", r.get(t, "pre"), r.get(t, "edits"))
		}
		r.run(t, unmark, unmarkEnv, "false")
		if r.get(t, "pre") != "false" || r.get(t, "name") != "v9.9.9" || trim(r.get(t, "body")) != trim(notes) {
			t.Errorf("unmark of a backport: pre=%s title %q body %q", r.get(t, "pre"), r.get(t, "name"), r.get(t, "body"))
		}
		if regexp.MustCompile(`--latest(=true)?(\s|$)`).MatchString(r.get(t, "edits")) {
			t.Errorf("mark or unmark made a backport Latest: %s", r.get(t, "edits"))
		}
	})

	// N3: "Re-run all jobs" after a mark. softprops replaces the body (the
	// banner is gone) and resets the pre-release flag, and without an
	// explicit name it keeps the FAILED title. The release job must pass
	// the title releases get today (the tag), and unmark must still strip
	// the suffix when no banner is left.
	t.Run("re-run all jobs after a mark", func(t *testing.T) {
		var name string
		for _, st := range wf.Jobs["release"].Steps {
			if strings.HasPrefix(st.Uses, "softprops/action-gh-release@") {
				name = st.With["name"]
			}
		}
		if name != "${{ github.ref_name }}" {
			t.Errorf("softprops name is %q, want ${{ github.ref_name }} (the tag, the title a first run gets today), or a rerun keeps the FAILED title", name)
		}
		r := newShimRelease(t, "v9.9.9", notes, "false")
		r.run(t, mark, markEnv, "false")
		// softprops-style reset with no name input: new body, FAILED title kept.
		for f, v := range map[string]string{"body": notes, "pre": "false"} {
			if err := os.WriteFile(filepath.Join(r.dir, f), []byte(v), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if r.get(t, "name") != failed {
			t.Fatalf("setup: title after mark is %q", r.get(t, "name"))
		}
		r.run(t, unmark, unmarkEnv, "false")
		if got := r.get(t, "name"); got != "v9.9.9" {
			t.Errorf("unmark after a re-run left the title %q; promote would make a FAILED-titled release Latest", got)
		}
		if trim(r.get(t, "body")) != trim(notes) || r.get(t, "pre") != "false" {
			t.Errorf("unmark after a re-run changed body or flag: pre=%s body %q", r.get(t, "pre"), r.get(t, "body"))
		}
	})
}

// TestReleaseLatestOnlyAfterTheStrangerPasses (review F12, CoS default
// pending Aslim): the GitHub Release is created without "Latest", and only
// promote, which needs the stranger job and runs only for the highest stable
// tag (backports and rcs never), marks it Latest.
func TestReleaseLatestOnlyAfterTheStrangerPasses(t *testing.T) {
	wf, _ := readWorkflow(t, "release.yml")
	var created bool
	for _, st := range wf.Jobs["release"].Steps {
		if strings.HasPrefix(st.Uses, "softprops/action-gh-release@") {
			created = true
			if st.With["make_latest"] != "false" {
				t.Errorf("release creates the GitHub Release with make_latest %q, want 'false' (it would show Latest before the stranger check)", st.With["make_latest"])
			}
		}
	}
	if !created {
		t.Fatal("release job has no softprops/action-gh-release step")
	}
	p := wf.Jobs["promote"]
	if !strings.Contains(p.If, "needs.preflight.outputs.promote_latest == 'true'") {
		t.Errorf("promote must still be gated on promote_latest (backports and rcs never take latest): %q", p.If)
	}
	if p.Permissions["contents"] != "write" {
		t.Errorf("promote needs contents: write to mark the GitHub Release Latest, has %v", p.Permissions)
	}
	var sets bool
	for _, st := range p.Steps {
		if regexp.MustCompile(`gh release edit\b[^\n]*--latest(\s|$)`).MatchString(st.Run) {
			sets = true
		}
	}
	if !sets {
		t.Error("promote does not mark the GitHub Release Latest (gh release edit ... --latest)")
	}
	if !contains(needsList(p.Needs), "unmark-failed") {
		t.Error("promote must run after unmark-failed: a release still flagged pre-release cannot be marked Latest")
	}
	for name, j := range wf.Jobs {
		if name == "promote" {
			continue
		}
		for _, st := range j.Steps {
			if regexp.MustCompile(`--latest(=true)?(\s|$)`).MatchString(st.Run) {
				t.Errorf("job %s marks a release Latest; only promote may", name)
			}
		}
	}
}

// TestReadmeKindBlockInstallsTheKindHookException (fix/quickstart-honest-
// score): the README kind block, which the stranger job runs verbatim,
// passes the release's kind overlay, pinned to the same release as its
// --version, and the README no longer shows the hook's score as the read's.
func TestReadmeKindBlockInstallsTheKindHookException(t *testing.T) {
	block, err := readmeBashBlock(readmeText(t), strangerHelmHeading, 1)
	if err != nil {
		t.Fatal(err)
	}
	cmds := publishedInstallCommands("README kind block", block)
	if len(cmds) != 1 {
		t.Fatalf("want one helm install of the published chart in the kind block, got %d:\n%s", len(cmds), block)
	}
	if !strings.Contains(cmds[0].command, "-f "+kindOverlayURL(chartVersion(t))) {
		t.Errorf("the README kind install does not pass -f %s:\n%s", kindOverlayURL(chartVersion(t)), cmds[0].command)
	}
	for _, m := range regexp.MustCompile(`raw\.githubusercontent\.com/olokotoh/olaitan/([^/\s]+)/`).FindAllStringSubmatch(readmeText(t), -1) {
		if m[1] != "v"+chartVersion(t) {
			t.Errorf("README fetches a file at %s, Chart.yaml is %s", m[1], chartVersion(t))
		}
	}
	if regexp.MustCompile(`(?m)^\s*score\s+36\s*$`).MatchString(readmeText(t)) {
		t.Error("README still shows score 36 as the read's result; that was the kind hook's Critical rule")
	}
}

// strangerMain runs hack/stranger.sh LEG for real (not plan mode) against
// the kubectl shim of quickstart_test.go, with FALCO (written for the
// quickstart's demo pod) moved to the stranger's pod and namespace and a
// transition at 08:41:19.5Z. It returns the output and the job summary.
func strangerMain(t *testing.T, leg, falco string, env ...string) (string, string, error) {
	t.Helper()
	move := strings.NewReplacer("olaitan-quickstart", "olaitan-stranger", "quickstart-demo", "stranger-demo")
	summary := filepath.Join(t.TempDir(), "summary.md")
	cmd := exec.Command("bash", strangerScript(t), leg)
	cmd.Dir = repoRoot(t)
	cmd.Env = strangerEnv(append([]string{
		"PATH=" + resultShim(t),
		"GITHUB_STEP_SUMMARY=" + summary,
		"SHIM_AGG=" + writeTemp(t, "agg.log", transitionAt("olaitan-stranger", "stranger-demo", "2026-09-24T08:41:19.5Z")),
		"SHIM_FALCO=" + writeTemp(t, "falco.log", move.Replace(falco)),
	}, env...)...)
	out, err := cmd.CombinedOutput()
	sum, _ := os.ReadFile(summary)
	return string(out), string(sum), err
}

// TestStrangerMainResult (review F1, F6): the result block of main, run end
// to end with a kubectl shim. On the helm path (the kind overlay) a
// transition the read did not cause fails the job as a product fault; on
// the kubectl path (install.yaml, no kind hook exception) it is a
// ::warning:: and a WARNING line in the job summary.
func TestStrangerMainResult(t *testing.T) {
	kubectlReadme := "STRANGER_README=" + writeReadme(t, regexp.MustCompile(`/releases/download/v[^/]+/install\.yaml`).ReplaceAllString(readmeText(t), "/releases/download/v9.9.9-test/install.yaml"))
	for _, leg := range []string{"helm", "kubectl"} {
		var env []string
		if leg == "kubectl" {
			env = append(env, kubectlReadme)
		}
		out, sum, err := strangerMain(t, leg, falcoLogReadOnly, env...)
		if err != nil || !strings.Contains(out, "Olaitan saw the read of /etc/shadow and moved the workload:") || strings.Contains(out, "::warning") {
			t.Errorf("%s leg, the read alone: exit %v, want 0, the \"saw the read\" headline and no warning:\n%s", leg, err, out)
		}
		if !strings.Contains(sum, "Read sensitive file untrusted") {
			t.Errorf("%s leg summary lacks the rule list:\n%s", leg, sum)
		}

		out, sum, err = strangerMain(t, leg, falcoLogHookOnly, env...)
		if leg == "helm" {
			if err == nil {
				t.Errorf("helm leg passed although the read did not cause the transition:\n%s", out)
			}
			if !strings.Contains(out, "::error title=stranger-path check failed [product: the read did not cause the transition]") || !strings.Contains(sum, "**FAILED [product: the read did not cause the transition]**") {
				t.Errorf("helm leg failure does not name the product phase in the log and summary:\n%s\nsummary:\n%s", out, sum)
			}
		} else {
			if err != nil {
				t.Errorf("kubectl leg failed on the hook's rule; install.yaml has no kind hook exception, so it warns (%v):\n%s", err, out)
			}
			if !strings.Contains(out, "::warning title=stranger-path check::") || !strings.Contains(sum, "**WARNING**") || !strings.Contains(sum, "not caused by the read") {
				t.Errorf("kubectl leg does not warn in the log and the summary:\n%s\nsummary:\n%s", out, sum)
			}
		}
		if !strings.Contains(out, "Drop and execute new binary in container") {
			t.Errorf("%s leg does not print the rule that did cause it:\n%s", leg, out)
		}

		out, _, err = strangerMain(t, leg, falcoLogHook, env...)
		if err != nil || !strings.Contains(out, "the read of /etc/shadow and other rules contributed (Drop and execute new binary in container)") {
			t.Errorf("%s leg, hook and read: exit %v, want 0 and a headline naming the other rule:\n%s", leg, err, out)
		}
	}
}
