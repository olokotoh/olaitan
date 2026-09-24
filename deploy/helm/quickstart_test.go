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

// Story 12.2: `make quickstart` is a real detection from a real action with
// Falco on. PR #99 (Story 8.3) got to ten minutes by switching Falco off and
// publishing the S1 scenario's events on NATS itself; these tests keep that
// shape out of the quickstart path and pin what the script actually does.

// quickstartEnv is os.Environ() without any QUICKSTART_* setting, so a
// developer who has one exported (say QUICKSTART_CHART=local) does not
// change what these tests see, then the test's own settings on top.
func quickstartEnv(extra ...string) []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "QUICKSTART_") {
			env = append(env, kv)
		}
	}
	return append(env, extra...)
}

func quickstartScript(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "hack", "quickstart.sh")
}

// quickstartPlan runs the script in plan mode, which prints every command it
// would run and touches nothing (no cluster, no helm, no kubectl).
func quickstartPlan(t *testing.T, env ...string) string {
	t.Helper()
	cmd := exec.Command("bash", quickstartScript(t))
	cmd.Dir = repoRoot(t)
	cmd.Env = quickstartEnv(append([]string{"QUICKSTART_PLAN=1"}, env...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("quickstart plan (%v) failed: %v\n%s", env, err, out)
	}
	return string(out)
}

// quickstartFunc sources the script and calls one of its functions. $0 is
// "quickstart-test", never the script path: the script runs main when
// BASH_SOURCE[0] equals $0, and an earlier version of this helper passed the
// script as $0, which made a unit test create a real kind cluster. Plan mode
// is set as well, so even a guard regression cannot touch a cluster.
func quickstartFunc(t *testing.T, stdin string, fn string, args ...string) (string, error) {
	t.Helper()
	script := `source "$1"; shift; "$@"`
	cmd := exec.Command("bash", append([]string{"-c", script, "quickstart-test", quickstartScript(t), fn}, args...)...)
	cmd.Dir = repoRoot(t)
	cmd.Env = quickstartEnv("QUICKSTART_PLAN=1")
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.Output()
	return string(out), err
}

// quickstartTarget returns the recipe lines of a Makefile target.
func quickstartTarget(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	var body []string
	in := false
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(l, name+":") {
			in = true
			continue
		}
		if in {
			if !strings.HasPrefix(l, "\t") {
				break
			}
			body = append(body, l)
		}
	}
	if !in {
		t.Fatalf("Makefile has no %s target", name)
	}
	return strings.Join(body, "\n")
}

func TestQuickstartTargetsRunTheScript(t *testing.T) {
	if body := quickstartTarget(t, "quickstart"); !strings.Contains(body, "hack/quickstart.sh") {
		t.Errorf("make quickstart does not run hack/quickstart.sh:\n%s", body)
	}
	if body := quickstartTarget(t, "quickstart-clean"); !strings.Contains(body, "kind delete cluster") {
		t.Errorf("make quickstart-clean does not delete the cluster:\n%s", body)
	}
}

// TestQuickstartHasNoInjection (AC2). The quickstart must not be able to
// fake the detection: no NATS client, no port-forward to reach one, no event
// subject, and no way to switch Falco off.
func TestQuickstartHasNoInjection(t *testing.T) {
	raw, err := os.ReadFile(quickstartScript(t))
	if err != nil {
		t.Fatal(err)
	}
	path := map[string]string{
		"hack/quickstart.sh":        string(raw),
		"Makefile quickstart":       quickstartTarget(t, "quickstart"),
		"Makefile quickstart-clean": quickstartTarget(t, "quickstart-clean"),
	}
	forbidden := []*regexp.Regexp{
		regexp.MustCompile(`(?i)nats\s+(pub|publish|req|request|stream\s+add)`),
		regexp.MustCompile(`(?i)jetstream`),
		regexp.MustCompile(`port-forward`),
		regexp.MustCompile(`:4222`),
		regexp.MustCompile(`olaitan\.events\.`),
		regexp.MustCompile(`falco\.enabled\s*=\s*false`),
		regexp.MustCompile(`endpoints\.falco`),
		regexp.MustCompile(`cmd/olaitan-quickstart`), // PR #99's injector binary
		regexp.MustCompile(`\bgo (run|build)\b`),
		regexp.MustCompile(`values-quickstart\.yaml`),
	}
	for where, text := range path {
		for i, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			for _, re := range forbidden {
				if re.MatchString(line) {
					t.Errorf("%s:%d matches %s (the quickstart must not inject or turn Falco off): %s", where, i+1, re, strings.TrimSpace(line))
				}
			}
		}
	}
}

// shippedExclusions reads the namespaces the shipped config never acts in
// or never scores. A demo pod in one of those produces nothing.
func shippedExclusions(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "config", "olaitan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(n.Content); i += 2 {
				k, v := n.Content[i], n.Content[i+1]
				if (k.Value == "excluded_namespaces" || k.Value == "never_scored_namespaces") && v.Kind == yaml.SequenceNode {
					for _, s := range v.Content {
						out = append(out, s.Value)
					}
				}
				walk(v)
			}
			return
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	walk(&doc)
	if len(out) == 0 {
		t.Fatal("found no excluded_namespaces or never_scored_namespaces in config/olaitan.yaml")
	}
	return out
}

var (
	planInstall = regexp.MustCompile(`(?m)^\+ helm install olaitan (\S+)(.*)$`)
	planExec    = regexp.MustCompile(`(?m)^\+ kubectl (?:--context \S+ )?-n (\S+) exec \S+ -- cat /etc/shadow$`)
	planWaitAll = regexp.MustCompile(`(?m)^\+ kubectl (?:--context \S+ )?-n olaitan wait pod --all --for=condition=Ready`)
	planPodImg  = regexp.MustCompile(`--image=(\S+)`)
)

// TestQuickstartPlanPublished (AC1, AC3): the default path is the stranger's
// path. The timer starts at kind create, the chart is the published one at
// the Chart.yaml version, Falco is left on, and the action is a real read
// of /etc/shadow in a namespace the agent scores, from a pinned image.
func TestQuickstartPlanPublished(t *testing.T) {
	plan := quickstartPlan(t)
	lines := strings.Split(strings.TrimSpace(plan), "\n")

	// The only command before kind create cluster is the check that the
	// chart version is really published (review E1): a version that is not
	// in the registry yet must fail before a cluster exists.
	var cmds []string
	for _, l := range lines {
		if strings.HasPrefix(l, "+ ") {
			cmds = append(cmds, l)
		}
	}
	wantShow := "+ helm show chart " + publishedChartRef + " --version " + chartVersion(t)
	if len(cmds) < 2 || cmds[0] != wantShow {
		t.Errorf("the first command must be %q (before any cluster exists), got %q", wantShow, cmds)
	}
	if len(cmds) < 2 || !strings.HasPrefix(cmds[1], "+ kind create cluster --name olaitan-quickstart") {
		t.Errorf("kind create cluster must come straight after the version check (the clock starts there), got %q", cmds)
	}
	if strings.Index(plan, "clock starts: kind create cluster") < strings.Index(plan, wantShow) {
		t.Error("the version check must run before the clock starts")
	}
	if !strings.Contains(plan, "clock starts") {
		t.Error("plan does not say where the clock starts")
	}

	m := planInstall.FindStringSubmatch(plan)
	if m == nil {
		t.Fatalf("no helm install in the plan:\n%s", plan)
	}
	if m[1] != publishedChartRef {
		t.Errorf("default chart is %s, want the published %s", m[1], publishedChartRef)
	}
	if v := versionFlag.FindStringSubmatch(m[2]); v == nil || v[1] != chartVersion(t) {
		t.Errorf("default install does not pin --version %s: %s", chartVersion(t), m[0])
	}
	for _, want := range []string{"--namespace olaitan", "--wait", "--kube-context kind-olaitan-quickstart"} {
		if !strings.Contains(m[2], want) {
			t.Errorf("helm install lacks %q: %s", want, m[0])
		}
	}
	if !planWaitAll.MatchString(plan) {
		t.Error("plan does not wait for every pod Ready after helm (helm --wait can return during the collector back-off)")
	}

	e := planExec.FindStringSubmatch(plan)
	if e == nil {
		t.Fatalf("no `kubectl -n <ns> exec <pod> -- cat /etc/shadow` in the plan:\n%s", plan)
	}
	for _, ex := range shippedExclusions(t) {
		if e[1] == ex {
			t.Errorf("the attack runs in %s, which the shipped config excludes or never scores", e[1])
		}
	}
	img := planPodImg.FindStringSubmatch(plan)
	if img == nil || !regexp.MustCompile(`^[^@\s]+:[^@\s]+@sha256:[0-9a-f]{64}$`).MatchString(img[1]) {
		t.Errorf("attack pod image is not pinned by tag and digest: %v", img)
	}
}

// TestQuickstartPlanLocal (AC4): the local option installs the checkout's
// chart, and a local image is loaded into kind instead of pulled.
func TestQuickstartPlanLocal(t *testing.T) {
	plan := quickstartPlan(t, "QUICKSTART_CHART=local")
	m := planInstall.FindStringSubmatch(plan)
	if m == nil || m[1] != "deploy/helm/olaitan" {
		t.Fatalf("QUICKSTART_CHART=local does not install deploy/helm/olaitan: %v", m)
	}
	if versionFlag.MatchString(m[2]) {
		t.Errorf("a local chart install takes no --version: %s", m[0])
	}

	if strings.Contains(plan, "helm show chart") {
		t.Errorf("a local chart install needs no registry check:\n%s", plan)
	}

	plan = quickstartPlan(t, "QUICKSTART_CHART=local", "QUICKSTART_IMAGE=olaitan:dev")
	if !strings.Contains(plan, "+ kind load docker-image olaitan:dev --name olaitan-quickstart") {
		t.Errorf("QUICKSTART_IMAGE is not loaded into kind:\n%s", plan)
	}
	m = planInstall.FindStringSubmatch(plan)
	for _, want := range []string{"image.repository=olaitan", "image.tag=dev", "image.digest=", "image.pullPolicy=Never"} {
		if m == nil || !strings.Contains(m[2], want) {
			t.Errorf("local image install lacks %s: %v", want, m)
		}
	}
}

// TestQuickstartRejectsDigestImage (review E4): QUICKSTART_IMAGE is a
// repo:tag for kind load; a digest reference used to be split into
// image.repository=olaitan@sha256 and image.tag=<hex>.
func TestQuickstartRejectsDigestImage(t *testing.T) {
	for _, img := range []string{
		"olaitan@sha256:abcd",
		"olaitan:dev@sha256:abcd",
		"localhost:5000/olaitan",
		"olaitan",
	} {
		cmd := exec.Command("bash", quickstartScript(t))
		cmd.Dir = repoRoot(t)
		cmd.Env = quickstartEnv("QUICKSTART_PLAN=1", "QUICKSTART_CHART=local", "QUICKSTART_IMAGE="+img)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Errorf("QUICKSTART_IMAGE=%s accepted:\n%s", img, out)
			continue
		}
		if !strings.Contains(string(out), "must be repo:tag") {
			t.Errorf("QUICKSTART_IMAGE=%s rejected without the repo:tag message:\n%s", img, out)
		}
	}
	// A registry with a port is still a valid repo:tag.
	plan := quickstartPlan(t, "QUICKSTART_CHART=local", "QUICKSTART_IMAGE=localhost:5000/olaitan:dev")
	if !strings.Contains(plan, "image.repository=localhost:5000/olaitan") || !strings.Contains(plan, "image.tag=dev") {
		t.Errorf("localhost:5000/olaitan:dev was not split into repo and tag:\n%s", plan)
	}
}

// quickstartRejects runs the script in plan mode with env and returns its
// output, failing the test when the script accepts the setting or runs any
// command (a "+ " line) before rejecting it.
func quickstartRejects(t *testing.T, want string, env ...string) {
	t.Helper()
	cmd := exec.Command("bash", quickstartScript(t))
	cmd.Dir = repoRoot(t)
	cmd.Env = quickstartEnv(append([]string{"QUICKSTART_PLAN=1"}, env...)...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Errorf("%v accepted:\n%s", env, out)
		return
	}
	if !strings.Contains(string(out), want) {
		t.Errorf("%v rejected without %q:\n%s", env, want, out)
	}
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(l, "+ ") {
			t.Errorf("%v ran %q before it was rejected", env, l)
		}
	}
}

// TestQuickstartRejectsBadBudget (review round 2, F6): QUICKSTART_BUDGET is
// compared with [ -le ], so a value that is not a whole number of seconds
// used to surface only as a bash error after the whole run. It is checked
// before anything runs.
func TestQuickstartRejectsBadBudget(t *testing.T) {
	for _, b := range []string{"abc", "-5", "1.5", "10m", " 600", "600s"} {
		quickstartRejects(t, "QUICKSTART_BUDGET must be a whole number of seconds", "QUICKSTART_BUDGET="+b)
	}
	for _, b := range []string{"0", "900"} {
		if plan := quickstartPlan(t, "QUICKSTART_BUDGET="+b); !strings.Contains(plan, "budget "+b+"s") {
			t.Errorf("QUICKSTART_BUDGET=%s not used:\n%s", b, plan)
		}
	}
}

// TestQuickstartRejectsEmptyImageParts (review round 2, F7): an image with
// an empty repository or tag used to reach helm as image.repository= or
// image.tag=. It is rejected before anything is created.
func TestQuickstartRejectsEmptyImageParts(t *testing.T) {
	for _, img := range []string{"olaitan:", ":dev", ":", "localhost:5000/olaitan:"} {
		quickstartRejects(t, "must be repo:tag", "QUICKSTART_CHART=local", "QUICKSTART_IMAGE="+img)
	}
}

// fakeTools puts failing stand-ins for helm, kind, kubectl and docker first
// on PATH, so a function under test that calls one of them for real cannot
// reach a registry or a cluster. Each records its arguments in calls.log.
func fakeTools(t *testing.T, helmExit int) (path, calls string) {
	t.Helper()
	dir := t.TempDir()
	calls = filepath.Join(dir, "calls.log")
	for tool, code := range map[string]int{"helm": helmExit, "kind": 1, "kubectl": 1, "docker": 1} {
		body := "#!/bin/sh\necho \"" + tool + " $*\" >>\"" + calls + "\"\nexit " + strconv.Itoa(code) + "\n"
		if err := os.WriteFile(filepath.Join(dir, tool), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir + string(os.PathListSeparator) + os.Getenv("PATH"), calls
}

// TestQuickstartVersionCheck (review E1): the published chart version is
// checked in the registry before the clock starts, and a version that is
// not there stops the run with a pointer to the two ways out.
func TestQuickstartVersionCheck(t *testing.T) {
	run := func(helmExit int) (string, error, string) {
		path, calls := fakeTools(t, helmExit)
		cmd := exec.Command("bash", "-c", `source "$1"; shift; "$@"`, "quickstart-test", quickstartScript(t), "qs_check_published", "9.9.9-rc9")
		cmd.Dir = repoRoot(t)
		cmd.Env = quickstartEnv("PATH=" + path)
		out, err := cmd.CombinedOutput()
		log, _ := os.ReadFile(calls)
		return string(out), err, string(log)
	}

	out, err, calls := run(1)
	if err == nil {
		t.Fatalf("an unpublished version passed the check:\n%s", out)
	}
	if calls != "helm show chart "+publishedChartRef+" --version 9.9.9-rc9\n" {
		t.Errorf("the check ran %q, want only helm show chart for 9.9.9-rc9", calls)
	}
	// helm also fails when the registry cannot be reached, so the message
	// must not claim the version is unpublished (review round 2).
	for _, want := range []string{"9.9.9-rc9", "not published yet, or the registry cannot be reached", "QUICKSTART_VERSION=", "QUICKSTART_CHART=local"} {
		if !strings.Contains(out, want) {
			t.Errorf("the failure does not mention %s:\n%s", want, out)
		}
	}

	if out, err, _ := run(0); err != nil {
		t.Errorf("a published version failed the check: %v\n%s", err, out)
	}
}

func TestQuickstartRejectsUnknownChartSource(t *testing.T) {
	cmd := exec.Command("bash", quickstartScript(t))
	cmd.Dir = repoRoot(t)
	cmd.Env = quickstartEnv("QUICKSTART_PLAN=1", "QUICKSTART_CHART=elsewhere")
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Errorf("QUICKSTART_CHART=elsewhere accepted:\n%s", out)
	}
}

// aggregatorLog is shaped like the rc4 aggregator's output in the Story 12.1
// live run: startup noise, a transition in another namespace, then ours.
const aggregatorLog = `{"time":"2026-09-24T03:12:01Z","level":"WARN","msg":"aggregator: nats connect failed","err":"nats: no servers available for connection"}
{"time":"2026-09-24T03:13:40Z","level":"INFO","msg":"aggregator: fsm transition","ring":"aggregator","version":"v1.0.0-rc4","workload_id":"other/Pod/x","from_state":"CLEAN","to_state":"SUSPICIOUS","reason":"escalation_threshold_crossed","score":22,"score_rules":22,"package_id":"epkg-1"}
{"time":"2026-09-24T03:14:23.55529407Z","level":"INFO","msg":"aggregator: fsm transition","ring":"aggregator","version":"v1.0.0-rc4","workload_id":"olaitan-quickstart/Pod/demo","from_state":"CLEAN","to_state":"SUSPICIOUS","reason":"escalation_threshold_crossed","score":36,"score_rules":36,"score_baseline":0,"score_llm":0,"risk_window":false,"package_id":"epkg-c9f477b7d807fb4c"}
{"time":"2026-09-24T03:15:02Z","level":"INFO","msg":"aggregator: fsm transition","ring":"aggregator","version":"v1.0.0-rc4","workload_id":"olaitan-quickstart/Pod/demo","from_state":"SUSPICIOUS","to_state":"RESTRICTED","reason":"escalation_threshold_crossed","score":61.5,"package_id":"epkg-2"}
{"time":"2026-09-24T03:15:03Z","level":"INFO","msg":"aggregator: scored package","workload_id":"olaitan-quickstart/Pod/demo","score":61.5}
`

func TestQuickstartParsesTheFirstTransition(t *testing.T) {
	out, err := quickstartFunc(t, aggregatorLog, "qs_parse_transition", "olaitan-quickstart")
	if err != nil {
		t.Fatalf("qs_parse_transition: %v", err)
	}
	want := "olaitan-quickstart/Pod/demo\tCLEAN\tSUSPICIOUS\t36\t2026-09-24T03:14:23.55529407Z\n"
	if out != want {
		t.Errorf("qs_parse_transition = %q, want %q", out, want)
	}

	if out, err := quickstartFunc(t, aggregatorLog, "qs_parse_transition", "nowhere"); err == nil {
		t.Errorf("no transition in namespace nowhere, but got %q", out)
	}
	// A namespace that is a prefix of another must not match it.
	if out, err := quickstartFunc(t, aggregatorLog, "qs_parse_transition", "olaitan"); err == nil {
		t.Errorf("namespace olaitan matched olaitan-quickstart's transition: %q", out)
	}
}

func TestQuickstartBudget(t *testing.T) {
	if _, err := quickstartFunc(t, "", "qs_within_budget", "599", "600"); err != nil {
		t.Errorf("599 s reported over a 600 s budget: %v", err)
	}
	if _, err := quickstartFunc(t, "", "qs_within_budget", "601", "600"); err == nil {
		t.Error("601 s reported within a 600 s budget")
	}
}

// falcoLog is shaped like Falco's JSON stdout (json_output on): another pod
// reading /etc/shadow under a different rule comes first, then the demo
// pod's alert, then a line from a pod whose name has the demo's as a prefix.
const falcoLog = `{"hostname":"n","output":"x","output_fields":{"container.name":"other","fd.name":"/etc/shadow","k8s.ns.name":"default","k8s.pod.name":"other"},"priority":"Warning","rule":"Some other rule","source":"syscall","time":"2026-09-24T08:41:17Z"}
{"hostname":"n","output":"x","output_fields":{"container.name":"quickstart-demo","fd.name":"/etc/passwd","k8s.ns.name":"olaitan-quickstart","k8s.pod.name":"quickstart-demo"},"priority":"Notice","rule":"Unrelated passwd rule","source":"syscall","time":"2026-09-24T08:41:18Z"}
{"hostname":"n","output":"x","output_fields":{"container.name":"quickstart-demo","fd.name":"/etc/shadow","k8s.ns.name":"olaitan-quickstart","k8s.pod.name":"quickstart-demo"},"priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","time":"2026-09-24T08:41:19Z"}
`

// TestQuickstartRuleIsTheDemoPods (review E2): the printed Falco rule is the
// one that fired for the demo pod in the demo namespace, not the first
// /etc/shadow line in the log.
func TestQuickstartRuleIsTheDemoPods(t *testing.T) {
	out, err := quickstartFunc(t, falcoLog, "qs_parse_rule", "olaitan-quickstart", "quickstart-demo")
	if err != nil {
		t.Fatalf("qs_parse_rule: %v", err)
	}
	if out != "Read sensitive file untrusted\n" {
		t.Errorf("qs_parse_rule = %q, want the demo pod's rule", out)
	}
	for _, c := range [][2]string{{"olaitan-quickstart", "quickstart"}, {"default", "quickstart-demo"}} {
		if out, err := quickstartFunc(t, falcoLog, "qs_parse_rule", c[0], c[1]); err == nil || out != "" {
			t.Errorf("qs_parse_rule %s %s matched %q, want nothing", c[0], c[1], out)
		}
	}
}
