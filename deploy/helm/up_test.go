//go:build helm

package helm_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Story 12.3: `make up` takes a machine with Docker, kind, helm and kubectl
// to a live detection on the full profile (kind-full, every source on,
// Falco on) and `make down` removes all of it. None of these tests creates
// anything: the scripts run in plan mode (UP_PLAN=1) with stand-ins for
// docker, kind, helm, kubectl, openssl and python3 first on PATH, and the
// host facts preflight reads (inotify limits, BTF, kernel) come from
// fixtures.

const upCluster = "olaitan-full"

func upScript(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "hack", name)
}

// upEnv is os.Environ() without PATH, KUBECONFIG, any UP_* or FAKE_*
// setting, or anything hack/falco-support.env defines (preflight lets the
// environment override those), then the test's own settings on top.
func upEnv(extra ...string) []string {
	var env []string
	for _, kv := range os.Environ() {
		switch {
		case strings.HasPrefix(kv, "UP_"), strings.HasPrefix(kv, "FAKE_"), strings.HasPrefix(kv, "FALCO_"),
			strings.HasPrefix(kv, "PATH="), strings.HasPrefix(kv, "KUBECONFIG="):
			continue
		}
		env = append(env, kv)
	}
	return append(env, extra...)
}

// upHost is a fake host: a bin dir of stand-ins plus the basic utilities the
// scripts need (and nothing else from the real PATH, so a real kind or
// docker can never be reached), and fixtures for the host facts.
type upHost struct {
	t       *testing.T
	bin     string
	calls   string
	inotify string
	btf     string
	out     string
	env     []string
}

// stubs: every stand-in logs its arguments and answers read-only probes
// from FAKE_* variables. Nothing here touches a real cluster or daemon.
var upStubs = map[string]string{
	"docker": `case "$1" in
info) exit "${FAKE_DOCKER_EXIT:-0}" ;;
ps) [ -n "${FAKE_DOCKER_PS:-}" ] && printf '%s\n' "$FAKE_DOCKER_PS"; exit 0 ;;
esac
exit 0`,
	"kind": `if [ "$1" = get ] && [ "$2" = clusters ]; then
  [ -n "${FAKE_KIND_CLUSTERS:-}" ] && printf '%s\n' "$FAKE_KIND_CLUSTERS"
  exit 0
fi
exit 0`,
	"kubectl": `if [ "$1" = config ]; then
  case "$2" in
  get-contexts) [ -n "${FAKE_CONTEXTS:-}" ] && printf '%s\n' "$FAKE_CONTEXTS" ;;
  get-clusters) printf 'NAME\n'; [ -n "${FAKE_CONTEXTS:-}" ] && printf '%s\n' "$FAKE_CONTEXTS" ;;
  get-users) printf 'NAME\n'; [ -n "${FAKE_CONTEXTS:-}" ] && printf '%s\n' "$FAKE_CONTEXTS" ;;
  esac
  exit 0
fi
exit 0`,
	"helm":    `exit 0`,
	"openssl": `exit 0`,
	"make":    `exit 0`,
	"python3": `exit "${FAKE_PYTHON_EXIT:-0}"`,
}

// upBasics are linked into the fake PATH from the real one.
var upBasics = []string{"bash", "sh", "sed", "grep", "cat", "date", "uname", "sort", "head", "tail",
	"tr", "seq", "mkdir", "env", "dirname", "basename", "rm", "cut", "wc", "sleep", "id", "printf", "test", "cp", "mktemp"}

func newUpHost(t *testing.T) *upHost {
	t.Helper()
	dir := t.TempDir()
	h := &upHost{
		t:       t,
		bin:     filepath.Join(dir, "bin"),
		calls:   filepath.Join(dir, "calls.log"),
		inotify: filepath.Join(dir, "inotify"),
		btf:     filepath.Join(dir, "vmlinux"),
		out:     filepath.Join(dir, "olaitan-full-out"),
	}
	for _, d := range []string{h.bin, h.inotify} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range upStubs {
		h.stub(name, body)
	}
	for _, name := range upBasics {
		p, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		if err := os.Symlink(p, filepath.Join(h.bin, name)); err != nil {
			t.Fatal(err)
		}
	}
	h.limits("512", "524288")
	if err := os.WriteFile(h.btf, []byte("btf"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.env = []string{
		"PATH=" + h.bin,
		"HOME=" + dir,
		"UP_PLAN=1",
		"UP_CLUSTER=" + upCluster,
		"UP_OUT_DIR=" + h.out,
		"UP_WORKERS=1",
		"UP_INOTIFY_DIR=" + h.inotify,
		"UP_BTF_FILE=" + h.btf,
		"UP_KERNEL=6.8.0-45-generic",
		"UP_OS=Linux",
	}
	return h
}

func (h *upHost) stub(name, body string) {
	h.t.Helper()
	script := "#!/bin/sh\necho \"" + name + " $*\" >>\"" + h.calls + "\"\n" + body + "\n"
	if err := os.WriteFile(filepath.Join(h.bin, name), []byte(script), 0o755); err != nil {
		h.t.Fatal(err)
	}
}

func (h *upHost) limits(instances, watches string) {
	h.t.Helper()
	for f, v := range map[string]string{"max_user_instances": instances, "max_user_watches": watches} {
		if err := os.WriteFile(filepath.Join(h.inotify, f), []byte(v+"\n"), 0o644); err != nil {
			h.t.Fatal(err)
		}
	}
}

// run executes hack/<script> with the fake host and extra env.
func (h *upHost) run(script string, extra ...string) (string, error) {
	h.t.Helper()
	cmd := exec.Command(filepath.Join(h.bin, "bash"), upScript(h.t, script))
	cmd.Dir = repoRoot(h.t)
	cmd.Env = upEnv(append(append([]string{}, h.env...), extra...)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// fn sources hack/<script> and calls one of its functions. $0 is never the
// script path, so main cannot run (the Story 12.2 incident: a helper that
// passed the script as $0 made a unit test create a real kind cluster).
func (h *upHost) fn(script, name string, args ...string) (string, error) {
	h.t.Helper()
	cmd := exec.Command(filepath.Join(h.bin, "bash"), append([]string{"-c", `source "$1"; shift; "$@"`, "up-test", upScript(h.t, script), name}, args...)...)
	cmd.Dir = repoRoot(h.t)
	cmd.Env = upEnv(h.env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func planCommands(out string) []string {
	var cmds []string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "+ ") {
			cmds = append(cmds, l)
		}
	}
	return cmds
}

func TestUpDownTargetsRunTheScripts(t *testing.T) {
	up := quickstartTarget(t, "up")
	for _, want := range []string{"hack/up.sh", "$(FULL_CLUSTER_NAME)", "$(FULL_OUT_DIR)", "$(FULL_WORKERS)", "$(UP_BUDGET)"} {
		if !strings.Contains(up, want) {
			t.Errorf("make up lacks %s:\n%s", want, up)
		}
	}
	down := quickstartTarget(t, "down")
	for _, want := range []string{"hack/down.sh", "$(FULL_CLUSTER_NAME)", "$(FULL_OUT_DIR)"} {
		if !strings.Contains(down, want) {
			t.Errorf("make down lacks %s:\n%s", want, down)
		}
	}
}

// TestUpHasNoInjection: the detection make up prints must come from Falco
// seeing a real action, exactly as in the quickstart (Story 12.2 AC2).
func TestUpHasNoInjection(t *testing.T) {
	path := map[string]string{
		"Makefile up":   quickstartTarget(t, "up"),
		"Makefile down": quickstartTarget(t, "down"),
	}
	for _, s := range []string{"up.sh", "down.sh"} {
		raw, err := os.ReadFile(upScript(t, s))
		if err != nil {
			t.Fatal(err)
		}
		path["hack/"+s] = string(raw)
	}
	forbidden := []*regexp.Regexp{
		regexp.MustCompile(`(?i)nats\s+(pub|publish|req|request|stream\s+add)`),
		regexp.MustCompile(`(?i)jetstream`),
		regexp.MustCompile(`port-forward`),
		regexp.MustCompile(`:4222`),
		regexp.MustCompile(`olaitan\.events\.`),
		regexp.MustCompile(`falco\.enabled\s*=\s*false`),
		regexp.MustCompile(`watch_config_files\s*=\s*false`),
		regexp.MustCompile(`endpoints\.falco`),
		regexp.MustCompile(`\bgo (run|build)\b`),
	}
	for where, text := range path {
		for i, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			for _, re := range forbidden {
				if re.MatchString(line) {
					t.Errorf("%s:%d matches %s: %s", where, i+1, re, strings.TrimSpace(line))
				}
			}
		}
	}
}

var (
	upPlanInstall = regexp.MustCompile(`(?m)^\+ env (.*) hack/install-full-kind\.sh (\S+)$`)
	upPlanExec    = regexp.MustCompile(`(?m)^\+ kubectl (?:--kubeconfig \S+ --context \S+ )-n (\S+) exec \S+ -c \S+ -- cat /etc/shadow$`)
)

// TestUpPlan (AC1): the order is preflight, staging, the kind-full bring-up
// with the full profile, the waits, then a real read of /etc/shadow in a
// namespace the agent scores, from a pinned image. The clock starts before
// preflight, so the printed time is the whole command.
func TestUpPlan(t *testing.T) {
	h := newUpHost(t)
	out, err := h.run("up.sh")
	if err != nil {
		t.Fatalf("up plan on a good host failed: %v\n%s", err, out)
	}
	clock := strings.Index(out, "clock starts")
	pre := strings.Index(out, "preflight")
	cmds := planCommands(out)
	if clock < 0 || pre < 0 || clock > pre {
		t.Errorf("the clock must start before preflight:\n%s", out)
	}
	if len(cmds) == 0 || strings.Index(out, cmds[0]) < pre {
		t.Fatalf("preflight must run before any command:\n%s", out)
	}
	if !strings.Contains(out, "budget 900s") {
		t.Errorf("the default budget is not 900 s:\n%s", out)
	}
	if cmds[0] != "+ make -s helm-deps" {
		t.Errorf("the first command must stage the chart (make -s helm-deps), got %q", cmds[0])
	}

	m := upPlanInstall.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no hack/install-full-kind.sh in the plan:\n%s", out)
	}
	if len(cmds) < 2 || !strings.Contains(cmds[1], "hack/install-full-kind.sh") {
		t.Errorf("the kind-full bring-up must come straight after staging, got %q", cmds)
	}
	for _, want := range []string{"CLUSTER_NAME=" + upCluster, "WORKERS=1", "KUBECONFIG=" + h.out + "/kubeconfig"} {
		if !strings.Contains(m[1], want) {
			t.Errorf("install-full-kind.sh is not given %s: %s", want, m[0])
		}
	}
	if m[2] != h.out {
		t.Errorf("install-full-kind.sh out dir = %s, want %s", m[2], h.out)
	}

	kctx := "--kubeconfig " + h.out + "/kubeconfig --context kind-" + upCluster
	for _, rs := range []string{"ds/olaitan-falco", "ds/olaitan-collector", "deploy/olaitan-aggregator"} {
		if !strings.Contains(out, "+ kubectl "+kctx+" -n default rollout status "+rs) {
			t.Errorf("the plan does not wait for %s through the out-dir kubeconfig:\n%s", rs, out)
		}
	}
	if strings.Contains(out, "wait pod --all") {
		t.Error("kubectl wait pod --all never returns on kind-full: the Ollama pull Job pod completes and is never Ready")
	}

	e := upPlanExec.FindStringSubmatch(out)
	if e == nil {
		t.Fatalf("no `kubectl ... -n <ns> exec <pod> -c <container> -- cat /etc/shadow` in the plan:\n%s", out)
	}
	for _, ex := range append(shippedExclusions(t), "default") {
		if e[1] == ex {
			t.Errorf("the attack runs in %s, which the full profile does not score", e[1])
		}
	}
	img := planPodImg.FindStringSubmatch(out)
	if img == nil || !regexp.MustCompile(`^[^@\s]+:[^@\s]+@sha256:[0-9a-f]{64}$`).MatchString(img[1]) {
		t.Errorf("attack pod image is not pinned by tag and digest: %v", img)
	}

	// UP_WORKERS empty keeps hack/kind-full.yaml's node list as written, and
	// then needs no python3.
	out, err = h.run("up.sh", "UP_WORKERS=", "FAKE_PYTHON_EXIT=1")
	if err != nil {
		t.Fatalf("UP_WORKERS= plan failed: %v\n%s", err, out)
	}
	if m := upPlanInstall.FindStringSubmatch(out); m == nil || !strings.Contains(m[1], "WORKERS= ") {
		t.Errorf("UP_WORKERS= must pass WORKERS= (kind-full.yaml as written): %v", m)
	}
}

// TestUpPreflightBlockers (AC2): each blocker names the exact remedy, and a
// blocked run creates nothing: not one command is printed or run.
func TestUpPreflightBlockers(t *testing.T) {
	cases := []struct {
		name  string
		setup func(h *upHost)
		env   []string
		want  []string
		not   []string
	}{
		{
			name:  "stock inotify limits",
			setup: func(h *upHost) { h.limits("128", "65536") },
			want:  []string{"inotify", "instances=128", "watches=65536", "sudo sysctl -w fs.inotify.max_user_instances=512 fs.inotify.max_user_watches=524288"},
		},
		{
			// Raising one limit must not lower the other.
			name:  "only instances low",
			setup: func(h *upHost) { h.limits("128", "1048576") },
			want:  []string{"sudo sysctl -w fs.inotify.max_user_instances=512\n"},
			not:   []string{"fs.inotify.max_user_watches=524288"},
		},
		{
			name:  "only watches low",
			setup: func(h *upHost) { h.limits("1024", "8192") },
			want:  []string{"sudo sysctl -w fs.inotify.max_user_watches=524288\n"},
			not:   []string{"fs.inotify.max_user_instances=512"},
		},
		{
			name: "no BTF",
			env:  []string{"UP_BTF_FILE=/nonexistent/vmlinux"},
			want: []string{"/nonexistent/vmlinux", "BTF", "CONFIG_DEBUG_INFO_BTF=y"},
		},
		{
			name: "Docker not reachable",
			env:  []string{"FAKE_DOCKER_EXIT=1"},
			want: []string{"Docker", "sudo systemctl start docker", "sudo usermod -aG docker"},
		},
		{
			name: "cluster already there",
			env:  []string{"FAKE_KIND_CLUSTERS=other\n" + upCluster},
			want: []string{"kind cluster " + upCluster + " already exists", "make down"},
		},
		{
			name:  "kind missing",
			setup: func(h *upHost) { _ = os.Remove(filepath.Join(h.bin, "kind")) },
			want:  []string{"kind is not on PATH", "https://kind.sigs.k8s.io/docs/user/quick-start/#installation"},
		},
		{
			name:  "helm missing",
			setup: func(h *upHost) { _ = os.Remove(filepath.Join(h.bin, "helm")) },
			want:  []string{"helm is not on PATH", "https://helm.sh/docs/intro/install/"},
		},
		{
			name: "PyYAML missing with a trimmed node list",
			env:  []string{"FAKE_PYTHON_EXIT=1"},
			want: []string{"PyYAML", "sudo apt-get install -y python3-yaml", "make up FULL_WORKERS="},
		},
		{
			name: "a Falco the kernel is known to crash",
			env:  []string{"UP_KERNEL=7.0.0-1013-aws", "FALCO_PINNED_VERSION=0.44.0"},
			want: []string{"Falco 0.44.0 crashes", "7.0.0-1013-aws"},
		},
		{
			name:  "every blocker in one run",
			setup: func(h *upHost) { h.limits("128", "65536") },
			env:   []string{"UP_BTF_FILE=/nonexistent/vmlinux", "FAKE_DOCKER_EXIT=1"},
			want:  []string{"inotify", "BTF", "sudo systemctl start docker", "3 blocker(s)"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newUpHost(t)
			if c.setup != nil {
				c.setup(h)
			}
			out, err := h.run("up.sh", c.env...)
			if err == nil {
				t.Fatalf("preflight let the run go on:\n%s", out)
			}
			for _, w := range c.want {
				if !strings.Contains(out, w) {
					t.Errorf("output lacks %q:\n%s", w, out)
				}
			}
			for _, n := range c.not {
				if strings.Contains(out, n) {
					t.Errorf("output has %q:\n%s", n, out)
				}
			}
			if !strings.Contains(out, "nothing was created") {
				t.Errorf("a blocked run must say nothing was created:\n%s", out)
			}
			if cmds := planCommands(out); len(cmds) > 0 {
				t.Errorf("a blocked run printed commands %q", cmds)
			}
			log, _ := os.ReadFile(h.calls)
			for _, l := range strings.Split(string(log), "\n") {
				if strings.HasPrefix(l, "kind create") || strings.HasPrefix(l, "helm ") || strings.HasPrefix(l, "make ") {
					t.Errorf("a blocked run called %q", l)
				}
			}
		})
	}
}

// TestUpRejectsBadBudget: UP_BUDGET is checked before preflight.
func TestUpRejectsBadBudget(t *testing.T) {
	for _, b := range []string{"abc", "-5", "1.5", "15m", "900s"} {
		h := newUpHost(t)
		out, err := h.run("up.sh", "UP_BUDGET="+b)
		if err == nil || !strings.Contains(out, "UP_BUDGET must be a whole number of seconds") {
			t.Errorf("UP_BUDGET=%s: err=%v\n%s", b, err, out)
		}
		if cmds := planCommands(out); len(cmds) > 0 {
			t.Errorf("UP_BUDGET=%s ran %q", b, cmds)
		}
	}
}

func TestUpBudget(t *testing.T) {
	h := newUpHost(t)
	if _, err := h.fn("up.sh", "qs_within_budget", "899", "900"); err != nil {
		t.Errorf("899 s reported over a 900 s budget: %v", err)
	}
	if _, err := h.fn("up.sh", "qs_within_budget", "901", "900"); err == nil {
		t.Error("901 s reported within a 900 s budget")
	}
}

// TestDownPlan (AC3): make down deletes the cluster through the kubeconfig
// make up wrote, removes a kind context from the default kubeconfig when
// one is there, and removes the out dir and the audit mount.
func TestDownPlan(t *testing.T) {
	h := newUpHost(t)
	out, err := h.run("down.sh")
	if err != nil {
		t.Fatalf("down plan failed: %v\n%s", err, out)
	}
	cmds := strings.Join(planCommands(out), "\n")
	for _, want := range []string{
		"+ kind delete cluster --name " + upCluster + " --kubeconfig " + h.out + "/kubeconfig",
		"+ rm -rf " + h.out,
		"+ rm -rf " + filepath.Join(repoRoot(t), "hack", ".audit-full"),
	} {
		if !strings.Contains(cmds, want) {
			t.Errorf("down plan lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(cmds, "kubectl config delete-") {
		t.Errorf("no kind context in the default kubeconfig, but down deletes one:\n%s", out)
	}

	out, err = h.run("down.sh", "FAKE_CONTEXTS=kind-"+upCluster, "FAKE_DOCKER_PS=abc123")
	if err != nil {
		t.Fatalf("down plan failed: %v\n%s", err, out)
	}
	cmds = strings.Join(planCommands(out), "\n")
	for _, want := range []string{
		"+ kubectl config delete-context kind-" + upCluster,
		"+ kubectl config delete-cluster kind-" + upCluster,
		"+ kubectl config delete-user kind-" + upCluster,
		"+ docker rm -f abc123",
	} {
		if !strings.Contains(cmds, want) {
			t.Errorf("down plan lacks %q:\n%s", want, out)
		}
	}
}

// TestDownRefusesDangerousOutDir: the out dir is rm -rf'd, so an empty
// value, /, the home directory or the repository itself is refused before
// anything runs.
func TestDownRefusesDangerousOutDir(t *testing.T) {
	h := newUpHost(t)
	home := ""
	for _, kv := range h.env {
		if strings.HasPrefix(kv, "HOME=") {
			home = strings.TrimPrefix(kv, "HOME=")
		}
	}
	for _, d := range []string{"", "/", home, home + "/", repoRoot(t), "relative/dir"} {
		out, err := h.run("down.sh", "UP_OUT_DIR="+d)
		if err == nil || !strings.Contains(out, "refusing") {
			t.Errorf("UP_OUT_DIR=%q accepted: %v\n%s", d, err, out)
		}
		if cmds := planCommands(out); len(cmds) > 0 {
			t.Errorf("UP_OUT_DIR=%q ran %q", d, cmds)
		}
	}
}

// TestDownLeftovers (AC3): the check make down ends with fails on any
// cluster, node container or kubeconfig context left behind.
func TestDownLeftovers(t *testing.T) {
	h := newUpHost(t)
	if out, err := h.fn("down.sh", "down_leftovers"); err != nil || !strings.Contains(out, "no cluster, no container, no kubeconfig context") {
		t.Errorf("a clean host failed the check: %v\n%s", err, out)
	}
	for _, c := range []struct {
		env  string
		want string
	}{
		{"FAKE_KIND_CLUSTERS=" + upCluster, "cluster " + upCluster},
		{"FAKE_DOCKER_PS=abc123", "container abc123"},
		{"FAKE_CONTEXTS=kind-" + upCluster, "context kind-" + upCluster},
	} {
		h.env = append(h.env, c.env)
		out, err := h.fn("down.sh", "down_leftovers")
		if err == nil || !strings.Contains(out, c.want) {
			t.Errorf("%s: leftover not reported (err=%v):\n%s", c.env, err, out)
		}
		h.env = h.env[:len(h.env)-1]
	}
	if err := os.MkdirAll(h.out, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.out, "kubeconfig"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := h.fn("down.sh", "down_leftovers"); err == nil || !strings.Contains(out, h.out+"/kubeconfig") {
		t.Errorf("the out-dir kubeconfig was not reported (err=%v):\n%s", err, out)
	}
}
