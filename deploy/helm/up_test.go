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

const (
	upCluster = "olaitan-full"
	upMarker  = ".olaitan-up"
)

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
  [ -n "${FAKE_KIND_EXIT:-}" ] && exit "$FAKE_KIND_EXIT"
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
logs="" f=""
for a in "$@"; do
  case "$a" in
  exec) exit "${FAKE_EXEC_EXIT:-0}" ;;
  logs) logs=1 ;;
  app.kubernetes.io/component=aggregator) f="${FAKE_AGG_LOG:-}" ;;
  app.kubernetes.io/name=falco) f="${FAKE_FALCO_LOG:-}" ;;
  esac
done
if [ -n "$logs" ]; then
  [ -n "${FAKE_LOGS_EXIT:-}" ] && exit "$FAKE_LOGS_EXIT"
  [ -n "$f" ] && cat "$f"
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
	"tr", "seq", "mkdir", "env", "dirname", "basename", "rm", "cut", "wc", "sleep", "id", "printf", "test", "cp", "mktemp", "realpath", "ls", "chmod"}

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

// stub replaces bin/<name>. The old entry is removed first: for one of the
// upBasics it is a symlink, and writing through it would overwrite the real
// tool.
func (h *upHost) stub(name, body string) {
	h.t.Helper()
	if err := os.Remove(filepath.Join(h.bin, name)); err != nil && !os.IsNotExist(err) {
		h.t.Fatal(err)
	}
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
	return h.fnEnv(nil, script, name, args...)
}

// fnEnv is fn with extra environment on top of the fake host's.
func (h *upHost) fnEnv(extra []string, script, name string, args ...string) (string, error) {
	h.t.Helper()
	cmd := exec.Command(filepath.Join(h.bin, "bash"), append([]string{"-c", `source "$1"; shift; "$@"`, "up-test", upScript(h.t, script), name}, args...)...)
	cmd.Dir = repoRoot(h.t)
	cmd.Env = upEnv(append(append([]string{}, h.env...), extra...)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// home is the fake host's HOME.
func (h *upHost) home() string {
	for _, kv := range h.env {
		if strings.HasPrefix(kv, "HOME=") {
			return strings.TrimPrefix(kv, "HOME=")
		}
	}
	h.t.Fatal("no HOME in the fake host")
	return ""
}

// write creates dir/name (and dir) with body.
func (h *upHost) write(dir, name, body string) {
	h.t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

// markOut makes the out dir look like make up made it for cluster.
func (h *upHost) markOut(cluster string) {
	h.t.Helper()
	h.write(h.out, upMarker, cluster+"\n")
}

// upMutating are the calls a plan (or a blocked run) must never make.
var upMutating = []string{"kind create", "kind delete", "docker rm", "kubectl config delete", "kubectl create",
	"kubectl run", "kubectl exec", "helm ", "make ", "rm ", "mkdir "}

// loggedMutations stubs rm and mkdir (log only) so they show up in
// calls.log, and returns a func that lists every mutating call made.
func (h *upHost) loggedMutations() func() []string {
	h.t.Helper()
	h.stub("rm", "exit 0")
	h.stub("mkdir", "exit 0")
	return func() []string {
		raw, _ := os.ReadFile(h.calls)
		var bad []string
		for _, l := range strings.Split(string(raw), "\n") {
			for _, m := range upMutating {
				if strings.HasPrefix(l, m) {
					bad = append(bad, l)
				}
			}
		}
		return bad
	}
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
	mutations := h.loggedMutations()
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
	// F2: the first write after preflight is the ownership marker make down
	// looks for before it removes the out dir.
	if cmds[0] != "+ mark "+h.out+"/"+upMarker+" "+upCluster {
		t.Errorf("the first command must write the out-dir marker, got %q", cmds[0])
	}
	if len(cmds) < 2 || cmds[1] != "+ make -s helm-deps" {
		t.Fatalf("the chart must be staged (make -s helm-deps) straight after the marker, got %q", cmds)
	}
	if bad := mutations(); len(bad) > 0 {
		t.Errorf("the plan made mutating calls: %q", bad)
	}

	m := upPlanInstall.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no hack/install-full-kind.sh in the plan:\n%s", out)
	}
	if len(cmds) < 3 || !strings.Contains(cmds[2], "hack/install-full-kind.sh") {
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
			want: []string{"inotify", "instances=128", "watches=65536", "sudo sysctl -w fs.inotify.max_user_instances=512 fs.inotify.max_user_watches=524288",
				"/etc/sysctl.d/99-olaitan.conf", "\n           fs.inotify.max_user_instances = 512\n", "\n           fs.inotify.max_user_watches = 524288\n"},
		},
		{
			// Raising one limit must not lower the other.
			name:  "only instances low",
			setup: func(h *upHost) { h.limits("128", "1048576") },
			want:  []string{"sudo sysctl -w fs.inotify.max_user_instances=512\n", "fs.inotify.max_user_instances = 512\n"},
			not:   []string{"fs.inotify.max_user_watches=524288", "fs.inotify.max_user_watches = "},
		},
		{
			name:  "only watches low",
			setup: func(h *upHost) { h.limits("1024", "8192") },
			want:  []string{"sudo sysctl -w fs.inotify.max_user_watches=524288\n", "fs.inotify.max_user_watches = 524288\n"},
			not:   []string{"fs.inotify.max_user_instances=512", "fs.inotify.max_user_instances = "},
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
			name:  "docker missing",
			setup: func(h *upHost) { _ = os.Remove(filepath.Join(h.bin, "docker")) },
			want:  []string{"docker is not on PATH", "https://docs.docker.com/engine/install/"},
		},
		{
			name:  "kubectl missing",
			setup: func(h *upHost) { _ = os.Remove(filepath.Join(h.bin, "kubectl")) },
			want:  []string{"kubectl is not on PATH", "https://kubernetes.io/docs/tasks/tools/"},
		},
		{
			name:  "openssl missing",
			setup: func(h *upHost) { _ = os.Remove(filepath.Join(h.bin, "openssl")) },
			want:  []string{"openssl is not on PATH", "sudo apt-get install -y openssl"},
		},
		{
			// F4: a marker from an earlier make up with no cluster behind it.
			name: "stale out dir from make up",
			setup: func(h *upHost) {
				h.markOut(upCluster)
				h.write(filepath.Join(h.out, "calico"), "calico-values.yaml", "x")
			},
			want: []string{"left from an earlier run", "fix: make down"},
		},
		{
			// F4: calico/ and audit material with no marker: make e2e-full made it.
			name: "stale out dir from make e2e-full",
			setup: func(h *upHost) {
				h.write(filepath.Join(h.out, "calico"), "calico-values.yaml", "x")
				h.write(filepath.Join(h.out, "audit-certs"), "audit-ca.crt", "x")
			},
			want: []string{"calico", "audit-certs", "make e2e-full-down"},
		},
		{
			// F2: make up would write key material into it and mark it as
			// its own, and make down would then remove it.
			name:  "out dir is someone else's",
			setup: func(h *upHost) { h.write(h.out, "notes.txt", "mine") },
			want:  []string{"was not made by make up", "FULL_OUT_DIR"},
		},
		{
			name:  "marker names another cluster",
			setup: func(h *upHost) { h.markOut("other") },
			want:  []string{"cluster other", "make down FULL_CLUSTER_NAME=other"},
		},
		{
			// F5: the same guard as make down, as a blocker.
			name:  "out dir is the home directory",
			setup: func(h *upHost) { h.env = append(h.env, "UP_OUT_DIR="+h.home()+"//") },
			want:  []string{"refusing out dir", "home directory"},
		},
		{
			// F5: empty is refused by both scripts, never replaced by the default.
			name: "out dir empty",
			env:  []string{"UP_OUT_DIR="},
			want: []string{"refusing out dir", "empty"},
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
			mutations := h.loggedMutations()
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
			if bad := mutations(); len(bad) > 0 {
				t.Errorf("a blocked run made mutating calls: %q", bad)
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
	h.markOut(upCluster)
	h.write(h.out, "kubeconfig", "x")
	mutations := h.loggedMutations()
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
	// F3: every removal is named, including that the cluster goes by name.
	for _, want := range []string{
		"==> deleting kind cluster " + upCluster + " (any kind cluster with this name)",
		"==> removing " + h.out + " (make up's marker names " + upCluster + ")",
		"==> removing " + filepath.Join(repoRoot(t), "hack", ".audit-full"),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("down plan does not say %q:\n%s", want, out)
		}
	}
	if bad := mutations(); len(bad) > 0 {
		t.Errorf("the down plan made mutating calls: %q", bad)
	}

	out, err = h.run("down.sh", "FAKE_CONTEXTS=kind-"+upCluster, "FAKE_DOCKER_PS=abc123")
	if err != nil {
		t.Fatalf("down plan failed: %v\n%s", err, out)
	}
	cmds = strings.Join(planCommands(out), "\n")
	// A second make down, after the out dir is gone, still deletes the
	// cluster (kind cannot lock a kubeconfig in a missing directory).
	if err := os.RemoveAll(h.out); err != nil {
		t.Fatal(err)
	}
	if again, err := h.run("down.sh"); err != nil || !strings.Contains(again, "+ kind delete cluster --name "+upCluster+"\n") {
		t.Errorf("down without the out dir: %v\n%s", err, again)
	}
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
	for _, want := range []string{
		"==> removing leftover node container abc123 (kind cluster " + upCluster + ")",
		"==> removing context kind-" + upCluster + " from the default kubeconfig",
		"==> removing cluster kind-" + upCluster + " from the default kubeconfig",
		"==> removing user kind-" + upCluster + " from the default kubeconfig",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("down plan does not say %q:\n%s", want, out)
		}
	}
}

// TestDownOwnership (F2): the out dir is removed only when make up's marker
// is there and names this cluster. Otherwise make down still removes the
// cluster and the kind kubeconfig entries (by name, never through a
// kubeconfig in a directory it does not own), leaves the directory, says
// why, and exits non-zero.
func TestDownOwnership(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup func(h *upHost)
		want  string
	}{
		{"no marker", func(h *upHost) { h.write(h.out, "kubeconfig", "x") }, "no " + upMarker},
		{"marker names another cluster", func(h *upHost) { h.markOut("other"); h.write(h.out, "kubeconfig", "x") }, "names other"},
		{"marker is a symlink", func(h *upHost) {
			h.write(h.out, "kubeconfig", "x")
			h.write(filepath.Dir(h.out), "elsewhere", upCluster+"\n")
			if err := os.Symlink(filepath.Join(filepath.Dir(h.out), "elsewhere"), filepath.Join(h.out, upMarker)); err != nil {
				t.Fatal(err)
			}
		}, "no " + upMarker},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newUpHost(t)
			c.setup(h)
			out, err := h.run("down.sh", "FAKE_CONTEXTS=kind-"+upCluster)
			if err == nil {
				t.Errorf("down went on with an out dir make up did not make:\n%s", out)
			}
			cmds := strings.Join(planCommands(out), "\n")
			if strings.Contains(cmds, "rm -rf "+h.out) {
				t.Errorf("down removes an out dir it does not own:\n%s", out)
			}
			if !strings.Contains(cmds, "+ kind delete cluster --name "+upCluster+"\n") || strings.Contains(cmds, "--kubeconfig "+h.out) {
				t.Errorf("down must delete the cluster by name, not through the unowned kubeconfig:\n%s", out)
			}
			if !strings.Contains(cmds, "+ kubectl config delete-context kind-"+upCluster) {
				t.Errorf("down must still remove the kind context it owns:\n%s", out)
			}
			if !strings.Contains(out, "not removing "+h.out) || !strings.Contains(out, c.want) {
				t.Errorf("down does not say why it keeps %s (%q):\n%s", h.out, c.want, out)
			}
			if _, err := os.Stat(filepath.Join(h.out, "kubeconfig")); err != nil {
				t.Errorf("the unowned out dir is gone: %v", err)
			}
		})
	}
}

// TestUpMark (F2): make up's marker holds the cluster name, and make down
// accepts exactly that.
func TestUpMark(t *testing.T) {
	h := newUpHost(t)
	if out, err := h.fnEnv([]string{"UP_PLAN="}, "up.sh", "up_mark", h.out, upCluster); err != nil {
		t.Fatalf("up_mark: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(filepath.Join(h.out, upMarker))
	if err != nil || string(raw) != upCluster+"\n" {
		t.Fatalf("marker = %q, %v; want %q", raw, err, upCluster+"\n")
	}
	if fi, err := os.Stat(h.out); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("out dir mode = %v, %v; want 0700 (it holds key material)", fi, err)
	}
	if out, err := h.fn("down.sh", "down_owns", h.out, upCluster); err != nil {
		t.Errorf("down does not accept make up's marker: %v\n%s", err, out)
	}
	if _, err := h.fn("down.sh", "down_owns", h.out, "other"); err == nil {
		t.Error("down accepts a marker for another cluster")
	}
}

// TestDownRefusesDangerousOutDir: the out dir is rm -rf'd, so an empty
// value, /, the home directory or the repository itself is refused before
// anything runs.
//
// F1: the check is on the canonical path (realpath -m, the repository with
// pwd -P), so // and .. spellings are caught, every parent of the home
// directory and of the repository is refused, and a symlink is refused
// before it is resolved. F5: make up refuses the same list in preflight.
func TestDownRefusesDangerousOutDir(t *testing.T) {
	h := newUpHost(t)
	home := h.home()
	repo := repoRoot(t)
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{
		"", "/", "//", "///", home, home + "/", home + "//", home + "/./",
		home + "/../" + filepath.Base(home), filepath.Dir(home), filepath.Dir(filepath.Dir(home)),
		repo, repo + "/", filepath.Dir(repo), filepath.Join(repo, "hack"), filepath.Join(repo, "hack") + "/../..",
		link, link + "/", link + "//",
		"relative/dir", "./x",
	} {
		out, err := h.run("down.sh", "UP_OUT_DIR="+d)
		if err == nil || !strings.Contains(out, "refusing") {
			t.Errorf("down UP_OUT_DIR=%q accepted: %v\n%s", d, err, out)
		}
		if cmds := planCommands(out); len(cmds) > 0 {
			t.Errorf("down UP_OUT_DIR=%q ran %q", d, cmds)
		}
		out, err = h.run("up.sh", "UP_OUT_DIR="+d)
		if err == nil || !strings.Contains(out, "refusing out dir") || !strings.Contains(out, "nothing was created") {
			t.Errorf("up UP_OUT_DIR=%q accepted: %v\n%s", d, err, out)
		}
		if cmds := planCommands(out); len(cmds) > 0 {
			t.Errorf("up UP_OUT_DIR=%q ran %q", d, cmds)
		}
	}
	if _, err := os.Stat(target); err != nil {
		t.Errorf("the symlink target is gone: %v", err)
	}
	// A path that only looks like one of those is fine.
	for _, d := range []string{home + "/.olaitan-full", home + "/.olaitan-full/", filepath.Join(filepath.Dir(repo), "elsewhere")} {
		if out, err := h.fn("down.sh", "olaitan_out_dir", d, repo); err != nil {
			t.Errorf("olaitan_out_dir %q refused: %v\n%s", d, err, out)
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

// TestDownLeftoversUnverified (F9): a probe that cannot run is never read as
// "nothing left".
func TestDownLeftoversUnverified(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup func(h *upHost)
		env   string
		want  string
	}{
		{"kind missing", func(h *upHost) { _ = os.Remove(filepath.Join(h.bin, "kind")) }, "", "kind get clusters"},
		{"kind fails", nil, "FAKE_KIND_EXIT=1", "kind get clusters"},
		{"docker missing", func(h *upHost) { _ = os.Remove(filepath.Join(h.bin, "docker")) }, "", "docker ps"},
		{"docker fails", func(h *upHost) { h.stub("docker", "exit 1") }, "", "docker ps"},
		{"kubectl missing", func(h *upHost) { _ = os.Remove(filepath.Join(h.bin, "kubectl")) }, "", "kubectl config get-contexts"},
		{"kubectl fails", func(h *upHost) { h.stub("kubectl", "exit 1") }, "", "kubectl config get-contexts"},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newUpHost(t)
			if c.setup != nil {
				c.setup(h)
			}
			if c.env != "" {
				h.env = append(h.env, c.env)
			}
			out, err := h.fn("down.sh", "down_leftovers")
			if err == nil || !strings.Contains(out, "could not verify") || !strings.Contains(out, c.want) {
				t.Errorf("unverified probe not reported (err=%v):\n%s", err, out)
			}
			if strings.Contains(out, "no cluster, no container, no kubeconfig context left") {
				t.Errorf("down claims nothing is left when it could not look:\n%s", out)
			}
		})
	}
}

// TestDownMainFailsWhenLeft (AC3): a real (not plan) make down whose final
// check finds a cluster exits non-zero. Every tool, rm included, is a
// stand-in that only logs.
func TestDownMainFailsWhenLeft(t *testing.T) {
	h := newUpHost(t)
	h.markOut(upCluster)
	h.stub("rm", "exit 0")
	out, err := h.run("down.sh", "UP_PLAN=", "FAKE_KIND_CLUSTERS="+upCluster)
	if err == nil || !strings.Contains(out, "left: kind cluster "+upCluster) {
		t.Errorf("down passed with a cluster left (err=%v):\n%s", err, out)
	}
	raw, _ := os.ReadFile(h.calls)
	if !strings.Contains(string(raw), "rm -rf "+h.out) {
		t.Errorf("down did not remove its own out dir:\n%s", raw)
	}
}

// upDetectLogs writes the aggregator and Falco log fixtures.
func upDetectLogs(t *testing.T, transition, alert bool) (agg, falco string) {
	t.Helper()
	dir := t.TempDir()
	agg, falco = filepath.Join(dir, "agg.log"), filepath.Join(dir, "falco.log")
	a := `{"time":"2026-09-25T06:30:00Z","msg":"aggregator: started"}` + "\n"
	if transition {
		a += `{"time":"2026-09-25T06:42:25Z","msg":"aggregator: fsm transition","workload_id":"olaitan-up/Pod/up-demo","from_state":"CLEAN","to_state":"SUSPICIOUS","score":27.5}` + "\n"
	}
	f := `{"rule":"Read sensitive file untrusted","output_fields":{"k8s.ns.name":"kube-system","k8s.pod.name":"other","fd.name":"/etc/shadow"}}` + "\n"
	if alert {
		f += `{"rule":"Read sensitive file untrusted","output_fields":{"k8s.ns.name":"olaitan-up","k8s.pod.name":"up-demo","fd.name":"/etc/shadow"}}` + "\n"
	}
	for p, body := range map[string]string{agg: a, falco: f} {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return agg, falco
}

// TestUpDetect (F6, F10): make up succeeds only when Falco alerted on the
// demo pod's /etc/shadow read AND the aggregator moved a workload in its
// namespace, as hack/stranger.sh requires. A log that cannot be read stops
// the run; a failed exec is counted apart from the reads that ran.
func TestUpDetect(t *testing.T) {
	fast := "UP_POLL=0; UP_ATTEMPT_GAP=1; "
	for _, c := range []struct {
		name              string
		transition, alert bool
		env               []string
		ok                bool
		want              []string
	}{
		{"both", true, true, nil, true, []string{"reads=1 failed=0", "rule=Read sensitive file untrusted", "found=olaitan-up/Pod/up-demo"}},
		{"transition without a Falco alert", true, false, nil, false, []string{"product: no Falco alert", "none"}},
		{"Falco alert without a transition", false, true, nil, false, []string{"product: no FSM transition"}},
		{"exec fails", true, true, []string{"FAKE_EXEC_EXIT=1"}, true, []string{"reads=0 failed=1", "exec 1 failed"}},
		{"log read fails", true, true, []string{"FAKE_LOGS_EXIT=7"}, false, []string{"reading the aggregator log exited 7"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newUpHost(t)
			agg, falco := upDetectLogs(t, c.transition, c.alert)
			env := append([]string{"UP_PLAN=", "FAKE_AGG_LOG=" + agg, "FAKE_FALCO_LOG=" + falco}, c.env...)
			out, err := h.fnEnv(env, "up.sh", "eval", fast+`up_detect "$(date +%s)" 3 && printf 'reads=%s failed=%s\nrule=%s\nfound=%s\n' "$UP_READS" "$UP_FAILED" "$UP_RULE" "$UP_FOUND"`)
			if (err == nil) != c.ok {
				t.Errorf("err=%v, want ok=%v:\n%s", err, c.ok, out)
			}
			for _, w := range c.want {
				if !strings.Contains(out, w) {
					t.Errorf("output lacks %q:\n%s", w, out)
				}
			}
		})
	}
	raw, err := os.ReadFile(upScript(t, "up.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if regexp.MustCompile(`qs_parse_rule[^\n]*\|\|\s*true`).Match(raw) {
		t.Error("hack/up.sh swallows a failed Falco rule lookup with || true")
	}
}
