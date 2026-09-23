//go:build e2e

package e2e_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/olokotoh/olaitan/internal/subjects"
)

// fullProfileSources is Story 10.5's five-source contract for the
// kind-full reference profile.
//
// The metric label is the schema EventSource, not the Helm key, and two
// of the five differ from the name an operator types into values.yaml:
//
//	containerdSensor -> source="runtime"  (SourceRuntime)
//	calicoSensor     -> source="network"  (SourceNetwork)
//
// internal/schema/event.go pins both so the adapter axis names the
// architectural layer rather than the implementation: a future CRI-O or
// Cilium adapter reports on the same axis. Asserting "containerd" or
// "calico" here fails against a perfectly healthy sensor, which is a
// uniquely expensive way to waste a cluster rebuild. Confirmed against
// live /metrics output on kind-full, 2026-09-21.
var fullProfileSources = []struct {
	source  string
	helmKey string
}{
	{"falco", "falco.enabled + falcoIngest"},
	{"audit", "auditWebhook.enabled"},
	{"runtime", "containerdSensor.enabled"},
	{"network", "calicoSensor.enabled"},
	{"applog", "applogSidecar.enabled"},
}

func sourceHealthyRE(source string) *regexp.Regexp {
	return regexp.MustCompile(
		fmt.Sprintf(`(?m)^olaitan_source_healthy\{[^}]*source=%q[^}]*\} 1$`, source))
}

// TestFullProfileAllFiveSourcesHealthy is Story 10.5 AC1: on kind-full,
// each of the five sources reports healthy in metrics within 5 minutes of
// install. Until Story 10.5 there was no profile that switched all five on
// at once -- values-kind.yaml leaves auditWebhook, containerdSensor,
// calicoSensor and applogSidecar at their chart defaults of false -- so
// this combination had never been exercised on a live cluster.
func TestFullProfileAllFiveSourcesHealthy(t *testing.T) {
	// Gated like every other profile-specific test in this package
	// (OLT_E2E_FORENSICS, OLT_E2E_RSLT, OLT_E2E_OVERLAYS). Without this,
	// `make e2e-local` runs the whole package UNFILTERED against the kindnet
	// e2e cluster installed from values-kind.yaml, where four of these five
	// sources are deliberately off: the test would burn its full 5-minute
	// budget and fail on a cluster that is behaving exactly as intended.
	if os.Getenv("OLT_E2E_FULL") == "" {
		t.Skip("full-profile smoke skipped; set OLT_E2E_FULL=1 (make e2e-full) to run")
	}
	requireKindCluster(t)

	// requireKindCluster only checks that a cluster of the expected NAME
	// appears in `kind get clusters`; it does not check that kubectl is
	// pointed at it. On a developer box that still has olaitan-e2e lying
	// around, that guard passes while the client talks to something else
	// entirely, so a green result would prove nothing. Assert the profile
	// itself: the audit webhook is off in every other values overlay, so its
	// presence is a reliable marker that values-full.yaml is what is installed.
	requireFullProfile(t)

	requirePodsExist(t, "app.kubernetes.io/component=collector")

	// Health is PER NODE, so no single collector pod ever reports all five.
	// The collector is a DaemonSet; the audit receiver is only dialled by the
	// apiserver on a control-plane node, and the containerd sensor only sees
	// lifecycle events on nodes where pods actually churn. Observed on
	// kind-full 2026-09-21: the control-plane pod reported runtime=0 while the
	// worker reported runtime=1, and the worker reported audit=0 permanently.
	// Scraping one pod (port-forward ds/olaitan-collector picks an arbitrary
	// one) therefore cannot pass, however healthy the cluster is. AC1 is a
	// statement about the cluster, so the assertion unions across every pod.
	names := strings.Fields(strings.TrimSpace(kubectl(t,
		"get", "pods", "-n", defaultNamespace,
		"-l", "app.kubernetes.io/component=collector",
		"-o", "jsonpath={range .items[*]}{.metadata.name} {end}")))
	if len(names) == 0 {
		t.Fatal("no collector pods found")
	}
	ports := forwardCollectors(t, names)

	// AC1 says "within 5 minutes of install". Falco's metrics interval is 1m
	// and Calico's Goldmane flow window is comparable, so the slow sources
	// land in the tail of that budget.
	deadline := time.Now().Add(5 * time.Minute)
	pending := make(map[string]string, len(fullProfileSources))
	for _, s := range fullProfileSources {
		pending[s.source] = s.helmKey
	}

	seen := map[string]string{}
	for time.Now().Before(deadline) && len(pending) > 0 {
		for i, port := range ports {
			body := fullProfileScrape(port)
			if body == "" {
				continue
			}
			for source := range pending {
				if sourceHealthyRE(source).MatchString(body) {
					seen[source] = names[i]
					delete(pending, source)
				}
			}
		}
		if len(pending) == 0 {
			for _, s := range fullProfileSources {
				t.Logf("source %-8s healthy on %s", s.source, seen[s.source])
			}
			return
		}
		time.Sleep(5 * time.Second)
	}

	// Iterate the ordered slice, not the map, so the failure message is
	// stable run to run and diffable between two failing runs.
	var missing []string
	for _, s := range fullProfileSources {
		if helmKey, still := pending[s.source]; still {
			missing = append(missing, fmt.Sprintf("%s (%s)", s.source, helmKey))
		}
	}
	var snapshot strings.Builder
	for i, name := range names {
		fmt.Fprintf(&snapshot, "  --- %s\n%s\n", name,
			grepLines(fullProfileScrape(ports[i]), "olaitan_source_healthy"))
	}
	t.Fatalf("kind-full: %d of %d sources never reported healthy on ANY collector within 5m: %s\n%s",
		len(pending), len(fullProfileSources), strings.Join(missing, ", "), snapshot.String())
}

// fullProfileScrape fetches one collector's /metrics over a port-forward
// bound to a FREE, dynamically chosen local port.
//
// Two mechanisms were tried and only this one works here, which is worth
// recording because the reason is the profile itself:
//
//   - The apiserver pod proxy (kubectl get --raw .../proxy/metrics) routes
//     apiserver -> POD IP, so it is subject to this release's NetworkPolicy.
//     Port 9090 is not admitted from the apiserver, so it succeeds only for
//     the collector that happens to share a node with the apiserver and
//     silently returns nothing for every other pod. That reads as a flat zero
//     for whichever sources are node-local to the others.
//   - port-forward routes apiserver -> KUBELET -> container, which bypasses
//     pod NetworkPolicy entirely. That is why it works on an enforcing CNI.
//
// The port is chosen at run time rather than from a fixed base because
// portForward() returns as soon as the port DIALS, without checking the bind
// belonged to its own child: any leftover forward on a fixed port silently
// satisfies that dial and the test then scrapes whatever the stale forward
// points at. That happened during development and produced a confident,
// completely wrong failure.
func fullProfileScrape(port int) string {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + strconv.Itoa(port) + "/metrics")
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return string(b)
}

// freePort reserves an ephemeral port from the kernel and releases it. A
// fixed base port is what let a stale forward hijack this test.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot reserve a local port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

// forwardCollectors port-forwards every collector pod and returns the local
// port for each, in the same order as pods.
func forwardCollectors(t *testing.T, pods []string) []int {
	t.Helper()
	ports := make([]int, len(pods))
	for i, name := range pods {
		ports[i] = freePort(t)
		portForward(t, "pod/"+name, strconv.Itoa(ports[i]), "9090")
	}
	return ports
}

// grepLines returns only the lines of body containing substr, so a failure
// message carries the relevant metrics rather than the whole snapshot.
func grepLines(body, substr string) string {
	var keep []string
	for _, line := range strings.Split(body, "\n") {
		if strings.Contains(line, substr) {
			keep = append(keep, "  "+line)
		}
	}
	if len(keep) == 0 {
		return "  (no olaitan_source_healthy lines in the snapshot)"
	}
	return strings.Join(keep, "\n")
}

// TestFullProfileEachSourceIngestsARealAction is Story 10.5 AC2: "each source
// ingests at least one event caused by a real action (exec, API call,
// container start, network flow, log line)".
//
// This asserts on event CONTENT, not on counters, and the distinction is the
// whole point. Two earlier versions of this test compared per-source counter
// deltas before and after the actions. Both passed while the actions were
// silently not happening: one dialled a Service that does not exist in this
// chart, another ran an exec that could not fire the Falco rule it named. The
// counters moved anyway, because audit, network and falco all climb
// continuously from kubelet chatter, Goldmane's ambient flow export and
// Falco's own metrics snapshots. A delta over a four-minute window proves
// only that the cluster was alive.
//
// Epic 10 exists because evidence of exactly that shape was found not to mean
// what it appeared to mean, so the only acceptable standard here is an event
// that names something this test created. Every action is tagged with a
// per-run marker and each source must yield a raw event carrying it.
func TestFullProfileEachSourceIngestsARealAction(t *testing.T) {
	if os.Getenv("OLT_E2E_FULL") == "" {
		t.Skip("full-profile smoke skipped; set OLT_E2E_FULL=1 (make e2e-full) to run")
	}
	requireKindCluster(t)
	requireFullProfile(t)
	requirePodsExist(t, "app.kubernetes.io/component=collector")

	runID := fmt.Sprintf("%d", time.Now().UnixNano()%1e9)
	podName := "ac2-probe-" + runID
	peerName := "ac2-peer-" + runID
	logMarker := "ac2-log-" + runID

	// Subscribe BEFORE acting. The raw subjects are Ring 1 -> Ring 2, i.e.
	// what each sensor actually published, which is the earliest point where
	// "this source ingested this event" is answerable.
	portForward(t, "svc/"+defaultReleaseName+"-nats", natsLocalPort, "4222")
	nc, err := nats.Connect("nats://localhost:" + natsLocalPort)
	if err != nil {
		t.Fatalf("nats connect: %v", err)
	}
	t.Cleanup(nc.Close)

	var mu sync.Mutex
	hits := map[string]string{} // source -> the raw event that carried the marker
	sub, err := nc.Subscribe(subjects.RawPrefix+">", func(m *nats.Msg) {
		body := string(m.Data)
		source := strings.TrimPrefix(m.Subject, subjects.RawPrefix)
		if !ac2Match(source, body, podName, logMarker) {
			return
		}
		mu.Lock()
		if _, seen := hits[source]; !seen {
			hits[source] = body
		}
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("nats subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })

	// --- the deliberate actions, each carrying the marker -------------------

	t.Cleanup(func() {
		_ = exec.Command("kubectl", "delete", "pod", podName, peerName,
			"-n", defaultNamespace, "--ignore-not-found",
			"--grace-period=0", "--force").Run()
	})

	// runtime (container start) + applog (log line), plus a peer to flow to.
	kubectlApply(t, fmt.Sprintf(ac2PeerPodTemplate, peerName))
	kubectlApply(t, fmt.Sprintf(ac2ProbePodTemplate, podName, logMarker))
	for _, pod := range []string{peerName, podName} {
		mustAction(t, "pod ready: "+pod,
			"kubectl", "wait", "--for=condition=Ready", "pod/"+pod,
			"-n", defaultNamespace, "--timeout=180s")
	}

	// falco: read /etc/shadow, which fires the stock "Read sensitive file
	// untrusted" rule. An earlier version used "Terminal shell in container"
	// via `kubectl exec -t`, but that rule conditions on proc.tty != 0 and
	// kubectl never allocates a tty here: without -i it forces TTY off, and
	// with -i it still refuses because a test's stdin is not a terminal
	// (kubectl pkg/cmd/exec SetupTTY). The rule could not fire, and the
	// Falco event that satisfied the old matcher came from some other rule
	// naming the same pod. ac2Match now requires this rule by name.
	mustAction(t, "falco: "+ac2FalcoRule,
		"kubectl", "exec", "-n", defaultNamespace, podName,
		"-c", "app", "--", "cat", "/etc/shadow")

	// audit: a single-object get, which the shipped policy records at
	// RequestResponse (a list is only Metadata), naming this pod.
	mustAction(t, "audit: get the probe pod",
		"kubectl", "get", "pod", podName, "-n", defaultNamespace, "-o", "name")

	// network: a real pod-to-pod flow, probe -> peer, on a path nothing else
	// in the cluster takes. Two earlier targets were wrong in instructive
	// ways: olaitan-aggregator has no Service in this chart (NXDOMAIN, no flow
	// at all), and the audit webhook is correctly firewalled by this very
	// profile's NetworkPolicy to kube-system and the apiserver, so an ordinary
	// pod times out reaching it. Neither probe pod carries the release labels,
	// so the release policy does not select them and the flow is unimpeded.
	peerIP := strings.TrimSpace(kubectl(t, "get", "pod", peerName,
		"-n", defaultNamespace, "-o", "jsonpath={.status.podIP}"))
	if peerIP == "" {
		t.Fatal("peer pod has no IP; cannot generate a pod-to-pod flow")
	}
	mustAction(t, "network: pod-to-pod request to "+peerIP,
		"kubectl", "exec", "-n", defaultNamespace, podName,
		"-c", "app", "--", "wget", "-q", "-T", "10", "-O", "/dev/null",
		"http://"+peerIP+":8080/")

	// --- wait for each source to publish an event naming the marker ---------
	// Falco's and Goldmane's export intervals are about a minute, so allow
	// several before concluding a source did not ingest the action.
	deadline := time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) {
		mu.Lock()
		done := ac2Complete(hits)
		mu.Unlock()
		if done {
			break
		}
		time.Sleep(5 * time.Second)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, src := range fullProfileSources {
		body, ok := hits[src.source]
		if !ok {
			t.Errorf("source %q published no raw event naming %q: the deliberate action for this source was not ingested",
				src.source, podName)
			continue
		}
		t.Logf("source %-8s ingested an event naming the probe (%d bytes)", src.source, len(body))
	}
}

// ac2FalcoRule is the stock Falco rule the AC2 Falco action fires. Reading
// /etc/shadow matches it without a tty, which kubectl cannot give a test.
const ac2FalcoRule = "Read sensitive file untrusted"

// ac2Match reports whether a raw event on source was caused by this run's
// deliberate action. Every source must name the probe pod (or, for applog,
// carry the log marker). Falco must additionally name ac2FalcoRule: the probe
// runs a shell loop and gets a sidecar injected, so other rules can name the
// same pod, and only the rule the action fires attributes the event to it.
func ac2Match(source, body, podName, logMarker string) bool {
	if !strings.Contains(body, podName) && !strings.Contains(body, logMarker) {
		return false
	}
	if source == "falco" {
		return strings.Contains(body, podName) && strings.Contains(body, ac2FalcoRule)
	}
	return true
}

// ac2Complete reports whether every source in the five-source contract has a
// hit. It counts only those sources: the raw wildcard can deliver subjects
// outside the contract, and len(hits) would let the wait end early.
func ac2Complete(hits map[string]string) bool {
	for _, s := range fullProfileSources {
		if _, ok := hits[s.source]; !ok {
			return false
		}
	}
	return true
}

// ac2PeerPodTemplate is the flow destination: a trivial HTTP listener. It
// carries no release labels, so the release NetworkPolicy does not select it.
const ac2PeerPodTemplate = `
apiVersion: v1
kind: Pod
metadata:
  name: %s
spec:
  containers:
    - name: peer
      image: busybox:1.36
      command: ["/bin/sh","-c"]
      args:
        - |
          mkdir -p /www && echo ok > /www/index.html
          httpd -f -p 8080 -h /www
      ports:
        - containerPort: 8080
`

// ac2ProbePodTemplate takes the pod name and the log marker. It writes to
// /var/log/app/stdout.log specifically: the sidecar tails that path and
// stderr.log, not *.log.
const ac2ProbePodTemplate = `
apiVersion: v1
kind: Pod
metadata:
  name: %s
  annotations:
    olaitan.io/log-sidecar: "enabled"
spec:
  containers:
    - name: app
      image: busybox:1.36
      command: ["/bin/sh","-c"]
      args:
        - |
          mkdir -p /var/log/app
          i=0
          while true; do
            i=$((i+1))
            echo "{\"level\":\"warn\",\"msg\":\"%s line $i\"}" >> /var/log/app/stdout.log
            sleep 2
          done
`

// requireFullProfile fails unless this cluster runs values-full.yaml. Only
// that profile gives the collector an audit-webhook hostPort, so it is a
// reliable marker. requireKindCluster alone is not enough: it only checks a
// cluster of the expected NAME exists, never that kubectl points at it.
func requireFullProfile(t *testing.T) {
	t.Helper()
	out, err := exec.Command("kubectl", "get", "daemonset",
		defaultReleaseName+"-collector", "-n", defaultNamespace,
		"-o", `jsonpath={.spec.template.spec.containers[*].ports[?(@.name=="audit-webhook")].hostPort}`,
	).Output()
	hostPort, convErr := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || convErr != nil || hostPort <= 0 {
		t.Fatalf("this cluster is not running the full profile: the collector DaemonSet has no audit-webhook hostPort (got %q).\n"+
			"Only values-full.yaml sets it. Bring the cluster up with `make e2e-full`.",
			strings.TrimSpace(string(out)))
	}
}

// mustAction runs a deliberate action and fails the test if it did not happen.
// Swallowing the error here would surface four minutes later as "source X
// ingested no event", pointing the reader at the sensor instead of the probe.
func mustAction(t *testing.T, what string, name string, args ...string) {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: the deliberate action itself failed, so the assertion below would be meaningless: %v\n%s",
			what, err, out)
	}
	t.Logf("action ok: %s", what)
}

// kubectlApply pipes a manifest to `kubectl apply -f -`.
func kubectlApply(t *testing.T, manifest string) {
	t.Helper()
	cmd := exec.Command("kubectl", "apply", "-n", defaultNamespace, "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("kubectl apply failed: %v\n%s", err, out)
	}
}
