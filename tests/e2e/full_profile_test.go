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
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
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
	if out := kubectl(t, "get", "daemonset", defaultReleaseName+"-collector",
		"-n", defaultNamespace,
		"-o", `jsonpath={range .spec.template.spec.containers[*].ports[*]}{.name}={.hostPort} {end}`,
	); !strings.Contains(out, "audit-webhook=") {
		t.Fatalf("this cluster is not running the full profile: the collector has no audit-webhook hostPort (got %q).\n"+
			"Bring it up with hack/install-full-kind.sh, or run `make e2e-full`.", strings.TrimSpace(out))
	}

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
// The distinction this test exists to enforce: a non-zero counter is NOT
// evidence of AC2. On a freshly installed cluster every one of these counters
// climbs on its own, from kubelet and controller-manager API chatter, Goldmane's
// ambient flow export, Falco's background rules and the container churn of the
// install itself. Epic 10 was opened because evidence of exactly that shape
// turned out not to mean what it appeared to mean, so this test performs one
// deliberate action per source and asserts THAT source's counter moved.
//
// Counters are summed across every collector pod, because each source is
// node-local: the action may land on any node.
func TestFullProfileEachSourceIngestsARealAction(t *testing.T) {
	if os.Getenv("OLT_E2E_FULL") == "" {
		t.Skip("full-profile smoke skipped; set OLT_E2E_FULL=1 (make e2e-full) to run")
	}
	requireKindCluster(t)
	requirePodsExist(t, "app.kubernetes.io/component=collector")

	names := collectorPodNames(t)
	ports := forwardCollectors(t, names)

	// Fail loudly if a collector cannot be scraped at all. Silently summing
	// over a subset is how the first two attempts at this test produced
	// confident, wrong answers about sources that live on the other node.
	for i, name := range names {
		if fullProfileScrape(ports[i]) == "" {
			t.Fatalf("collector %s returned no metrics; the per-source sums would be taken over a subset of nodes and mean nothing", name)
		}
	}

	before := sumEventsBySource(t, ports)

	// --- the deliberate actions, one per source -----------------------------

	// runtime (containerd lifecycle) + applog (log line): one pod does both.
	// The sidecar tails /var/log/app/stdout.log specifically, not *.log.
	t.Cleanup(func() {
		_ = exec.Command("kubectl", "delete", "pod", "ac2-probe",
			"-n", defaultNamespace, "--ignore-not-found", "--wait=false").Run()
	})
	kubectlApply(t, ac2ProbePodManifest)
	kubectl(t, "wait", "--for=condition=Ready", "pod/ac2-probe",
		"-n", defaultNamespace, "--timeout=180s")

	// falco: a terminal shell in a container is one of Falco's stock rules,
	// so this is an alert the default ruleset is guaranteed to raise.
	_ = exec.Command("kubectl", "exec", "-n", defaultNamespace, "ac2-probe",
		"-c", "app", "--", "/bin/sh", "-c", "id").Run()

	// audit: a deliberate, attributable API call. A Secret read is audited at
	// RequestResponse by the shipped policy, so it cannot be confused with a
	// kubelet watch.
	_ = exec.Command("kubectl", "get", "secrets", "-n", defaultNamespace).Run()

	// network (Calico flow): pod-to-pod traffic the cluster would not otherwise
	// generate. Reaching the collector's own metrics port is enough to produce
	// a flow record.
	_ = exec.Command("kubectl", "exec", "-n", defaultNamespace, "ac2-probe",
		"-c", "app", "--", "wget", "-q", "-T", "5", "-O", "/dev/null",
		"http://"+defaultReleaseName+"-aggregator."+defaultNamespace+".svc:9090/metrics").Run()

	// --- assert each source moved -------------------------------------------
	// Falco's metrics interval is 1m and Goldmane's flow window is comparable,
	// so allow three intervals for the slow sources rather than reading once.
	deadline := time.Now().Add(4 * time.Minute)
	var after map[string]float64
	pending := map[string]bool{}
	for _, s := range fullProfileSources {
		pending[s.source] = true
	}
	for time.Now().Before(deadline) && len(pending) > 0 {
		after = sumEventsBySource(t, ports)
		for source := range pending {
			if after[source] > before[source] {
				delete(pending, source)
			}
		}
		if len(pending) == 0 {
			break
		}
		time.Sleep(10 * time.Second)
	}

	for _, s := range fullProfileSources {
		delta := after[s.source] - before[s.source]
		if delta <= 0 {
			t.Errorf("source %q ingested no event after a deliberate action: %.0f -> %.0f (delta %.0f)",
				s.source, before[s.source], after[s.source], delta)
			continue
		}
		t.Logf("source %-8s %.0f -> %.0f (+%.0f)", s.source, before[s.source], after[s.source], delta)
	}
}

const ac2ProbePodManifest = `
apiVersion: v1
kind: Pod
metadata:
  name: ac2-probe
  namespace: default
  annotations:
    olaitan.io/log-sidecar: "enabled"
spec:
  containers:
    - name: app
      image: busybox:1.36
      command: ["/bin/sh","-c"]
      args:
        - |
          i=0
          while true; do
            i=$((i+1))
            echo "{\"level\":\"warn\",\"msg\":\"ac2 deliberate log line $i\"}" >> /var/log/app/stdout.log
            sleep 2
          done
`

// collectorPodNames returns every collector pod, in a stable order.
func collectorPodNames(t *testing.T) []string {
	t.Helper()
	names := strings.Fields(strings.TrimSpace(kubectl(t,
		"get", "pods", "-n", defaultNamespace,
		"-l", "app.kubernetes.io/component=collector",
		"-o", "jsonpath={range .items[*]}{.metadata.name} {end}")))
	if len(names) == 0 {
		t.Fatal("no collector pods found")
	}
	sort.Strings(names)
	return names
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

var eventsTotalRE = regexp.MustCompile(
	`(?m)^olaitan_sensor_events_total\{[^}]*source="([a-z]+)"[^}]*\} ([0-9.e+]+)$`)

// sumEventsBySource totals olaitan_sensor_events_total across every collector,
// because each source is node-local and a deliberate action lands on one node.
func sumEventsBySource(t *testing.T, ports []int) map[string]float64 {
	t.Helper()
	totals := map[string]float64{}
	for _, port := range ports {
		for _, m := range eventsTotalRE.FindAllStringSubmatch(
			fullProfileScrape(port), -1) {
			v, err := strconv.ParseFloat(m[2], 64)
			if err != nil {
				continue
			}
			totals[m[1]] += v
		}
	}
	return totals
}
