//go:build e2e

package e2e_test

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// One local port per collector pod, allocated upward from this base.
// Must not collide with metricsLocalPort (aggregator) or
// collectorMetricsLocalPort (Story 10.4), which other tests forward
// concurrently.
const fullProfileBasePort = 9093

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
	requireKindCluster(t)
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

	for i, name := range names {
		portForward(t, "pod/"+name, strconv.Itoa(fullProfileBasePort+i), "9090")
	}

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
		for i, name := range names {
			body := fullProfileScrape(fullProfileBasePort + i)
			if body == "" {
				continue
			}
			for source := range pending {
				if sourceHealthyRE(source).MatchString(body) {
					seen[source] = name
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

	var missing []string
	for source, helmKey := range pending {
		missing = append(missing, fmt.Sprintf("%s (%s)", source, helmKey))
	}
	var snapshot strings.Builder
	for i, name := range names {
		fmt.Fprintf(&snapshot, "  --- %s\n%s\n", name,
			grepLines(fullProfileScrape(fullProfileBasePort+i), "olaitan_source_healthy"))
	}
	t.Fatalf("kind-full: %d of %d sources never reported healthy on ANY collector within 5m: %s\n%s",
		len(pending), len(fullProfileSources), strings.Join(missing, ", "), snapshot.String())
}

// fullProfileScrape fetches one collector's /metrics, returning "" on any error
// so a pod that is briefly restarting does not fail the whole assertion.
func fullProfileScrape(port int) string {
	resp, err := http.Get("http://127.0.0.1:" + strconv.Itoa(port) + "/metrics")
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
