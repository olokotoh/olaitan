//go:build e2e

package e2e_test

import (
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"
)

// collectorMetricsLocalPort must not collide with metricsLocalPort (the
// aggregator's), which other tests in this package forward at the same time.
const collectorMetricsLocalPort = "9092"

var (
	falcoHealthy = regexp.MustCompile(`(?m)^olaitan_source_healthy\{[^}]*source="falco"[^}]*\} 1$`)
	falco401     = regexp.MustCompile(`(?m)^olaitan_sensor_falco_http_requests_total\{[^}]*code="401"[^}]*\} ([0-9.e+]+)$`)
)

// TestFalcoSourceIsLive is Story 10.4's proof that Falco is ON in every e2e
// install. It runs in every e2e job. The collector marks Falco healthy only
// when Falco's own metrics snapshot (or an alert) arrives over http_output,
// so a green result means Falco loaded its driver inside kind, found the
// node-local ingest Service, and presented the right token. Until Story
// 10.4 every e2e target installed with Falco switched off and this path
// never ran.
func TestFalcoSourceIsLive(t *testing.T) {
	requirePodsExist(t, "app.kubernetes.io/component=collector")
	requirePodsExist(t, "app.kubernetes.io/name=falco")
	kubectl(t, "rollout", "status", "-n", defaultNamespace,
		"ds/"+defaultReleaseName+"-falco", "--timeout=5m")
	portForward(t, "ds/"+defaultReleaseName+"-collector", collectorMetricsLocalPort, "9090")

	// Falco's metrics interval is 1m, so the first heartbeat lands about a
	// minute after it loads its driver. Allow three intervals.
	deadline := time.Now().Add(4 * time.Minute)
	var body string
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://127.0.0.1:" + collectorMetricsLocalPort + "/metrics")
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			body = string(b)
			if m := falco401.FindStringSubmatch(body); m != nil && m[1] != "0" {
				t.Fatalf("the collector rejected Falco's token (401 x %s): Falco and the collector disagree on falco-http-token", m[1])
			}
			if falcoHealthy.MatchString(body) {
				return
			}
		}
		time.Sleep(5 * time.Second)
	}
	var lines []string
	for _, l := range strings.Split(body, "\n") {
		if strings.Contains(l, "falco") && !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	t.Fatalf("Falco never reported healthy to the collector within 4 minutes; falco metrics:\n%s",
		strings.Join(lines, "\n"))
}
