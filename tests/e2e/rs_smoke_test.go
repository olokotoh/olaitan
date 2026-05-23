//go:build e2e

// Package e2e_test holds the Story 1.19 kind-based smoke test that
// validates the chart installs healthy under the RS evaluation arm and
// that a synthetic S1 container-escape event produces the load-bearing
// AC5 metrics on the aggregator's Prometheus surface.
//
// The test is gated by the `e2e` build tag because it shells out to
// `kubectl` for port-forward and assumes a running kind cluster with
// the Olaitan chart already installed. It is driven by `make e2e-local`
// (developer workflow) and the `e2e` CI job in
// `.github/workflows/ci.yml` (which boots a fresh kind cluster on each
// run).
//
// # Why Falco is disabled in the smoke test
//
// Falco's eBPF probe loads against the host kernel. Inside a kind
// cluster the "host" is the kind container, which does not have the
// eBPF subsystem mounted. Falco would log `failed to load probe` and
// crash-loop. The chart install therefore sets `falco.enabled=false`
// and this test publishes JSON-marshalled raw events directly to
// `olaitan.events.raw.falco` -- the NATS subject Falco would publish
// to in production. The pipeline's correlator, rule engine, and
// baseline engine then process the events identically to a
// Falco-driven path.
//
// # What the test does not validate
//
// The Falco gRPC adapter's translation logic is not exercised by this
// test; the Story 1.6 unit + integration tests cover that. A future
// kubeadm-cluster nightly job (out of scope for Story 1.19) would
// close the remaining end-to-end gap by exercising Falco on a real
// host kernel.
package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

// init wires the prometheus/common metric-name validator. v0.67.x
// leaves model.NameValidationScheme defaulted to Unset and panics
// inside TextParser.TextToMetricFamilies when the first metric name
// is checked. Set Legacy validation (matches the historical
// metric-name regexp the Olaitan codebase relies on; the metrics
// surface does not use UTF-8-extended names).
func init() {
	model.NameValidationScheme = model.LegacyValidation
}

const (
	defaultKindCluster   = "olaitan-e2e"
	defaultNamespace     = "default"
	defaultReleaseName   = "olaitan"
	natsLocalPort        = "4222"
	metricsLocalPort     = "9090"
	assertionTimeout     = 30 * time.Second
	assertionPollInteval = 500 * time.Millisecond
)

// kindClusterName returns the configured cluster name. Defaults to the
// `olaitan-e2e` cluster created by `make e2e-local`; CI / developer
// machines override via the `KIND_CLUSTER_NAME` environment variable
// when running against an existing cluster.
func kindClusterName() string {
	if v := os.Getenv("KIND_CLUSTER_NAME"); v != "" {
		return v
	}
	return defaultKindCluster
}

// requireKindCluster skips the test if `kind get clusters` does not
// report the expected cluster name. A graceful skip is preferable to a
// hard failure when a developer runs `go test -tags=e2e ./...` without
// the kind harness up.
func requireKindCluster(t *testing.T) {
	t.Helper()
	out, err := exec.Command("kind", "get", "clusters").Output()
	if err != nil {
		t.Skipf("kind binary not available or `kind get clusters` failed: %v", err)
	}
	name := kindClusterName()
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == name {
			return
		}
	}
	t.Skipf("kind cluster %q not found; run `make e2e-local` first", name)
}

// kubectl runs kubectl with the given args and returns stdout on
// success or fails the test on any non-zero exit, including stderr in
// the failure message for diagnosability.
func kubectl(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("kubectl", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("kubectl %s failed: %v\nstderr:\n%s",
			strings.Join(args, " "), err, stderr.String())
	}
	return stdout.String()
}

// waitForPodsReady blocks until the aggregator pod reports Ready, up
// to 120 seconds. Scoped to the aggregator only: the smoke test
// injects synthetic events directly into NATS via port-forward so the
// collector DaemonSet is not on the critical path. Falco's eBPF probe
// cannot load inside kind nodes (kind nodes are containers; eBPF is
// host-scoped) and the collector pod is run with endpoints.falco set
// to a tcp:// target so the /run/falco hostPath mount is skipped --
// the collector starts but never connects to Falco. None of that
// blocks the aggregator-side pipeline the test exercises.
func waitForPodsReady(t *testing.T) {
	t.Helper()
	kubectl(t, "wait", "--for=condition=Ready",
		"-n", defaultNamespace,
		"--selector=app.kubernetes.io/component=aggregator",
		"--timeout=120s", "pods")
}

// portForward starts `kubectl port-forward` in the background and
// registers a cleanup to terminate it. Returns once the local port is
// reachable. Pollss every 100ms up to 10 seconds for the local
// listener to come up; the kubectl process may take a moment to wire
// the connection.
func portForward(t *testing.T, target, localPort, remotePort string) {
	t.Helper()
	cmd := exec.Command("kubectl", "port-forward",
		"-n", defaultNamespace, target,
		fmt.Sprintf("%s:%s", localPort, remotePort))
	if err := cmd.Start(); err != nil {
		t.Fatalf("port-forward %s start failed: %v", target, err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", "localhost:"+localPort, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("port-forward %s did not become reachable on localhost:%s within 10s", target, localPort)
}

// publishSyntheticRuleEvent injects an event that satisfies
// `rules/priv/OLT-PRIV-001.yaml` so the rule engine fires
// `olaitan_decision_rules_matches_by_attribute_total{rule_id="OLT-PRIV-001"}`.
// The event shape mirrors the existing fixture at
// `internal/decision/rules/testdata/scenarios/S1/package.json` adapted
// to the on-wire raw-event JSON the Falco adapter emits.
func publishSyntheticRuleEvent(t *testing.T, nc *nats.Conn) {
	t.Helper()
	// Match-fields for OLT-PRIV-001: process.cap_effective contains
	// CAP_SYS_ADMIN, workload owner_kind=Deployment, namespace=non-system.
	raw := map[string]any{
		"process.exe":             "/host/bin/sh",
		"process.cap_effective":   "CAP_NET_BIND_SERVICE CAP_SYS_ADMIN CAP_SETUID",
		"k8s.pod.namespace":       "tenant-acme",
		"k8s.workload.owner_kind": "Deployment",
		"k8s.workload.owner_name": "web",
	}
	rawJSON, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal raw event: %v", err)
	}
	event := map[string]any{
		"id":        "smoke-rule-match-1",
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"source":    "falco",
		"category":  "syscall",
		"severity":  "CRITICAL",
		"summary":   "Story 1.19 e2e smoke: synthetic CAP_SYS_ADMIN acquisition",
		"raw":       json.RawMessage(rawJSON),
		"pod": map[string]any{
			"name":      "web-7f9b8c4d5-smoke",
			"namespace": "tenant-acme",
			"uid":       "smoke-uid-1",
		},
	}
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	if err := nc.Publish("olaitan.events.raw.falco", payload); err != nil {
		t.Fatalf("publish rule-match event: %v", err)
	}
}

// publishSyntheticBaselineSpike injects 100 priming events to clear
// the warm-up window, then a single spike event that the baseline
// engine should classify as a deviation. The chart install uses
// `--set baselines.warmupDuration=5s` so the warm-up timer expires
// well before the test's assertion deadline.
func publishSyntheticBaselineSpike(t *testing.T, nc *nats.Conn) {
	t.Helper()
	pod := map[string]any{
		"name":      "web-7f9b8c4d5-baseline",
		"namespace": "tenant-acme",
		"uid":       "smoke-uid-2",
	}
	publish := func(id string, dstIPs []string) {
		raw := map[string]any{
			"event.category":          "flow",
			"network.dst_ips":         dstIPs,
			"k8s.pod.namespace":       "tenant-acme",
			"k8s.workload.owner_kind": "Deployment",
		}
		rawJSON, _ := json.Marshal(raw)
		ev := map[string]any{
			"id":        id,
			"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
			"source":    "network",
			"category":  "flow",
			"summary":   "Story 1.19 e2e smoke: synthetic outbound flow",
			"raw":       json.RawMessage(rawJSON),
			"pod":       pod,
		}
		b, _ := json.Marshal(ev)
		if err := nc.Publish("olaitan.events.raw.network", b); err != nil {
			t.Fatalf("publish baseline-priming event %s: %v", id, err)
		}
	}
	// 100 priming events with a low, stable distinct-IP count.
	for i := 0; i < 100; i++ {
		publish(fmt.Sprintf("smoke-baseline-prime-%d", i), []string{"10.0.0.1"})
	}
	// One spike event with a very high distinct-IP count to land in
	// the >=10 sigma bucket (Story 1.18 P1 boundary).
	spike := make([]string, 50)
	for i := range spike {
		spike[i] = fmt.Sprintf("10.0.0.%d", i+10)
	}
	publish("smoke-baseline-spike", spike)
}

// scrapeMetrics fetches the aggregator's Prometheus surface and
// returns the parsed metric families keyed by metric name.
func scrapeMetrics(t *testing.T) map[string]*metricFamily {
	t.Helper()
	resp, err := http.Get("http://localhost:" + metricsLocalPort + "/metrics")
	if err != nil {
		t.Fatalf("scrape metrics: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("scrape metrics: HTTP %d", resp.StatusCode)
	}
	parser := expfmt.TextParser{}
	parsed, err := parser.TextToMetricFamilies(resp.Body)
	if err != nil {
		t.Fatalf("parse metrics: %v", err)
	}
	out := make(map[string]*metricFamily, len(parsed))
	for name, family := range parsed {
		mf := &metricFamily{samples: make([]metricSample, 0, len(family.GetMetric()))}
		for _, m := range family.GetMetric() {
			s := metricSample{labels: make(map[string]string, len(m.GetLabel()))}
			for _, lp := range m.GetLabel() {
				s.labels[lp.GetName()] = lp.GetValue()
			}
			if c := m.GetCounter(); c != nil {
				s.value = c.GetValue()
			} else if g := m.GetGauge(); g != nil {
				s.value = g.GetValue()
			} else if h := m.GetHistogram(); h != nil {
				s.value = float64(h.GetSampleCount())
			}
			mf.samples = append(mf.samples, s)
		}
		out[name] = mf
	}
	return out
}

type metricFamily struct{ samples []metricSample }
type metricSample struct {
	labels map[string]string
	value  float64
}

// sumWhere returns the sum of sample values whose labels match every
// (key, value) pair in `match`. Returns 0 when the family is missing
// or no sample matches.
func (mf *metricFamily) sumWhere(match map[string]string) float64 {
	if mf == nil {
		return 0
	}
	var total float64
sample:
	for _, s := range mf.samples {
		for k, v := range match {
			if s.labels[k] != v {
				continue sample
			}
		}
		total += s.value
	}
	return total
}

// TestKindSmoke_RS_EmitsRuleMatchAndBaselineDeviation is the AC5
// pin: with the chart installed under `evaluation.config=RS`, a
// synthetic S1 container-escape event published to
// `olaitan.events.raw.falco` should produce at least one rule match
// and one baseline deviation visible on the aggregator's Prometheus
// surface within the NFR3 100 ms detection budget plus a comfortable
// 30-second poll ceiling (the test's wall-clock budget; the engine
// internals operate well below it).
func TestKindSmoke_RS_EmitsRuleMatchAndBaselineDeviation(t *testing.T) {
	requireKindCluster(t)
	waitForPodsReady(t)
	portForward(t, "svc/"+defaultReleaseName+"-nats", natsLocalPort, "4222")
	// The aggregator Deployment exposes containerPort 9090 but the
	// chart does not render a Service for the aggregator (Story 1.18
	// observability is scrape-annotation-based, no ServiceMonitor or
	// metrics Service is rendered). Port-forward to the Deployment
	// directly so the test does not depend on a Service that does
	// not exist.
	portForward(t, "deploy/"+defaultReleaseName+"-aggregator", metricsLocalPort, "9090")
	nc, err := nats.Connect("nats://localhost:" + natsLocalPort)
	if err != nil {
		t.Fatalf("NATS connect: %v", err)
	}
	t.Cleanup(nc.Close)
	publishSyntheticRuleEvent(t, nc)
	publishSyntheticBaselineSpike(t, nc)
	if err := nc.Flush(); err != nil {
		t.Fatalf("NATS flush: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), assertionTimeout)
	defer cancel()
	var lastErr error
	for {
		select {
		case <-ctx.Done():
			t.Fatalf("metric assertions did not pass within %s; last error: %v",
				assertionTimeout, lastErr)
		default:
		}
		metrics := scrapeMetrics(t)
		matches := metrics["olaitan_decision_rules_matches_by_attribute_total"].sumWhere(map[string]string{"rule_id": "OLT-PRIV-001"})
		deviations := metrics["olaitan_decision_baseline_deviations_total"].sumWhere(nil)
		evidence := metrics["olaitan_correlator_evidence_packages_total"].sumWhere(nil)
		switch {
		case matches < 1:
			lastErr = fmt.Errorf("rule matches for OLT-PRIV-001 = %v; want >= 1", matches)
		case deviations < 1:
			lastErr = fmt.Errorf("baseline deviations = %v; want >= 1", deviations)
		case evidence < 1:
			lastErr = fmt.Errorf("correlator evidence packages = %v; want >= 1", evidence)
		default:
			// Source-health check on the sources the chart actually
			// started. Falco is disabled per the chart-install --set;
			// the surviving sources should report healthy.
			sourceHealthy := metrics["olaitan_source_healthy"]
			if sourceHealthy != nil {
				for _, sample := range sourceHealthy.samples {
					if sample.value != 1 {
						lastErr = fmt.Errorf("source %q unhealthy (gauge=%v); all enabled sources must be healthy",
							sample.labels["source"], sample.value)
						break
					}
				}
				if lastErr == nil {
					return // success
				}
			} else {
				return // no source_healthy gauge exposed yet; not load-bearing
			}
		}
		time.Sleep(assertionPollInteval)
	}
}
