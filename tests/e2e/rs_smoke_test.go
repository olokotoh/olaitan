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
	"github.com/nats-io/nats.go/jetstream"
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

// applySyntheticWorkload creates a `tenant-acme/web` Deployment so the
// aggregator's correlator can resolve a real pod via the apiserver and
// walk its OwnerReferences to a Deployment OwnerKind. Without a real
// pod, the resolver falls back to a pod-name-keyed identity with
// OwnerKind="Pod" and the OLT-PRIV-001 rule (which requires
// owner_kind in [Deployment, StatefulSet]) cannot match.
//
// Returns the actual pod name so the test publishes synthetic events
// against the workload the cluster knows about. The cleanup deletes
// the namespace (cascading-deletes Deployment + ReplicaSet + Pod).
//
// The pod image is `registry.k8s.io/pause:3.10`, which kind nodes
// already cache as the per-pod sandbox image, so the pod reaches Ready
// without an upstream pull.
func applySyntheticWorkload(t *testing.T) string {
	t.Helper()
	manifest := `
apiVersion: v1
kind: Namespace
metadata:
  name: tenant-acme
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: tenant-acme
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: web
          image: registry.k8s.io/pause:3.10
`
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("kubectl apply synthetic workload failed: %v\nstderr:\n%s", err, stderr.String())
	}
	t.Cleanup(func() {
		// Best-effort cleanup; do not fail the test on teardown errors
		// (CI tears the kind cluster down on job end anyway).
		_ = exec.Command("kubectl", "delete", "namespace", "tenant-acme",
			"--wait=false", "--ignore-not-found").Run()
	})
	kubectl(t, "wait", "--for=condition=Ready",
		"-n", "tenant-acme",
		"--selector=app=web",
		"--timeout=60s", "pods")
	out := kubectl(t, "get", "pods",
		"-n", "tenant-acme",
		"-l", "app=web",
		"-o", "jsonpath={.items[0].metadata.name}")
	podName := strings.TrimSpace(out)
	if podName == "" {
		t.Fatalf("synthetic workload: pod name not resolvable")
	}
	return podName
}

// publishSyntheticEvidencePackages pre-seeds the per-workload baseline
// store by publishing synthetic EvidencePackages directly to the
// `olaitan.evidence.packages` subject. This bypasses the correlator's
// rising-edge constraint -- the correlator only emits ONE package per
// workload per 60s window (window/window.go:171-184), which would
// otherwise leave the baseline with Count<3 and `preStd=0` for the
// entire test budget, so AC5's deviation half cannot fire purely
// through the streaming path.
//
// Eleven packages: ten alternating distinct=1/distinct=2 priming
// observations (Welford accumulates Count=10, Mean=1.5, Std≈0.527),
// then one spike at distinct=50. The spike's sigma vs the primed
// baseline is ~92, well above the 3-sigma deviation gate.
//
// Packages carry Trigger.Type="multi_signal" so neither the rules-
// engine nor the baseline-engine re-entrancy guards filter them. The
// (Namespace, PodName) key on each package matches the real pod so
// the baseline store keys line up with the workload the correlator
// will later resolve on the rule-match path.
//
// Network events use the singular `network.dst_ip` field that
// `extractOutboundUniqueDstIPs` (baseline/metrics.go:69) looks for.
// Posture identity is set so `extractOutboundUniqueDstIPs` does not
// blank out on the package-level k8s.* path and so the package keys
// resolve cleanly via `resolveWorkloadKey`.
// publishJS publishes via JetStream so the test fails loudly if the
// subject is not bound to any stream (core NATS publish silently
// drops in that case, which is exactly the failure mode that hid the
// "no stream subscribed to this subject" defect under the prior
// nc.Publish-only path).
func publishJS(t *testing.T, js jetstream.JetStream, subject string, payload []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := js.Publish(ctx, subject, payload); err != nil {
		t.Fatalf("jetstream publish %s: %v", subject, err)
	}
}

func publishSyntheticEvidencePackages(t *testing.T, js jetstream.JetStream, podName string) {
	t.Helper()
	now := time.Now().UTC()
	posture := map[string]any{
		"identity": map[string]any{
			"namespace":  "tenant-acme",
			"owner_kind": "Deployment",
			"owner_name": "web",
			"pod_name":   podName,
		},
	}
	identity := map[string]any{
		"namespace":  "tenant-acme",
		"owner_kind": "Deployment",
		"owner_name": "web",
		"pod_name":   podName,
	}
	makePkg := func(id string, distinctIPs int) []byte {
		events := make([]map[string]any, 0, distinctIPs)
		for j := 0; j < distinctIPs; j++ {
			raw := map[string]any{
				"network.dst_ip": fmt.Sprintf("10.0.0.%d", j+1),
			}
			rawJSON, _ := json.Marshal(raw)
			events = append(events, map[string]any{
				"id":        fmt.Sprintf("%s-ev-%d", id, j),
				"timestamp": now.Format(time.RFC3339Nano),
				"source":    "network",
				"category":  "flow",
				"raw":       json.RawMessage(rawJSON),
				"pod": map[string]any{
					"name":      podName,
					"namespace": "tenant-acme",
				},
			})
		}
		pkg := map[string]any{
			"schema_version":    "1.0",
			"package_id":        id,
			"workload_id":       "tenant-acme/Deployment/web",
			"workload_identity": identity,
			"assembled_at":      now.Format(time.RFC3339Nano),
			"window_start":      now.Add(-30 * time.Second).Format(time.RFC3339Nano),
			"window_end":        now.Format(time.RFC3339Nano),
			"trigger": map[string]any{
				"type":     "multi_signal",
				"fired_at": now.Format(time.RFC3339Nano),
			},
			"events":           events,
			"workload_posture": posture,
		}
		b, err := json.Marshal(pkg)
		if err != nil {
			t.Fatalf("marshal preseed package %s: %v", id, err)
		}
		return b
	}
	// 10 priming packages: alternate distinct=1 / distinct=2 so std > 0.
	pattern := []int{1, 2, 1, 2, 1, 2, 1, 2, 1, 2}
	for i, distinct := range pattern {
		publishJS(t, js, "olaitan.evidence.packages", makePkg(fmt.Sprintf("preseed-pkg-%d", i), distinct))
	}
	// 1 spike package: distinct=50 lands in the >=10 sigma bucket
	// (Story 1.18 P1 boundary).
	publishJS(t, js, "olaitan.evidence.packages", makePkg("preseed-pkg-spike", 50))
}

// publishCorrelatorTrigger publishes one network and one falco raw
// event so the correlator's multi-source rising-edge fires a package
// the rules engine matches OLT-PRIV-001 against (counter bump) and
// the correlator's own `olaitan_correlator_evidence_packages_total`
// counter increments. The baseline-deviation assertion is satisfied
// by `publishSyntheticEvidencePackages` above; this function is the
// rules-engine + correlator-counter half of AC5.
func publishCorrelatorTrigger(t *testing.T, js jetstream.JetStream, podName string) {
	t.Helper()
	pod := map[string]any{
		"name":      podName,
		"namespace": "tenant-acme",
		"uid":       "smoke-uid-1",
	}
	// Network priming event: makes the correlator window go from 0 to
	// 1 source. No rising edge yet (MultiSignalMinSources=2).
	netRaw := map[string]any{
		"network.dst_ip": "10.0.0.1",
	}
	netRawJSON, _ := json.Marshal(netRaw)
	netEvent := map[string]any{
		"id":        "smoke-correlator-net-1",
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"source":    "network",
		"category":  "flow",
		"summary":   "Story 1.19 e2e smoke: synthetic outbound flow priming",
		"raw":       json.RawMessage(netRawJSON),
		"pod":       pod,
	}
	netPayload, _ := json.Marshal(netEvent)
	publishJS(t, js, "olaitan.events.raw.network", netPayload)
	// Falco event with CAP_SYS_ADMIN: second source, rising edge fires,
	// correlator emits an EvidencePackage onto EVIDENCE.packages; rules
	// engine matches OLT-PRIV-001 against this event.
	falcoRaw := map[string]any{
		"process.exe":           "/host/bin/sh",
		"process.cap_effective": "CAP_NET_BIND_SERVICE CAP_SYS_ADMIN CAP_SETUID",
	}
	falcoRawJSON, _ := json.Marshal(falcoRaw)
	falcoEvent := map[string]any{
		"id":        "smoke-rule-match-1",
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"source":    "falco",
		"category":  "syscall",
		"severity":  "CRITICAL",
		"summary":   "Story 1.19 e2e smoke: synthetic CAP_SYS_ADMIN acquisition",
		"raw":       json.RawMessage(falcoRawJSON),
		"pod":       pod,
	}
	falcoPayload, _ := json.Marshal(falcoEvent)
	publishJS(t, js, "olaitan.events.raw.falco", falcoPayload)
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
	// expfmt.TextParser carries its own scheme field; the zero value is
	// UnsetValidation and panics on the first metric-name check. Use
	// NewTextParser to pin the scheme explicitly. (The package-level
	// model.NameValidationScheme set in init is only used by callers
	// that read the package var; TextParser does not.)
	parser := expfmt.NewTextParser(model.LegacyValidation)
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
	// Create a real Deployment-owned pod so the aggregator's
	// correlator/posture resolver returns OwnerKind=Deployment. Without
	// a real pod the resolver falls back to a pod-name identity with
	// OwnerKind=Pod, OLT-PRIV-001's owner_kind in [Deployment,
	// StatefulSet] filter rejects the package, and AC5 fails.
	podName := applySyntheticWorkload(t)
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
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatalf("JetStream context: %v", err)
	}
	// Pre-seed the per-workload baseline by publishing 11 synthetic
	// EvidencePackages directly onto EVIDENCE.packages. The correlator
	// only emits one package per rising-edge transition per workload
	// in the 60s window, which is insufficient observation history
	// for the baseline engine (preCount<2, preStd=0) to ever fire a
	// deviation in the 30s assertion budget. See the docstring on
	// publishSyntheticEvidencePackages for the design rationale.
	publishSyntheticEvidencePackages(t, js, podName)
	// Give the baseline-engine durable consumer time to drain the 11
	// pre-seed packages before the correlator-emitted Package_A
	// lands behind them on the EVIDENCE stream. The default
	// FetchMaxWait is 250ms and the engine is single-threaded
	// (MaxAckPending=1), so 3s comfortably accommodates 11 messages
	// plus a fetch-loop turnaround. JetStream stream-order guarantees
	// the pre-seed messages land in the stream before Package_A
	// regardless, but this sleep keeps the diagnosis loud if the
	// consumer is wedged.
	time.Sleep(3 * time.Second)
	publishCorrelatorTrigger(t, js, podName)
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
