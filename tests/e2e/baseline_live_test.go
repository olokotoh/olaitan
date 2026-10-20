//go:build e2e

package e2e_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/olokotoh/olaitan/internal/subjects"
)

// Story 10.12 live gate (AC1, AC2, AC8). A real workload runs on the
// full profile (Falco ON, five sources) and behaves steadily for the
// configured warm-up plus 15 evaluated minutes; the baseline must stay silent.
// The workload is then switched (through its own ConfigMap, so no kubectl
// exec adds operator noise to the pod) to a real behavioural change: an
// API burst against its own pod, six dropped-and-executed binaries, and
// connections to six new destination ports. Each must surface on EVIDENCE
// as a baseline_deviation package with its metric and sigma.
//
// Nothing is published to NATS by this test: every event comes from a
// real sensor watching a real pod. It only reads EVIDENCE.
//
// Gated: OLT_E2E_FULL=1 and OLT_E2E_BASELINE_LIVE=1. The benign phase is
// the warm-up plus OLT_BASELINE_QUIET (default 15m) of evaluated minutes,
// so it runs for about 55 minutes: use -timeout 80m. OLT_BASELINE_WARMUP
// must match the installed baselines.warmupDuration (default 30m).
func TestBaselineLive_RealWorkload(t *testing.T) {
	if os.Getenv("OLT_E2E_FULL") == "" || os.Getenv("OLT_E2E_BASELINE_LIVE") == "" {
		t.Skip("baseline live gate skipped; set OLT_E2E_FULL=1 and OLT_E2E_BASELINE_LIVE=1 and run with -timeout 70m")
	}
	requireKindCluster(t)
	requireFullProfile(t)

	warmup := 30 * time.Minute
	if v := os.Getenv("OLT_BASELINE_WARMUP"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			t.Fatalf("OLT_BASELINE_WARMUP=%q: %v", v, err)
		}
		warmup = d
	}
	quiet := 15 * time.Minute
	if v := os.Getenv("OLT_BASELINE_QUIET"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			t.Fatalf("OLT_BASELINE_QUIET=%q: %v", v, err)
		}
		quiet = d
	}
	// Warm-up starts when the first minute closes, so add two minutes to
	// be sure `quiet` evaluated minutes follow it.
	benign := warmup + quiet + 2*time.Minute
	if benign < 35*time.Minute {
		benign = 35 * time.Minute
	}

	ns := fmt.Sprintf("olt-bl-%d", time.Now().UnixNano()%1e9)
	workloadID := ns + "/Deployment/steady"
	t.Cleanup(func() {
		// Olaitan's own response can restrict or isolate this workload
		// (its token read is a WARNING Falco alert, the dropped binaries a
		// CRITICAL one). Record what it did, so a missing deviation is not
		// misread as a baseline failure.
		if out, err := exec.Command("kubectl", "-n", ns, "get", "networkpolicy", "-o", "name").CombinedOutput(); err == nil {
			t.Logf("NetworkPolicies in %s at the end: %q", ns, strings.TrimSpace(string(out)))
		}
		_ = exec.Command("kubectl", "delete", "namespace", ns, "--ignore-not-found", "--wait=false").Run()
	})
	start := time.Now().Add(-2 * time.Second)
	mustRun(t, "create namespace "+ns, "kubectl", "create", "namespace", ns)
	applyIn(t, ns, baselineLiveManifest(ns))
	mustRun(t, "peer ready", "kubectl", "-n", ns, "rollout", "status", "deploy/peer", "--timeout=3m")
	mustRun(t, "steady ready", "kubectl", "-n", ns, "rollout", "status", "deploy/steady", "--timeout=3m")
	// Fail now, not after an hour, if the workload cannot reach the
	// apiserver: its first cycle must have every GET answered 200. This one
	// log read falls inside the warm-up, so it cannot move the baseline.
	if c, logs := waitSteadyCycle(t, ns, 3*time.Minute, func(c steadyCycle) bool { return true }); c == nil || c.OK != c.Gets || c.Gets == 0 || strings.Contains(logs, "apiserver_get_failed") {
		t.Fatalf("steady workload's API calls do not reach kube-apiserver (first cycle %+v); the audit_events_per_min check would be meaningless. Workload log:\n%s", c, logs)
	}
	t.Logf("steady workload %s up at %s; benign window %s (warm-up %s)", workloadID, time.Now().UTC().Format(time.RFC3339), benign, warmup)

	time.Sleep(benign)
	devs, read := readBaselineDeviations(t, start, workloadID)
	if read == 0 {
		// The workload's own token read raises a rule_match package at
		// start, so an empty read means the check itself is broken, not
		// that the baseline was quiet.
		t.Fatalf("AC1 check read no EVIDENCE package at all since %s; the check cannot prove silence", start.UTC().Format(time.RFC3339))
	}
	for _, d := range devs {
		t.Logf("deviation during the benign window: %s", d)
	}
	if len(devs) != 0 {
		t.Fatalf("AC1: the benign steady workload produced %d baseline deviation(s) over %s", len(devs), benign)
	}
	t.Logf("AC1 ok: zero baseline deviations for %s over %s", workloadID, benign)

	switchedAt := time.Now()
	mustRun(t, "switch the workload to deviate", "kubectl", "-n", ns, "patch", "configmap", "steady-mode",
		"--type=merge", "-p", `{"data":{"mode":"deviate"}}`)
	want := map[string]bool{"audit_events_per_min": false, "distinct_exec_paths": false, "outbound_unique_dst_ips": false}
	deadline := time.Now().Add(8 * time.Minute)
	for {
		time.Sleep(30 * time.Second)
		got, _ := readBaselineDeviations(t, switchedAt, workloadID)
		for _, d := range got {
			if d.Sigma < 3 || d.StdDev <= 0 {
				t.Fatalf("AC2: deviation below the 3-sigma gate or without a std_dev: %s", d)
			}
			if _, ok := want[d.Metric]; ok && !want[d.Metric] {
				want[d.Metric] = true
				t.Logf("AC2 deviation: %s", d)
			}
		}
		done := true
		for _, ok := range want {
			done = done && ok
		}
		if done || time.Now().After(deadline) {
			// Read the workload log only now, so the read adds no audit
			// event to the deviate minutes being judged.
			requireDeviateBurstLanded(t, ns)
		}
		if done {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("AC2: after the real behavioural change, deviations seen per metric: %v", want)
		}
	}
}

// steadyCycle is one `cycle=N mode=M gets=G ok=K` line of the steady
// workload's log.
type steadyCycle struct {
	Cycle int
	Mode  string
	Gets  int
	OK    int
}

// parseSteadyLog returns every cycle line of the steady workload's log, in
// order. Lines that are not cycle lines (apiserver_get_failed, curl noise)
// are skipped; callers look for those in the raw log.
func parseSteadyLog(logs string) []steadyCycle {
	var out []steadyCycle
	for _, line := range strings.Split(logs, "\n") {
		var c steadyCycle
		seen := 0
		for _, f := range strings.Fields(line) {
			k, v, ok := strings.Cut(f, "=")
			if !ok {
				continue
			}
			n, err := strconv.Atoi(v)
			switch {
			case k == "cycle" && err == nil:
				c.Cycle = n
				seen++
			case k == "mode":
				c.Mode = v
				seen++
			case k == "gets" && err == nil:
				c.Gets = n
				seen++
			case k == "ok" && err == nil:
				c.OK = n
				seen++
			}
		}
		if seen == 4 {
			out = append(out, c)
		}
	}
	return out
}

// steadyLogs returns the steady workload's whole log.
func steadyLogs(t *testing.T, ns string) string {
	t.Helper()
	out, err := exec.Command("kubectl", "-n", ns, "logs", "deploy/steady", "--tail=-1").CombinedOutput()
	if err != nil {
		t.Fatalf("kubectl logs deploy/steady: %v\n%s", err, out)
	}
	return string(out)
}

// waitSteadyCycle polls the workload log until a cycle line matches, and
// returns it with the log. A nil cycle means none matched in time.
func waitSteadyCycle(t *testing.T, ns string, timeout time.Duration, match func(steadyCycle) bool) (*steadyCycle, string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		logs := steadyLogs(t, ns)
		for _, c := range parseSteadyLog(logs) {
			if match(c) {
				return &c, logs
			}
		}
		if time.Now().After(deadline) {
			return nil, logs
		}
		time.Sleep(10 * time.Second)
	}
}

// requireDeviateBurstLanded fails the test unless a deviate cycle had all
// 80 of its GETs answered 200: without that, a missing (or present)
// audit_events_per_min deviation says nothing about the baseline engine.
func requireDeviateBurstLanded(t *testing.T, ns string) {
	t.Helper()
	c, logs := waitSteadyCycle(t, ns, 2*time.Minute, func(c steadyCycle) bool { return c.Mode == "deviate" })
	if c == nil {
		t.Fatalf("AC2: the steady workload logged no deviate cycle after the switch. Workload log:\n%s", logs)
	}
	for _, c := range parseSteadyLog(logs) {
		if c.Mode == "deviate" && c.Gets == 80 && c.OK == 80 {
			t.Logf("AC2: deviate burst landed: cycle %d, %d of %d GETs answered 200", c.Cycle, c.OK, c.Gets)
			return
		}
	}
	t.Fatalf("AC2: no deviate cycle had all 80 apiserver GETs answered 200; the API burst did not reach kube-apiserver. Workload log:\n%s", logs)
}

type liveDeviation struct {
	Metric string  `json:"metric"`
	Value  float64 `json:"value"`
	Mean   float64 `json:"mean"`
	StdDev float64 `json:"std_dev"`
	Sigma  float64 `json:"sigma"`
}

func (d liveDeviation) String() string {
	return fmt.Sprintf("metric=%s value=%.1f mean=%.2f std_dev=%.2f sigma=%.2f", d.Metric, d.Value, d.Mean, d.StdDev, d.Sigma)
}

// readBaselineDeviations returns every baseline_deviation package for
// workloadID published on EVIDENCE since `since`, and how many packages
// (any workload) it read, so a caller asserting silence can tell "quiet"
// from "read nothing". It opens its own short-lived port-forward each
// call: a single forward held for most of an hour is the likeliest thing
// to break in this test. A fetch error other than running out of
// messages, or an undecodable package, fails the test.
func readBaselineDeviations(t *testing.T, since time.Time, workloadID string) ([]liveDeviation, int) {
	t.Helper()
	port := strconv.Itoa(freePort(t))
	stop := startPortForward(t, "svc/"+defaultReleaseName+"-nats", port, "4222")
	defer stop()
	nc, err := nats.Connect("nats://localhost:" + port)
	if err != nil {
		t.Fatalf("nats connect: %v", err)
	}
	defer nc.Close()
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatalf("jetstream: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cons, err := js.OrderedConsumer(ctx, "EVIDENCE", jetstream.OrderedConsumerConfig{
		FilterSubjects: []string{subjects.EvidencePackages},
		DeliverPolicy:  jetstream.DeliverByStartTimePolicy,
		OptStartTime:   &since,
	})
	if err != nil {
		t.Fatalf("EVIDENCE consumer: %v", err)
	}
	var out []liveDeviation
	total := 0
	for {
		batch, err := cons.Fetch(100, jetstream.FetchMaxWait(3*time.Second))
		if err != nil {
			t.Fatalf("EVIDENCE fetch: %v", err)
		}
		n := 0
		for msg := range batch.Messages() {
			n++
			total++
			var pkg struct {
				WorkloadID string `json:"workload_id"`
				Trigger    struct {
					Type              string         `json:"type"`
					BaselineDeviation *liveDeviation `json:"baseline_deviation"`
				} `json:"trigger"`
			}
			if err := json.Unmarshal(msg.Data(), &pkg); err != nil {
				t.Fatalf("undecodable EVIDENCE package: %v", err)
			}
			if pkg.WorkloadID == workloadID && pkg.Trigger.Type == "baseline_deviation" && pkg.Trigger.BaselineDeviation != nil {
				out = append(out, *pkg.Trigger.BaselineDeviation)
			}
		}
		if err := batch.Error(); err != nil && !errors.Is(err, nats.ErrTimeout) && !errors.Is(err, jetstream.ErrNoMessages) && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("EVIDENCE fetch batch: %v", err)
		}
		if n == 0 {
			return out, total
		}
	}
}

// startPortForward is portForward without the test-scoped cleanup, so a
// caller can open and close forwards repeatedly on fresh ports.
func startPortForward(t *testing.T, target, localPort, remotePort string) func() {
	t.Helper()
	cmd := exec.Command("kubectl", "port-forward", "-n", defaultNamespace, target, localPort+":"+remotePort)
	if err := cmd.Start(); err != nil {
		t.Fatalf("port-forward %s: %v", target, err)
	}
	stop := func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", "localhost:"+localPort, 200*time.Millisecond); err == nil {
			_ = c.Close()
			return stop
		}
		time.Sleep(200 * time.Millisecond)
	}
	stop()
	t.Fatalf("port-forward %s not reachable on %s", target, localPort)
	return stop
}

func applyIn(t *testing.T, ns, manifest string) {
	t.Helper()
	cmd := exec.Command("kubectl", "apply", "-n", ns, "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("kubectl apply: %v\n%s", err, out)
	}
}

// baselineClientImage runs the steady workload (Story 12.8, #230). The
// 2026-10-20 live run showed busybox 1.36 wget cannot complete a TLS
// handshake with kube-apiserver (alert 40), and the `|| true` after it hid
// that, so the API burst never reached the apiserver and
// audit_events_per_min could not deviate. curl verifies the cluster CA, so a
// 200 proves the GET really landed. Same tag and digest as the S2 target
// (deploy/demo/scenarios/s2-credential-exfil), pinned per Story 12.6.
const baselineClientImage = "curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69"

// baselineLiveManifest is the steady workload of the 2026-10-19 live run
// (its own ServiceAccount allowed to GET its own pod), on a one-minute
// cycle so the baseline gets a busy sample every minute, plus a peer it
// talks to. mode=deviate (ConfigMap, re-read every cycle) turns on the real
// behavioural change. Each cycle logs `gets=N ok=M`, the GETs sent and the
// ones the apiserver answered 200, and an `apiserver_get_failed` line when
// any failed; the test reads that log instead of trusting the burst.
// Peer calls keep `|| true`: a refused or restricted connection still makes
// the flow the destination metric counts, and Olaitan may restrict the pod.
func baselineLiveManifest(ns string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: ServiceAccount
metadata: {name: steady}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: read-pods}
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: steady-read-pods}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: read-pods}
subjects: [{kind: ServiceAccount, name: steady, namespace: %[1]s}]
---
apiVersion: v1
kind: ConfigMap
metadata: {name: steady-mode}
data: {mode: steady}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: peer}
spec:
  replicas: 1
  selector: {matchLabels: {app: peer}}
  template:
    metadata: {labels: {app: peer}}
    spec:
      containers:
        - name: httpd
          image: busybox:1.36
          command: ["/bin/sh", "-c"]
          args:
            - |
              mkdir -p /www && echo ok > /www/index.html
              for p in 8080 8081 8082 8083 8084 8085 8086; do httpd -p $p -h /www; done
              sleep 2147483647
---
apiVersion: v1
kind: Service
metadata: {name: peer}
spec:
  selector: {app: peer}
  ports:
    - {name: p8080, port: 8080}
    - {name: p8081, port: 8081}
    - {name: p8082, port: 8082}
    - {name: p8083, port: 8083}
    - {name: p8084, port: 8084}
    - {name: p8085, port: 8085}
    - {name: p8086, port: 8086}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: steady}
spec:
  replicas: 1
  selector: {matchLabels: {app: steady}}
  template:
    metadata: {labels: {app: steady}}
    spec:
      serviceAccountName: steady
      volumes:
        - name: mode
          configMap: {name: steady-mode}
      containers:
        - name: app
          image: `+baselineClientImage+`
          volumeMounts: [{name: mode, mountPath: /etc/steady}]
          command: ["/bin/sh", "-c"]
          args:
            - |
              T=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
              CA=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
              U=https://kubernetes.default.svc/api/v1/namespaces/%[1]s/pods/$HOSTNAME
              c=0
              while true; do
                c=$((c+1))
                mode=$(cat /etc/steady/mode 2>/dev/null)
                if [ "$mode" = deviate ]; then n=80; else n=$((1 + RANDOM %% 3)); fi
                i=0
                ok=0
                last=none
                while [ $i -lt $n ]; do
                  code=$(curl -sS -m 10 --cacert "$CA" -H "Authorization: Bearer $T" -o /dev/null -w '%%{http_code}' "$U" 2>/tmp/curl.err)
                  if [ "$code" = 200 ]; then ok=$((ok+1)); else last="code=$code err=$(head -c 200 /tmp/curl.err | tr '\n' ' ')"; fi
                  i=$((i+1))
                done
                if [ $ok -ne $n ]; then echo "apiserver_get_failed cycle=$c $last"; fi
                wget -q -T 5 -O /dev/null http://peer.%[1]s.svc:8080/ || true
                if [ "$mode" = deviate ]; then
                  for p in 8081 8082 8083 8084 8085 8086; do wget -q -T 5 -O /dev/null http://peer.%[1]s.svc:$p/ || true; done
                  for b in 1 2 3 4 5 6; do cp /usr/bin/curl /tmp/dropped$b; /tmp/dropped$b --version >/dev/null; done
                fi
                echo "$(date -u +%%FT%%TZ) cycle=$c mode=$mode gets=$n ok=$ok"
                sleep 60
              done
`, ns)
}
