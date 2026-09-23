//go:build e2e

// Story 10.7 AC4: a real incident on kind-full produces an archived report
// whose sha256 equals its object key.
//
// Nothing here is published to NATS by the test. A fresh workload reads
// /etc/shadow inside its own container; Falco's stock "Read sensitive file
// untrusted" rule fires, the collector ingests it, the correlator opens an
// investigation, the FSM leaves CLEAN, the settling window finalises the
// incident, the DFIR agent writes the report and the durable writer PUTs it
// to MinIO. The test only reads: the REPORTS.generated announce, and the
// object bytes, which it hashes itself rather than trusting any hash the
// system reports.
//
// Gated twice. OLT_E2E_FULL says the cluster runs the Story 10.5 full profile;
// OLT_E2E_REPORT_ARCHIVE says the report archive has been switched on against
// the in-cluster MinIO fixture (`make e2e-full-report-archive` does both the
// setup and the run). The full profile on its own has no object store, so
// running this under OLT_E2E_FULL alone would fail for a reason unrelated to
// the archive.
package e2e_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/olokotoh/olaitan/internal/subjects"
)

const (
	reportArchiveBucket = "olaitan-reports"
	// The settling window is 10s in the archive overlay, but on a laptop-sized
	// kind-full cluster the path from the syscall to the PUT also crosses
	// Falco's output batching, the correlator, the analyst chain and the DFIR
	// agent. Four minutes is generous on purpose: this asserts integrity, not
	// latency.
	reportArchiveBudget = 4 * time.Minute
)

func TestReportArchive_RealIncidentOnFullProfile(t *testing.T) {
	if os.Getenv("OLT_E2E_FULL") == "" || os.Getenv("OLT_E2E_REPORT_ARCHIVE") == "" {
		t.Skip("report-archive integrity smoke skipped; set OLT_E2E_FULL=1 and OLT_E2E_REPORT_ARCHIVE=1 (make e2e-full-report-archive) to run")
	}
	requireKindCluster(t)
	if out, err := exec.Command("kubectl", "get", "deploy", "minio", "-n", defaultNamespace, "-o", "name").CombinedOutput(); err != nil {
		t.Fatalf("the MinIO fixture is not deployed, so there is nowhere to archive to; run `make e2e-full-report-archive`: %v\n%s", err, out)
	}
	// Idempotent. The alias lives in the MinIO container's own mc config and
	// is gone after any restart of that pod.
	kubectl(t, "exec", "deploy/minio", "-n", defaultNamespace, "--",
		"mc", "--no-color", "alias", "set", "local", "http://localhost:9000", "olaitan-e2e", "olaitan-e2e-secret")

	runID := fmt.Sprintf("%d", time.Now().UnixNano()%1e9)
	ns := "olaitan-ac4-" + runID
	workloadID := ns + "/Deployment/victim"

	// Read REPORTS from the moment this test started, so an announce left
	// over from an earlier run cannot satisfy this one. A start time, not
	// DeliverNew: the jetstream client creates an ordered consumer lazily on
	// the first fetch, so DeliverNew would mean "new as of whenever the loop
	// first polls", not "new as of now". An explicit ephemeral consumer with a
	// start time is created here and cannot race the attack.
	start := time.Now().Add(-2 * time.Second)
	portForward(t, "svc/"+defaultReleaseName+"-nats", natsLocalPort, "4222")
	nc, err := nats.Connect("nats://localhost:" + natsLocalPort)
	if err != nil {
		t.Fatalf("nats connect: %v", err)
	}
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatalf("jetstream: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cons, err := js.CreateOrUpdateConsumer(ctx, "REPORTS", jetstream.ConsumerConfig{
		FilterSubject:     subjects.ReportsGenerated,
		AckPolicy:         jetstream.AckNonePolicy,
		DeliverPolicy:     jetstream.DeliverByStartTimePolicy,
		OptStartTime:      &start,
		InactiveThreshold: 10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("REPORTS consumer: %v", err)
	}

	// --- the attack, for real, inside a pod ---------------------------------
	t.Cleanup(func() {
		_ = exec.Command("kubectl", "delete", "namespace", ns, "--ignore-not-found", "--wait=false").Run()
	})
	mustRun(t, "create namespace "+ns, "kubectl", "create", "namespace", ns)
	mustRun(t, "create victim", "kubectl", "-n", ns, "create", "deployment", "victim", "--image=nginx:1.27-alpine")
	mustRun(t, "victim ready", "kubectl", "-n", ns, "rollout", "status", "deploy/victim", "--timeout=3m")
	// Let Falco's container plugin learn the new container, as the Story 10.3
	// CI step does; an alert raised before that carries no pod and is dropped
	// as a host event.
	time.Sleep(10 * time.Second)
	attackAt := time.Now()
	mustRun(t, "falco: read /etc/shadow in the victim",
		"kubectl", "-n", ns, "exec", "deploy/victim", "--", "sh", "-c", "cat /etc/shadow > /dev/null")

	// --- the announce --------------------------------------------------------
	var announce reportGeneratedAnnounce
	var incidentID string
	deadline := time.Now().Add(reportArchiveBudget)
	for announce.WorkloadID != workloadID {
		if time.Now().After(deadline) {
			t.Fatalf("no REPORTS.generated for %s within %s: the incident was not raised, not finalised, or not archived", workloadID, reportArchiveBudget)
		}
		batch, err := cons.Fetch(10, jetstream.FetchMaxWait(5*time.Second))
		if err != nil {
			t.Logf("REPORTS fetch: %v", err)
			time.Sleep(time.Second)
			continue
		}
		for msg := range batch.Messages() {
			var a reportGeneratedAnnounce
			var id struct {
				IncidentID string `json:"incident_id"`
			}
			if json.Unmarshal(msg.Data(), &a) != nil || json.Unmarshal(msg.Data(), &id) != nil {
				continue
			}
			t.Logf("REPORTS.generated seen for %s", a.WorkloadID)
			if a.WorkloadID == workloadID {
				announce, incidentID = a, id.IncidentID
			}
		}
		if err := batch.Error(); err != nil && !errors.Is(err, nats.ErrTimeout) && !errors.Is(err, context.DeadlineExceeded) {
			t.Logf("REPORTS batch: %v", err)
		}
	}
	t.Logf("announce: final_fsm_state=%s report_url=%s report_sha256=%s", announce.FinalFSMState, announce.ReportURL, announce.ReportSHA256)

	// --- the incident is the attack ---------------------------------------
	// The settling controller writes one report per non-CLEAN episode. If
	// anything moved the victim out of CLEAN before the attack (on kind, the
	// mount-product-files hook trips a Falco rule on every pod start unless
	// the overlay's exception is in place), the report would describe that
	// and this test would prove nothing about the attack. So every FSM
	// transition of the victim must be at or after the attack, and the report
	// must be for the incident the attack opened.
	pw := kubectl(t, "get", "secret", defaultReleaseName+"-secrets", "-n", defaultNamespace,
		"-o", "jsonpath={.data.redis-password}")
	pwRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pw))
	if err != nil {
		t.Fatalf("decode redis password: %v", err)
	}
	histOut := kubectl(t, "exec", defaultReleaseName+"-redis-master-0", "-n", defaultNamespace, "--",
		"redis-cli", "-a", string(pwRaw), "--no-auth-warning", "lrange", "fsm:"+workloadID+":history", "0", "-1")
	var opened string
	for _, line := range strings.Split(strings.TrimSpace(histOut), "\n") {
		var h struct {
			Timestamp time.Time `json:"timestamp"`
			From      string    `json:"from_state"`
			To        string    `json:"to_state"`
			PackageID string    `json:"package_id"`
		}
		if json.Unmarshal([]byte(line), &h) != nil {
			continue
		}
		t.Logf("fsm history: %s %s -> %s (package %s)", h.Timestamp.Format(time.RFC3339Nano), h.From, h.To, h.PackageID)
		// One second of slack: host and node read the same kernel clock on
		// kind, but the two timestamps are taken in different processes.
		if h.Timestamp.Before(attackAt.Add(-time.Second)) {
			t.Fatalf("the victim moved %s -> %s at %s, before the attack at %s: the archived report describes something other than the attack",
				h.From, h.To, h.Timestamp.Format(time.RFC3339Nano), attackAt.UTC().Format(time.RFC3339Nano))
		}
		if h.From == "CLEAN" && opened == "" {
			opened = h.PackageID
		}
	}
	if opened == "" {
		t.Fatalf("fsm:%s:history has no transition out of CLEAN:\n%s", workloadID, histOut)
	}
	if incidentID != opened {
		t.Fatalf("the report is for incident %q, but the attack opened incident %q", incidentID, opened)
	}
	t.Logf("incident %s was opened by the attack and is the one archived", opened)

	// --- integrity -----------------------------------------------------------
	// The object key's basename is the content address. Assert the shape
	// first, so a key that merely contains the hash somewhere does not pass.
	if announce.ReportSHA256 == "" || len(announce.ReportSHA256) != sha256.Size*2 {
		t.Fatalf("report_sha256 %q is not a sha256 hex digest", announce.ReportSHA256)
	}
	keySHA := strings.TrimSuffix(path.Base(announce.ReportURL), ".md")
	if keySHA != announce.ReportSHA256 {
		t.Fatalf("object key %q does not end in the announced digest %q", announce.ReportURL, announce.ReportSHA256)
	}

	// Hash the bytes MinIO actually holds, here, in the test.
	obj := kubectl(t, "exec", "deploy/minio", "-n", defaultNamespace, "--",
		"mc", "--no-color", "cat", "local/"+reportArchiveBucket+"/"+announce.ReportURL)
	sum := sha256.Sum256([]byte(obj))
	got := hex.EncodeToString(sum[:])
	if got != keySHA {
		t.Fatalf("sha256 of the archived object is %s, but its key says %s", got, keySHA)
	}
	t.Logf("sha256(object) = %s = key basename", got)

	if !strings.Contains(obj, `schema_version: "report.v1"`) {
		t.Errorf("archived object does not look like a report.v1 document:\n%s", obj)
	}

	// At rest: SSE-KMS and object lock, both preconditions of the durable
	// writer (Story 4.6) that the fixture used to be unable to satisfy.
	stat := kubectl(t, "exec", "deploy/minio", "-n", defaultNamespace, "--",
		"mc", "--no-color", "stat", "local/"+reportArchiveBucket+"/"+announce.ReportURL)
	if !strings.Contains(stat, "SSE-KMS") {
		t.Errorf("archived object is not SSE-KMS encrypted:\n%s", stat)
	}
	if !strings.Contains(stat, "Object-Lock-Mode") {
		t.Errorf("archived object carries no object-lock retention:\n%s", stat)
	}
}

// mustRun runs a deliberate action and fails the test if it did not happen,
// so a failed action is reported as itself rather than minutes later as a
// missing report.
func mustRun(t *testing.T, what string, name string, args ...string) {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", what, err, out)
	}
	t.Logf("action ok: %s", what)
}
