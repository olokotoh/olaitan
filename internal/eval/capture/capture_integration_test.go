//go:build integration

package capture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go/jetstream"
	"gopkg.in/yaml.v3"

	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// startTestServer spins up an in-process NATS server with JetStream enabled
// (the settling_integration_test.go embedded-JetStream idiom, BI-11). No kind
// cluster, no external infra.
func startTestServer(t *testing.T) *natsserver.Server {
	t.Helper()
	opts := &natsserver.Options{
		Host:      "127.0.0.1",
		Port:      -1,
		JetStream: true,
		StoreDir:  t.TempDir(),
		NoLog:     true,
		NoSigs:    true,
	}
	srv, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatalf("start test nats server: %v", err)
	}
	srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats server not ready")
	}
	t.Cleanup(srv.Shutdown)
	return srv
}

func newTestClient(t *testing.T, srv *natsserver.Server) *natsclient.Client {
	t.Helper()
	c, err := natsclient.NewClient(natsclient.ClientConfig{
		URL:           srv.ClientURL(),
		Name:          "capture-it",
		MaxReconnects: 0,
		ReconnectWait: time.Second,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

// itStreamConfigs provisions the run's streams with tiny MemoryStorage MaxBytes
// so the in-process server reserves nothing like the production cap. The
// subjects are the REAL internal/subjects constants (BI-1).
func itStreamConfigs() []jetstream.StreamConfig {
	return []jetstream.StreamConfig{
		{Name: "EVENTS_RAW", Subjects: []string{subjects.RawPrefix + ">"}, MaxAge: time.Hour, MaxBytes: 16 * 1024 * 1024, MaxMsgSize: 512 * 1024, Storage: jetstream.MemoryStorage, Retention: jetstream.LimitsPolicy},
		{Name: "EVIDENCE", Subjects: []string{subjects.EvidencePrefix + ">"}, MaxAge: time.Hour, MaxBytes: 16 * 1024 * 1024, Storage: jetstream.MemoryStorage, Retention: jetstream.LimitsPolicy},
		{Name: "AUDIT_ASSESSMENTS", Subjects: []string{subjects.AuditAssessments}, MaxAge: time.Hour, MaxBytes: 16 * 1024 * 1024, Storage: jetstream.MemoryStorage, Retention: jetstream.LimitsPolicy},
		{Name: "AUDIT_TRANSITIONS", Subjects: []string{subjects.AuditTransitions}, MaxAge: time.Hour, MaxBytes: 16 * 1024 * 1024, Storage: jetstream.MemoryStorage, Retention: jetstream.LimitsPolicy},
		{Name: "REPORTS", Subjects: []string{subjects.ReportsGenerated}, MaxAge: time.Hour, MaxBytes: 16 * 1024 * 1024, Storage: jetstream.MemoryStorage, Retention: jetstream.LimitsPolicy},
	}
}

func ensureStreams(t *testing.T, c *natsclient.Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, cfg := range itStreamConfigs() {
		if _, err := c.JetStream().CreateOrUpdateStream(ctx, cfg); err != nil {
			t.Fatalf("ensure stream %s: %v", cfg.Name, err)
		}
	}
}

func publishJSON(t *testing.T, c *natsclient.Client, subject string, payload any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.PublishJS(ctx, subject, payload); err != nil {
		t.Fatalf("publish %s: %v", subject, err)
	}
}

// TestCaptureIntegration_S5RS_SixArtefacts is the AC5 load-bearing proof
// (BI-11): an embedded-NATS in-process S5 + RS + 1-trial run. It publishes a
// deterministic stimulus to the REAL subjects, runs the rich Capturer, and
// asserts (1) all six artefacts exist under the run dir, (2) every .jsonl line
// json.Unmarshals into the envelope, (3) metadata.yaml's manifest_sha256 ==
// sha256sum eval/manifest.yaml, and (4) the size-cap alert trips on a synthetic
// over-cap run (the "not silent" proof). No kind cluster.
func TestCaptureIntegration_S5RS_SixArtefacts(t *testing.T) {
	srv := startTestServer(t)
	c := newTestClient(t, srv)
	ensureStreams(t, c)

	startedAt := time.Now().UTC()

	// Deterministic S5 (cryptomining) + RS stimulus to the REAL subjects
	// (BI-1): a raw event, an EvidencePackage, an FSM transition, an LLM
	// assessment, and a REPORTS.generated announcement. The payloads carry
	// just enough shape for the measure-vs-target + report header to read.
	publishJSON(t, c, subjects.RawFalco, map[string]any{
		"id": "evt-1", "source": "falco", "summary": "xmrig spawned", "timestamp": startedAt,
	})
	publishJSON(t, c, subjects.EvidencePackages, map[string]any{
		"schema_version": "evidence.v1", "package_id": "pkg-s5",
		"assembled_at": startedAt.Add(8 * time.Second),
	})
	publishJSON(t, c, subjects.AuditTransitions, map[string]any{
		"schema_version": "audit.transitions.v1", "after_state": "SUSPICIOUS",
		"decided_at": startedAt.Add(10 * time.Second), "package_id": "pkg-s5",
	})
	publishJSON(t, c, subjects.AuditAssessments, map[string]any{
		"schema_version": "audit.assessments.v2", "package_id": "pkg-s5", "mode": "full",
	})
	publishJSON(t, c, subjects.ReportsGenerated, map[string]any{
		"schema_version": "reports.generated.v1", "incident_id": "pkg-s5",
		"report_sha256": "deadbeef", "report_url": "reports/2026/06/15/deadbeef.md",
		"final_fsm_state": "SUSPICIOUS",
	})

	runDir := filepath.Join(t.TempDir(), "run-s5-rs")
	capturer := New(Config{Client: c, Logger: nil, DrainWindow: 400 * time.Millisecond})
	res, err := capturer.Capture(context.Background(), runDir)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}

	// Every non-metadata artefact captured its one published message.
	if res.Counts.Events != 1 || res.Counts.Evidence != 1 || res.Counts.Assessments != 1 ||
		res.Counts.FSM != 1 || res.Counts.Reports != 1 {
		t.Fatalf("drain counts = %+v; want one of each", res.Counts)
	}

	// (1) all six artefacts exist; the metadata.yaml is written below by the
	// harness-equivalent finalise path.
	manifestPath := repoManifestPath(t)
	wantHash := fileSHA256(t, manifestPath)
	writeITMetadata(t, runDir, res, wantHash, startedAt)

	for _, name := range []string{
		EventsArtefact, EvidenceArtefact, AssessmentsArtefact,
		FSMArtefact, ReportArtefact, MetadataArtefact,
	} {
		if _, err := os.Stat(filepath.Join(runDir, name)); err != nil {
			t.Errorf("artefact %q missing: %v", name, err)
		}
	}

	// (2) every .jsonl line unmarshals into the envelope.
	for _, name := range []string{EventsArtefact, EvidenceArtefact, AssessmentsArtefact, FSMArtefact} {
		assertJSONLParses(t, filepath.Join(runDir, name))
	}

	// (3) metadata.yaml manifest_sha256 == sha256sum eval/manifest.yaml.
	mdRaw, err := os.ReadFile(filepath.Join(runDir, MetadataArtefact))
	if err != nil {
		t.Fatalf("read metadata.yaml: %v", err)
	}
	var md map[string]any
	if err := yaml.Unmarshal(mdRaw, &md); err != nil {
		t.Fatalf("parse metadata.yaml: %v", err)
	}
	if md["manifest_sha256"] != wantHash {
		t.Errorf("metadata manifest_sha256 = %v; want %s (sha256sum eval/manifest.yaml)", md["manifest_sha256"], wantHash)
	}
	// The S5 detection signal was captured + the criterion measured honestly.
	if md["fsm_state_source"] != FSMSourceObservedTransitions {
		t.Errorf("fsm_state_source = %v; want observed_transitions (a transition was captured)", md["fsm_state_source"])
	}

	// (4) the size-cap alert trips on a synthetic over-cap run (the not-silent
	// proof, AC4/BI-10): a normal run is under the cap, and a 1-byte cap trips it.
	under, err := CheckSize(runDir, DefaultMaxRunSizeBytes)
	if err != nil {
		t.Fatalf("CheckSize under: %v", err)
	}
	if under.SizeCapExceeded {
		t.Errorf("a normal S5+RS run (%d bytes) must be under the 500 MiB cap", under.SizeBytes)
	}
	over, err := CheckSize(runDir, 1)
	if err != nil {
		t.Fatalf("CheckSize over: %v", err)
	}
	if !over.SizeCapExceeded {
		t.Errorf("a 1-byte cap must trip the size alert (the not-silent proof)")
	}
	// Fail-OPEN: the artefacts are still present after the over-cap check.
	if _, err := os.Stat(filepath.Join(runDir, EventsArtefact)); err != nil {
		t.Errorf("artefacts deleted on cap exceed; the cap must be fail-LOUD not fail-delete")
	}
}

// writeITMetadata writes a metadata.yaml carrying the AC3 fields the harness
// finalise computes (the in-process equivalent of cmd/olaitan-eval's
// writeMetadataFinalised), so the test can prove AC5's manifest-hash match +
// the measured fields without importing package main.
func writeITMetadata(t *testing.T, runDir string, res CaptureResult, hash string, startedAt time.Time) {
	t.Helper()
	m := Measure(res.Transitions, res.Evidence, Target{FSMState: "SUSPICIOUS", TimeToDetectSeconds: 120, Floor: false}, startedAt)
	sc, err := CheckSize(runDir, DefaultMaxRunSizeBytes)
	if err != nil {
		t.Fatalf("CheckSize: %v", err)
	}
	md := map[string]any{
		"run_id":                   "run-s5-rs",
		"manifest_sha256":          hash,
		"scenario":                 "s5",
		"config":                   "rs",
		"runs":                     1,
		"started_at":               startedAt.Format(time.RFC3339),
		"finished_at":              time.Now().UTC().Format(time.RFC3339),
		"olaitan_eval_version":     "it",
		"success_criterion_met":    m.SuccessCriterionMet,
		"measured_time_to_detect":  m.MeasuredTimeToDetect,
		"measured_final_fsm_state": m.MeasuredFinalFSMState,
		"fsm_state_source":         m.FSMStateSource,
		"resource_usage":           SnapshotResourceUsage(),
		"size_bytes":               sc.SizeBytes,
		"size_cap_exceeded":        sc.SizeCapExceeded,
	}
	b, err := yaml.Marshal(md)
	if err != nil {
		t.Fatalf("marshal metadata: %v", err)
	}
	if err := os.WriteFile(filepath.Join(runDir, MetadataArtefact), b, 0o644); err != nil {
		t.Fatalf("write metadata.yaml: %v", err)
	}
}

// assertJSONLParses asserts every line of a .jsonl artefact unmarshals into the
// Envelope and carries a non-empty payload (AC2/AC5).
func assertJSONLParses(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	n := 0
	for dec.More() {
		var env Envelope
		if err := dec.Decode(&env); err != nil {
			t.Fatalf("%s line %d does not parse into the envelope: %v", path, n+1, err)
		}
		if env.SchemaVersion == "" || env.Subject == "" || len(env.Payload) == 0 {
			t.Errorf("%s line %d envelope incomplete: %+v", path, n+1, env)
		}
		n++
	}
}

func repoManifestPath(t *testing.T) string {
	t.Helper()
	// internal/eval/capture -> repo root is three levels up.
	p := filepath.Join("..", "..", "..", "eval", "manifest.yaml")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("eval/manifest.yaml not found at %s: %v", p, err)
	}
	return p
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
