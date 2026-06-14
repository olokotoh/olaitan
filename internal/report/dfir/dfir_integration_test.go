//go:build integration

package dfir

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/olokotoh/olaitan/internal/agent/provider"
	"github.com/olokotoh/olaitan/internal/metrics"
	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/response/settling"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// This integration test asserts NO external infra is required: it stands up an
// in-process NATS server with JetStream, provisions the INCIDENTS stream, runs
// the real DFIR agent as a durable consumer against fake providers, publishes
// IncidentFinalised events, and asserts the rendered ForensicReport is announced
// on REPORTS.generated (or fails closed on a schema violation).

func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

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
		URL:              srv.ClientURL(),
		Name:             "dfir-it",
		MaxReconnects:    0,
		ReconnectWait:    time.Second,
		ReconnectBufSize: 1 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

func ensureStreams(t *testing.T, c *natsclient.Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, cfg := range []jetstream.StreamConfig{
		{
			Name:       "INCIDENTS",
			Subjects:   []string{subjects.IncidentFinalised},
			MaxAge:     time.Hour,
			MaxBytes:   1 * 1024 * 1024,
			Storage:    jetstream.MemoryStorage,
			Retention:  jetstream.LimitsPolicy,
			Duplicates: 2 * time.Minute,
		},
		{
			Name:       "REPORTS",
			Subjects:   []string{subjects.ReportsGenerated},
			MaxAge:     time.Hour,
			MaxBytes:   1 * 1024 * 1024,
			Storage:    jetstream.MemoryStorage,
			Retention:  jetstream.LimitsPolicy,
			Duplicates: 2 * time.Minute,
		},
	} {
		if _, err := c.JetStream().CreateOrUpdateStream(ctx, cfg); err != nil {
			t.Fatalf("ensure %s stream: %v", cfg.Name, err)
		}
	}
}

func publishFinalised(t *testing.T, c *natsclient.Client, evt settling.IncidentFinalised) {
	t.Helper()
	pub, err := settling.NewNATSPublisher(c)
	if err != nil {
		t.Fatalf("NewNATSPublisher: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := pub.PublishIncidentFinalised(ctx, evt); err != nil {
		t.Fatalf("publish finalised: %v", err)
	}
}

func drainReports(t *testing.T, c *natsclient.Client, want int, within time.Duration) []ReportGenerated {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), within)
	defer cancel()
	stream, err := c.JetStream().Stream(ctx, "REPORTS")
	if err != nil {
		t.Fatalf("stream REPORTS: %v", err)
	}
	cons, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       "dfir-it-reader",
		AckPolicy:     jetstream.AckExplicitPolicy,
		FilterSubject: subjects.ReportsGenerated,
	})
	if err != nil {
		t.Fatalf("consumer: %v", err)
	}
	var out []ReportGenerated
	deadline := time.Now().Add(within)
	for len(out) < want && time.Now().Before(deadline) {
		msg, ferr := cons.Next(jetstream.FetchMaxWait(200 * time.Millisecond))
		if ferr != nil {
			continue
		}
		var evt ReportGenerated
		if err := json.Unmarshal(msg.Data(), &evt); err != nil {
			t.Fatalf("unmarshal report event: %v", err)
		}
		out = append(out, evt)
		_ = msg.Ack()
	}
	return out
}

func runAgent(t *testing.T, c *natsclient.Client, fp provider.Provider, reports ReportPublisher, audit AuditRecorder) func() {
	t.Helper()
	reg := metrics.NewRegistry()
	a, err := NewDFIR(fp, PromptSpec{System: "dfir", Version: "dfir.it.v1"}, reports, audit, reg, discardLog())
	if err != nil {
		t.Fatalf("NewDFIR: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = a.Run(ctx, c) }()
	return func() { cancel(); <-done }
}

func itFinalised(pkg, wid, state string, score float64) settling.IncidentFinalised {
	return settling.IncidentFinalised{
		SchemaVersion: settling.SchemaVersionIncidentFinalised,
		PackageID:     pkg,
		WorkloadID:    wid,
		FinalState:    state,
		ThreatScore:   score,
		FinalisedAt:   time.Now().UTC(),
		History: []schema.StateTransition{
			{ToState: schema.PodSecurityState("RESTRICTED")},
			{ToState: schema.PodSecurityState(state)},
		},
	}
}

// TestIntegration_SchemaConformingAnnounced: a schema-conforming fake provider
// yields a valid rendered ForensicReport announced on REPORTS.generated.
func TestIntegration_SchemaConformingAnnounced(t *testing.T) {
	srv := startTestServer(t)
	c := newTestClient(t, srv)
	ensureStreams(t, c)

	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8", resp: provider.Response{Raw: validReportJSON, StopReason: "end_turn", Model: "claude-opus-4-8"}}
	rp, err := NewNATSReportPublisher(c)
	if err != nil {
		t.Fatalf("NewNATSReportPublisher: %v", err)
	}
	stop := runAgent(t, c, fp, rp, nil)
	defer stop()

	publishFinalised(t, c, itFinalised("pkg-it-1", "ns/Deployment/web", "QUARANTINED", 88))

	evts := drainReports(t, c, 1, 5*time.Second)
	if len(evts) != 1 {
		t.Fatalf("got %d REPORTS.generated events, want 1", len(evts))
	}
	if evts[0].IncidentID != "pkg-it-1" || evts[0].FinalFSMState != "QUARANTINED" {
		t.Errorf("announcement wrong: %+v", evts[0])
	}
	if len(evts[0].ReportSHA256) != 64 {
		t.Errorf("report SHA256 not 64 hex: %q", evts[0].ReportSHA256)
	}
	if evts[0].SchemaVersion != SchemaVersionReportGenerated {
		t.Errorf("schema_version = %q", evts[0].SchemaVersion)
	}
}

// TestIntegration_SchemaViolationFailsClosed: a schema-violating fake provider
// triggers the fail-closed path (no report announced), and the failure is
// recorded in the audit recorder.
func TestIntegration_SchemaViolationFailsClosed(t *testing.T) {
	srv := startTestServer(t)
	c := newTestClient(t, srv)
	ensureStreams(t, c)

	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8", resp: provider.Response{Raw: `{"body": 123}`, StopReason: "end_turn"}}
	rp, err := NewNATSReportPublisher(c)
	if err != nil {
		t.Fatalf("NewNATSReportPublisher: %v", err)
	}
	ar := &fakeAuditRecorder{}
	stop := runAgent(t, c, fp, rp, ar)
	defer stop()

	// Control workload that succeeds, so "zero reports for the violating one" is
	// a non-vacuous assertion (the settling integration-test precedent).
	publishFinalised(t, c, itFinalised("pkg-bad", "ns/Deployment/bad", "RESTRICTED", 50))

	evts := drainReports(t, c, 1, 2*time.Second)
	if len(evts) != 0 {
		t.Fatalf("a schema-violating reply must announce no report, got %d", len(evts))
	}
	// Give the consumer a beat to have processed + audited the failure.
	deadline := time.Now().Add(2 * time.Second)
	for len(ar.records) == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if len(ar.records) == 0 || ar.records[0].Status != statusSchemaViolation {
		t.Errorf("the failure must be audited with schema_violation, got %+v", ar.records)
	}
}

// TestIntegration_ScenarioTechniques: each S1-S5 scenario renders with its bound
// technique announced. The technique is sourced from the persisted assessment;
// since the wire IncidentFinalised carries no assessment, this test drives the
// agent's Generate directly against the fake provider with a per-scenario
// assessment to assert the technique rendering, while still proving the consumer
// path end-to-end for one scenario.
func TestIntegration_ScenarioTechniques(t *testing.T) {
	srv := startTestServer(t)
	c := newTestClient(t, srv)
	ensureStreams(t, c)

	for scen, tech := range scenarioTechnique {
		scen, tech := scen, tech
		t.Run(scen, func(t *testing.T) {
			fp := &fakeProvider{name: "claude", model: "claude-opus-4-8", resp: provider.Response{Raw: validReportJSON, StopReason: "end_turn"}}
			reg := metrics.NewRegistry()
			a, err := NewDFIR(fp, PromptSpec{System: "dfir", Version: "dfir.it.v1"}, &fakeReportPublisher{}, nil, reg, discardLog())
			if err != nil {
				t.Fatalf("NewDFIR: %v", err)
			}
			inc := Incident{
				Event:      itFinalised("pkg-"+scen, "wl-"+scen, "QUARANTINED", 80),
				Package:    schema.EvidencePackage{PackageID: "pkg-" + scen, WorkloadID: "wl-" + scen},
				Assessment: &schema.ThreatAssessment{MitreTechniques: []string{tech}},
			}
			rendered, reported, gerr := a.Generate(context.Background(), inc)
			if gerr != nil || !reported {
				t.Fatalf("%s: reported=%v err=%v", scen, reported, gerr)
			}
			if !strings.Contains(rendered, "- \""+tech+"\"") {
				t.Errorf("%s: rendered report missing bound technique %q", scen, tech)
			}
		})
	}
}
