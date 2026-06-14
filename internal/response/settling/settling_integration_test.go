//go:build integration

package settling

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go/jetstream"

	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// startTestServer spins up an in-process NATS server with JetStream enabled
// (mirrors internal/nats/nats_test.go's helper).
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
		Name:             "settling-it",
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

// ensureIncidentsStream provisions the INCIDENTS stream with a tiny MemoryStorage
// MaxBytes so the in-process server does not reserve the full production cap.
func ensureIncidentsStream(t *testing.T, c *natsclient.Client) {
	t.Helper()
	cfg := jetstream.StreamConfig{
		Name:       "INCIDENTS",
		Subjects:   []string{subjects.IncidentFinalised},
		MaxAge:     time.Hour,
		MaxBytes:   1 * 1024 * 1024,
		Storage:    jetstream.MemoryStorage,
		Retention:  jetstream.LimitsPolicy,
		Duplicates: 2 * time.Minute,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.JetStream().CreateOrUpdateStream(ctx, cfg); err != nil {
		t.Fatalf("ensure INCIDENTS stream: %v", err)
	}
}

// drainFinalised pulls up to want messages off INCIDENTS.finalised within the
// deadline, returning the decoded events.
func drainFinalised(t *testing.T, c *natsclient.Client, want int, within time.Duration) []IncidentFinalised {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), within)
	defer cancel()
	stream, err := c.JetStream().Stream(ctx, "INCIDENTS")
	if err != nil {
		t.Fatalf("stream INCIDENTS: %v", err)
	}
	cons, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       "settling-it-reader",
		AckPolicy:     jetstream.AckExplicitPolicy,
		FilterSubject: subjects.IncidentFinalised,
	})
	if err != nil {
		t.Fatalf("consumer: %v", err)
	}
	var out []IncidentFinalised
	deadline := time.Now().Add(within)
	for len(out) < want && time.Now().Before(deadline) {
		msg, ferr := cons.Next(jetstream.FetchMaxWait(200 * time.Millisecond))
		if ferr != nil {
			continue
		}
		var evt IncidentFinalised
		if err := json.Unmarshal(msg.Data(), &evt); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		out = append(out, evt)
		_ = msg.Ack()
	}
	return out
}

func runIT(t *testing.T, c *natsclient.Client, window time.Duration) (*Controller, func()) {
	t.Helper()
	pub, err := NewNATSPublisher(c)
	if err != nil {
		t.Fatalf("NewNATSPublisher: %v", err)
	}
	ctrl, err := New(Config{Window: window}, pub, nil, discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = ctrl.Run(ctx) }()
	return ctrl, func() { cancel(); <-done }
}

func itTransition(wid string, to schema.PodSecurityState, from schema.PodSecurityState, score float64) schema.StateTransition {
	return schema.StateTransition{
		Timestamp:   time.Now(),
		FromState:   from,
		ToState:     to,
		TriggerType: "automated",
		Confidence:  score,
		WorkloadID:  wid,
		PackageID:   "pkg-" + wid,
		Reason:      schema.ReasonEscalationThresholdCrossed,
	}
}

// TestIntegration_StablePublishesOne (AC5): a workload stable in a non-CLEAN
// state through the full window publishes exactly one IncidentFinalised, and
// the payload shape round-trips through the real INCIDENTS stream.
func TestIntegration_StablePublishesOne(t *testing.T) {
	srv := startTestServer(t)
	c := newTestClient(t, srv)
	ensureIncidentsStream(t, c)
	ctrl, stop := runIT(t, c, 30*time.Millisecond)
	defer stop()

	ctrl.Publish(itTransition("w-stable", schema.StateQuarantined, schema.StateRestricted, 88))

	evts := drainFinalised(t, c, 1, 3*time.Second)
	if len(evts) != 1 {
		t.Fatalf("got %d IncidentFinalised events, want 1", len(evts))
	}
	evt := evts[0]
	if evt.FinalState != string(schema.StateQuarantined) {
		t.Errorf("final_state = %q, want QUARANTINED", evt.FinalState)
	}
	if evt.ThreatScore != 88 {
		t.Errorf("threat_score = %v, want 88", evt.ThreatScore)
	}
	if evt.WorkloadID != "w-stable" || evt.PackageID != "pkg-w-stable" {
		t.Errorf("workload/package = %q/%q", evt.WorkloadID, evt.PackageID)
	}
	if evt.SchemaVersion != SchemaVersionIncidentFinalised {
		t.Errorf("schema_version = %q", evt.SchemaVersion)
	}
}

// TestIntegration_OscillatingResetsThenOne (AC5): oscillating non-CLEAN states
// reset the timer; after stabilisation at most one finalisation results.
func TestIntegration_OscillatingResetsThenOne(t *testing.T) {
	srv := startTestServer(t)
	c := newTestClient(t, srv)
	ensureIncidentsStream(t, c)
	ctrl, stop := runIT(t, c, 50*time.Millisecond)
	defer stop()

	ctrl.Publish(itTransition("w-osc", schema.StateSuspicious, schema.StateClean, 30))
	time.Sleep(20 * time.Millisecond)
	ctrl.Publish(itTransition("w-osc", schema.StateRestricted, schema.StateSuspicious, 55))
	time.Sleep(20 * time.Millisecond)
	ctrl.Publish(itTransition("w-osc", schema.StateQuarantined, schema.StateRestricted, 92))

	evts := drainFinalised(t, c, 1, 3*time.Second)
	if len(evts) != 1 {
		t.Fatalf("got %d events, want exactly 1 after stabilisation", len(evts))
	}
	if evts[0].FinalState != string(schema.StateQuarantined) {
		t.Errorf("surviving final_state = %q, want QUARANTINED", evts[0].FinalState)
	}
}

// TestIntegration_DeescalationToCleanPublishesNone (AC5): de-escalation to
// CLEAN before the window completes publishes zero IncidentFinalised.
func TestIntegration_DeescalationToCleanPublishesNone(t *testing.T) {
	srv := startTestServer(t)
	c := newTestClient(t, srv)
	ensureIncidentsStream(t, c)
	ctrl, stop := runIT(t, c, 60*time.Millisecond)
	defer stop()

	ctrl.Publish(itTransition("w-clean", schema.StateQuarantined, schema.StateRestricted, 90))
	time.Sleep(20 * time.Millisecond)
	ctrl.Publish(itTransition("w-clean", schema.StateClean, schema.StateQuarantined, 0))

	evts := drainFinalised(t, c, 1, 1500*time.Millisecond)
	if len(evts) != 0 {
		t.Fatalf("got %d events, want 0 (CLEAN cancels finalisation, AC4)", len(evts))
	}
}
