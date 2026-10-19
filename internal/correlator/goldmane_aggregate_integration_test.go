//go:build integration

package correlator

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	kubefake "k8s.io/client-go/kubernetes/fake"

	"github.com/olokotoh/olaitan/internal/correlator/assembler"
	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// Story 11.2b live gate, 2026-10-19: end to end through the correlator. A
// Falco alert from the S4 pod and the real Goldmane flow that pod opened meet
// in ONE window (tenant-acme/Deployment/web), cross the two-source threshold,
// and the published multi_signal package carries the flow, so the rule
// engine (which evaluates every event of a multi_signal package) can match
// OLT-NET-002 on it. Before the fix the flow was dropped at identity
// resolution and never reached any window.
//
// Scope: this proves attribution only, with the flow arriving as the second
// source. On the live run Goldmane flows arrive 15-30s after Falco/runtime/
// audit, into a window that has usually already fired; under the Story 1.14
// D1 rising edge that window does not re-publish, so this ordering is NOT the
// live one. That timing gap is an OPEN decision, not fixed here.
func TestIntegration_GoldmaneFlowJoinsItsDeploymentWindow(t *testing.T) {
	srv := startTestNATSServer(t)
	nc, err := natsclient.NewClient(natsclient.ClientConfig{URL: srv.ClientURL(), Name: "goldmane-aggregate-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer closeCancel()
		_ = nc.Close(closeCtx)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := natsclient.EnsureStreams(ctx, nc.JetStream(), testStreamConfigs()); err != nil {
		t.Fatal(err)
	}
	kube := kubefake.NewSimpleClientset(s4Cluster()...)
	c, err := New(Config{
		NATS:                  nc,
		Kube:                  kube,
		Assembler:             assembler.New(assembler.Config{Kube: kube, Posture: fakePosture{now: time.Now}, MaxPackageBytes: 128 * 1024}),
		WindowDuration:        time.Minute,
		MultiSignalMinSources: 2,
		FalcoTriggerFloor:     "off",
		Log:                   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	stream, err := nc.JetStream().Stream(ctx, "EVIDENCE")
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable: "goldmane-aggregate-test", AckPolicy: jetstream.AckExplicitPolicy, FilterSubject: subjects.EvidencePackages,
	})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	falco := schema.Event{
		ID: "falco-s4", Timestamp: now, Source: schema.SourceFalco, Category: schema.CategorySyscall,
		Severity: "notice", Summary: "exec in web",
		Pod: schema.PodRef{Namespace: "tenant-acme", Name: "web-bd846c7f-kx8cv", UID: "web-uid"},
	}
	flow := loadLiveS4Flows(t)[0]
	flow.Timestamp = now // the live window start is far in the past; only the identity path is under test
	if _, err := c.AddEvent(ctx, falco); err != nil {
		t.Fatalf("falco event: %v", err)
	}
	if _, err := c.AddEvent(ctx, flow); err != nil {
		t.Fatalf("live goldmane flow dropped: %v", err)
	}
	pkg := nextPackage(t, consumer)
	if pkg.Trigger.Type != "multi_signal" {
		t.Fatalf("trigger = %q, want multi_signal", pkg.Trigger.Type)
	}
	if pkg.WorkloadID != "tenant-acme/Deployment/web" {
		t.Fatalf("package workload = %q, want tenant-acme/Deployment/web", pkg.WorkloadID)
	}
	var sawFlow bool
	for _, ev := range pkg.Events {
		if ev.ID == flow.ID && ev.Source == schema.SourceNetwork {
			sawFlow = true
		}
	}
	if !sawFlow {
		t.Fatalf("multi_signal package does not carry the live flow %s; events=%d", flow.ID, len(pkg.Events))
	}
}
