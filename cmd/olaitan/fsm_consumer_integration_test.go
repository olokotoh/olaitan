//go:build integration

package main

import (
	"context"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go/jetstream"
	"golang.org/x/sync/errgroup"

	"github.com/olokotoh/olaitan/internal/agent/provider"
	"github.com/olokotoh/olaitan/internal/decision/analyst"
	"github.com/olokotoh/olaitan/internal/decision/score"
	"github.com/olokotoh/olaitan/internal/metrics"
	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/response/fsm"
	"github.com/olokotoh/olaitan/internal/response/risk"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// TestIntegration_FSMConsumerScoresBeforeChain drives the REAL wired consumer
// (wireFSMConsumer) over an embedded JetStream with a real analyst.Chain whose
// provider blocks until released (Story 7.4, issue #186):
//
//  1. a triggering package for workload A reaches SUSPICIOUS while A's chain
//     is blocked, and stays un-acked (Story 3.9 resume);
//  2. a package for workload B is evaluated meanwhile (its own chain is
//     dispatched to the second worker and blocks too);
//  3. releasing the chain produces A's second, model-driven transition, and
//     the package is then acked.
func TestIntegration_FSMConsumerScoresBeforeChain(t *testing.T) {
	opts := &natsserver.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir(), NoLog: true, NoSigs: true}
	srv, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatalf("nats server: %v", err)
	}
	srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats server not ready")
	}
	t.Cleanup(srv.Shutdown)

	nc, err := natsclient.NewClient(natsclient.ClientConfig{URL: srv.ClientURL(), Name: "fsm-consumer-test"})
	if err != nil {
		t.Fatalf("nats client: %v", err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = nc.Close(c)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := natsclient.EnsureStreams(ctx, nc.JetStream(), []jetstream.StreamConfig{{
		Name: "EVIDENCE", Subjects: []string{subjects.EvidencePrefix + ">"}, MaxAge: time.Hour,
		MaxBytes: 16 * 1024 * 1024, Storage: jetstream.MemoryStorage, Retention: jetstream.LimitsPolicy,
	}}); err != nil {
		t.Fatalf("ensure streams: %v", err)
	}

	bp := &blockingProvider{scriptedProvider: scriptedProvider{byRole: map[provider.Role]string{
		provider.RoleL1:     `{"hypothesis":"credential theft","cited_evidence":[{"event_id":"evt-p-a1"}],"confidence":70}`,
		provider.RoleL2:     `{"verdict":"confirmed","verified_evidence":[{"event_id":"evt-p-a1","finding":"confirmed"}],"confidence":66}`,
		provider.RoleSenior: `{"threat_type":"credential_access","reasoning":"shadow read confirmed","confidence":80}`,
	}}, gate: make(chan struct{})}
	reg := metrics.NewRegistry()
	l1, _ := analyst.NewL1(bp, analyst.PromptSpec{System: "s", Version: "v"}, reg, nil)
	l2, _ := analyst.NewL2(bp, analyst.PromptSpec{System: "s", Version: "v"}, reg, nil)
	sr, _ := analyst.NewSenior(bp, analyst.PromptSpec{System: "s", Version: "v"}, reg, nil)
	chain, err := analyst.NewChain(l1, l2, sr, reg, nil)
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	runs, _ := analyst.RegisterChainRunsMetric(reg)
	dispatches, _ := analyst.RegisterChainDispatchMetric(reg)
	sink := &recordingSink{}
	machine, err := fsm.New(nil, nil, sink, nil)
	if err != nil {
		t.Fatalf("fsm.New: %v", err)
	}
	calc, err := score.New(nil, metrics.NewRegistry())
	if err != nil {
		t.Fatalf("score.New: %v", err)
	}

	runCtx, runCancel := context.WithCancel(ctx)
	g, gctx := errgroup.WithContext(runCtx)
	if err := wireFSMConsumer(gctx, g, chainTestLogger(), nc, calc, machine, chain, chain.Mode(), nil, &fakeAssessmentPub{}, runs, dispatches, risk.New(0)); err != nil {
		t.Fatalf("wireFSMConsumer: %v", err)
	}
	defer func() {
		runCancel()
		_ = g.Wait()
	}()

	waitFor := func(what string, cond func([]schema.StateTransition) bool) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if cond(sink.all()) {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %s; transitions: %+v", what, sink.all())
	}
	has := func(wl string, to schema.PodSecurityState) func([]schema.StateTransition) bool {
		return func(sts []schema.StateTransition) bool {
			for _, st := range sts {
				if st.WorkloadID == wl && st.ToState == to {
					return true
				}
			}
			return false
		}
	}

	if _, err := nc.PublishJS(ctx, subjects.EvidencePackages, pkgFor("ns/Deployment/a", "p-a1", "80")); err != nil {
		t.Fatalf("publish A: %v", err)
	}
	waitFor("A SUSPICIOUS while its chain is blocked", has("ns/Deployment/a", schema.StateSuspicious))

	if _, err := nc.PublishJS(ctx, subjects.EvidencePackages, pkgFor("ns/Deployment/b", "p-b1", "80")); err != nil {
		t.Fatalf("publish B: %v", err)
	}
	waitFor("B evaluated while A's chain is blocked", has("ns/Deployment/b", schema.StateSuspicious))

	stream, err := nc.JetStream().Stream(ctx, "EVIDENCE")
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	cons, err := stream.Consumer(ctx, "olaitan-response-fsm")
	if err != nil {
		t.Fatalf("consumer: %v", err)
	}
	info, err := cons.Info(ctx)
	if err != nil {
		t.Fatalf("consumer info: %v", err)
	}
	// Both packages trigger the chain (severity 80 >= the FR19 floor) and both
	// chains are blocked on the provider, so both stay un-acked.
	if info.NumAckPending != 2 {
		t.Fatalf("ack pending = %d, want 2 (A and B, held while their chains run)", info.NumAckPending)
	}

	close(bp.gate)
	waitFor("A's model-driven second transition", has("ns/Deployment/a", schema.StateRestricted))

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if info, err = cons.Info(ctx); err == nil && info.NumAckPending == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if info.NumAckPending != 0 {
		t.Fatalf("ack pending = %d after the verdict was applied, want 0", info.NumAckPending)
	}
	var restricted schema.StateTransition
	for _, st := range sink.all() {
		if st.WorkloadID == "ns/Deployment/a" && st.ToState == schema.StateRestricted {
			restricted = st
		}
	}
	if restricted.PackageID != "p-a1" {
		t.Fatalf("the model-driven transition must carry the triggering package, got %+v", restricted)
	}
}
