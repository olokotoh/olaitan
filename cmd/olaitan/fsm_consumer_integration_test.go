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
	responseaudit "github.com/olokotoh/olaitan/internal/response/audit"
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
	if err := wireFSMConsumer(gctx, g, chainTestLogger(), nc, calc, machine, chain, chain.Mode(), nil, &fakeAssessmentPub{}, runs, dispatches, risk.New(0), make(chan struct{})); err != nil {
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

	// B cites the same event id the scripted model answers with, so its
	// chain completes on the first attempt (an uncitable answer would enter
	// the 1 s / 4 s retry back-off and make the ack timing below flaky).
	pkgB := pkgFor("ns/Deployment/b", "p-b1", "80")
	pkgB.RuleMatches[0].EventID = "evt-p-a1"
	pkgB.Events = []schema.Event{{ID: "evt-p-a1"}}
	if _, err := nc.PublishJS(ctx, subjects.EvidencePackages, pkgB); err != nil {
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

	pending := -1
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ci, ierr := cons.Info(ctx); ierr == nil {
			pending = ci.NumAckPending
			if pending == 0 {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if pending != 0 {
		t.Fatalf("ack pending = %d after the verdicts were applied, want 0", pending)
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

// TestIntegration_ShutdownDrainBeforeNATSClose pins the round-2 review fix
// (PR #209): the aggregator's NATS close and the FSM sinks must wait for the
// FSM consumer's shutdown drain. A chain that finishes inside the shutdown
// grace AFTER the ring context is cancelled must still get its
// AUDIT.assessments publish, its AUDIT.transitions event for the model-driven
// transition, and its ack, all before the connection is drained. It wires
// the same helpers the ring uses (startNATSCloserAfterFSM,
// drainAwareContext) around a real connection close.
func TestIntegration_ShutdownDrainBeforeNATSClose(t *testing.T) {
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

	nc, err := natsclient.NewClient(natsclient.ClientConfig{URL: srv.ClientURL(), Name: "fsm-shutdown-test"})
	if err != nil {
		t.Fatalf("nats client: %v", err)
	}
	// A second connection observes the server after nc is drained.
	obs, err := natsclient.NewClient(natsclient.ClientConfig{URL: srv.ClientURL(), Name: "fsm-shutdown-observer"})
	if err != nil {
		t.Fatalf("observer client: %v", err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = obs.Close(c)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := natsclient.EnsureStreams(ctx, nc.JetStream(), []jetstream.StreamConfig{
		{Name: "EVIDENCE", Subjects: []string{subjects.EvidencePrefix + ">"}, MaxAge: time.Hour, MaxBytes: 16 * 1024 * 1024, Storage: jetstream.MemoryStorage, Retention: jetstream.LimitsPolicy},
		{Name: "AUDIT_TEST", Subjects: []string{subjects.AuditTransitions, subjects.AuditAssessments}, MaxAge: time.Hour, MaxBytes: 16 * 1024 * 1024, Storage: jetstream.MemoryStorage, Retention: jetstream.LimitsPolicy},
	}); err != nil {
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
	assessPub, err := responseaudit.NewNATSAssessmentPublisher(nc)
	if err != nil {
		t.Fatalf("assessment publisher: %v", err)
	}
	tp, err := responseaudit.NewNATSTransitionPublisher(nc)
	if err != nil {
		t.Fatalf("transition publisher: %v", err)
	}
	auditSink, err := responseaudit.NewTransitionAuditSink(tp, chainTestLogger(), responseaudit.TransitionAuditSinkConfig{DrainEvery: 20 * time.Millisecond})
	if err != nil {
		t.Fatalf("transition sink: %v", err)
	}
	machine, err := fsm.New(nil, nil, fsm.MultiSink{auditSink}, nil)
	if err != nil {
		t.Fatalf("fsm.New: %v", err)
	}
	calc, err := score.New(nil, metrics.NewRegistry())
	if err != nil {
		t.Fatalf("score.New: %v", err)
	}

	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	g, gctx := errgroup.WithContext(runCtx)
	fsmDone := make(chan struct{})
	sinkCtx := drainAwareContext(gctx, fsmDone, fsmShutdownBound)
	g.Go(func() error { return auditSink.Run(sinkCtx) })
	if err := wireFSMConsumer(gctx, g, chainTestLogger(), nc, calc, machine, chain, chain.Mode(), nil, assessPub, runs, dispatches, risk.New(0), fsmDone); err != nil {
		t.Fatalf("wireFSMConsumer: %v", err)
	}
	startNATSCloserAfterFSM(gctx, g, fsmDone, fsmShutdownBound, func() {
		c, ccancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer ccancel()
		_ = nc.Close(c)
	})

	if _, err := nc.PublishJS(ctx, subjects.EvidencePackages, pkgFor("ns/Deployment/a", "p-a1", "80")); err != nil {
		t.Fatalf("publish: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for machine.State("ns/Deployment/a") != schema.StateSuspicious && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if machine.State("ns/Deployment/a") != schema.StateSuspicious {
		t.Fatal("setup: A never reached SUSPICIOUS")
	}
	// Give the chain time to be picked up, then request shutdown (which
	// also requests the NATS close) while the chain is still blocked, and
	// let the chain finish inside the shutdown grace.
	time.Sleep(200 * time.Millisecond)
	runCancel()
	time.Sleep(300 * time.Millisecond)
	close(bp.gate)
	if err := g.Wait(); err != nil {
		t.Fatalf("ring returned error: %v", err)
	}
	if machine.State("ns/Deployment/a") != schema.StateRestricted {
		t.Fatalf("the verdict finished inside the grace must be applied: state %s", machine.State("ns/Deployment/a"))
	}

	octx, ocancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer ocancel()
	countOn := func(subject string) uint64 {
		st, serr := obs.JetStream().Stream(octx, "AUDIT_TEST")
		if serr != nil {
			t.Fatalf("observer stream: %v", serr)
		}
		info, ierr := st.Info(octx, jetstream.WithSubjectFilter(subject))
		if ierr != nil {
			t.Fatalf("observer stream info: %v", ierr)
		}
		return info.State.Subjects[subject]
	}
	if n := countOn(subjects.AuditAssessments); n != 1 {
		t.Fatalf("AUDIT.assessments messages = %d, want 1 (published before the NATS drain)", n)
	}
	if n := countOn(subjects.AuditTransitions); n != 2 {
		t.Fatalf("AUDIT.transitions messages = %d, want 2 (deterministic + model-driven, both before the drain)", n)
	}
	st, err := obs.JetStream().Stream(octx, "EVIDENCE")
	if err != nil {
		t.Fatalf("observer evidence stream: %v", err)
	}
	cons, err := st.Consumer(octx, "olaitan-response-fsm")
	if err != nil {
		t.Fatalf("observer consumer: %v", err)
	}
	ci, err := cons.Info(octx)
	if err != nil {
		t.Fatalf("observer consumer info: %v", err)
	}
	if ci.NumAckPending != 0 {
		t.Fatalf("ack pending = %d, want 0 (the drained verdict's package acked before the NATS close)", ci.NumAckPending)
	}
}
