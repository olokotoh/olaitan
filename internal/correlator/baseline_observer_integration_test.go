//go:build integration

package correlator

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/nats-io/nats.go/jetstream"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"

	"github.com/olokotoh/olaitan/internal/correlator/assembler"
	"github.com/olokotoh/olaitan/internal/correlator/trigger"
	"github.com/olokotoh/olaitan/internal/decision/baseline"
	natsclient "github.com/olokotoh/olaitan/internal/nats"
	redisclient "github.com/olokotoh/olaitan/internal/redis"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// clockedObserver hands each attributed event straight to the engine on
// a virtual clock, so a 45-minute replay runs in milliseconds. In
// production the engine's own Run loop does the same from its queue.
type clockedObserver struct {
	e   *baseline.Engine
	now *time.Time
}

func (o clockedObserver) ObserveEvent(workloadID string, identity schema.WorkloadIdentity, ev schema.Event) {
	ev.Timestamp = *o.now
	o.e.Ingest(context.Background(), baseline.Observation{WorkloadID: workloadID, Identity: identity, Event: ev}, *o.now)
}

// Story 10.12, end to end in process: real event shapes from the
// 2026-10-19 run go through the correlator's identity resolution (a
// Deployment-owned pod, and its Goldmane aggregate), into the baseline
// engine, and a real 80-call API burst after 45 benign minutes is
// published on EVIDENCE as a baseline_deviation package carrying the
// metric and sigma.
func TestIntegration_CorrelatorFeedsBaselineAndPublishesDeviation(t *testing.T) {
	srv := startTestNATSServer(t)
	nc, err := natsclient.NewClient(natsclient.ClientConfig{URL: srv.ClientURL(), Name: "baseline-observer-test"})
	if err != nil {
		t.Fatalf("nats client: %v", err)
	}
	t.Cleanup(func() { _ = nc.Close(context.Background()) })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := natsclient.EnsureStreams(ctx, nc.JetStream(), testStreamConfigs()); err != nil {
		t.Fatalf("ensure streams: %v", err)
	}

	isController := true
	kube := kubefake.NewSimpleClientset()
	for _, o := range []any{
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "steady", Namespace: "olt-baseline", UID: "d"}},
		&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "steady-7d8fc54b55", Namespace: "olt-baseline", UID: "r",
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "steady", UID: "d", Controller: &isController}}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "steady-7d8fc54b55-n4psz", Namespace: "olt-baseline", UID: "p", GenerateName: "steady-7d8fc54b55-",
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "steady-7d8fc54b55", UID: "r", Controller: &isController}}}},
	} {
		switch v := o.(type) {
		case *appsv1.Deployment:
			_ = kube.Tracker().Add(v)
		case *appsv1.ReplicaSet:
			_ = kube.Tracker().Add(v)
		case *corev1.Pod:
			_ = kube.Tracker().Add(v)
		}
	}
	asm := assembler.New(assembler.Config{Kube: kube, Posture: fakePosture{now: time.Now}, MaxPackageBytes: 128 * 1024})
	c, err := New(Config{NATS: nc, Kube: kube, Assembler: asm, WindowDuration: 10 * time.Minute, MultiSignalMinSources: 2,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), NeverScoredNamespaces: []string{"default"}})
	if err != nil {
		t.Fatalf("correlator New: %v", err)
	}

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	rcfg := redisclient.DefaultConfig()
	rcfg.Addr = mr.Addr()
	rc, err := redisclient.NewClient(rcfg)
	if err != nil {
		t.Fatal(err)
	}
	store, _ := baseline.NewStore(rc)
	warm, _ := baseline.NewWarmup(store, baseline.WarmupConfig{Duration: 30 * time.Minute})
	clock := time.Date(2026, 10, 19, 20, 51, 0, 0, time.UTC)
	warm.SetNow(func() time.Time { return clock })
	eng, err := baseline.New(baseline.Config{Store: store, Warmup: warm, Emitter: c, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), OwnNamespaces: []string{"default"}})
	if err != nil {
		t.Fatalf("baseline New: %v", err)
	}
	c.SetEventObserver(clockedObserver{e: eng, now: &clock})

	fx := loadBaselineFixtures(t)
	get := func(i int) schema.Event {
		ev := fx["audit_operator_exec"]
		ev.ID = fmt.Sprintf("get-%d", i)
		return ev
	}
	flow := fx["cni_flow_src"]
	seq := 0
	t0 := clock
	for cycle := 0; cycle < 15; cycle++ {
		clock = t0.Add(time.Duration(cycle)*3*time.Minute + 18*time.Second)
		for i := 0; i < 1+cycle%3; i++ {
			seq++
			if _, err := c.AddEvent(ctx, get(seq)); err != nil {
				t.Fatalf("AddEvent: %v", err)
			}
		}
		f := flow
		f.ID = fmt.Sprintf("flow-%d", cycle)
		if _, err := c.AddEvent(ctx, f); err != nil {
			t.Fatalf("AddEvent(flow from the Goldmane aggregate): %v", err)
		}
		for s := 5 * time.Second; s < 3*time.Minute; s += 5 * time.Second {
			clock = clock.Add(5 * time.Second)
			eng.Tick(ctx, clock)
		}
	}
	burst := t0.Add(45*time.Minute + 18*time.Second)
	clock = burst
	for i := 0; i < 80; i++ {
		seq++
		if _, err := c.AddEvent(ctx, get(seq)); err != nil {
			t.Fatalf("AddEvent: %v", err)
		}
	}
	clock = burst.Add(time.Minute)
	eng.Tick(ctx, clock)

	stream, err := nc.JetStream().Stream(ctx, "EVIDENCE")
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{Durable: "t", AckPolicy: jetstream.AckExplicitPolicy, FilterSubject: subjects.EvidencePackages, DeliverPolicy: jetstream.DeliverAllPolicy})
	if err != nil {
		t.Fatal(err)
	}
	var devs []schema.BaselineDeviation
	for {
		msg, err := consumer.Next(jetstream.FetchMaxWait(time.Second))
		if err != nil {
			break
		}
		_ = msg.Ack()
		var pkg schema.EvidencePackage
		if err := json.Unmarshal(msg.Data(), &pkg); err != nil {
			t.Fatal(err)
		}
		if pkg.Trigger.Type == trigger.TypeBaselineDeviation && pkg.Trigger.BaselineDeviation != nil {
			if pkg.WorkloadID != "olt-baseline/Deployment/steady" {
				t.Fatalf("deviation package for %q, want olt-baseline/Deployment/steady", pkg.WorkloadID)
			}
			devs = append(devs, *pkg.Trigger.BaselineDeviation)
		}
	}
	if len(devs) != 1 || devs[0].Metric != baseline.MetricAuditEventsPerMin || devs[0].Value != 80 || devs[0].Sigma < 3 {
		t.Fatalf("baseline_deviation packages = %+v, want exactly one audit_events_per_min with value 80 and sigma >= 3", devs)
	}
}

// loadBaselineFixtures reads the real 2026-10-19 event fixtures shared
// with the baseline package.
func loadBaselineFixtures(t *testing.T) map[string]schema.Event {
	t.Helper()
	b, err := os.ReadFile("../decision/baseline/testdata/real-events-2026-10-19.json")
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	out := map[string]schema.Event{}
	for _, k := range []string{"audit_operator_exec", "falco_k8s_api_wget"} {
		var ev schema.Event
		if err := json.Unmarshal(raw[k], &ev); err != nil {
			t.Fatal(err)
		}
		out[k] = ev
	}
	var flows []schema.Event
	if err := json.Unmarshal(raw["cni_flows_s4"], &flows); err != nil {
		t.Fatal(err)
	}
	// The S4 flow's source is tenant-acme/web; re-home the Src report on
	// the steady workload's Goldmane aggregate.
	var f schema.Event
	for _, fl := range flows {
		for _, tag := range fl.Tags {
			if tag == "reporter:src" {
				f = fl
			}
		}
	}
	if f.ID == "" {
		t.Fatal("no Src-reported flow in the fixture")
	}
	f.Pod = schema.PodRef{Namespace: "olt-baseline", Name: "steady-7d8fc54b55-*", Node: f.Pod.Node}
	out["cni_flow_src"] = f
	return out
}
