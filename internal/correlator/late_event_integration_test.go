//go:build integration

package correlator

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/prometheus/client_golang/prometheus/testutil"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	kubefake "k8s.io/client-go/kubernetes/fake"

	"github.com/olokotoh/olaitan/internal/correlator/assembler"
	"github.com/olokotoh/olaitan/internal/decision/rules"
	rulesloader "github.com/olokotoh/olaitan/internal/decision/rules/loader"
	"github.com/olokotoh/olaitan/internal/metrics"
	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// Story 11.2b, the per-event rule path (Story 1.15 realised; an ADDITION to
// Story 1.14 D1). On the 2026-10-19 live run the S4 Goldmane flows arrived
// 15-30s after Falco/runtime/audit, into a window that had already fired, so
// under the D1 rising edge they reached no package and OLT-NET-002 never
// matched. These tests pin the addition against the REAL corpus (rules/) and
// the REAL live flows.

type lateRig struct {
	c        *Correlator
	consumer jetstream.Consumer
	engine   *rules.Engine
	ctx      context.Context
}

func repoRulesDir(t *testing.T) string {
	t.Helper()
	_, f, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	return filepath.Join(filepath.Dir(f), "..", "..", "rules")
}

// newLateRig builds a correlator over NATS with the real rules engine as its
// per-event evaluator (withEvaluator=false leaves the path off, the pre-11.2b
// behaviour). The window and assembler run on clock, so a replay is
// deterministic.
func newLateRig(t *testing.T, name string, withEvaluator bool, clock func() time.Time, objs ...k8sruntime.Object) *lateRig {
	t.Helper()
	srv := startTestNATSServer(t)
	nc, err := natsclient.NewClient(natsclient.ClientConfig{URL: srv.ClientURL(), Name: name})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = nc.Close(cctx)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	if err := natsclient.EnsureStreams(ctx, nc.JetStream(), testStreamConfigs()); err != nil {
		t.Fatal(err)
	}
	kube := kubefake.NewSimpleClientset(objs...)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	c, err := New(Config{
		NATS:                  nc,
		Kube:                  kube,
		Assembler:             assembler.New(assembler.Config{Kube: kube, Posture: fakePosture{now: clock}, MaxPackageBytes: 128 * 1024, Now: clock}),
		WindowDuration:        time.Minute,
		MultiSignalMinSources: 2,
		Log:                   log,
		MetricsRegistry:       metrics.NewRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	c.window.SetNow(clock)
	c.now = clock
	rl := rulesloader.New(repoRulesDir(t), log)
	if err := rl.Load(); err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	eng, err := rules.New(rules.Config{NATS: nc, Loader: rl, Emitter: c, Metrics: metrics.NewRegistry(), Log: log})
	if err != nil {
		t.Fatal(err)
	}
	if withEvaluator {
		c.SetEventRuleEvaluator(eng)
	}
	stream, err := nc.JetStream().Stream(ctx, "EVIDENCE")
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable: name, AckPolicy: jetstream.AckExplicitPolicy, FilterSubject: subjects.EvidencePackages,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &lateRig{c: c, consumer: consumer, engine: eng, ctx: ctx}
}

// drain returns every package published so far.
func (r *lateRig) drain(t *testing.T) []schema.EvidencePackage {
	t.Helper()
	var out []schema.EvidencePackage
	for {
		batch, err := r.consumer.Fetch(50, jetstream.FetchMaxWait(300*time.Millisecond))
		if err != nil {
			t.Fatalf("fetch: %v", err)
		}
		n := 0
		for msg := range batch.Messages() {
			n++
			var pkg schema.EvidencePackage
			if err := json.Unmarshal(msg.Data(), &pkg); err != nil {
				t.Fatalf("decode package: %v", err)
			}
			_ = msg.Ack()
			out = append(out, pkg)
		}
		if n == 0 {
			return out
		}
	}
}

func webPodEvent(id string, src schema.EventSource, ts time.Time) schema.Event {
	return schema.Event{
		ID: id, Timestamp: ts, Source: src, Category: schema.CategorySyscall, Severity: "notice", Summary: id,
		Pod: schema.PodRef{Namespace: "tenant-acme", Name: "web-bd846c7f-kx8cv", UID: "web-uid"},
	}
}

// poolFlowFrom rewrites a real S4 flow's projected destination to the S5
// stratum pool on 3333 (the shape cni.Translate projects; no real S5 flow was
// saved on the live run).
func poolFlowFrom(t *testing.T, ev schema.Event, id string) schema.Event {
	t.Helper()
	var raw map[string]any
	if err := json.Unmarshal(ev.Raw, &raw); err != nil {
		t.Fatal(err)
	}
	raw["network.dst_port"] = "3333"
	raw["network.dest_name"] = "s5-stratum-pool-9c8c7876-*"
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	ev.Raw = b
	ev.ID = id
	return ev
}

func TestIntegration_LateFlowAfterFiredWindowYieldsOneRuleMatch(t *testing.T) {
	now := time.Date(2026, 10, 19, 20, 52, 50, 0, time.UTC)
	var clockNow atomic.Value
	clockNow.Store(now)
	clock := func() time.Time { return clockNow.Load().(time.Time) }
	r := newLateRig(t, "late-flow", true, clock, s4Cluster()...)
	r.c.SetFalcoTriggerFloor("off")

	// Falco + runtime from the S4 pod: the window fires (D1 rising edge).
	for _, ev := range []schema.Event{webPodEvent("falco-1", schema.SourceFalco, now), webPodEvent("rt-1", schema.SourceRuntime, now)} {
		if _, err := r.c.AddEvent(r.ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	first := r.drain(t)
	if len(first) != 1 || first[0].Trigger.Type != "multi_signal" {
		t.Fatalf("want the one multi_signal package, got %d", len(first))
	}

	// The real S4 flow lands 25s later, stamped with its Goldmane window START.
	clockNow.Store(now.Add(25 * time.Second))
	flows := loadLiveS4Flows(t)
	late := flows[1]
	late.Timestamp = now.Add(10 * time.Second)
	if _, err := r.c.AddEvent(r.ctx, late); err != nil {
		t.Fatal(err)
	}
	got := r.drain(t)
	if len(got) != 1 {
		t.Fatalf("late flow: want exactly one package, got %d", len(got))
	}
	p := got[0]
	if p.Trigger.Type != "rule_match" || p.Trigger.Origin != schema.TriggerOriginLateEvent {
		t.Fatalf("trigger = %q origin %q, want rule_match / late_event", p.Trigger.Type, p.Trigger.Origin)
	}
	if len(p.RuleMatches) != 1 || p.RuleMatches[0].RuleID != "OLT-NET-002" || p.RuleMatches[0].EventID != late.ID {
		t.Fatalf("rule matches = %+v, want OLT-NET-002 on %s", p.RuleMatches, late.ID)
	}
	if p.WorkloadID != "tenant-acme/Deployment/web" {
		t.Fatalf("workload = %q", p.WorkloadID)
	}
	if len(p.Events) != 1 || p.Events[0].ID != late.ID {
		t.Fatalf("a late package must carry only its own event (no snapshot re-publish), got %d events", len(p.Events))
	}

	// A second identical flow (the other reporter record) in the same window:
	// no second package.
	again := flows[2]
	again.Timestamp = now.Add(15 * time.Second)
	if _, err := r.c.AddEvent(r.ctx, again); err != nil {
		t.Fatal(err)
	}
	if extra := r.drain(t); len(extra) != 0 {
		t.Fatalf("second OLT-NET-002 flow in the window published %d package(s), want 0", len(extra))
	}

	// S5: a pool flow is a different rule, so it gets its own package.
	if _, err := r.c.AddEvent(r.ctx, poolFlowFrom(t, flows[1], "pool-1")); err != nil {
		t.Fatal(err)
	}
	pool := r.drain(t)
	if len(pool) != 1 || len(pool[0].RuleMatches) != 1 || pool[0].RuleMatches[0].RuleID != "OLT-IMPACT-006" {
		t.Fatalf("pool flow: want one OLT-IMPACT-006 package, got %+v", pool)
	}
	if v := testutil.ToFloat64(r.c.metrics.lateEventRulePackages.WithLabelValues("OLT-NET-002")); v != 1 {
		t.Fatalf("late_event_rule_packages_total{OLT-NET-002} = %v, want 1", v)
	}
}

// A flow that was ALREADY inside a published multi_signal snapshot is
// evaluated by the rules engine there; a later flow of the same rule in that
// window must not add a late package (pre-claim).
func TestIntegration_SnapshotMatchedRuleIsNotRepeatedByLatePath(t *testing.T) {
	now := time.Date(2026, 10, 19, 20, 53, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	r := newLateRig(t, "late-preclaim", true, clock, s4Cluster()...)
	r.c.SetFalcoTriggerFloor("off")
	flows := loadLiveS4Flows(t)
	f0 := flows[0]
	f0.Timestamp = now
	if _, err := r.c.AddEvent(r.ctx, webPodEvent("falco-1", schema.SourceFalco, now)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.c.AddEvent(r.ctx, f0); err != nil { // second source: the rising edge, flow inside
		t.Fatal(err)
	}
	f1 := flows[1]
	f1.Timestamp = now
	if _, err := r.c.AddEvent(r.ctx, f1); err != nil {
		t.Fatal(err)
	}
	pkgs := r.drain(t)
	if len(pkgs) != 1 || pkgs[0].Trigger.Type != "multi_signal" {
		t.Fatalf("want only the multi_signal package (the rules engine matches NET-002 on it), got %d", len(pkgs))
	}
}

// S1-S3 regression: replaying the REAL S1-S3 events of the 2026-10-19 live
// run (52 Falco/runtime/audit events of tenant-acme/web) publishes the same
// packages, byte for byte, with the per-event path on as with it off.
func TestIntegration_S1S3ReplayIsUnchangedByLatePath(t *testing.T) {
	events := loadEventsFixture(t, "testdata/s1-s3-events-live-2026-10-19.jsonl")
	objs := []k8sruntime.Object{&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "tenant-acme"}}}
	for _, rs := range []string{"web-8447d48b7", "web-84f577bc9", "web-bd846c7f"} {
		objs = append(objs, &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: rs, Namespace: "tenant-acme", OwnerReferences: controllerRef("Deployment", "web")}})
	}
	for _, p := range []string{"web-8447d48b7-fzprc", "web-84f577bc9-5fdb6", "web-bd846c7f-jnfpv"} {
		rs := p[:strings.LastIndex(p, "-")]
		objs = append(objs, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: p, Namespace: "tenant-acme", GenerateName: rs + "-", OwnerReferences: controllerRef("ReplicaSet", rs)}})
	}
	replay := func(name string, on bool) []schema.EvidencePackage {
		var cur atomic.Value
		cur.Store(events[0].Timestamp)
		clock := func() time.Time { return cur.Load().(time.Time) }
		r := newLateRig(t, name, on, clock, objs...)
		for _, ev := range events {
			cur.Store(ev.Timestamp)
			_, _ = r.c.AddEvent(r.ctx, ev) // drop-and-continue like Run
		}
		return r.drain(t)
	}
	off := replay("replay-off", false)
	on := replay("replay-on", true)
	if len(off) == 0 {
		t.Fatal("replay published nothing; the fixture did not exercise the correlator")
	}
	norm := func(ps []schema.EvidencePackage) []string {
		out := make([]string, 0, len(ps))
		for _, p := range ps {
			p.PackageID = ""
			p.Trigger.FiredAt = time.Time{}
			// distinctSources iterates a map, so this order was never
			// deterministic (pre-existing; recorded as deferred).
			sort.Slice(p.Trigger.DistinctSources, func(i, j int) bool { return p.Trigger.DistinctSources[i] < p.Trigger.DistinctSources[j] })
			b, _ := json.Marshal(p)
			out = append(out, string(b))
		}
		return out
	}
	a, b := norm(off), norm(on)
	if len(a) != len(b) {
		late := 0
		for _, p := range on {
			if p.Trigger.Origin == schema.TriggerOriginLateEvent {
				late++
			}
		}
		t.Fatalf("S1-S3 replay: %d packages with the path off, %d with it on (%d late_event)", len(a), len(b), late)
	}
	for i := range a {
		if a[i] != b[i] {
			k := 0
			for k < len(a[i]) && k < len(b[i]) && a[i][k] == b[i][k] {
				k++
			}
			lo := k - 120
			if lo < 0 {
				lo = 0
			}
			t.Fatalf("S1-S3 replay package %d differs with the per-event path on at byte %d:\noff: %.300s\non:  %.300s", i, k, a[i][lo:], b[i][lo:])
		}
	}
}

func loadEventsFixture(t *testing.T, path string) []schema.Event {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var out []schema.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 256*1024), 4*1024*1024)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		var ev schema.Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatal(err)
		}
		out = append(out, ev)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}
