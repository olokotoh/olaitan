//go:build integration

package correlator

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go/jetstream"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubefake "k8s.io/client-go/kubernetes/fake"

	"github.com/olokotoh/olaitan/internal/collector/posture"
	"github.com/olokotoh/olaitan/internal/correlator/assembler"
	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/subjects"
)

func TestIntegration_CorrelatorPublishesEvidenceForAllTriggersAndCap(t *testing.T) {
	srv := startTestNATSServer(t)
	nc, err := natsclient.NewClient(natsclient.ClientConfig{URL: srv.ClientURL(), Name: "correlator-test"})
	if err != nil {
		t.Fatalf("nats client: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = nc.Close(ctx)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := natsclient.EnsureStreams(ctx, nc.JetStream(), testStreamConfigs()); err != nil {
		t.Fatalf("ensure streams: %v", err)
	}

	kube := kubefake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "api-pod", Namespace: "payments", UID: "pod-uid"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "rule-pod", Namespace: "payments", UID: "rule-uid"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "base-pod", Namespace: "payments", UID: "base-uid"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "huge-pod", Namespace: "payments", UID: "huge-uid"}},
	)
	posture := fakePosture{now: time.Now}
	asm := assembler.New(assembler.Config{Kube: kube, Posture: posture, MaxPackageBytes: 128 * 1024})
	c, err := New(Config{
		NATS:                  nc,
		Kube:                  kube,
		Assembler:             asm,
		WindowDuration:        time.Minute,
		MultiSignalMinSources: 2,
		Log:                   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("correlator New: %v", err)
	}

	stream, err := nc.JetStream().Stream(ctx, "EVIDENCE")
	if err != nil {
		t.Fatalf("evidence stream: %v", err)
	}
	consumer, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       "correlator-evidence-test",
		AckPolicy:     jetstream.AckExplicitPolicy,
		FilterSubject: subjects.EvidencePackages,
	})
	if err != nil {
		t.Fatalf("evidence consumer: %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	t.Cleanup(runCancel)
	errCh := make(chan error, 1)
	go func() { errCh <- c.Run(runCtx) }()

	publishRaw(t, ctx, nc, subjects.RawAudit, testEvent("audit-1", "api-pod", schema.SourceAudit, schema.CategoryAudit, "warning", "audit"))
	publishRaw(t, ctx, nc, subjects.RawFalco, testEvent("falco-1", "api-pod", schema.SourceFalco, schema.CategorySyscall, "critical", "falco"))
	multi := nextPackage(t, consumer)
	if multi.Trigger.Type != "multi_signal" {
		t.Fatalf("multi trigger type: got %q", multi.Trigger.Type)
	}

	ruleID := "payments/Pod/rule-pod"
	if _, err := c.AddEvent(ctx, testEvent("rule-event", "rule-pod", schema.SourceRuntime, schema.CategoryLifecycle, "warning", "runtime")); err != nil {
		t.Fatalf("add rule event: %v", err)
	}
	if _, err := c.FireRuleMatch(ctx, ruleID, schema.RuleMatch{RuleID: "OLT-1", RuleName: "test rule", Severity: "high", EventID: "rule-event"}); err != nil {
		t.Fatalf("FireRuleMatch: %v", err)
	}
	rule := nextPackage(t, consumer)
	if rule.Trigger.Type != "rule_match" || len(rule.RuleMatches) != 1 {
		t.Fatalf("rule package: %+v", rule.Trigger)
	}

	baseID := "payments/Pod/base-pod"
	if _, err := c.AddEvent(ctx, testEvent("base-event", "base-pod", schema.SourceRuntime, schema.CategoryLifecycle, "warning", "runtime")); err != nil {
		t.Fatalf("add baseline event: %v", err)
	}
	if _, err := c.FireBaselineDeviation(ctx, baseID, schema.BaselineDeviation{Metric: "exec_rate", Value: 9, Mean: 1, StdDev: 2, Sigma: 4, PodUID: "base-uid"}); err != nil {
		t.Fatalf("FireBaselineDeviation: %v", err)
	}
	baseline := nextPackage(t, consumer)
	if baseline.Trigger.Type != "baseline_deviation" || len(baseline.BaselineDeviations) != 1 {
		t.Fatalf("baseline package: %+v", baseline.Trigger)
	}

	hugeID := "payments/Pod/huge-pod"
	huge := testEvent("huge-event", "huge-pod", schema.SourceFalco, schema.CategorySyscall, "critical", strings.Repeat("summary ", 1000))
	huge.Raw = json.RawMessage(`{"payload":"` + strings.Repeat("x", 300000) + `"}`)
	if _, err := c.AddEvent(ctx, huge); err != nil {
		t.Fatalf("add huge event: %v", err)
	}
	if _, err := c.FireRuleMatch(ctx, hugeID, schema.RuleMatch{RuleID: "OLT-HUGE", RuleName: "huge", Severity: "critical", EventID: "huge-event"}); err != nil {
		t.Fatalf("FireRuleMatch huge: %v", err)
	}
	capped := nextPackage(t, consumer)
	body, err := json.Marshal(capped)
	if err != nil {
		t.Fatalf("marshal capped: %v", err)
	}
	if len(body) > 128*1024 {
		t.Fatalf("capped package bytes = %d, want <= 131072", len(body))
	}
	if capped.Overflow == nil {
		t.Fatalf("expected overflow summary in capped package")
	}

	runCancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Run did not stop")
	}
}

func TestIntegration_CorrelatorTriggerToPublishLatencyBudget(t *testing.T) {
	srv := startTestNATSServer(t)
	nc, err := natsclient.NewClient(natsclient.ClientConfig{URL: srv.ClientURL(), Name: "correlator-latency-test"})
	if err != nil {
		t.Fatalf("nats client: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = nc.Close(ctx)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := natsclient.EnsureStreams(ctx, nc.JetStream(), testStreamConfigs()); err != nil {
		t.Fatalf("ensure streams: %v", err)
	}

	const samples = 40
	pods := make([]runtime.Object, 0, samples)
	for i := 0; i < samples; i++ {
		pods = append(pods, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "lat-pod-" + strconv.Itoa(i), Namespace: "payments"}})
	}
	kube := kubefake.NewSimpleClientset(pods...)
	windowDuration := time.Second
	c, err := New(Config{
		NATS:                  nc,
		Kube:                  kube,
		Assembler:             assembler.New(assembler.Config{Kube: kube, Posture: fakePosture{now: time.Now}, MaxPackageBytes: 128 * 1024}),
		WindowDuration:        windowDuration,
		MultiSignalMinSources: 2,
		Log:                   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("correlator New: %v", err)
	}

	stream, err := nc.JetStream().Stream(ctx, "EVIDENCE")
	if err != nil {
		t.Fatalf("evidence stream: %v", err)
	}
	consumer, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       "correlator-latency-test",
		AckPolicy:     jetstream.AckExplicitPolicy,
		FilterSubject: subjects.EvidencePackages,
	})
	if err != nil {
		t.Fatalf("consumer: %v", err)
	}

	durations := make([]time.Duration, 0, samples)
	for i := 0; i < samples; i++ {
		pod := "lat-pod-" + strconv.Itoa(i)
		workloadID := "payments/Pod/" + pod
		if _, err := c.AddEvent(ctx, testEvent("lat-event-"+strconv.Itoa(i), pod, schema.SourceFalco, schema.CategorySyscall, "warning", "latency")); err != nil {
			t.Fatalf("AddEvent %d: %v", i, err)
		}
		start := time.Now()
		if _, err := c.FireRuleMatch(ctx, workloadID, schema.RuleMatch{RuleID: "OLT-LAT", Severity: "high", EventID: "lat-event-" + strconv.Itoa(i)}); err != nil {
			t.Fatalf("FireRuleMatch %d: %v", i, err)
		}
		_ = nextPackage(t, consumer)
		durations = append(durations, time.Since(start))
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	p99 := durations[int(float64(len(durations)-1)*0.99)]
	if p99 > windowDuration+100*time.Millisecond {
		t.Fatalf("trigger-to-publish p99 = %s, want <= %s", p99, windowDuration+100*time.Millisecond)
	}
}

func startTestNATSServer(t *testing.T) *natsserver.Server {
	t.Helper()
	opts := &natsserver.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir(), NoLog: true, NoSigs: true}
	srv, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatalf("new nats server: %v", err)
	}
	srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatalf("nats server not ready")
	}
	t.Cleanup(srv.Shutdown)
	return srv
}

func testStreamConfigs() []jetstream.StreamConfig {
	return []jetstream.StreamConfig{
		{Name: "EVENTS_RAW", Subjects: []string{subjects.RawPrefix + ">"}, MaxAge: time.Hour, MaxBytes: 16 * 1024 * 1024, MaxMsgSize: 512 * 1024, Storage: jetstream.MemoryStorage, Retention: jetstream.LimitsPolicy},
		{Name: "EVIDENCE", Subjects: []string{subjects.EvidencePrefix + ">"}, MaxAge: time.Hour, MaxBytes: 16 * 1024 * 1024, Storage: jetstream.MemoryStorage, Retention: jetstream.LimitsPolicy},
	}
}

func publishRaw(t *testing.T, ctx context.Context, nc *natsclient.Client, subject string, ev schema.Event) {
	t.Helper()
	if _, err := nc.PublishJS(ctx, subject, ev, jetstream.WithMsgID(ev.ID)); err != nil {
		t.Fatalf("publish %s: %v", subject, err)
	}
}

func nextPackage(t *testing.T, consumer jetstream.Consumer) schema.EvidencePackage {
	t.Helper()
	msg, err := consumer.Next(jetstream.FetchMaxWait(3 * time.Second))
	if err != nil {
		t.Fatalf("next evidence package: %v", err)
	}
	defer func() { _ = msg.Ack() }()
	var pkg schema.EvidencePackage
	if err := json.Unmarshal(msg.Data(), &pkg); err != nil {
		t.Fatalf("unmarshal package: %v", err)
	}
	return pkg
}

func testEvent(id, pod string, source schema.EventSource, category schema.EventCategory, severity, summary string) schema.Event {
	return schema.Event{
		ID:        id,
		Timestamp: time.Now().UTC(),
		Source:    source,
		Pod:       schema.PodRef{Name: pod, Namespace: "payments", UID: pod + "-uid"},
		Severity:  severity,
		Category:  category,
		Summary:   summary,
	}
}

type fakePosture struct {
	now func() time.Time
}

func (f fakePosture) Get(_ context.Context, pod *corev1.Pod, _ ...posture.Option) (*schema.WorkloadPosture, error) {
	return &schema.WorkloadPosture{
		Identity:   schema.WorkloadIdentity{Namespace: pod.Namespace, OwnerKind: "Pod", OwnerName: pod.Name, PodName: pod.Name},
		OrphanPod:  true,
		CapturedAt: f.now(),
	}, nil
}
