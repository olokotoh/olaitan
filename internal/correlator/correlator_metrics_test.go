//go:build integration

package correlator

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"

	"github.com/olokotoh/olaitan/internal/correlator/assembler"
	"github.com/olokotoh/olaitan/internal/metrics"
	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// TestIntegration_CorrelatorMetricsExposeAllThreeFamilies covers
// Story 1.18 AC1 end-to-end: with a real metrics registry attached
// via Config.MetricsRegistry, driving multi-signal + rule_match
// triggers through the correlator surfaces the three new metric
// families on the Prometheus registry, and an oversize package
// bumps the overflow counter.
func TestIntegration_CorrelatorMetricsExposeAllThreeFamilies(t *testing.T) {
	srv := startTestNATSServer(t)
	nc, err := natsclient.NewClient(natsclient.ClientConfig{URL: srv.ClientURL(), Name: "correlator-metrics-test"})
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
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "rule-pod", Namespace: "payments", UID: "rule-uid"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "huge-pod", Namespace: "payments", UID: "huge-uid"}},
	)
	asm := assembler.New(assembler.Config{Kube: kube, Posture: fakePosture{now: time.Now}, MaxPackageBytes: 128 * 1024})
	reg := metrics.NewRegistry()
	c, err := New(Config{
		NATS:                  nc,
		Kube:                  kube,
		Assembler:             asm,
		WindowDuration:        time.Minute,
		MultiSignalMinSources: 2,
		Log:                   slog.New(slog.NewTextHandler(io.Discard, nil)),
		MetricsRegistry:       reg,
	})
	if err != nil {
		t.Fatalf("correlator New: %v", err)
	}
	if c.metrics.evidencePackages == nil {
		t.Fatalf("metrics.evidencePackages handle is nil after construction with non-nil registry")
	}

	stream, err := nc.JetStream().Stream(ctx, "EVIDENCE")
	if err != nil {
		t.Fatalf("evidence stream: %v", err)
	}
	consumer, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       "correlator-metrics-test",
		AckPolicy:     jetstream.AckExplicitPolicy,
		FilterSubject: subjects.EvidencePackages,
	})
	if err != nil {
		t.Fatalf("evidence consumer: %v", err)
	}

	// Fire a rule_match trigger -- simplest path that always produces
	// one publish, regardless of window state.
	ruleID := "payments/Pod/rule-pod"
	if _, err := c.FireRuleMatch(ctx, ruleID, schema.RuleMatch{RuleID: "OLT-1", RuleName: "test", Severity: "high", EventID: "rule-ev"}); err != nil {
		t.Fatalf("FireRuleMatch: %v", err)
	}
	pkg := nextPackage(t, consumer)
	if pkg.Trigger.Type != "rule_match" {
		t.Fatalf("trigger type = %q, want rule_match", pkg.Trigger.Type)
	}

	// evidence_packages_total{trigger_type=rule_match} should now be 1.
	if got := testutil.ToFloat64(c.metrics.evidencePackages.WithLabelValues("rule_match")); got < 1 {
		t.Errorf("evidence_packages_total{rule_match} = %v, want >= 1", got)
	}

	// window_size_bytes should have observed at least one sample. The
	// histogram surfaces in Gather() once sampled.
	mfs, err := reg.Gatherer().Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	var sawWindow, sawOverflow bool
	for _, mf := range mfs {
		switch mf.GetName() {
		case "olaitan_correlator_window_size_bytes":
			sawWindow = true
		case "olaitan_correlator_overflow_summarised_total":
			sawOverflow = true
		}
	}
	if !sawWindow {
		t.Errorf("window_size_bytes histogram did not surface after publish")
	}
	if !sawOverflow {
		t.Errorf("overflow_summarised_total counter did not register")
	}

	// Now fire an oversized rule_match against huge-pod so the
	// assembler triggers cap-enforcement and pkg.Overflow != nil.
	hugeID := "payments/Pod/huge-pod"
	huge := testEvent("huge-ev", "huge-pod", schema.SourceFalco, schema.CategorySyscall, "critical", strings.Repeat("s ", 1000))
	huge.Raw = json.RawMessage(`{"payload":"` + strings.Repeat("x", 300000) + `"}`)
	if _, err := c.AddEvent(ctx, huge); err != nil {
		t.Fatalf("AddEvent huge: %v", err)
	}
	if _, err := c.FireRuleMatch(ctx, hugeID, schema.RuleMatch{RuleID: "OLT-HUGE", RuleName: "huge", Severity: "critical", EventID: "huge-ev"}); err != nil {
		t.Fatalf("FireRuleMatch huge: %v", err)
	}
	capped := nextPackage(t, consumer)
	if capped.Overflow == nil {
		t.Fatalf("expected overflow on capped package")
	}

	if got := c.overflowSummarisedCount.Load(); got < 1 {
		t.Errorf("overflowSummarisedCount = %d, want >= 1", got)
	}
}
