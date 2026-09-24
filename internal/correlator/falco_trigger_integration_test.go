//go:build integration

package correlator

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"

	"github.com/olokotoh/olaitan/internal/correlator/assembler"
	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/subjects"
)

func falcoAlert(id, pod, rule, priority string) schema.Event {
	raw, _ := json.Marshal(map[string]any{
		"rule": rule, "priority": priority, "source": "syscall",
		"tags":      []string{"T1555", "mitre_credential_access"},
		"file.path": "/etc/shadow", "process.exe": "/bin/cat",
	})
	ev := testEvent(id, pod, schema.SourceFalco, schema.CategorySyscall, "warning", rule)
	ev.Raw = raw
	return ev
}

func noPackage(t *testing.T, consumer jetstream.Consumer, why string) {
	t.Helper()
	msg, err := consumer.Next(jetstream.FetchMaxWait(700 * time.Millisecond))
	if err == nil {
		var pkg schema.EvidencePackage
		_ = json.Unmarshal(msg.Data(), &pkg)
		_ = msg.Ack()
		t.Errorf("%s: unexpected package, trigger %s %+v", why, pkg.Trigger.Type, pkg.RuleMatches)
	}
}

// Story 10.3: one sensor is enough for a serious alert. A Falco Warning on
// a real pod publishes a rule_match evidence package on its own; before,
// the default single-source install could never publish evidence.
func TestIntegration_FalcoAlertStartsAnInvestigationOnItsOwn(t *testing.T) {
	srv := startTestNATSServer(t)
	nc, err := natsclient.NewClient(natsclient.ClientConfig{URL: srv.ClientURL(), Name: "falco-trigger-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = nc.Close(ctx)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := natsclient.EnsureStreams(ctx, nc.JetStream(), testStreamConfigs()); err != nil {
		t.Fatal(err)
	}
	kube := kubefake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: "payments", UID: "web-uid"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "web-2", Namespace: "payments", UID: "web2-uid"}},
	)
	c, err := New(Config{
		NATS:                  nc,
		Kube:                  kube,
		Assembler:             assembler.New(assembler.Config{Kube: kube, Posture: fakePosture{now: time.Now}, MaxPackageBytes: 128 * 1024}),
		WindowDuration:        time.Minute,
		MultiSignalMinSources: 2,
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
		Durable: "falco-trigger-test", AckPolicy: jetstream.AckExplicitPolicy, FilterSubject: subjects.EvidencePackages,
	})
	if err != nil {
		t.Fatal(err)
	}

	pkg, err := c.AddEvent(ctx, falcoAlert("ev-1", "web-1", "Read sensitive file untrusted", "WARNING"))
	if err != nil {
		t.Fatalf("AddEvent: %v", err)
	}
	if pkg == nil {
		t.Fatal("a Falco Warning on a pod published no evidence package")
	}
	got := nextPackage(t, consumer)
	if got.Trigger.Type != "rule_match" || len(got.RuleMatches) != 1 {
		t.Fatalf("package trigger %q with %d rule matches", got.Trigger.Type, len(got.RuleMatches))
	}
	rm := got.RuleMatches[0]
	if rm.RuleID != "falco:Read sensitive file untrusted" || rm.Severity != "50" || rm.EventID != "ev-1" {
		t.Errorf("rule match = %+v", rm)
	}
	if len(got.Events) == 0 {
		t.Error("the package does not carry the triggering event")
	}

	// The same rule on the same workload inside the window is one
	// investigation, not one per syscall.
	if _, err := c.AddEvent(ctx, falcoAlert("ev-2", "web-1", "Read sensitive file untrusted", "WARNING")); err != nil {
		t.Fatal(err)
	}
	noPackage(t, consumer, "repeat of the same rule inside the window")

	// A different rule on the same workload is a new finding.
	if _, err := c.AddEvent(ctx, falcoAlert("ev-3", "web-1", "Search Private Keys or Passwords", "WARNING")); err != nil {
		t.Fatal(err)
	}
	if p := nextPackage(t, consumer); p.RuleMatches[0].RuleName != "Search Private Keys or Passwords" {
		t.Errorf("second rule package = %+v", p.RuleMatches)
	}

	// Below the floor: nothing.
	if _, err := c.AddEvent(ctx, falcoAlert("ev-4", "web-2", "Terminal shell in container", "NOTICE")); err != nil {
		t.Fatal(err)
	}
	noPackage(t, consumer, "Notice alert")

	// Excluded namespaces never open an investigation, whatever Falco
	// says: Olaitan must not score (or, with enforcement on, isolate) its
	// own pods or kube-system. Seen live on kind before this guard: the
	// collector and aggregator went SUSPICIOUS at their own startup.
	c.SetExcludedNamespaces([]string{"payments"})
	if _, err := c.AddEvent(ctx, falcoAlert("ev-x", "web-1", "Drop and execute new binary in container", "CRITICAL")); err != nil {
		t.Fatal(err)
	}
	noPackage(t, consumer, "alert in an excluded namespace")
	c.SetExcludedNamespaces(nil)

	// Switched off at runtime: nothing.
	c.SetFalcoTriggerFloor("off")
	if _, err := c.AddEvent(ctx, falcoAlert("ev-5", "web-2", "Read sensitive file untrusted", "CRITICAL")); err != nil {
		t.Fatal(err)
	}
	noPackage(t, consumer, "trigger switched off")
}

// Story 10.3 AC3: events with no Kubernetes pod (host processes, non-k8s
// containers) are dropped and counted, not logged as a WARN per event.
func TestAddEvent_HostEventsAreDroppedAndCounted(t *testing.T) {
	srv := startTestNATSServer(t)
	nc, err := natsclient.NewClient(natsclient.ClientConfig{URL: srv.ClientURL(), Name: "host-event-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = nc.Close(ctx)
	})
	c, err := New(Config{NATS: nc, Assembler: assembler.New(assembler.Config{MaxPackageBytes: 128 * 1024}), Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	host := falcoAlert("host-1", "", "Read sensitive file untrusted", "WARNING")
	host.Pod = schema.PodRef{Node: "node-1"}
	pkg, err := c.AddEvent(context.Background(), host)
	if err != nil || pkg != nil {
		t.Errorf("host event: pkg=%v err=%v, want dropped quietly", pkg, err)
	}
	if c.HostEventsDropped() != 1 {
		t.Errorf("HostEventsDropped = %d, want 1", c.HostEventsDropped())
	}
}

// newScoringTestCorrelator wires a correlator to a fresh NATS server with a
// durable EVIDENCE consumer, for the Story 10.6 namespace tests.
func newScoringTestCorrelator(t *testing.T, name string, cfg Config) (*Correlator, jetstream.Consumer, context.Context) {
	t.Helper()
	srv := startTestNATSServer(t)
	nc, err := natsclient.NewClient(natsclient.ClientConfig{URL: srv.ClientURL(), Name: name})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = nc.Close(ctx)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	if err := natsclient.EnsureStreams(ctx, nc.JetStream(), testStreamConfigs()); err != nil {
		t.Fatal(err)
	}
	kube := kubefake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: "payments", UID: "web-uid"}},
	)
	cfg.NATS = nc
	cfg.Kube = kube
	cfg.Assembler = assembler.New(assembler.Config{Kube: kube, Posture: fakePosture{now: time.Now}, MaxPackageBytes: 128 * 1024})
	cfg.WindowDuration = time.Minute
	cfg.MultiSignalMinSources = 2
	cfg.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
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
	return c, consumer, ctx
}

// Story 10.6: a never-scored namespace (Olaitan's own) opens no
// investigation by ANY path, not only the single-alert Falco trigger. On
// kind-full the release lives in `default`, and its own aggregator and
// Ollama crossed the multi-signal threshold at startup; the rule and
// baseline engines then raised FR19 chains on those packages, which queued
// ahead of a real attack. Dropping the events at the correlator means no
// package, so neither engine ever sees the workload.
func TestIntegration_NeverScoredNamespaceOpensNoPackageByAnyPath(t *testing.T) {
	c, consumer, ctx := newScoringTestCorrelator(t, "never-scored-ns-test", Config{NeverScoredNamespaces: []string{"payments"}})

	// Two distinct sources on one workload (the multi-signal rising edge),
	// then a Critical Falco alert (the single-alert trigger).
	for _, ev := range []schema.Event{
		testEvent("ex-1", "web-1", schema.SourceAudit, schema.CategoryAudit, "info", "get pod"),
		testEvent("ex-2", "web-1", schema.SourceNetwork, schema.CategoryFlow, "info", "flow"),
		falcoAlert("ex-3", "web-1", "Drop and execute new binary in container", "CRITICAL"),
	} {
		pkg, err := c.AddEvent(ctx, ev)
		if err != nil {
			t.Fatalf("AddEvent %s: %v", ev.ID, err)
		}
		if pkg != nil {
			t.Fatalf("AddEvent %s returned a %s package for a never-scored namespace", ev.ID, pkg.Trigger.Type)
		}
	}
	noPackage(t, consumer, "multi-signal and Falco in a never-scored namespace")
	if got := c.NeverScoredEventsDropped(); got != 3 {
		t.Errorf("NeverScoredEventsDropped = %d, want 3", got)
	}

	// Lift it (hot reload): the same two sources now correlate.
	c.SetNeverScoredNamespaces(nil)
	for _, ev := range []schema.Event{
		testEvent("ok-1", "web-1", schema.SourceAudit, schema.CategoryAudit, "info", "get pod"),
		testEvent("ok-2", "web-1", schema.SourceNetwork, schema.CategoryFlow, "info", "flow"),
	} {
		if _, err := c.AddEvent(ctx, ev); err != nil {
			t.Fatalf("AddEvent %s: %v", ev.ID, err)
		}
	}
	if p := nextPackage(t, consumer); p.Trigger.Type != "multi_signal" {
		t.Errorf("after lifting it: trigger %q, want multi_signal", p.Trigger.Type)
	}
}

// Story 10.6 review (D3): response.excluded_namespaces (kube-system by
// default) means NEVER ENFORCED, not never scored. A compromised
// kube-system workload must still be correlated: its multi-signal package
// is published, as before Story 10.6; only the single-alert Falco trigger
// stays off there (Story 10.3), and the response ring never isolates it.
func TestIntegration_ExcludedNamespaceIsStillScored(t *testing.T) {
	c, consumer, ctx := newScoringTestCorrelator(t, "excluded-ns-test", Config{ExcludedNamespaces: []string{"payments"}})

	if _, err := c.AddEvent(ctx, falcoAlert("fx-1", "web-1", "Drop and execute new binary in container", "CRITICAL")); err != nil {
		t.Fatal(err)
	}
	noPackage(t, consumer, "single Falco alert in an excluded namespace")

	for _, ev := range []schema.Event{
		testEvent("mx-1", "web-1", schema.SourceAudit, schema.CategoryAudit, "info", "get pod"),
	} {
		if _, err := c.AddEvent(ctx, ev); err != nil {
			t.Fatalf("AddEvent %s: %v", ev.ID, err)
		}
	}
	if p := nextPackage(t, consumer); p.Trigger.Type != "multi_signal" {
		t.Errorf("excluded namespace: trigger %q, want multi_signal (still scored)", p.Trigger.Type)
	}
	if got := c.NeverScoredEventsDropped(); got != 0 {
		t.Errorf("NeverScoredEventsDropped = %d, want 0 for an excluded (never-enforced) namespace", got)
	}
}
