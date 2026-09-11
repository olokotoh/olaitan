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
