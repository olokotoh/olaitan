// Command olaitan-quickstart drives the ten-minute demo (Story 8.3).
//
// It injects the S1 container-escape scenario into a running Olaitan install
// and prints the detection and isolation timeline the agent produces.
//
// # WHAT THIS DEMONSTRATES, AND WHAT IT DOES NOT
//
// Falco's eBPF probe cannot load inside kind nodes: kind nodes are containers
// and eBPF is host-scoped (hack/kind-config.yaml). The quickstart therefore
// publishes the scenario's events directly onto the subjects Falco would have
// published on, exactly as tests/e2e/rs_smoke_test.go does.
//
// So this exercises correlation, scoring, the FSM and the response path
// against a real cluster with the SENSING layer simulated. It is NOT a
// demonstration of eBPF catching a container escape, and every line this
// program prints says so. If you change that wording, you are changing a
// claim, not a string.
//
// The event recipes come from internal/eval/scenario, the same single source
// of truth cmd/olaitan-eval and the e2e suite use, so the demo cannot drift
// away from what the evaluation actually measures.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	scenario "github.com/olokotoh/olaitan/internal/eval/scenario"
	"github.com/olokotoh/olaitan/internal/response/audit"
	"github.com/olokotoh/olaitan/internal/subjects"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "olaitan-quickstart: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		natsURL    = flag.String("nats-url", "nats://localhost:4222", "NATS URL; the quickstart target reaches this through a kubectl port-forward")
		scenarioID = flag.String("scenario", "s1", "scenario to inject")
		podName    = flag.String("pod", "web-quickstart", "pod name the synthetic events are attributed to")
		watch      = flag.Duration("watch", 90*time.Second, "how long to watch for state transitions after injecting")
	)
	flag.Parse()

	events := scenario.Events(*scenarioID, *podName, time.Now().UTC())
	if len(events) == 0 {
		return fmt.Errorf("no recipe events for scenario %q", *scenarioID)
	}

	nc, err := nats.Connect(*natsURL)
	if err != nil {
		return fmt.Errorf("connect to NATS at %s: %w (is the port-forward up?)", *natsURL, err)
	}
	defer nc.Close()

	js, err := jetstream.New(nc)
	if err != nil {
		return fmt.Errorf("JetStream context: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *watch+30*time.Second)
	defer cancel()

	banner(*scenarioID, *podName)

	// Start watching BEFORE injecting. A transition that fires between the
	// publish and the subscribe would otherwise be invisible, and the demo
	// would under-report what the agent actually did.
	transitions := make(chan audit.AuditTransition, 64)
	stop, err := watchTransitions(ctx, js, transitions)
	if err != nil {
		return fmt.Errorf("watch %s: %w", subjects.AuditTransitions, err)
	}
	defer stop()

	start := time.Now()
	for _, ev := range events {
		if _, err := js.Publish(ctx, ev.Subject, ev.Payload); err != nil {
			return fmt.Errorf("publish %s: %w", ev.Subject, err)
		}
	}
	fmt.Printf("  injected %d synthetic events for scenario %s\n\n", len(events), *scenarioID)
	fmt.Printf("  %-9s  %-9s %-16s %-6s %s\n", "ELAPSED", "FROM", "TO", "SCORE", "REASON")
	fmt.Printf("  %-9s  %-9s %-16s %-6s %s\n", "-------", "----", "--", "-----", "------")

	deadline := time.After(*watch)
	seen := 0
	for {
		select {
		case tr := <-transitions:
			seen++
			fmt.Printf("  %-9s  %-9s %-16s %-6.0f %s\n",
				time.Since(start).Round(100*time.Millisecond),
				tr.BeforeState, tr.AfterState, tr.TriggeringThreatScore, tr.Reason)
		case <-deadline:
			return summarise(seen, *watch)
		case <-ctx.Done():
			return summarise(seen, *watch)
		}
	}
}

// watchTransitions subscribes to the audit transitions subject and forwards
// decoded transitions. The consumer is ephemeral and ordered, mirroring the
// diagnostic consumer in the e2e suite.
func watchTransitions(ctx context.Context, js jetstream.JetStream, out chan<- audit.AuditTransition) (func(), error) {
	// A plain core-NATS subscription is enough: the quickstart only needs
	// transitions that happen while it is watching, and it starts watching
	// before it injects.
	nc := js.Conn()
	s, serr := nc.Subscribe(subjects.AuditTransitions, func(m *nats.Msg) {
		var tr audit.AuditTransition
		if err := json.Unmarshal(m.Data, &tr); err != nil {
			return
		}
		// encoding/json accepts any JSON object into this struct and leaves
		// every field at its zero value, so a message of a different shape
		// on this subject would otherwise be reported as a transition with
		// blank states. This guard is not theoretical: the first version of
		// this program decoded schema.StateTransition, whose JSON tags
		// (from_state/to_state/confidence) do NOT match the audit.transitions.v1
		// wire event (before_state/after_state/triggering_threat_score), and it
		// printed a hollow row claiming a transition had happened.
		if tr.AfterState == "" {
			return
		}
		select {
		case out <- tr:
		default:
		}
	})
	if serr != nil {
		return nil, serr
	}
	return func() { _ = s.Unsubscribe() }, nil
}

func banner(scenarioID, podName string) {
	fmt.Print(`
  Olaitan quickstart
  ==================

  IMPORTANT: this is an INJECTED scenario, not live syscall capture.

  Falco's eBPF probe cannot load inside a kind node, so the scenario's
  events are published straight onto the subjects Falco would have used.
  What you are about to watch is the correlation, scoring, state-machine
  and response path working on a real cluster. The sensing layer is
  simulated.

`)
	fmt.Printf("  scenario: %s   workload: %s\n\n", scenarioID, podName)
}

func summarise(seen int, watched time.Duration) error {
	fmt.Println()
	if seen == 0 {
		fmt.Printf(`  No state transitions in %s.

  That is a result, not necessarily a failure. Most likely causes, in
  order:

    1. The events were attributed to a pod the cluster does not have. The
       correlator resolves the pod through the apiserver and walks its
       OwnerReferences; the OLT rules require owner_kind Deployment or
       StatefulSet, so a name that resolves to nothing matches nothing.
       Pass --pod with a REAL pod name.
    2. You ran the demo twice against the same cluster. The workload is
       already SUSPICIOUS, and CLEAN -> SUSPICIOUS does not fire again.
       Start clean:
         make quickstart-clean && make quickstart
    3. The aggregator is not healthy:
         kubectl logs -l app.kubernetes.io/component=aggregator --tail=50
         kubectl get pods

  If the aggregator is in CrashLoopBackOff with "insufficient storage
  resources available", the install is missing
  nats.streamMaxBytesOverride (issue #96); use values-quickstart.yaml.
`, watched)
		return errors.New("no transitions observed")
	}
	fmt.Printf(`  %d transition(s) observed.

  Each row above is a real decision: the agent correlated the injected
  signals into an evidence package, scored it, and moved the workload.
  Enforcement was off, so no NetworkPolicy was written; on a real cluster
  with response.networkPolicy.enabled, RESTRICTED and QUARANTINED are the
  states that would have generated one.

  Next: docs/ten-values-that-matter.md
`, seen)
	return nil
}
