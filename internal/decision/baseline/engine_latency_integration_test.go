//go:build integration

package baseline_test

import (
	"context"
	"io"
	"log/slog"
	"sort"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"

	"github.com/olokotoh/olaitan/internal/decision/baseline"
	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/schema"
)

// TestIntegration_BaselineEngineLatencyBudget locks AC6: the
// per-package evaluation p99 must remain at or below 100 ms (NFR3).
// The bench drives baseline.Engine.HandleForBench against 1,000
// EvidencePackages on a 50-workload corpus of pre-warmed Welford
// state. HandleForBench is the same code path handle() runs on real
// JetStream messages (minus the msg.Ack), so the latency gate
// measures production semantics rather than a hoisted shortcut
// (Copilot C4 + Blind Hunter B11 + Story 1.15 P4+P5 closure
// precedent).
//
// The bench does not exercise the JetStream consumer because the
// inbound subscribe latency is unbounded by AC6 (NFR3 explicitly
// scopes "evaluation per EvidencePackage", not end-to-end consumer
// latency). Story 1.18 owns the consumer-side budget.
func TestIntegration_BaselineEngineLatencyBudget(t *testing.T) {
	srv := startBenchNATSServer(t)
	nc, err := natsclient.NewClient(natsclient.ClientConfig{URL: srv.ClientURL(), Name: "baseline-bench"})
	if err != nil {
		t.Fatalf("nats: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = nc.Close(ctx)
	})

	mr := startMiniredis(t)
	rc := newRedis(t, mr.Addr())
	store, _ := baseline.NewStore(rc)
	w, _ := baseline.NewWarmup(store, baseline.WarmupConfig{Duration: 30 * time.Minute})
	emit := newRecordingEmitter()

	engine, err := baseline.New(baseline.Config{
		NATS: nc, Store: store, Warmup: w, Emitter: emit,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("baseline.New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const workloads = 50
	for i := 0; i < workloads; i++ {
		pod := "Deployment-svc-" + itoa(i)
		wf := &baseline.Welford{}
		for j := 0; j < 30; j++ {
			wf.Update(2)
		}
		all := map[string]*baseline.Welford{}
		for _, n := range baseline.MetricNames() {
			all[n] = &baseline.Welford{}
		}
		all["outbound_unique_dst_ips"] = wf
		if err := store.Save(ctx, "default", pod, all); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}

	const N = 1000
	durations := make([]time.Duration, 0, N)
	for i := 0; i < N; i++ {
		pkg := packageWithFlows("pkg-bench-"+itoa(i), []string{"10.0.0." + itoa(i%256), "10.0.0." + itoa((i+1)%256)})
		pkg.WorkloadIdentity = schema.WorkloadIdentity{Namespace: "default", OwnerKind: "Deployment", OwnerName: "svc-" + itoa(i%workloads)}

		start := time.Now()
		if _, err := engine.HandleForBench(ctx, &pkg); err != nil {
			t.Fatalf("HandleForBench[%d]: %v", i, err)
		}
		durations = append(durations, time.Since(start))
	}

	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	p99 := durations[int(0.99*float64(N))]
	t.Logf("p50=%s p90=%s p99=%s",
		durations[N/2],
		durations[int(0.90*float64(N))],
		p99,
	)
	if p99 > 100*time.Millisecond {
		t.Errorf("p99 latency = %s, exceeds AC6/NFR3 100ms gate", p99)
	}
}

// startBenchNATSServer mirrors startTestNATSServer but is local to
// the bench file so it does not conflict with the helper in
// engine_integration_test.go when the integration build tag is on.
func startBenchNATSServer(t *testing.T) *natsserver.Server {
	t.Helper()
	return startTestNATSServer(t)
}
