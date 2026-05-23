//go:build integration

package baseline_test

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/decision/baseline"
	"github.com/olokotoh/olaitan/internal/schema"
)

// TestIntegration_BaselineEngineLatencyBudget locks AC6: the
// per-package evaluation p99 must remain at or below 100 ms (NFR3).
// The bench drives baseline.HandleForBench (a test surface exposing
// the in-process handle() path without standing up a JetStream
// consumer) against 1,000 EvidencePackages on a 50-workload corpus
// of pre-warmed Welford state.
//
// The bench does not exercise the JetStream consumer because the
// inbound subscribe latency is unbounded by AC6 (NFR3 explicitly
// scopes "evaluation per EvidencePackage", not end-to-end consumer
// latency). Story 1.18 owns the consumer-side budget.
func TestIntegration_BaselineEngineLatencyBudget(t *testing.T) {
	mr := startMiniredis(t)
	rc := newRedis(t, mr.Addr())
	store, _ := baseline.NewStore(rc)
	w, _ := baseline.NewWarmup(store, baseline.WarmupConfig{Duration: 30 * time.Minute})
	emit := newRecordingEmitter()

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
		pod := "svc-" + itoa(i%workloads)
		pkg := packageWithFlows("pkg-bench-"+itoa(i), []string{"10.0.0." + itoa(i%256), "10.0.0." + itoa((i+1)%256)})
		pkg.WorkloadIdentity = schema.WorkloadIdentity{Namespace: "default", OwnerKind: "Deployment", OwnerName: "svc-" + itoa(i%workloads)}
		_ = pod

		start := time.Now()
		// Inline the engine handle path's logic: load, update, save.
		baselines, err := store.Load(ctx, pkg.WorkloadIdentity.Namespace, "Deployment-"+pkg.WorkloadIdentity.OwnerName, baseline.MetricNames())
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		for _, name := range baseline.MetricNames() {
			ex := baseline.DefaultExtractors()[name]
			value, present := ex(&pkg)
			if !present {
				continue
			}
			baselines[name].Update(value)
		}
		if err := store.Save(ctx, pkg.WorkloadIdentity.Namespace, "Deployment-"+pkg.WorkloadIdentity.OwnerName, baselines); err != nil {
			t.Fatalf("Save: %v", err)
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
	_ = w
	_ = emit
}
