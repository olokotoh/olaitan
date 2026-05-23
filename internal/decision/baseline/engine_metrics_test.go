package baseline

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/olokotoh/olaitan/internal/correlator/trigger"
	"github.com/olokotoh/olaitan/internal/metrics"
	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/schema"
)

// TestEngine_DeviationsVecLabelledBySigmaBucket covers Story 1.18
// AC3: a deviation emission bumps olaitan_decision_baseline_deviations_total
// under the correct {metric, sigma_bucket} label tuple, with at least
// one increment in EACH of the three bucket labels.
//
// The harness uses three distinct workloads (one per target bucket) so
// Welford state updates from one driven package never bleed into the
// next workload's sigma computation. Pre-warm uses values alternating
// 15 and 25 (mean = 20, Bessel-corrected stddev about 5.085) so the
// driven unique-IP counts 37 / 50 / 80 land at sigma about 3.34 / 5.90
// / 11.80 respectively, deterministically populating "3-5", "5-10",
// and "10+".
func TestEngine_DeviationsVecLabelledBySigmaBucket(t *testing.T) {
	store, warmup := newRealStoreAndWarmup(t)

	reg := metrics.NewRegistry()
	emit := &stubEmitter{}
	cfg := Config{
		NATS:    &natsclient.Client{}, // unused in HandleForBench path
		Store:   store,
		Warmup:  warmup,
		Emitter: emit,
		Metrics: reg,
	}
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cases := []struct {
		namespace string
		pod       string
		workload  string
		dsts      int
		want      string
	}{
		{"default", "Deployment-a", "default/Deployment/a", 37, "3-5"},
		{"default", "Deployment-b", "default/Deployment/b", 50, "5-10"},
		{"default", "Deployment-c", "default/Deployment/c", 80, "10+"},
	}

	for _, tc := range cases {
		wf := &Welford{}
		for i := 0; i < 30; i++ {
			v := 15.0
			if i%2 == 0 {
				v = 25.0
			}
			wf.Update(v)
		}
		preload := map[string]*Welford{}
		for _, n := range MetricNames() {
			preload[n] = &Welford{}
		}
		preload["outbound_unique_dst_ips"] = wf
		if err := store.Save(context.Background(), tc.namespace, tc.pod, preload); err != nil {
			t.Fatalf("Save(%s): %v", tc.workload, err)
		}

		pkg := makeFlowPkg(tc.dsts)
		pkg.WorkloadID = tc.workload
		pkg.WorkloadIdentity = schema.WorkloadIdentity{
			Namespace: tc.namespace,
			OwnerKind: "Deployment",
			OwnerName: tc.pod[len("Deployment-"):],
		}
		if _, err := e.HandleForBench(context.Background(), &pkg); err != nil {
			t.Fatalf("HandleForBench(%s): %v", tc.workload, err)
		}
	}

	got35 := testutil.ToFloat64(e.deviationsVec.WithLabelValues("outbound_unique_dst_ips", "3-5"))
	got510 := testutil.ToFloat64(e.deviationsVec.WithLabelValues("outbound_unique_dst_ips", "5-10"))
	got10p := testutil.ToFloat64(e.deviationsVec.WithLabelValues("outbound_unique_dst_ips", "10+"))

	if got35 < 1 {
		t.Errorf("expected at least one deviation in the 3-5 bucket from the 37-dst spike, got %v", got35)
	}
	if got510 < 1 {
		t.Errorf("expected at least one deviation in the 5-10 bucket from the 50-dst spike, got %v", got510)
	}
	if got10p < 1 {
		t.Errorf("expected at least one deviation in the 10+ bucket from the 80-dst spike, got %v", got10p)
	}
}

// makeFlowPkg constructs a small EvidencePackage with `count` unique
// network flow events. Used to drive deviations of varying magnitude
// against a pre-warmed outbound_unique_dst_ips baseline.
func makeFlowPkg(count int) schema.EvidencePackage {
	events := make([]schema.Event, 0, count)
	for i := 0; i < count; i++ {
		ip := "10.0.0." + itoa(i+1)
		raw := []byte(`{"dst_ip":"` + ip + `"}`)
		events = append(events, schema.Event{
			ID:       "ev-" + ip,
			Source:   schema.SourceNetwork,
			Category: schema.CategoryFlow,
			Pod:      schema.PodRef{Namespace: "default", Name: "svc", UID: "u"},
			Raw:      raw,
		})
	}
	return schema.EvidencePackage{
		WorkloadID:       "default/Deployment/svc",
		WorkloadIdentity: schema.WorkloadIdentity{Namespace: "default", OwnerKind: "Deployment", OwnerName: "svc"},
		Events:           events,
		Trigger:          schema.EvidenceTrigger{Type: trigger.TypeMultiSignal},
	}
}
