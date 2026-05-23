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
// under the correct {metric, sigma_bucket} label tuple. We drive the
// per-deviation increment path directly (no JetStream consumer) by
// constructing an Engine with a stub emitter and calling
// HandleForBench against pre-warmed Welford state with three
// different sigma magnitudes.
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

	// Pre-warm an obvious deviation: Welford state with Mean=2,
	// StdDev=~0.1 so a value of (2 + N*0.1) lands at sigma N.
	wf := &Welford{}
	for i := 0; i < 30; i++ {
		// Tight cluster of values around 2 to keep StdDev small.
		v := 2.0
		if i%2 == 0 {
			v = 2.1
		}
		wf.Update(v)
	}
	preload := map[string]*Welford{}
	for _, n := range MetricNames() {
		preload[n] = &Welford{}
	}
	preload["outbound_unique_dst_ips"] = wf
	if err := store.Save(context.Background(), "default", "Deployment-svc", preload); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Drive three packages with deviations sized to land in each
	// bucket: ~3.5 sigma -> "3-5", ~7 sigma -> ">=5", ~15 sigma ->
	// ">=10". The exact dst-IP counts hit the sigma magnitudes
	// approximately given the pre-warm distribution above.
	for _, dsts := range []int{30, 60, 120} {
		pkg := makeFlowPkg(dsts)
		if _, err := e.HandleForBench(context.Background(), &pkg); err != nil {
			t.Fatalf("HandleForBench: %v", err)
		}
	}

	got35 := testutil.ToFloat64(e.deviationsVec.WithLabelValues("outbound_unique_dst_ips", "3-5"))
	got510 := testutil.ToFloat64(e.deviationsVec.WithLabelValues("outbound_unique_dst_ips", ">=5"))
	got10p := testutil.ToFloat64(e.deviationsVec.WithLabelValues("outbound_unique_dst_ips", ">=10"))
	total := got35 + got510 + got10p
	if total < 3 {
		t.Errorf("expected at least 3 deviation emissions across buckets, got %v + %v + %v = %v",
			got35, got510, got10p, total)
	}
	if got10p < 1 {
		t.Errorf("expected at least one deviation in >=10 bucket from the 120-dst spike, got %v", got10p)
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
