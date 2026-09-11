package applog

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/subjects"
)

// Story 10.10: applog sidecars run inside workload pods, one process each,
// and nothing scraped them, so applog health was never observable. Each
// sidecar now publishes a heartbeat on olaitan.health.applog; the collector
// on the same node tracks them.

type recordingCorePub struct {
	mu   sync.Mutex
	subj []string
	msgs [][]byte
}

func (p *recordingCorePub) Publish(subject string, data any) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.subj = append(p.subj, subject)
	p.msgs = append(p.msgs, b)
	return nil
}

func (p *recordingCorePub) count() int { p.mu.Lock(); defer p.mu.Unlock(); return len(p.msgs) }

func TestRunHeartbeat_PublishesAtOnceThenPeriodically(t *testing.T) {
	pub := &recordingCorePub{}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	events := int64(0)
	RunHeartbeat(ctx, pub, 25*time.Millisecond, func() Heartbeat {
		events += 3
		return Heartbeat{Namespace: "shop", Pod: "api-1", Node: "n1", Container: "api", Healthy: true, Events: events}
	})
	if pub.count() < 3 {
		t.Fatalf("%d heartbeats in 120ms at a 25ms interval; the first must go out at once", pub.count())
	}
	want, _ := subjects.Health("applog")
	if pub.subj[0] != want {
		t.Errorf("subject = %q, want %q", pub.subj[0], want)
	}
	var hb Heartbeat
	if err := json.Unmarshal(pub.msgs[0], &hb); err != nil {
		t.Fatal(err)
	}
	if hb.Namespace != "shop" || hb.Pod != "api-1" || hb.Node != "n1" || !hb.Healthy || hb.Events != 3 {
		t.Errorf("heartbeat = %+v", hb)
	}
}

func heartbeatJSON(t *testing.T, hb Heartbeat) []byte {
	t.Helper()
	b, err := json.Marshal(hb)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSidecarTracker(t *testing.T) {
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	tr := NewSidecarTracker("n1", 90*time.Second)
	tr.now = func() time.Time { return now }

	if !tr.Healthy() || tr.Live() != 0 {
		t.Fatal("a node with no sidecars must read healthy with zero live (nothing is failing)")
	}
	tr.Observe(heartbeatJSON(t, Heartbeat{Namespace: "shop", Pod: "a", Node: "n1", Healthy: true, Events: 10}))
	tr.Observe(heartbeatJSON(t, Heartbeat{Namespace: "shop", Pod: "b", Node: "n1", Healthy: true, Events: 5}))
	tr.Observe(heartbeatJSON(t, Heartbeat{Namespace: "shop", Pod: "c", Node: "other-node", Healthy: false}))
	tr.Observe([]byte("not json"))
	if tr.Live() != 2 || tr.Stale() != 0 || tr.Unhealthy() != 0 || !tr.Healthy() {
		t.Errorf("live=%d stale=%d unhealthy=%d healthy=%v; another node's sidecar must be ignored",
			tr.Live(), tr.Stale(), tr.Unhealthy(), tr.Healthy())
	}
	if tr.EventsTotal() != 15 {
		t.Errorf("EventsTotal = %d, want 15", tr.EventsTotal())
	}

	// Sidecar a restarts (its counter resets) and reports 4 new events: the
	// node total must keep climbing, never go backwards.
	tr.Observe(heartbeatJSON(t, Heartbeat{Namespace: "shop", Pod: "a", Node: "n1", Healthy: true, Events: 4}))
	if tr.EventsTotal() != 19 {
		t.Errorf("after a sidecar restart EventsTotal = %d, want 19 (monotonic)", tr.EventsTotal())
	}

	// b reports itself unhealthy: the source is unhealthy.
	tr.Observe(heartbeatJSON(t, Heartbeat{Namespace: "shop", Pod: "b", Node: "n1", Healthy: false, Events: 5}))
	if tr.Unhealthy() != 1 || tr.Healthy() {
		t.Errorf("unhealthy=%d healthy=%v after a sidecar reported unhealthy", tr.Unhealthy(), tr.Healthy())
	}

	// Silence: past the stale threshold both are stale and the source is
	// unhealthy; long past it they are forgotten (the pods are gone).
	now = now.Add(2 * time.Minute)
	if tr.Stale() != 2 || tr.Live() != 0 || tr.Healthy() {
		t.Errorf("after 2m of silence: live=%d stale=%d healthy=%v", tr.Live(), tr.Stale(), tr.Healthy())
	}
	now = now.Add(15 * time.Minute)
	if tr.Stale() != 0 || tr.Live() != 0 || !tr.Healthy() {
		t.Errorf("sidecars silent for 17m must be forgotten: live=%d stale=%d healthy=%v", tr.Live(), tr.Stale(), tr.Healthy())
	}
	if tr.EventsTotal() != 19 {
		t.Errorf("forgetting a sidecar must not shrink the counter: %d", tr.EventsTotal())
	}
}
