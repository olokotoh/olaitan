package applog

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/subjects"
)

// Story 10.10: applog sidecars run inside workload pods, one process each,
// and nothing scraped them, so applog health was never observable. Each
// sidecar now publishes a heartbeat on its node's health subject; the
// collector on the same node tracks them.

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

func (p *recordingCorePub) at(t *testing.T, i int) Heartbeat {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	var hb Heartbeat
	if err := json.Unmarshal(p.msgs[i], &hb); err != nil {
		t.Fatal(err)
	}
	return hb
}

// The first heartbeat must go out immediately, not one interval later: a
// sidecar that starts and dies inside the interval would otherwise never
// be seen at all, and every restart would leave a 30s hole.
func TestRunHeartbeat_FirstOneGoesOutBeforeTheFirstTick(t *testing.T) {
	pub := &recordingCorePub{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already done: the ticker (an hour) can never fire
	RunHeartbeat(ctx, pub, "olaitan.health.applog.n1", time.Hour, func() Heartbeat {
		return Heartbeat{Namespace: "shop", Pod: "api-1", Node: "n1", Healthy: true, Events: 3}
	})
	if pub.count() != 2 {
		t.Fatalf("%d heartbeats, want 2 (one at once, one departing)", pub.count())
	}
	if pub.subj[0] != "olaitan.health.applog.n1" {
		t.Errorf("subject = %q", pub.subj[0])
	}
	first := pub.at(t, 0)
	if first.Pod != "api-1" || !first.Healthy || first.Events != 3 || first.Departing {
		t.Errorf("first heartbeat = %+v", first)
	}
	// The last one says the sidecar is going away, so the collector drops
	// it instead of counting it stale for ten minutes after a rollout.
	if last := pub.at(t, 1); !last.Departing {
		t.Errorf("last heartbeat is not marked departing: %+v", last)
	}
}

func TestRunHeartbeat_RepeatsOnTheInterval(t *testing.T) {
	pub := &recordingCorePub{}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	RunHeartbeat(ctx, pub, "olaitan.health.applog.n1", 25*time.Millisecond, func() Heartbeat {
		return Heartbeat{Namespace: "shop", Pod: "api-1", Node: "n1", Healthy: true}
	})
	if pub.count() < 4 {
		t.Errorf("%d heartbeats in 120ms at a 25ms interval", pub.count())
	}
}

func TestHeartbeatSubject(t *testing.T) {
	base, err := subjects.Health("applog")
	if err != nil {
		t.Fatal(err)
	}
	got, err := HeartbeatSubject("olaitan-worker")
	if err != nil {
		t.Fatal(err)
	}
	if got != base+".olaitan-worker" {
		t.Errorf("subject = %q, want %q", got, base+".olaitan-worker")
	}
	// A node name is a DNS subdomain and may contain dots, which are NATS
	// subject separators: an unescaped one would silently split the
	// subject and the collector would never match its own node.
	got, err = HeartbeatSubject("ip-10-0-0-1.eu-west-1.compute.internal")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(got, ".") != strings.Count(base, ".")+1 {
		t.Errorf("subject %q has extra separators from the node name", got)
	}
	if _, err := HeartbeatSubject(""); err == nil {
		t.Error("an empty node name must not produce a subject")
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
	tick := func(d time.Duration) { now = now.Add(d) }

	if !tr.Healthy() || tr.Live() != 0 {
		t.Fatal("a node with no sidecars must read healthy with zero live (nothing is failing)")
	}
	tr.Observe(heartbeatJSON(t, Heartbeat{Namespace: "shop", Pod: "a", Node: "n1", Started: 1, Healthy: true, Events: 10, Engaged: 2}))
	tr.Observe(heartbeatJSON(t, Heartbeat{Namespace: "shop", Pod: "b", Node: "n1", Started: 1, Healthy: true, Events: 5}))
	tr.Observe(heartbeatJSON(t, Heartbeat{Namespace: "shop", Pod: "c", Node: "other-node", Healthy: false}))
	tr.Observe([]byte("not json"))
	tick(time.Second)
	if tr.Live() != 2 || tr.Stale() != 0 || tr.Unhealthy() != 0 || !tr.Healthy() {
		t.Errorf("live=%d stale=%d unhealthy=%d healthy=%v; another node's sidecar must be ignored",
			tr.Live(), tr.Stale(), tr.Unhealthy(), tr.Healthy())
	}
	if tr.EventsTotal() != 15 || tr.EngagedTotal() != 2 {
		t.Errorf("events=%d engaged=%d, want 15 and 2", tr.EventsTotal(), tr.EngagedTotal())
	}

	// A sidecar that has not seen its first line yet is starting, not
	// broken: a quiet workload must not make the node's source unhealthy.
	tr.Observe(heartbeatJSON(t, Heartbeat{Namespace: "shop", Pod: "q", Node: "n1", Started: 1, Healthy: false, Starting: true}))
	tick(time.Second)
	if tr.Unhealthy() != 0 || !tr.Healthy() || tr.Live() != 3 {
		t.Errorf("a starting sidecar counted as a fault: live=%d unhealthy=%d healthy=%v", tr.Live(), tr.Unhealthy(), tr.Healthy())
	}

	// Sidecar a restarts (new Started, counters from zero) and reports 4
	// events: the node total must keep climbing, never go backwards.
	tr.Observe(heartbeatJSON(t, Heartbeat{Namespace: "shop", Pod: "a", Node: "n1", Started: 2, Healthy: true, Events: 4}))
	if tr.EventsTotal() != 19 {
		t.Errorf("after a sidecar restart EventsTotal = %d, want 19 (monotonic)", tr.EventsTotal())
	}

	// b reports itself unhealthy past its first line: the source is unhealthy.
	tr.Observe(heartbeatJSON(t, Heartbeat{Namespace: "shop", Pod: "b", Node: "n1", Started: 1, Healthy: false, Events: 5}))
	tick(time.Second)
	if tr.Unhealthy() != 1 || tr.Healthy() {
		t.Errorf("unhealthy=%d healthy=%v after a sidecar reported unhealthy", tr.Unhealthy(), tr.Healthy())
	}

	// Silence: past the stale threshold they are stale and the source is
	// unhealthy; long past it they are retired (the pods are gone).
	tick(2 * time.Minute)
	if tr.Stale() != 3 || tr.Live() != 0 || tr.Healthy() {
		t.Errorf("after 2m of silence: live=%d stale=%d healthy=%v", tr.Live(), tr.Stale(), tr.Healthy())
	}
	tick(15 * time.Minute)
	if tr.Stale() != 0 || tr.Live() != 0 || !tr.Healthy() {
		t.Errorf("sidecars silent for 17m must be retired: live=%d stale=%d healthy=%v", tr.Live(), tr.Stale(), tr.Healthy())
	}
	if tr.EventsTotal() != 19 {
		t.Errorf("retiring a sidecar must not shrink the counter: %d", tr.EventsTotal())
	}

	// A sidecar that comes back after a long outage, same run, must not
	// have its whole cumulative count added a second time.
	tr.Observe(heartbeatJSON(t, Heartbeat{Namespace: "shop", Pod: "b", Node: "n1", Started: 1, Healthy: true, Events: 9}))
	if tr.EventsTotal() != 23 {
		t.Errorf("EventsTotal = %d after a long-silent sidecar returned with 9 (it had 5); want 23", tr.EventsTotal())
	}
}

// An ordinary rollout must not page anyone: a departing sidecar is
// forgotten at once, not counted stale for the next ten minutes.
func TestSidecarTracker_DepartingSidecarIsForgottenAtOnce(t *testing.T) {
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	tr := NewSidecarTracker("n1", 90*time.Second)
	tr.now = func() time.Time { return now }

	tr.Observe(heartbeatJSON(t, Heartbeat{Namespace: "shop", Pod: "a", Node: "n1", Started: 1, Healthy: true, Events: 7}))
	now = now.Add(time.Second)
	if tr.Live() != 1 {
		t.Fatalf("live = %d, want 1", tr.Live())
	}
	tr.Observe(heartbeatJSON(t, Heartbeat{Namespace: "shop", Pod: "a", Node: "n1", Started: 1, Healthy: true, Events: 8, Departing: true}))
	now = now.Add(5 * time.Minute)
	if tr.Live() != 0 || tr.Stale() != 0 || !tr.Healthy() {
		t.Errorf("after a clean shutdown: live=%d stale=%d healthy=%v; want nothing counted and the node healthy",
			tr.Live(), tr.Stale(), tr.Healthy())
	}
	if tr.EventsTotal() != 8 {
		t.Errorf("the last heartbeat's events were dropped: %d, want 8", tr.EventsTotal())
	}
}

// The watermark map must not grow without bound on a node that churns
// through pods all day.
func TestSidecarTracker_RetiredSidecarsAreBounded(t *testing.T) {
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	tr := NewSidecarTracker("n1", 90*time.Second)
	tr.now = func() time.Time { return now }
	for i := 0; i < maxTracked*2; i++ {
		pod := "pod-" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + time.Duration(i).String()
		tr.Observe(heartbeatJSON(t, Heartbeat{Namespace: "shop", Pod: pod, Node: "n1", Started: 1, Healthy: true, Events: 1, Departing: true}))
		now = now.Add(time.Second)
	}
	tr.mu.Lock()
	n := len(tr.sidecars)
	tr.mu.Unlock()
	if n > maxTracked+1 {
		t.Errorf("tracking %d retired sidecars, want at most %d", n, maxTracked+1)
	}
	if tr.Live() != 0 {
		t.Errorf("live = %d, want 0", tr.Live())
	}
}
