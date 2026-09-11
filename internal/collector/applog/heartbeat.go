package applog

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/olokotoh/olaitan/internal/sourcehealth"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// Story 10.10. An applog sidecar runs inside each opted-in workload pod as
// its own process, and nothing scraped it, so applog health was never
// observable (source_healthy{source="applog"} did not exist). Each sidecar
// now publishes a small heartbeat on subjects.Health("applog") (core NATS,
// ephemeral, the subject family reserved for ring health), and the collector
// on the same node tracks the sidecars it hears from.

// HeartbeatInterval is how often a sidecar reports.
const HeartbeatInterval = 30 * time.Second

// Heartbeat is one sidecar's report.
type Heartbeat struct {
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Node      string `json:"node"`
	Container string `json:"container"`
	// Healthy is the sidecar's own source health (tail and publish path).
	Healthy bool `json:"healthy"`
	// Events is the sidecar's cumulative published-event count; it resets
	// when the sidecar restarts.
	Events int64 `json:"events"`
}

type corePublisher interface {
	Publish(subject string, data any) error
}

// RunHeartbeat publishes snapshot() at once and then every interval until
// ctx ends. A failed publish is ignored: the next one retries, and a
// collector that stops hearing a sidecar marks it stale, which is the
// signal an operator needs.
func RunHeartbeat(ctx context.Context, pub corePublisher, interval time.Duration, snapshot func() Heartbeat) {
	subj, err := subjects.Health("applog")
	if err != nil {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		_ = pub.Publish(subj, snapshot())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// forgetAfter drops a sidecar that has been silent this long: its pod is
// gone, and a deleted workload must not hold the node's source unhealthy.
const forgetAfter = 10 * time.Minute

type sidecarState struct {
	lastSeen   time.Time
	healthy    bool
	lastEvents int64
}

// SidecarTracker is the collector-side view of the applog sidecars on one
// node. It satisfies the metrics layer's adapter contract (Health,
// EventsTotal, EngagedTotal), so applog appears as source_healthy and
// sensor_events_total like the other sources.
type SidecarTracker struct {
	node       string
	staleAfter time.Duration
	now        func() time.Time

	mu       sync.Mutex
	sidecars map[string]*sidecarState
	events   int64 // monotonic sum of per-sidecar increments
}

// NewSidecarTracker tracks heartbeats from sidecars on node. A sidecar
// silent for longer than staleAfter counts as stale.
func NewSidecarTracker(node string, staleAfter time.Duration) *SidecarTracker {
	return &SidecarTracker{node: node, staleAfter: staleAfter, now: time.Now, sidecars: map[string]*sidecarState{}}
}

// Observe records one heartbeat body. Heartbeats from other nodes and
// undecodable bodies are ignored.
func (t *SidecarTracker) Observe(body []byte) {
	var hb Heartbeat
	if err := json.Unmarshal(body, &hb); err != nil || hb.Node != t.node || hb.Pod == "" {
		return
	}
	key := hb.Namespace + "/" + hb.Pod
	t.mu.Lock()
	defer t.mu.Unlock()
	st, ok := t.sidecars[key]
	if !ok {
		st = &sidecarState{}
		t.sidecars[key] = st
	}
	// Accumulate increments; a lower count means the sidecar restarted
	// and everything it reports since is new.
	if hb.Events >= st.lastEvents {
		t.events += hb.Events - st.lastEvents
	} else {
		t.events += hb.Events
	}
	st.lastEvents = hb.Events
	st.lastSeen = t.now()
	st.healthy = hb.Healthy
}

// counts returns live, stale and unhealthy sidecars, forgetting long-silent
// ones on the way.
func (t *SidecarTracker) counts() (live, stale, unhealthy int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for k, st := range t.sidecars {
		age := now.Sub(st.lastSeen)
		switch {
		case age > forgetAfter:
			delete(t.sidecars, k)
		case age > t.staleAfter:
			stale++
		default:
			live++
			if !st.healthy {
				unhealthy++
			}
		}
	}
	return live, stale, unhealthy
}

// Live is the number of sidecars heard from within the stale threshold.
func (t *SidecarTracker) Live() int64 { l, _, _ := t.counts(); return l }

// Stale is the number of sidecars gone silent (but not yet forgotten).
func (t *SidecarTracker) Stale() int64 { _, s, _ := t.counts(); return s }

// Unhealthy is the number of live sidecars reporting their own source
// unhealthy.
func (t *SidecarTracker) Unhealthy() int64 { _, _, u := t.counts(); return u }

// Healthy is true when no known sidecar is stale or unhealthy. A node with
// no applog workloads is healthy: nothing is failing. Live tells the two
// apart.
func (t *SidecarTracker) Healthy() bool {
	_, s, u := t.counts()
	return s == 0 && u == 0
}

// EventsTotal is the node's cumulative applog event count, monotonic
// across sidecar restarts.
func (t *SidecarTracker) EventsTotal() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.events
}

// EngagedTotal: sidecars do their own rate limiting; the tracker has no
// breaker of its own.
func (t *SidecarTracker) EngagedTotal() int64 { return 0 }

// Health adapts the tracker to the metrics layer's source-health reader.
func (t *SidecarTracker) Health() sourcehealth.Reader { return trackerHealth{t} }

type trackerHealth struct{ t *SidecarTracker }

func (h trackerHealth) Status() (bool, error) { return h.t.Healthy(), nil }
