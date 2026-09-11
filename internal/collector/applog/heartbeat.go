package applog

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/olokotoh/olaitan/internal/sourcehealth"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// Story 10.10. An applog sidecar runs inside each opted-in workload pod as
// its own process, and nothing scraped it, so applog health was never
// observable (source_healthy{source="applog"} did not exist). Each sidecar
// now publishes a small heartbeat on a node-scoped health subject (core
// NATS, ephemeral, the subject family reserved for ring health), and the
// collector on the same node tracks the sidecars it hears from.

// HeartbeatInterval is how often a sidecar reports.
const HeartbeatInterval = 30 * time.Second

// HeartbeatSubject is the subject a sidecar on node publishes to, and the
// only one that node's collector subscribes to. It is node-scoped on
// purpose: a cluster-wide subject would deliver every sidecar's heartbeat
// to every collector, which then discards all but its own node's (5000
// sidecars across 200 nodes is 33k deliveries a second, 99.5% of them
// thrown away).
//
// A node name is a DNS subdomain and may contain dots, which are NATS
// subject separators, so dots become underscores. Both sides call this
// function, so the mapping only has to be consistent, not reversible.
func HeartbeatSubject(node string) (string, error) {
	base, err := subjects.Health("applog")
	if err != nil {
		return "", err
	}
	tok := strings.Map(func(r rune) rune {
		switch r {
		case '.', '*', '>', ' ', '\t', '\n', '\r':
			return '_'
		}
		return r
	}, node)
	if tok == "" {
		return "", fmt.Errorf("applog: heartbeat subject: empty node name")
	}
	return base + "." + tok, nil
}

// Heartbeat is one sidecar's report.
type Heartbeat struct {
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Node      string `json:"node"`
	Container string `json:"container"`
	// Healthy is the sidecar's own source health (tail and publish path).
	Healthy bool `json:"healthy"`
	// Starting is true between the sidecar's start and its first
	// published line. It is not a fault: a workload that has not logged
	// yet leaves the sidecar in this state indefinitely, and the
	// collector must not report it as a failure.
	Starting bool `json:"starting,omitempty"`
	// Departing is the sidecar's last heartbeat, sent as it shuts down,
	// so the collector drops it at once instead of calling it stale for
	// minutes after an ordinary rollout.
	Departing bool `json:"departing,omitempty"`
	// Started identifies this run of the sidecar (Unix nanoseconds). A
	// changed value means the process restarted and its counters below
	// start again from zero.
	Started int64 `json:"started"`
	// Events is the sidecar's cumulative published-event count.
	Events int64 `json:"events"`
	// Engaged is the sidecar's cumulative rate-limit engagements.
	Engaged int64 `json:"engaged"`
}

type corePublisher interface {
	Publish(subject string, data any) error
}

// RunHeartbeat publishes snapshot() at once and then every interval until
// ctx ends, then publishes one final heartbeat marked Departing. A failed
// publish is ignored: the next one retries, and a collector that stops
// hearing a sidecar marks it stale, which is the signal an operator needs.
func RunHeartbeat(ctx context.Context, pub corePublisher, subject string, interval time.Duration, snapshot func() Heartbeat) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		_ = pub.Publish(subject, snapshot())
		select {
		case <-ctx.Done():
			// The pod is going away (rollout, scale-down, drain). Say
			// so on a context that is not already cancelled, so the
			// collector forgets this sidecar now rather than counting
			// it stale for the next ten minutes.
			hb := snapshot()
			hb.Departing = true
			_ = pub.Publish(subject, hb)
			return
		case <-t.C:
		}
	}
}

// forgetAfter drops a sidecar that has been silent this long without
// saying goodbye: its pod is gone, and a deleted workload must not hold
// the node's source unhealthy.
const forgetAfter = 10 * time.Minute

// maxTracked bounds the per-sidecar watermarks kept for pods that have
// gone. Without them a sidecar that goes quiet for longer than
// forgetAfter and comes back would have its whole cumulative count added
// a second time.
const maxTracked = 512

// countsCacheFor keeps one Prometheus scrape's three gauges consistent:
// without it, live, stale and unhealthy are three separate scans and a
// sidecar crossing a threshold mid-scrape appears in two of them or
// neither.
const countsCacheFor = 100 * time.Millisecond

type sidecarState struct {
	lastSeen   time.Time
	healthy    bool
	starting   bool
	started    int64
	lastEvents int64
	lastEng    int64
	// gone is set when the sidecar said goodbye or went silent past
	// forgetAfter. The entry stays as a watermark and is not counted.
	gone bool
}

type counts struct {
	live, stale, unhealthy int64
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
	engaged  int64

	cached   counts
	cachedAt time.Time
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
		st = &sidecarState{started: hb.Started}
		t.sidecars[key] = st
		t.prune()
	}
	if st.started != hb.Started {
		// A different run of the sidecar: its counters restarted, so
		// everything it reports is new.
		st.started = hb.Started
		st.lastEvents, st.lastEng = 0, 0
	}
	t.events += increment(hb.Events, st.lastEvents)
	t.engaged += increment(hb.Engaged, st.lastEng)
	st.lastEvents, st.lastEng = hb.Events, hb.Engaged
	st.lastSeen = t.now()
	st.healthy = hb.Healthy
	st.starting = hb.Starting
	st.gone = hb.Departing
	t.cachedAt = time.Time{}
}

// increment is what a report of now adds to a total that last saw prev.
// A counter that went backwards means the sidecar restarted between
// reports, so all of now is new.
func increment(now, prev int64) int64 {
	if now >= prev {
		return now - prev
	}
	return now
}

// prune bounds the watermark map, dropping the sidecars that departed
// longest ago. Called with the lock held.
func (t *SidecarTracker) prune() {
	if len(t.sidecars) <= maxTracked {
		return
	}
	type entry struct {
		key  string
		seen time.Time
	}
	gone := make([]entry, 0, len(t.sidecars))
	for k, st := range t.sidecars {
		if st.gone {
			gone = append(gone, entry{k, st.lastSeen})
		}
	}
	sort.Slice(gone, func(i, j int) bool { return gone[i].seen.Before(gone[j].seen) })
	for _, e := range gone {
		if len(t.sidecars) <= maxTracked {
			return
		}
		delete(t.sidecars, e.key)
	}
}

// counts returns live, stale and unhealthy sidecars, retiring long-silent
// ones on the way. A sidecar still starting counts as live and not as
// unhealthy.
func (t *SidecarTracker) counts() counts {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	if !t.cachedAt.IsZero() && now.Sub(t.cachedAt) < countsCacheFor {
		return t.cached
	}
	var c counts
	for _, st := range t.sidecars {
		if st.gone {
			continue
		}
		age := now.Sub(st.lastSeen)
		switch {
		case age > forgetAfter:
			st.gone = true
		case age > t.staleAfter:
			c.stale++
		default:
			c.live++
			if !st.healthy && !st.starting {
				c.unhealthy++
			}
		}
	}
	t.prune()
	t.cached, t.cachedAt = c, now
	return c
}

// Live is the number of sidecars heard from within the stale threshold.
func (t *SidecarTracker) Live() int64 { return t.counts().live }

// Stale is the number of sidecars gone silent without saying goodbye.
func (t *SidecarTracker) Stale() int64 { return t.counts().stale }

// Unhealthy is the number of live sidecars reporting their own source
// unhealthy (past their first line).
func (t *SidecarTracker) Unhealthy() int64 { return t.counts().unhealthy }

// Healthy is true when no known sidecar is stale or unhealthy. A node with
// no applog workloads is healthy: nothing is failing. Live tells the two
// apart.
func (t *SidecarTracker) Healthy() bool {
	c := t.counts()
	return c.stale == 0 && c.unhealthy == 0
}

// EventsTotal is the node's cumulative applog event count, monotonic
// across sidecar restarts.
func (t *SidecarTracker) EventsTotal() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.events
}

// EngagedTotal is the node's cumulative count of sidecar rate-limit
// engagements: each sidecar runs its own limiter and reports it here.
func (t *SidecarTracker) EngagedTotal() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.engaged
}

// Health adapts the tracker to the metrics layer's source-health reader.
func (t *SidecarTracker) Health() sourcehealth.Reader { return trackerHealth{t} }

type trackerHealth struct{ t *SidecarTracker }

func (h trackerHealth) Status() (bool, error) { return h.t.Healthy(), nil }
