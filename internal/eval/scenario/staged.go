// Staged injection (Story 7.2): the scenario stimulus unfolds over time
// rather than in a single instant, so measured_time_to_detect is honestly
// non-zero and varies run-to-run. Event CONTENT (ids, raw field maps,
// subjects) is byte-deterministic across seeds; ONLY the injection timing
// varies, drawn from a per-scenario stagger profile jittered by a seeded,
// fully deterministic hash (the package's no-nondeterminism doctrine holds:
// no global rand, no wall-clock-keyed branching; the seed is the run index,
// so run r of scenario s always reproduces the same offsets).
package scenario

import (
	"encoding/json"
	"time"
)

// StagedEvent pairs one synthetic raw event with its injection offset from
// scenario start. The driver publishes the embedded Event at start+Offset, so
// the pipeline sees the stimulus unfold over the attack's real temporal shape.
type StagedEvent struct {
	Event
	Offset time.Duration
}

// staggerProfile returns, for a scenario, the base offset of each event (in the
// order Events emits them) and the nominal stagger SPAN. The profiles model the
// real temporal shape of each attack; the CONTENT is untouched. Index 0 is the
// priming event, published at t=0. A scenario with N events has N base offsets.
func staggerProfile(scenarioID string) (offsets []time.Duration, span time.Duration) {
	s := time.Second
	switch scenarioID {
	case "s1": // escape: a short burst inside ~5s
		return []time.Duration{0, 4 * s}, 5 * s
	case "s2": // token read, then discovery calls spread over ~15s
		return []time.Duration{0, 3 * s, 14 * s}, 15 * s
	case "s3": // scan fan-out over ~25s
		return []time.Duration{0, 24 * s}, 25 * s
	case "s4": // beaconing: >=3 beacons at jittered intervals, span ~100s
		return []time.Duration{0, 90 * s}, 100 * s
	case "s5": // miner launch (priming, proc) then sustained-load flow inside ~10s
		// 4s/9s gap (not 5s/9s) so even at the +/-2s jitter extremes the two
		// non-priming events cannot coincide.
		return []time.Duration{0, 4 * s, 9 * s}, 10 * s
	}
	return nil, 0
}

// MaxStagedJitter bounds the per-event seeded jitter. Non-priming events are
// shifted by up to this much either way, so different runs produce different
// (but reproducible) offsets and the pipeline latency measurement varies. It
// is exported so the driver can widen the settle ceiling to cover an event
// whose jittered offset exceeds the nominal StaggerSpan (PR #93 review).
const MaxStagedJitter = 2 * time.Second

// jitterFor returns a deterministic per-run, per-event jitter in
// [-MaxStagedJitter, +MaxStagedJitter], seeded ONLY by
// (scenarioID, run, eventIndex) via an FNV-seeded splitmix64 step. Run r of
// scenario s always reproduces the same jitter; different runs differ. No
// global rand, no wall clock. The priming event (index 0) is never jittered so
// t=0 is stable across runs.
func jitterFor(scenarioID string, run, eventIndex int) time.Duration {
	if eventIndex == 0 {
		return 0
	}
	var h uint64 = 1469598103934665603
	for _, b := range []byte(scenarioID) {
		h = (h ^ uint64(b)) * 1099511628211
	}
	h ^= uint64(run)*0x9E3779B97F4A7C15 + uint64(eventIndex)*0xC2B2AE3D27D4EB4F
	h ^= h >> 30
	h *= 0xBF58476D1CE4E5B9
	h ^= h >> 27
	span := int64(2*MaxStagedJitter) + 1
	return time.Duration(int64(h%uint64(span))) - MaxStagedJitter
}

// StaggerSpan returns the nominal (un-jittered) time span of a scenario's
// staged stimulus, so the driver can derive an effective settle ceiling that
// accounts for the injection schedule (Story 7.2 AC5).
func StaggerSpan(scenarioID string) time.Duration {
	_, span := staggerProfile(scenarioID)
	return span
}

// StagedEvents returns the scenario stimulus with per-event injection offsets
// (Story 7.2 AC1-AC2). Every field EXCEPT the embedded timestamp is identical
// to Events; the timestamp is re-stamped to ts+Offset so an event's embedded
// time equals when the driver actually injects it. This is load-bearing: the
// correlator evicts window events older than its 60s window by their EMBEDDED
// timestamp, so a match published at ts+90s but stamped ts would arrive
// already-stale and be dropped, and the scenario could never be detected
// (PR #93 review). The returned slice is in recipe order (non-decreasing base
// offset); the driver publishes each event at start+Offset. If the stagger
// profile and the recipe disagree on length (a programming error, guarded by a
// unit test), every offset is 0 and timestamps are unchanged so the stimulus
// degrades to all-at-once rather than mis-scheduling.
func StagedEvents(scenarioID, podName string, ts time.Time, run int) []StagedEvent {
	base := Events(scenarioID, podName, ts)
	offsets, _ := staggerProfile(scenarioID)
	out := make([]StagedEvent, len(base))
	if len(offsets) != len(base) {
		for i, e := range base {
			out[i] = StagedEvent{Event: e}
		}
		return out
	}
	for i, e := range base {
		off := offsets[i] + jitterFor(scenarioID, run, i)
		if off < 0 {
			off = 0
		}
		out[i] = StagedEvent{Event: restampEvent(e, ts.Add(off)), Offset: off}
	}
	return out
}

// restampEvent returns a copy of ev with its embedded JSON "timestamp" field
// set to at (RFC3339Nano). Only the timestamp field changes; every other field
// is preserved semantically (each value round-trips as json.RawMessage, so
// values are byte-preserved and only the object's key order may differ, which
// is JSON-equivalent, PR #93 Copilot review). On any decode/encode error the
// event is returned unchanged (the payloads are engine-produced JSON objects,
// so this never happens in practice; failing closed to the original is safe).
func restampEvent(ev Event, at time.Time) Event {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(ev.Payload, &m); err != nil {
		return ev
	}
	stamp, err := json.Marshal(at.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return ev
	}
	m["timestamp"] = stamp
	b, err := json.Marshal(m)
	if err != nil {
		return ev
	}
	return Event{Subject: ev.Subject, Payload: b}
}
