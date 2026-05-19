// Package window keeps per-workload sliding event buffers for the
// Ring-2 correlator.
package window

import (
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/olokotoh/olaitan/internal/schema"
)

// Snapshot is an immutable copy of one workload's current event window.
type Snapshot struct {
	WorkloadID string
	Events     []schema.Event
	Start      time.Time
	End        time.Time
}

// Store keeps one time-bounded event buffer per workload.
type Store struct {
	mu       sync.RWMutex
	window   time.Duration
	workload map[string][]schema.Event
	// fired tracks per-workload "multi-signal convergence already fired"
	// state so the correlator only fires on the rising edge of the
	// predicate (FR9 convergence; deduped re-fires per closure decision
	// D23). The flag is reset when the per-workload buffer falls back
	// below the configured minSources or empties entirely.
	fired map[string]bool
	// now is the clock used for eviction cutoffs. Defaulting to
	// time.Now keeps production behaviour intact; tests override it to
	// drive deterministic expiry.
	now func() time.Time
}

// NewStore constructs a Store with a positive window duration.
func NewStore(window time.Duration) *Store {
	if window <= 0 {
		window = time.Minute
	}
	return &Store{
		window:   window,
		workload: map[string][]schema.Event{},
		fired:    map[string]bool{},
		now:      func() time.Time { return time.Now().UTC() },
	}
}

// SetNow overrides the clock used for cutoff computation. Intended for
// tests; production callers must not invoke this.
func (s *Store) SetNow(now func() time.Time) {
	if now == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}

// SetWindowDuration changes the expiry horizon and retroactively trims
// every workload's buffer to the new cutoff. A shrink applied while a
// long-lived window is in flight evicts entries immediately so the
// next Add observes the new horizon rather than carrying stale events
// across the hot-reload boundary.
func (s *Store) SetWindowDuration(window time.Duration) {
	if window <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.window = window
	cutoff := s.now().Add(-window)
	for workloadID, events := range s.workload {
		kept := events[:0]
		for _, candidate := range events {
			if !candidate.Timestamp.Before(cutoff) {
				kept = append(kept, candidate)
			}
		}
		if len(kept) == 0 {
			delete(s.workload, workloadID)
			delete(s.fired, workloadID)
			continue
		}
		s.workload[workloadID] = kept
		if !meetsMinSources(kept, distinctSourceCountForFired(workloadID, s.fired)) {
			// Source set may have shrunk below the previously-fired
			// threshold; the next Add will re-check and either re-arm
			// or remain dormant. Conservative behaviour here keeps the
			// "fired" flag in sync with the trimmed buffer.
			delete(s.fired, workloadID)
		}
	}
}

// distinctSourceCountForFired is a helper that returns 0 when the
// workload has not previously fired, so meetsMinSources below
// short-circuits and SetWindowDuration leaves dormant workloads alone.
func distinctSourceCountForFired(workloadID string, fired map[string]bool) int {
	if fired[workloadID] {
		// Use 2 (the minimum allowed by config validation) as the
		// retroactive check. SetWindowDuration cannot know the
		// caller's configured minSources, so it conservatively
		// re-arms whenever the buffer's distinct-source count drops
		// below 2. A subsequent Add with the live minSources will
		// re-fire correctly.
		return 2
	}
	return 0
}

func meetsMinSources(events []schema.Event, minSources int) bool {
	if minSources <= 0 {
		return true
	}
	seen := map[schema.EventSource]struct{}{}
	for _, ev := range events {
		if ev.Source != "" {
			seen[ev.Source] = struct{}{}
		}
	}
	return len(seen) >= minSources
}

// Add inserts ev into workloadID's buffer, expires events older than
// now-window (now is the store's clock, decoupled from ev.Timestamp so
// a skewed future-dated event cannot rewind the cutoff), and returns
// the post-insert snapshot.
func (s *Store) Add(workloadID string, ev schema.Event) (Snapshot, error) {
	snap, _, err := s.AddAndCheckRisingEdge(workloadID, ev, 0)
	return snap, err
}

// AddAndCheckRisingEdge inserts ev, evicts expired entries, and
// reports whether the multi-signal convergence predicate just
// transitioned from false to true for this workload. minSources <= 0
// disables the rising-edge check (returns transitioned=false). The
// fired flag is reset when the post-insert buffer's distinct-source
// count drops below minSources, so a workload that expires below the
// threshold and later climbs back re-fires once.
func (s *Store) AddAndCheckRisingEdge(workloadID string, ev schema.Event, minSources int) (Snapshot, bool, error) {
	if workloadID == "" {
		return Snapshot{}, false, errors.New("window: workload id is empty")
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	events := append(s.workload[workloadID], ev)
	cutoff := s.now().Add(-s.window)
	kept := events[:0]
	for _, candidate := range events {
		if !candidate.Timestamp.Before(cutoff) {
			kept = append(kept, candidate)
		}
	}
	sortEvents(kept)
	if len(kept) == 0 {
		delete(s.workload, workloadID)
		delete(s.fired, workloadID)
		return makeSnapshotLocked(workloadID, kept), false, nil
	}
	s.workload[workloadID] = kept

	transitioned := false
	if minSources > 0 {
		current := meetsMinSources(kept, minSources)
		prior := s.fired[workloadID]
		switch {
		case current && !prior:
			s.fired[workloadID] = true
			transitioned = true
		case !current && prior:
			// Re-arm: the distinct-source set dropped below the
			// threshold, the next time we climb back we should fire
			// again per the rising-edge contract.
			delete(s.fired, workloadID)
		}
	}
	return makeSnapshotLocked(workloadID, kept), transitioned, nil
}

// Snapshot returns a copy of workloadID's current buffer.
func (s *Store) Snapshot(workloadID string) Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return makeSnapshotLocked(workloadID, s.workload[workloadID])
}

func makeSnapshotLocked(workloadID string, events []schema.Event) Snapshot {
	out := append([]schema.Event(nil), events...)
	snap := Snapshot{WorkloadID: workloadID, Events: out}
	if len(out) > 0 {
		snap.Start = out[0].Timestamp
		snap.End = out[len(out)-1].Timestamp
	}
	return snap
}

func sortEvents(events []schema.Event) {
	sort.SliceStable(events, func(i, j int) bool {
		if !events[i].Timestamp.Equal(events[j].Timestamp) {
			return events[i].Timestamp.Before(events[j].Timestamp)
		}
		return events[i].ID < events[j].ID
	})
}
