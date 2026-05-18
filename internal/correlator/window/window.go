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
}

// NewStore constructs a Store with a positive window duration.
func NewStore(window time.Duration) *Store {
	if window <= 0 {
		window = time.Minute
	}
	return &Store{window: window, workload: map[string][]schema.Event{}}
}

// SetWindowDuration changes the expiry horizon used by future Adds.
func (s *Store) SetWindowDuration(window time.Duration) {
	if window <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.window = window
}

// Add inserts ev into workloadID's buffer, expires events older than
// ev.Timestamp-window, and returns the post-insert snapshot.
func (s *Store) Add(workloadID string, ev schema.Event) (Snapshot, error) {
	if workloadID == "" {
		return Snapshot{}, errors.New("window: workload id is empty")
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	events := append(s.workload[workloadID], ev)
	cutoff := ev.Timestamp.Add(-s.window)
	kept := events[:0]
	for _, candidate := range events {
		if !candidate.Timestamp.Before(cutoff) {
			kept = append(kept, candidate)
		}
	}
	sortEvents(kept)
	s.workload[workloadID] = kept
	return makeSnapshotLocked(workloadID, kept), nil
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
