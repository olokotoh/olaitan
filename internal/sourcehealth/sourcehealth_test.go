package sourcehealth

import (
	"errors"
	"sync"
	"testing"
)

func TestTracker_ZeroValueReportsUnhealthy(t *testing.T) {
	t.Parallel()
	var tr Tracker
	healthy, err := tr.Status()
	if healthy {
		t.Fatalf("zero-value tracker should be unhealthy, got healthy=true")
	}
	if err != nil {
		t.Fatalf("zero-value tracker should report nil err, got %v", err)
	}
}

func TestTracker_MarkHealthyClearsError(t *testing.T) {
	t.Parallel()
	var tr Tracker
	tr.MarkUnhealthy(errors.New("boom"))
	tr.MarkHealthy()
	healthy, err := tr.Status()
	if !healthy {
		t.Fatalf("after MarkHealthy, expected healthy=true")
	}
	if err != nil {
		t.Fatalf("MarkHealthy should clear lastErr, got %v", err)
	}
}

func TestTracker_MarkUnhealthyRetainsError(t *testing.T) {
	t.Parallel()
	var tr Tracker
	want := errors.New("connect refused")
	tr.MarkUnhealthy(want)
	healthy, err := tr.Status()
	if healthy {
		t.Fatalf("after MarkUnhealthy, expected healthy=false")
	}
	if !errors.Is(err, want) {
		t.Fatalf("MarkUnhealthy should retain err, got %v want %v", err, want)
	}
}

func TestTracker_MarkUnhealthyNilErr(t *testing.T) {
	t.Parallel()
	var tr Tracker
	tr.MarkUnhealthy(nil)
	healthy, err := tr.Status()
	if healthy {
		t.Fatalf("expected healthy=false")
	}
	if err != nil {
		t.Fatalf("nil err should remain nil, got %v", err)
	}
}

func TestTracker_LastWriterWins(t *testing.T) {
	t.Parallel()
	var tr Tracker
	tr.MarkUnhealthy(errors.New("old"))
	tr.MarkUnhealthy(errors.New("new"))
	_, err := tr.Status()
	if err == nil || err.Error() != "new" {
		t.Fatalf("expected last writer's err 'new', got %v", err)
	}
}

// TestTracker_Concurrent confirms readers and writers can race without
// observing a torn (healthy, err) snapshot. The race detector flags any
// data race; the assertion only checks that Status returns a consistent
// view (healthy=true ⇒ err=nil; healthy=false ⇒ err is one of the
// writers' err or nil).
func TestTracker_Concurrent(t *testing.T) {
	t.Parallel()
	var tr Tracker
	const writers = 8
	const readers = 8
	const iterations = 1000

	var wg sync.WaitGroup
	wg.Add(writers + readers)

	for i := 0; i < writers; i++ {
		go func(id int) {
			defer wg.Done()
			myErr := errors.New("writer error")
			for j := 0; j < iterations; j++ {
				if j%2 == 0 {
					tr.MarkHealthy()
				} else {
					tr.MarkUnhealthy(myErr)
				}
			}
		}(i)
	}

	for i := 0; i < readers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				healthy, err := tr.Status()
				// Self-consistency: healthy=true must imply err=nil
				// because MarkHealthy stores {true, nil}.
				if healthy && err != nil {
					t.Errorf("torn snapshot: healthy=true but err=%v", err)
					return
				}
			}
		}()
	}

	wg.Wait()
}

// Reader interface compile-time assertion: *Tracker must satisfy Reader.
var _ Reader = (*Tracker)(nil)
