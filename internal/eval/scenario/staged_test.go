package scenario

import (
	"bytes"
	"testing"
	"time"
)

// TestStagedEvents_ContentByteIdenticalAcrossRuns proves staging changes ONLY
// timing: the event payloads are byte-identical to Events and stable across
// run seeds (AC1).
func TestStagedEvents_ContentByteIdenticalAcrossRuns(t *testing.T) {
	ts := time.Unix(1000, 0)
	for _, sc := range []string{"s1", "s2", "s3", "s4", "s5"} {
		base := Events(sc, "web", ts)
		for _, run := range []int{0, 1, 7, 42} {
			staged := StagedEvents(sc, "web", ts, run)
			if len(staged) != len(base) {
				t.Fatalf("%s run %d: %d staged events, want %d", sc, run, len(staged), len(base))
			}
			for i := range base {
				if staged[i].Subject != base[i].Subject || !bytes.Equal(staged[i].Payload, base[i].Payload) {
					t.Fatalf("%s run %d event %d: staged content diverged from Events", sc, run, i)
				}
			}
		}
	}
}

// TestStagedEvents_DeterministicPerSeedDistinctAcrossSeeds pins AC2: the same
// run reproduces the same offsets, different runs differ, and priming
// (index 0) is never jittered.
func TestStagedEvents_DeterministicPerSeedDistinctAcrossSeeds(t *testing.T) {
	ts := time.Unix(2000, 0)
	a := StagedEvents("s2", "web", ts, 3)
	b := StagedEvents("s2", "web", ts, 3)
	for i := range a {
		if a[i].Offset != b[i].Offset {
			t.Fatalf("s2 run 3 event %d: offset not reproducible (%v vs %v)", i, a[i].Offset, b[i].Offset)
		}
	}
	if a[0].Offset != 0 {
		t.Fatalf("priming event must be at t=0, got %v", a[0].Offset)
	}
	c := StagedEvents("s2", "web", ts, 4)
	differs := false
	for i := 1; i < len(a); i++ {
		if a[i].Offset != c[i].Offset {
			differs = true
		}
	}
	if !differs {
		t.Fatal("s2 runs 3 and 4 produced identical offsets; jitter is not run-varying")
	}
}

// TestStagedEvents_OffsetsOrderedAndWithinSpan pins AC1/AC5: offsets are
// non-negative, non-decreasing, and inside the nominal span plus the jitter
// margin, so the driver's effective-ceiling derivation from StaggerSpan is
// sound.
func TestStagedEvents_OffsetsOrderedAndWithinSpan(t *testing.T) {
	ts := time.Unix(3000, 0)
	for _, sc := range []string{"s1", "s2", "s3", "s4", "s5"} {
		span := StaggerSpan(sc)
		for _, run := range []int{0, 5, 99} {
			staged := StagedEvents(sc, "web", ts, run)
			prev := time.Duration(-1)
			for i, e := range staged {
				if e.Offset < 0 {
					t.Fatalf("%s run %d event %d: negative offset %v", sc, run, i, e.Offset)
				}
				if e.Offset > span+maxStagedJitter {
					t.Fatalf("%s run %d event %d: offset %v exceeds span %v + jitter", sc, run, i, e.Offset, span)
				}
				if e.Offset < prev {
					t.Fatalf("%s run %d event %d: offset %v out of order (< %v)", sc, run, i, e.Offset, prev)
				}
				prev = e.Offset
			}
		}
	}
}

// TestStaggerProfile_MatchesRecipeLength guards the profile/recipe alignment so
// the StagedEvents fallback path is never taken in production.
func TestStaggerProfile_MatchesRecipeLength(t *testing.T) {
	ts := time.Unix(4000, 0)
	for _, sc := range []string{"s1", "s2", "s3", "s4", "s5"} {
		offsets, _ := staggerProfile(sc)
		if got := len(Events(sc, "web", ts)); got != len(offsets) {
			t.Fatalf("%s: %d recipe events but %d profile offsets", sc, got, len(offsets))
		}
	}
}
