package falco

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/schema"
)

// item builds a queued alert whose event ID is its position, so a test can
// see exactly which alerts survived.
func item(id string, size int) bufferedAlert {
	return bufferedAlert{ev: schema.Event{ID: id}, size: size}
}

func drainIDs(t *testing.T, b *alertBuffer) []string {
	t.Helper()
	var ids []string
	for {
		it, ok := b.tryTake()
		if !ok {
			return ids
		}
		ids = append(ids, it.ev.ID)
	}
}

func equalIDs(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestBuffer_CountBoundDropsTheOldest(t *testing.T) {
	b := newAlertBuffer(3, 1<<20)
	var dropped int
	for _, id := range []string{"1", "2", "3", "4", "5"} {
		d, ok := b.push(item(id, 10))
		if !ok {
			t.Fatalf("push %s refused on an open buffer", id)
		}
		dropped += d
	}
	if dropped != 2 {
		t.Errorf("dropped = %d, want 2 (5 pushed into a bound of 3)", dropped)
	}
	if n, by := b.stats(); n != 3 || by != 30 {
		t.Errorf("depth=%d bytes=%d, want 3/30", n, by)
	}
	if got := drainIDs(t, b); !equalIDs(got, []string{"3", "4", "5"}) {
		t.Errorf("kept %v, want the newest [3 4 5] in arrival order", got)
	}
}

func TestBuffer_ByteBoundDropsTheOldestUntilTheNewAlertFits(t *testing.T) {
	b := newAlertBuffer(100, 100)
	for _, id := range []string{"1", "2"} {
		if d, _ := b.push(item(id, 40)); d != 0 {
			t.Fatalf("push %s dropped %d under the bound", id, d)
		}
	}
	// 80 held + 70 new = 150 > 100: dropping "1" leaves 110, still over,
	// so "2" goes too.
	if d, _ := b.push(item("3", 70)); d != 2 {
		t.Errorf("dropped = %d, want 2", d)
	}
	if n, by := b.stats(); n != 1 || by != 70 {
		t.Errorf("depth=%d bytes=%d, want 1/70", n, by)
	}
	if got := drainIDs(t, b); !equalIDs(got, []string{"3"}) {
		t.Errorf("kept %v, want [3]", got)
	}
}

// An alert larger than the whole byte bound can never fit. It is dropped on
// arrival and counted, and must not flush the queue on its way out.
func TestBuffer_AlertLargerThanTheByteBoundIsDroppedAlone(t *testing.T) {
	b := newAlertBuffer(100, 100)
	b.push(item("1", 30))
	d, ok := b.push(item("huge", 101))
	if !ok || d != 1 {
		t.Errorf("push(huge) = dropped %d ok %v, want 1 true", d, ok)
	}
	if got := drainIDs(t, b); !equalIDs(got, []string{"1"}) {
		t.Errorf("kept %v, want [1]; an oversize alert must not evict others", got)
	}
}

func TestBuffer_TakeBlocksUntilAnAlertArrivesOrTheContextEnds(t *testing.T) {
	b := newAlertBuffer(10, 1<<20)
	got := make(chan string, 1)
	go func() {
		it, ok := b.take(context.Background())
		if ok {
			got <- it.ev.ID
		}
	}()
	select {
	case id := <-got:
		t.Fatalf("take returned %q from an empty buffer", id)
	case <-time.After(50 * time.Millisecond):
	}
	b.push(item("a", 1))
	select {
	case id := <-got:
		if id != "a" {
			t.Errorf("took %q, want a", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("take did not wake on push")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool, 1)
	go func() { _, ok := b.take(ctx); done <- ok }()
	cancel()
	select {
	case ok := <-done:
		if ok {
			t.Error("take returned an alert after its context was cancelled on an empty buffer")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("take ignored context cancellation")
	}
}

func TestBuffer_CloseRefusesNewAlertsAndHandsOutTheRest(t *testing.T) {
	b := newAlertBuffer(10, 1<<20)
	b.push(item("1", 1))
	b.push(item("2", 1))
	b.close()
	if _, ok := b.push(item("3", 1)); ok {
		t.Error("a closed buffer accepted an alert")
	}
	for _, want := range []string{"1", "2"} {
		it, ok := b.take(context.Background())
		if !ok || it.ev.ID != want {
			t.Fatalf("take = %q %v, want %s true", it.ev.ID, ok, want)
		}
	}
	if _, ok := b.take(context.Background()); ok {
		t.Error("take on a closed, empty buffer returned an alert")
	}
}

// requeue puts the alert the worker was holding back at the head, so a
// shutdown can count or drain it. It ignores close and the bound: the
// alert was already accepted.
func TestBuffer_RequeueReturnsTheInFlightAlertToTheHead(t *testing.T) {
	b := newAlertBuffer(2, 1<<20)
	b.push(item("1", 1))
	head, _ := b.tryTake()
	b.push(item("2", 1))
	b.push(item("3", 1))
	b.close()
	b.requeue(head)
	if got := drainIDs(t, b); !equalIDs(got, []string{"1", "2", "3"}) {
		t.Errorf("order after requeue = %v, want [1 2 3]", got)
	}
}

// Drop accounting must be exact under concurrent producers (run with -race):
// with no consumer, everything pushed beyond the bound is dropped, once.
func TestBuffer_DropCountIsExactUnderConcurrentPushes(t *testing.T) {
	const producers, each, bound = 8, 500, 64
	b := newAlertBuffer(bound, 1<<30)
	var mu sync.Mutex
	var dropped int
	var wg sync.WaitGroup
	for p := 0; p < producers; p++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				d, _ := b.push(item("x", 7))
				mu.Lock()
				dropped += d
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if want := producers*each - bound; dropped != want {
		t.Errorf("dropped = %d, want exactly %d", dropped, want)
	}
	if n, by := b.stats(); n != bound || by != bound*7 {
		t.Errorf("depth=%d bytes=%d, want %d/%d", n, by, bound, bound*7)
	}
}
