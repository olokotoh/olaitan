package falco

import (
	"context"
	"sync"

	"github.com/olokotoh/olaitan/internal/schema"
)

// bufferedAlert is one translated alert waiting to be published, with the
// size of its marshalled form (the bytes PublishJS will send).
type bufferedAlert struct {
	ev   schema.Event
	size int
}

// alertBuffer is the bounded FIFO between the http_output handler and the
// publish worker (issue #135). It is bounded by alert count and by bytes.
// A push that does not fit drops the oldest queued alerts until it does,
// and reports how many it dropped so the caller can count them exactly.
//
// The alert the worker is currently publishing has left the queue, so it
// is outside both bounds: the adapter holds at most maxAlerts queued alerts
// plus one in flight.
type alertBuffer struct {
	mu       sync.Mutex
	items    []bufferedAlert // items[head:] are queued, oldest first
	head     int
	bytes    int
	maxItems int
	maxBytes int
	closed   bool
	// ready has one slot; a push fills it so a blocked take wakes. A
	// full slot means a wake-up is already pending.
	ready chan struct{}
}

func newAlertBuffer(maxItems, maxBytes int) *alertBuffer {
	return &alertBuffer{maxItems: maxItems, maxBytes: maxBytes, ready: make(chan struct{}, 1)}
}

// push appends it, first dropping the oldest queued alerts until it fits.
// An alert larger than the whole byte bound can never fit; it is dropped on
// its own and the queue is left alone. ok is false when the buffer is
// closed, in which case nothing is queued or dropped.
func (b *alertBuffer) push(it bufferedAlert) (dropped int, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, false
	}
	if it.size > b.maxBytes {
		return 1, true
	}
	for b.len() > 0 && (b.len()+1 > b.maxItems || b.bytes+it.size > b.maxBytes) {
		b.popLocked()
		dropped++
	}
	b.items = append(b.items, it)
	b.bytes += it.size
	b.signal()
	return dropped, true
}

// requeue puts an alert the worker took back at the head. It ignores close
// and both bounds: the alert was already accepted, and shutdown needs to
// drain or count it.
func (b *alertBuffer) requeue(it bufferedAlert) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.head > 0 {
		b.head--
		b.items[b.head] = it
	} else {
		b.items = append([]bufferedAlert{it}, b.items...)
	}
	b.bytes += it.size
	b.signal()
}

// take removes and returns the oldest alert, waiting for one if the queue
// is empty. It returns false when ctx ends, or when the buffer is closed
// and empty.
func (b *alertBuffer) take(ctx context.Context) (bufferedAlert, bool) {
	for {
		b.mu.Lock()
		if b.len() > 0 {
			it := b.popLocked()
			if b.len() > 0 {
				b.signal()
			}
			b.mu.Unlock()
			return it, true
		}
		closed := b.closed
		b.mu.Unlock()
		if closed {
			return bufferedAlert{}, false
		}
		select {
		case <-ctx.Done():
			return bufferedAlert{}, false
		case <-b.ready:
		}
	}
}

// tryTake is take without waiting.
func (b *alertBuffer) tryTake() (bufferedAlert, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.len() == 0 {
		return bufferedAlert{}, false
	}
	return b.popLocked(), true
}

// close stops push from accepting alerts and wakes a waiting take.
func (b *alertBuffer) close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	b.signal()
}

// stats returns the queued alert count and their total bytes.
func (b *alertBuffer) stats() (n, bytes int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.len(), b.bytes
}

func (b *alertBuffer) len() int { return len(b.items) - b.head }

// popLocked removes the head. The backing array is compacted once half of
// it is dead, so a long-lived buffer does not grow without bound.
func (b *alertBuffer) popLocked() bufferedAlert {
	it := b.items[b.head]
	b.items[b.head] = bufferedAlert{}
	b.head++
	b.bytes -= it.size
	if b.head == len(b.items) {
		b.items = b.items[:0]
		b.head = 0
	} else if b.head >= 64 && b.head*2 >= len(b.items) {
		n := copy(b.items, b.items[b.head:])
		clear(b.items[n:])
		b.items = b.items[:n]
		b.head = 0
	}
	return it
}

func (b *alertBuffer) signal() {
	select {
	case b.ready <- struct{}{}:
	default:
	}
}
