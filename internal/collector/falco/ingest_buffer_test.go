package falco

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	natsjs "github.com/nats-io/nats.go/jetstream"

	"github.com/olokotoh/olaitan/internal/schema"
)

// Issue #135: Falco's http_output does not retry, so the adapter must not
// make an alert's fate depend on NATS being up at the moment Falco posts.

// alertN is the real alert fixture with its timestamp digits replaced, so
// each n is a distinct alert with a distinct event ID.
func alertN(t *testing.T, n int) []byte {
	t.Helper()
	return bytes.ReplaceAll(fixture(t, "http_output_alert.json"), []byte("544857414"), []byte(fmt.Sprintf("%09d", n)))
}

// outagePub is a JetStream stand-in that can be "down" (every publish
// fails with a transient error) or "up" (records the event).
type outagePub struct {
	mu       sync.Mutex
	down     bool
	attempts int
	events   []schema.Event
}

func (p *outagePub) PublishJS(_ context.Context, _ string, data any, _ ...natsjs.PublishOpt) (*natsjs.PubAck, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.attempts++
	if p.down {
		return nil, errors.New("nats: no responders available for request")
	}
	p.events = append(p.events, data.(schema.Event))
	return &natsjs.PubAck{Stream: "EVENTS_RAW"}, nil
}

func (p *outagePub) setDown(v bool) { p.mu.Lock(); p.down = v; p.mu.Unlock() }
func (p *outagePub) nAttempts() int { p.mu.Lock(); defer p.mu.Unlock(); return p.attempts }
func (p *outagePub) ids() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, len(p.events))
	for i, e := range p.events {
		out[i] = e.ID
	}
	return out
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// eventID is the ID the adapter will give alertN(n).
func eventID(t *testing.T, n int) string {
	t.Helper()
	resp, err := DecodeHTTPOutput(alertN(t, n))
	if err != nil {
		t.Fatal(err)
	}
	ev, err := Translate(resp, "kind-node")
	if err != nil {
		t.Fatal(err)
	}
	return ev.ID
}

// AC1: the 204 does not wait for NATS.
func TestHandler_AcknowledgesOnceQueuedWithoutWaitingForNATS(t *testing.T) {
	pub := &outagePub{down: true}
	a := newRunningAdapter(t, pub, nil)
	start := time.Now()
	rec := post(t, a, "/falco/"+testToken, "application/json", alertN(t, 1))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("code = %d, want 204 while NATS is down", rec.Code)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("handler took %s with NATS down; it must not wait on the publish", d)
	}
	waitFor(t, "a publish attempt", func() bool { return pub.nAttempts() > 0 })
	if healthy, _ := a.Health().Status(); healthy {
		t.Error("source healthy while every publish fails")
	}
}

// AC4 + no loss under the bound: every alert accepted during the outage is
// published, once each, in arrival order, after NATS returns.
func TestAdapter_NATSOutageUnderTheBoundLosesNothing(t *testing.T) {
	pub := &outagePub{down: true}
	a := newRunningAdapter(t, pub, func(c *Config) { c.BufferMaxAlerts = 100 })
	const n = 50
	var want []string
	for i := 1; i <= n; i++ {
		if rec := post(t, a, "/falco/"+testToken, "application/json", alertN(t, i)); rec.Code != http.StatusNoContent {
			t.Fatalf("alert %d: code %d", i, rec.Code)
		}
		want = append(want, eventID(t, i))
	}
	waitFor(t, "retries while down", func() bool { return pub.nAttempts() >= 3 })
	if len(pub.ids()) != 0 {
		t.Fatal("published while NATS was down")
	}

	pub.setDown(false)
	waitFor(t, "all alerts published", func() bool { return len(pub.ids()) == n })
	if got := pub.ids(); !equalIDs(got, want) {
		t.Errorf("published order differs from arrival order")
	}
	if a.BufferDropped() != 0 || a.EventsTotal() != n || a.AlertsReceivedTotal() != n {
		t.Errorf("dropped=%d events=%d received=%d, want 0/%d/%d", a.BufferDropped(), a.EventsTotal(), a.AlertsReceivedTotal(), n, n)
	}
	waitFor(t, "empty buffer gauges", func() bool { return a.BufferDepth() == 0 && a.BufferBytes() == 0 })
	if healthy, _ := a.Health().Status(); !healthy {
		t.Error("source still unhealthy after NATS came back and every alert was published")
	}
}

// AC3: over the bound, the oldest queued alerts go, and the counter is
// exact. The worker holds alert 1 (in flight, retrying), the queue holds the
// newest 10, and alerts 2..20 are dropped: 19.
func TestAdapter_DropOldestCounterIsExactWhenTheBoundIsExceeded(t *testing.T) {
	pub := &outagePub{down: true}
	a := newRunningAdapter(t, pub, func(c *Config) { c.BufferMaxAlerts = 10 })
	post(t, a, "/falco/"+testToken, "application/json", alertN(t, 1))
	waitFor(t, "the worker to hold alert 1", func() bool { return pub.nAttempts() > 0 })
	for i := 2; i <= 30; i++ {
		if rec := post(t, a, "/falco/"+testToken, "application/json", alertN(t, i)); rec.Code != http.StatusNoContent {
			t.Fatalf("alert %d: code %d; a full buffer still acknowledges", i, rec.Code)
		}
	}
	if got := a.BufferDropped(); got != 19 {
		t.Fatalf("BufferDropped = %d, want exactly 19 (30 received, 1 in flight, 10 queued)", got)
	}
	if a.BufferDepth() != 10 {
		t.Errorf("BufferDepth = %d, want 10", a.BufferDepth())
	}

	pub.setDown(false)
	waitFor(t, "11 publishes", func() bool { return len(pub.ids()) == 11 })
	want := []string{eventID(t, 1)}
	for i := 21; i <= 30; i++ {
		want = append(want, eventID(t, i))
	}
	if got := pub.ids(); !equalIDs(got, want) {
		t.Errorf("published %v\nwant alert 1 then 21..30 %v", got, want)
	}
	if int64(len(pub.ids()))+a.BufferDropped() != a.AlertsReceivedTotal() {
		t.Errorf("published %d + dropped %d != received %d", len(pub.ids()), a.BufferDropped(), a.AlertsReceivedTotal())
	}
}

// The byte bound uses the marshalled event size, what NATS would store.
func TestAdapter_ByteBoundCountsMarshalledEventSize(t *testing.T) {
	pub := &outagePub{down: true}
	a := newRunningAdapter(t, pub, func(c *Config) { c.BufferMaxAlerts = 1000; c.BufferMaxBytes = 1 })
	post(t, a, "/falco/"+testToken, "application/json", alertN(t, 1))
	if a.BufferDropped() != 1 {
		t.Errorf("an alert bigger than a 1-byte bound was not dropped: BufferDropped=%d", a.BufferDropped())
	}
}

// AC7: shutdown stops accepting, then drains what it holds.
func TestRun_ShutdownDrainsTheBuffer(t *testing.T) {
	pub := &outagePub{down: true}
	a := newTestAdapter(t, pub, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	waitFor(t, "listener", func() bool { return a.Addr() != "" })
	for i := 1; i <= 5; i++ {
		resp, err := http.Post("http://"+a.Addr()+"/falco/"+testToken, "application/json", bytes.NewReader(alertN(t, i)))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("alert %d: %d", i, resp.StatusCode)
		}
	}
	cancel()
	pub.setDown(false)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not return")
	}
	if len(pub.ids()) != 5 || a.ShutdownLost() != 0 {
		t.Errorf("published %d, lost %d; want 5 published, 0 lost", len(pub.ids()), a.ShutdownLost())
	}
}

// AC7: when NATS stays down past the drain budget, the loss is counted,
// including the alert the worker was holding.
func TestRun_ShutdownCountsWhatItCouldNotDrain(t *testing.T) {
	pub := &outagePub{down: true}
	a := newTestAdapter(t, pub, func(c *Config) { c.ShutdownDrain = 100 * time.Millisecond })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	waitFor(t, "listener", func() bool { return a.Addr() != "" })
	for i := 1; i <= 5; i++ {
		resp, err := http.Post("http://"+a.Addr()+"/falco/"+testToken, "application/json", bytes.NewReader(alertN(t, i)))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	waitFor(t, "a publish attempt", func() bool { return pub.nAttempts() > 0 })
	start := time.Now()
	cancel()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not return with NATS down")
	}
	if d := time.Since(start); d > 8*time.Second {
		t.Errorf("shutdown took %s with a 100ms drain budget", d)
	}
	if a.ShutdownLost() != 5 {
		t.Errorf("ShutdownLost = %d, want 5 (queued plus in flight)", a.ShutdownLost())
	}
}

// After shutdown has begun the adapter no longer accepts alerts; 503 tells
// Falco (and its log) that this one was not taken.
func TestHandler_RefusesAlertsOnceShutdownHasBegun(t *testing.T) {
	a := newTestAdapter(t, &outagePub{}, nil)
	a.buf.close()
	if rec := post(t, a, "/falco/"+testToken, "application/json", alertN(t, 1)); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("code = %d, want 503 after close", rec.Code)
	}
}

func TestNew_BufferDefaults(t *testing.T) {
	a := newTestAdapter(t, &outagePub{}, nil)
	if a.cfg.BufferMaxAlerts != 4096 || a.cfg.BufferMaxBytes != 16<<20 || a.cfg.ShutdownDrain != 10*time.Second {
		t.Errorf("defaults = %d alerts, %d bytes, drain %s; want 4096, 16 MiB, 10s", a.cfg.BufferMaxAlerts, a.cfg.BufferMaxBytes, a.cfg.ShutdownDrain)
	}
}
