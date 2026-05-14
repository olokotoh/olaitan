package falco

import (
	"context"
	"testing"
	"time"

	natsjs "github.com/nats-io/nats.go/jetstream"

	"github.com/olokotoh/olaitan/internal/retry"
)

// stubPub is a no-op natsPublisher for unit tests of New()/Health().
// Integration tests use the real *natsclient.Client against an embedded
// NATS server (see falco_integration_test.go).
type stubPub struct{}

func (stubPub) PublishJS(ctx context.Context, subject string, data any, opts ...natsjs.PublishOpt) (*natsjs.PubAck, error) {
	return &natsjs.PubAck{Stream: "EVENTS_RAW"}, nil
}

func TestNew_RejectsNilPublisher(t *testing.T) {
	_, err := New(Config{Endpoint: "unix:///run/falco/falco.sock", Hostname: "node"}, nil, nil)
	if err == nil {
		t.Fatal("New(nil pub): expected error, got nil")
	}
}

func TestNew_RejectsEmptyEndpoint(t *testing.T) {
	_, err := New(Config{Hostname: "node"}, stubPub{}, nil)
	if err == nil {
		t.Fatal("New(empty endpoint): expected error")
	}
}

func TestNew_RejectsEmptyHostname(t *testing.T) {
	_, err := New(Config{Endpoint: "unix:///x"}, stubPub{}, nil)
	if err == nil {
		t.Fatal("New(empty hostname): expected error")
	}
}

func TestNew_AppliesDefaultRetryWhenZeroValued(t *testing.T) {
	a, err := New(Config{Endpoint: "unix:///x", Hostname: "node"}, stubPub{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.cfg.Retry.Min == 0 {
		t.Error("New: zero-value Retry should have been replaced with DefaultRetry()")
	}
	d := DefaultRetry()
	if a.cfg.Retry.Min != d.Min || a.cfg.Retry.Max != d.Max {
		t.Errorf("DefaultRetry not applied: got %v, want %v", a.cfg.Retry, d)
	}
}

func TestNew_PreservesCallerSuppliedRetry(t *testing.T) {
	custom := retry.Strategy{Min: 100 * time.Millisecond, Max: 500 * time.Millisecond, Multiplier: 1.5, Jitter: 0, MaxAttempts: 3}
	a, err := New(Config{Endpoint: "unix:///x", Hostname: "node", Retry: custom}, stubPub{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.cfg.Retry.Min != custom.Min || a.cfg.Retry.MaxAttempts != custom.MaxAttempts {
		t.Errorf("New overwrote caller Retry: got %+v, want %+v", a.cfg.Retry, custom)
	}
}

func TestHealth_ReturnsTrackerInZeroState(t *testing.T) {
	a, err := New(Config{Endpoint: "unix:///x", Hostname: "node"}, stubPub{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := a.Health()
	if h == nil {
		t.Fatal("Health() returned nil")
	}
	healthy, herr := h.Status()
	if healthy {
		t.Error("zero-state Adapter should report unhealthy")
	}
	if herr != nil {
		t.Errorf("zero-state lastErr should be nil, got %v", herr)
	}
}

// Lifecycle / Run-loop verification (ctx-cancel exits cleanly,
// dial-and-retry, translate-and-publish) is covered by the bufconn +
// embedded-NATS integration test in falco_integration_test.go landed
// under Task 8. The unit tests above stop at config-time invariants so
// this file does not depend on the gRPC plumbing.

func TestEventsTotal_ZeroOnConstruct(t *testing.T) {
	a, err := New(Config{Endpoint: "unix:///x", Hostname: "node"}, stubPub{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := a.EventsTotal(); got != 0 {
		t.Errorf("EventsTotal on fresh Adapter: got %d, want 0", got)
	}
}

func TestEventsTotal_IncrementsOnPublishSuccess(t *testing.T) {
	a, err := New(Config{Endpoint: "unix:///x", Hostname: "node"}, stubPub{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Direct atomic increments simulate the inline a.eventsPublished.Add(1)
	// in the publishWithRetry success path; the full receive loop is
	// covered in the integration test. This unit gates the getter
	// contract independent of the gRPC plumbing.
	a.eventsPublished.Add(3)
	if got := a.EventsTotal(); got != 3 {
		t.Errorf("EventsTotal after Add(3): got %d, want 3", got)
	}
}
