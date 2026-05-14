package main

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/sync/errgroup"

	"github.com/olokotoh/olaitan/internal/config"
	"github.com/olokotoh/olaitan/internal/sourcehealth"
)

// fakeAdapter satisfies the adapterMetrics structural-typed contract
// without dragging in a real adapter and its NATS / gRPC dependencies.
type fakeAdapter struct {
	tracker sourcehealth.Tracker
	events  atomic.Int64
}

func (f *fakeAdapter) Health() sourcehealth.Reader { return &f.tracker }
func (f *fakeAdapter) EventsTotal() int64          { return f.events.Load() }

func quietTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestStartMetricsServer_NilConfigRejected(t *testing.T) {
	t.Parallel()
	g, _ := errgroup.WithContext(context.Background())
	if _, err := startMetricsServer(context.Background(), g, quietTestLogger(), nil, nil, nil); err == nil {
		t.Error("nil config: got nil error, want rejection")
	}
}

func TestStartMetricsServer_EmptyAddressRejected(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{Metrics: config.MetricsConfig{Address: ""}}
	g, _ := errgroup.WithContext(context.Background())
	if _, err := startMetricsServer(context.Background(), g, quietTestLogger(), cfg, nil, nil); err == nil {
		t.Error("empty address: got nil error, want rejection")
	}
}

func TestStartMetricsServer_RegistersStreamingAdapters(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g, gctx := errgroup.WithContext(ctx)
	cfg := &config.Config{
		Metrics: config.MetricsConfig{Address: "127.0.0.1:0"},
	}
	a1, a2 := &fakeAdapter{}, &fakeAdapter{}
	a1.tracker.MarkHealthy()
	a1.events.Store(10)
	a2.events.Store(20)
	sources := map[string]adapterMetrics{
		"falco": a1,
		"audit": a2,
	}

	reg, err := startMetricsServer(gctx, g, quietTestLogger(), cfg, sources, nil)
	if err != nil {
		t.Fatalf("startMetricsServer: %v", err)
	}
	if reg == nil {
		t.Fatal("startMetricsServer returned nil registry")
	}

	// Gather metric families through the gatherer (no HTTP round-trip
	// needed). Verify both adapters' gauges and counters are present.
	mfs, err := reg.Gatherer().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	names := map[string]bool{}
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	wantNames := []string{
		"olaitan_source_healthy",
		"olaitan_sensor_events_total",
		"olaitan_sensor_posture_disabled", // posture disabled by default in cfg
	}
	for _, n := range wantNames {
		if !names[n] {
			t.Errorf("missing metric family %q in %v", n, names)
		}
	}

	cancel()
	_ = g.Wait() // metrics server exits cleanly on ctx cancel
}

func TestStartMetricsServer_PostureDisabledGaugeRegistered(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g, gctx := errgroup.WithContext(ctx)
	cfg := &config.Config{Metrics: config.MetricsConfig{Address: "127.0.0.1:0"}}
	// Posture disabled (default), so posture_disabled gauge appears
	// rather than the six counters.
	reg, err := startMetricsServer(gctx, g, quietTestLogger(), cfg, nil, nil)
	if err != nil {
		t.Fatalf("startMetricsServer: %v", err)
	}

	mfs, _ := reg.Gatherer().Gather()
	found := false
	for _, mf := range mfs {
		if strings.Contains(mf.GetName(), "posture_disabled") {
			found = true
		}
		if strings.Contains(mf.GetName(), "posture_cache_hit_total") {
			t.Errorf("posture_cache_hit_total should not be registered when disabled, got %s", mf.GetName())
		}
	}
	if !found {
		t.Errorf("posture_disabled gauge not registered when posture is disabled")
	}

	cancel()
	_ = g.Wait()
}

func TestStartMetricsServer_DuplicateAdapterRegistrationSurfaces(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g, gctx := errgroup.WithContext(ctx)
	cfg := &config.Config{Metrics: config.MetricsConfig{Address: "127.0.0.1:0"}}
	// Two adapters registered under the same source label simulates a
	// wiring bug; the helper should surface it rather than the
	// metrics server crashing at scrape time.
	a := &fakeAdapter{}
	// Single map can't hold a duplicate key, so we exercise the
	// duplicate path via two sequential calls in the same way the
	// production wiring would (e.g. a future Story 1.14 retry-wires
	// the collector against an already-registered Registry).
	reg, err := startMetricsServer(gctx, g, quietTestLogger(), cfg,
		map[string]adapterMetrics{"falco": a}, nil)
	if err != nil {
		t.Fatalf("startMetricsServer: %v", err)
	}
	if err := reg.RegisterAdapter("falco", a.Health(), a.EventsTotal); err == nil {
		t.Error("duplicate RegisterAdapter: got nil error, want rejection")
	}

	cancel()
	_ = g.Wait()
}

func TestRegisterAdapterCounters_FalcoIsNoOp(t *testing.T) {
	t.Parallel()
	// Falco only contributes the source_healthy / sensor_events_total
	// pair; detail counters are nil. Asserts the switch path does not
	// fall through to a misregistered counter or panic on the
	// pseudo-default case.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g, gctx := errgroup.WithContext(ctx)
	cfg := &config.Config{Metrics: config.MetricsConfig{Address: "127.0.0.1:0"}}
	a := &fakeAdapter{}
	reg, err := startMetricsServer(gctx, g, quietTestLogger(), cfg,
		map[string]adapterMetrics{"falco": a}, nil)
	if err != nil {
		t.Fatalf("startMetricsServer: %v", err)
	}
	if err := registerAdapterCounters(reg, "falco", a); err != nil {
		t.Errorf("registerAdapterCounters(falco) returned %v on a fake adapter, want nil (no-op fall-through)", err)
	}
	cancel()
	_ = g.Wait()
}

func TestStartMetricsServer_PropagatesRegistrationError(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g, gctx := errgroup.WithContext(ctx)
	cfg := &config.Config{Metrics: config.MetricsConfig{Address: "127.0.0.1:0"}}

	// Bare empty-source-label key triggers the RegisterAdapter "empty
	// source" rejection. The helper must surface this rather than
	// proceeding to bind a server on a half-registered registry.
	a := &fakeAdapter{}
	_, err := startMetricsServer(gctx, g, quietTestLogger(), cfg,
		map[string]adapterMetrics{"": a}, nil)
	if err == nil {
		t.Errorf("startMetricsServer with empty source: got nil error, want propagation of RegisterAdapter rejection")
	}
	// Defensive: ensure the surface error chain contains the helper
	// boundary prefix.
	if err != nil && !strings.Contains(err.Error(), "register adapter") {
		t.Errorf("error does not wrap RegisterAdapter boundary: %v", err)
	}

	// Sanity: errgroup did not start a server on the empty-config
	// path (no goroutines to wait on).
	cancel()
	_ = g.Wait()
}
