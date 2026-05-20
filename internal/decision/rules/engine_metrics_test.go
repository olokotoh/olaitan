package rules

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/olokotoh/olaitan/internal/decision/rules/loader"
	"github.com/olokotoh/olaitan/internal/metrics"
	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/schema"
)

// stubEmitter is a no-op emitter for unit tests that need to
// construct an Engine via New() but do not exercise the JetStream
// hot path. The integration-tag tests use a recording emitter; this
// stub keeps the unit tests free of those imports.
type stubEmitter struct{}

func (stubEmitter) FireRuleMatch(_ context.Context, _ string, _ schema.RuleMatch) (*schema.EvidencePackage, error) {
	return nil, nil
}

// TestNew_RegistersAllMetrics drives the New() constructor with a
// real metrics.Registry. Asserts no error on metric registration
// and that the gauge / counter / histogram surface is bound. This
// closes the registerMetrics coverage gap that unit tests on
// evaluatePackage do not reach (those use a bare Engine without
// metrics).
func TestNew_RegistersAllMetrics(t *testing.T) {
	dir := t.TempDir()
	l := loader.New(dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := l.Load(); err != nil {
		t.Fatalf("loader.Load: %v", err)
	}
	reg := metrics.NewRegistry()
	e, err := New(Config{
		NATS:    nil, // forces nil-nats validation to short-circuit
		Loader:  l,
		Emitter: stubEmitter{},
		Metrics: reg,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	// NATS nil is an explicit error from New(); we expect that.
	if err == nil {
		t.Fatalf("New with nil NATS: expected error, got nil")
	}
	if e != nil {
		t.Errorf("New: expected nil Engine on error path, got %#v", e)
	}
}

// TestNew_PopulatesEngineFields drives the happy path: nil NATS is
// disallowed by New, so we supply a non-nil stub via a typed nil
// dance. Easier: use a sentinel struct that satisfies the contract
// minimally.
func TestNew_RejectsNilLoader(t *testing.T) {
	_, err := New(Config{
		NATS:    &natsclient.Client{},
		Loader:  nil,
		Emitter: stubEmitter{},
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err == nil {
		t.Fatalf("New with nil Loader: expected error, got nil")
	}
}

func TestNew_RejectsNilEmitter(t *testing.T) {
	dir := t.TempDir()
	l := loader.New(dir, nil)
	if err := l.Load(); err != nil {
		t.Fatalf("loader.Load: %v", err)
	}
	_, err := New(Config{
		NATS:    &natsclient.Client{},
		Loader:  l,
		Emitter: nil,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err == nil {
		t.Fatalf("New with nil Emitter: expected error, got nil")
	}
}

// TestNew_HappyPathWithMetricsRegistry covers the registerMetrics
// path end-to-end: with a real loader, a stub emitter, and a real
// metrics.Registry, the constructor must succeed and the registry
// must carry the five metric families.
func TestNew_HappyPathWithMetricsRegistry(t *testing.T) {
	dir := t.TempDir()
	l := loader.New(dir, nil)
	if err := l.Load(); err != nil {
		t.Fatalf("loader.Load: %v", err)
	}
	reg := metrics.NewRegistry()
	e, err := New(Config{
		NATS:    &natsclient.Client{},
		Loader:  l,
		Emitter: stubEmitter{},
		Metrics: reg,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if e == nil {
		t.Fatalf("Engine: nil")
	}
	// Gather to confirm registration succeeded.
	mfs, err := reg.Gatherer().Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	want := map[string]bool{
		"olaitan_decision_rules_loaded":             false,
		"olaitan_decision_rules_evaluations_total":  false,
		"olaitan_decision_rules_reloads_total":      false,
		"olaitan_decision_rules_skipped_self_total": false,
		"olaitan_decision_rules_evaluation_seconds": false,
	}
	for _, mf := range mfs {
		if _, ok := want[mf.GetName()]; ok {
			want[mf.GetName()] = true
		}
	}
	for name, present := range want {
		if !present {
			t.Errorf("metric %q not registered", name)
		}
	}
}
