package rules

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

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

// TestNew_RejectsNilNATS asserts that New() returns an explicit
// error when the NATS client is nil, before any metric registration
// runs. Renamed from TestNew_RegistersAllMetrics in code-review P7:
// the prior name claimed coverage that was never exercised (the
// nil-NATS branch short-circuits before registerMetrics). The
// happy-path metric registration is covered by
// TestNew_HappyPathWithMetricsRegistry below.
func TestNew_RejectsNilNATS(t *testing.T) {
	dir := t.TempDir()
	l := loader.New(dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := l.Load(); err != nil {
		t.Fatalf("loader.Load: %v", err)
	}
	reg := metrics.NewRegistry()
	e, err := New(Config{
		NATS:    nil,
		Loader:  l,
		Emitter: stubEmitter{},
		Metrics: reg,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
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
	// Story 1.18 added matches_by_attribute_total alongside the
	// Story 1.15 families. The CounterVec is registered but won't
	// surface in Gather() until at least one series is observed; the
	// .Add(0) primes the family so it materialises during Gather
	// without affecting per-label counts.
	e.matchesVec.WithLabelValues("OLT-TEST", "low", "T0000").Add(0)
	// Gather to confirm registration succeeded.
	mfs, err := reg.Gatherer().Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	want := map[string]bool{
		"olaitan_decision_rules_loaded":                     false,
		"olaitan_decision_rules_evaluations_total":          false,
		"olaitan_decision_rules_matches_total":              false,
		"olaitan_decision_rules_matches_by_attribute_total": false,
		"olaitan_decision_rules_reloads_total":              false,
		"olaitan_decision_rules_skipped_self_total":         false,
		"olaitan_decision_rules_evaluation_seconds":         false,
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

// TestBumpMatchesVec_FansOutPerTechnique covers Story 1.18 AC2 / BI-4:
// a RuleMatch carrying N MitreTags increments matches_by_attribute_total
// N times, once per (rule_id, severity_bucket, attack_technique)
// triple. An empty MitreTags slice emits one bump with the "unknown"
// sentinel.
func TestBumpMatchesVec_FansOutPerTechnique(t *testing.T) {
	dir := t.TempDir()
	l := loader.New(dir, nil)
	if err := l.Load(); err != nil {
		t.Fatalf("loader.Load: %v", err)
	}
	reg := metrics.NewRegistry()
	e, err := New(Config{
		NATS: &natsclient.Client{}, Loader: l, Emitter: stubEmitter{}, Metrics: reg,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Single technique -> one bump under (rule_id, bucket, technique).
	e.bumpMatchesVec(schema.RuleMatch{RuleID: "OLT-PRIV-001", Severity: "90", MitreTags: []string{"T1611"}})
	if got := testutil.ToFloat64(e.matchesVec.WithLabelValues("OLT-PRIV-001", "critical", "T1611")); got != 1 {
		t.Errorf("single-tech (critical, T1611) = %v, want 1", got)
	}

	// Multi-technique rule -> one bump per technique.
	e.bumpMatchesVec(schema.RuleMatch{RuleID: "OLT-NET-002", Severity: "75", MitreTags: []string{"T1071", "T1071.001"}})
	if got := testutil.ToFloat64(e.matchesVec.WithLabelValues("OLT-NET-002", "high", "T1071")); got != 1 {
		t.Errorf("multi-tech (high, T1071) = %v, want 1", got)
	}
	if got := testutil.ToFloat64(e.matchesVec.WithLabelValues("OLT-NET-002", "high", "T1071.001")); got != 1 {
		t.Errorf("multi-tech (high, T1071.001) = %v, want 1", got)
	}

	// Empty MitreTags -> one bump with "unknown" sentinel.
	e.bumpMatchesVec(schema.RuleMatch{RuleID: "OLT-NOTAG", Severity: "10", MitreTags: nil})
	if got := testutil.ToFloat64(e.matchesVec.WithLabelValues("OLT-NOTAG", "low", "unknown")); got != 1 {
		t.Errorf("empty-tags (low, unknown) = %v, want 1", got)
	}

	// Invalid severity string -> "low" bucket (defensive).
	e.bumpMatchesVec(schema.RuleMatch{RuleID: "OLT-BADSEV", Severity: "abc", MitreTags: []string{"T9999"}})
	if got := testutil.ToFloat64(e.matchesVec.WithLabelValues("OLT-BADSEV", "low", "T9999")); got != 1 {
		t.Errorf("bad-severity (low, T9999) = %v, want 1", got)
	}
}
