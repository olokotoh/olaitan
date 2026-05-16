package main

import (
	"io"
	"log/slog"
	"testing"

	"github.com/olokotoh/olaitan/internal/ratelimit"
)

func TestBuildAppLogRateLimiter_DefaultsEnabled(t *testing.T) {
	t.Setenv("K8S_NODE_NAME", "node-a")

	l, err := buildAppLogRateLimiter(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("buildAppLogRateLimiter: %v", err)
	}
	if !l.Enabled() {
		t.Fatal("applog sidecar limiter should default to enabled")
	}
	if l.Source() != "applog" {
		t.Fatalf("source: got %q, want applog", l.Source())
	}
	if l.Node() != "node-a" {
		t.Fatalf("node: got %q, want node-a", l.Node())
	}
	if l.Threshold() != ratelimit.DefaultThreshold {
		t.Fatalf("threshold: got %d, want %d", l.Threshold(), ratelimit.DefaultThreshold)
	}
}

func TestBuildAppLogRateLimiter_EnvOverrides(t *testing.T) {
	t.Setenv("K8S_NODE_NAME", "node-a")
	t.Setenv("OLAITAN_RATE_LIMIT_THRESHOLD_EVENTS_PER_SEC", "500")
	t.Setenv("OLAITAN_RATE_LIMIT_COOLDOWN_SECONDS", "30")
	t.Setenv("OLAITAN_RATE_LIMIT_SAMPLING_RATE", "0.005")

	l, err := buildAppLogRateLimiter(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("buildAppLogRateLimiter: %v", err)
	}
	if l.Threshold() != 500 {
		t.Fatalf("threshold: got %d, want 500", l.Threshold())
	}
	if l.Cooldown().Seconds() != 30 {
		t.Fatalf("cooldown: got %s, want 30s", l.Cooldown())
	}
	if l.SamplingRate() != 0.005 {
		t.Fatalf("samplingRate: got %v, want 0.005", l.SamplingRate())
	}
}
