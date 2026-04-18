package nats

import (
	"context"
	"fmt"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/olokotoh/olaitan/internal/subjects"
)

// streamConfigs defines the JetStream persistence streams per the architecture
// contract (EVENTS normalised 24h / 10 GiB, THREATS 7d, EVIDENCE never-expire
// with a defensive MaxBytes cap for disk safety).
var streamConfigs = []jetstream.StreamConfig{
	{
		Name:      "EVENTS",
		Subjects:  []string{subjects.Normalised},
		MaxAge:    24 * time.Hour,
		MaxBytes:  10 * 1024 * 1024 * 1024, // 10 GiB
		Storage:   jetstream.FileStorage,
		Retention: jetstream.LimitsPolicy,
	},
	{
		Name:      "THREATS",
		Subjects:  []string{subjects.ThreatsPrefix + ">"},
		MaxAge:    7 * 24 * time.Hour,
		Storage:   jetstream.FileStorage,
		Retention: jetstream.LimitsPolicy,
	},
	{
		Name:      "EVIDENCE",
		Subjects:  []string{subjects.EvidencePrefix + ">"},
		MaxAge:    0,                        // never auto-expire
		MaxBytes:  100 * 1024 * 1024 * 1024, // 100 GiB safety cap — tune for production
		Storage:   jetstream.FileStorage,
		Retention: jetstream.LimitsPolicy,
	},
}

// StreamConfigs returns a deep copy of the JetStream stream configurations.
// Callers may mutate the returned value without affecting package state.
func StreamConfigs() []jetstream.StreamConfig {
	out := make([]jetstream.StreamConfig, len(streamConfigs))
	for i, cfg := range streamConfigs {
		c := cfg
		if len(cfg.Subjects) > 0 {
			c.Subjects = append([]string(nil), cfg.Subjects...)
		}
		out[i] = c
	}
	return out
}

// EnsureStreams creates or updates the provided JetStream streams.
// Pass StreamConfigs() for the architecture-contract defaults. Tests may
// pass reduced configs to avoid provisioning the full production MaxBytes
// reservation on resource-constrained runners.
func EnsureStreams(ctx context.Context, js jetstream.JetStream, configs []jetstream.StreamConfig) error {
	for _, cfg := range configs {
		if _, err := js.CreateOrUpdateStream(ctx, cfg); err != nil {
			return fmt.Errorf("nats: ensure stream %s: %w", cfg.Name, err)
		}
	}
	return nil
}
