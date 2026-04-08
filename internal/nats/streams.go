package nats

import (
	"context"
	"fmt"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// streamConfigs defines JetStream persistence streams.
var streamConfigs = []jetstream.StreamConfig{
	{
		Name:      "EVENTS",
		Subjects:  []string{"olaitan.events.>"},
		MaxAge:    24 * time.Hour,
		Storage:   jetstream.FileStorage,
		Retention: jetstream.LimitsPolicy,
	},
	{
		Name:      "THREATS",
		Subjects:  []string{"olaitan.threats.>", "olaitan.correlated.>"},
		MaxAge:    7 * 24 * time.Hour,
		Storage:   jetstream.FileStorage,
		Retention: jetstream.LimitsPolicy,
	},
	{
		Name:      "EVIDENCE",
		Subjects:  []string{"olaitan.state.>", "olaitan.health.>"},
		MaxAge:    0, // permanent
		Storage:   jetstream.FileStorage,
		Retention: jetstream.LimitsPolicy,
	},
}

// StreamConfigs returns a copy of the JetStream stream configurations.
func StreamConfigs() []jetstream.StreamConfig {
	out := make([]jetstream.StreamConfig, len(streamConfigs))
	copy(out, streamConfigs)
	return out
}

// EnsureStreams creates or updates all JetStream streams.
func EnsureStreams(ctx context.Context, js jetstream.JetStream) error {
	for _, cfg := range streamConfigs {
		_, err := js.CreateOrUpdateStream(ctx, cfg)
		if err != nil {
			return fmt.Errorf("nats: ensure stream %s: %w", cfg.Name, err)
		}
	}
	return nil
}
