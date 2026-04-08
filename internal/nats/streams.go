package nats

import (
	"fmt"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// Stream definitions for JetStream persistence.
var StreamConfigs = []jetstream.StreamConfig{
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

// EnsureStreams creates or updates all JetStream streams.
func EnsureStreams(js jetstream.JetStream) error {
	for _, cfg := range StreamConfigs {
		_, err := js.CreateOrUpdateStream(ctx(), cfg)
		if err != nil {
			return fmt.Errorf("nats: ensure stream %s: %w", cfg.Name, err)
		}
	}
	return nil
}
