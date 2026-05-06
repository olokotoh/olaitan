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
//
// EVENTS_RAW was added by Story 1.6 to give the per-source raw subjects
// (subjects.RawPrefix + ">") at-least-once semantics. The retention budget
// is sized for the correlator's 60s sliding window: raw events older than
// the window are dead weight, but 6h gives generous slack for replay during
// debugging plus a buffer if the correlator is briefly behind. 50 GiB caps
// disk pressure at roughly 1000 events/sec/source × 5 sources × ~250 bytes
// × 6h while keeping the bound defensive.
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
		Name:     "EVENTS_RAW",
		Subjects: []string{subjects.RawPrefix + ">"},
		MaxAge:   6 * time.Hour,
		MaxBytes: 50 * 1024 * 1024 * 1024, // 50 GiB; see comment block above
		// MaxMsgSize caps each individual event at 256 KiB. A
		// well-formed Falco / audit / CNI event sits comfortably under
		// 4 KiB; a runaway rule emitting a multi-MiB output_fields blob
		// would otherwise produce perpetual publish failures and tight
		// retry loops in the adapter. The cap fails such messages
		// loudly at PublishJS time so the adapter can log+drop rather
		// than wedge the consume loop.
		MaxMsgSize: 256 * 1024,
		Storage:    jetstream.FileStorage,
		Retention:  jetstream.LimitsPolicy,
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
		MaxBytes:  100 * 1024 * 1024 * 1024, // 100 GiB safety cap, tune for production
		Storage:   jetstream.FileStorage,
		Retention: jetstream.LimitsPolicy,
	},
}

// StreamConfigs returns a copy of the JetStream stream configurations.
// The outer slice and each entry's Subjects slice are independently duplicated,
// so callers may safely mutate those fields without affecting package state.
// Other reference-typed fields on jetstream.StreamConfig (Mirror, Sources,
// Placement, Republish, etc.) are not currently populated by this package
// and are therefore not deep-copied; if future configurations set them,
// extend the copy to cover those fields.
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
