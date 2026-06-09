package nats

import (
	"context"
	"fmt"
	"os"
	"strconv"
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
		// Duplicates is the at-least-once + server-side dedup
		// window. Adapter publishWithRetry attaches the event ID
		// as the Nats-Msg-Id header so a retry the server already
		// persisted is server-side suppressed. Two minutes covers
		// the bounded inner-retry budget (~9s) plus generous slack
		// for cross-pod re-publishes on a brief NATS partition.
		// Locked in by TestStreamConfigsCoversNetworkFlowSubject.
		Duplicates: 2 * time.Minute,
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
	{
		// OVERRIDES carries the Story 2.7 operator-override applied/rejected
		// events (subjects.OverridesApplied). The architecture pins a 365-day
		// retention (architecture.md:238 "OVERRIDES.applied | 365 days") so an
		// operator can audit which workloads were manually pinned over the past
		// year. LimitsPolicy + FileStorage like the other streams. The
		// controller publishes with jetstream.WithMsgID so a poll re-emit is
		// server-side deduplicated within the dedup window.
		Name:       "OVERRIDES",
		Subjects:   []string{subjects.OverridesApplied},
		MaxAge:     365 * 24 * time.Hour,
		Storage:    jetstream.FileStorage,
		Retention:  jetstream.LimitsPolicy,
		Duplicates: 2 * time.Minute,
	},
	{
		// AUDIT_TRANSITIONS carries the Story 2.8 append-only SIEM audit copy of
		// every FSM state change (subjects.AuditTransitions, FR40). Retention
		// defaults to 90 days (AC4): this reconciles the architecture's
		// generalised "AUDIT.* 365 d" table (architecture.md:239) with the AC's
		// specific 90 d, which matches the STATE_TRANSITIONS.applied operational
		// audit-trail row. Retention is Helm-tunable via StreamConfigsWithAudit.
		// Retention is LimitsPolicy NOT Interest/WorkQueue: NFR16 requires the
		// audit subjects be append-only (consumers cannot delete events), and
		// only LimitsPolicy keeps messages until MaxAge regardless of consumer
		// ack. The transitions sink publishes with jetstream.WithMsgID so a
		// drainer re-publish is server-side deduplicated within the window.
		Name:       "AUDIT_TRANSITIONS",
		Subjects:   []string{subjects.AuditTransitions},
		MaxAge:     defaultAuditTransitionsMaxAge,
		Storage:    jetstream.FileStorage,
		Retention:  jetstream.LimitsPolicy,
		Duplicates: 2 * time.Minute,
	},
	{
		// AUDIT_OVERRIDES carries the Story 2.8 append-only SIEM audit copy of
		// every operator override application/rejection (subjects.AuditOverrides,
		// FR40), the SIEM sibling of OVERRIDES.applied. 365 d retention (AC4),
		// LimitsPolicy (NFR16 append-only), Helm-tunable. The override controller
		// publishes with the same WithMsgID derivation as the operational subject
		// so a poll re-emit is deduplicated.
		Name:       "AUDIT_OVERRIDES",
		Subjects:   []string{subjects.AuditOverrides},
		MaxAge:     defaultAuditOverridesMaxAge,
		Storage:    jetstream.FileStorage,
		Retention:  jetstream.LimitsPolicy,
		Duplicates: 2 * time.Minute,
	},
	{
		// AUDIT_POLICIES carries the Story 2.8 append-only SIEM audit copy of
		// every NetworkPolicy mutation (subjects.AuditPolicies, FR40). 365 d
		// retention (AC4), LimitsPolicy (NFR16 append-only), Helm-tunable.
		Name:       "AUDIT_POLICIES",
		Subjects:   []string{subjects.AuditPolicies},
		MaxAge:     defaultAuditPoliciesMaxAge,
		Storage:    jetstream.FileStorage,
		Retention:  jetstream.LimitsPolicy,
		Duplicates: 2 * time.Minute,
	},
}

// defaultAudit*MaxAge are the Story 2.8 AC4 retention defaults baked into
// streamConfigs. They are the DEFAULTS; an operator tunes each independently
// via StreamConfigsWithAudit (driven from response.audit.retention.* config,
// BI-7/BI-8) so AC4's Helm-tunability is real rather than cosmetic.
const (
	defaultAuditTransitionsMaxAge = 90 * 24 * time.Hour
	defaultAuditOverridesMaxAge   = 365 * 24 * time.Hour
	defaultAuditPoliciesMaxAge    = 365 * 24 * time.Hour
)

// AuditRetention carries the operator-tuned per-subject MaxAge for the three
// Story 2.8 AUDIT_* streams (BI-7). A non-positive field means "leave the
// baked-in default"; StreamConfigsWithAudit substitutes only positive values,
// so a zero-valued AuditRetention is equivalent to StreamConfigs().
type AuditRetention struct {
	Transitions time.Duration
	Overrides   time.Duration
	Policies    time.Duration
}

// auditStreamNames maps each AUDIT_* stream name to the AuditRetention field
// that drives its MaxAge. Used by StreamConfigsWithAudit so the override is
// keyed on the stream contract, not a positional index.
var auditStreamNames = map[string]func(AuditRetention) time.Duration{
	"AUDIT_TRANSITIONS": func(a AuditRetention) time.Duration { return a.Transitions },
	"AUDIT_OVERRIDES":   func(a AuditRetention) time.Duration { return a.Overrides },
	"AUDIT_POLICIES":    func(a AuditRetention) time.Duration { return a.Policies },
}

// StreamConfigs returns a copy of the JetStream stream configurations.
// The outer slice and each entry's Subjects slice are independently duplicated,
// so callers may safely mutate those fields without affecting package state.
// Other reference-typed fields on jetstream.StreamConfig (Mirror, Sources,
// Placement, Republish, etc.) are not currently populated by this package
// and are therefore not deep-copied; if future configurations set them,
// extend the copy to cover those fields.
//
// When the OLT_NATS_STREAM_MAXBYTES_OVERRIDE env var is set to a
// positive int64, every stream's MaxBytes is capped at that value.
// This is the CI/kind escape hatch for Story 1.19 D6: production sums
// to 160 GiB across streams (10 + 50 + 100), which exceeds the kind
// node's 10Gi PVC backing and causes JetStream err 10047 on
// CreateOrUpdateStream. The honest fix is to scale MaxBytes down for
// constrained environments rather than lie to JetStream about
// fileStore.maxSize. Production deployments leave the env var unset
// and size the NATS PVC to accommodate the configured sum.
func StreamConfigs() []jetstream.StreamConfig {
	return streamConfigsWith(AuditRetention{})
}

// StreamConfigsWithAudit returns StreamConfigs() with the three Story 2.8
// AUDIT_* streams' MaxAge overridden by the operator-tuned ar (BI-7/BI-8). A
// non-positive ar field leaves that stream's baked-in default (90/365/365 d).
// The aggregator threads its response.audit.retention.* config in here so
// AC4's Helm-tunability drives the real stream MaxAge; callers that want the
// pure architecture defaults use StreamConfigs() (a zero AuditRetention).
func StreamConfigsWithAudit(ar AuditRetention) []jetstream.StreamConfig {
	return streamConfigsWith(ar)
}

func streamConfigsWith(ar AuditRetention) []jetstream.StreamConfig {
	override := streamMaxBytesOverride()
	out := make([]jetstream.StreamConfig, len(streamConfigs))
	for i, cfg := range streamConfigs {
		c := cfg
		if len(cfg.Subjects) > 0 {
			c.Subjects = append([]string(nil), cfg.Subjects...)
		}
		if override > 0 && (c.MaxBytes == 0 || c.MaxBytes > override) {
			c.MaxBytes = override
		}
		if field, isAudit := auditStreamNames[c.Name]; isAudit {
			if d := field(ar); d > 0 {
				c.MaxAge = d
			}
		}
		out[i] = c
	}
	return out
}

func streamMaxBytesOverride() int64 {
	v := os.Getenv("OLT_NATS_STREAM_MAXBYTES_OVERRIDE")
	if v == "" {
		return 0
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		return 0
	}
	return n
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
