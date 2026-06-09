package override

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// Rejection reason label values (BI-5). state_unavailable distinguishes a
// real-but-unimplemented state (PRESERVED_KILLED, Epic 4) from a typo'd state
// (invalid_state) so operators can tell the two apart.
const (
	ReasonStateUnavailable = "state_unavailable"
	ReasonInvalidState     = "invalid_state"
)

// OverrideApplied is the OVERRIDES.applied event payload (BI-10). It is the
// new wire shape this story introduces (docs/schema-versioning.md). It carries
// both the applied (rejected:false) and rejected (rejected:true) cases.
type OverrideApplied struct {
	SchemaVersion  string    `json:"schema_version"`
	WorkloadID     string    `json:"workload_id"`
	RequestedState string    `json:"requested_state"`
	BeforeState    string    `json:"before_state"`
	TTLSeconds     int       `json:"ttl_seconds"`
	OperatorID     string    `json:"operator_id,omitempty"`
	Source         string    `json:"source"`
	Rejected       bool      `json:"rejected"`
	Reason         string    `json:"reason,omitempty"`
	PublishedAt    time.Time `json:"published_at"`
	// AppliedAtNs is the override's applied-at nanosecond timestamp, used in
	// the dedup message id so a poll re-emit is server-side deduplicated.
	AppliedAtNs int64 `json:"applied_at_ns"`
}

// OverridePublisher is the one-method publish seam (BI-10) so the controller's
// tests can inject a fake without a real NATS connection.
type OverridePublisher interface {
	PublishOverride(ctx context.Context, evt OverrideApplied) error
}

// natsOverridePublisher publishes OverrideApplied events to
// subjects.OverridesApplied via PublishJS with a per-(workload, applied_at)
// dedup id, so a poll re-emit of the same override is suppressed inside the
// OVERRIDES stream's dedup window.
type natsOverridePublisher struct {
	nc *natsclient.Client
}

// NewNATSPublisher returns an OverridePublisher backed by the shared NATS
// client. A nil client is a construction error.
func NewNATSPublisher(nc *natsclient.Client) (OverridePublisher, error) {
	if nc == nil {
		return nil, fmt.Errorf("override: nil nats client")
	}
	return &natsOverridePublisher{nc: nc}, nil
}

// PublishOverride publishes evt to OVERRIDES.applied with WithMsgID dedup.
func (p *natsOverridePublisher) PublishOverride(ctx context.Context, evt OverrideApplied) error {
	if evt.SchemaVersion == "" {
		evt.SchemaVersion = SchemaVersionOverride
	}
	if evt.PublishedAt.IsZero() {
		evt.PublishedAt = time.Now().UTC()
	}
	msgID := evt.WorkloadID + ":" + strconv.FormatInt(evt.AppliedAtNs, 10)
	if evt.Rejected {
		// A rejection carries no applied_at; key the dedup on the rejection
		// reason + requested state so distinct rejections are not collapsed.
		msgID = evt.WorkloadID + ":rejected:" + evt.Reason + ":" + evt.RequestedState
	}
	if _, err := p.nc.PublishJS(ctx, subjects.OverridesApplied, evt, jetstream.WithMsgID(msgID)); err != nil {
		return fmt.Errorf("override: publish applied: %w", err)
	}
	return nil
}

// validOverrideTarget reports whether s is one of the four reachable Epic-2
// states an operator may pin a workload to (BI-5). PRESERVED_KILLED (Epic 4)
// and any unknown value are rejected. Mirrors the fsm package's internal
// guard; kept local so the override controller can pre-filter rejections and
// assign the distinct reason label before calling Machine.Pin.
func validOverrideTarget(s schema.PodSecurityState) bool {
	switch s {
	case schema.StateClean, schema.StateSuspicious, schema.StateRestricted, schema.StateQuarantined:
		return true
	default:
		return false
	}
}

// stateOrder ranks the four reachable states for the most-isolating tie-break
// (BI-9). Higher is more isolating. An unknown state ranks -1 so it never wins
// a tie-break (it is rejected separately).
func stateOrder(s schema.PodSecurityState) int {
	switch s {
	case schema.StateClean:
		return 0
	case schema.StateSuspicious:
		return 1
	case schema.StateRestricted:
		return 2
	case schema.StateQuarantined:
		return 3
	default:
		return -1
	}
}
