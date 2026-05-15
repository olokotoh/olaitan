package schema

import (
	"encoding/json"
	"time"
)

// EventSource identifies which signal layer produced the event.
type EventSource string

const (
	SourceFalco   EventSource = "falco"
	SourceAudit   EventSource = "audit"
	SourceRuntime EventSource = "runtime"
	SourceNetwork EventSource = "network"
	SourceAppLog  EventSource = "applog"
)

// EventCategory classifies the type of activity.
type EventCategory string

const (
	CategorySyscall   EventCategory = "syscall"
	CategoryAPI       EventCategory = "api"
	CategoryAudit     EventCategory = "audit"
	CategoryLifecycle EventCategory = "lifecycle"
	CategoryFlow      EventCategory = "flow"
	CategoryLog       EventCategory = "log"
)

// PodRef identifies the Kubernetes pod associated with an event.
type PodRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Node      string `json:"node,omitempty"`
	UID       string `json:"uid"`
}

// Event is the normalised event schema. All signal sources produce Events.
//
// Sampled and SamplingRate were added in Story 1.13 to carry the
// per-source rate-limit circuit breaker's degradation state. When the
// breaker is engaged the adapter sets Sampled=true and SamplingRate to
// the fraction in (0, 1] of events being emitted; the correlator
// (Story 1.14) and the DFIR report writer consume these so a sampled
// period is honestly disclosed rather than implying full-fidelity
// coverage. The fields are JSON-omitempty: an unsampled event marshals
// to a byte-identical form against the pre-1.13 wire format, so the
// EVENTS.raw stream's MaxMsgSize budget is unaffected.
type Event struct {
	ID           string          `json:"id"`
	Timestamp    time.Time       `json:"timestamp"`
	Source       EventSource     `json:"source"`
	Pod          PodRef          `json:"pod"`
	Severity     string          `json:"severity,omitempty"`
	Category     EventCategory   `json:"category"`
	Summary      string          `json:"summary"`
	Raw          json.RawMessage `json:"raw,omitempty"`
	Tags         []string        `json:"tags,omitempty"`
	Sampled      bool            `json:"sampled,omitempty"`
	SamplingRate float64         `json:"sampling_rate,omitempty"`
}
