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
type Event struct {
	ID        string          `json:"id"`
	Timestamp time.Time       `json:"timestamp"`
	Source    EventSource     `json:"source"`
	Pod       PodRef          `json:"pod"`
	Severity  string          `json:"severity,omitempty"`
	Category  EventCategory   `json:"category"`
	Summary   string          `json:"summary"`
	Raw       json.RawMessage `json:"raw,omitempty"`
	Tags      []string        `json:"tags,omitempty"`
}
