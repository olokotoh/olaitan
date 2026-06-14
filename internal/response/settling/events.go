// Package settling hosts the Story 4.3 settling-window controller (FR42/NFR7),
// the Ring-4 (response) seam that decides WHEN a workload's incident is
// "settled" and ready for a DFIR post-mortem. It is a fsm.TransitionSink
// appended to the existing fsm.MultiSink (the Story 4.2 forensics controller
// precedent): every actual FSM transition is fanned out to it, and it arms a
// per-workload timer that fires only when the workload has been stable in a
// non-CLEAN state for the configured settling window (default 60 s). On fire it
// publishes one IncidentFinalised event to the INCIDENTS.finalised subject; the
// Story 4.4 DFIR agent consumes that event as its invocation trigger.
//
// SCOPE FENCE (Story 4.3 BI-10): this package produces ONLY the finalisation
// EVENT. It does NOT build the DFIR agent, the ForensicReport schema, the
// Markdown report (Story 4.4), persistence-side redaction (Story 4.5), or the
// S3 report writer (Story 4.6). It MUST NOT touch the reserved 4.4 DFIR seams
// (RoleDFIR, dfir.txt, internal/report/dfir/).
//
// Ring discipline: this package may import substrate (internal/schema,
// internal/nats, internal/subjects) and same-ring sibling TYPES
// (internal/response/fsm). It MUST NOT import Ring 1 collectors or Ring 5
// report packages.
package settling

import (
	"time"

	"github.com/olokotoh/olaitan/internal/schema"
)

// SchemaVersionIncidentFinalised is stamped on every IncidentFinalised wire
// event per the architecture's schema-versioning ADR (architecture.md:244,
// docs/schema-versioning.md). It versions independently of the AUDIT.* subjects
// (the audit.transitions.v1 precedent).
const SchemaVersionIncidentFinalised = "incidents.finalised.v1"

// IncidentFinalised is the INCIDENTS.finalised wire event (schema_version
// incidents.finalised.v1): the Story 4.3 settling-window finalisation trigger
// (AC3). It is published when a workload's FSM has been stable in a non-CLEAN
// state for the full settling window. The Story 4.4 DFIR agent consumes it.
//
// The five AC3 payload fields are carried literally on the wire so a consumer
// needs no rename map: package_id and workload_id from the surviving candidate
// schema.StateTransition; final_state = the surviving candidate ToState;
// threat_score = the Confidence (ConfidenceScore.Total) on that transition,
// captured at the moment the final state was entered and NOT re-sampled at
// expiry (BI-7); history = the full []schema.StateTransition, sourced from the
// persisted Redis-backed FSM history list (restart-safe) when a Store reader is
// wired, else the transitions observed in-process (Open Assumption 2).
//
// finalised_at is the controller's clock at timer expiry. It is the second half
// of the JetStream WithMsgID discriminator (package_id + finalising-transition
// timestamp) so a drainer re-publish / restart-replay within the dedup window
// is suppressed, while a legitimately NEW incident for the same workload after
// a CLEAN cycle (a distinct finalising transition) is NOT suppressed (BI-8,
// Open Assumption 5).
//
// Authoritative validation source: docs/schemas/incidents/finalised.json.
type IncidentFinalised struct {
	SchemaVersion string `json:"schema_version"`
	// PackageID is the EvidencePackage idempotency key that drove the
	// evaluation establishing the final state (schema.StateTransition.PackageID).
	PackageID string `json:"package_id"`
	// WorkloadID is the WorkloadIdentity canonical string the FSM keyed the
	// incident on (schema.StateTransition.WorkloadID).
	WorkloadID string `json:"workload_id"`
	// FinalState is the surviving candidate ToState the workload settled in
	// (one of the four non-CLEAN states; CLEAN never finalises, AC4).
	FinalState string `json:"final_state"`
	// ThreatScore is the Confidence (ConfidenceScore.Total) on the transition
	// that established the final state, captured at entry, NOT re-sampled (BI-7).
	ThreatScore float64 `json:"threat_score"`
	// FinalisedAt is the controller clock at settling-window expiry; the second
	// half of the dedup discriminator (BI-8).
	FinalisedAt time.Time `json:"finalised_at"`
	// History is the full FSM transition history for the workload, the durable
	// carrier being the Redis fsm:{workload_id}:history list (cap 1000). May be
	// empty if the persisted history could not be read AND no transitions were
	// observed in-process (the controller never blocks finalisation on history).
	History []schema.StateTransition `json:"history"`
}
