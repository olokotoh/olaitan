package falco

import "sync/atomic"

// SourceHealth is an in-process health tracker for the Falco signal
// source. Story 1.6 surfaces this struct via Adapter.Health() so the
// retry loop can mark the source unhealthy on any connect-or-stream
// failure and healthy again on the next successful receipt; Story 1.12
// (per-source health and event metrics surface) binds the tracker to a
// Prometheus gauge `source_healthy{source="falco"}` per FR8.
//
// Why an in-process tracker rather than introducing Prometheus here:
// the FR8 ownership split documented in architecture.md (§
// "Observability surface") assigns per-source state to
// `internal/collector/*/health.go` and the unified /metrics endpoint to
// `cmd/olaitan/metrics.go` (Story 1.12). Bringing in
// `prometheus/client_golang` in this story would pre-empt Story 1.12's
// metric-naming and endpoint-routing decisions for all five sources at
// once, which is exactly the kind of premature commitment the
// story-driven decomposition is meant to prevent.
//
// Concurrency contract: state is held in a single atomic.Pointer to a
// value-type snapshot, so Status() is a single atomic load and a
// reader can never observe a torn (healthy, lastErr) tuple. Multiple
// goroutines may read via Status and write via MarkHealthy /
// MarkUnhealthy concurrently without external synchronisation; the
// last writer wins under contention. This stronger guarantee replaces
// the previous atomic.Bool + atomic.Pointer pair, which was
// eventually-consistent.
type SourceHealth struct {
	state atomic.Pointer[healthState]
}

// healthState is the single-load snapshot stored in SourceHealth. It is
// always replaced wholesale; never mutated in place.
type healthState struct {
	healthy bool
	lastErr error
}

// MarkHealthy records that the source is currently producing events.
// Clears any previously stored error so subsequent Status() calls do
// not surface a stale connection failure once the source has recovered.
func (h *SourceHealth) MarkHealthy() {
	h.state.Store(&healthState{healthy: true})
}

// MarkUnhealthy records that the source is failing. The supplied error
// is retained so Status() callers (and the future Prometheus gauge's
// remediation labels in Story 1.12) can surface the cause. A nil err
// is allowed for the initial-disconnected state where no specific
// failure has been observed.
func (h *SourceHealth) MarkUnhealthy(err error) {
	h.state.Store(&healthState{healthy: false, lastErr: err})
}

// Status returns the current (healthy, lastErr) pair. The zero-value
// SourceHealth reports (false, nil), reflecting the "never connected"
// initial state. lastErr is nil when the source is healthy or when no
// specific error has been recorded.
//
// The single atomic load guarantees that a reader sees a self-consistent
// snapshot: there is no window in which (healthy=true, lastErr=<old>)
// or vice versa can be observed.
func (h *SourceHealth) Status() (bool, error) {
	if s := h.state.Load(); s != nil {
		return s.healthy, s.lastErr
	}
	return false, nil
}
