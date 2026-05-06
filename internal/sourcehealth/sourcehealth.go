// Package sourcehealth provides a small in-process health tracker that
// every Ring 1 source adapter can consume to publish a single binary
// health bit plus the most recent error. Story 1.6 (Falco gRPC) hosted
// the original *SourceHealth concrete type inside the falco package as
// a single-instance helper; Story 1.7 (Kubernetes audit webhook) is the
// second concrete consumer, which is the rule-of-three minus one moment
// for the health tracker to graduate to a shared package. The full
// SourceAdapter interface is intentionally NOT extracted yet -- the
// gRPC bidi-stream surface and the HTTP-receiver surface still differ
// enough that abstracting the adapter shape would be premature.
//
// Concurrency contract: the tracker holds a single atomic.Pointer to a
// value-type snapshot, so Status() is one atomic load and a reader can
// never observe a torn (healthy, lastErr) tuple. Multiple goroutines
// may read via Status and write via MarkHealthy / MarkUnhealthy
// concurrently without external synchronisation; the last writer wins
// under contention. This is the same eventual-vs-strong-consistency
// guarantee the Falco package landed in Story 1.6's atomic.Pointer
// rewrite, lifted verbatim so behaviour is unchanged for the falco
// consumer.
//
// Why an in-process tracker rather than introducing Prometheus here:
// the FR8 ownership split documented in architecture.md (§
// "Observability surface") assigns per-source state to the adapter and
// the unified /metrics endpoint to cmd/olaitan/metrics.go (Story 1.12).
// Bringing in prometheus/client_golang here would pre-empt that
// decision for all five sources at once.
package sourcehealth

import "sync/atomic"

// Reader is the read-only view of a Tracker. Adapters expose this from
// their Health() method so the unified Prometheus collector (Story
// 1.12) can read the binary state and the last error without reaching
// the mutator methods MarkHealthy / MarkUnhealthy.
type Reader interface {
	Status() (healthy bool, lastErr error)
}

// Tracker is the single-source-of-truth for one adapter's health view.
// Construct via the zero value: the zero Tracker reports (false, nil),
// which is the correct "never connected" initial state.
type Tracker struct {
	state atomic.Pointer[state]
}

// state is the snapshot stored inside the atomic pointer. It is always
// replaced wholesale; never mutated in place.
type state struct {
	healthy bool
	lastErr error
}

// MarkHealthy records that the source is currently producing events.
// Clears any previously stored error so subsequent Status() calls do
// not surface a stale failure once the source has recovered.
func (t *Tracker) MarkHealthy() {
	t.state.Store(&state{healthy: true})
}

// MarkUnhealthy records that the source is failing. The supplied error
// is retained so Status() callers (and the future Prometheus gauge's
// remediation labels in Story 1.12) can surface the cause. A nil err
// is allowed for the initial-disconnected case where no specific
// failure has been observed.
func (t *Tracker) MarkUnhealthy(err error) {
	t.state.Store(&state{healthy: false, lastErr: err})
}

// Status returns the current (healthy, lastErr) pair. The zero-value
// Tracker reports (false, nil), reflecting the "never connected"
// initial state. lastErr is nil when the source is healthy or when no
// specific error has been recorded.
//
// The single atomic load guarantees readers see a self-consistent
// snapshot: there is no window in which (healthy=true, lastErr=<old>)
// or vice versa can be observed.
func (t *Tracker) Status() (bool, error) {
	if s := t.state.Load(); s != nil {
		return s.healthy, s.lastErr
	}
	return false, nil
}
