package fsm

import "github.com/olokotoh/olaitan/internal/schema"

// MultiSink fans a single FSM transition out to several TransitionSinks.
//
// Story 2.2 wired the FSM to exactly one TransitionSink; Story 2.3 made
// that the Redis persistence sink. Story 2.4 adds a second independent
// consumer (the NetworkPolicy enforcement manager), and later stories add
// a NATS audit sink (2.8). Rather than teach the Machine about multiple
// sinks, the wiring composes them here: New receives a MultiSink and
// Publish delivers each transition to every member in order.
//
// Members are expected to be non-blocking on Publish (the Redis sink
// buffers and the netpol manager enqueues), so a slow member cannot stall
// the FSM goroutine. A nil or empty MultiSink is a safe no-op, mirroring
// NopSink, so the aggregator can fall back to it when no real sink is
// enabled. A nil member is skipped so callers can build the slice
// conditionally without guarding every append.
type MultiSink []TransitionSink

// Publish delivers st to every non-nil member in order.
func (m MultiSink) Publish(st schema.StateTransition) {
	for _, s := range m {
		if s != nil {
			s.Publish(st)
		}
	}
}
