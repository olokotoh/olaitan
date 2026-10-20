package correlator

import (
	"time"

	"github.com/olokotoh/olaitan/internal/schema"
)

// EventObserver receives every event the correlator attributes to a
// scored workload: after identity resolution (a Goldmane aggregate
// arrives under its owner's workload id) and after the host-event and
// never-scored filters. The baseline engine is the observer (Story
// 10.12): it samples each workload's real activity on a fixed time base
// instead of the rising-edge EvidencePackage snapshots. ObserveEvent must
// not block; the correlator calls it on its single consume goroutine.
type EventObserver interface {
	ObserveEvent(workloadID string, identity schema.WorkloadIdentity, ev schema.Event)
}

type observerBox struct{ o EventObserver }

// SetEventObserver installs (or, with nil, removes) the event observer.
// Safe for concurrent use with AddEvent.
func (c *Correlator) SetEventObserver(o EventObserver) {
	if o == nil {
		c.observer.Store(nil)
		return
	}
	c.observer.Store(&observerBox{o: o})
}

func (c *Correlator) notifyObserver(workloadID string, identity schema.WorkloadIdentity, ev schema.Event) {
	if b := c.observer.Load(); b != nil {
		b.o.ObserveEvent(workloadID, identity, ev)
	}
}

// cacheTTL is the identity cache TTL, honouring a hot reload.
func (c *Correlator) cacheTTL() time.Duration {
	if v := c.identityTTLReload.Load(); v > 0 {
		return time.Duration(v)
	}
	return c.identityCacheTTL
}
