package settling

import (
	"context"
	"fmt"

	"github.com/nats-io/nats.go/jetstream"

	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// natsPublisher publishes IncidentFinalised events to subjects.IncidentFinalised
// via the shared NATS client's PublishJS, attaching the BI-8 dedup msg id
// (FinalisedMsgID = package_id + finalising-transition timestamp) so a drainer
// re-publish / restart-replay of the SAME finalisation is server-side
// deduplicated within the INCIDENTS stream's 2-minute window, while a NEW
// incident for the same workload after a CLEAN cycle is not suppressed.
type natsPublisher struct {
	nc *natsclient.Client
}

// NewNATSPublisher returns a Publisher backed by the shared NATS client. A nil
// client is a construction error so the failure surfaces at wiring time, not on
// the first finalisation (the audit publisher precedent).
func NewNATSPublisher(nc *natsclient.Client) (Publisher, error) {
	if nc == nil {
		return nil, fmt.Errorf("settling: nil nats client for publisher")
	}
	return &natsPublisher{nc: nc}, nil
}

// PublishIncidentFinalised publishes evt to INCIDENTS.finalised with the
// once-per-incident dedup msg id.
func (p *natsPublisher) PublishIncidentFinalised(ctx context.Context, evt IncidentFinalised) error {
	if _, err := p.nc.PublishJS(ctx, subjects.IncidentFinalised, evt, jetstream.WithMsgID(FinalisedMsgID(evt))); err != nil {
		return fmt.Errorf("settling: publish incident-finalised: %w", err)
	}
	return nil
}
