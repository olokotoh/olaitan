package dfir

import (
	"context"
	"fmt"

	"github.com/nats-io/nats.go/jetstream"

	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// natsReportPublisher publishes ReportGenerated events to REPORTS.generated. The
// msgID is the incident_id + report SHA256 so a re-announcement of the same
// report (a redelivery that slipped past the in-process idempotency guard after
// a restart) is server-side deduplicated within the REPORTS stream's dedup
// window. The REPORTS stream itself is provisioned by Story 4.6; in 4.4 the
// publish rides the core/JetStream surface and degrades gracefully if the
// stream is absent (the announcement is best-effort, the durable write is 4.6).
type natsReportPublisher struct {
	nc *natsclient.Client
}

// NewNATSReportPublisher returns a ReportPublisher backed by the shared NATS
// client. A nil client is a construction error.
func NewNATSReportPublisher(nc *natsclient.Client) (ReportPublisher, error) {
	if nc == nil {
		return nil, fmt.Errorf("dfir: nil nats client for report publisher")
	}
	return &natsReportPublisher{nc: nc}, nil
}

// PublishReportGenerated publishes evt to REPORTS.generated with WithMsgID dedup
// keyed on incident_id + report SHA256.
func (p *natsReportPublisher) PublishReportGenerated(ctx context.Context, evt ReportGenerated) error {
	msgID := evt.IncidentID + ":" + evt.ReportSHA256
	if _, err := p.nc.PublishJS(ctx, subjects.ReportsGenerated, evt, jetstream.WithMsgID(msgID)); err != nil {
		return fmt.Errorf("dfir: publish report generated: %w", err)
	}
	return nil
}
