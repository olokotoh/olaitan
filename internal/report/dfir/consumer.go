package dfir

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/response/settling"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// durableName is the DFIR agent's distinct durable cursor on the INCIDENTS
// stream (BI-1 / OA1). A distinct durable gives the agent its own cursor; the
// LimitsPolicy stream is append-only so a consumer ack does NOT delete the
// trigger-of-record, and multiple durables can attach without competing.
const durableName = "olaitan-dfir-agent"

// consumerMaxDeliver bounds JetStream's per-message redelivery (mirrors the
// rules-engine template). With AckExplicitPolicy a crashed/un-acked delivery is
// redelivered up to this many times; the BI-10 idempotency guard suppresses a
// duplicate emission across redeliveries.
const consumerMaxDeliver = 5

// fetchBackoff is the bounded sleep between consumer.Next attempts on a
// non-timeout fetch error (the rules-engine value).
const fetchBackoff = time.Second

// Run attaches the durable JetStream consumer on the INCIDENTS stream and
// dispatches each IncidentFinalised to Generate until ctx is cancelled. It
// mirrors the rules-engine consumer template (BI-1): CreateOrUpdateConsumer with
// Durable / AckExplicitPolicy / FilterSubject / MaxDeliver, a
// consumer.Next(FetchMaxWait) loop, and drain-on-cancel. A permanent decode
// error or a fail-closed generation failure is drop-and-ack (a bad event must
// not crash-loop the consumer; the failure is recorded in AUDIT.assessments).
func (a *Agent) Run(ctx context.Context, nc *natsclient.Client) error {
	if nc == nil {
		return errors.New("dfir: nil nats client")
	}
	stream, err := nc.JetStream().Stream(ctx, "INCIDENTS")
	if err != nil {
		return fmt.Errorf("dfir: stream INCIDENTS: %w", err)
	}
	consumer, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       durableName,
		AckPolicy:     jetstream.AckExplicitPolicy,
		FilterSubject: subjects.IncidentFinalised,
		MaxDeliver:    consumerMaxDeliver,
	})
	if err != nil {
		return fmt.Errorf("dfir: consumer: %w", err)
	}

	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		msg, err := consumer.Next(jetstream.FetchMaxWait(250 * time.Millisecond))
		if err != nil {
			if isExpectedFetchTimeout(err) {
				continue
			}
			a.log.Warn("dfir: consumer fetch failed", "err", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(fetchBackoff):
			}
			continue
		}
		a.handle(ctx, msg)
	}
}

// handle decodes the inbound IncidentFinalised event, builds the Incident,
// generates the report, and acks. A permanent decode error is drop-and-ack (a
// malformed event must not crash-loop the consumer). A fail-closed generation
// failure is also acked (OA5: no malformed report persisted, the failure is
// audited inside Generate); a redelivery-duplicate is acked by the idempotency
// guard inside Generate (BI-10).
func (a *Agent) handle(ctx context.Context, msg jetstream.Msg) {
	a.handleData(ctx, msg.Data())
	// Every outcome (decode error, fail-closed generation failure, success, or
	// idempotent drop) is acked: a malformed event must not crash-loop the
	// consumer, and a fail-closed failure is recorded in AUDIT.assessments
	// (OA5), so there is nothing to redeliver. The bounded MaxDeliver covers a
	// genuinely transient crash BEFORE this ack.
	_ = msg.Ack()
}

// handleData decodes the event bytes and generates the report. It is the
// ack-agnostic core of handle, factored out so the decode + fail-closed paths
// are unit-testable without a fake jetstream.Msg.
func (a *Agent) handleData(ctx context.Context, data []byte) {
	inc, err := decodeIncident(data)
	if err != nil {
		a.log.Warn("dfir: dropping malformed IncidentFinalised", "err", err)
		return
	}
	if _, _, gerr := a.Generate(ctx, inc); gerr != nil {
		a.log.Warn("dfir: report generation failed (fail-closed)",
			"incident_id", inc.Event.PackageID, "err", gerr)
	}
}

// decodeIncident decodes an IncidentFinalised wire event into a minimal
// Incident: the event itself, plus a minimal EvidencePackage carrying the
// package_id / workload_id so the redaction-guarded Request.Package is populated
// (AC4). The persisted evidence events / WorkloadPosture / ThreatAssessment are
// NOT on the wire event; an IncidentResolver (future) would enrich them. The
// minimal package still satisfies the REDACTION CONTRACT (Redact() runs over it
// pre-send) and the report renders from the event's history + threat score.
func decodeIncident(data []byte) (Incident, error) {
	var evt settling.IncidentFinalised
	if err := json.Unmarshal(data, &evt); err != nil {
		return Incident{}, fmt.Errorf("decode IncidentFinalised: %w", err)
	}
	inc := Incident{
		Event: evt,
		Package: schema.EvidencePackage{
			PackageID:  evt.PackageID,
			WorkloadID: evt.WorkloadID,
		},
	}
	return inc, nil
}

// isExpectedFetchTimeout mirrors the rules-engine helper: the jetstream client
// sometimes wraps the per-fetch timeout as a bare error string rather than a
// sentinel.
func isExpectedFetchTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, jetstream.ErrNoMessages) {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if strings.Contains(err.Error(), "nats: no messages") {
		return true
	}
	return false
}
