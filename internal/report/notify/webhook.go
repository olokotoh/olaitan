// Package notify hosts the Story 4.8 OPTIONAL incident notification webhook: a
// SEPARATE durable JetStream consumer of REPORTS.generated that, when enabled via
// config (response.notifications.enabled + a non-empty webhook_url), fires ONE
// outbound HTTP POST of an operator-facing JSON payload per confirmed-incident
// report announcement to the configured URL (Slack / email-relay / PagerDuty are
// just the URL; there is NO per-vendor formatting code).
//
// # Structural decoupling (AC3, BI-3, PO ratification 3)
//
// The webhook is a SEPARATE durable consumer (its own cursor
// `olaitan-notification-webhook`, DISTINCT from the DFIR agent's
// `olaitan-dfir-agent`) launched on the errgroup adjacent to the DFIR agent. It
// reacts to the REPORTS.generated announce AFTER the synchronous DFIR write +
// announce; a delivery failure NEVER blocks the report write or the response-side
// FSM. An undeliverable webhook (after retry exhaustion) is drop-and-ack so a
// flaky target cannot stall the REPORTS cursor.
//
// # Retry + transient/permanent split (AC3, BI-7, PO ratification 4)
//
// Delivery is wrapped in the EXISTING internal/retry Strategy.Do with a
// configurable limit. A transient failure (connection/timeout error, a 5xx, a
// 429) is RETRYABLE; a permanent 4xx target-rejection (400/401/403/404, a
// mis-configured URL) is wrapped retry.Permanent so Do bails immediately (the
// claude isPermanent + Story 4.7 transient-vs-permanent precedent). On exhaust or
// a permanent failure the deliverer logs structured at warn (the SCRUBBED host
// only) and increments the delivery metric with result="failed"; it NEVER errors
// the consumer goroutine.
//
// # Secret-URL scrub (AC1, BI-5, PO ratification 5)
//
// The webhook URL may embed a credential (a Slack incoming-webhook URL is
// hooks.slack.com/services/T.../B.../<token>), so it is treated as a secret: it
// is supplied via the NOTIFICATIONS_WEBHOOK_URL env var at wiring time and is
// NEVER logged in full. Structured logs carry the URL host only.
//
// # Ring discipline (BI-10)
//
// This package may import the substrate it operates over (internal/nats,
// internal/subjects, internal/retry, internal/metrics) and the event type it
// consumes (internal/report/dfir.ReportGenerated, a one-way consumer dependency).
// It MUST NOT import internal/decision/score or any FSM package (the trust-bound
// fence: the webhook is a downstream metadata announcer, never a score-fold).
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/olokotoh/olaitan/internal/metrics"
	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/report/dfir"
	"github.com/olokotoh/olaitan/internal/retry"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// durableName is the webhook consumer's DISTINCT durable cursor on the REPORTS
// stream (BI-3). It is deliberately different from the DFIR agent's
// `olaitan-dfir-agent` durable so the two cursors do not compete.
const durableName = "olaitan-notification-webhook"

// consumerMaxDeliver bounds JetStream's per-message redelivery. With
// AckExplicitPolicy a crashed/un-acked delivery is redelivered up to this many
// times; the webhook acks AFTER the delivery attempt (success OR exhaust), so the
// only duplicate window is a crash mid-POST. The payload carries an
// idempotency_key (the report SHA) for receiver-side dedup (BI-8 accept-duplicate).
const consumerMaxDeliver = 5

// fetchBackoff is the bounded sleep between consumer.Next attempts on a
// non-timeout fetch error (the DFIR-consumer value).
const fetchBackoff = time.Second

// errorBodyReadBytes bounds how much of a non-2xx response body the deliverer
// reads for the classification log; the body is upstream-controlled.
const errorBodyReadBytes = 4 << 10

// payload is the operator-facing JSON POST body (AC1, BI-4). Every field is
// NON-SENSITIVE control-plane/metadata: the report URL is a content-addressed key
// (the SHA, not a presigned credential), the techniques + threat score are
// already-decided already-redacted values, the workload id is the FSM key. NO raw
// evidence travels.
//
// AttackTechniques is the honest ARRAY (OA2 recommended resolution): AC1 names it
// singular but the source is the technique LIST, which may be empty ("not
// recorded") per the 4.4 PO Option A deferral; an empty list renders as [].
// IdempotencyKey is the report SHA256 so an at-least-once redelivery is dedupable
// receiver-side (BI-8).
type payload struct {
	WorkloadID       string   `json:"workload_id"`
	AttackTechniques []string `json:"attack_techniques"`
	ThreatScore      float64  `json:"threat_score"`
	ReportURL        string   `json:"report_url"`
	FSMState         string   `json:"fsm_state"`
	PublishedAt      string   `json:"published_at"`
	IdempotencyKey   string   `json:"idempotency_key"`
}

// Webhook is the outbound notification deliverer + the durable REPORTS.generated
// consumer. It POSTs a payload built from each ReportGenerated event to the
// configured URL with configurable-limit retry, scrubbing the secret URL in logs.
type Webhook struct {
	url       string
	host      string // the scrubbed URL host for structured logs (never the full URL)
	httpc     *http.Client
	strategy  retry.Strategy
	delivered *prometheus.CounterVec
	log       *slog.Logger
}

// Config carries the wiring inputs for NewWebhook.
type Config struct {
	// URL is the resolved webhook target (the NOTIFICATIONS_WEBHOOK_URL env var
	// override, or the plain config value). MUST be non-empty.
	URL string
	// RetryMaxAttempts / RetryMin / RetryMax map onto retry.Strategy.
	RetryMaxAttempts int
	RetryMin         time.Duration
	RetryMax         time.Duration
	// Timeout bounds the per-attempt HTTP client.
	Timeout time.Duration
}

// NewWebhook constructs a Webhook deliverer + registers the delivery counter on
// the shared metrics registry. A nil registry or an empty URL is a construction
// error (the gate at the wiring layer guarantees a non-empty URL).
func NewWebhook(cfg Config, reg *metrics.Registry, log *slog.Logger) (*Webhook, error) {
	if cfg.URL == "" {
		return nil, errors.New("notify: empty webhook url")
	}
	if log == nil {
		log = slog.Default()
	}
	host := scrubURL(cfg.URL)
	// olaitan_notification_webhook_delivered_total{result} is the AC4 /
	// epics.md:2020-named delivery counter (the full Story 4.9 observability
	// surface is out of scope; 4.8 seeds only this counter). result in
	// {delivered, failed}; the label set is statically bounded (cardinality-safe).
	delivered, err := reg.RegisterCounterVec("olaitan_notification_webhook_delivered_total",
		"Optional incident notification webhook delivery outcomes by result {delivered, failed} (Story 4.8).",
		[]string{"result"})
	if err != nil {
		return nil, fmt.Errorf("notify: delivery metric: %w", err)
	}
	return &Webhook{
		url:  cfg.URL,
		host: host,
		httpc: &http.Client{
			Timeout: cfg.Timeout,
		},
		strategy: retry.Strategy{
			Min:         cfg.RetryMin,
			Max:         cfg.RetryMax,
			Multiplier:  2,
			Jitter:      1,
			MaxAttempts: cfg.RetryMaxAttempts,
		},
		delivered: delivered,
		log:       log,
	}, nil
}

// Host returns the scrubbed webhook host (never the full token-bearing URL); used
// by the NFR18 construction log at the wiring layer.
func (w *Webhook) Host() string { return w.host }

// Run attaches the durable JetStream consumer on the REPORTS stream and delivers
// each REPORTS.generated to the webhook until ctx is cancelled. It mirrors the
// DFIR-consumer template (BI-3): CreateOrUpdateConsumer with Durable /
// AckExplicitPolicy / FilterSubject / MaxDeliver, a consumer.Next(FetchMaxWait)
// loop, and drain-on-cancel. Every message is drop-and-acked (success OR exhaust)
// so a flaky/down webhook target never crash-loops the consumer or stalls the
// cursor.
func (w *Webhook) Run(ctx context.Context, nc *natsclient.Client) error {
	if nc == nil {
		return errors.New("notify: nil nats client")
	}
	stream, err := nc.JetStream().Stream(ctx, "REPORTS")
	if err != nil {
		return fmt.Errorf("notify: stream REPORTS: %w", err)
	}
	consumer, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       durableName,
		AckPolicy:     jetstream.AckExplicitPolicy,
		FilterSubject: subjects.ReportsGenerated,
		MaxDeliver:    consumerMaxDeliver,
	})
	if err != nil {
		return fmt.Errorf("notify: consumer: %w", err)
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
			w.log.Warn("notify: consumer fetch failed", "err", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(fetchBackoff):
			}
			continue
		}
		w.handle(ctx, msg)
	}
}

// handle decodes the inbound ReportGenerated event, delivers the webhook, and
// acks. Every outcome (decode error, delivery success, retry exhaustion, a
// permanent target-rejection) is acked: a malformed event must not crash-loop the
// consumer, and an undeliverable target is drop-and-ack so a flaky webhook cannot
// stall the REPORTS cursor (the DFIR drop-and-ack precedent).
func (w *Webhook) handle(ctx context.Context, msg jetstream.Msg) {
	w.handleData(ctx, msg.Data())
	_ = msg.Ack()
}

// handleData decodes the event bytes and delivers the webhook. It is the
// ack-agnostic core of handle, factored out so the decode + delivery paths are
// unit-testable without a fake jetstream.Msg (the DFIR handleData precedent).
func (w *Webhook) handleData(ctx context.Context, data []byte) {
	var evt dfir.ReportGenerated
	if err := json.Unmarshal(data, &evt); err != nil {
		w.log.Warn("notify: dropping malformed ReportGenerated", "err", err)
		return
	}
	w.deliver(ctx, evt)
}

// deliver builds the operator-facing payload and POSTs it with configurable-limit
// retry. On success it increments result="delivered"; on exhaust or a permanent
// failure it logs structured at warn (the SCRUBBED host only) and increments
// result="failed". It NEVER returns an error (the consumer never crash-loops).
func (w *Webhook) deliver(ctx context.Context, evt dfir.ReportGenerated) {
	body, err := json.Marshal(buildPayload(evt))
	if err != nil {
		// A marshalling failure of our own small struct should never happen;
		// treat it as a permanent (drop) failure rather than crash-looping.
		w.log.Warn("notification webhook delivery failed",
			"host", w.host, "incident_id", evt.IncidentID, "reason", "payload marshal", "err", err)
		w.delivered.WithLabelValues("failed").Inc()
		return
	}

	attempts := 0
	derr := w.strategy.Do(ctx, func(ctx context.Context) error {
		attempts++
		return w.post(ctx, body)
	})
	if derr != nil {
		w.log.Warn("notification webhook delivery failed",
			"host", w.host, "incident_id", evt.IncidentID, "attempts", attempts, "err", derr)
		w.delivered.WithLabelValues("failed").Inc()
		return
	}
	w.delivered.WithLabelValues("delivered").Inc()
}

// post performs ONE HTTP POST attempt and classifies the result (BI-7,
// transient/permanent split mirroring claude.isPermanent + Story 4.7):
//   - a connection/timeout/transport error -> RETRYABLE (returned bare)
//   - a 2xx -> success (nil)
//   - a 429 or any 5xx -> RETRYABLE (returned bare, so Strategy.Do backs off)
//   - any other 4xx (a target-rejection / mis-configured URL) -> PERMANENT
//     (wrapped retry.Permanent so Do bails immediately)
func (w *Webhook) post(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		// A bad URL is a permanent configuration mistake; no retry helps. The
		// build error is scrubbed (BI-5): http errors embed the full URL, so we
		// log the host + the underlying cause, never the token-bearing URL.
		return retry.Permanent(fmt.Errorf("notify: build request to host %s: %s", w.host, scrubErr(err)))
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := w.httpc.Do(req)
	if err != nil {
		// A transport error (connection refused, DNS, timeout) is transient. It
		// is SCRUBBED (BI-5): net/http wraps it in a *url.Error that embeds the
		// full request URL, so we report the host + the underlying cause only.
		return fmt.Errorf("notify: transport to host %s: %s", w.host, scrubErr(err))
	}
	defer func() { _ = resp.Body.Close() }()

	// Drain a bounded prefix so the connection can be reused; the snippet is
	// upstream-controlled, so it is read bounded and not logged in full.
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, errorBodyReadBytes))

	sc := resp.StatusCode
	switch {
	case sc >= 200 && sc < 300:
		return nil
	case sc == http.StatusTooManyRequests || sc >= 500:
		// 429 + every 5xx are transient: retry with backoff.
		return fmt.Errorf("notify: webhook returned %d (transient)", sc)
	case sc >= 400 && sc < 500:
		// Any other 4xx is a target-rejection / mis-configuration: permanent.
		return retry.Permanent(fmt.Errorf("notify: webhook rejected with %d (permanent): %s", sc, summarise(snippet)))
	default:
		// A 1xx/3xx is unexpected for a webhook receiver; treat as transient.
		return fmt.Errorf("notify: webhook returned unexpected status %d", sc)
	}
}

// buildPayload maps a ReportGenerated to the operator-facing JSON payload (BI-4).
// attack_techniques is the honest array (an empty/"not recorded" list renders as
// []); published_at is GeneratedAt in RFC3339; the idempotency key is the report
// SHA256.
func buildPayload(evt dfir.ReportGenerated) payload {
	techniques := evt.AttackTechniques
	if techniques == nil {
		techniques = []string{}
	}
	return payload{
		WorkloadID:       evt.WorkloadID,
		AttackTechniques: techniques,
		ThreatScore:      evt.ThreatScore,
		ReportURL:        evt.ReportURL,
		FSMState:         evt.FinalFSMState,
		PublishedAt:      evt.GeneratedAt.UTC().Format(time.RFC3339),
		IdempotencyKey:   evt.ReportSHA256,
	}
}

// scrubURL returns the host of the webhook URL (BI-5): a Slack/PagerDuty URL
// embeds a token in its path, so logs carry the host only, never the full URL. A
// URL that does not parse returns the redaction marker rather than echoing the
// raw (possibly token-bearing) string.
func scrubURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(redacted)"
	}
	return u.Host
}

// scrubErr returns an error's message with the token-bearing webhook URL removed
// (BI-5). net/http transport errors are *url.Error values whose Error() embeds
// the full request URL; we unwrap to the inner cause (which carries no URL) so
// the structured log never leaks the secret. A non-url.Error is returned as-is
// (it does not carry the URL).
func scrubErr(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return ue.Err.Error()
	}
	return err.Error()
}

// summarise trims an upstream error-body prefix to a short, single-line snippet
// for the classification error; it never carries a credential because the snippet
// is the receiver's own error text, not the request URL.
func summarise(raw []byte) string {
	s := strings.TrimSpace(string(raw))
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// isExpectedFetchTimeout mirrors the DFIR-consumer helper: the jetstream client
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
