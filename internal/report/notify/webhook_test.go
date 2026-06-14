package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/report/dfir"
)

// fastConfig returns a Config with a sub-millisecond backoff so the retry/exhaust
// tests run sub-second; the URL is filled in per test.
func fastConfig(url string) Config {
	return Config{
		URL:              url,
		RetryMaxAttempts: 3,
		RetryMin:         time.Millisecond,
		RetryMax:         2 * time.Millisecond,
		Timeout:          2 * time.Second,
	}
}

// newTestWebhook builds a Webhook against a fresh registry, returning the webhook
// and a logBuf so tests can assert the URL is never logged in full.
func newTestWebhook(t *testing.T, cfg Config) (*Webhook, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	w, err := NewWebhook(cfg, metrics.NewRegistry(), log)
	if err != nil {
		t.Fatalf("NewWebhook: %v", err)
	}
	return w, &buf
}

// sampleEvent is the synthesised ReportGenerated the deliver tests drive.
func sampleEvent() dfir.ReportGenerated {
	return dfir.ReportGenerated{
		SchemaVersion:    dfir.SchemaVersionReportGenerated,
		IncidentID:       "pkg-1",
		WorkloadID:       "ns/Deployment/web",
		ReportSHA256:     "deadbeef",
		ReportURL:        "reports/2026/06/14/deadbeef.md",
		FinalFSMState:    "QUARANTINED",
		GeneratedAt:      time.Date(2026, 6, 14, 10, 0, 0, 0, time.UTC),
		ThreatScore:      88.5,
		AttackTechniques: []string{"T1611", "T1610"},
	}
}

func deliveredCount(t *testing.T, w *Webhook, result string) float64 {
	t.Helper()
	return testutil.ToFloat64(w.delivered.WithLabelValues(result))
}

// TestDeliver_Success: a 200 delivers the POST once, the body decodes to the
// expected operator-facing payload, and result="delivered".
func TestDeliver_Success(t *testing.T) {
	var got payload
	var count int32
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&count, 1)
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		rw.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	w, _ := newTestWebhook(t, fastConfig(srv.URL))
	w.deliver(context.Background(), sampleEvent())

	if n := atomic.LoadInt32(&count); n != 1 {
		t.Fatalf("server saw %d requests, want exactly 1", n)
	}
	if got.WorkloadID != "ns/Deployment/web" || got.ThreatScore != 88.5 ||
		got.ReportURL != "reports/2026/06/14/deadbeef.md" || got.FSMState != "QUARANTINED" ||
		got.PublishedAt != "2026-06-14T10:00:00Z" || got.IdempotencyKey != "deadbeef" {
		t.Errorf("payload mismatch: %+v", got)
	}
	if len(got.AttackTechniques) != 2 || got.AttackTechniques[0] != "T1611" {
		t.Errorf("attack_techniques = %v, want [T1611 T1610]", got.AttackTechniques)
	}
	if deliveredCount(t, w, "delivered") != 1 {
		t.Errorf("result=delivered counter = %v, want 1", deliveredCount(t, w, "delivered"))
	}
	if deliveredCount(t, w, "failed") != 0 {
		t.Errorf("result=failed counter = %v, want 0", deliveredCount(t, w, "failed"))
	}
}

// TestDeliver_EmptyTechniquesRendersArray: an event with no techniques ("not
// recorded") sends attack_techniques as [], never null (BI-4 honest array).
func TestDeliver_EmptyTechniquesRendersArray(t *testing.T) {
	var rawBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rawBody, _ = readAll(r)
		rw.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	evt := sampleEvent()
	evt.AttackTechniques = nil
	w, _ := newTestWebhook(t, fastConfig(srv.URL))
	w.deliver(context.Background(), evt)

	if !strings.Contains(string(rawBody), `"attack_techniques":[]`) {
		t.Errorf("empty techniques must render as [], got %s", rawBody)
	}
}

// TestDeliver_RetryThenSuccess: a server that 503s N-1 times then 200 succeeds
// after >=1 retry, and the request count matches.
func TestDeliver_RetryThenSuccess(t *testing.T) {
	var count int32
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&count, 1)
		if n < 3 {
			rw.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		rw.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	w, _ := newTestWebhook(t, fastConfig(srv.URL)) // MaxAttempts 3
	w.deliver(context.Background(), sampleEvent())

	if n := atomic.LoadInt32(&count); n != 3 {
		t.Fatalf("server saw %d requests, want 3 (2 x 503 then 200)", n)
	}
	if deliveredCount(t, w, "delivered") != 1 {
		t.Errorf("a retried-then-200 delivery must count delivered=1, got %v", deliveredCount(t, w, "delivered"))
	}
}

// TestDeliver_ExhaustLogsWarnAndCountsFailed: an always-503 server exhausts the
// configurable retry limit, logs warn (the SCRUBBED host, never the full URL),
// counts result="failed", and does NOT crash.
func TestDeliver_ExhaustLogsWarnAndCountsFailed(t *testing.T) {
	var count int32
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&count, 1)
		rw.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	cfg := fastConfig(srv.URL)
	cfg.RetryMaxAttempts = 3
	w, buf := newTestWebhook(t, cfg)
	w.deliver(context.Background(), sampleEvent())

	if n := atomic.LoadInt32(&count); n != 3 {
		t.Fatalf("server saw %d requests, want 3 (the configurable limit)", n)
	}
	if deliveredCount(t, w, "failed") != 1 {
		t.Errorf("exhaust must count failed=1, got %v", deliveredCount(t, w, "failed"))
	}
	logs := buf.String()
	if !strings.Contains(logs, "notification webhook delivery failed") {
		t.Errorf("exhaust must log the structured warn line\n%s", logs)
	}
	if !strings.Contains(logs, `level=WARN`) {
		t.Errorf("the failure must be logged at warn\n%s", logs)
	}
	assertURLNeverLogged(t, logs, srv.URL)
}

// TestDeliver_PermanentBailsImmediately: a 400 is a permanent target-rejection,
// so Strategy.Do bails after exactly one request and counts failed.
func TestDeliver_PermanentBailsImmediately(t *testing.T) {
	var count int32
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&count, 1)
		rw.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	w, buf := newTestWebhook(t, fastConfig(srv.URL))
	w.deliver(context.Background(), sampleEvent())

	if n := atomic.LoadInt32(&count); n != 1 {
		t.Fatalf("a permanent 400 must bail after 1 request, server saw %d", n)
	}
	if deliveredCount(t, w, "failed") != 1 {
		t.Errorf("a permanent failure must count failed=1, got %v", deliveredCount(t, w, "failed"))
	}
	assertURLNeverLogged(t, buf.String(), srv.URL)
}

// TestDeliver_UnreachableServerExhausts: a closed/unreachable target exhausts via
// transport errors (transient) without crashing.
func TestDeliver_UnreachableServerExhausts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // now unreachable

	cfg := fastConfig(url)
	cfg.RetryMaxAttempts = 2
	w, buf := newTestWebhook(t, cfg)
	w.deliver(context.Background(), sampleEvent())

	if deliveredCount(t, w, "failed") != 1 {
		t.Errorf("an unreachable target must count failed=1, got %v", deliveredCount(t, w, "failed"))
	}
	assertURLNeverLogged(t, buf.String(), url)
}

// TestHandleData_MalformedEventDropAndAck: a malformed ReportGenerated is dropped
// (logged) without a POST and without crashing (the consumer ack-agnostic core).
func TestHandleData_MalformedEventDropAndAck(t *testing.T) {
	var count int32
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&count, 1)
		rw.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	w, buf := newTestWebhook(t, fastConfig(srv.URL))
	w.handleData(context.Background(), []byte(`{not json`))

	if n := atomic.LoadInt32(&count); n != 0 {
		t.Fatalf("a malformed event must not POST, server saw %d requests", n)
	}
	if !strings.Contains(buf.String(), "dropping malformed ReportGenerated") {
		t.Errorf("a malformed event must be logged as dropped\n%s", buf.String())
	}
}

// TestHandleData_DeliversValidEvent: a valid event bytes drives a delivery
// through the consumer core (no real NATS).
func TestHandleData_DeliversValidEvent(t *testing.T) {
	var count int32
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&count, 1)
		rw.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	w, _ := newTestWebhook(t, fastConfig(srv.URL))
	data, _ := json.Marshal(sampleEvent())
	w.handleData(context.Background(), data)

	if n := atomic.LoadInt32(&count); n != 1 {
		t.Fatalf("a valid event must POST once, server saw %d", n)
	}
	if deliveredCount(t, w, "delivered") != 1 {
		t.Errorf("delivered=1 expected, got %v", deliveredCount(t, w, "delivered"))
	}
}

// TestScrubURL: a token-bearing URL scrubs down to the host only.
func TestScrubURL(t *testing.T) {
	cases := map[string]string{
		"https://hooks.slack.com/services/T000/B000/XXXXSECRETTOKEN": "hooks.slack.com",
		"https://events.pagerduty.com/v2/enqueue?token=abc":          "events.pagerduty.com",
		"::::not-a-url": "(redacted)",
		"":              "(redacted)",
	}
	for in, want := range cases {
		if got := scrubURL(in); got != want {
			t.Errorf("scrubURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestNewWebhook_RejectsEmptyURL: an empty URL is a construction error (the gate
// guarantees a non-empty URL at the wiring layer).
func TestNewWebhook_RejectsEmptyURL(t *testing.T) {
	if _, err := NewWebhook(Config{URL: ""}, metrics.NewRegistry(), nil); err == nil {
		t.Fatal("an empty webhook url must be a construction error")
	}
}

// TestIsExpectedFetchTimeout: the no-messages / deadline sentinels are expected
// (loop continues), an arbitrary error is not.
func TestIsExpectedFetchTimeout(t *testing.T) {
	if isExpectedFetchTimeout(nil) {
		t.Error("nil must not be an expected fetch timeout")
	}
	if !isExpectedFetchTimeout(jetstream.ErrNoMessages) {
		t.Error("ErrNoMessages must be an expected fetch timeout")
	}
	if !isExpectedFetchTimeout(context.DeadlineExceeded) {
		t.Error("DeadlineExceeded must be an expected fetch timeout")
	}
	if !isExpectedFetchTimeout(errors.New("nats: no messages")) {
		t.Error("the bare 'nats: no messages' string must be expected")
	}
	if isExpectedFetchTimeout(errors.New("boom")) {
		t.Error("an arbitrary error must not be an expected fetch timeout")
	}
}

// TestRun_NilClient: Run rejects a nil NATS client (the construction guard).
func TestRun_NilClient(t *testing.T) {
	w, _ := newTestWebhook(t, fastConfig("https://hooks.example.com/x"))
	if err := w.Run(context.Background(), nil); err == nil {
		t.Fatal("Run with a nil client must error")
	}
}

// TestHost: the construction-log host accessor returns the scrubbed host.
func TestHost(t *testing.T) {
	w, _ := newTestWebhook(t, fastConfig("https://hooks.slack.com/services/T/B/secret"))
	if w.Host() != "hooks.slack.com" {
		t.Errorf("Host() = %q, want hooks.slack.com", w.Host())
	}
}

// assertURLNeverLogged fails if the full token-bearing URL ever appears in the
// structured logs (BI-5): only the host may be logged.
func assertURLNeverLogged(t *testing.T, logs, fullURL string) {
	t.Helper()
	// The httptest URL is http://127.0.0.1:PORT (no embedded token), but the
	// scrub contract is that the FULL URL string never appears; only the host
	// (127.0.0.1:PORT) does. We assert the scheme+host+path form is absent.
	if strings.Contains(logs, fullURL) {
		t.Errorf("the full webhook URL %q must never appear in logs\n%s", fullURL, logs)
	}
}

// readAll reads the request body fully for the payload-shape assertions.
func readAll(r *http.Request) ([]byte, error) {
	var b bytes.Buffer
	_, err := b.ReadFrom(r.Body)
	return b.Bytes(), err
}
