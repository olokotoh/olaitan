package dfir

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/minio/minio-go/v7"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/olokotoh/olaitan/internal/agent/provider"
	redisclient "github.com/olokotoh/olaitan/internal/redis"
	"github.com/olokotoh/olaitan/internal/report/archive"
	"github.com/olokotoh/olaitan/internal/report/deferq"
)

// testutilGauge reads the agent's deferred-depth gauge value.
func testutilGauge(t *testing.T, a *Agent) float64 {
	t.Helper()
	return testutil.ToFloat64(a.deferredGauge)
}

// newDeferredQueueForTest wires a real deferq.DeferredQueue over a miniredis
// instance and the agent's own write-metric family, plus a drainer over arch, so
// the inline-defer path and the drain are end-to-end testable without docker.
func newDeferredQueueForTest(t *testing.T, a *Agent, arch archive.ReportArchive) (*deferq.DeferredQueue, *deferq.DeferredDrainer, *redisclient.Client) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	cfg := redisclient.DefaultConfig()
	cfg.Addr = mr.Addr()
	rc, err := redisclient.NewClient(cfg)
	if err != nil {
		t.Fatalf("redis client: %v", err)
	}
	t.Cleanup(func() { _ = rc.Close(context.Background()) })
	q, err := deferq.NewDeferredQueue(rc, 1000, a.WriteMetrics(), nil)
	if err != nil {
		t.Fatalf("deferred queue: %v", err)
	}
	dr, err := deferq.NewDeferredDrainer(q, arch, time.Hour, nil)
	if err != nil {
		t.Fatalf("deferred drainer: %v", err)
	}
	return q, dr, rc
}

// TestWriteReport_InlineRetrySucceeds is the AC1 proof: a BRIEF transient outage
// (one failing Put, then success) is absorbed by the short inline retry on the
// synchronous span, counted result="retried", with no deferral.
func TestWriteReport_InlineRetrySucceeds(t *testing.T) {
	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8", resp: provider.Response{Raw: validReportJSON, StopReason: "end_turn", Model: "claude-opus-4-8"}}
	// FlakyArchive: fail the first Put transiently, then deliver.
	flaky := archive.NewFlakyArchive(archive.NewFakeArchive(), 1)
	a := newAgentWithArchive(t, fp, &fakeReportPublisher{}, nil, flaky)

	start := time.Now()
	_, reported, err := a.Generate(context.Background(), testIncident())
	elapsed := time.Since(start)
	if err != nil || !reported {
		t.Fatalf("Generate: reported=%v err=%v", reported, err)
	}
	if got := writeCount(t, a, writeResultRetried); got != 1 {
		t.Errorf("a write that succeeded after a retry must count retried, got %v", got)
	}
	if got := writeCount(t, a, writeResultSuccess); got != 0 {
		t.Errorf("a retried write must NOT also count success, got %v", got)
	}
	// NFR7: the inline retry budget stays well under the 10s p99 (one backoff of
	// at most 250ms). Generous ceiling to avoid flakiness on a busy CI box.
	if elapsed > 3*time.Second {
		t.Errorf("inline retry took %v, must stay well under NFR7's 10s p99", elapsed)
	}
}

// TestWriteReport_InlineRetryBudgetBounded asserts a sustained transient outage
// exhausts the SHORT inline retry (3 attempts) quickly rather than blocking
// Generate for the full 60s window (BI-1 NFR7 proof). Without a deferred queue
// wired it falls to the fail-loud path.
func TestWriteReport_InlineRetryBudgetBounded(t *testing.T) {
	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8", resp: provider.Response{Raw: validReportJSON, StopReason: "end_turn", Model: "claude-opus-4-8"}}
	// A long outage (more failures than attempts): the inline retry exhausts.
	flaky := archive.NewFlakyArchive(archive.NewFakeArchive(), 100)
	a := newAgentWithArchive(t, fp, &fakeReportPublisher{}, nil, flaky)

	start := time.Now()
	_, reported, err := a.Generate(context.Background(), testIncident())
	elapsed := time.Since(start)
	if err != nil || !reported {
		t.Fatalf("Generate: reported=%v err=%v", reported, err)
	}
	// No deferred queue wired => fail-loud (the irreducible nil-queue path).
	if got := writeCount(t, a, writeResultError); got != 1 {
		t.Errorf("a transient outage beyond budget with no queue must fail loud (error), got %v", got)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("inline retry blocked Generate for %v: must stay well under NFR7's 10s p99 (BI-1)", elapsed)
	}
}

// TestWriteReport_DefersBeyondBudget is the AC2 proof: a transient outage beyond
// the short inline budget ENQUEUES to the deferred queue (result="deferred") and
// increments the deferred-depth gauge; the drain worker then re-PUTs it on
// recovery (result="drained"), decrementing the gauge to zero (AC3).
func TestWriteReport_DefersBeyondBudget(t *testing.T) {
	ctx := context.Background()
	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8", resp: provider.Response{Raw: validReportJSON, StopReason: "end_turn", Model: "claude-opus-4-8"}}
	// The inline write hits a long transient outage. The drain re-PUTs against the
	// SAME flaky archive once we declare recovery.
	flaky := archive.NewFlakyArchive(archive.NewFakeArchive(), 100)
	a := newAgentWithArchive(t, fp, &fakeReportPublisher{}, nil, flaky)
	q, dr, _ := newDeferredQueueForTest(t, a, flaky)
	a.SetDeferredQueue(q)

	_, reported, err := a.Generate(ctx, testIncident())
	if err != nil || !reported {
		t.Fatalf("Generate: reported=%v err=%v", reported, err)
	}
	if got := writeCount(t, a, writeResultDeferred); got != 1 {
		t.Errorf("a transient outage beyond budget must defer, got deferred=%v", got)
	}
	if got := testutilGauge(t, a); got != 1 {
		t.Errorf("deferred-depth gauge = %v, want 1 after defer", got)
	}

	// Recovery: S3 returns; the drain re-PUTs the deferred report FIFO and
	// decrements the gauge to zero.
	flaky.SetFailFor(0)
	dr.DrainOnce(ctx)
	if got := writeCount(t, a, "drained"); got != 1 {
		t.Errorf("the drain must count drained, got %v", got)
	}
	if got := testutilGauge(t, a); got != 0 {
		t.Errorf("deferred-depth gauge after drain = %v, want 0", got)
	}
}

// TestWriteReport_RedisDownEnqueueFallsBackToFailLoud is the BI-7 proof: when the
// deferred-queue enqueue fails (Redis down), writeReport falls back to the 4.6
// fail-loud (result="error") and does NOT panic or block Generate.
func TestWriteReport_RedisDownEnqueueFallsBackToFailLoud(t *testing.T) {
	ctx := context.Background()
	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8", resp: provider.Response{Raw: validReportJSON, StopReason: "end_turn", Model: "claude-opus-4-8"}}
	flaky := archive.NewFlakyArchive(archive.NewFakeArchive(), 100)
	a := newAgentWithArchive(t, fp, &fakeReportPublisher{}, nil, flaky)
	q, _, rc := newDeferredQueueForTest(t, a, flaky)
	a.SetDeferredQueue(q)
	// Close the Redis client so the enqueue RPUSH fails (Redis down).
	_ = rc.Close(ctx)

	_, reported, err := a.Generate(ctx, testIncident())
	if err != nil || !reported {
		t.Fatalf("Generate must not fail or block on a Redis-down enqueue: reported=%v err=%v", reported, err)
	}
	if got := writeCount(t, a, writeResultError); got != 1 {
		t.Errorf("a Redis-down enqueue must fall back to fail-loud (error), got %v", got)
	}
	if got := writeCount(t, a, writeResultDeferred); got != 0 {
		t.Errorf("a failed enqueue must NOT count deferred, got %v", got)
	}
}

// TestWriteReport_PermanentErrorNotDeferred is the BI-2 proof: a permanent 4xx
// misconfiguration is NOT retried/deferred; it keeps the fail-loud behaviour
// (result="error") even with a deferred queue wired, so a misconfig does not
// fill Redis.
func TestWriteReport_PermanentErrorNotDeferred(t *testing.T) {
	ctx := context.Background()
	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8", resp: provider.Response{Raw: validReportJSON, StopReason: "end_turn", Model: "claude-opus-4-8"}}
	flaky := archive.NewFlakyArchive(archive.NewFakeArchive(), 100)
	flaky.FailWith = minio.ErrorResponse{StatusCode: http.StatusForbidden, Code: "AccessDenied"}
	a := newAgentWithArchive(t, fp, &fakeReportPublisher{}, nil, flaky)
	q, _, _ := newDeferredQueueForTest(t, a, flaky)
	a.SetDeferredQueue(q)

	_, reported, err := a.Generate(ctx, testIncident())
	if err != nil || !reported {
		t.Fatalf("Generate: reported=%v err=%v", reported, err)
	}
	if got := writeCount(t, a, writeResultError); got != 1 {
		t.Errorf("a permanent 4xx must fail loud (error), got %v", got)
	}
	if got := writeCount(t, a, writeResultDeferred); got != 0 {
		t.Errorf("a permanent 4xx must NOT be deferred, got %v", got)
	}
	if got := testutilGauge(t, a); got != 0 {
		t.Errorf("a permanent 4xx must not increment the deferred gauge, got %v", got)
	}
}

// TestPutWithInlineRetry_FirstTrySuccess confirms a first-try success reports
// attempts=1 (so result stays "success", not "retried").
func TestPutWithInlineRetry_FirstTrySuccess(t *testing.T) {
	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8", resp: provider.Response{Raw: validReportJSON, StopReason: "end_turn"}}
	fa := archive.NewFakeArchive()
	a := newAgentWithArchive(t, fp, &fakeReportPublisher{}, nil, fa)
	_, attempts, err := a.putWithInlineRetry(context.Background(), "reports/k.md", []byte("body"))
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if attempts != 1 {
		t.Errorf("first-try success attempts = %d, want 1", attempts)
	}
}
