package deferq

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/minio/minio-go/v7"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	redisclient "github.com/olokotoh/olaitan/internal/redis"
	"github.com/olokotoh/olaitan/internal/report/archive"
)

// testMetrics builds a fresh Metrics set backed by a private prometheus registry
// (so each test is isolated and there is no duplicate-registration across tests).
func testMetrics(t *testing.T) Metrics {
	t.Helper()
	gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "test_report_writes_deferred_count"}, nil)
	dropped := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "test_report_writes_dropped_total"}, []string{"reason"})
	writes := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "test_report_writes_total"}, []string{"result"})
	reg := prometheus.NewRegistry()
	for _, c := range []prometheus.Collector{gauge, dropped, writes} {
		if err := reg.Register(c); err != nil {
			t.Fatalf("register: %v", err)
		}
	}
	return Metrics{Deferred: gauge.WithLabelValues(), Dropped: dropped, Writes: writes}
}

func gaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	var m dto.Metric
	if err := g.Write(&m); err != nil {
		t.Fatalf("gauge write: %v", err)
	}
	return m.GetGauge().GetValue()
}

func counterValue(t *testing.T, c *prometheus.CounterVec, labels ...string) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.WithLabelValues(labels...).Write(&m); err != nil {
		t.Fatalf("counter write: %v", err)
	}
	return m.GetCounter().GetValue()
}

func newRedis(t *testing.T) *redisclient.Client {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	cfg := redisclient.DefaultConfig()
	cfg.Addr = mr.Addr()
	cli, err := redisclient.NewClient(cfg)
	if err != nil {
		t.Fatalf("redis client: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close(context.Background()) })
	return cli
}

func permanent403() error {
	return minio.ErrorResponse{StatusCode: http.StatusForbidden, Code: "AccessDenied"}
}

// TestEnqueue_IncrementsGauge confirms an enqueue RPUSHes the envelope and bumps
// the deferred-depth gauge, and that the drain re-PUTs it and decrements (AC2/AC3).
func TestEnqueue_DrainFIFO_DecrementsToZero(t *testing.T) {
	ctx := context.Background()
	cli := newRedis(t)
	m := testMetrics(t)
	q, err := NewDeferredQueue(cli, 0, m, nil)
	if err != nil {
		t.Fatalf("queue: %v", err)
	}
	fake := archive.NewFakeArchive()
	dr, err := NewDeferredDrainer(q, fake, time.Hour, nil) // long tick: drive drain manually
	if err != nil {
		t.Fatalf("drainer: %v", err)
	}

	keys := []string{"reports/2026/06/14/aaa.md", "reports/2026/06/14/bbb.md", "reports/2026/06/14/ccc.md"}
	for i, k := range keys {
		if err := q.Enqueue(ctx, k, []byte("body-"+k), archive.PutOptions{}, "inc-"+string(rune('0'+i))); err != nil {
			t.Fatalf("enqueue %q: %v", k, err)
		}
	}
	if got := gaugeValue(t, m.Deferred); got != 3 {
		t.Fatalf("gauge after enqueue = %v, want 3", got)
	}

	dr.drain(ctx)

	if got := gaugeValue(t, m.Deferred); got != 0 {
		t.Fatalf("gauge after drain = %v, want 0", got)
	}
	if got := counterValue(t, m.Writes, "drained"); got != 3 {
		t.Fatalf("drained count = %v, want 3", got)
	}
	// FIFO: the bodies landed under the right keys.
	for _, k := range keys {
		if body, ok := fake.Body(k); !ok || string(body) != "body-"+k {
			t.Fatalf("key %q not re-PUT correctly (ok=%v)", k, ok)
		}
	}
}

// TestDrain_StillDown_LeavesHead confirms that when S3 is still failing
// transiently the drain leaves the head in place (FIFO preserved) and does NOT
// decrement the gauge (AC3).
func TestDrain_StillDown_LeavesHead(t *testing.T) {
	ctx := context.Background()
	cli := newRedis(t)
	m := testMetrics(t)
	q, _ := NewDeferredQueue(cli, 0, m, nil)
	// FlakyArchive in permanent outage for this pass.
	flaky := archive.NewFlakyArchive(archive.NewFakeArchive(), 100)
	dr, _ := NewDeferredDrainer(q, flaky, time.Hour, nil)

	if err := q.Enqueue(ctx, "reports/x.md", []byte("b"), archive.PutOptions{}, "inc"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	dr.drain(ctx)
	if got := gaugeValue(t, m.Deferred); got != 1 {
		t.Fatalf("gauge still-down = %v, want 1 (head left in place)", got)
	}
	if n, _ := cli.DeferredReportLen(ctx); n != 1 {
		t.Fatalf("queue len = %d, want 1", n)
	}

	// Recovery: turn off the outage; the next drain re-PUTs and decrements.
	flaky.SetFailFor(0)
	dr.drain(ctx)
	if got := gaugeValue(t, m.Deferred); got != 0 {
		t.Fatalf("gauge after recovery = %v, want 0", got)
	}
}

// TestDrain_PoisonPermanent_DeadLettered confirms a permanent 4xx re-PUT error
// dead-letters the head (LPOP + result=error + gauge dec) rather than looping
// forever (BI-6).
func TestDrain_PoisonPermanent_DeadLettered(t *testing.T) {
	ctx := context.Background()
	cli := newRedis(t)
	m := testMetrics(t)
	q, _ := NewDeferredQueue(cli, 0, m, nil)
	flaky := archive.NewFlakyArchive(archive.NewFakeArchive(), 1)
	flaky.FailWith = permanent403()
	dr, _ := NewDeferredDrainer(q, flaky, time.Hour, nil)

	if err := q.Enqueue(ctx, "reports/poison.md", []byte("b"), archive.PutOptions{}, "inc"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	dr.drain(ctx)
	if got := gaugeValue(t, m.Deferred); got != 0 {
		t.Fatalf("gauge after dead-letter = %v, want 0", got)
	}
	if got := counterValue(t, m.Writes, "error"); got != 1 {
		t.Fatalf("error count = %v, want 1", got)
	}
	if n, _ := cli.DeferredReportLen(ctx); n != 0 {
		t.Fatalf("poison head not dead-lettered: len = %d", n)
	}
}

// TestDrain_DoubleDrain_DedupedNoOp confirms a re-peek of the same
// content-addressed key after a "crash" (re-PUT then no commit) is a HEAD-deduped
// no-op on the second drain (idempotency, BI-9).
func TestDrain_DoubleDrain_DedupedNoOp(t *testing.T) {
	ctx := context.Background()
	cli := newRedis(t)
	m := testMetrics(t)
	q, _ := NewDeferredQueue(cli, 0, m, nil)
	fake := archive.NewFakeArchive()
	dr, _ := NewDeferredDrainer(q, fake, time.Hour, nil)

	key := "reports/dup.md"
	if err := q.Enqueue(ctx, key, []byte("b"), archive.PutOptions{}, "inc"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	// First drain re-PUTs and commits.
	dr.drain(ctx)
	if fake.PutCount() != 1 {
		t.Fatalf("first drain PutCount = %d, want 1", fake.PutCount())
	}
	// Simulate a crash-replay: the SAME envelope is enqueued again (a double-drain
	// after a crash before the LPOP committed). The re-PUT must be a HEAD-deduped
	// no-op (no second durable write).
	if err := q.Enqueue(ctx, key, []byte("b"), archive.PutOptions{}, "inc"); err != nil {
		t.Fatalf("re-enqueue: %v", err)
	}
	dr.drain(ctx)
	if fake.PutCount() != 1 {
		t.Fatalf("double-drain caused a second durable write: PutCount = %d, want 1 (deduped)", fake.PutCount())
	}
	if got := counterValue(t, m.Writes, "deduped"); got != 1 {
		t.Fatalf("deduped count = %v, want 1", got)
	}
	if got := gaugeValue(t, m.Deferred); got != 0 {
		t.Fatalf("gauge after double-drain = %v, want 0", got)
	}
}

// TestDrain_UndecodableHead_DeadLettered confirms a malformed envelope at the
// head is dead-lettered (committed + result=error) so it never blocks the drain
// (BI-4/BI-6).
func TestDrain_UndecodableHead_DeadLettered(t *testing.T) {
	ctx := context.Background()
	cli := newRedis(t)
	m := testMetrics(t)
	q, _ := NewDeferredQueue(cli, 0, m, nil)
	fake := archive.NewFakeArchive()
	dr, _ := NewDeferredDrainer(q, fake, time.Hour, nil)

	// Push a non-JSON head directly (and increment the gauge to mirror an enqueue).
	if _, err := cli.EnqueueDeferredReport(ctx, []byte("{not valid json"), 0); err != nil {
		t.Fatalf("raw enqueue: %v", err)
	}
	m.Deferred.Inc()
	dr.drain(ctx)
	if n, _ := cli.DeferredReportLen(ctx); n != 0 {
		t.Fatalf("undecodable head not dead-lettered: len = %d", n)
	}
	if got := counterValue(t, m.Writes, "error"); got != 1 {
		t.Fatalf("error count = %v, want 1", got)
	}
}

// fakeListClient is a listClient seam whose enqueue always fails, proving the
// queue surfaces the enqueue error for the caller's fail-loud fallback (BI-7).
type fakeListClient struct{ enqErr error }

func (f fakeListClient) EnqueueDeferredReport(context.Context, []byte, int64) (int64, error) {
	return 0, f.enqErr
}
func (f fakeListClient) PeekDeferredReport(context.Context) ([]byte, bool, error) {
	return nil, false, nil
}
func (f fakeListClient) CommitDeferredReport(context.Context) error       { return nil }
func (f fakeListClient) DeferredReportLen(context.Context) (int64, error) { return 0, nil }

// TestEnqueue_RedisDown_SurfacesError confirms an enqueue failure (Redis down)
// is surfaced as an error (the caller falls back to fail-loud) and the gauge is
// NOT incremented (BI-7/BI-8).
func TestEnqueue_RedisDown_SurfacesError(t *testing.T) {
	ctx := context.Background()
	m := testMetrics(t)
	q, err := newDeferredQueue(fakeListClient{enqErr: errors.New("redis down")}, 0, m, nil)
	if err != nil {
		t.Fatalf("queue: %v", err)
	}
	if err := q.Enqueue(ctx, "reports/x.md", []byte("b"), archive.PutOptions{}, "inc"); err == nil {
		t.Fatal("enqueue should surface the redis-down error")
	}
	if got := gaugeValue(t, m.Deferred); got != 0 {
		t.Fatalf("gauge after failed enqueue = %v, want 0 (incremented on confirmed enqueue only)", got)
	}
}

// TestEnqueue_BoundedCap_DropsOldestAndCounts confirms a cap overflow drops the
// oldest, counts dropped{reason=queue_full}, and keeps the gauge consistent
// (PO ratification 7).
func TestEnqueue_BoundedCap_DropsOldestAndCounts(t *testing.T) {
	ctx := context.Background()
	cli := newRedis(t)
	m := testMetrics(t)
	q, _ := NewDeferredQueue(cli, 2, m, nil) // cap 2

	for i := 0; i < 4; i++ {
		if err := q.Enqueue(ctx, "reports/k.md", []byte("b"), archive.PutOptions{}, "inc"); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	// 4 enqueues, cap 2 => 2 dropped.
	if got := counterValue(t, m.Dropped, "queue_full"); got != 2 {
		t.Fatalf("dropped count = %v, want 2", got)
	}
	// Gauge tracks the true depth: 4 increments - 2 drops = 2.
	if got := gaugeValue(t, m.Deferred); got != 2 {
		t.Fatalf("gauge = %v, want 2", got)
	}
	if n, _ := cli.DeferredReportLen(ctx); n != 2 {
		t.Fatalf("queue len = %d, want 2", n)
	}
}

// TestNewDeferredQueue_NilGuards confirms the constructor rejects a nil client
// and nil metric handles.
func TestNewDeferredQueue_NilGuards(t *testing.T) {
	m := testMetrics(t)
	if _, err := NewDeferredQueue(nil, 0, m, nil); err == nil {
		t.Fatal("nil client should be rejected")
	}
	cli := newRedis(t)
	if _, err := NewDeferredQueue(cli, 0, Metrics{}, nil); err == nil {
		t.Fatal("nil metric handles should be rejected")
	}
}

// TestRun_CtxCancel confirms Run returns nil on context cancellation.
func TestRun_CtxCancel(t *testing.T) {
	cli := newRedis(t)
	m := testMetrics(t)
	q, _ := NewDeferredQueue(cli, 0, m, nil)
	dr, _ := NewDeferredDrainer(q, archive.NewFakeArchive(), 10*time.Millisecond, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := dr.Run(ctx); err != nil {
		t.Fatalf("Run on cancelled ctx = %v, want nil", err)
	}
}
