//go:build integration

package metrics_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil/promlint"
	"golang.org/x/sync/errgroup"

	"github.com/olokotoh/olaitan/internal/health"
	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/sourcehealth"
)

// fakeIntegrationAdapter mirrors the unit-test fakeAdapter at
// integration scope. Tests use the trackable Tracker to simulate
// upstream disconnects within the AC2 10s budget.
type fakeIntegrationAdapter struct {
	tracker sourcehealth.Tracker
	events  atomic.Int64
}

func (f *fakeIntegrationAdapter) Health() sourcehealth.Reader { return &f.tracker }
func (f *fakeIntegrationAdapter) EventsTotal() int64          { return f.events.Load() }

func integrationLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func pickIntegrationPort(t *testing.T) string {
	t.Helper()
	// Defer to net.Listen-style kernel-assigned port so parallel
	// integration tests do not collide on a static :9090.
	return "127.0.0.1:0"
}

// TestIntegration_HealthGaugeWithinTenSecondBudget asserts AC2: a
// scrape made within 10 seconds of MarkUnhealthy observes the gauge
// transitioned to 0. The test exercises the full HTTP path (real
// httptest.NewServer via metrics.Server.Start) so the NFR36
// "no-mock-only" invariant holds at the substrate boundary.
func TestIntegration_HealthGaugeWithinTenSecondBudget(t *testing.T) {
	t.Parallel()

	a := &fakeIntegrationAdapter{}
	a.tracker.MarkHealthy()
	reg := metrics.NewRegistry()
	if err := reg.RegisterAdapter("fake", a.Health(), a.EventsTotal); err != nil {
		t.Fatalf("RegisterAdapter: %v", err)
	}

	addr := pickIntegrationPort(t)
	srv := metrics.New(addr, integrationLogger(), reg)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx) }()
	resolvedAddr := waitForBoundAddr(t, srv)

	// Confirm initial state: healthy=1.
	body := mustScrape(t, resolvedAddr)
	if !strings.Contains(body, `olaitan_source_healthy{source="fake"} 1`) {
		t.Fatalf("initial gauge: want 1, body:\n%s", body)
	}

	// Simulate upstream disconnect at t=0; the AC2 budget starts now.
	mark := time.Now()
	a.tracker.MarkUnhealthy(errors.New("simulated disconnect"))

	// Poll the endpoint every 100ms until the gauge reads 0 or the
	// 10s budget expires.
	deadline := mark.Add(10 * time.Second)
	transition := time.Time{}
	for time.Now().Before(deadline) {
		body := mustScrape(t, resolvedAddr)
		if strings.Contains(body, `olaitan_source_healthy{source="fake"} 0`) {
			transition = time.Now()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if transition.IsZero() {
		t.Fatalf("gauge did not transition to 0 within 10s budget; final scrape body:\n%s", mustScrape(t, resolvedAddr))
	}
	elapsed := transition.Sub(mark)
	if elapsed > 10*time.Second {
		t.Errorf("AC2 budget exceeded: gauge took %s to transition (ceiling 10s)", elapsed)
	}
	t.Logf("AC2 gauge transition latency: %s (ceiling 10s)", elapsed)

	cancel()
	if err := <-errCh; err != nil {
		t.Errorf("Server.Start: got %v, want nil", err)
	}
}

// TestIntegration_DualServerGracefulShutdown asserts the two-server
// lifecycle from Dev Notes binding interpretation 5: internal/health
// and internal/metrics run under the same errgroup, and ctx-cancel
// drains both within the 5s shutdownTimeout budget without either
// blocking the other.
func TestIntegration_DualServerGracefulShutdown(t *testing.T) {
	t.Parallel()

	healthAddr := pickIntegrationPort(t)
	metricsAddr := pickIntegrationPort(t)

	healthSrv := health.New(healthAddr, integrationLogger(), nil)
	metricsSrv := metrics.New(metricsAddr, integrationLogger(), metrics.NewRegistry())

	ctx, cancel := context.WithCancel(t.Context())
	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error { return healthSrv.Start(gctx) })
	g.Go(func() error { return metricsSrv.Start(gctx) })

	// Give both servers a moment to bind before we cancel.
	time.Sleep(150 * time.Millisecond)

	shutdownStart := time.Now()
	cancel()

	done := make(chan error, 1)
	go func() { done <- g.Wait() }()
	select {
	case err := <-done:
		elapsed := time.Since(shutdownStart)
		if err != nil {
			t.Errorf("dual shutdown: got %v, want nil", err)
		}
		// Each server's shutdownTimeout is 5s; the test ceiling allows
		// generous slack for goroutine scheduling on a loaded CI runner
		// without making the assertion meaningless.
		if elapsed > 7*time.Second {
			t.Errorf("dual shutdown took %s, expected < 7s", elapsed)
		}
		t.Logf("dual graceful shutdown latency: %s", elapsed)
	case <-time.After(15 * time.Second):
		t.Fatalf("dual shutdown deadlocked")
	}
}

// TestIntegration_PromlintZeroProblems gates NFR32 at the integration
// boundary: every registered metric has documented HELP, TYPE, name,
// labels, and unit. promlint flags violations like missing-help-text
// or counter-name-without-_total which would otherwise sneak past
// unit tests that only check for substring presence.
//
// Substrate note: this test deliberately uses scrapeViaServer (an
// in-process handler dispatch) rather than a real httptest.NewServer.
// promlint is a static check on the rendered text format -- the network
// substrate adds nothing to the lint result and would force this test
// to bind a TCP port for no analytical gain. The other three
// TestIntegration_* tests in this file (HealthGauge, DualServer,
// ConcurrentScrapes) do exercise the real HTTP surface, so NFR36
// substrate compliance is met overall. AC7 binding interpretation #9
// in the story Dev Notes documents the carve-out (Review D2).
//
// Coverage note: this test registers a fake "applog" source against
// the same Registry the production code uses. Production only wires
// four streaming sources from startCollectorRing (falco, audit,
// runtime, network); applog runs in a per-pod sidecar that has no
// metrics surface as of Story 1.12. See AC1 binding interpretation #8.
func TestIntegration_PromlintZeroProblems(t *testing.T) {
	t.Parallel()

	reg := metrics.NewRegistry()
	// Register all five streaming sources plus the posture counters
	// so the linter sees the full Story 1.12 surface in one pass.
	sources := []string{"falco", "audit", "runtime", "network", "applog"}
	for _, s := range sources {
		a := &fakeIntegrationAdapter{}
		if err := reg.RegisterAdapter(s, a.Health(), a.EventsTotal); err != nil {
			t.Fatalf("RegisterAdapter(%q): %v", s, err)
		}
	}
	getters := metrics.PostureGetters{
		"cache_hit":    func() int64 { return 0 },
		"cache_miss":   func() int64 { return 0 },
		"cache_bypass": func() int64 { return 0 },
		"api_errors":   func() int64 { return 0 },
		"orphan_pods":  func() int64 { return 0 },
		"unavailable":  func() int64 { return 0 },
	}
	if err := reg.RegisterPostureCounters(getters); err != nil {
		t.Fatalf("RegisterPostureCounters: %v", err)
	}

	body := scrapeViaServer(t, reg)
	linter := promlint.New(strings.NewReader(body))
	problems, err := linter.Lint()
	if err != nil {
		t.Fatalf("promlint: %v", err)
	}
	if len(problems) != 0 {
		for _, p := range problems {
			t.Errorf("promlint problem: metric=%q text=%q", p.Metric, p.Text)
		}
		t.Fatalf("promlint found %d problem(s); see error log", len(problems))
	}
}

// TestIntegration_ConcurrentScrapesNoDataRace exercises the
// concurrent-scrape-vs-write contract: 1k parallel scrapes against
// the real HTTP surface while writers increment the underlying
// atomics. Race detector + NFR35 substrate.
func TestIntegration_ConcurrentScrapesNoDataRace(t *testing.T) {
	t.Parallel()

	a := &fakeIntegrationAdapter{}
	a.tracker.MarkHealthy()
	reg := metrics.NewRegistry()
	if err := reg.RegisterAdapter("falco", a.Health(), a.EventsTotal); err != nil {
		t.Fatalf("RegisterAdapter: %v", err)
	}

	addr := pickIntegrationPort(t)
	srv := metrics.New(addr, integrationLogger(), reg)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx) }()
	resolvedAddr := waitForBoundAddr(t, srv)

	const writers, perWriter, scrapers, scrapesEach = 4, 10_000, 8, 100
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perWriter; j++ {
				a.events.Add(1)
			}
		}()
	}
	for i := 0; i < scrapers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < scrapesEach; j++ {
				_ = mustScrape(t, resolvedAddr)
			}
		}()
	}
	wg.Wait()

	if got := a.EventsTotal(); got != int64(writers*perWriter) {
		t.Errorf("counter: got %d, want %d", got, writers*perWriter)
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Errorf("Start: %v", err)
	}
}

// waitForBoundAddr polls Server.Addr() until the listener resolves a
// kernel-assigned port, then polls the /metrics endpoint until it
// returns 200. Returns the resolved address. Times out after 2s.
func waitForBoundAddr(t *testing.T, srv *metrics.Server) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if a := srv.Addr(); a != "" {
			// Confirm the listener actually serves before returning.
			resp, err := http.Get("http://" + a + "/metrics")
			if err == nil {
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return a
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("metrics server did not bind within 2s")
	return ""
}

// mustScrape performs a single GET on the /metrics endpoint and
// returns the body. Fails the test on any non-200 response or read
// error so callers can treat the return value as trusted text.
func mustScrape(t *testing.T, addr string) string {
	t.Helper()
	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("scrape status: got %d, want 200", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("scrape body: %v", err)
	}
	return string(b)
}

// scrapeViaServer is a no-HTTP-server convenience: render the
// metrics through the in-process handler so a test that only wants
// the text format can avoid binding a TCP socket.
func scrapeViaServer(t *testing.T, reg *metrics.Registry) string {
	t.Helper()
	// Drive the handler via a recorder so the test does not need a
	// listener at all. The promlint test does not need the network
	// substrate; the gauge-transition test above does.
	rec := newRecorder()
	req, err := http.NewRequest(http.MethodGet, "/metrics", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	reg.Handler().ServeHTTP(rec, req)
	if rec.code != http.StatusOK {
		t.Fatalf("handler status: got %d, want 200", rec.code)
	}
	return rec.body.String()
}

// recorder is a minimal http.ResponseWriter test stub. Kept inline
// rather than importing net/http/httptest.ResponseRecorder so the
// imports stay tight.
type recorder struct {
	headers http.Header
	body    strings.Builder
	code    int
}

func newRecorder() *recorder {
	return &recorder{headers: make(http.Header), code: http.StatusOK}
}

func (r *recorder) Header() http.Header         { return r.headers }
func (r *recorder) Write(p []byte) (int, error) { return r.body.Write(p) }
func (r *recorder) WriteHeader(code int)        { r.code = code }
