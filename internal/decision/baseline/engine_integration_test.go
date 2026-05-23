//go:build integration

package baseline_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/olokotoh/olaitan/internal/correlator/trigger"
	"github.com/olokotoh/olaitan/internal/decision/baseline"
	natsclient "github.com/olokotoh/olaitan/internal/nats"
	redisclient "github.com/olokotoh/olaitan/internal/redis"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/subjects"
)

type recordingEmitter struct {
	calls atomic.Int64
	last  atomic.Value // schema.BaselineDeviation
	all   []schema.BaselineDeviation
	mu    chan struct{}
}

func newRecordingEmitter() *recordingEmitter {
	r := &recordingEmitter{mu: make(chan struct{}, 1)}
	r.mu <- struct{}{}
	return r
}

func (r *recordingEmitter) FireBaselineDeviation(_ context.Context, _ string, dev schema.BaselineDeviation) (*schema.EvidencePackage, error) {
	r.calls.Add(1)
	r.last.Store(dev)
	<-r.mu
	r.all = append(r.all, dev)
	r.mu <- struct{}{}
	return nil, nil
}

func startTestNATSServer(t *testing.T) *natsserver.Server {
	t.Helper()
	opts := &natsserver.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir(), NoLog: true, NoSigs: true}
	srv, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatalf("new nats server: %v", err)
	}
	srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatalf("nats server not ready")
	}
	t.Cleanup(srv.Shutdown)
	return srv
}

func testStreamConfigs() []jetstream.StreamConfig {
	return []jetstream.StreamConfig{
		{Name: "EVIDENCE", Subjects: []string{subjects.EvidencePrefix + ">"}, MaxAge: time.Hour, MaxBytes: 16 * 1024 * 1024, Storage: jetstream.MemoryStorage, Retention: jetstream.LimitsPolicy},
	}
}

func newRedis(t *testing.T, addr string) *redisclient.Client {
	t.Helper()
	cfg := redisclient.DefaultConfig()
	cfg.Addr = addr
	c, err := redisclient.NewClient(cfg)
	if err != nil {
		t.Fatalf("redis: %v", err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

func newEngine(t *testing.T, nc *natsclient.Client, store *baseline.Store, warmup *baseline.Warmup, emit baseline.BaselineDeviationEmitter) *baseline.Engine {
	t.Helper()
	e, err := baseline.New(baseline.Config{
		NATS:    nc,
		Store:   store,
		Warmup:  warmup,
		Emitter: emit,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("baseline.New: %v", err)
	}
	return e
}

func flowEvent(dst string, bytesOut float64) schema.Event {
	raw, _ := json.Marshal(map[string]any{"dst_ip": dst, "bytes_out": bytesOut})
	return schema.Event{
		ID:       "ev-" + dst,
		Source:   schema.SourceNetwork,
		Category: schema.CategoryFlow,
		Pod:      schema.PodRef{Namespace: "default", Name: "web-0", UID: "pod-uid-1"},
		Raw:      raw,
	}
}

func packageWithFlows(packageID string, dsts []string) schema.EvidencePackage {
	events := make([]schema.Event, 0, len(dsts))
	for _, d := range dsts {
		events = append(events, flowEvent(d, 100))
	}
	return schema.EvidencePackage{
		SchemaVersion: "1",
		PackageID:     packageID,
		WorkloadID:    "default/Deployment/web",
		WorkloadIdentity: schema.WorkloadIdentity{
			Namespace: "default",
			OwnerKind: "Deployment",
			OwnerName: "web",
		},
		WindowStart: time.Now().UTC().Add(-1 * time.Minute),
		WindowEnd:   time.Now().UTC(),
		Events:      events,
		Trigger:     schema.EvidenceTrigger{Type: trigger.TypeMultiSignal, FiredAt: time.Now().UTC()},
	}
}

func waitFor(t *testing.T, deadline time.Duration, fn func() bool) bool {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		if fn() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func TestIntegration_BaselineEngineEmitsDeviationForOutboundIPSurge(t *testing.T) {
	srv := startTestNATSServer(t)
	nc, err := natsclient.NewClient(natsclient.ClientConfig{URL: srv.ClientURL(), Name: "baseline-engine-test"})
	if err != nil {
		t.Fatalf("nats: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = nc.Close(ctx)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := natsclient.EnsureStreams(ctx, nc.JetStream(), testStreamConfigs()); err != nil {
		t.Fatalf("ensure streams: %v", err)
	}

	mr := startMiniredis(t)
	rc := newRedis(t, mr.Addr())
	store, err := baseline.NewStore(rc)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	w, err := baseline.NewWarmup(store, baseline.WarmupConfig{Duration: 30 * time.Minute})
	if err != nil {
		t.Fatalf("warmup: %v", err)
	}
	// Pre-warm Welford state for outbound_unique_dst_ips so the
	// engine has a baseline to compare against. Save 30 samples
	// averaging 2 unique IPs/window with low variance.
	wf := &baseline.Welford{}
	for i := 0; i < 30; i++ {
		wf.Update(2)
	}
	wf.Update(3)
	saveAll := map[string]*baseline.Welford{
		"outbound_unique_dst_ips":     wf,
		"distinct_exec_paths":         {},
		"outbound_bytes":              {},
		"audit_events_per_min":        {},
		"container_restarts_per_hour": {},
	}
	if err := store.Save(ctx, "default", "Deployment-web", saveAll); err != nil {
		t.Fatalf("preload Save: %v", err)
	}

	emit := newRecordingEmitter()
	e := newEngine(t, nc, store, w, emit)

	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	done := make(chan error, 1)
	go func() { done <- e.Run(runCtx) }()

	// Inject a package with 50 unique destinations -- a clear surge.
	dsts := make([]string, 50)
	for i := 0; i < 50; i++ {
		dsts[i] = "10.0.0." + itoa(i+1)
	}
	pkg := packageWithFlows("pkg-surge-1", dsts)
	if _, err := nc.PublishJS(ctx, subjects.EvidencePackages, pkg, jetstream.WithMsgID(pkg.PackageID)); err != nil {
		t.Fatalf("publish: %v", err)
	}

	if !waitFor(t, 5*time.Second, func() bool { return emit.calls.Load() >= 1 }) {
		t.Fatalf("emitter never fired; got %d calls", emit.calls.Load())
	}

	got := emit.last.Load().(schema.BaselineDeviation)
	if got.Metric != "outbound_unique_dst_ips" {
		t.Errorf("Metric = %q want outbound_unique_dst_ips", got.Metric)
	}
	if got.Value != 50 {
		t.Errorf("Value = %v want 50", got.Value)
	}
	if got.Sigma < 3.0 {
		t.Errorf("Sigma = %v, expected >= 3", got.Sigma)
	}

	runCancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Errorf("Run did not return")
	}
}

func TestIntegration_ReEntrancyGuardSkipsBaselineDeviationPackages(t *testing.T) {
	srv := startTestNATSServer(t)
	nc, err := natsclient.NewClient(natsclient.ClientConfig{URL: srv.ClientURL(), Name: "baseline-reentry"})
	if err != nil {
		t.Fatalf("nats: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = nc.Close(ctx)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := natsclient.EnsureStreams(ctx, nc.JetStream(), testStreamConfigs()); err != nil {
		t.Fatalf("ensure streams: %v", err)
	}

	mr := startMiniredis(t)
	rc := newRedis(t, mr.Addr())
	store, _ := baseline.NewStore(rc)
	w, _ := baseline.NewWarmup(store, baseline.WarmupConfig{Duration: 30 * time.Minute})

	emit := newRecordingEmitter()
	e, err := baseline.New(baseline.Config{
		NATS: nc, Store: store, Warmup: w, Emitter: emit,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("baseline.New: %v", err)
	}
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	done := make(chan error, 1)
	go func() { done <- e.Run(runCtx) }()

	pkg := packageWithFlows("pkg-reentry", []string{"10.0.0.1", "10.0.0.2"})
	pkg.Trigger.Type = trigger.TypeBaselineDeviation
	if _, err := nc.PublishJS(ctx, subjects.EvidencePackages, pkg, jetstream.WithMsgID(pkg.PackageID)); err != nil {
		t.Fatalf("publish: %v", err)
	}
	time.Sleep(500 * time.Millisecond)
	if got := emit.calls.Load(); got != 0 {
		t.Errorf("emit.calls = %d, want 0 (re-entrancy guard must skip)", got)
	}

	runCancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Errorf("Run did not return")
	}
}

func TestIntegration_WarmupActiveSuppressesDeviation(t *testing.T) {
	srv := startTestNATSServer(t)
	nc, err := natsclient.NewClient(natsclient.ClientConfig{URL: srv.ClientURL(), Name: "baseline-warmup"})
	if err != nil {
		t.Fatalf("nats: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = nc.Close(ctx)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := natsclient.EnsureStreams(ctx, nc.JetStream(), testStreamConfigs()); err != nil {
		t.Fatalf("ensure streams: %v", err)
	}

	mr := startMiniredis(t)
	rc := newRedis(t, mr.Addr())
	store, _ := baseline.NewStore(rc)
	w, _ := baseline.NewWarmup(store, baseline.WarmupConfig{Duration: 30 * time.Minute})

	// Pre-warm a baseline that would otherwise trigger.
	wf := &baseline.Welford{}
	for i := 0; i < 30; i++ {
		wf.Update(2)
	}
	wf.Update(3)
	all := map[string]*baseline.Welford{
		"outbound_unique_dst_ips":     wf,
		"distinct_exec_paths":         {},
		"outbound_bytes":              {},
		"audit_events_per_min":        {},
		"container_restarts_per_hour": {},
	}
	if err := store.Save(ctx, "default", "Deployment-web", all); err != nil {
		t.Fatalf("preload: %v", err)
	}
	// Engage warm-up by publishing a restart lifecycle event package
	// FIRST and confirming the engine reacts, then publish the surge
	// package and assert it does NOT emit.
	emit := newRecordingEmitter()
	e := newEngine(t, nc, store, w, emit)

	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	done := make(chan error, 1)
	go func() { done <- e.Run(runCtx) }()

	restartPkg := schema.EvidencePackage{
		SchemaVersion:    "1",
		PackageID:        "pkg-restart-1",
		WorkloadID:       "default/Deployment/web",
		WorkloadIdentity: schema.WorkloadIdentity{Namespace: "default", OwnerKind: "Deployment", OwnerName: "web"},
		WindowStart:      time.Now().UTC().Add(-1 * time.Minute),
		WindowEnd:        time.Now().UTC(),
		Events: []schema.Event{{
			ID: "ev-restart", Source: schema.SourceRuntime, Category: schema.CategoryLifecycle,
			Pod: schema.PodRef{Namespace: "default", Name: "web-0"}, Tags: []string{"attempt:1"},
		}},
		Trigger: schema.EvidenceTrigger{Type: trigger.TypeMultiSignal, FiredAt: time.Now().UTC()},
	}
	if _, err := nc.PublishJS(ctx, subjects.EvidencePackages, restartPkg, jetstream.WithMsgID(restartPkg.PackageID)); err != nil {
		t.Fatalf("publish restart: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	// Now publish a surge package; warm-up must suppress the emit.
	dsts := make([]string, 50)
	for i := 0; i < 50; i++ {
		dsts[i] = "10.0.0." + itoa(i+1)
	}
	surge := packageWithFlows("pkg-surge-warmup", dsts)
	if _, err := nc.PublishJS(ctx, subjects.EvidencePackages, surge, jetstream.WithMsgID(surge.PackageID)); err != nil {
		t.Fatalf("publish surge: %v", err)
	}
	time.Sleep(500 * time.Millisecond)
	if got := emit.calls.Load(); got != 0 {
		t.Errorf("emit.calls = %d, want 0 (warm-up active must suppress emission)", got)
	}

	// Verify warm-up state was persisted (AC4).
	_, _, present, err := store.LoadWarmup(ctx, "default", "Deployment-web")
	if err != nil {
		t.Fatalf("LoadWarmup: %v", err)
	}
	if !present {
		t.Errorf("warm-up state was not persisted after restart event")
	}

	runCancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Errorf("Run did not return")
	}
}

// TestIntegration_BaselineSurvivesControllerRestart locks AC4: a
// controller restart preserves Welford state in Redis and the
// reloaded engine produces the same sigma as the originating engine.
func TestIntegration_BaselineSurvivesControllerRestart(t *testing.T) {
	mr := startMiniredis(t)
	rc1 := newRedis(t, mr.Addr())
	store1, _ := baseline.NewStore(rc1)

	wf := &baseline.Welford{}
	for i := 0; i < 30; i++ {
		wf.Update(2)
	}
	wf.Update(3)
	probe := wf.Sigma(50)

	all := map[string]*baseline.Welford{
		"outbound_unique_dst_ips":     wf,
		"distinct_exec_paths":         {},
		"outbound_bytes":              {},
		"audit_events_per_min":        {},
		"container_restarts_per_hour": {},
	}
	if err := store1.Save(context.Background(), "default", "Deployment-web", all); err != nil {
		t.Fatalf("Save: %v", err)
	}

	rc2 := newRedis(t, mr.Addr())
	store2, _ := baseline.NewStore(rc2)
	reloaded, err := store2.Load(context.Background(), "default", "Deployment-web", baseline.MetricNames())
	if err != nil {
		t.Fatalf("Load after restart: %v", err)
	}
	got := reloaded["outbound_unique_dst_ips"].Sigma(50)
	if probe != got {
		t.Errorf("post-restart sigma drift: got %v want %v", got, probe)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	out := []byte{}
	for i > 0 {
		out = append([]byte{byte('0' + i%10)}, out...)
		i /= 10
	}
	return string(out)
}
