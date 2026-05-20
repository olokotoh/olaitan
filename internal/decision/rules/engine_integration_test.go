//go:build integration

package rules

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/olokotoh/olaitan/internal/correlator/trigger"
	"github.com/olokotoh/olaitan/internal/decision/rules/loader"
	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// recordingEmitter mirrors the captureEmitter in engine_test.go but
// is integration-scope so the unit tests don't drag in NATS.
type recordingEmitter struct {
	calls atomic.Int64
	last  atomic.Value // schema.RuleMatch
}

func (r *recordingEmitter) FireRuleMatch(_ context.Context, _ string, match schema.RuleMatch) (*schema.EvidencePackage, error) {
	r.calls.Add(1)
	r.last.Store(match)
	return nil, nil
}

func TestIntegration_EngineEmitsRuleMatchForFalcoXmrigPackage(t *testing.T) {
	srv := startTestNATSServer(t)
	nc, err := natsclient.NewClient(natsclient.ClientConfig{URL: srv.ClientURL(), Name: "rules-engine-test"})
	if err != nil {
		t.Fatalf("nats client: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = nc.Close(ctx)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := natsclient.EnsureStreams(ctx, nc.JetStream(), testStreamConfigs()); err != nil {
		t.Fatalf("ensure streams: %v", err)
	}

	dir := t.TempDir()
	copyRuleFile(t, "testdata/positive/OLT-IMPACT-005.yaml", filepath.Join(dir, "olt-impact-005.yaml"))
	l := loader.New(dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := l.Load(); err != nil {
		t.Fatalf("loader.Load: %v", err)
	}

	emit := &recordingEmitter{}
	e, err := New(Config{
		NATS:    nc,
		Loader:  l,
		Emitter: emit,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("rules.New: %v", err)
	}

	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	done := make(chan error, 1)
	go func() { done <- e.Run(runCtx) }()

	// Publish a synthetic EvidencePackage matching OLT-IMPACT-005.
	raw, _ := json.Marshal(map[string]any{
		"process.exe":             "/usr/local/bin/xmrig",
		"k8s.workload.owner_kind": "Deployment",
		"network.dst_port":        3333,
	})
	pkg := schema.EvidencePackage{
		SchemaVersion: "1",
		PackageID:     "pkg-xmrig-1",
		WorkloadID:    "tenant-acme/Deployment/web",
		WorkloadPosture: &schema.WorkloadPosture{
			Identity: schema.WorkloadIdentity{
				Namespace: "tenant-acme",
				OwnerKind: "Deployment",
				OwnerName: "web",
			},
		},
		Events: []schema.Event{
			{
				ID:       "ev-1",
				Source:   schema.SourceFalco,
				Category: schema.CategorySyscall,
				Raw:      raw,
			},
		},
		Trigger: schema.EvidenceTrigger{Type: trigger.TypeMultiSignal, FiredAt: time.Now().UTC()},
	}
	if _, err := nc.PublishJS(ctx, subjects.EvidencePackages, pkg, jetstream.WithMsgID(pkg.PackageID)); err != nil {
		t.Fatalf("publish: %v", err)
	}

	deadline := time.After(3 * time.Second)
	for {
		if emit.calls.Load() >= 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("emitter never fired; got %d calls", emit.calls.Load())
		case <-time.After(10 * time.Millisecond):
		}
	}

	v := emit.last.Load()
	if v == nil {
		t.Fatalf("emitter recorded no match")
	}
	got := v.(schema.RuleMatch)
	if got.RuleID != "OLT-IMPACT-005" {
		t.Errorf("RuleID = %q, want OLT-IMPACT-005", got.RuleID)
	}
	if got.Severity != "75" {
		t.Errorf("Severity = %q, want 75", got.Severity)
	}
	if len(got.MitreTags) != 1 || got.MitreTags[0] != "T1496" {
		t.Errorf("MitreTags = %v, want [T1496]", got.MitreTags)
	}

	runCancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Errorf("Run did not return within 2s of ctx cancel")
	}
}

func TestIntegration_ReEntrancyGuardSkipsRuleMatchPackages(t *testing.T) {
	srv := startTestNATSServer(t)
	nc, err := natsclient.NewClient(natsclient.ClientConfig{URL: srv.ClientURL(), Name: "rules-engine-reentry"})
	if err != nil {
		t.Fatalf("nats client: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = nc.Close(ctx)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := natsclient.EnsureStreams(ctx, nc.JetStream(), testStreamConfigs()); err != nil {
		t.Fatalf("ensure streams: %v", err)
	}

	dir := t.TempDir()
	copyRuleFile(t, "testdata/positive/OLT-IMPACT-005.yaml", filepath.Join(dir, "olt-impact-005.yaml"))
	l := loader.New(dir, nil)
	if err := l.Load(); err != nil {
		t.Fatalf("loader.Load: %v", err)
	}

	emit := &recordingEmitter{}
	e, err := New(Config{
		NATS: nc, Loader: l, Emitter: emit,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("rules.New: %v", err)
	}

	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	done := make(chan error, 1)
	go func() { done <- e.Run(runCtx) }()

	// Publish a package whose trigger type is rule_match - the
	// engine MUST skip it (re-entrancy guard).
	raw, _ := json.Marshal(map[string]any{"process.exe": "/usr/local/bin/xmrig"})
	pkg := schema.EvidencePackage{
		PackageID:  "pkg-reentry-1",
		WorkloadID: "ns/Deployment/web",
		Events:     []schema.Event{{ID: "ev-1", Raw: raw}},
		Trigger:    schema.EvidenceTrigger{Type: trigger.TypeRuleMatch, FiredAt: time.Now().UTC()},
	}
	if _, err := nc.PublishJS(ctx, subjects.EvidencePackages, pkg, jetstream.WithMsgID(pkg.PackageID)); err != nil {
		t.Fatalf("publish: %v", err)
	}

	time.Sleep(500 * time.Millisecond)
	if got := emit.calls.Load(); got != 0 {
		t.Errorf("emit.calls = %d, want 0 (rule_match-triggered packages must be skipped)", got)
	}
	if got := e.skippedSelf.Load(); got == 0 {
		t.Errorf("skippedSelf = 0, want >0 (re-entrancy counter must record the skip)")
	}

	runCancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Errorf("Run did not return")
	}
}

func TestIntegration_HotReloadAddsNewRule(t *testing.T) {
	srv := startTestNATSServer(t)
	nc, err := natsclient.NewClient(natsclient.ClientConfig{URL: srv.ClientURL(), Name: "rules-engine-hotreload"})
	if err != nil {
		t.Fatalf("nats client: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = nc.Close(ctx)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := natsclient.EnsureStreams(ctx, nc.JetStream(), testStreamConfigs()); err != nil {
		t.Fatalf("ensure streams: %v", err)
	}

	dir := t.TempDir()
	// Start with the IMPACT-005 rule only.
	copyRuleFile(t, "testdata/positive/OLT-IMPACT-005.yaml", filepath.Join(dir, "olt-impact-005.yaml"))
	l := loader.New(dir, nil)
	if err := l.Load(); err != nil {
		t.Fatalf("loader.Load: %v", err)
	}

	emit := &recordingEmitter{}
	e, err := New(Config{
		NATS: nc, Loader: l, Emitter: emit,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("rules.New: %v", err)
	}
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	watchCtx, watchCancel := context.WithCancel(ctx)
	defer watchCancel()
	go func() { _ = l.Watch(watchCtx) }()
	done := make(chan error, 1)
	go func() { done <- e.Run(runCtx) }()

	// Give the fsnotify watcher a moment to register its inotify
	// fd against the rule dir before we mutate it.
	time.Sleep(100 * time.Millisecond)

	if got := e.loadedCount.Load(); got != 1 {
		t.Errorf("initial loadedCount = %d, want 1", got)
	}

	// Add a second rule and wait for the hot-reload subscriber to
	// fire.
	const additional = `
title: Tenant namespace gate
id: OLT-NET-001
attack:
  - T1071
severity: 40
detection:
  sel:
    k8s.pod.namespace|startswith: 'tenant-'
  condition: sel
`
	if err := os.WriteFile(filepath.Join(dir, "olt-net-001.yaml"), []byte(additional), 0o600); err != nil {
		t.Fatalf("write additional rule: %v", err)
	}

	deadline := time.After(3 * time.Second)
	for {
		if e.loadedCount.Load() == 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("loadedCount never reached 2; got %d", e.loadedCount.Load())
		case <-time.After(50 * time.Millisecond):
		}
	}
	if e.reloadSuccess.Load() == 0 {
		t.Errorf("reloadSuccess = 0, want >0")
	}

	runCancel()
	watchCancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Errorf("Run did not return")
	}
}

// startTestNATSServer mirrors the correlator integration suite's
// helper so we don't drag in a third helper package. Kept local
// because the engine tests don't share a build tag with the
// correlator package.
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
		{Name: "EVENTS_RAW", Subjects: []string{subjects.RawPrefix + ">"}, MaxAge: time.Hour, MaxBytes: 16 * 1024 * 1024, MaxMsgSize: 512 * 1024, Storage: jetstream.MemoryStorage, Retention: jetstream.LimitsPolicy},
		{Name: "EVIDENCE", Subjects: []string{subjects.EvidencePrefix + ">"}, MaxAge: time.Hour, MaxBytes: 16 * 1024 * 1024, Storage: jetstream.MemoryStorage, Retention: jetstream.LimitsPolicy},
	}
}

func copyRuleFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
}
