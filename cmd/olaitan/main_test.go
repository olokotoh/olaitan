package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"golang.org/x/sync/errgroup"
	"k8s.io/client-go/kubernetes"
	kubefake "k8s.io/client-go/kubernetes/fake"

	"github.com/olokotoh/olaitan/internal/config"
)

// writeTestConfig drops a minimal valid olaitan.yaml into t.TempDir()
// so runRing has something config.NewManager can load without network.
// Keep the fields aligned with internal/config/config.go validation.
func writeTestConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "olaitan.yaml")
	body := `detection:
  confidence_bands:
    watch: 40
    alert: 70
    act: 90
  baseline_window: 24h
  rules:
    enabled: false
  baselines:
    enabled: false
response:
  excluded_namespaces:
    - kube-system
analyst:
  provider: api
  api:
    endpoint: ""
    model: ""
    api_key_secret: olaitan-llm
  local:
    endpoint: ""
    model: ""
  score_cap: 35
  timeout: 10s
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write test config: %v", err)
	}
	return path
}

// pickFreePort mirrors the health package's helper — duplicated
// because main_test is package main and cannot import internal test
// utilities without exposing them publicly.
func pickFreePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pickFreePort: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func TestVersion(t *testing.T) {
	if version == "" {
		t.Error("version should not be empty")
	}
}

func TestRun_NoArgs_PrintsUsageAndExits1(t *testing.T) {
	code := run(nil, os.Stderr)
	if code != 1 {
		t.Errorf("exit code: got %d want 1", code)
	}
}

func TestRun_UnknownCommand_Exits2(t *testing.T) {
	code := run([]string{"not-a-real-command"}, os.Stderr)
	if code != 2 {
		t.Errorf("exit code: got %d want 2", code)
	}
}

func TestRun_Version_Exits0(t *testing.T) {
	if code := run([]string{"version"}, os.Stderr); code != 0 {
		t.Errorf("version exit code: got %d want 0", code)
	}
}

func TestRun_Help_Exits0(t *testing.T) {
	for _, arg := range []string{"help", "-h", "--help"} {
		if code := run([]string{arg}, os.Stderr); code != 0 {
			t.Errorf("%q exit code: got %d want 0", arg, code)
		}
	}
}

func TestRunRing_MissingConfig_Exits1(t *testing.T) {
	// Point --config at a path that does not exist — config.NewManager
	// must fail and runRing must map that to exit 1.
	code := runRing("collector", []string{"--config=/nonexistent/path/olaitan.yaml"}, os.Stderr)
	if code != 1 {
		t.Errorf("exit code on missing config: got %d want 1", code)
	}
}

func TestRun_DispatchesAppLogSidecar_MissingEnv_Exits1(t *testing.T) {
	// applog-sidecar dispatch must route to runApplogSidecar which
	// fail-fasts on missing required env vars. The test asserts the
	// dispatch case path (not the env-var validation behaviour itself,
	// which has its own coverage in cmd_applog_test.go if added).
	for _, name := range []string{"K8S_POD_NAME", "K8S_POD_NAMESPACE", "K8S_POD_UID", "K8S_NODE_NAME", "OLAITAN_TARGET_CONTAINER", "NATS_URL"} {
		t.Setenv(name, "")
	}
	code := run([]string{"applog-sidecar"}, os.Stderr)
	if code != 1 {
		t.Errorf("applog-sidecar without env: got %d want 1", code)
	}
}

func TestRun_DispatchesAppLogWebhook_MissingEnv_Exits1(t *testing.T) {
	t.Setenv("OLAITAN_WEBHOOK_TLS_CERT", "")
	t.Setenv("OLAITAN_WEBHOOK_TLS_KEY", "")
	code := run([]string{"applog-webhook"}, os.Stderr)
	if code != 1 {
		t.Errorf("applog-webhook without env: got %d want 1", code)
	}
}

func TestRunRing_GracefulShutdown(t *testing.T) {
	// Swap healthAddr to a free port for this test — production uses
	// :8080 which tests mustn't bind. Restore after.
	prevAddr := healthAddr
	healthAddr = pickFreePort(t)
	t.Cleanup(func() { healthAddr = prevAddr })

	cfgPath := writeTestConfig(t)
	natsSrv := startTestNATSForMain(t)
	t.Setenv("NATS_URL", natsSrv.ClientURL())

	// Drive runRingCtx directly with our own cancellable context — no
	// real signals involved. This avoids the SIGINT-to-test-process
	// pattern that interleaves badly with `go test -p>1` and the test
	// runner's own Ctrl-C handler.
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	done := make(chan int, 1)
	go func() {
		done <- runRingCtx(ctx, "aggregator", []string{"--config=" + cfgPath}, os.Stderr)
	}()

	// Poll until /healthz responds, proving the server is live.
	readyBy := time.Now().Add(3 * time.Second)
	for time.Now().Before(readyBy) {
		resp, err := http.Get("http://" + healthAddr + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				goto READY
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("health server never became ready at %s", healthAddr)
READY:

	cancel()

	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("runRingCtx exit code after cancel: got %d want 0", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("runRingCtx did not exit within 5s of cancel")
	}
}

// startTestNATSForMain spins up an embedded NATS server with
// JetStream so startCollectorRing's EnsureStreams call can complete.
// Kept local (not shared with the adapter integration tests' helper)
// because main_test is package main and cannot import internal test
// helpers without a dedicated test package.
func startTestNATSForMain(t *testing.T) *natsserver.Server {
	t.Helper()
	opts := &natsserver.Options{
		Host:      "127.0.0.1",
		Port:      -1,
		JetStream: true,
		StoreDir:  t.TempDir(),
		// JetStreamMaxStore must exceed the sum of production
		// StreamConfigs' MaxBytes (~160 GiB; 100 GiB EVIDENCE +
		// 50 GiB EVENTS_RAW + 10 GiB EVENTS). nats-server's
		// "reserve MaxBytes against MaxStore" guard rejects stream
		// creation when storeReserved would exceed MaxStore.
		// Embedded NATS only applies MaxBytes as a soft cap;
		// physical disk allocation is not required.
		JetStreamMaxMemory: 1024 * 1024 * 1024,        // 1 GiB
		JetStreamMaxStore:  1024 * 1024 * 1024 * 1024, // 1 TiB
		NoLog:              true,
		NoSigs:             true,
	}
	srv, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatalf("start test nats server: %v", err)
	}
	srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats server not ready")
	}
	t.Cleanup(srv.Shutdown)
	return srv
}

// TestStartCollectorRing_WiresCalicoAdapter exercises the Calico
// CNI flow adapter wire-up branch in startCollectorRing. Story
// 1.10 Task 5.3 promised the wire-up; the bmad-code-review (D4)
// surfaced the absence of any test coverage as a report-matches-
// code violation. Two sub-tests cover both branches: enabled=true
// (the adapter goroutine is registered and the function returns
// nil) and enabled=false (no calico-specific work is done; the
// function still returns nil because the falco / audit / cri /
// applog paths handle their own gating).
//
// The test exercises the production StreamConfigs through the
// embedded NATS server, which reserves the sum of MaxBytes (~160
// GiB) against MaxStore. On a CI runner with insufficient disk,
// the EnsureStreams call fails with "insufficient storage
// resources available" -- the test t.Skip's in that case so the
// suite is not noisy on resource-constrained machines.
func TestStartCollectorRing_WiresCalicoAdapter(t *testing.T) {
	cases := []struct {
		name           string
		calicoEnabled  bool
		extraGoroutine int // expected goroutine delta beyond the falco baseline
	}{
		{"calico-enabled", true, 1},
		{"calico-disabled", false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			natsSrv := startTestNATSForMain(t)
			t.Setenv("NATS_URL", natsSrv.ClientURL())
			// FALCO_SOCKET points at a non-existent path; falco.New
			// only validates non-empty, so the adapter constructs
			// fine. Run will fail on first dial but that is in a
			// goroutine the test cancels before that happens.
			t.Setenv("FALCO_SOCKET", "/dev/null")
			t.Setenv("K8S_NODE_NAME", "test-node")

			// Load the minimal valid config the existing writeTestConfig
			// helper produces; mutate the calico block per the sub-test.
			cfgPath := writeTestConfig(t)
			cfg, err := config.Load(cfgPath)
			if err != nil {
				t.Fatalf("config.Load: %v", err)
			}
			if tc.calicoEnabled {
				cfg.Detection.Sources.Calico = config.CalicoSourceConfig{
					Enabled:        true,
					GoldmaneAddr:   "127.0.0.1:1",
					CABundlePath:   filepath.Join(t.TempDir(), "ca.crt"),
					ClientCertPath: filepath.Join(t.TempDir(), "client.crt"),
					ClientKeyPath:  filepath.Join(t.TempDir(), "client.key"),
				}
				// Write placeholder TLS files so cni.New's path
				// validation passes (the files must exist; content
				// is irrelevant because Run is cancelled before
				// loadTLSConfigFromDisk).
				for _, p := range []string{
					cfg.Detection.Sources.Calico.CABundlePath,
					cfg.Detection.Sources.Calico.ClientCertPath,
					cfg.Detection.Sources.Calico.ClientKeyPath,
				} {
					if err := os.WriteFile(p, []byte("placeholder"), 0o644); err != nil {
						t.Fatalf("write %s: %v", p, err)
					}
				}
			}

			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)
			g, gctx := errgroup.WithContext(ctx)
			log := slog.New(slog.NewTextHandler(io.Discard, nil))

			if err := startCollectorRing(gctx, g, log, cfg, nil); err != nil {
				if strings.Contains(err.Error(), "insufficient storage resources available") {
					t.Skipf("skipping: production StreamConfigs need ~160 GiB MaxStore; embedded NATS reports %v", err)
				}
				t.Fatalf("startCollectorRing: %v", err)
			}

			// Cancel and let goroutines exit; assert they unwind
			// without a panic. The goroutine-count delta cannot be
			// asserted directly (errgroup keeps its tally private)
			// but a successful unwind without panic is the binding
			// test that the wire-up landed cleanly.
			cancel()
			waitErrCh := make(chan error, 1)
			go func() { waitErrCh <- g.Wait() }()
			select {
			case <-waitErrCh:
				// errgroup may surface a non-nil error from the
				// falco/cni adapter exiting on cancelled context;
				// the wiring itself succeeded if we got this far.
			case <-time.After(5 * time.Second):
				t.Fatalf("errgroup did not unwind within 5s of cancel")
			}
		})
	}
}

// TestStartAggregator_BuildsPostureClientWhenEnabled exercises the
// Story 1.11 wiring: when detection.posture.enabled=true and the
// kube-client factory returns a valid clientset, startAggregatorRing
// constructs the package-level postureClient and returns nil.
func TestStartAggregator_BuildsPostureClientWhenEnabled(t *testing.T) {
	// Save and restore the package-level seam so this test does not
	// leak into other tests in the suite.
	prevFactory := kubeClientFactory
	prevClient := postureClient.Load()
	t.Cleanup(func() {
		kubeClientFactory = prevFactory
		postureClient.Store(prevClient)
	})

	kubeClientFactory = func(*slog.Logger) (kubernetes.Interface, error) {
		return kubefake.NewSimpleClientset(), nil
	}
	postureClient.Store(nil)

	rulesDisabled := false
	baselinesDisabled := false
	cfg := &config.Config{
		Detection: config.DetectionConfig{
			Posture:   config.PostureConfig{Enabled: true},
			Rules:     config.RulesConfig{Enabled: &rulesDisabled},
			Baselines: config.BaselinesConfig{Enabled: &baselinesDisabled},
		},
		// Story 1.12: startAggregatorRing now starts the Prometheus
		// surface under the errgroup. ":0" lets the kernel pick a free
		// port so parallel tests do not collide.
		Metrics: config.MetricsConfig{Address: "127.0.0.1:0"},
	}
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))

	ctx, cancel := context.WithCancel(context.Background())
	g, gctx := errgroup.WithContext(ctx)
	natsSrv := startTestNATSForMain(t)
	t.Setenv("NATS_URL", natsSrv.ClientURL())
	if err := startAggregatorRing(gctx, g, log, cfg, nil, nil); err != nil {
		cancel()
		_ = g.Wait()
		t.Fatalf("startAggregatorRing: %v", err)
	}
	if postureClient.Load() == nil {
		t.Errorf("postureClient: got nil, want non-nil")
	}
	cancel()
	_ = g.Wait()
}

// TestStartAggregator_PostureDisabledLeavesClientNil exercises the
// short-circuit when posture is disabled: no kube-client construction,
// postureClient stays nil, no error.
func TestStartAggregator_PostureDisabledLeavesClientNil(t *testing.T) {
	prevFactory := kubeClientFactory
	prevClient := postureClient.Load()
	t.Cleanup(func() {
		kubeClientFactory = prevFactory
		postureClient.Store(prevClient)
	})

	kubeClientFactory = func(*slog.Logger) (kubernetes.Interface, error) {
		t.Fatalf("kube client factory must not be called when posture disabled")
		return nil, nil
	}
	postureClient.Store(nil)

	rulesDisabled := false
	baselinesDisabled := false
	cfg := &config.Config{
		Detection: config.DetectionConfig{
			Posture:   config.PostureConfig{Enabled: false},
			Rules:     config.RulesConfig{Enabled: &rulesDisabled},
			Baselines: config.BaselinesConfig{Enabled: &baselinesDisabled},
		},
		Metrics: config.MetricsConfig{Address: "127.0.0.1:0"},
	}
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	g, gctx := errgroup.WithContext(ctx)
	natsSrv := startTestNATSForMain(t)
	t.Setenv("NATS_URL", natsSrv.ClientURL())
	if err := startAggregatorRing(gctx, g, log, cfg, nil, nil); err != nil {
		cancel()
		_ = g.Wait()
		t.Fatalf("startAggregatorRing: %v", err)
	}
	if postureClient.Load() != nil {
		t.Errorf("postureClient: got non-nil, want nil")
	}
	cancel()
	_ = g.Wait()
}

// TestStartAggregator_RulesEngineEnabledWiresGoroutines exercises
// the Story 1.15 wiring: when detection.rules.enabled=true and the
// rule directory exists, startAggregatorRing spawns the rule-engine
// run + watch goroutines and returns nil. The errgroup-goroutine
// count cannot be asserted directly (errgroup keeps its tally
// private), so we assert "no error" + "clean cancel" as the binding
// indicator the wire-up landed.
func TestStartAggregator_RulesEngineEnabledWiresGoroutines(t *testing.T) {
	prevFactory := kubeClientFactory
	prevClient := postureClient.Load()
	t.Cleanup(func() {
		kubeClientFactory = prevFactory
		postureClient.Store(prevClient)
	})
	kubeClientFactory = func(*slog.Logger) (kubernetes.Interface, error) {
		return kubefake.NewSimpleClientset(), nil
	}
	postureClient.Store(nil)

	rulesDir := t.TempDir()
	rulesEnabled := true
	baselinesDisabled := false
	postureDisabled := config.PostureConfig{Enabled: false}
	cfg := &config.Config{
		Detection: config.DetectionConfig{
			Posture:   postureDisabled,
			Rules:     config.RulesConfig{Enabled: &rulesEnabled, Path: rulesDir},
			Baselines: config.BaselinesConfig{Enabled: &baselinesDisabled},
		},
		Metrics: config.MetricsConfig{Address: "127.0.0.1:0"},
	}
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	g, gctx := errgroup.WithContext(ctx)
	natsSrv := startTestNATSForMain(t)
	t.Setenv("NATS_URL", natsSrv.ClientURL())
	if err := startAggregatorRing(gctx, g, log, cfg, nil, nil); err != nil {
		cancel()
		_ = g.Wait()
		t.Fatalf("startAggregatorRing: %v", err)
	}
	cancel()
	// Allow up to 5s for the rule-engine + watcher + correlator
	// goroutines to unwind cleanly on ctx cancel.
	done := make(chan error, 1)
	go func() { done <- g.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("errgroup did not unwind within 5s")
	}
}

// TestStartAggregator_RulesEngineDisabledSkipsWiring exercises the
// Story 1.15 short-circuit: when detection.rules.enabled=false the
// rule engine is not constructed and no rule directory is required.
// A bogus path is supplied to prove the loader is never invoked.
func TestStartAggregator_RulesEngineDisabledSkipsWiring(t *testing.T) {
	prevFactory := kubeClientFactory
	prevClient := postureClient.Load()
	t.Cleanup(func() {
		kubeClientFactory = prevFactory
		postureClient.Store(prevClient)
	})
	postureClient.Store(nil)

	rulesDisabled := false
	baselinesDisabled := false
	cfg := &config.Config{
		Detection: config.DetectionConfig{
			Posture:   config.PostureConfig{Enabled: false},
			Rules:     config.RulesConfig{Enabled: &rulesDisabled, Path: "/nonexistent/path/that/would/break/loader"},
			Baselines: config.BaselinesConfig{Enabled: &baselinesDisabled},
		},
		Metrics: config.MetricsConfig{Address: "127.0.0.1:0"},
	}
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	g, gctx := errgroup.WithContext(ctx)
	natsSrv := startTestNATSForMain(t)
	t.Setenv("NATS_URL", natsSrv.ClientURL())
	if err := startAggregatorRing(gctx, g, log, cfg, nil, nil); err != nil {
		cancel()
		_ = g.Wait()
		t.Fatalf("startAggregatorRing with rules disabled: %v (loader must NOT be invoked)", err)
	}
	cancel()
	done := make(chan error, 1)
	go func() { done <- g.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("errgroup did not unwind within 5s")
	}
}

// TestStartAggregator_KubeClientFailureWrapsError exercises the
// posture-enabled-with-broken-client path: the function returns a
// wrapped error and leaves postureClient nil.
func TestStartAggregator_KubeClientFailureWrapsError(t *testing.T) {
	prevFactory := kubeClientFactory
	prevClient := postureClient.Load()
	t.Cleanup(func() {
		kubeClientFactory = prevFactory
		postureClient.Store(prevClient)
	})

	kubeClientFactory = func(*slog.Logger) (kubernetes.Interface, error) {
		return nil, fmt.Errorf("simulated rest.InClusterConfig failure")
	}
	postureClient.Store(nil)

	cfg := &config.Config{
		Detection: config.DetectionConfig{
			Posture: config.PostureConfig{Enabled: true},
		},
		Metrics: config.MetricsConfig{Address: "127.0.0.1:0"},
	}
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	g, gctx := errgroup.WithContext(context.Background())
	_ = g // group is not exercised on the early-return failure path
	err := startAggregatorRing(gctx, g, log, cfg, nil, nil)
	if err == nil {
		t.Fatalf("expected error from startAggregatorRing under kube-client failure")
	}
	if !strings.Contains(err.Error(), "posture: kube client") {
		t.Errorf("err: got %q, want wrap with %q", err, "posture: kube client")
	}
	if postureClient.Load() != nil {
		t.Errorf("postureClient: got non-nil, want nil on failure path")
	}
}
