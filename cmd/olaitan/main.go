// Command olaitan is the entrypoint for both the collector (DaemonSet)
// and the aggregator (Deployment). One binary, two subcommands --
// selected at container start via the Helm chart's pod spec (see
// deploy/helm/olaitan/templates/daemonset.yaml + deployment.yaml).
//
// Ring wiring is stubbed here: Story 1.7 delivers the shared startup
// skeleton (flag parsing, config load + watch, health server, SIGTERM
// graceful shutdown). The actual ring goroutines -- signal collectors,
// correlator, analyst, decision, response -- land in Epic 2+.
//
// Exit codes:
//
//	0  graceful shutdown (SIGINT/SIGTERM)
//	1  startup error (bad flags, config load failure, health server bind)
//	2  unknown subcommand
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/olokotoh/olaitan/internal/collector/audit"
	"github.com/olokotoh/olaitan/internal/collector/cni"
	"github.com/olokotoh/olaitan/internal/collector/cri"
	"github.com/olokotoh/olaitan/internal/collector/falco"
	"github.com/olokotoh/olaitan/internal/collector/posture"
	"github.com/olokotoh/olaitan/internal/config"
	"github.com/olokotoh/olaitan/internal/health"
	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/retry"
)

var version = "dev"

// healthAddr is a package-level override hook for tests. Production
// always serves on :8080 (matches the Helm chart's containerPort.health
// and the liveness/readiness probe target).
var healthAddr = ":8080"

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

// run is the testable body of main. Splitting out lets main_test.go
// exercise flag parsing and subcommand dispatch without exec'ing a
// fresh binary. stderr is an io.Writer so tests can capture output
// via a bytes.Buffer.
func run(args []string, stderr io.Writer) int {
	if len(args) < 1 {
		printUsage(stderr)
		return 1
	}

	switch args[0] {
	case "collector", "aggregator":
		return runRing(args[0], args[1:], stderr)
	case "applog-sidecar":
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		return runApplogSidecar(ctx, args[1:], stderr)
	case "applog-webhook":
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		return runApplogWebhook(ctx, args[1:], stderr)
	case "version":
		fmt.Printf("olaitan %s\n", version)
		return 0
	case "help", "-h", "--help":
		printUsage(stderr)
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command: %s\n\n", args[0])
		printUsage(stderr)
		return 2
	}
}

// runRing is the shared lifecycle for both the collector and the
// aggregator subcommands. The two rings diverge only in the log-line
// identity and (in later stories) the goroutines they spawn after the
// health server is up.
//
// runRing wires SIGINT/SIGTERM into the lifecycle context. The
// signal-free body lives in runRingCtx, which tests drive with an
// in-process cancellation rather than racing real signals against the
// `go test` runner.
func runRing(ring string, args []string, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return runRingCtx(ctx, ring, args, stderr)
}

// runRingCtx is runRing with the lifecycle context injected. Tests
// pass a context they can cancel directly, so we never have to send
// real signals to the test process.
func runRingCtx(ctx context.Context, ring string, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("olaitan "+ring, flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "/etc/olaitan/olaitan.yaml", "path to olaitan.yaml (mounted from ConfigMap olaitan-config)")
	if err := fs.Parse(args); err != nil {
		// flag already printed usage for -h and the parse error; just
		// map the "help requested" case to 0 and everything else to 1.
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}

	log := slog.New(slog.NewJSONHandler(stderr, nil))
	log = log.With("ring", ring, "version", version)

	mgr, err := config.NewManager(*cfgPath, log)
	if err != nil {
		log.Error("startup: load config", "path", *cfgPath, "err", err)
		return 1
	}

	// Wrap ctx with an explicit cancel so the error path can tear down
	// the errgroup's gctx (errgroup itself only cancels gctx on a
	// goroutine error or parent-ctx cancel; the ring-wiring failure
	// path needs to force the cancel from outside the group).
	ringCtx, ringCancel := context.WithCancel(ctx)
	defer ringCancel()

	// Hot-reload goroutine. Watch returns nil when ringCtx is cancelled;
	// when it returns an error before cancel (fsnotify exhaustion,
	// inode rotation), trip the watcherFailed flag so the readiness
	// probe goes 503 and kubelet restarts the pod -- preferable to the
	// log-and-pretend-config-reload-still-works failure mode.
	//
	// Tied to ringCtx (not the outer ctx) so ringCancel on the error
	// path also tears the watcher down; otherwise <-watcherDone below
	// would block until the operator sent SIGTERM.
	var watcherFailed atomic.Bool
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		if err := mgr.Watch(ringCtx); err != nil && ringCtx.Err() == nil {
			watcherFailed.Store(true)
			log.Error("config: watch exited unexpectedly -- readiness probe will fail",
				"err", err)
		}
	}()

	// /healthz check: 503 when the watcher has failed. Story 8.1 will
	// extend this with NATS/Redis liveness once those clients land.
	check := func() error {
		if watcherFailed.Load() {
			return errors.New("config watcher exited unexpectedly")
		}
		return nil
	}

	// Ring goroutines run alongside the health server under a shared
	// errgroup so a fatal source failure trips ctx-cancel for everyone
	// (kubelet then restarts the pod).
	g, gctx := errgroup.WithContext(ringCtx)

	// Health server on :8080. Start returns when gctx is cancelled.
	srv := health.New(healthAddr, log, check)
	g.Go(func() error {
		if err := srv.Start(gctx); err != nil {
			return fmt.Errorf("startup: health server %q: %w", healthAddr, err)
		}
		return nil
	})

	// Ring-specific wiring. The collector subcommand spawns Ring 1
	// adapter goroutines (Story 1.6 lands the Falco adapter as the
	// first; Stories 1.7-1.10 add the four others, with the
	// SourceAdapter interface extraction landing in Story 1.7 once a
	// second concrete instance reveals what is variant vs invariant).
	// The aggregator subcommand's wiring lands in Epic 2.
	switch ring {
	case "collector":
		if err := startCollectorRing(gctx, g, log, mgr.Get()); err != nil {
			log.Error("startup: collector ring wiring", "err", err)
			// Cancel ringCtx (the parent of gctx) so the health server
			// and any goroutines already registered on g unblock; then
			// drain the group and the watcher.
			ringCancel()
			_ = g.Wait()
			<-watcherDone
			return 1
		}
	case "aggregator":
		if err := startAggregatorRing(ringCtx, log, mgr.Get()); err != nil {
			log.Error("startup: aggregator ring wiring", "err", err)
			ringCancel()
			_ = g.Wait()
			<-watcherDone
			return 1
		}
	default:
		log.Info(ring+": not yet implemented, awaiting Epic 2 wiring",
			"config", *cfgPath,
		)
	}

	if err := g.Wait(); err != nil {
		// errgroup.Wait propagates the first non-nil error; ctx-cancel
		// itself is not an error, so anything here is a real failure.
		if !errors.Is(err, context.Canceled) {
			log.Error("ring exited with error", "err", err)
			ringCancel()
			<-watcherDone
			return 1
		}
	}

	log.Info(ring + ": shutting down")
	<-watcherDone
	return 0
}

// kubeClientFactory is the test-seam for constructing a typed K8s
// clientset. Production calls rest.InClusterConfig (with the
// out-of-cluster KUBECONFIG fallback below); tests override this
// variable to inject a fake clientset.
var kubeClientFactory = defaultKubeClientFactory

func defaultKubeClientFactory(log *slog.Logger) (kubernetes.Interface, error) {
	if cfg, err := rest.InClusterConfig(); err == nil {
		return kubernetes.NewForConfig(cfg)
	}
	// Out-of-cluster fallback: KUBECONFIG env var or the default
	// loading rules. This path supports `make deploy-kind` smoke
	// tests run from an operator workstation; production Pods always
	// have InClusterConfig.
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	overrides := &clientcmd.ConfigOverrides{}
	clientCfg := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)
	cfg, err := clientCfg.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("k8s rest config: %w", err)
	}
	return kubernetes.NewForConfig(cfg)
}

// postureClient is the package-level reference to the constructed
// posture client. Story 1.14 (correlator) reads this when assembling
// EvidencePackages; Story 1.12 binds the cache-hit counter to the
// Prometheus surface via the client's getters. The reference is set
// only when posture.enabled=true in the loaded config and the K8s
// client construction succeeds; otherwise it stays nil and downstream
// callers fall through to a degraded posture (Unavailable=true).
//
// atomic.Pointer guards the read/write seam against the inevitable
// future case where startAggregatorRing is invoked more than once
// (hot-reload, test re-entry) while a correlator goroutine concurrently
// reads the client. Without the atomic, `go test -race` flags the
// concurrent access; with it, the read-side load is a single 8-byte
// MOV on every modern architecture, so the cost is zero compared to
// a guarded read of a plain pointer.
var postureClient atomic.Pointer[posture.Client]

// getPostureClient returns the currently registered posture.Client, or
// nil if posture is disabled / not yet wired. Callers (Story 1.14
// correlator) should treat nil as "posture unavailable, emit a
// degraded EvidencePackage". The getter is the discipline pattern for
// reading the atomic.Pointer; Story 1.14's correlator goroutine should
// call this rather than touching the package variable directly.
//
// atomic-pointer read-side discipline is part of the Story 1.11
// substrate even though no caller exists yet.
//
//nolint:unused // wired by Story 1.14 (correlator); kept here so the
func getPostureClient() *posture.Client { return postureClient.Load() }

// startAggregatorRing performs the Story 1.11 wiring: construct a
// posture.Client backed by an in-cluster (or KUBECONFIG-backed) K8s
// clientset, store it in the package-level postureClient pointer so
// Story 1.14's correlator can pick it up. The Story 1.14 correlator
// wiring lands here later. For now this function only constructs the
// client and verifies the K8s API is reachable when posture is
// enabled.
//
// Behaviour matrix:
//
//   - posture.enabled=true AND K8s client construction succeeds -> set
//     postureClient and return nil.
//   - posture.enabled=true AND K8s client construction fails -> log
//     error and return the error so the pod CrashLoops; an
//     intentionally-enabled posture must not silently degrade.
//   - posture.enabled=false -> log "posture disabled", leave
//     postureClient nil, return nil.
func startAggregatorRing(ctx context.Context, log *slog.Logger, cfg *config.Config) error {
	if !cfg.Detection.Posture.Enabled {
		log.Info("aggregator: posture client disabled in config; skipping")
		return nil
	}

	cs, err := kubeClientFactory(log)
	if err != nil {
		return fmt.Errorf("posture: kube client: %w", err)
	}

	pCfg := posture.DefaultConfig()
	if d := cfg.Detection.Posture.CacheTTL.Duration(); d > 0 {
		pCfg.CacheTTL = d
	}
	if d := cfg.Detection.Posture.FetchTimeout.Duration(); d > 0 {
		pCfg.FetchTimeout = d
	}

	client, err := posture.New(pCfg, cs, log)
	if err != nil {
		return fmt.Errorf("posture: client init: %w", err)
	}
	postureClient.Store(client)
	log.Info("aggregator: posture client constructed",
		"cache_ttl", pCfg.CacheTTL,
		"fetch_timeout", pCfg.FetchTimeout,
	)
	// Future Story 1.14: wire postureClient into the correlator
	// goroutine here. The ctx is plumbed through for the lifecycle
	// hand-off so the correlator can scope per-Get contexts under
	// ringCtx.
	_ = ctx
	return nil
}

// startCollectorRing wires the Ring 1 sensor adapters into the supplied
// errgroup. As of Story 1.7 the Falco gRPC adapter (Story 1.6) and the
// Kubernetes audit-webhook receiver (Story 1.7) both land here;
// Stories 1.8-1.10 will add cri, applog, and cni adapters by
// following the same spawn pattern.
//
// Connection coordinates come from environment variables injected by
// the Helm chart's downward API (see deploy/helm/olaitan/templates/
// daemonset.yaml): NATS_URL for the bus, FALCO_SOCKET for the Falco
// gRPC endpoint, K8S_NODE_NAME for the per-event Pod.Node identifier.
// The audit-webhook adapter is gated on cfg.Detection.Sources.Audit.
// Enabled, so a chart deploy with the default
// auditWebhook.enabled=false leaves the receiver dormant.
func startCollectorRing(ctx context.Context, g *errgroup.Group, log *slog.Logger, cfg *config.Config) error {
	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		return errors.New("collector: NATS_URL env var is empty (set by Helm chart)")
	}
	falcoSocket := os.Getenv("FALCO_SOCKET")
	if falcoSocket == "" {
		return errors.New("collector: FALCO_SOCKET env var is empty (set by Helm chart)")
	}
	nodeName := os.Getenv("K8S_NODE_NAME")
	if nodeName == "" {
		return errors.New("collector: K8S_NODE_NAME env var is empty (set by Helm chart's downward API)")
	}

	natsCfg := natsclient.DefaultConfig()
	natsCfg.URL = natsURL
	natsCfg.Name = "olaitan-collector"

	nc, err := natsclient.NewClient(natsCfg)
	if err != nil {
		return fmt.Errorf("collector: nats: %w", err)
	}

	// closeNATS is the shared error-path teardown: bound at 2s so a
	// half-connected client cannot hang startup, and the failure case
	// (nc.Close error) is logged rather than swallowed silently.
	closeNATS := func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := nc.Close(closeCtx); err != nil {
			log.Warn("collector: nats close on error path", "err", err)
		}
	}

	// Provision JetStream streams once at startup. EnsureStreams is
	// idempotent so a re-run on a pre-existing stream is a no-op.
	streamsCtx, streamsCancel := context.WithTimeout(ctx, 10*time.Second)
	defer streamsCancel()
	if err := natsclient.EnsureStreams(streamsCtx, nc.JetStream(), natsclient.StreamConfigs()); err != nil {
		closeNATS()
		return fmt.Errorf("collector: ensure streams: %w", err)
	}

	adapter, err := falco.New(falco.Config{
		Endpoint: falcoSocket,
		Hostname: nodeName,
	}, nc, log)
	if err != nil {
		closeNATS()
		return fmt.Errorf("collector: falco adapter: %w", err)
	}

	// Falco adapter goroutine. NATS drain happens after g.Wait()
	// returns (see runRingCtx) so the adapter has fully exited before
	// nc.Close races against any in-flight PublishJS.
	adapterDone := make(chan struct{})
	g.Go(func() error {
		defer close(adapterDone)
		if err := adapter.Run(ctx); err != nil {
			return fmt.Errorf("collector: falco run: %w", err)
		}
		return nil
	})

	// Drain NATS only after the adapter has signalled exit. Avoids the
	// shutdown race where parallel-goroutine drain raced PublishJS and
	// surfaced ErrClientClosed as an errgroup error.
	g.Go(func() error {
		select {
		case <-adapterDone:
		case <-ctx.Done():
			<-adapterDone
		}
		// Allow up to 10s for the drain; matches the Helm chart's
		// terminationGracePeriodSeconds budget.
		drainCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := nc.Close(drainCtx); err != nil {
			log.Warn("collector: nats drain", "err", err)
		}
		return nil
	})

	// Story 1.7: Kubernetes audit-webhook receiver. Gated on the
	// config block so a chart deploy with auditWebhook.enabled=false
	// leaves the receiver dormant.
	if cfg != nil && cfg.Detection.Sources.Audit.Enabled {
		auditCfg := audit.Config{
			ListenAddr:       cfg.Detection.Sources.Audit.ListenAddr,
			TLSCertFile:      cfg.Detection.Sources.Audit.TLSCertFile,
			TLSKeyFile:       cfg.Detection.Sources.Audit.TLSKeyFile,
			ClientCAFile:     cfg.Detection.Sources.Audit.ClientCAFile,
			Hostname:         nodeName,
			MaxPayloadBytes:  cfg.Detection.Sources.Audit.MaxPayloadBytes,
			StalenessTimeout: cfg.Detection.Sources.Audit.StalenessTimeout.Duration(),
			PublishRetry:     toRetryStrategy(cfg.Detection.Sources.Audit.PublishRetry),
		}
		auditAdapter, aerr := audit.New(auditCfg, nc, log)
		if aerr != nil {
			closeNATS()
			return fmt.Errorf("collector: audit adapter: %w", aerr)
		}
		g.Go(func() error {
			if err := auditAdapter.Run(ctx); err != nil {
				return fmt.Errorf("collector: audit run: %w", err)
			}
			return nil
		})
		log.Info("collector: ring 1 wired (audit)",
			"listen_addr", auditCfg.ListenAddr,
			"max_payload_bytes", auditCfg.MaxPayloadBytes)
	}

	// Story 1.8: containerd CRI lifecycle adapter. Gated on the
	// config block so a chart deploy with containerdSensor.enabled=false
	// (default) leaves the adapter dormant. The adapter mounts the
	// host's CRI socket directory via a Helm hostPath volume; the
	// security boundary is documented in deploy/helm/olaitan/CRI.md.
	if cfg != nil && cfg.Detection.Sources.Containerd.Enabled {
		criCfg := cri.Config{
			SocketPath:       cfg.Detection.Sources.Containerd.SocketPath,
			Hostname:         nodeName,
			DialTimeout:      cfg.Detection.Sources.Containerd.DialTimeout.Duration(),
			StalenessTimeout: cfg.Detection.Sources.Containerd.StalenessTimeout.Duration(),
			ConnectRetry:     toRetryStrategy(cfg.Detection.Sources.Containerd.ConnectRetry),
			PublishRetry:     toRetryStrategy(cfg.Detection.Sources.Containerd.PublishRetry),
		}
		criAdapter, cerr := cri.New(criCfg, nc, log)
		if cerr != nil {
			closeNATS()
			return fmt.Errorf("collector: cri adapter: %w", cerr)
		}
		g.Go(func() error {
			if err := criAdapter.Run(ctx); err != nil {
				// P22: clean shutdown surfaces context.Canceled
				// (sometimes wrapped by retry.Do); treat as nil to
				// keep errgroup.Wait quiet, matching the Story 1.6
				// Falco / Story 1.7 audit pattern.
				if errors.Is(err, context.Canceled) {
					return nil
				}
				return fmt.Errorf("collector: cri run: %w", err)
			}
			return nil
		})
		log.Info("collector: ring 1 wired (containerd cri)",
			"socket_path", criCfg.SocketPath)
	}

	// Story 1.10: Calico CNI flow adapter. Gated on the config block
	// so a chart deploy with calicoSensor.enabled=false (default)
	// leaves the adapter dormant. Goldmane requires the operator to
	// have installed Calico v3.31.5+ via the Tigera operator path
	// (ADR-2026-05-12-01); the agent presents a client cert signed
	// by the Tigera CA on every connect.
	if cfg != nil && cfg.Detection.Sources.Calico.Enabled {
		cniCfg := cni.Config{
			GoldmaneAddr:        cfg.Detection.Sources.Calico.GoldmaneAddr,
			ServerName:          cfg.Detection.Sources.Calico.ServerName,
			CABundlePath:        cfg.Detection.Sources.Calico.CABundlePath,
			ClientCertPath:      cfg.Detection.Sources.Calico.ClientCertPath,
			ClientKeyPath:       cfg.Detection.Sources.Calico.ClientKeyPath,
			DialTimeout:         cfg.Detection.Sources.Calico.DialTimeout.Duration(),
			StalenessTimeout:    cfg.Detection.Sources.Calico.StalenessTimeout.Duration(),
			ConnectRetry:        toRetryStrategy(cfg.Detection.Sources.Calico.ConnectRetry),
			PublishRetry:        toRetryStrategy(cfg.Detection.Sources.Calico.PublishRetry),
			MaxEventBytes:       cfg.Detection.Sources.Calico.MaxEventBytes,
			StartTimeGte:        cfg.Detection.Sources.Calico.StartTimeGte,
			AggregationInterval: cfg.Detection.Sources.Calico.AggregationInterval,
			Hostname:            nodeName,
		}
		cniAdapter, nerr := cni.New(cniCfg, nc, log)
		if nerr != nil {
			closeNATS()
			return fmt.Errorf("collector: cni adapter: %w", nerr)
		}
		g.Go(func() error {
			if err := cniAdapter.Run(ctx); err != nil {
				if errors.Is(err, context.Canceled) {
					return nil
				}
				return fmt.Errorf("collector: cni run: %w", err)
			}
			return nil
		})
		log.Info("collector: ring 1 wired (calico cni)",
			"goldmane_addr", cniCfg.GoldmaneAddr)
	}

	log.Info("collector: ring 1 wired", "falco_socket", falcoSocket, "node", nodeName)
	return nil
}

// toRetryStrategy materialises the YAML-shaped RetryStrategyConfig as
// an internal/retry.Strategy. Empty / zero fields are passed through
// to retry.Strategy where they are interpreted as "use the adapter's
// default" by retry.Strategy.IsZero().
func toRetryStrategy(r config.RetryStrategyConfig) retry.Strategy {
	return retry.Strategy{
		Min:         r.Min.Duration(),
		Max:         r.Max.Duration(),
		Multiplier:  r.Multiplier,
		Jitter:      r.Jitter,
		MaxAttempts: r.MaxAttempts,
	}
}

func printUsage(w io.Writer) {
	_, _ = fmt.Fprintf(w, `Usage: olaitan <command> [flags]

Commands:
  collector        Run the signal collector (DaemonSet mode)
  aggregator       Run the aggregator (correlator + decision + response)
  applog-sidecar   Run the application log sidecar (in-pod, opt-in)
  applog-webhook   Run the application log MutatingAdmissionWebhook server
  version          Print version
  help             Show this help

Flags (collector, aggregator):
  --config <path>   Path to olaitan.yaml (default: /etc/olaitan/olaitan.yaml)

Olaitan -- LLM-powered autonomous runtime security agent for Kubernetes.
`)
}
