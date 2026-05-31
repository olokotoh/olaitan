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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/nats-io/nats.go/jetstream"
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
	"github.com/olokotoh/olaitan/internal/correlator"
	correlatorasm "github.com/olokotoh/olaitan/internal/correlator/assembler"
	"github.com/olokotoh/olaitan/internal/decision/baseline"
	"github.com/olokotoh/olaitan/internal/decision/rules"
	rulesloader "github.com/olokotoh/olaitan/internal/decision/rules/loader"
	"github.com/olokotoh/olaitan/internal/decision/score"
	"github.com/olokotoh/olaitan/internal/health"
	"github.com/olokotoh/olaitan/internal/metrics"
	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/ratelimit"
	redisclient "github.com/olokotoh/olaitan/internal/redis"
	"github.com/olokotoh/olaitan/internal/response/fsm"
	"github.com/olokotoh/olaitan/internal/retry"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/subjects"
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
		if err := startCollectorRing(gctx, g, log, mgr.Get(), mgr.Subscribe); err != nil {
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
		if err := startAggregatorRing(gctx, g, log, mgr.Get(), mgr.Subscribe, mgr); err != nil {
			// A cancelled context during startup is a clean shutdown, not
			// a crash; mirror the g.Wait() path below and exit 0. The
			// aggregator wiring makes context-dependent JetStream calls
			// (wireFSMConsumer), so cancellation in the startup window can
			// surface here as a wrapped context.Canceled.
			if errors.Is(err, context.Canceled) {
				log.Info(ring + ": shutting down")
				ringCancel()
				_ = g.Wait()
				<-watcherDone
				return 0
			}
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
	cfg, inClusterErr := rest.InClusterConfig()
	if inClusterErr == nil {
		return kubernetes.NewForConfig(cfg)
	}
	// Out-of-cluster fallback: KUBECONFIG env var or the default
	// loading rules. This path supports `make deploy-kind` smoke
	// tests run from an operator workstation; production Pods always
	// have InClusterConfig.
	//
	// If we are running in-cluster and InClusterConfig nevertheless
	// failed (RBAC mis-mount, projected-token absent, malformed
	// CA), the fallback's failure would mask the real cause. Wrap
	// both errors so operators see why InClusterConfig was
	// rejected before learning that KUBECONFIG could not be
	// loaded either.
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	overrides := &clientcmd.ConfigOverrides{}
	clientCfg := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)
	cfg, err := clientCfg.ClientConfig()
	if err != nil {
		// errors.Join (Go 1.20+) carries both causes through %w
		// chains so operators inspecting the wrapped error see
		// the in-cluster reason alongside the KUBECONFIG reason.
		log.Warn("kube client: in-cluster config rejected; KUBECONFIG fallback also failed",
			"in_cluster_err", inClusterErr.Error(),
			"kubeconfig_err", err.Error(),
		)
		return nil, fmt.Errorf("k8s rest config: in-cluster: %w; kubeconfig fallback: %w", inClusterErr, err)
	}
	if os.Getenv("KUBECONFIG") == "" {
		// We are most likely running in-cluster but InClusterConfig
		// failed and we resolved a kubeconfig from the default
		// loading rules anyway. Log the in-cluster failure so the
		// operator can spot a mis-mounted projected-token before it
		// becomes a "why is my pod talking to the wrong apiserver"
		// puzzle later.
		log.Warn("kube client: in-cluster config rejected, using kubeconfig fallback",
			"in_cluster_err", inClusterErr.Error(),
		)
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
// call this rather than touching the package variable directly. The
// function is unused as of Story 1.11 -- it is shipped now so the
// atomic-pointer read-side pattern is established before the first
// reader lands.
//
//nolint:unused // Story 1.14 (correlator) is the first caller.
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
func startAggregatorRing(ctx context.Context, g *errgroup.Group, log *slog.Logger, cfg *config.Config, subscribe func(func(*config.Config)), mgr *config.Manager) error {
	var client *posture.Client
	var cs kubernetes.Interface
	if cfg.Detection.Posture.Enabled {
		var err error
		cs, err = kubeClientFactory(log)
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

		client, err = posture.New(pCfg, cs, log)
		if err != nil {
			return fmt.Errorf("posture: client init: %w", err)
		}
		postureClient.Store(client)
		log.Info("aggregator: posture client constructed",
			"cache_ttl", pCfg.CacheTTL,
			"fetch_timeout", pCfg.FetchTimeout,
		)
	} else {
		log.Info("aggregator: posture client disabled in config; skipping")
	}

	// Story 1.12: Prometheus metrics surface for the aggregator ring.
	// No streaming adapters yet (Story 1.14 lands the correlator); the
	// surface exists so the posture counters (or the posture_disabled
	// gauge) can be scraped, and so future aggregator-side adapters
	// inherit the wiring. Story 1.15 reuses the returned registry to
	// register the rule-engine counters and the
	// evaluation_seconds histogram.
	metricsReg, merr := startMetricsServer(ctx, g, log, cfg, "", nil, client)
	if merr != nil {
		return fmt.Errorf("aggregator: metrics: %w", merr)
	}

	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		return errors.New("aggregator: NATS_URL env var is empty (set by Helm chart)")
	}
	natsCfg := natsclient.DefaultConfig()
	natsCfg.URL = natsURL
	natsCfg.Name = "olaitan-aggregator"
	nc, err := natsclient.NewClient(natsCfg)
	if err != nil {
		return fmt.Errorf("aggregator: nats: %w", err)
	}
	closeNATS := func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := nc.Close(closeCtx); err != nil {
			log.Warn("aggregator: nats close", "err", err)
		}
	}

	streamsCtx, streamsCancel := context.WithTimeout(ctx, 10*time.Second)
	defer streamsCancel()
	if err := natsclient.EnsureStreams(streamsCtx, nc.JetStream(), natsclient.StreamConfigs()); err != nil {
		closeNATS()
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("aggregator: ensure streams: %w", err)
	}

	corrAssembler := correlatorasm.New(correlatorasm.Config{
		Kube:                  cs,
		Posture:               client,
		MaxPackageBytes:       cfg.Detection.Correlator.MaxPackageBytesOrDefault(),
		HighSeverityThreshold: cfg.Detection.Correlator.HighSeverityThresholdOrDefault(),
		Log:                   log,
	})
	corr, err := correlator.New(correlator.Config{
		NATS:                  nc,
		Kube:                  cs,
		Assembler:             corrAssembler,
		WindowDuration:        cfg.Detection.Correlator.WindowDuration.Duration(),
		MultiSignalMinSources: cfg.Detection.Correlator.MultiSignalMinSourcesOrDefault(),
		Log:                   log,
		MetricsRegistry:       metricsReg,
	})
	if err != nil {
		closeNATS()
		return fmt.Errorf("aggregator: correlator: %w", err)
	}
	if subscribe != nil {
		subscribe(func(newCfg *config.Config) {
			if newCfg == nil {
				return
			}
			corr.UpdateConfig(
				newCfg.Detection.Correlator.WindowDuration.Duration(),
				newCfg.Detection.Correlator.MultiSignalMinSourcesOrDefault(),
			)
		})
	}
	g.Go(func() error {
		if err := corr.Run(ctx); err != nil {
			return fmt.Errorf("aggregator: correlator run: %w", err)
		}
		return nil
	})

	// Story 1.15: OLT Sigma rule engine wiring. The engine consumes
	// EvidencePackages from EVIDENCE.packages, evaluates them against
	// the loaded rule corpus, and re-emits matches through the
	// correlator's FireRuleMatch entry point (the correlator
	// satisfies the rules.RuleMatchEmitter interface by signature).
	// When rules.enabled=false the engine is skipped entirely; the
	// JetStream consumer olaitan-rules-engine is not created.
	if cfg.Detection.Rules.EnabledOrDefault() {
		// Defensive: validate() skips the Path check when Enabled is
		// nil (so test-bypass Configs can omit the block). If a
		// caller reaches here with a nil Enabled (treated as the
		// default true) and an empty Path, fail loud rather than
		// crashing inside the loader's WalkDir("") later
		// (code-review P22).
		if cfg.Detection.Rules.Path == "" {
			closeNATS()
			return errors.New("aggregator: detection.rules.path is empty but rules engine is enabled")
		}
		rl := rulesloader.New(cfg.Detection.Rules.Path, log)
		if err := rl.Load(); err != nil {
			closeNATS()
			return fmt.Errorf("aggregator: rules loader: %w", err)
		}
		engine, err := rules.New(rules.Config{
			NATS:    nc,
			Loader:  rl,
			Emitter: corr,
			Metrics: metricsReg,
			Log:     log,
		})
		if err != nil {
			closeNATS()
			return fmt.Errorf("aggregator: rules engine: %w", err)
		}
		// Wire the loader's reject path to the engine's
		// rejected-counter hook so olaitan_decision_rules_reloads_total
		// {outcome="rejected"} stays in sync with reload-rejected log
		// lines (code-review P1).
		rl.SubscribeRejected(func(error) { engine.NoteReloadRejected() })
		// Note: rules.path and rules.enabled changes are intentionally
		// not wired through config.Manager.Subscribe (code-review D3).
		// The loader path is a K8s volume mountPath; changing it via
		// helm upgrade rewrites the Deployment spec which K8s rolls
		// anyway, so "hot-reload" of path is architecturally
		// meaningless. The enabled toggle is restart-required by design.
		g.Go(func() error {
			if err := rl.Watch(ctx); err != nil {
				return fmt.Errorf("aggregator: rules watcher: %w", err)
			}
			return nil
		})
		g.Go(func() error {
			if err := engine.Run(ctx); err != nil {
				return fmt.Errorf("aggregator: rules engine run: %w", err)
			}
			return nil
		})
		log.Info("aggregator: rules engine wired",
			"path", cfg.Detection.Rules.Path,
			"count", rl.Get().Len())
	} else {
		log.Info("aggregator: rules engine disabled in config; skipping")
	}

	// Story 1.17: Welford baseline engine wiring. The engine consumes
	// EvidencePackages from EVIDENCE.packages, maintains per-workload
	// Welford state for the five default metrics, and re-emits
	// deviations through the correlator's FireBaselineDeviation entry
	// point (the correlator satisfies the BaselineDeviationEmitter
	// interface by signature). When baselines.enabled=false the engine
	// is skipped entirely; the JetStream consumer
	// olaitan-baseline-engine is not created and Redis is not dialled.
	if cfg.Detection.Baselines.EnabledOrDefault() {
		// Defensive Path-non-empty equivalent (Story 1.15 P22 pattern):
		// validate() skips the RedisAddr check when Enabled is nil.
		// Fail loud if we reach this branch with an empty addr rather
		// than crashing inside the redis client constructor.
		if cfg.Detection.Baselines.RedisAddr == "" {
			closeNATS()
			return errors.New("aggregator: detection.baselines.redis_addr is empty but baseline engine is enabled")
		}
		baselineEngine, baselineCloser, berr := wireBaselineEngine(ctx, cfg, nc, corr, metricsReg, log)
		if berr != nil {
			closeNATS()
			return berr
		}
		if subscribe != nil {
			subscribe(func(newCfg *config.Config) {
				if newCfg == nil {
					return
				}
				baselineEngine.SetSigmaMultiplier(newCfg.Detection.Baselines.SigmaMultiplierOrDefault())
				baselineEngine.SetWarmupDuration(newCfg.Detection.Baselines.WarmupDurationOrDefault())
				// Copilot C5 + Edge Case Hunter E1 + Acceptance
				// Auditor A1: both knobs are hot-reloadable per BI-3.
				// Without the SetWarmupDuration call, warmupDuration
				// was silently restart-required despite the helm
				// values comment + BI-3 docstring claiming hot-reload.
			})
		}
		g.Go(func() error {
			if err := baselineEngine.Run(ctx); err != nil {
				return fmt.Errorf("aggregator: baseline engine run: %w", err)
			}
			return nil
		})
		g.Go(func() error {
			<-ctx.Done()
			baselineCloser()
			return nil
		})
		log.Info("aggregator: baseline engine wired",
			"path", "baseline:",
			"warmup_duration", cfg.Detection.Baselines.WarmupDurationOrDefault(),
			"sigma_multiplier", cfg.Detection.Baselines.SigmaMultiplierOrDefault())
	} else {
		log.Info("aggregator: baseline engine disabled in config; skipping")
	}

	// Story 2.1: deterministic ThreatScore calculator (FR30). The
	// calculator is stateless and reads cfg via mgr.Get() on every
	// Score() invocation, so the wiring is purely construction +
	// metric registration. Story 2.2 lands the FSM consumer that
	// closes the discard below; until then the `_ =` keeps the
	// construction live so an explicit consumer plug-in for Story
	// 2.2 is a one-line patch rather than a re-discovery exercise.
	scoreCalc, scoreErr := score.New(mgr, metricsReg)
	if scoreErr != nil {
		closeNATS()
		return fmt.Errorf("aggregator: score: %w", scoreErr)
	}
	snap := scoreCalc.Snapshot()
	log.Info("aggregator: score calculator wired",
		"rule_weight", snap.RuleWeight,
		"baseline_weight", snap.BaselineWeight,
		"llm_weight", snap.LLMWeight,
		"llm_cap", snap.LLMCap,
		"sigma_normaliser", snap.SigmaNormaliser)

	// Story 2.2: response-ring FSM (FR31/FR32). The FSM is the Story
	// 2.2 consumer that closes the previous `_ = scoreCalc` discard: it
	// scores every inbound EvidencePackage and folds ConfidenceScore.Total
	// into fsm.Evaluate, one state step at a time. A no-op TransitionSink
	// is wired for now; Story 2.3 (Redis persistence) and Story 2.8 (NATS
	// audit) replace it with real sinks. Dwell guards and the de-escalation
	// cooldown read config.Manager.Get() once per Evaluate call, following
	// the Story 2.1 score precedent, so a hot config reload (FR49) flows
	// into the live machine without a Subscribe callback.
	// Story 2.3: durable FSM-state persistence (FR37/NFR24). When enabled,
	// the FSM emits transitions through a Redis-backed sink and rehydrates
	// its in-memory map from Redis BEFORE the consumer starts, so a restart
	// never silently de-escalates a workload to CLEAN. When disabled, it
	// keeps the Story 2.2 NopSink and skips restore.
	var fsmSink fsm.TransitionSink = fsm.NopSink{}
	var fsmStore *fsm.Store
	if cfg.Detection.FSM.PersistenceEnabledOrDefault() {
		redisSink, store, fsmCloser, perr := wireFSMPersistence(cfg, log)
		if perr != nil {
			closeNATS()
			return fmt.Errorf("aggregator: fsm persistence: %w", perr)
		}
		fsmSink = redisSink
		fsmStore = store
		g.Go(func() error {
			<-ctx.Done()
			fsmCloser()
			return nil
		})
		g.Go(func() error {
			return redisSink.Run(ctx)
		})
	}
	stateMachine, fsmErr := fsm.New(mgr, metricsReg, fsmSink, nil)
	if fsmErr != nil {
		closeNATS()
		return fmt.Errorf("aggregator: fsm: %w", fsmErr)
	}
	if fsmStore != nil {
		recovered, skipped, rerr := stateMachine.Restore(ctx, fsmStore)
		if rerr != nil {
			closeNATS()
			return fmt.Errorf("aggregator: fsm restore: %w", rerr)
		}
		log.Info("aggregator: fsm state recovered from redis", "recovered", recovered, "skipped", skipped)
	}
	if err := wireFSMConsumer(ctx, g, log, nc, scoreCalc, stateMachine); err != nil {
		closeNATS()
		return fmt.Errorf("aggregator: fsm consumer: %w", err)
	}
	log.Info("aggregator: fsm wired",
		"suspicious_threshold", cfg.Detection.ConfidenceBands.Watch,
		"restricted_threshold", cfg.Detection.ConfidenceBands.Alert,
		"quarantined_threshold", cfg.Detection.ConfidenceBands.Act,
		"suspicious_dwell_seconds", cfg.Detection.FSM.SuspiciousDwellSecondsOrDefault(),
		"restricted_dwell_seconds", cfg.Detection.FSM.RestrictedDwellSecondsOrDefault(),
		"quarantined_dwell_seconds", cfg.Detection.FSM.QuarantinedDwellSecondsOrDefault(),
		"deescalation_cooldown_seconds", cfg.Detection.FSM.DeescalationCooldownSecondsOrDefault(),
		"persistence_enabled", cfg.Detection.FSM.PersistenceEnabledOrDefault())

	g.Go(func() error {
		<-ctx.Done()
		closeNATS()
		return nil
	})
	log.Info("aggregator: correlator wired",
		"window_duration", cfg.Detection.Correlator.WindowDuration.Duration(),
		"max_package_bytes", cfg.Detection.Correlator.MaxPackageBytesOrDefault(),
		"multi_signal_min_sources", cfg.Detection.Correlator.MultiSignalMinSourcesOrDefault())
	return nil
}

// wireBaselineEngine constructs the Story 1.17 baseline engine and
// its Redis-backed Store + Warmup controller. Returns the engine, a
// closer that should be deferred for graceful shutdown, and any
// construction error. Centralised here so startAggregatorRing stays
// readable and the engine+store+warmup triple is wired in a single
// place.
func wireBaselineEngine(ctx context.Context, cfg *config.Config, nc *natsclient.Client, emit baseline.BaselineDeviationEmitter, metricsReg *metrics.Registry, log *slog.Logger) (*baseline.Engine, func(), error) {
	rcfg := redisclient.DefaultConfig()
	rcfg.Addr = cfg.Detection.Baselines.RedisAddr
	// NFR8: Redis AUTH is mandatory when the baseline engine is enabled.
	// The Helm chart's olaitan-secrets Secret carries the password under
	// key `redis-password`; the aggregator Deployment surfaces it as the
	// REDIS_PASSWORD env var via valueFrom.secretKeyRef.
	//
	// TrimRight guards against the common secretKeyRef pitfall where the
	// password value carries a trailing newline (kubectl create secret
	// --from-file appends one); the trailing \n breaks AUTH against
	// Redis even though the operator-supplied secret looks correct.
	pwd := strings.TrimRight(os.Getenv("REDIS_PASSWORD"), "\r\n")
	if pwd == "" {
		return nil, func() {}, fmt.Errorf("NFR8: REDIS_PASSWORD env var is required when detection.baselines.enabled=true (set --set secrets.redisPassword or wire a secretKeyRef)")
	}
	rcfg.Password = pwd
	rc, err := redisclient.NewClient(rcfg)
	if err != nil {
		return nil, func() {}, fmt.Errorf("aggregator: baseline redis: %w", err)
	}
	closer := func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := rc.Close(closeCtx); err != nil {
			log.Warn("aggregator: baseline redis close", "err", err)
		}
	}
	store, err := baseline.NewStore(rc)
	if err != nil {
		closer()
		return nil, func() {}, fmt.Errorf("aggregator: baseline store: %w", err)
	}
	warmup, err := baseline.NewWarmup(store, baseline.WarmupConfig{
		Duration: cfg.Detection.Baselines.WarmupDurationOrDefault(),
	})
	if err != nil {
		closer()
		return nil, func() {}, fmt.Errorf("aggregator: baseline warmup: %w", err)
	}
	engine, err := baseline.New(baseline.Config{
		NATS:            nc,
		Store:           store,
		Warmup:          warmup,
		Emitter:         emit,
		Metrics:         metricsReg,
		Log:             log,
		SigmaMultiplier: cfg.Detection.Baselines.SigmaMultiplierOrDefault(),
	})
	if err != nil {
		closer()
		return nil, func() {}, fmt.Errorf("aggregator: baseline engine: %w", err)
	}
	_ = ctx
	return engine, closer, nil
}

// wireFSMPersistence constructs the Story 2.3 Redis-backed FSM store and
// transition sink. Returns the sink (whose Run is the background outage
// replayer), the store (for the restore-on-startup hook), a closer to
// defer for graceful shutdown, and any construction error. Mirrors
// wireBaselineEngine, including the NFR8 mandatory REDIS_PASSWORD AUTH.
func wireFSMPersistence(cfg *config.Config, log *slog.Logger) (*fsm.RedisSink, *fsm.Store, func(), error) {
	rcfg := redisclient.DefaultConfig()
	rcfg.Addr = cfg.Detection.FSM.RedisAddrOrDefault()
	// NFR8: Redis AUTH is mandatory when FSM persistence is enabled. The
	// password is surfaced as REDIS_PASSWORD via secretKeyRef; TrimRight
	// guards the trailing-newline secretKeyRef pitfall (see wireBaselineEngine).
	pwd := strings.TrimRight(os.Getenv("REDIS_PASSWORD"), "\r\n")
	if pwd == "" {
		return nil, nil, func() {}, fmt.Errorf("NFR8: REDIS_PASSWORD env var is required when detection.fsm.persistence_enabled=true (set --set secrets.redisPassword or wire a secretKeyRef)")
	}
	rcfg.Password = pwd
	rc, err := redisclient.NewClient(rcfg)
	if err != nil {
		return nil, nil, func() {}, fmt.Errorf("aggregator: fsm redis: %w", err)
	}
	closer := func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if cerr := rc.Close(closeCtx); cerr != nil {
			log.Warn("aggregator: fsm redis close", "err", cerr)
		}
	}
	store, err := fsm.NewStore(rc)
	if err != nil {
		closer()
		return nil, nil, func() {}, fmt.Errorf("aggregator: fsm store: %w", err)
	}
	sink, err := fsm.NewRedisSink(store, log, fsm.RedisSinkConfig{})
	if err != nil {
		closer()
		return nil, nil, func() {}, fmt.Errorf("aggregator: fsm sink: %w", err)
	}
	return sink, store, closer, nil
}

// fsmConsumerMaxDeliver caps JetStream's per-message redelivery for the
// FSM consumer so a poison package cannot loop forever. Mirrors the
// rules-engine consumerMaxDeliver (Story 1.14 P18 closure).
const fsmConsumerMaxDeliver = 5

// fsmFetchBackoff is the bounded sleep between consumer.Next attempts
// after a non-timeout error; the consumer honours context cancellation
// immediately rather than completing the backoff. Mirrors the rules
// engine.
const fsmFetchBackoff = time.Second

// wireFSMConsumer wires the Story 2.2 scoring + FSM evidence consumer.
// It creates a durable JetStream consumer on subjects.EvidencePackages,
// scores each inbound package via scoreCalc, and folds
// ConfidenceScore.Total into stateMachine.Evaluate keyed by the
// package's WorkloadID (AC1/AC4). It runs on its own errgroup goroutine
// and returns nil on graceful ctx cancellation. The FSM is the documented
// Story 2.2 consumer of the Story 2.1 calculator; see startAggregatorRing.
func wireFSMConsumer(ctx context.Context, g *errgroup.Group, log *slog.Logger, nc *natsclient.Client, scoreCalc *score.Calculator, stateMachine *fsm.Machine) error {
	stream, err := nc.JetStream().Stream(ctx, "EVIDENCE")
	if err != nil {
		return fmt.Errorf("stream EVIDENCE: %w", err)
	}
	consumer, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       "olaitan-response-fsm",
		AckPolicy:     jetstream.AckExplicitPolicy,
		FilterSubject: subjects.EvidencePackages,
		MaxDeliver:    fsmConsumerMaxDeliver,
	})
	if err != nil {
		return fmt.Errorf("consumer: %w", err)
	}

	g.Go(func() error {
		for {
			if err := ctx.Err(); err != nil {
				return nil
			}
			msg, err := consumer.Next(jetstream.FetchMaxWait(250 * time.Millisecond))
			if err != nil {
				if isFSMFetchTimeout(err) {
					continue
				}
				log.Warn("aggregator: fsm consumer fetch failed", "err", err)
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(fsmFetchBackoff):
				}
				continue
			}

			var pkg schema.EvidencePackage
			if jerr := json.Unmarshal(msg.Data(), &pkg); jerr != nil {
				// A malformed package must not crash-loop the ring: drop
				// and ack (mirrors the rules engine's drop-and-ack).
				log.Warn("aggregator: fsm consumer decode failed; dropping", "err", jerr)
				_ = msg.Ack()
				continue
			}

			sc, serr := scoreCalc.Score(&pkg)
			if serr != nil {
				log.Warn("aggregator: fsm score failed; dropping", "err", serr, "package_id", pkg.PackageID)
				_ = msg.Ack()
				continue
			}

			// An empty WorkloadID would key every unattributed package into a
			// single shared FSM state, so one orphan's score would drive the
			// state reported for all orphans. Drop and ack instead.
			if pkg.WorkloadID == "" {
				log.Warn("aggregator: fsm consumer dropping package with empty workload_id", "package_id", pkg.PackageID)
				_ = msg.Ack()
				continue
			}

			st := stateMachine.Evaluate(pkg.WorkloadID, sc.Total, pkg.PackageID)
			if st.FromState != st.ToState {
				log.Info("aggregator: fsm transition",
					"workload_id", st.WorkloadID,
					"from_state", string(st.FromState),
					"to_state", string(st.ToState),
					"reason", st.Reason,
					"score", st.Confidence,
					"package_id", st.PackageID)
			}
			_ = msg.Ack()
		}
	})
	return nil
}

// isFSMFetchTimeout reports whether err is an expected empty-fetch signal
// from consumer.Next rather than a real consumer failure. Mirrors the
// rules/baseline engines' isExpectedFetchTimeout.
func isFSMFetchTimeout(err error) bool {
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
//
// subscribe is the config.Manager.Subscribe entry point; the ring
// registers a callback against it so a `helm upgrade --set
// rateLimit.thresholdEventsPerSec=500` propagates per-adapter rate-limit
// updates without a process restart per FR49 (Story 1.13). Tests pass
// nil to skip the subscription wiring.
func startCollectorRing(ctx context.Context, g *errgroup.Group, log *slog.Logger, cfg *config.Config, subscribe func(func(*config.Config))) error {
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

	// metricsSources collects every constructed adapter so the metrics
	// surface can bind them once at the end. Each insertion uses the
	// canonical schema.Source* constant as the label value so
	// dashboards can join on the enum without renaming (binding
	// interpretation: AC1's "network_flow" enumerand is overridden to
	// "network" to match the existing schema.SourceNetwork constant).
	metricsSources := map[string]adapterMetrics{}

	// Story 1.13: per-source per-node rate-limit limiters. Constructed
	// once per source from the current cfg.RateLimit; each adapter is
	// handed a pointer to its limiter via the Config struct so the
	// hot-reload Subscribe callback below can mutate threshold /
	// cooldown / sampling-rate values without a process restart.
	rateLimiters := map[string]*ratelimit.Limiter{}
	buildLimiter := func(source string) (*ratelimit.Limiter, error) {
		return ratelimit.New(ratelimit.Options{
			Source:       source,
			Node:         nodeName,
			Enabled:      cfg.RateLimit.EnabledOrDefault(),
			Threshold:    cfg.RateLimit.ThresholdEventsPerSec,
			Cooldown:     time.Duration(cfg.RateLimit.CooldownSeconds) * time.Second,
			SamplingRate: cfg.RateLimit.SamplingRate,
			OnTransition: makeRateLimitTransitionLogger(log),
		})
	}
	for _, source := range []string{
		string(schema.SourceFalco),
		string(schema.SourceAudit),
		string(schema.SourceRuntime),
		string(schema.SourceNetwork),
	} {
		l, err := buildLimiter(source)
		if err != nil {
			return fmt.Errorf("collector: rate-limit %s: %w", source, err)
		}
		rateLimiters[source] = l
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
		Endpoint:  falcoSocket,
		Hostname:  nodeName,
		RateLimit: rateLimiters[string(schema.SourceFalco)],
	}, nc, log)
	if err != nil {
		closeNATS()
		return fmt.Errorf("collector: falco adapter: %w", err)
	}
	metricsSources[string(schema.SourceFalco)] = adapter

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
			RateLimit:        rateLimiters[string(schema.SourceAudit)],
		}
		auditAdapter, aerr := audit.New(auditCfg, nc, log)
		if aerr != nil {
			closeNATS()
			return fmt.Errorf("collector: audit adapter: %w", aerr)
		}
		metricsSources[string(schema.SourceAudit)] = auditAdapter
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
			RateLimit:        rateLimiters[string(schema.SourceRuntime)],
		}
		criAdapter, cerr := cri.New(criCfg, nc, log)
		if cerr != nil {
			closeNATS()
			return fmt.Errorf("collector: cri adapter: %w", cerr)
		}
		metricsSources[string(schema.SourceRuntime)] = criAdapter
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
			RateLimit:           rateLimiters[string(schema.SourceNetwork)],
		}
		cniAdapter, nerr := cni.New(cniCfg, nc, log)
		if nerr != nil {
			closeNATS()
			return fmt.Errorf("collector: cni adapter: %w", nerr)
		}
		metricsSources[string(schema.SourceNetwork)] = cniAdapter
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

	// Story 1.12: Prometheus metrics surface on :9090/metrics.
	// startMetricsServer registers the per-adapter source_healthy gauge,
	// sensor_events_total counter, and per-adapter detail counters in
	// that order BEFORE the HTTP server goroutine starts accepting
	// scrapes (Review P2: closes the scrape window where a scrape would
	// otherwise see source_healthy without audit_rejected, cri_*, cni_*).
	// Posture lives in the aggregator ring, so postureCli is nil here;
	// the disabled gauge is suppressed in the collector to avoid
	// double-registering across the two rings (the aggregator registers
	// it).
	if _, merr := startMetricsServer(ctx, g, log, cfg, nodeName, metricsSources, nil); merr != nil {
		closeNATS()
		return fmt.Errorf("collector: metrics: %w", merr)
	}

	// Story 1.13: hot-reload rate-limit knobs via config.Manager.
	// Subscribe per FR49. The callback runs synchronously on the
	// watcher goroutine; Limiter.Update* is atomic so steady-state
	// traffic is not paused by the threshold swap. subscribe may be
	// nil in tests that bypass the Manager.
	if subscribe != nil {
		subscribe(func(newCfg *config.Config) {
			if newCfg == nil {
				return
			}
			applyRateLimitReload(log, rateLimiters, newCfg.RateLimit)
		})
	}

	log.Info("collector: ring 1 wired",
		"falco_socket", falcoSocket,
		"node", nodeName,
		"rate_limit_enabled", cfg.RateLimit.EnabledOrDefault(),
		"rate_limit_threshold", cfg.RateLimit.ThresholdEventsPerSec,
		"rate_limit_cooldown", cfg.RateLimit.CooldownSeconds,
		"rate_limit_sampling", cfg.RateLimit.SamplingRate,
	)
	return nil
}

// makeRateLimitTransitionLogger returns the OnTransition callback every
// rate-limit limiter is constructed with. The callback emits a single
// info-level structured log line per engage/disengage transition per
// guardrail 29 (sustained engagement does not log; only the edges do).
func makeRateLimitTransitionLogger(log *slog.Logger) ratelimit.TransitionFn {
	return func(tr ratelimit.Transition) {
		if tr.Engaged {
			log.Info("rate_limit: engaged",
				"source", tr.Source,
				"node", tr.Node,
				"events_per_second", tr.EventsPerSecond,
				"threshold", tr.Threshold,
				"sampling_rate", tr.SamplingRate,
			)
			return
		}
		log.Info("rate_limit: disengaged",
			"source", tr.Source,
			"node", tr.Node,
			"engaged_for_seconds", tr.EngagedFor.Seconds(),
		)
	}
}

// applyRateLimitReload pushes the four rate-limit knobs from a freshly
// loaded RateLimitConfig into every adapter's *ratelimit.Limiter. Each
// Update* call is atomic (config.Manager guarantees Validate ran before
// the callback fires), so the hot path is never paused during the swap.
// Per-knob failures (which would only happen if Validate is bypassed)
// are logged at warn level without aborting the rest of the reload.
func applyRateLimitReload(log *slog.Logger, limiters map[string]*ratelimit.Limiter, rl config.RateLimitConfig) {
	for source, l := range limiters {
		if err := l.UpdateThreshold(rl.ThresholdEventsPerSec); err != nil {
			log.Warn("rate_limit: reload threshold rejected", "source", source, "err", err)
		}
		if err := l.UpdateCooldown(time.Duration(rl.CooldownSeconds) * time.Second); err != nil {
			log.Warn("rate_limit: reload cooldown rejected", "source", source, "err", err)
		}
		if err := l.UpdateSamplingRate(rl.SamplingRate); err != nil {
			log.Warn("rate_limit: reload sampling_rate rejected", "source", source, "err", err)
		}
		l.UpdateEnabled(rl.EnabledOrDefault())
	}
	log.Info("rate_limit: hot-reload applied",
		"enabled", rl.EnabledOrDefault(),
		"threshold", rl.ThresholdEventsPerSec,
		"cooldown", rl.CooldownSeconds,
		"sampling_rate", rl.SamplingRate,
	)
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
