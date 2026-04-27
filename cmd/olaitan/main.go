// Command olaitan is the entrypoint for both the collector (DaemonSet)
// and the aggregator (Deployment). One binary, two subcommands —
// selected at container start via the Helm chart's pod spec (see
// deploy/helm/olaitan/templates/daemonset.yaml + deployment.yaml).
//
// Ring wiring is stubbed here: Story 1.7 delivers the shared startup
// skeleton (flag parsing, config load + watch, health server, SIGTERM
// graceful shutdown). The actual ring goroutines — signal collectors,
// correlator, analyst, decision, response — land in Epic 2+.
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

	"github.com/olokotoh/olaitan/internal/config"
	"github.com/olokotoh/olaitan/internal/health"
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

	// Hot-reload goroutine. Watch returns nil when ctx is cancelled;
	// when it returns an error before ctx-cancel (fsnotify exhaustion,
	// inode rotation), trip the watcherFailed flag so the readiness
	// probe goes 503 and kubelet restarts the pod — preferable to the
	// log-and-pretend-config-reload-still-works failure mode.
	var watcherFailed atomic.Bool
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		if err := mgr.Watch(ctx); err != nil && ctx.Err() == nil {
			watcherFailed.Store(true)
			log.Error("config: watch exited unexpectedly — readiness probe will fail",
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

	// Health server on :8080. Start returns when ctx is cancelled, so we
	// run it inline (blocking) — the watcher goroutine already covers
	// the parallel teardown path.
	srv := health.New(healthAddr, log, check)
	log.Info(ring+": not yet implemented, awaiting ring wiring",
		"config", *cfgPath,
	)

	if err := srv.Start(ctx); err != nil {
		log.Error("startup: health server", "addr", healthAddr, "err", err)
		// Block on the watcher so it gets a chance to clean up before
		// returning. The watcher goroutine reacts to ctx cancellation;
		// runRing's outer signal.NotifyContext defer (or the test's
		// context cancel) is what unblocks it.
		<-watcherDone
		return 1
	}

	log.Info(ring + ": shutting down")
	<-watcherDone
	return 0
}

func printUsage(w io.Writer) {
	_, _ = fmt.Fprintf(w, `Usage: olaitan <command> [flags]

Commands:
  collector    Run the signal collector (DaemonSet mode)
  aggregator   Run the aggregator (correlator + decision + response)
  version      Print version
  help         Show this help

Flags (collector, aggregator):
  --config <path>   Path to olaitan.yaml (default: /etc/olaitan/olaitan.yaml)

Olaitan — LLM-powered autonomous runtime security agent for Kubernetes.
`)
}
