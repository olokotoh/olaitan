package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/olokotoh/olaitan/internal/admission/applog"
	collectorapplog "github.com/olokotoh/olaitan/internal/collector/applog"
	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/schema"
)

// runApplogSidecar is the cmd/olaitan applog-sidecar entry-point. The
// sidecar runs in-pod alongside an opt-in cooperating workload (the
// MutatingAdmissionWebhook in internal/admission/applog injected it
// based on the olaitan.io/log-sidecar="enabled" annotation), tails
// the cooperating application's stdout and stderr from the shared
// emptyDir volume, and publishes each line to NATS subjects.RawAppLog
// as a schema.Event of source=applog / category=log.
//
// Configuration: every parameter comes from environment variables
// injected by the admission webhook's downward-API patch. There is no
// olaitan.yaml on the sidecar's filesystem because the sidecar runs
// inside an arbitrary operator workload pod, not the agent
// DaemonSet's pod.
//
// Required env vars:
//
//   - K8S_POD_NAME        the workload pod's name (downward API)
//   - K8S_POD_NAMESPACE   the workload pod's namespace (downward API)
//   - K8S_POD_UID         the workload pod's UID (downward API)
//   - K8S_NODE_NAME       the node hosting the pod (downward API)
//   - OLAITAN_TARGET_CONTAINER  the application container name being tailed
//   - NATS_URL            connection URL for the JetStream-backed bus
//
// Optional env vars (sane defaults):
//
//   - OLAITAN_APPLOG_STDOUT_PATH   default /var/log/app/stdout.log
//   - OLAITAN_APPLOG_STDERR_PATH   default /var/log/app/stderr.log
//   - OLAITAN_APPLOG_CHANNEL_BUFFER  default 1024
//   - OLAITAN_APPLOG_STALENESS_TIMEOUT  default 30m
//
// The sidecar exits with code 0 on graceful SIGTERM (kubelet
// terminating the workload pod) or on a panic recovered by the
// adapter's defer recover() (Story 1.9 guardrail item 18: a sidecar
// panic must not take down the workload pod). Any other startup
// failure surfaces as exit 1.
func runApplogSidecar(ctx context.Context, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("olaitan applog-sidecar", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}

	log := slog.New(slog.NewJSONHandler(stderr, nil))
	log = log.With("subcommand", "applog-sidecar", "version", version)

	required := []string{"K8S_POD_NAME", "K8S_POD_NAMESPACE", "K8S_POD_UID", "K8S_NODE_NAME", "OLAITAN_TARGET_CONTAINER", "NATS_URL"}
	for _, name := range required {
		if os.Getenv(name) == "" {
			log.Error("startup: required env var is empty", "name", name)
			return 1
		}
	}

	cfg := collectorapplog.Config{
		StdoutPath: getenvDefault("OLAITAN_APPLOG_STDOUT_PATH", "/var/log/app/stdout.log"),
		StderrPath: getenvDefault("OLAITAN_APPLOG_STDERR_PATH", "/var/log/app/stderr.log"),
		Pod: schema.PodRef{
			Name:      os.Getenv("K8S_POD_NAME"),
			Namespace: os.Getenv("K8S_POD_NAMESPACE"),
			UID:       os.Getenv("K8S_POD_UID"),
			Node:      os.Getenv("K8S_NODE_NAME"),
		},
		Container: os.Getenv("OLAITAN_TARGET_CONTAINER"),
		Labels:    parseLabelsFromEnv(),
	}
	if v := os.Getenv("OLAITAN_APPLOG_CHANNEL_BUFFER"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			log.Error("startup: OLAITAN_APPLOG_CHANNEL_BUFFER not a valid int", "value", v, "err", err)
			return 1
		}
		cfg.ChannelBuffer = n
	}
	if v := os.Getenv("OLAITAN_APPLOG_STALENESS_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			log.Error("startup: OLAITAN_APPLOG_STALENESS_TIMEOUT not a valid duration", "value", v, "err", err)
			return 1
		}
		cfg.StalenessTimeout = d
	}

	natsCfg := natsclient.DefaultConfig()
	natsCfg.URL = os.Getenv("NATS_URL")
	natsCfg.Name = "olaitan-applog-sidecar"
	nc, err := natsclient.NewClient(natsCfg)
	if err != nil {
		log.Error("startup: nats client", "err", err)
		return 1
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if cerr := nc.Close(closeCtx); cerr != nil {
			log.Warn("shutdown: nats close", "err", cerr)
		}
	}()

	adapter, err := collectorapplog.New(cfg, nc, log)
	if err != nil {
		log.Error("startup: applog adapter", "err", err)
		return 1
	}

	log.Info("applog-sidecar: started",
		"pod", cfg.Pod.Namespace+"/"+cfg.Pod.Name,
		"container", cfg.Container,
		"stdout_path", cfg.StdoutPath,
		"stderr_path", cfg.StderrPath)

	if err := adapter.Run(ctx); err != nil {
		log.Error("applog-sidecar: run exited with error", "err", err)
		return 1
	}
	log.Info("applog-sidecar: graceful shutdown")
	return 0
}

// runApplogWebhook is the cmd/olaitan applog-webhook entry-point. The
// webhook server runs as a Deployment (replicaCount default 2 for HA
// per the K8s admission-webhook good-practice guidance). Every Pod-
// create admission request flows through this server; pods bearing
// the olaitan.io/log-sidecar="enabled" annotation receive a JSON
// Patch that adds the applog sidecar container to spec.initContainers
// (with restartPolicy: Always per KEP-753) and the shared emptyDir
// log volume to spec.volumes plus the peer container's volumeMounts.
//
// Required env vars:
//
//   - OLAITAN_WEBHOOK_TLS_CERT  filesystem path to the TLS server cert
//   - OLAITAN_WEBHOOK_TLS_KEY   filesystem path to the TLS server key
//
// Optional env vars (sane defaults):
//
//   - OLAITAN_WEBHOOK_LISTEN_ADDR     default :8443
//   - OLAITAN_WEBHOOK_USE_NATIVE_SIDECAR  default true (KEP-753 native sidecar)
//   - OLAITAN_WEBHOOK_SIDECAR_IMAGE   default ""; when empty the
//     webhook reads the image from a downward-API env passthrough so
//     the chart can supply image:tag at deploy time.
func runApplogWebhook(ctx context.Context, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("olaitan applog-webhook", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}

	log := slog.New(slog.NewJSONHandler(stderr, nil))
	log = log.With("subcommand", "applog-webhook", "version", version)

	cert := os.Getenv("OLAITAN_WEBHOOK_TLS_CERT")
	key := os.Getenv("OLAITAN_WEBHOOK_TLS_KEY")
	if cert == "" || key == "" {
		log.Error("startup: OLAITAN_WEBHOOK_TLS_CERT and OLAITAN_WEBHOOK_TLS_KEY must both be set")
		return 1
	}

	useNative := true
	if v := os.Getenv("OLAITAN_WEBHOOK_USE_NATIVE_SIDECAR"); v != "" {
		switch strings.ToLower(v) {
		case "true", "1", "yes":
			useNative = true
		case "false", "0", "no":
			useNative = false
		default:
			log.Error("startup: OLAITAN_WEBHOOK_USE_NATIVE_SIDECAR must be a boolean", "value", v)
			return 1
		}
	}

	cfg := applog.WebhookConfig{
		ListenAddr:       getenvDefault("OLAITAN_WEBHOOK_LISTEN_ADDR", ":8443"),
		TLSCertFile:      cert,
		TLSKeyFile:       key,
		UseNativeSidecar: useNative,
		SidecarImage:     os.Getenv("OLAITAN_WEBHOOK_SIDECAR_IMAGE"),
	}

	srv, err := applog.NewWebhook(cfg, log)
	if err != nil {
		log.Error("startup: webhook", "err", err)
		return 1
	}

	log.Info("applog-webhook: started",
		"listen_addr", cfg.ListenAddr,
		"use_native_sidecar", cfg.UseNativeSidecar)

	if err := srv.Run(ctx); err != nil {
		log.Error("applog-webhook: run exited with error", "err", err)
		return 1
	}
	log.Info("applog-webhook: graceful shutdown")
	return 0
}

// getenvDefault returns os.Getenv(name) if non-empty, otherwise def.
func getenvDefault(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// parseLabelsFromEnv reads pod labels from a downward-API projected
// volume at /etc/podinfo/labels. Each line is `key="value"`. Returns
// nil if the file is missing or empty (the sidecar still runs; tags
// just lack pod-label entries).
func parseLabelsFromEnv() map[string]string {
	const path = "/etc/podinfo/labels"
	body, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	out := make(map[string]string)
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		k := strings.TrimSpace(line[:eq])
		v := strings.TrimSpace(line[eq+1:])
		v = strings.Trim(v, `"`)
		if k == "" {
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// _ is a build-time assertion that the runApplog* functions match the
// switch-case dispatch signatures used in main.go. Without this the
// signatures could drift silently.
var (
	_ = func(ctx context.Context, args []string, stderr io.Writer) int {
		return runApplogSidecar(ctx, args, stderr)
	}
	_ = func(ctx context.Context, args []string, stderr io.Writer) int {
		return runApplogWebhook(ctx, args, stderr)
	}

	// duration is referenced via fmt.Sprintf in helper paths (kept to
	// avoid an unused-import lint when the optional time/strconv
	// branches above are unreachable in a stripped build).
	_ time.Duration
	_ = fmt.Sprintf
)
