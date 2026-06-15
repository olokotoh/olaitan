package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Story 5.3 fills the FROZEN ConfigOverlay seam (runner.go) WITHOUT
// reshaping the interface or the Runner loop (the Story 5.1
// PO-Ratification-1 freeze, the same discipline Story 5.2 honoured for the
// Scenario seam). It supplies the six values-eval-{config}.yaml overlays
// and a real helmOverlay that applies the matching overlay via `helm
// upgrade --install --values <overlay> --wait` and confirms the aggregator
// Ready via an explicit `kubectl rollout status` before the scenario fires.

// overlayFiles maps the validated --config arm (lower-cased) to its
// committed values-eval-<slug>.yaml overlay filename (BI-1). The first four
// arms map cleanly; the two ablation arms normalise the canonical enum's
// awkward filename characters: RSLT-L1-only -> rslt-l1-only (clean) and
// RSLT-L1+L2 -> rslt-l1-l2 (the "+" normalised to "-" in the filename; the
// IN-FILE evaluation.config stays the canonical RSLT-L1+L2 so the chart's
// validator + effective-value helpers fire unchanged). The legacy "rslt"
// alias collapses to the same overlay as "rslt-full".
var overlayFiles = map[string]string{
	"f":            "values-eval-f.yaml",
	"rs":           "values-eval-rs.yaml",
	"rsl":          "values-eval-rsl.yaml",
	"rslt":         "values-eval-rslt-full.yaml",
	"rslt-full":    "values-eval-rslt-full.yaml",
	"rslt-l1-only": "values-eval-rslt-l1-only.yaml",
	"rslt-l1-l2":   "values-eval-rslt-l1-l2.yaml",
}

// overlayFileFor resolves the validated --config arm to its overlay
// filename. It normalises the arm first (case-insensitive + the canonical
// "+" -> "-" rewrite, normalizeArm) so the canonical chart enum
// `RSLT-L1+L2` (and any mixed-case spelling) resolves to the same overlay
// the flag-parse path validated. It returns false for any arm with no
// committed overlay so helmOverlay.Apply fails closed rather than shelling
// out with an empty --values path (defence in depth alongside the
// flag-parse validateConfig tightening, BI-4).
func overlayFileFor(config string) (string, bool) {
	f, ok := overlayFiles[normalizeArm(config)]
	return f, ok
}

// defaultOverlayConfig returns the harness's default overlay wiring (the
// flag defaults, BI-5): the in-repo chart root + overlays dir, the
// "olaitan" release + namespace, and a 5m Ready-gate budget.
func defaultOverlayConfig() overlayConfig {
	return overlayConfig{
		chartRoot:   "deploy/helm/olaitan",
		release:     "olaitan",
		namespace:   "olaitan",
		overlaysDir: "deploy/helm/olaitan",
		timeout:     5 * time.Minute,
	}
}

// overlayConfig holds the helmOverlay wiring threaded in from the CLI flags
// (the Story 5.2 --scenarios-root precedent). It is a small struct rather
// than five positional newRunner args so the call site stays readable.
type overlayConfig struct {
	chartRoot   string
	release     string
	namespace   string
	overlaysDir string
	timeout     time.Duration
}

// overlayRunFunc runs an external command (helm / kubectl) returning a
// clear error on a non-zero exit. It is the injectable shell-out the
// helmOverlay drives, threaded from run() so a unit test can assert the
// exact argv without a cluster while main wires the real execRunCmd.
type overlayRunFunc func(ctx context.Context, name string, args ...string) error

// helmOverlay is the real ConfigOverlay impl Story 5.3 wires behind the
// frozen seam, replacing the Story-5.1 rsOverlay log-deferral. Apply
// resolves the arm to its overlay file (fail closed if missing, BI-4),
// runs `helm upgrade --install <release> <chartRoot> --namespace <ns>
// --values <overlaysDir>/<overlay> --wait --timeout <budget>` (the
// chart-level Ready gate), then `kubectl rollout status
// deploy/<release>-olaitan-aggregator --namespace <ns> --timeout <budget>`
// (the explicit aggregator-Ready gate the AC's "pods Ready" intent wants,
// BI-5). Any non-zero exit / timeout returns a fail-closed error.
type helmOverlay struct {
	chartRoot   string
	release     string
	namespace   string
	overlaysDir string
	timeout     time.Duration
	logger      *slog.Logger
	// runCmd runs an external command, returning a clear error on a
	// non-zero exit. It is a field so the unit test can assert the exact
	// helm / kubectl argv (the overlay file, --wait, the rollout-status
	// target) without a cluster; main wires the real execRunCmd.
	runCmd overlayRunFunc
}

// newHelmOverlay builds a helmOverlay from the threaded overlayConfig and
// the injected command runner (main passes execRunCmd; a unit test passes a
// fake). A nil logger defaults to slog.Default and a nil runCmd defaults to
// the real execRunCmd so Apply cannot nil-panic.
func newHelmOverlay(oc overlayConfig, runCmd overlayRunFunc, logger *slog.Logger) *helmOverlay {
	if logger == nil {
		logger = slog.Default()
	}
	if runCmd == nil {
		runCmd = execRunCmd
	}
	return &helmOverlay{
		chartRoot:   oc.chartRoot,
		release:     oc.release,
		namespace:   oc.namespace,
		overlaysDir: oc.overlaysDir,
		timeout:     oc.timeout,
		logger:      logger,
		runCmd:      runCmd,
	}
}

// Apply selects the named configuration arm for the trial by applying its
// committed values overlay and waiting for the aggregator to be Ready
// (AC2). It is FAIL-CLOSED: a missing overlay file, a non-zero helm /
// kubectl exit, or a Ready-gate timeout returns an error, which the Runner
// surfaces as "overlay apply: ..." and the trial aborts (the deferred
// Cleanup still runs, Story 5.1 BI-2).
func (o *helmOverlay) Apply(ctx context.Context, config string) error {
	overlayFile, ok := overlayFileFor(config)
	if !ok {
		return fmt.Errorf("config overlay: %q has no committed values-eval overlay (want one of f, rs, rsl, rslt/rslt-full, rslt-l1-only, rslt-l1-l2)", config)
	}
	valuesPath := filepath.Join(o.overlaysDir, overlayFile)
	// Fail closed if the resolved overlay file does not exist on disk
	// (defence in depth: a mis-set --overlays-dir or a deleted overlay
	// must abort loudly, not let helm dial an empty --values path).
	if _, err := os.Stat(valuesPath); err != nil {
		return fmt.Errorf("config overlay: values file %q for arm %q not found: %w", valuesPath, config, err)
	}

	timeout := o.timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	aggregatorDeploy := aggregatorDeployName(o.release)

	// Scope the overlay timeout to a context DEADLINE on the apply phase
	// (the helm-upgrade --wait + the aggregator rollout-status gate), so a
	// child that ignores its own --timeout flag is still cancelled when the
	// budget elapses. The deadline is derived from the incoming ctx, so a
	// caller-cancelled run also aborts the in-flight helm/kubectl child (the
	// derived ctx threads into the exec.CommandContext children via runCmd).
	// It bounds ONLY this phase -- the whole-trial budget is the Runner
	// loop's concern -- which is why the deadline is per-Apply, not on the
	// whole Run (the frozen ConfigOverlay seam stays Apply(ctx, config)).
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	o.logger.Info("config overlay: applying arm",
		"config", config,
		"overlay", valuesPath,
		"release", o.release,
		"namespace", o.namespace,
		"timeout", timeout.String())

	// (1) helm upgrade --install --reuse-values --values <overlay> --wait
	// --timeout <budget> (the chart-level Ready gate).
	//
	// --reuse-values makes the RS re-apply genuinely IDEMPOTENT on the
	// existing release (BI-8 option (a), the documented "idempotent
	// no-change upgrade" that "re-applies the same RS values"): the overlay
	// is LAYERED on top of the install-time values (e.g. the kind-smoke
	// image / falco overrides) rather than resetting every non-overlay knob
	// to the chart default. On a first install (no prior release) helm
	// treats --reuse-values as a no-op and uses only the overlay, so the
	// "first-install" path (BI-8 option (b)) still works. This refines the
	// BI-5 literal argv with the flag the documented idempotent intent
	// requires.
	helmArgs := []string{
		"upgrade", "--install", o.release, o.chartRoot,
		"--namespace", o.namespace,
		"--reuse-values",
		"--values", valuesPath,
		"--wait",
		"--timeout", timeout.String(),
	}
	if err := o.runCmd(ctx, "helm", helmArgs...); err != nil {
		return fmt.Errorf("config overlay: helm upgrade for arm %q failed: %w", config, err)
	}

	// (2) explicit aggregator rollout-status Ready gate (BI-5): the
	// aggregator is the component the scenario hits, so confirm it
	// specifically is Ready (helm --wait covers all resources; this makes
	// the AC's "pods Ready" intent unambiguous and the failure message
	// precise).
	rolloutArgs := []string{
		"rollout", "status", aggregatorDeploy,
		"--namespace", o.namespace,
		"--timeout", timeout.String(),
	}
	if err := o.runCmd(ctx, "kubectl", rolloutArgs...); err != nil {
		return fmt.Errorf("config overlay: aggregator %q did not reach Ready for arm %q: %w", aggregatorDeploy, config, err)
	}

	o.logger.Info("config overlay: arm Ready", "config", config, "aggregator", aggregatorDeploy)
	return nil
}

// aggregatorDeployName returns the `deploy/<name>` rollout-status target for
// the aggregator under the given release name, mirroring the chart's
// olaitan.fullname helper (_helpers.tpl) so the explicit Ready gate (BI-5)
// names the deployment the chart ACTUALLY renders.
//
// VERIFIED against the chart (Story 5.3): the aggregator deployment is
// <fullname>-aggregator, where fullname is the release name when it already
// contains the chart name "olaitan" (the canonical `--release olaitan` case
// collapses olaitan-olaitan to olaitan, so the deployment is
// olaitan-aggregator, NOT olaitan-olaitan-aggregator), else
// <release>-olaitan-aggregator. This refines the BI-5 literal
// "<release>-olaitan-aggregator" string to the chart's real fullname-dedup
// behaviour; without it the canonical release's rollout-status would target a
// non-existent deployment and the Ready gate would always fail.
func aggregatorDeployName(release string) string {
	const chartName = "olaitan"
	fullname := release
	if !strings.Contains(release, chartName) {
		fullname = release + "-" + chartName
	}
	return "deploy/" + fullname + "-aggregator"
}

// execRunCmd is the real os/exec command runner wired into helmOverlay in
// main.go. It runs name+args with the given context (so a cancelled run
// aborts the shell-out) and folds combined output into a clear error on a
// non-zero exit so the fail-closed message names what helm / kubectl
// printed. It is small and side-effecting, so it lives behind the
// injectable runCmd field and is exercised by the e2e RS path on kind
// (AC4 HALF B), not unit-tested directly.
func execRunCmd(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
