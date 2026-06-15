package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// recordedCmd captures one helmOverlay shell-out for argv assertions.
type recordedCmd struct {
	name string
	args []string
}

// TestOverlayFileFor_Resolution pins the config -> overlay-file map (BI-1):
// the four clean arms, the legacy "rslt" alias collapsing to rslt-full, the
// two ablation slugs (incl. the rslt-l1-l2 filename normalisation of the
// canonical RSLT-L1+L2), case-insensitively; an unknown arm fails closed.
func TestOverlayFileFor_Resolution(t *testing.T) {
	cases := []struct {
		config string
		want   string
	}{
		{"f", "values-eval-f.yaml"},
		{"rs", "values-eval-rs.yaml"},
		{"rsl", "values-eval-rsl.yaml"},
		{"rslt", "values-eval-rslt-full.yaml"}, // legacy alias
		{"rslt-full", "values-eval-rslt-full.yaml"},
		{"rslt-l1-only", "values-eval-rslt-l1-only.yaml"},
		{"rslt-l1-l2", "values-eval-rslt-l1-l2.yaml"}, // BI-1: + normalised in the filename
		{"RSLT-Full", "values-eval-rslt-full.yaml"},   // case-insensitive
		{"RSLT-L1-L2", "values-eval-rslt-l1-l2.yaml"}, // case-insensitive
		{"RSLT-L1+L2", "values-eval-rslt-l1-l2.yaml"}, // BI-1: canonical chart enum (the "+")
		{"rslt-l1+l2", "values-eval-rslt-l1-l2.yaml"}, // lower-case "+" form
	}
	for _, tc := range cases {
		got, ok := overlayFileFor(tc.config)
		if !ok || got != tc.want {
			t.Errorf("overlayFileFor(%q) = (%q, %v); want (%q, true)", tc.config, got, ok, tc.want)
		}
	}

	for _, bad := range []string{"rslt-bogus", "bogus", "rslt-l1", ""} {
		if got, ok := overlayFileFor(bad); ok {
			t.Errorf("overlayFileFor(%q) = (%q, true); want (\"\", false) (fail closed)", bad, got)
		}
	}
}

// TestOverlayFilesCoverValidatedArms guards the BI-4 lock-step invariant:
// every arm validateConfig accepts MUST have an overlay-file mapping (else a
// validated arm would dispatch into a missing overlay). The legacy "rslt"
// alias is the only non-filename arm and is covered explicitly above.
func TestOverlayFilesCoverValidatedArms(t *testing.T) {
	// Include the canonical chart enum spelling `RSLT-L1+L2` (the "+" form)
	// to prove every documented arm validateConfig accepts also resolves to
	// an overlay file after normalisation (BI-1 + BI-4 lock-step).
	for _, arm := range []string{"f", "rs", "rsl", "rslt", "rslt-full", "rslt-l1-only", "rslt-l1-l2", "RSLT-L1+L2"} {
		if err := validateConfig(arm); err != nil {
			t.Fatalf("validateConfig(%q) rejected a real arm: %v", arm, err)
		}
		if _, ok := overlayFileFor(arm); !ok {
			t.Errorf("validated arm %q has no overlayFiles mapping (BI-4 lock-step broken)", arm)
		}
	}
}

// writeOverlayFixtures writes empty stand-in overlay files into dir so the
// helmOverlay's fail-closed os.Stat passes for an Apply argv assertion that
// must not depend on the real committed overlays' contents.
func writeOverlayFixtures(t *testing.T, dir string) {
	t.Helper()
	for _, f := range overlayFiles {
		path := filepath.Join(dir, f)
		if err := os.WriteFile(path, []byte("evaluation:\n  config: x\n"), 0o644); err != nil {
			t.Fatalf("write overlay fixture %q: %v", path, err)
		}
	}
}

// TestHelmOverlayApply_Argv asserts Apply issues the exact helm + kubectl
// argv the AC2 / BI-5 Ready gate requires: a `helm upgrade --install` with
// the resolved overlay file + --wait + --timeout, then a `kubectl rollout
// status deploy/<release>-olaitan-aggregator` with the namespace + timeout.
// The injected runCmd records the calls; no cluster is touched.
func TestHelmOverlayApply_Argv(t *testing.T) {
	dir := t.TempDir()
	writeOverlayFixtures(t, dir)

	var calls []recordedCmd
	o := newHelmOverlay(overlayConfig{
		chartRoot:   "charts/olaitan",
		release:     "myrel",
		namespace:   "myns",
		overlaysDir: dir,
		timeout:     90 * time.Second,
	}, func(ctx context.Context, name string, args ...string) error {
		calls = append(calls, recordedCmd{name: name, args: args})
		return nil
	}, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))

	if err := o.Apply(context.Background(), "rslt-l1-l2"); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("expected 2 shell-outs (helm + kubectl), got %d: %+v", len(calls), calls)
	}

	helmCall := calls[0]
	if helmCall.name != "helm" {
		t.Errorf("first call = %q; want helm", helmCall.name)
	}
	helmJoined := strings.Join(helmCall.args, " ")
	for _, want := range []string{
		"upgrade --install myrel charts/olaitan",
		"--namespace myns",
		"--reuse-values",
		"--values " + filepath.Join(dir, "values-eval-rslt-l1-l2.yaml"),
		"--wait",
		"--timeout 1m30s",
	} {
		if !strings.Contains(helmJoined, want) {
			t.Errorf("helm argv %q missing %q", helmJoined, want)
		}
	}

	kubectlCall := calls[1]
	if kubectlCall.name != "kubectl" {
		t.Errorf("second call = %q; want kubectl", kubectlCall.name)
	}
	kubectlJoined := strings.Join(kubectlCall.args, " ")
	for _, want := range []string{
		"rollout status deploy/myrel-olaitan-aggregator",
		"--namespace myns",
		"--timeout 1m30s",
	} {
		if !strings.Contains(kubectlJoined, want) {
			t.Errorf("kubectl argv %q missing %q", kubectlJoined, want)
		}
	}
}

// TestHelmOverlayApply_MissingOverlayFailsClosed asserts that an arm whose
// resolved overlay file is absent on disk aborts BEFORE any shell-out
// (defence in depth, BI-4): the run must not dial helm with an empty
// --values path.
func TestHelmOverlayApply_MissingOverlayFailsClosed(t *testing.T) {
	dir := t.TempDir() // empty: no overlay files written
	called := false
	o := newHelmOverlay(defaultOverlayConfigWith(dir), func(ctx context.Context, name string, args ...string) error {
		called = true
		return nil
	}, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))

	err := o.Apply(context.Background(), "rs")
	if err == nil {
		t.Fatalf("expected a fail-closed error for a missing overlay file, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error %q does not name the missing overlay file", err.Error())
	}
	if called {
		t.Errorf("helm/kubectl must NOT run when the overlay file is missing")
	}
}

// TestHelmOverlayApply_UnknownArmFailsClosed asserts an arm with no
// overlay-file mapping fails closed before any shell-out (the validateConfig
// tightening is the primary guard; this is the in-Apply defence in depth).
func TestHelmOverlayApply_UnknownArmFailsClosed(t *testing.T) {
	dir := t.TempDir()
	writeOverlayFixtures(t, dir)
	called := false
	o := newHelmOverlay(defaultOverlayConfigWith(dir), func(ctx context.Context, name string, args ...string) error {
		called = true
		return nil
	}, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))

	if err := o.Apply(context.Background(), "rslt-bogus"); err == nil {
		t.Fatalf("expected a fail-closed error for an unknown arm, got nil")
	}
	if called {
		t.Errorf("helm/kubectl must NOT run for an unknown arm")
	}
}

// TestHelmOverlayApply_HelmFailureSurfaces asserts a non-zero helm exit is
// surfaced as a fail-closed error and the rollout-status gate is NOT reached
// (the Ready gate is meaningless if the upgrade itself failed).
func TestHelmOverlayApply_HelmFailureSurfaces(t *testing.T) {
	dir := t.TempDir()
	writeOverlayFixtures(t, dir)
	var sawKubectl bool
	o := newHelmOverlay(defaultOverlayConfigWith(dir), func(ctx context.Context, name string, args ...string) error {
		if name == "kubectl" {
			sawKubectl = true
		}
		if name == "helm" {
			return fmt.Errorf("release failed: timed out waiting for the condition")
		}
		return nil
	}, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))

	err := o.Apply(context.Background(), "rs")
	if err == nil || !strings.Contains(err.Error(), "helm upgrade") {
		t.Fatalf("expected a helm-upgrade fail-closed error, got %v", err)
	}
	if sawKubectl {
		t.Errorf("rollout-status must NOT run after a failed helm upgrade")
	}
}

// TestHelmOverlayApply_RolloutTimeoutSurfaces asserts the explicit
// aggregator Ready gate is fail-closed: a non-zero kubectl rollout-status
// exit aborts the trial with a clear error naming the aggregator.
func TestHelmOverlayApply_RolloutTimeoutSurfaces(t *testing.T) {
	dir := t.TempDir()
	writeOverlayFixtures(t, dir)
	o := newHelmOverlay(defaultOverlayConfigWith(dir), func(ctx context.Context, name string, args ...string) error {
		if name == "kubectl" {
			return fmt.Errorf("error: deployment exceeded its progress deadline")
		}
		return nil
	}, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))

	err := o.Apply(context.Background(), "rs")
	if err == nil || !strings.Contains(err.Error(), "Ready") {
		t.Fatalf("expected an aggregator-not-Ready fail-closed error, got %v", err)
	}
	if !strings.Contains(err.Error(), "olaitan-aggregator") {
		t.Errorf("error %q does not name the aggregator deployment", err.Error())
	}
}

// TestHelmOverlayApply_TimeoutCancelsChild asserts the overlay timeout is
// wired as a context DEADLINE on the apply phase: a helm child that ignores
// its own --timeout flag (here a fake that blocks until ctx is cancelled) is
// still aborted when the budget elapses, and the rollout-status gate is not
// reached.
func TestHelmOverlayApply_TimeoutCancelsChild(t *testing.T) {
	dir := t.TempDir()
	writeOverlayFixtures(t, dir)

	oc := defaultOverlayConfigWith(dir)
	oc.timeout = 20 * time.Millisecond // tiny budget so the test is fast

	var sawKubectl bool
	o := newHelmOverlay(oc, func(ctx context.Context, name string, args ...string) error {
		if name == "kubectl" {
			sawKubectl = true
			return nil
		}
		// helm: simulate a hung child that ignores its --timeout flag and
		// only unblocks when the derived ctx deadline cancels it.
		<-ctx.Done()
		return ctx.Err()
	}, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))

	err := o.Apply(context.Background(), "rs")
	if err == nil {
		t.Fatalf("expected the apply to abort when the overlay-timeout deadline elapsed, got nil")
	}
	if sawKubectl {
		t.Errorf("rollout-status must NOT run after the helm child was cancelled")
	}
}

// TestHelmOverlayApply_ParentCancelAbortsApply asserts a caller-cancelled
// run also aborts the in-flight overlay apply (the derived ctx inherits the
// parent's cancellation, threading into the exec.CommandContext children).
func TestHelmOverlayApply_ParentCancelAbortsApply(t *testing.T) {
	dir := t.TempDir()
	writeOverlayFixtures(t, dir)

	o := newHelmOverlay(defaultOverlayConfigWith(dir), func(ctx context.Context, name string, args ...string) error {
		<-ctx.Done()
		return ctx.Err()
	}, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	if err := o.Apply(ctx, "rs"); err == nil {
		t.Fatalf("expected a parent-cancellation abort, got nil")
	}
}

// TestAggregatorDeployName pins the fullname-dedup behaviour the chart's
// olaitan.fullname helper applies (Story 5.3 chart-wiring reconciliation):
// the canonical "olaitan" release collapses to olaitan-aggregator (NOT
// olaitan-olaitan-aggregator), while a release not containing "olaitan"
// expands to <release>-olaitan-aggregator.
func TestAggregatorDeployName(t *testing.T) {
	cases := map[string]string{
		"olaitan":      "deploy/olaitan-aggregator",
		"olaitan-prod": "deploy/olaitan-prod-aggregator",
		"myrel":        "deploy/myrel-olaitan-aggregator",
		"eval-olaitan": "deploy/eval-olaitan-aggregator",
	}
	for release, want := range cases {
		if got := aggregatorDeployName(release); got != want {
			t.Errorf("aggregatorDeployName(%q) = %q; want %q", release, got, want)
		}
	}
}

// defaultOverlayConfigWith returns the harness default overlay config with
// the overlays dir + chart root pointed at the supplied test dir.
func defaultOverlayConfigWith(dir string) overlayConfig {
	oc := defaultOverlayConfig()
	oc.overlaysDir = dir
	oc.chartRoot = dir
	return oc
}

// TestDefaultOverlayConfig pins the flag defaults (BI-5) so a default
// invocation targets the in-repo chart + the canonical olaitan release.
func TestDefaultOverlayConfig(t *testing.T) {
	oc := defaultOverlayConfig()
	if oc.chartRoot != "deploy/helm/olaitan" || oc.overlaysDir != "deploy/helm/olaitan" {
		t.Errorf("default chartRoot/overlaysDir = %q/%q; want deploy/helm/olaitan", oc.chartRoot, oc.overlaysDir)
	}
	if oc.release != "olaitan" || oc.namespace != "olaitan" {
		t.Errorf("default release/namespace = %q/%q; want olaitan", oc.release, oc.namespace)
	}
	if oc.timeout != 5*time.Minute {
		t.Errorf("default timeout = %s; want 5m0s", oc.timeout)
	}
}
