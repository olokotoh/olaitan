package main

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

// The FIVE frozen seams (the core Story 5.1 deliverable).
//
// The Runner holds five interface fields and drives them in the
// architecture-mandated order (architecture.md:712):
//
//	Reset -> Warm -> ConfigOverlay.Apply -> Scenario.Run -> Capturer.Capture -> Cleanup
//
// Story 5.1 FREEZES these signatures; Stories 5.2-5.5 supply rich
// implementations BEHIND them WITHOUT reshaping the Runner loop or the
// interface signatures (PO Ratification 1, BI-1). Every placeholder method
// carries a `// Story 5.x:` TODO naming the owning story so the fill-in is
// mechanical and the harness shape is frozen now.

// ClusterController owns the cluster lifecycle phases (Story 5.1, AC1). The
// 5.1 minimal impl assumes/reuses the Story-1.19 rs_smoke kind bring-up
// (the chart already installs healthy under evaluation.config=RS); the
// rich multi-arm reset/hardening is later.
type ClusterController interface {
	// Reset returns the cluster to a known clean baseline before a trial.
	Reset(ctx context.Context) error
	// Warm performs any pre-scenario warm-up (e.g. baseline priming).
	Warm(ctx context.Context) error
	// Cleanup tears the trial down. It runs as the LAST phase, via defer,
	// so it executes even when an earlier phase errors (BI-2).
	Cleanup(ctx context.Context) error
}

// ConfigOverlay applies the evaluation configuration arm (the F / RS / RSL
// / RSLT-full / ablation overlays). FILLED BY STORY 5.3: 5.3 supplies the
// six values-eval-{config}.yaml overlays behind this seam (helmOverlay in
// overlay.go, built by newHelmOverlay). Apply runs `helm upgrade --install
// --values values-eval-<name>.yaml --wait` plus an explicit `kubectl
// rollout status deploy/<release>-olaitan-aggregator` Ready gate; the 5.1
// rsOverlay log-deferral is replaced.
type ConfigOverlay interface {
	// Apply selects the named configuration arm (e.g. "rs", "rslt-full")
	// for the trial.
	Apply(ctx context.Context, config string) error
}

// Scenario launches the attack-scenario harness for the trial. FILLED BY
// STORY 5.2: 5.2 supplies the five MITRE-annotated S1-S5 harnesses under
// deploy/demo/scenarios/ behind this seam (scenarioHarness in scenario.go,
// built by newScenario). The 5.1 rsScenario no-op marker is replaced;
// --scenario sN now dispatches the matching sN-<slug>/ harness.
type Scenario interface {
	// Run drives the scenario's synthetic attack against the warmed
	// cluster.
	Run(ctx context.Context) error
}

// Capturer collects the per-run artefacts into runDir. OWNED BY STORY 5.4:
// 5.4 supplies the six-file events/evidence/assessments/fsm/report/metadata
// set behind this seam. The 5.1 minimal impl (metadataOnlyCapturer) writes
// metadata.yaml plus a placeholder marker only.
type Capturer interface {
	// Capture writes the trial's artefacts under runDir.
	Capture(ctx context.Context, runDir string) error
}

// DigestVerifier runs the fail-closed digest-verification gate (Story 5.1,
// AC3). It is invoked ONCE in main.go before the first trial, not
// per-trial (BI-2). The 5.1 minimal impl (imageDigestVerifier) checks the
// container image digest(s); the Falco-corpus / Sigma-SHA / bootstrap-SHA
// checks carry `// Story 5.x:` TODOs and are allow-listed until reachable
// (BI-6).
type DigestVerifier interface {
	// Verify checks each pinned artefact's actual digest against the
	// manifest pin and returns a clear expected-vs-actual error on ANY
	// mismatch OR any artefact whose actual digest cannot be resolved
	// (fail-closed, BI-6).
	Verify(ctx context.Context, m *Manifest) error
}

// Runner orchestrates a single trial through the five frozen seams in the
// fixed architecture-mandated order (architecture.md:712, BI-2). Stories
// 5.2-5.5 fill the seams without reshaping this loop.
type Runner struct {
	Cluster  ClusterController
	Overlay  ConfigOverlay
	Scenario Scenario
	Capturer Capturer

	// Config is the evaluation arm name (e.g. "rs") handed to
	// ConfigOverlay.Apply.
	Config string
	// Logger receives per-phase structured logs.
	Logger *slog.Logger
}

// Run drives one trial through reset -> warm -> overlay.Apply -> scenario
// -> capture -> cleanup. Cleanup is deferred so it runs even when an
// earlier phase errors (BI-2); the trial aborts on the first phase error,
// which is returned to the caller (the trial loop records it). trialDir is
// the runs/<run_id>/trial-<n>/ directory the Capturer writes into.
func (r *Runner) Run(ctx context.Context, trialDir string) (err error) {
	log := r.Logger
	if log == nil {
		log = slog.Default()
	}

	// Cleanup is the LAST phase and runs unconditionally via defer so a
	// scenario or capture failure still tears the trial down (BI-2). A
	// cleanup error does not mask an earlier phase error; it is only
	// surfaced when the trial otherwise succeeded.
	defer func() {
		if r.Cluster == nil {
			return
		}
		log.Info("eval phase: cleanup")
		if cerr := r.Cluster.Cleanup(ctx); cerr != nil {
			if err == nil {
				err = fmt.Errorf("cleanup: %w", cerr)
			} else {
				log.Error("cleanup failed after an earlier phase error", "cleanup_err", cerr, "phase_err", err)
			}
		}
	}()

	if r.Cluster != nil {
		log.Info("eval phase: reset")
		if err = r.Cluster.Reset(ctx); err != nil {
			return fmt.Errorf("reset: %w", err)
		}
		log.Info("eval phase: warm")
		if err = r.Cluster.Warm(ctx); err != nil {
			return fmt.Errorf("warm: %w", err)
		}
	}

	if r.Overlay != nil {
		log.Info("eval phase: overlay apply", "config", r.Config)
		if err = r.Overlay.Apply(ctx, r.Config); err != nil {
			return fmt.Errorf("overlay apply: %w", err)
		}
	}

	if r.Scenario != nil {
		log.Info("eval phase: scenario run")
		if err = r.Scenario.Run(ctx); err != nil {
			return fmt.Errorf("scenario run: %w", err)
		}
	}

	if r.Capturer != nil {
		log.Info("eval phase: capture", "trial_dir", trialDir)
		if err = r.Capturer.Capture(ctx, trialDir); err != nil {
			return fmt.Errorf("capture: %w", err)
		}
	}

	return nil
}

// --- MINIMAL real seam implementations for the AC5 RS path (BI-1) -------
//
// These satisfy the AC5 lightest-honest arm (S1 + RS + 1 trial reusing the
// Story-1.19 rs_smoke kind path). The RICH implementations land in
// 5.2/5.3/5.4; every placeholder method below carries a `// Story 5.x:`
// TODO naming its owning story.

// clusterController is the 5.1 minimal ClusterController. It reuses /
// assumes the Story-1.19 rs_smoke kind bring-up: the chart is already
// installed healthy under evaluation.config=RS by `make eval-smoke` (the
// e2e-local precedent), so Reset/Warm/Cleanup are no-ops at the 5.1
// foundation layer. The rich multi-arm reset is a later hardening pass.
type clusterController struct {
	logger *slog.Logger
}

func (c *clusterController) Reset(ctx context.Context) error {
	// Story 5.1 (hardening): the rich multi-arm reset (redeploy the chart
	// under the selected arm from a clean baseline) is a later hardening
	// pass. The AC5 RS path reuses the rs_smoke bring-up that `make
	// eval-smoke` installs, so the 5.1 minimal Reset is a no-op.
	return nil
}

func (c *clusterController) Warm(ctx context.Context) error {
	// Story 5.1 (hardening): full warm-up (baseline priming, source-health
	// gating) is later. The rs_smoke path primes the baseline inside the
	// scenario, so the 5.1 minimal Warm is a no-op.
	return nil
}

func (c *clusterController) Cleanup(ctx context.Context) error {
	// Story 5.1 (hardening): the rich teardown is later; CI tears the kind
	// cluster down on job end, so the 5.1 minimal Cleanup is a no-op.
	return nil
}

// The ConfigOverlay seam (runner.go interface) is filled by the Story-5.3
// real helmOverlay in overlay.go (built by newHelmOverlay): the Story-5.1
// rsOverlay log-deferral is replaced by a `helm upgrade --install --values
// values-eval-<name>.yaml --wait` apply plus an explicit `kubectl rollout
// status` aggregator Ready gate (fail-closed, BI-5).

// The Scenario seam (runner.go interface) is filled by the Story-5.2 rich
// per-scenario harness in scenario.go (scenarioHarness, built by
// newScenario). The 5.1 rsScenario no-op marker is replaced: --scenario sN
// now dispatches the matching deploy/demo/scenarios/sN-<slug>/ harness.

// The Capturer seam (runner.go interface) is filled by the Story-5.4 rich
// richCapturer adapter (capture.go), delegating to the importable
// internal/eval/capture package (BI-12). The Story-5.1 metadataOnlyCapturer
// placeholder (which wrote only a CAPTURE_PLACEHOLDER.md marker) is replaced;
// the rich Capturer drains the run's NATS subjects into the uniform
// six-artefact set under runs/<run_id>/ (events/evidence/assessments/fsm/
// report + the harness-finalised metadata.yaml). The Capturer interface
// signature is UNCHANGED (the 5.1 freeze).

// imageDigestVerifier is the 5.1 minimal DigestVerifier (AC3). It checks
// the container image digest(s) pinned in the manifest against the actual
// digest resolvable on the host (the lightest honest check). The gate is
// FAIL-CLOSED (BI-6): a mismatch OR an unresolvable digest is a REFUSE,
// not a skip, unless the artefact is on the allow-list.
//
// The Falco-corpus / Sigma-SHA / bootstrap-SHA verifications carry
// `// Story 5.x:` TODOs and are allow-listed by default until the corpora
// become harness-reachable.
type imageDigestVerifier struct {
	// allowUnverified is the set of artefact names the operator explicitly
	// allow-listed via --allow-unverified (BI-6). An allow-listed
	// artefact that cannot be verified is logged as voiding the
	// reproducibility guarantee for that artefact rather than refusing the
	// run.
	allowUnverified map[string]bool
	logger          *slog.Logger
	// resolveDigest resolves an image reference to its actual digest. It
	// is a field so tests can inject a deterministic resolver without a
	// container runtime. A nil resolver means "cannot resolve" (the
	// fail-closed default on a host with no runtime): every image is then
	// unresolvable and must be allow-listed to proceed.
	resolveDigest func(ctx context.Context, ref string) (string, error)
}

func (v *imageDigestVerifier) Verify(ctx context.Context, m *Manifest) error {
	// usedAllow tracks which --allow-unverified entries actually bypassed an
	// unverified artefact, so an entry that matched nothing (a typo, the
	// wrong case, or an artefact whose check is not yet wired) is surfaced
	// rather than silently ignored (a reproducibility footgun otherwise).
	usedAllow := make(map[string]bool, len(v.allowUnverified))
	for name, ref := range m.Images {
		expected := digestOf(ref)
		actual, err := v.resolve(ctx, ref)
		if err != nil {
			if v.allowUnverified[name] {
				usedAllow[name] = true
				v.logger.Warn("digest gate: image unverified but allow-listed; reproducibility guarantee voided for this artefact",
					"artefact", name, "ref", ref, "reason", err)
				continue
			}
			return fmt.Errorf("digest gate REFUSE: image %q (%s) actual digest unresolvable: %w (allow-list with --allow-unverified=%s to override, voiding the reproducibility guarantee)", name, ref, err, name)
		}
		if actual != expected {
			if v.allowUnverified[name] {
				usedAllow[name] = true
				v.logger.Warn("digest gate: image mismatch but allow-listed; reproducibility guarantee voided for this artefact",
					"artefact", name, "expected", expected, "actual", actual)
				continue
			}
			return fmt.Errorf("digest gate REFUSE: image %q digest mismatch: expected %s, actual %s (allow-list with --allow-unverified=%s to override, voiding the reproducibility guarantee)", name, expected, actual, name)
		}
		v.logger.Info("digest gate: image verified", "artefact", name, "digest", expected)
	}

	// Story 5.2/5.3: the Falco-corpus-tag, Sigma-corpus-SHA, and
	// cluster-bootstrap-script-SHA verifications land here as the corpora
	// become harness-reachable. Until then they are allow-listed by
	// default (the AC5 RS run must not be blocked by an unreachable
	// corpus, BI-6); each carries its owning-story TODO above.

	// Surface allow-list entries that matched nothing so a fat-fingered
	// --allow-unverified name does not silently appear to have taken effect.
	for name := range v.allowUnverified {
		if !usedAllow[name] {
			v.logger.Warn("digest gate: --allow-unverified entry matched no unverified artefact (typo, wrong case, or an artefact whose check is not yet wired)",
				"artefact", name)
		}
	}
	return nil
}

// resolve returns the actual digest of ref, or an error when it cannot be
// resolved (the fail-closed signal). A nil resolveDigest means the host
// has no container runtime wired, so every image is unresolvable.
func (v *imageDigestVerifier) resolve(ctx context.Context, ref string) (string, error) {
	if v.resolveDigest == nil {
		return "", fmt.Errorf("no digest resolver configured (no container runtime reachable)")
	}
	return v.resolveDigest(ctx, ref)
}

// digestOf returns the sha256:<hex> portion of a repo@sha256:<hex> image
// reference, or the whole string when it carries no @ separator (so a
// comparison still fails closed against a bare digest).
func digestOf(ref string) string {
	if i := strings.Index(ref, "@"); i >= 0 {
		return ref[i+1:]
	}
	return ref
}

// dockerResolveDigest resolves an image reference to its sha256 digest via
// the local container runtime (docker). It is the default resolver wired
// in main.go; on a host with no docker it returns an error, which the
// fail-closed gate treats as a REFUSE (unless allow-listed). It is small
// and side-effecting, so it lives behind the injectable resolveDigest
// field and is not unit-tested directly (the gate logic is tested with an
// injected resolver).
func dockerResolveDigest(ctx context.Context, ref string) (string, error) {
	// The manifest pins repo@sha256:<hex>; resolve the ACTUAL digest the
	// repo carries so Verify can emit the BI-6 expected-vs-actual message on
	// a real mismatch. `docker inspect` returns the repo's RepoDigests. A
	// host with no docker (CI image-load step aside) fails closed.
	//
	// Story 5.x (hardening): this inspects the local docker daemon's
	// RepoDigests for the repo, NOT the digest actually loaded into the kind
	// node; the kind-node-loaded-image check is a later hardening pass.
	repo := ref
	if i := strings.Index(ref, "@"); i >= 0 {
		repo = ref[:i]
	}
	out, err := exec.CommandContext(ctx, "docker", "image", "inspect",
		"--format", "{{range .RepoDigests}}{{println .}}{{end}}", repo).Output()
	if err != nil {
		return "", fmt.Errorf("docker image inspect %q: %w", repo, err)
	}
	return pickRepoDigest(string(out), repo, digestOf(ref))
}

// pickRepoDigest selects the digest to report from a docker `RepoDigests`
// listing. It returns an exact match when present (verified); otherwise the
// first real sha256 digest the repo carries, so Verify reports it as the
// ACTUAL against the expected pin (a genuine mismatch, not a generic
// "unresolvable"). Only when no sha256 digest is present at all is it
// unresolvable (fail-closed). It is a pure function so the selection logic
// is unit-tested without a container runtime.
func pickRepoDigest(repoDigestsOutput, repo, want string) (string, error) {
	var first string
	for _, line := range strings.Split(strings.TrimSpace(repoDigestsOutput), "\n") {
		d := digestOf(strings.TrimSpace(line))
		if !strings.HasPrefix(d, "sha256:") {
			continue
		}
		if d == want {
			return d, nil
		}
		if first == "" {
			first = d
		}
	}
	if first != "" {
		return first, nil
	}
	return "", fmt.Errorf("image %q has no resolvable repo-digest", repo)
}
