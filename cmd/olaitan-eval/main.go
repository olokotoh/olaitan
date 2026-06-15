package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// version is stamped at build time via -ldflags "-X main.version=...". It
// is recorded in metadata.yaml as olaitan_eval_version so a run records
// which harness produced it.
var version = "dev"

// runIDTimeFormat is the sortable, compact UTC timestamp prefix of a
// run_id (OA3): RFC3339 reduced to a lexically-sortable form with no
// separators that are unsafe in a directory name. It carries millisecond
// precision so two runs of the same arm against the same manifest within
// one second get distinct run_ids rather than colliding on the same dir.
const runIDTimeFormat = "20060102T150405.000Z"

// runConfig holds the parsed CLI flags for one olaitan-eval invocation.
type runConfig struct {
	manifestPath    string
	scenario        string
	scenariosRoot   string
	config          string
	runs            int
	out             string
	allowUnverified []string
	// Story 5.3: the helmOverlay wiring threaded into newRunner (the
	// Story 5.2 --scenarios-root precedent). chartRoot / overlaysDir
	// locate the chart + the committed values-eval-<name>.yaml overlays;
	// release / namespace name the helm release + namespace the overlay
	// upgrades; overlayTimeout bounds the helm --wait + the aggregator
	// rollout-status Ready gate so a slow LLM-arm pull cannot hang forever.
	chartRoot      string
	release        string
	namespace      string
	overlaysDir    string
	overlayTimeout time.Duration
}

// metadata is the MINIMAL per-run metadata.yaml schema (BI-5, BI-8). It
// carries at least run_id, manifest_sha256, scenario, config, runs,
// started_at, finished_at, and olaitan_eval_version. The FULL schema (and
// any per-trial metadata) is OWNED and EXTENDED by Story 5.5; the field
// names here are the frozen minimal contract 5.5 builds on.
type metadata struct {
	RunID              string `yaml:"run_id"`
	ManifestSHA256     string `yaml:"manifest_sha256"`
	Scenario           string `yaml:"scenario"`
	Config             string `yaml:"config"`
	Runs               int    `yaml:"runs"`
	StartedAt          string `yaml:"started_at"`
	FinishedAt         string `yaml:"finished_at"`
	OlaitanEvalVersion string `yaml:"olaitan_eval_version"`
	// Story 5.5: the full metadata schema (per-trial results, statistical
	// fields, the analysis-pipeline inputs) extends this minimal set.
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr, execRunCmd); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "olaitan-eval: %v\n", err)
		os.Exit(1)
	}
}

// run parses the CLI, loads + validates the manifest, computes the hash,
// runs the fail-closed digest-verification gate ONCE before the first
// trial, generates a run_id, lays out runs/<run_id>/, drives the trial
// loop, and writes the per-run metadata.yaml. It is separated from main so
// main_test.go can exercise the full dispatch with injectable
// stdout/stderr and without os.Exit. runCmd is the external-command runner
// the Story-5.3 helmOverlay shells out through (main passes the real
// execRunCmd; a unit test passes a fake so the full dispatch runs without a
// cluster).
func run(args []string, stdout, stderr io.Writer, runCmd overlayRunFunc) error {
	cfg, err := parseFlags(args, stderr)
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(stderr, nil))

	m, err := LoadManifest(cfg.manifestPath)
	if err != nil {
		return err
	}
	hash := m.SHA256()
	logger.Info("manifest loaded", "path", cfg.manifestPath, "manifest_sha256", hash)

	// AC3 fail-closed digest-verification gate, ONCE before the first
	// trial (BI-2, BI-6). The 5.1 minimal verifier checks the image
	// digest; --allow-unverified entries are the documented escape hatch.
	allow := make(map[string]bool, len(cfg.allowUnverified))
	for _, name := range cfg.allowUnverified {
		allow[name] = true
	}
	verifier := newImageDigestVerifier(allow, logger)
	if err := verifier.Verify(context.Background(), m); err != nil {
		return err
	}

	startedAt := time.Now().UTC()
	runID := newRunID(startedAt, cfg.scenario, cfg.config, hash)
	runDir := filepath.Join(cfg.out, runID)
	// Refuse to clobber: if the run dir already exists and is non-empty, a
	// prior run collided here (a sub-millisecond double-invocation). Fail
	// closed rather than overwrite trial-1 and leave stale trial-N dirs from
	// the earlier run, which would produce an internally-inconsistent run.
	if err := errIfRunDirInUse(runDir); err != nil {
		return err
	}
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return fmt.Errorf("create run dir %q: %w", runDir, err)
	}
	_, _ = fmt.Fprintf(stdout, "run_id: %s\n", runID)
	_, _ = fmt.Fprintf(stdout, "run_dir: %s\n", runDir)

	// Build the rich per-scenario harness (Story 5.2) and thread it into
	// the Runner behind the frozen Scenario seam. A mis-wired scenario
	// (no harness mapping, missing/invalid target.yaml) fails the run
	// loudly here rather than silently no-opping (BI-3).
	scenario, err := newScenario(cfg.scenario, cfg.scenariosRoot, logger)
	if err != nil {
		return err
	}
	// Story 5.3: build the real helmOverlay from the threaded overlay flags
	// (the Story 5.2 --scenarios-root precedent) and wire it behind the
	// frozen ConfigOverlay seam.
	oc := overlayConfig{
		chartRoot:   cfg.chartRoot,
		release:     cfg.release,
		namespace:   cfg.namespace,
		overlaysDir: cfg.overlaysDir,
		timeout:     cfg.overlayTimeout,
	}
	r := newRunner(cfg.config, scenario, oc, runCmd, logger)

	// The N-trial loop (AC4). Each trial writes runs/<run_id>/trial-<n>/.
	// A trial error aborts that trial and is recorded; the run continues
	// to the metadata write so a partial run is still reproducible-from.
	var firstErr error
	for trial := 1; trial <= cfg.runs; trial++ {
		trialDir := filepath.Join(runDir, fmt.Sprintf("trial-%d", trial))
		logger.Info("trial start", "trial", trial, "of", cfg.runs, "dir", trialDir)
		if err := r.Run(context.Background(), trialDir); err != nil {
			logger.Error("trial failed", "trial", trial, "err", err)
			if firstErr == nil {
				firstErr = fmt.Errorf("trial %d: %w", trial, err)
			}
		}
	}

	finishedAt := time.Now().UTC()
	md := metadata{
		RunID:              runID,
		ManifestSHA256:     hash,
		Scenario:           cfg.scenario,
		Config:             cfg.config,
		Runs:               cfg.runs,
		StartedAt:          startedAt.Format(time.RFC3339),
		FinishedAt:         finishedAt.Format(time.RFC3339),
		OlaitanEvalVersion: version,
	}
	if err := writeMetadata(runDir, md); err != nil {
		return err
	}
	logger.Info("run complete", "run_id", runID, "metadata", filepath.Join(runDir, "metadata.yaml"))

	return firstErr
}

// parseFlags parses the olaitan-eval CLI surface (AC4). --manifest defaults
// to eval/manifest.yaml, --runs defaults to 1, --out defaults to runs/.
// --allow-unverified is repeatable (comma-separated or repeated flag).
func parseFlags(args []string, stderr io.Writer) (runConfig, error) {
	fs := flag.NewFlagSet("olaitan-eval", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var cfg runConfig
	var allow stringSliceFlag
	fs.StringVar(&cfg.manifestPath, "manifest", "eval/manifest.yaml", "path to the reproducibility-envelope manifest")
	fs.StringVar(&cfg.scenario, "scenario", "", "scenario id to run (s1..s5)")
	fs.StringVar(&cfg.scenariosRoot, "scenarios-root", defaultScenariosRoot, "root directory holding the sN-<slug>/ attack-scenario harnesses (Story 5.2)")
	fs.StringVar(&cfg.config, "config", "", "evaluation configuration arm (f, rs, rsl, rslt, rslt-full, or an rslt-<ablation>)")
	fs.IntVar(&cfg.runs, "runs", 1, "number of trials to run")
	fs.StringVar(&cfg.out, "out", "runs", "output directory for runs/<run_id>/")
	fs.Var(&allow, "allow-unverified", "artefact names to skip in the digest gate (comma-separated or repeated; voids the reproducibility guarantee for each; off by default)")
	// Story 5.3: the ConfigOverlay (helmOverlay) wiring (BI-5). Defaults
	// match the in-repo chart layout + the canonical olaitan release.
	defOverlay := defaultOverlayConfig()
	fs.StringVar(&cfg.chartRoot, "chart-root", defOverlay.chartRoot, "path to the Helm chart the ConfigOverlay upgrades")
	fs.StringVar(&cfg.release, "release", defOverlay.release, "Helm release name the ConfigOverlay upgrades")
	fs.StringVar(&cfg.namespace, "namespace", defOverlay.namespace, "Kubernetes namespace the ConfigOverlay upgrades into")
	fs.StringVar(&cfg.overlaysDir, "overlays-dir", defOverlay.overlaysDir, "directory holding the values-eval-<name>.yaml configuration overlays")
	fs.DurationVar(&cfg.overlayTimeout, "overlay-timeout", defOverlay.timeout, "budget for the helm --wait + the aggregator rollout-status Ready gate")

	if err := fs.Parse(args); err != nil {
		return runConfig{}, err
	}

	if cfg.scenario == "" {
		return runConfig{}, fmt.Errorf("--scenario is required")
	}
	if err := validateScenario(cfg.scenario); err != nil {
		return runConfig{}, err
	}
	if cfg.config == "" {
		return runConfig{}, fmt.Errorf("--config is required")
	}
	// Normalise the arm name ONCE at parse time (case-insensitive +
	// the canonical "+" -> "-" rewrite) so every downstream consumer
	// (validateConfig, the helmOverlay overlayFileFor lookup, the run_id,
	// and metadata.config) sees the single canonical-lowercase form. A user
	// is free to pass any of the documented spellings -- the canonical
	// chart enum `RSLT-L1+L2`, lower `rslt-l1+l2`, the already-normalised
	// `rslt-l1-l2`, `RSLT-full`, `RS`, ... -- and they all resolve to the
	// right overlay; genuinely unknown arms still fail fast below.
	cfg.config = normalizeArm(cfg.config)
	if err := validateConfig(cfg.config); err != nil {
		return runConfig{}, err
	}
	if cfg.runs < 1 {
		return runConfig{}, fmt.Errorf("--runs must be >= 1 (got %d)", cfg.runs)
	}
	if cfg.overlayTimeout <= 0 {
		return runConfig{}, fmt.Errorf("--overlay-timeout must be > 0 (got %s)", cfg.overlayTimeout)
	}
	// Reject an explicitly-emptied overlay flag (all have safe defaults, so
	// an empty value means the user blanked it on purpose). Fail fast here
	// with a readable message rather than shelling out helm/kubectl with an
	// empty --release / --namespace (which also makes aggregatorDeployName
	// emit a bogus `-olaitan-aggregator` rollout-status target) or an empty
	// --chart-root / --overlays-dir (which dials helm at the wrong path).
	for _, e := range []struct {
		flag, val string
	}{
		{"--release", cfg.release},
		{"--namespace", cfg.namespace},
		{"--chart-root", cfg.chartRoot},
		{"--overlays-dir", cfg.overlaysDir},
	} {
		if strings.TrimSpace(e.val) == "" {
			return runConfig{}, fmt.Errorf("%s must not be empty", e.flag)
		}
	}
	cfg.allowUnverified = []string(allow)
	return cfg, nil
}

// stringSliceFlag is a repeatable, comma-splitting flag.Value. It accepts
// both `--allow-unverified a,b` and `--allow-unverified a --allow-unverified
// b`, accumulating the trimmed, non-empty entries (so the documented
// comma-separated AND repeated-flag forms both work, not just the last one).
type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return strings.Join(*s, ",") }

func (s *stringSliceFlag) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			*s = append(*s, p)
		}
	}
	return nil
}

// validateScenario rejects an unknown --scenario so a typo does not produce
// an official-looking but meaningless run (the five MITRE scenarios S1-S5
// are fixed by FR53/the rule corpus).
func validateScenario(s string) error {
	switch s {
	case "s1", "s2", "s3", "s4", "s5":
		return nil
	}
	return fmt.Errorf("--scenario %q is not a known scenario (want one of s1, s2, s3, s4, s5)", s)
}

// normalizeArm canonicalises a user-supplied --config arm to the single
// lowercase, "+"-free form the harness keys everything off (BI-1). The
// chart's canonical enum for the last ablation arm is `RSLT-L1+L2` (the
// "+" kept in the IN-FILE evaluation.config so the chart validator +
// effective-value helpers fire), but the harness's arm keys, overlay
// filenames, and run_id segment all use the normalised `rslt-l1-l2`. So a
// user passing the documented canonical/mixed-case spelling
// ({RSLT-L1+L2, rslt-l1+l2, RSLT-full, RS, ...}) maps to the right arm
// rather than being rejected. It only lowercases and rewrites "+" -> "-";
// it never invents an arm, so genuinely unknown arms still fail
// validateConfig below.
func normalizeArm(c string) string {
	return strings.ReplaceAll(strings.ToLower(c), "+", "-")
}

// validateConfig rejects an unknown --config arm so a typo (e.g. "rls" for
// "rsl") does not silently no-op into a meaningless run. Story 5.3 (BI-4)
// tightens this to EXACTLY the six arms that have a committed
// values-eval-<name>.yaml overlay: the FR53 four-way matrix (f, rs, rsl,
// rslt/rslt-full -- the legacy "rslt" alias collapses to the same overlay)
// plus the two RSLT ablation arms (rslt-l1-only, rslt-l1-l2). The input is
// the already-normalised arm (normalizeArm lowercases + rewrites "+" -> "-"
// at parse time), so the canonical chart enum `RSLT-L1+L2` resolves here as
// `rslt-l1-l2`. The open "rslt-" prefix Story 5.1 accepted as a
// forward-compat placeholder is gone: an unknown arm (e.g. "rslt-bogus")
// now fails fast at flag-parse rather than dispatching into a missing
// overlay file. The keys here MUST stay in lock-step with overlayFiles
// (overlay.go), the config -> overlay-file map the helmOverlay resolves.
func validateConfig(c string) error {
	switch normalizeArm(c) {
	case "f", "rs", "rsl", "rslt", "rslt-full", "rslt-l1-only", "rslt-l1-l2":
		return nil
	}
	return fmt.Errorf("--config %q is not a known evaluation arm (want one of f, rs, rsl, rslt, rslt-full, rslt-l1-only, rslt-l1+l2)", c)
}

// errIfRunDirInUse returns an error when runDir already exists and is
// non-empty (a run_id collision), so the harness fails closed rather than
// clobbering a prior run's trials. A missing or empty dir is free to use.
func errIfRunDirInUse(runDir string) error {
	entries, err := os.ReadDir(runDir)
	if err != nil {
		return nil // missing dir (or unreadable) is handled by MkdirAll next
	}
	if len(entries) > 0 {
		return fmt.Errorf("run dir %q already exists and is non-empty (run_id collision); refusing to clobber a prior run", runDir)
	}
	return nil
}

// newRunID builds the sortable, collision-resistant run_id (OA3):
// <UTC-compact-timestamp>-<scenario>-<config>-<short-manifest-hash>. The
// timestamp leads so a lexical sort is a chronological sort; the short
// hash makes two same-second runs of the same arm against the same
// manifest collide only when the manifest is byte-identical (in which case
// they ARE the same envelope, the intended reproducibility property).
func newRunID(at time.Time, scenario, config, manifestHash string) string {
	short := manifestHash
	if len(short) > 12 {
		short = short[:12]
	}
	return fmt.Sprintf("%s-%s-%s-%s", at.Format(runIDTimeFormat), scenario, config, short)
}

// newRunner wires the Runner with the seam impls for the configured arm. The
// Scenario seam is filled by the Story-5.2 rich per-scenario harness
// (threaded in from run() via newScenario) and the ConfigOverlay seam is now
// filled by the Story-5.3 real helmOverlay (built from the threaded overlay
// flags + the injected command runner, replacing the 5.1 rsOverlay
// log-deferral); the Cluster / Capturer seams keep their 5.1 minimal impls
// (Story 5.4 swaps in the rich Capturer behind the same interface). The
// Runner loop shape is unchanged (the 5.1 freeze).
func newRunner(config string, scenario Scenario, oc overlayConfig, runCmd overlayRunFunc, logger *slog.Logger) *Runner {
	return &Runner{
		Cluster:  &clusterController{logger: logger},
		Overlay:  newHelmOverlay(oc, runCmd, logger),
		Scenario: scenario,
		Capturer: &metadataOnlyCapturer{logger: logger},
		Config:   config,
		Logger:   logger,
	}
}

// newImageDigestVerifier wires the 5.1 minimal DigestVerifier with the
// default docker-backed resolver (AC3). The resolver is fail-closed: a
// host with no docker resolves nothing, so every image must be
// allow-listed to proceed.
func newImageDigestVerifier(allow map[string]bool, logger *slog.Logger) *imageDigestVerifier {
	return &imageDigestVerifier{
		allowUnverified: allow,
		logger:          logger,
		resolveDigest:   dockerResolveDigest,
	}
}

// writeMetadata marshals the minimal metadata.yaml into the run dir (AC3,
// BI-5). The manifest_sha256 field is the BI-5 carrier Story 5.5 consumes.
func writeMetadata(runDir string, md metadata) error {
	b, err := yaml.Marshal(md)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	path := filepath.Join(runDir, "metadata.yaml")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return fmt.Errorf("write metadata %q: %w", path, err)
	}
	return nil
}
