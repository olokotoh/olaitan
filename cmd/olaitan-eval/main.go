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
// separators that are unsafe in a directory name.
const runIDTimeFormat = "20060102T150405Z"

// runConfig holds the parsed CLI flags for one olaitan-eval invocation.
type runConfig struct {
	manifestPath    string
	scenario        string
	config          string
	runs            int
	out             string
	allowUnverified []string
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
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "olaitan-eval: %v\n", err)
		os.Exit(1)
	}
}

// run parses the CLI, loads + validates the manifest, computes the hash,
// runs the fail-closed digest-verification gate ONCE before the first
// trial, generates a run_id, lays out runs/<run_id>/, drives the trial
// loop, and writes the per-run metadata.yaml. It is separated from main so
// main_test.go can exercise the full dispatch with injectable
// stdout/stderr and without os.Exit.
func run(args []string, stdout, stderr io.Writer) error {
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
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return fmt.Errorf("create run dir %q: %w", runDir, err)
	}
	_, _ = fmt.Fprintf(stdout, "run_id: %s\n", runID)
	_, _ = fmt.Fprintf(stdout, "run_dir: %s\n", runDir)

	r := newRunner(cfg.config, logger)

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
	var allowRaw string
	fs.StringVar(&cfg.manifestPath, "manifest", "eval/manifest.yaml", "path to the reproducibility-envelope manifest")
	fs.StringVar(&cfg.scenario, "scenario", "", "scenario id to run (e.g. s1)")
	fs.StringVar(&cfg.config, "config", "", "evaluation configuration arm (e.g. rs, rslt-full)")
	fs.IntVar(&cfg.runs, "runs", 1, "number of trials to run")
	fs.StringVar(&cfg.out, "out", "runs", "output directory for runs/<run_id>/")
	fs.StringVar(&allowRaw, "allow-unverified", "", "comma-separated artefact names to skip in the digest gate (voids the reproducibility guarantee for each; off by default)")

	if err := fs.Parse(args); err != nil {
		return runConfig{}, err
	}

	if cfg.scenario == "" {
		return runConfig{}, fmt.Errorf("--scenario is required")
	}
	if cfg.config == "" {
		return runConfig{}, fmt.Errorf("--config is required")
	}
	if cfg.runs < 1 {
		return runConfig{}, fmt.Errorf("--runs must be >= 1 (got %d)", cfg.runs)
	}
	for _, name := range strings.Split(allowRaw, ",") {
		if n := strings.TrimSpace(name); n != "" {
			cfg.allowUnverified = append(cfg.allowUnverified, n)
		}
	}
	return cfg, nil
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

// newRunner wires the Runner with the 5.1 MINIMAL seam impls for the AC5
// RS path (BI-1). Stories 5.2-5.5 swap in the rich impls behind the same
// interfaces without touching this wiring shape.
func newRunner(config string, logger *slog.Logger) *Runner {
	return &Runner{
		Cluster:  &clusterController{logger: logger},
		Overlay:  &rsOverlay{logger: logger},
		Scenario: &rsScenario{logger: logger},
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
