// Package config loads, validates, and hot-reloads the central
// olaitan.yaml configuration. Every ring (collectors, correlator,
// analyst, decision, response, report) reads its runtime knobs through
// the Manager exposed here; rings MUST NOT construct a *Config via
// struct literals outside of tests.
//
// The split is:
//   - config.go  — types, Load, Validate, sentinel errors.
//   - watcher.go — Manager with fsnotify-backed hot-reload.
//
// Error wrapping follows the repo convention: every exported boundary
// returns errors prefixed "config:" wrapping the underlying cause.
// Logging is log/slog only, keyed on "path" and "err".
package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ErrWatcherRunning is returned by Manager.Watch when a second concurrent
// Watch is attempted on the same Manager. Start a fresh Manager (via
// NewManager) to re-watch after a previous Watch has returned.
var ErrWatcherRunning = errors.New("config: watcher already running")

// Config is the typed mirror of olaitan.yaml. Field layout mirrors
// architecture.md:417-426 (detection/response) and :806-835 (analyst).
//
// Readers obtain a *Config via Manager.Get and MUST treat it as
// immutable: slices (e.g., Response.ExcludedNamespaces) are shared by
// reference across goroutines and a mutation would race with the
// watcher swap.
type Config struct {
	Detection DetectionConfig `yaml:"detection"`
	Response  ResponseConfig  `yaml:"response"`
	Analyst   AnalystConfig   `yaml:"analyst"`
}

// DetectionConfig — see architecture.md:420 (confidence bands +
// baseline window). The bands gate the five-state pod FSM transitions;
// BaselineWindow sizes the per-workload statistical baseline.
type DetectionConfig struct {
	ConfidenceBands ConfidenceBands `yaml:"confidence_bands"`
	BaselineWindow  DurationYAML    `yaml:"baseline_window"`
}

// ConfidenceBands holds the three cumulative score thresholds that
// drive FSM transitions. Must satisfy watch < alert < act, each in
// [0,100]. Checked in Validate.
type ConfidenceBands struct {
	Watch int `yaml:"watch"`
	Alert int `yaml:"alert"`
	Act   int `yaml:"act"`
}

// ResponseConfig — see architecture.md:425 (excluded namespaces).
// Namespaces listed here are skipped by the response ring to prevent
// the agent from self-isolating or hard-killing cluster infrastructure.
type ResponseConfig struct {
	ExcludedNamespaces []string `yaml:"excluded_namespaces"`
}

// AnalystConfig — see architecture.md:806-835 (LLM analyst settings).
// Covers MVP single-analyst and Target multi-agent chain/subtasks.
type AnalystConfig struct {
	Provider string             `yaml:"provider"`
	API      AnalystAPIConfig   `yaml:"api"`
	Local    AnalystLLMEndpoint `yaml:"local"`
	ScoreCap int                `yaml:"score_cap"`
	Timeout  DurationYAML       `yaml:"timeout"`
	Chain    AnalystChain       `yaml:"chain"`
	Subtasks AnalystSubtasks    `yaml:"subtasks"`
}

// AnalystAPIConfig points at an external LLM API. APIKeySecret names a
// K8s Secret; the analyst ring (Epic 4) reads the actual value at
// runtime, the loader does not.
type AnalystAPIConfig struct {
	Endpoint     string `yaml:"endpoint"`
	Model        string `yaml:"model"`
	APIKeySecret string `yaml:"api_key_secret"`
}

// AnalystLLMEndpoint points at a local LLM endpoint (Ollama sidecar in
// the Target tier). Shared shape across chain.l1 / chain.l2 / top-level
// local — each has an endpoint + model pair with no auth.
type AnalystLLMEndpoint struct {
	Endpoint string `yaml:"endpoint"`
	Model    string `yaml:"model"`
}

// AnalystChain configures the Target-tier L1 → L2 review chain.
// Prompts are file paths relative to the repo root.
type AnalystChain struct {
	Enabled bool            `yaml:"enabled"`
	L1      AnalystChainLeg `yaml:"l1"`
	L2      AnalystChainLeg `yaml:"l2"`
}

// AnalystChainLeg is one rung of the L1/L2 chain. Model may be empty
// to inherit the top-level api.model or local.model.
type AnalystChainLeg struct {
	Prompt string `yaml:"prompt"`
	Model  string `yaml:"model"`
}

// AnalystSubtasks configures L1 sub-agent spawning (Target tier).
// SeverityThreshold in [0,100] — spawn only when the parent assessment
// clears the bar; MaxPerAssessment caps fan-out; AvailableTypes is the
// whitelist of sub-agent kinds the loader will accept.
type AnalystSubtasks struct {
	Enabled           bool         `yaml:"enabled"`
	MaxPerAssessment  int          `yaml:"max_per_assessment"`
	SeverityThreshold int          `yaml:"severity_threshold"`
	Timeout           DurationYAML `yaml:"timeout"`
	AvailableTypes    []string     `yaml:"available_types"`
}

// DurationYAML is time.Duration with a yaml.v3 UnmarshalYAML hook, so
// strings like "24h" decode natively. yaml.v3 has no built-in duration
// support; declaring the newtype here keeps struct tags declarative.
// Cast at the call site: time.Duration(cfg.Analyst.Timeout).
type DurationYAML time.Duration

// Duration returns the value as a time.Duration. Convenience accessor
// so ring code does not need to type-assert DurationYAML at every use.
func (d DurationYAML) Duration() time.Duration { return time.Duration(d) }

// UnmarshalYAML parses a YAML scalar string as a Go duration ("24h",
// "500ms", "1h30m"). Anything else — including a raw integer — is
// rejected with a wrapped error naming the offending input.
func (d *DurationYAML) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return fmt.Errorf("duration: expected string, got %s: %w", node.Tag, err)
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("duration: invalid %q: %w", s, err)
	}
	*d = DurationYAML(parsed)
	return nil
}

// Load reads, strict-YAML-decodes, and validates the file at path. The
// returned *Config is safe to share across goroutines provided callers
// respect the immutability contract documented on Config.
//
// Errors are wrapped with "config: <action> %q: %w" so callers can
// grep logs and use errors.Is for sentinels like os.ErrNotExist.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("config: open %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	cfg, err := decode(f, path)
	if err != nil {
		return nil, err
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: validate %q: %w", path, err)
	}
	return cfg, nil
}

// decode runs the strict yaml.v3 decoder against r. Split out so tests
// and hot-reload can share the same decode path without re-opening the
// file. KnownFields(true) turns typos like "confidence_band" into
// errors instead of silently defaulting the whole struct to zero.
func decode(r io.Reader, path string) (*Config, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)

	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("config: decode %q: %w", path, err)
	}
	return &cfg, nil
}

// Validate returns the first configuration error it finds, nil on
// success. Ordering is coarse-to-fine: top-level section → band
// ordering → per-field bounds. Callers either log-and-exit or
// log-and-reject, so a single error is more actionable than an
// aggregated list.
//
// Nil-safe: (*Config)(nil).Validate() returns a dedicated error
// rather than panicking, matching the other package nil-guard
// conventions in internal/nats and internal/redis.
func (c *Config) Validate() error {
	if c == nil {
		return errors.New("config: validate: nil config")
	}

	if err := c.Detection.validate(); err != nil {
		return err
	}
	if err := c.Response.validate(); err != nil {
		return err
	}
	if err := c.Analyst.validate(); err != nil {
		return err
	}
	return nil
}

func (d DetectionConfig) validate() error {
	if d.BaselineWindow.Duration() <= 0 {
		return fmt.Errorf("detection.baseline_window: must be > 0 (got %s)", d.BaselineWindow.Duration())
	}
	b := d.ConfidenceBands
	if err := bandRange("detection.confidence_bands.watch", b.Watch); err != nil {
		return err
	}
	if err := bandRange("detection.confidence_bands.alert", b.Alert); err != nil {
		return err
	}
	if err := bandRange("detection.confidence_bands.act", b.Act); err != nil {
		return err
	}
	if b.Watch >= b.Alert {
		return fmt.Errorf("detection.confidence_bands: watch(%d) must be < alert(%d)", b.Watch, b.Alert)
	}
	if b.Alert >= b.Act {
		return fmt.Errorf("detection.confidence_bands: alert(%d) must be < act(%d)", b.Alert, b.Act)
	}
	return nil
}

func (r ResponseConfig) validate() error {
	for i, ns := range r.ExcludedNamespaces {
		if ns == "" {
			return fmt.Errorf("response.excluded_namespaces[%d]: empty entry not allowed", i)
		}
		if strings.TrimSpace(ns) != ns {
			return fmt.Errorf("response.excluded_namespaces[%d]: leading/trailing whitespace in %q", i, ns)
		}
	}
	return nil
}

func (a AnalystConfig) validate() error {
	switch strings.ToLower(a.Provider) {
	case "api", "local":
	default:
		return fmt.Errorf("analyst.provider: must be one of [api local] (got %q)", a.Provider)
	}
	if a.ScoreCap < 0 || a.ScoreCap > 100 {
		return fmt.Errorf("analyst.score_cap: must be in [0,100] (got %d)", a.ScoreCap)
	}
	if a.Timeout.Duration() <= 0 {
		return fmt.Errorf("analyst.timeout: must be > 0 (got %s)", a.Timeout.Duration())
	}
	// Endpoint/model emptiness is NOT rejected here: the shipped default
	// olaitan.yaml leaves them blank for operators to fill in (AC8). The
	// analyst ring enforces non-empty endpoint at startup when it needs
	// to actually dial — config load is a parse-and-shape pass.
	if a.Chain.Enabled {
		if a.Chain.L1.Prompt == "" {
			return errors.New("analyst.chain.l1.prompt: must be set when chain.enabled=true")
		}
		if a.Chain.L2.Prompt == "" {
			return errors.New("analyst.chain.l2.prompt: must be set when chain.enabled=true")
		}
	}
	if a.Subtasks.Enabled {
		if a.Subtasks.MaxPerAssessment <= 0 {
			return fmt.Errorf("analyst.subtasks.max_per_assessment: must be > 0 (got %d)", a.Subtasks.MaxPerAssessment)
		}
		if a.Subtasks.SeverityThreshold < 0 || a.Subtasks.SeverityThreshold > 100 {
			return fmt.Errorf("analyst.subtasks.severity_threshold: must be in [0,100] (got %d)", a.Subtasks.SeverityThreshold)
		}
		if a.Subtasks.Timeout.Duration() <= 0 {
			return fmt.Errorf("analyst.subtasks.timeout: must be > 0 (got %s)", a.Subtasks.Timeout.Duration())
		}
		if len(a.Subtasks.AvailableTypes) == 0 {
			return errors.New("analyst.subtasks.available_types: must be non-empty when subtasks.enabled=true")
		}
		for i, t := range a.Subtasks.AvailableTypes {
			if t == "" || strings.TrimSpace(t) != t {
				return fmt.Errorf("analyst.subtasks.available_types[%d]: empty or padded entry %q", i, t)
			}
		}
	}
	return nil
}

func bandRange(field string, v int) error {
	if v < 0 || v > 100 {
		return fmt.Errorf("%s: must be in [0,100] (got %d)", field, v)
	}
	return nil
}
