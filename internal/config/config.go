// Package config loads, validates, and hot-reloads the central
// olaitan.yaml configuration. Every ring (collectors, correlator,
// analyst, decision, response, report) reads its runtime knobs through
// the Manager exposed here; rings MUST NOT construct a *Config via
// struct literals outside of tests.
//
// The split is:
//   - config.go  -- types, Load, Validate, sentinel errors.
//   - watcher.go -- Manager with fsnotify-backed hot-reload.
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
	"path/filepath"
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
	// Metrics configures the Story 1.12 Prometheus surface. Omission
	// substitutes the package default (":9090") at Load time; explicit
	// empty Address is rejected by Validate per guardrail 27 (the FR50
	// surface is mandatory, not optional).
	Metrics MetricsConfig `yaml:"metrics,omitempty"`
	// RateLimit configures the Story 1.13 per-source per-node
	// circuit breaker (FR51 sensing half; NFR22). Omission of the
	// block at Load time leaves the four defaults in force (enabled
	// true, 1000 events/sec threshold, 60s cooldown, 0.1 sampling
	// rate) so a chart deploy that has not yet adopted the block
	// inherits production behaviour.
	RateLimit RateLimitConfig `yaml:"rate_limit,omitempty"`
}

// MetricsConfig configures the Story 1.12 Prometheus surface bound at
// :9090/metrics on every Olaitan ring (collector DaemonSet and
// aggregator Deployment). Address follows net.Listen conventions
// (":9090" for all interfaces, "127.0.0.1:9090" for localhost-only,
// ":0" for the OS-assigned free port used in integration tests).
type MetricsConfig struct {
	Address string `yaml:"address,omitempty"`
}

// DefaultMetricsAddress is the Helm-aligned default. Load substitutes
// this when the operator omits the metrics block; Validate rejects an
// explicit empty Address so a typo cannot silently disable the
// surface.
const DefaultMetricsAddress = ":9090"

// RateLimitConfig configures the Story 1.13 per-source per-node
// circuit breaker. The four knobs are Helm-tunable per AC4 and
// hot-reload via the config.Manager.Subscribe callback wired by
// cmd/olaitan/main.go.
//
// Field semantics:
//
//   - Enabled toggles the breaker cluster-wide. When false the
//     per-adapter limiter short-circuits in Allow and the engagement
//     counter never advances.
//   - ThresholdEventsPerSec is the strict-greater-than threshold for
//     engagement. NFR22 / PRD line 439 default is 1000.
//   - CooldownSeconds is the contiguous below-threshold duration
//     required for disengagement. PRD line 439 default is 60.
//   - SamplingRate is the fraction in (0, 1] of events that survive
//     the sampling roll while engaged. PRD line 439 default is 0.1.
type RateLimitConfig struct {
	Enabled               *bool   `yaml:"enabled,omitempty"`
	ThresholdEventsPerSec int     `yaml:"threshold_events_per_sec,omitempty"`
	CooldownSeconds       int     `yaml:"cooldown_seconds,omitempty"`
	SamplingRate          float64 `yaml:"sampling_rate,omitempty"`

	thresholdSet bool
	cooldownSet  bool
	samplingSet  bool
}

// UnmarshalYAML tracks whether scalar knobs were omitted or explicitly
// set to zero. yaml's omitempty-shaped int/float fields otherwise
// collapse both cases to the Go zero value, which would make Load
// silently replace an operator's invalid zero with the production
// default instead of rejecting it.
func (r *RateLimitConfig) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("rate_limit: expected mapping, got %s", node.ShortTag())
	}
	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i].Value
		val := node.Content[i+1]
		switch key {
		case "enabled":
			var v bool
			if err := val.Decode(&v); err != nil {
				return fmt.Errorf("rate_limit.enabled: %w", err)
			}
			r.Enabled = &v
		case "threshold_events_per_sec":
			var v int
			if err := val.Decode(&v); err != nil {
				return fmt.Errorf("rate_limit.threshold_events_per_sec: %w", err)
			}
			r.ThresholdEventsPerSec = v
			r.thresholdSet = true
		case "cooldown_seconds":
			var v int
			if err := val.Decode(&v); err != nil {
				return fmt.Errorf("rate_limit.cooldown_seconds: %w", err)
			}
			r.CooldownSeconds = v
			r.cooldownSet = true
		case "sampling_rate":
			var v float64
			if err := val.Decode(&v); err != nil {
				return fmt.Errorf("rate_limit.sampling_rate: %w", err)
			}
			r.SamplingRate = v
			r.samplingSet = true
		default:
			return fmt.Errorf("field %s not found in type config.RateLimitConfig", key)
		}
	}
	return nil
}

// DefaultRateLimit returns the production defaults for the four rate
// limit knobs. Load substitutes these when the corresponding YAML field
// is omitted. The enabled toggle defaults to true: a chart deploy that has
// not yet adopted the rateLimit block inherits production backpressure
// rather than silently disabling the breaker.
func DefaultRateLimit() RateLimitConfig {
	t := true
	return RateLimitConfig{
		Enabled:               &t,
		ThresholdEventsPerSec: 1000,
		CooldownSeconds:       60,
		SamplingRate:          0.1,
	}
}

// EnabledOrDefault reports the effective enabled state, treating a nil
// pointer as "use the default" (true). Callers in main.go consult this
// when building the ratelimit.Options.
func (r RateLimitConfig) EnabledOrDefault() bool {
	if r.Enabled == nil {
		return true
	}
	return *r.Enabled
}

// validate enforces RateLimitConfig invariants. The four knobs default
// at Load when omitted; Validate rejects out-of-range values so a
// chart deploy with `--set rateLimit.threshold_events_per_sec=-1`
// crash-loops loudly rather than silently disabling the breaker.
func (r RateLimitConfig) validate() error {
	if !r.EnabledOrDefault() {
		// When disabled the other knobs are ignored at runtime; do not
		// reject negative thresholds in this case, but do reject
		// obviously broken sampling rates so a future re-enable does
		// not pick up an invalid value silently.
		if r.SamplingRate < 0 || r.SamplingRate > 1 {
			return fmt.Errorf("rate_limit.sampling_rate: must be in [0, 1] (got %v)", r.SamplingRate)
		}
		return nil
	}
	if r.ThresholdEventsPerSec < 1 {
		return fmt.Errorf("rate_limit.threshold_events_per_sec: must be >= 1 when enabled=true (got %d)", r.ThresholdEventsPerSec)
	}
	if r.CooldownSeconds < 1 {
		return fmt.Errorf("rate_limit.cooldown_seconds: must be >= 1 when enabled=true (got %d)", r.CooldownSeconds)
	}
	if r.SamplingRate <= 0 || r.SamplingRate > 1 {
		return fmt.Errorf("rate_limit.sampling_rate: must be in (0, 1] when enabled=true (got %v)", r.SamplingRate)
	}
	return nil
}

// DetectionConfig -- see architecture.md:420 (confidence bands +
// baseline window). The bands gate the five-state pod FSM transitions;
// BaselineWindow sizes the per-workload statistical baseline.
//
// Sources extends the detection plane with per-source adapter configs.
// Story 1.7 introduces the audit-webhook source. Future Stories
// 1.8-1.10 will add containerd CRI, application log, and Calico CNI
// flow sources under the same parent. The block is omitempty: clusters
// running only the Falco adapter (Story 1.6) need not declare it.
type DetectionConfig struct {
	ConfidenceBands ConfidenceBands  `yaml:"confidence_bands"`
	BaselineWindow  DurationYAML     `yaml:"baseline_window"`
	Correlator      CorrelatorConfig `yaml:"correlator,omitempty"`
	Sources         SourcesConfig    `yaml:"sources,omitempty"`
	// Story 1.11: posture sub-block configures the read-on-demand
	// workload posture client (FR7). architecture.md:324 pins the
	// 60s cache TTL ceiling; validate enforces it.
	Posture PostureConfig `yaml:"posture,omitempty"`
	// Story 1.15: rules sub-block configures the OLT Sigma rule
	// engine (FR15, FR49). Enabled is a pointer so the loader can
	// distinguish "operator omitted enabled, default to true" from
	// "operator explicitly set false" per the Story 1.14 D2 pattern.
	Rules RulesConfig `yaml:"rules,omitempty"`
	// Story 1.17: baselines sub-block configures the Welford
	// baseline engine (FR16/FR17/FR18). Mirrors the Story 1.15
	// RulesConfig pattern: Enabled and SigmaMultiplier are pointers
	// so the loader can distinguish operator omission from explicit
	// zero/false.
	Baselines BaselinesConfig `yaml:"baselines,omitempty"`
}

// CorrelatorConfig controls the Story 1.14 Ring-2 sliding-window
// correlator and EvidencePackage assembler.
//
// The three int knobs are pointers so the YAML loader can
// distinguish "operator omitted the field, substitute the default"
// from "operator set 0 explicitly". Without that distinction, an
// operator who writes `high_severity_threshold: 0` would have their
// explicit value silently replaced by the default 50; with pointers,
// the explicit 0 reaches validate() and either passes (0 is in the
// permitted range for high_severity_threshold) or is rejected
// (max_package_bytes=0 fails the "must be 131072" guard). The
// UnmarshalYAML hook below tracks which fields were present in the
// source YAML.
type CorrelatorConfig struct {
	WindowDuration        DurationYAML `yaml:"window_duration,omitempty"`
	MaxPackageBytes       *int         `yaml:"max_package_bytes,omitempty"`
	MultiSignalMinSources *int         `yaml:"multi_signal_min_sources,omitempty"`
	HighSeverityThreshold *int         `yaml:"high_severity_threshold,omitempty"`
}

// DefaultCorrelator returns Story 1.14's production defaults.
func DefaultCorrelator() CorrelatorConfig {
	return CorrelatorConfig{
		WindowDuration:        DurationYAML(60 * time.Second),
		MaxPackageBytes:       intPtr(128 * 1024),
		MultiSignalMinSources: intPtr(2),
		HighSeverityThreshold: intPtr(50),
	}
}

func intPtr(v int) *int { return &v }

// MaxPackageBytesOrDefault returns the effective max-package byte cap,
// substituting the production default when the operator omitted the
// field. Callers in cmd/olaitan/main.go consult this when constructing
// the assembler so the dereference site cannot panic on a nil pointer.
func (c CorrelatorConfig) MaxPackageBytesOrDefault() int {
	if c.MaxPackageBytes == nil {
		return 128 * 1024
	}
	return *c.MaxPackageBytes
}

// MultiSignalMinSourcesOrDefault returns the effective multi-signal
// threshold, substituting the default when omitted.
func (c CorrelatorConfig) MultiSignalMinSourcesOrDefault() int {
	if c.MultiSignalMinSources == nil {
		return 2
	}
	return *c.MultiSignalMinSources
}

// HighSeverityThresholdOrDefault returns the effective severity
// threshold, substituting the default when omitted.
func (c CorrelatorConfig) HighSeverityThresholdOrDefault() int {
	if c.HighSeverityThreshold == nil {
		return 50
	}
	return *c.HighSeverityThreshold
}

func (c CorrelatorConfig) validate() error {
	if c.WindowDuration.Duration() <= 0 {
		return fmt.Errorf("detection.correlator.window_duration: must be > 0 (got %s)", c.WindowDuration.Duration())
	}
	if c.MaxPackageBytes != nil && *c.MaxPackageBytes != 128*1024 {
		return fmt.Errorf("detection.correlator.max_package_bytes: must be 131072 bytes for Story 1.14 wire cap (got %d)", *c.MaxPackageBytes)
	}
	if c.MultiSignalMinSources != nil && *c.MultiSignalMinSources < 2 {
		return fmt.Errorf("detection.correlator.multi_signal_min_sources: must be >= 2 (got %d)", *c.MultiSignalMinSources)
	}
	if c.HighSeverityThreshold != nil {
		v := *c.HighSeverityThreshold
		if v < 0 || v > 100 {
			return fmt.Errorf("detection.correlator.high_severity_threshold: must be in [0,100] (got %d)", v)
		}
	}
	return nil
}

// PostureConfig configures the Story 1.11 read-on-demand workload
// posture client. When Enabled is true the aggregator constructs a
// posture.Client and exposes its cache-hit counter; when false the
// block may stay zero-valued and downstream callers receive a
// degraded Unavailable=true posture for every query.
type PostureConfig struct {
	Enabled      bool         `yaml:"enabled"`
	CacheTTL     DurationYAML `yaml:"cache_ttl,omitempty"`
	FetchTimeout DurationYAML `yaml:"fetch_timeout,omitempty"`
}

// validate enforces PostureConfig invariants. A zero block is allowed
// when Enabled is false; with Enabled=true CacheTTL and FetchTimeout
// must be non-negative (a zero value means "use the package default":
// 60s for CacheTTL and 5s for FetchTimeout, both applied downstream
// in startAggregatorRing). CacheTTL is bounded above by 60s per
// architecture.md:324 and Story 1.11 AC3 ("no greater than 60 seconds").
func (p PostureConfig) validate() error {
	if !p.Enabled {
		return nil
	}
	if p.CacheTTL.Duration() < 0 {
		return fmt.Errorf("detection.posture.cache_ttl: must be >= 0 (0 means default; got %s)", p.CacheTTL.Duration())
	}
	if p.CacheTTL.Duration() > 60*time.Second {
		return fmt.Errorf("detection.posture.cache_ttl: must be <= 60s per architecture.md:324 + Story 1.11 AC3 (got %s)", p.CacheTTL.Duration())
	}
	if p.FetchTimeout.Duration() < 0 {
		return fmt.Errorf("detection.posture.fetch_timeout: must be >= 0 (0 means default; got %s)", p.FetchTimeout.Duration())
	}
	return nil
}

// RulesConfig configures the Story 1.15 OLT Sigma rule engine.
//
// Enabled is a pointer (per the Story 1.14 D2 pointer-field
// precedent) so the loader distinguishes "operator omitted the
// field, default to enabled=true" from "operator explicitly set
// false". A sensing-only mode disables the engine entirely; the
// JetStream consumer olaitan-rules-engine is not created in that
// case and startAggregatorRing skips the engine goroutine.
//
// Path is the absolute directory the rule loader watches; it must
// match the aggregator Deployment's ConfigMap volumeMount. The
// engine's fsnotify watcher handles ConfigMap projected-volume
// swaps, so changing the ConfigMap contents reloads the rule
// corpus without restarting the controller. Changing Path itself
// goes through the config.Manager.Subscribe hot-reload callback
// and re-instantiates the loader (operationally rare).
type RulesConfig struct {
	Enabled *bool  `yaml:"enabled,omitempty"`
	Path    string `yaml:"path,omitempty"`
}

// DefaultRules returns the Story 1.15 production defaults: engine
// enabled, rule corpus mounted at the canonical /etc/olaitan/rules.
func DefaultRules() RulesConfig {
	t := true
	return RulesConfig{
		Enabled: &t,
		Path:    "/etc/olaitan/rules",
	}
}

// EnabledOrDefault reports the effective enabled state, treating a
// nil pointer as the default (true) per RateLimitConfig precedent.
func (r RulesConfig) EnabledOrDefault() bool {
	if r.Enabled == nil {
		return true
	}
	return *r.Enabled
}

// validate enforces RulesConfig invariants. When enabled=true the
// path must be non-empty and absolute. When enabled=false the block
// may stay zero-valued; the engine is not constructed and the path
// is unused. A nil Enabled pointer means the operator did not
// declare the block and Load did not run (e.g. an in-memory Config
// constructed by tests); skip validation in that case so tests can
// build a minimal valid Config without populating every sub-block.
// startAggregatorRing layers a defensive Path-non-empty check at
// engine-construction time (cmd/olaitan/main.go:startAggregatorRing)
// to catch the rare bypass case (code-review P22 defense in depth).
func (r RulesConfig) validate() error {
	if r.Enabled == nil {
		return nil
	}
	if !*r.Enabled {
		return nil
	}
	if r.Path == "" {
		return errors.New("detection.rules.path: required when rules.enabled=true")
	}
	if !filepath.IsAbs(r.Path) {
		return fmt.Errorf("detection.rules.path: must be an absolute path (got %q)", r.Path)
	}
	return nil
}

// BaselinesConfig configures the Story 1.17 Welford baseline engine.
//
// Enabled is a pointer (Story 1.14 D2 / Story 1.15 RulesConfig
// precedent) so the loader distinguishes "operator omitted, default
// to enabled=true" from "operator explicitly set false". Sensing-only
// mode disables the engine entirely; the JetStream consumer
// olaitan-baseline-engine is not created in that case and
// startAggregatorRing skips the engine goroutine.
//
// WarmupDuration and SigmaMultiplier are hot-reloadable via the
// config.Manager.Subscribe callback because they are pure in-process
// state with no Deployment-spec dependency. Enabled and RedisAddr are
// restart-required by design: toggling the engine or its Redis target
// rewires the aggregator ring.
type BaselinesConfig struct {
	Enabled         *bool        `yaml:"enabled,omitempty"`
	WarmupDuration  DurationYAML `yaml:"warmup_duration,omitempty"`
	SigmaMultiplier *float64     `yaml:"sigma_multiplier,omitempty"`
	RedisAddr       string       `yaml:"redis_addr,omitempty"`
}

// DefaultBaselines returns the Story 1.17 production defaults:
// engine enabled, 30-minute warm-up, 3-sigma threshold, Redis at the
// canonical "redis:6379" address.
func DefaultBaselines() BaselinesConfig {
	t := true
	s := 3.0
	return BaselinesConfig{
		Enabled:         &t,
		WarmupDuration:  DurationYAML(30 * time.Minute),
		SigmaMultiplier: &s,
		RedisAddr:       "redis:6379",
	}
}

// EnabledOrDefault reports the effective enabled state, treating a
// nil pointer as the default (true) per RulesConfig precedent.
func (b BaselinesConfig) EnabledOrDefault() bool {
	if b.Enabled == nil {
		return true
	}
	return *b.Enabled
}

// WarmupDurationOrDefault returns the effective warm-up window,
// substituting the 30-minute default when omitted.
func (b BaselinesConfig) WarmupDurationOrDefault() time.Duration {
	if b.WarmupDuration.Duration() > 0 {
		return b.WarmupDuration.Duration()
	}
	return 30 * time.Minute
}

// SigmaMultiplierOrDefault returns the effective sigma threshold,
// substituting the default 3.0 when omitted.
func (b BaselinesConfig) SigmaMultiplierOrDefault() float64 {
	if b.SigmaMultiplier == nil {
		return 3.0
	}
	return *b.SigmaMultiplier
}

// validate enforces BaselinesConfig invariants. When Enabled is nil
// (operator did not declare the block) validation is skipped so
// in-memory test fixtures can omit it. When Enabled=false the block
// may stay zero-valued. When Enabled=true the WarmupDuration must be
// positive, SigmaMultiplier must be positive, and RedisAddr must be
// non-empty.
func (b BaselinesConfig) validate() error {
	if b.Enabled == nil {
		return nil
	}
	if !*b.Enabled {
		return nil
	}
	if b.WarmupDuration.Duration() <= 0 {
		return fmt.Errorf("detection.baselines.warmup_duration: must be > 0 when baselines.enabled=true (got %s)", b.WarmupDuration.Duration())
	}
	if b.SigmaMultiplier == nil {
		return errors.New("detection.baselines.sigma_multiplier: required when baselines.enabled=true")
	}
	if *b.SigmaMultiplier <= 0 {
		return fmt.Errorf("detection.baselines.sigma_multiplier: must be > 0 (got %v)", *b.SigmaMultiplier)
	}
	if b.RedisAddr == "" {
		return errors.New("detection.baselines.redis_addr: required when baselines.enabled=true")
	}
	return nil
}

// SourcesConfig groups per-source adapter configuration. Each entry is
// optional; omission leaves the source's adapter disabled.
type SourcesConfig struct {
	Audit      AuditSourceConfig      `yaml:"audit,omitempty"`
	Containerd ContainerdSourceConfig `yaml:"containerd,omitempty"`
	Calico     CalicoSourceConfig     `yaml:"calico,omitempty"`
}

// AuditSourceConfig configures the Story 1.7 Kubernetes audit-webhook
// receiver. When Enabled is true the collector subcommand spawns the
// receiver goroutine and the config validator enforces non-empty TLS
// material. When Enabled is false the block may stay zero-valued; the
// adapter is not constructed.
type AuditSourceConfig struct {
	Enabled          bool                `yaml:"enabled"`
	ListenAddr       string              `yaml:"listen_addr,omitempty"`
	TLSCertFile      string              `yaml:"tls_cert_file,omitempty"`
	TLSKeyFile       string              `yaml:"tls_key_file,omitempty"`
	ClientCAFile     string              `yaml:"client_ca_file,omitempty"`
	MaxPayloadBytes  int64               `yaml:"max_payload_bytes,omitempty"`
	StalenessTimeout DurationYAML        `yaml:"staleness_timeout,omitempty"`
	PublishRetry     RetryStrategyConfig `yaml:"publish_retry,omitempty"`
}

// ContainerdSourceConfig configures the Story 1.8 containerd CRI
// lifecycle adapter. When Enabled is true the collector subcommand
// spawns the adapter goroutine and the config validator enforces a
// non-empty SocketPath. When Enabled is false the block may stay
// zero-valued; the adapter is not constructed.
type ContainerdSourceConfig struct {
	Enabled          bool                `yaml:"enabled"`
	SocketPath       string              `yaml:"socket_path,omitempty"`
	DialTimeout      DurationYAML        `yaml:"dial_timeout,omitempty"`
	StalenessTimeout DurationYAML        `yaml:"staleness_timeout,omitempty"`
	ConnectRetry     RetryStrategyConfig `yaml:"connect_retry,omitempty"`
	PublishRetry     RetryStrategyConfig `yaml:"publish_retry,omitempty"`
}

// validate enforces ContainerdSourceConfig invariants. Mirrors the
// AuditSourceConfig pattern: zero block is allowed when Enabled is
// false; partial retry blocks are rejected here rather than left to
// crashloop the adapter at runtime.
func (c ContainerdSourceConfig) validate() error {
	if !c.Enabled {
		return nil
	}
	if c.SocketPath == "" {
		return errors.New("detection.sources.containerd.socket_path: required when enabled=true")
	}
	if c.DialTimeout.Duration() < 0 {
		return fmt.Errorf("detection.sources.containerd.dial_timeout: must be >= 0 (0 means default; got %s)", c.DialTimeout.Duration())
	}
	if c.StalenessTimeout.Duration() < 0 {
		return fmt.Errorf("detection.sources.containerd.staleness_timeout: must be >= 0 (0 means default; got %s)", c.StalenessTimeout.Duration())
	}
	if err := c.ConnectRetry.validatePartial("detection.sources.containerd.connect_retry"); err != nil {
		return err
	}
	if err := c.PublishRetry.validatePartial("detection.sources.containerd.publish_retry"); err != nil {
		return err
	}
	return nil
}

// CalicoSourceConfig configures the Story 1.10 Calico CNI flow
// adapter. When Enabled is true the collector subcommand spawns the
// adapter goroutine and the config validator enforces a non-empty
// Goldmane address plus the three TLS file paths (Goldmane enforces
// mTLS; see ADR-2026-04-30-01). When Enabled is false the block may
// stay zero-valued; the adapter is not constructed.
type CalicoSourceConfig struct {
	Enabled          bool                `yaml:"enabled"`
	GoldmaneAddr     string              `yaml:"goldmane_addr,omitempty"`
	ServerName       string              `yaml:"server_name,omitempty"`
	CABundlePath     string              `yaml:"ca_bundle_path,omitempty"`
	ClientCertPath   string              `yaml:"client_cert_path,omitempty"`
	ClientKeyPath    string              `yaml:"client_key_path,omitempty"`
	DialTimeout      DurationYAML        `yaml:"dial_timeout,omitempty"`
	StalenessTimeout DurationYAML        `yaml:"staleness_timeout,omitempty"`
	ConnectRetry     RetryStrategyConfig `yaml:"connect_retry,omitempty"`
	PublishRetry     RetryStrategyConfig `yaml:"publish_retry,omitempty"`
	MaxEventBytes    int                 `yaml:"max_event_bytes,omitempty"`
	// StartTimeGte is a pointer so the YAML loader can distinguish
	// omitted (defaults to -60 replay; see DefaultStartTimeGteReplay
	// in internal/collector/cni) from explicit 0 (which means "now"
	// per Goldmane proto goldmane/proto/api.proto line 91). The
	// omitempty tag on a plain int64 would collapse these two cases.
	StartTimeGte        *int64 `yaml:"start_time_gte,omitempty"`
	AggregationInterval int64  `yaml:"aggregation_interval,omitempty"`
}

// validate enforces CalicoSourceConfig invariants. Mirrors the
// AuditSourceConfig / ContainerdSourceConfig patterns: zero block is
// allowed when Enabled is false; partial retry blocks are rejected
// here rather than left to crashloop the adapter at runtime. mTLS
// material is mandatory because Goldmane rejects server-only TLS
// (ADR-2026-04-30-01).
func (c CalicoSourceConfig) validate() error {
	if !c.Enabled {
		return nil
	}
	if c.GoldmaneAddr == "" {
		return errors.New("detection.sources.calico.goldmane_addr: required when enabled=true")
	}
	if c.CABundlePath == "" {
		return errors.New("detection.sources.calico.ca_bundle_path: required when enabled=true")
	}
	if c.ClientCertPath == "" {
		return errors.New("detection.sources.calico.client_cert_path: required when enabled=true")
	}
	if c.ClientKeyPath == "" {
		return errors.New("detection.sources.calico.client_key_path: required when enabled=true")
	}
	if c.DialTimeout.Duration() < 0 {
		return fmt.Errorf("detection.sources.calico.dial_timeout: must be >= 0 (0 means default; got %s)", c.DialTimeout.Duration())
	}
	if c.StalenessTimeout.Duration() < 0 {
		return fmt.Errorf("detection.sources.calico.staleness_timeout: must be >= 0 (0 means default; got %s)", c.StalenessTimeout.Duration())
	}
	if c.MaxEventBytes < 0 {
		return fmt.Errorf("detection.sources.calico.max_event_bytes: must be >= 0 (0 means default; got %d)", c.MaxEventBytes)
	}
	if c.MaxEventBytes > 0 && c.MaxEventBytes < 4096 {
		return fmt.Errorf("detection.sources.calico.max_event_bytes: must be >= 4096 when set (got %d)", c.MaxEventBytes)
	}
	if c.AggregationInterval < 0 {
		return fmt.Errorf("detection.sources.calico.aggregation_interval: must be >= 0 (0 means default; got %d)", c.AggregationInterval)
	}
	if c.AggregationInterval != 0 && c.AggregationInterval != 15 {
		return fmt.Errorf("detection.sources.calico.aggregation_interval: must be 15s per Goldmane proto (goldmane/proto/api.proto line 100; got %d)", c.AggregationInterval)
	}
	if c.StartTimeGte != nil && *c.StartTimeGte > 0 {
		return fmt.Errorf("detection.sources.calico.start_time_gte: must be <= 0 (negative is relative seconds, zero is 'now' per Goldmane proto goldmane/proto/api.proto line 91; got %d)", *c.StartTimeGte)
	}
	if err := c.ConnectRetry.validatePartial("detection.sources.calico.connect_retry"); err != nil {
		return err
	}
	if err := c.PublishRetry.validatePartial("detection.sources.calico.publish_retry"); err != nil {
		return err
	}
	return nil
}

// RetryStrategyConfig is the YAML mirror of internal/retry.Strategy.
// Adapters that expose retry knobs use this shape. Conversion to a
// `retry.Strategy` is performed by the caller (see
// `cmd/olaitan/main.go:toRetryStrategy`); this type intentionally
// avoids depending on `internal/retry` so the config package stays a
// leaf in the import graph.
type RetryStrategyConfig struct {
	Min         DurationYAML `yaml:"min,omitempty"`
	Max         DurationYAML `yaml:"max,omitempty"`
	Multiplier  float64      `yaml:"multiplier,omitempty"`
	Jitter      float64      `yaml:"jitter,omitempty"`
	MaxAttempts int          `yaml:"max_attempts,omitempty"`
}

// IsZero reports whether r is the Go zero value (no fields set).
// Used by retry-strategy validators that distinguish "operator left
// the block out, use defaults" from "operator set partial fields,
// validate after merge".
func (r RetryStrategyConfig) IsZero() bool {
	return r.Min == 0 && r.Max == 0 && r.Multiplier == 0 && r.Jitter == 0 && r.MaxAttempts == 0
}

// ConfidenceBands holds the three cumulative score thresholds that
// drive FSM transitions. Must satisfy watch < alert < act, each in
// [0,100]. Checked in Validate.
type ConfidenceBands struct {
	Watch int `yaml:"watch"`
	Alert int `yaml:"alert"`
	Act   int `yaml:"act"`
}

// ResponseConfig -- see architecture.md:425 (excluded namespaces).
// Namespaces listed here are skipped by the response ring to prevent
// the agent from self-isolating or hard-killing cluster infrastructure.
type ResponseConfig struct {
	ExcludedNamespaces []string `yaml:"excluded_namespaces"`
}

// AnalystConfig -- see architecture.md:806-835 (LLM analyst settings).
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
// local -- each has an endpoint + model pair with no auth.
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
// SeverityThreshold in [0,100] -- spawn only when the parent assessment
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
// "500ms", "1h30m"). Anything else -- including a raw integer -- is
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

	// Substitute the metrics-address default before Validate so an
	// operator who omits the metrics block (the expected case for
	// chart-deploys that have not yet adopted the Story 1.12 block)
	// is not rejected. Explicit empty (operator typed
	// `metrics.address: ""`) still fails Validate below per guardrail
	// 27.
	if cfg != nil && cfg.Metrics.Address == "" {
		cfg.Metrics.Address = DefaultMetricsAddress
	}

	// Substitute rate-limit defaults before Validate so an operator
	// who omits the rate_limit block inherits the Story 1.13
	// production defaults (Enabled=true, threshold=1000, cooldown=60s,
	// sampling=0.1). The RateLimitConfig UnmarshalYAML hook preserves
	// field-presence bits, so explicit zero values are left intact and
	// rejected by Validate when enabled=true.
	if cfg != nil {
		defCorrelator := DefaultCorrelator()
		if cfg.Detection.Correlator.WindowDuration == 0 {
			cfg.Detection.Correlator.WindowDuration = defCorrelator.WindowDuration
		}
		// Pointer-tagged knobs: nil means "operator omitted, use
		// default"; a non-nil 0 means "operator explicitly set 0,
		// hand it to Validate". This split closes P24 (silent override
		// of operator intent).
		if cfg.Detection.Correlator.MaxPackageBytes == nil {
			cfg.Detection.Correlator.MaxPackageBytes = defCorrelator.MaxPackageBytes
		}
		if cfg.Detection.Correlator.MultiSignalMinSources == nil {
			cfg.Detection.Correlator.MultiSignalMinSources = defCorrelator.MultiSignalMinSources
		}
		if cfg.Detection.Correlator.HighSeverityThreshold == nil {
			cfg.Detection.Correlator.HighSeverityThreshold = defCorrelator.HighSeverityThreshold
		}

		def := DefaultRateLimit()
		if cfg.RateLimit.Enabled == nil {
			cfg.RateLimit.Enabled = def.Enabled
		}
		if !cfg.RateLimit.thresholdSet {
			cfg.RateLimit.ThresholdEventsPerSec = def.ThresholdEventsPerSec
		}
		if !cfg.RateLimit.cooldownSet {
			cfg.RateLimit.CooldownSeconds = def.CooldownSeconds
		}
		if !cfg.RateLimit.samplingSet {
			cfg.RateLimit.SamplingRate = def.SamplingRate
		}

		// Story 1.15: substitute rules defaults before Validate so an
		// operator who omits the block inherits engine-enabled with
		// the canonical /etc/olaitan/rules path. The pointer-tagged
		// Enabled lets an explicit `enabled: false` survive intact.
		defRules := DefaultRules()
		if cfg.Detection.Rules.Enabled == nil {
			cfg.Detection.Rules.Enabled = defRules.Enabled
		}
		if cfg.Detection.Rules.Path == "" {
			cfg.Detection.Rules.Path = defRules.Path
		}

		// Story 1.17: substitute baseline defaults before Validate so
		// an operator who omits the block inherits engine-enabled with
		// the canonical 30m / 3-sigma / redis:6379 defaults. The
		// pointer-tagged Enabled lets an explicit `enabled: false`
		// survive intact.
		defBaselines := DefaultBaselines()
		if cfg.Detection.Baselines.Enabled == nil {
			cfg.Detection.Baselines.Enabled = defBaselines.Enabled
		}
		if cfg.Detection.Baselines.WarmupDuration.Duration() <= 0 {
			cfg.Detection.Baselines.WarmupDuration = defBaselines.WarmupDuration
		}
		if cfg.Detection.Baselines.SigmaMultiplier == nil {
			cfg.Detection.Baselines.SigmaMultiplier = defBaselines.SigmaMultiplier
		}
		if cfg.Detection.Baselines.RedisAddr == "" {
			cfg.Detection.Baselines.RedisAddr = defBaselines.RedisAddr
		}
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
	if err := c.Metrics.validate(); err != nil {
		return err
	}
	if err := c.RateLimit.validate(); err != nil {
		return err
	}
	return nil
}

// validate enforces MetricsConfig invariants. Empty Address is rejected
// (the Story 1.12 Prometheus surface is mandatory per FR50 and
// guardrail 27); ":0" is accepted because integration tests bind to the
// OS-assigned free port. Any net.Listen-acceptable string is otherwise
// honoured; we deliberately do NOT pre-validate the host:port shape so
// IPv6 literal addresses ("[::1]:9090") and unix sockets ("unix:/...")
// can land in a future story without amending the validator.
func (m MetricsConfig) validate() error {
	if m.Address == "" {
		return fmt.Errorf("metrics.address: must not be empty (FR50; guardrail 27); default %q is substituted by Load when the block is omitted",
			DefaultMetricsAddress)
	}
	return nil
}

func (d DetectionConfig) validate() error {
	if d.BaselineWindow.Duration() <= 0 {
		return fmt.Errorf("detection.baseline_window: must be > 0 (got %s)", d.BaselineWindow.Duration())
	}
	if err := d.Correlator.validate(); err != nil {
		return err
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
	if err := d.Sources.Audit.validate(); err != nil {
		return err
	}
	if err := d.Sources.Containerd.validate(); err != nil {
		return err
	}
	if err := d.Sources.Calico.validate(); err != nil {
		return err
	}
	if err := d.Posture.validate(); err != nil {
		return err
	}
	if err := d.Rules.validate(); err != nil {
		return err
	}
	if err := d.Baselines.validate(); err != nil {
		return err
	}
	return nil
}

// validate enforces the AuditSourceConfig invariants. When Enabled is
// false the block may be entirely zero-valued; only the enabled path
// requires the TLS triplet and a positive listen address.
//
// PublishRetry is validated structurally: a partial block (e.g. only
// `multiplier: 2` set, leaving `min` zero) is rejected here rather
// than left to crashloop the adapter at runtime with a wrapped
// "retry: min must be > 0" error.
func (a AuditSourceConfig) validate() error {
	if !a.Enabled {
		return nil
	}
	if a.ListenAddr == "" {
		return errors.New("detection.sources.audit.listen_addr: required when enabled=true")
	}
	if a.TLSCertFile == "" {
		return errors.New("detection.sources.audit.tls_cert_file: required when enabled=true")
	}
	if a.TLSKeyFile == "" {
		return errors.New("detection.sources.audit.tls_key_file: required when enabled=true")
	}
	if a.ClientCAFile == "" {
		return errors.New("detection.sources.audit.client_ca_file: required when enabled=true")
	}
	if a.MaxPayloadBytes < 0 {
		return fmt.Errorf("detection.sources.audit.max_payload_bytes: must be >= 0 (0 means default; got %d)", a.MaxPayloadBytes)
	}
	if a.StalenessTimeout.Duration() < 0 {
		return fmt.Errorf("detection.sources.audit.staleness_timeout: must be >= 0 (0 means default; got %s)", a.StalenessTimeout.Duration())
	}
	if err := a.PublishRetry.validatePartial("detection.sources.audit.publish_retry"); err != nil {
		return err
	}
	return nil
}

// validatePartial returns an error when r is not the zero value AND
// any required field is unset. Fully-zero r is "use defaults" and is
// accepted. Non-zero r must specify min, max, and multiplier; jitter
// defaults to 0 (deterministic backoff) and max_attempts to unlimited.
func (r RetryStrategyConfig) validatePartial(prefix string) error {
	if r.IsZero() {
		return nil
	}
	if r.Min.Duration() <= 0 {
		return fmt.Errorf("%s.min: must be > 0 when other retry fields are set", prefix)
	}
	if r.Max.Duration() < r.Min.Duration() {
		return fmt.Errorf("%s.max: must be >= min (got min=%s, max=%s)", prefix, r.Min.Duration(), r.Max.Duration())
	}
	if r.Multiplier < 1.0 {
		return fmt.Errorf("%s.multiplier: must be >= 1.0 (got %v)", prefix, r.Multiplier)
	}
	if r.Jitter < 0 || r.Jitter > 1 {
		return fmt.Errorf("%s.jitter: must be in [0, 1] (got %v)", prefix, r.Jitter)
	}
	if r.MaxAttempts < 0 {
		return fmt.Errorf("%s.max_attempts: must be >= 0 (got %d)", prefix, r.MaxAttempts)
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
	case "api", "local", "none":
		// "none" is the LLM-tier-bypass sentinel used by the Epic 5 F
		// and RS evaluation arms (Story 1.19 / FR53). The aggregator
		// does not construct an analyst ring when provider="none";
		// the rest of the AnalystConfig fields are accepted and
		// validated as usual but are inert at runtime.
	default:
		return fmt.Errorf("analyst.provider: must be one of [api local none] (got %q)", a.Provider)
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
	// to actually dial -- config load is a parse-and-shape pass.
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
