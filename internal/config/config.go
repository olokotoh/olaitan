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
	"net"
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
	// Report configures the Ring-5 report layer (Story 3.1 onward). Today it
	// carries only the redact sub-block, which gates the AUDIT.redactions SIEM
	// emission (redaction itself is always on, BI-7). Omission of the block
	// leaves the redact defaults (audit off, 365 d retention).
	Report ReportConfig `yaml:"report,omitempty"`
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
	// Story 2.1: score sub-block configures the deterministic
	// ThreatScore calculator (FR30). Pointer fields per the Story
	// 1.14 D2 / 1.15 / 1.17 precedent so the loader distinguishes
	// "operator omitted, substitute default" from "operator
	// explicitly set 0". All four knobs are hot-reloadable via
	// config.Manager.Get() on every Score() call -- no restart and
	// no Subscribe callback required.
	Score ScoreConfig `yaml:"score,omitempty"`
	// Story 2.2: fsm sub-block configures the per-state dwell guards
	// and the de-escalation cooldown for the response-ring FSM
	// (FR31/FR32). The escalation thresholds live in ConfidenceBands
	// (BI-3); this block adds ONLY the durations ConfidenceBands does
	// not cover (BI-4). Pointer fields mirror ScoreConfig so the
	// loader distinguishes "operator omitted, substitute default"
	// from "operator explicitly set 0" (a 0 s dwell is a meaningful
	// choice, e.g. SUSPICIOUS defaults to 0).
	FSM FSMConfig `yaml:"fsm,omitempty"`
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

// ScoreConfig configures the Story 2.1 deterministic ThreatScore
// calculator (FR30). The four knobs are pointer-tagged so the loader
// distinguishes "operator omitted, substitute default" from "operator
// explicitly set 0" (e.g. setting llm_weight to 0 in a sensing-only
// deployment is a meaningful explicit choice and must not silently
// revert to 0.3).
//
// All four knobs are hot-reloadable via config.Manager.Get() on every
// Score() call. The calculator is stateless and reads the snapshot
// on the hot path; no Subscribe callback is needed (the Story 1.13
// limiter is the Subscribe precedent for stateful consumers).
type ScoreConfig struct {
	RuleWeight     *float64 `yaml:"rule_weight,omitempty"`
	BaselineWeight *float64 `yaml:"baseline_weight,omitempty"`
	LLMWeight      *float64 `yaml:"llm_weight,omitempty"`
	LLMCap         *int     `yaml:"llm_cap,omitempty"`
}

// DefaultScore returns the FR30 production defaults: 0.4 rule weight,
// 0.3 baseline weight, 0.3 LLM weight, LLM cap 35 (Claude Opus per
// prd.md:294). The 0.3 * 35 = 10.5 trust-bound holds below the
// SUSPICIOUS threshold 20.
func DefaultScore() ScoreConfig {
	rw := 0.4
	bw := 0.3
	lw := 0.3
	cap := 35
	return ScoreConfig{
		RuleWeight:     &rw,
		BaselineWeight: &bw,
		LLMWeight:      &lw,
		LLMCap:         &cap,
	}
}

// RuleWeightOrDefault returns the effective rule weight, substituting
// the FR30 default when omitted.
func (s ScoreConfig) RuleWeightOrDefault() float64 {
	if s.RuleWeight == nil {
		return 0.4
	}
	return *s.RuleWeight
}

// BaselineWeightOrDefault returns the effective baseline weight,
// substituting the FR30 default when omitted.
func (s ScoreConfig) BaselineWeightOrDefault() float64 {
	if s.BaselineWeight == nil {
		return 0.3
	}
	return *s.BaselineWeight
}

// LLMWeightOrDefault returns the effective LLM weight, substituting
// the FR30 default when omitted.
func (s ScoreConfig) LLMWeightOrDefault() float64 {
	if s.LLMWeight == nil {
		return 0.3
	}
	return *s.LLMWeight
}

// LLMCapOrDefault returns the effective LLM cap, substituting the
// Claude Opus default (35) when omitted.
func (s ScoreConfig) LLMCapOrDefault() int {
	if s.LLMCap == nil {
		return 35
	}
	return *s.LLMCap
}

// SuspiciousThreshold is the ThreatScore at or above which a workload is
// classed SUSPICIOUS (prd.md:294). The FR30 trust-bound requires that the
// LLM tier alone can never reach it: max(LLM-only) = LLMWeight*LLMCap must
// stay strictly below this value.
const SuspiciousThreshold = 20.0

// RestrictedThreshold and QuarantinedThreshold are the FSM band defaults
// (AC1 source of truth: SUSPICIOUS 20, RESTRICTED 40, QUARANTINED 70).
// They back the nil-config fall-through in internal/response/fsm so that
// path cannot silently drift from the loaded ConfidenceBands defaults.
const (
	RestrictedThreshold  = 40.0
	QuarantinedThreshold = 70.0
)

// validate enforces ScoreConfig invariants. Each weight must lie in
// [0.0, 1.0]; the three weights must sum to <= 1.0 (a 1e-9 tolerance
// is allowed for float round-off when an operator sets e.g. 0.333 x 3);
// LLMCap must lie in [0, 100]; and the LLM-only trust-bound
// LLMWeight*LLMCap must stay below SuspiciousThreshold (prd.md:294).
//
// The sum-<=1 check alone does NOT pin that trust-bound: it constrains
// each weight individually but says nothing about the weight*cap product.
// A config such as llm_weight=0.3, llm_cap=100 (both individually valid,
// weights summing to 1.0) would let the LLM tier alone drive Total to
// 0.3*100 = 30 >= 20, escalating a workload to SUSPICIOUS on LLM input
// only. The product is therefore enforced explicitly below. The LLM term
// is hard-zeroed in Epic 2 (score.go), so this guards against an Epic 3
// regression (epics.md:1589) rather than a live Epic 2 path. Added per
// Story 2.1 code review (PR #29).
//
// A nil ScoreConfig (all four pointer fields nil) means the operator
// did not declare the block; skip validation so in-memory test
// fixtures can omit the sub-block. The Load path substitutes
// DefaultScore before Validate, so production-deployed configs always
// reach validate with non-nil pointers.
func (s ScoreConfig) validate() error {
	if s.RuleWeight == nil && s.BaselineWeight == nil && s.LLMWeight == nil && s.LLMCap == nil {
		return nil
	}
	if s.RuleWeight != nil {
		if *s.RuleWeight < 0 || *s.RuleWeight > 1 {
			return fmt.Errorf("detection.score.rule_weight: must be in [0.0, 1.0] (got %v)", *s.RuleWeight)
		}
	}
	if s.BaselineWeight != nil {
		if *s.BaselineWeight < 0 || *s.BaselineWeight > 1 {
			return fmt.Errorf("detection.score.baseline_weight: must be in [0.0, 1.0] (got %v)", *s.BaselineWeight)
		}
	}
	if s.LLMWeight != nil {
		if *s.LLMWeight < 0 || *s.LLMWeight > 1 {
			return fmt.Errorf("detection.score.llm_weight: must be in [0.0, 1.0] (got %v)", *s.LLMWeight)
		}
	}
	rw, bw, lw := s.RuleWeightOrDefault(), s.BaselineWeightOrDefault(), s.LLMWeightOrDefault()
	if sum := rw + bw + lw; sum > 1.0+1e-9 {
		return fmt.Errorf("detection.score: weights must sum to <= 1.0 (got %.6f from rule_weight=%v, baseline_weight=%v, llm_weight=%v; weights omitted from the config use the FR30 defaults 0.4/0.3/0.3)", sum, rw, bw, lw)
	}
	if s.LLMCap != nil {
		if *s.LLMCap < 0 || *s.LLMCap > 100 {
			return fmt.Errorf("detection.score.llm_cap: must be in [0, 100] (got %d)", *s.LLMCap)
		}
	}
	if llmOnly := lw * float64(s.LLMCapOrDefault()); llmOnly >= SuspiciousThreshold {
		return fmt.Errorf("detection.score: llm_weight*llm_cap = %.3f must be < %.0f (the SUSPICIOUS threshold, prd.md:294); the LLM tier alone must not escalate a workload (FR30 trust-bound)", llmOnly, SuspiciousThreshold)
	}
	return nil
}

// FSMConfig configures the Story 2.2 response-ring finite state machine
// (FR31/FR32). It covers ONLY the per-state minimum dwell guards and the
// de-escalation cooldown; the escalation thresholds are reused from
// ConfidenceBands (BI-3, BI-4). The four knobs are pointer-tagged so the
// loader distinguishes "operator omitted, substitute default" from
// "operator explicitly set 0" (a 0 s dwell on SUSPICIOUS is the default
// and a meaningful explicit choice).
//
// All four are hot-reloadable: the FSM reads config.Manager.Get() once
// per Evaluate call, following the Story 2.1 score precedent. No restart
// and no Subscribe callback are required.
type FSMConfig struct {
	SuspiciousDwellSeconds      *int `yaml:"suspicious_dwell_seconds,omitempty"`
	RestrictedDwellSeconds      *int `yaml:"restricted_dwell_seconds,omitempty"`
	QuarantinedDwellSeconds     *int `yaml:"quarantined_dwell_seconds,omitempty"`
	DeescalationCooldownSeconds *int `yaml:"deescalation_cooldown_seconds,omitempty"`

	// Story 2.3: durable FSM-state persistence (FR37/NFR24). Unlike the
	// dwell/cooldown knobs above (hot-reloadable), these are
	// restart-required: toggling persistence or its Redis target rewires
	// the aggregator's FSM sink and restore hook. PersistenceEnabled is
	// pointer-tagged so an explicit `false` survives the loader.
	PersistenceEnabled *bool  `yaml:"persistence_enabled,omitempty"`
	RedisAddr          string `yaml:"redis_addr,omitempty"`
}

// FSM default dwell guards (seconds) and de-escalation cooldown. The
// SUSPICIOUS dwell is 0 so a freshly-flagged workload can escalate to
// RESTRICTED immediately once the score crosses the alert band; the
// RESTRICTED and QUARANTINED dwells are 120 s to damp oscillation
// (AC2); the de-escalation cooldown is 600 s (AC3).
const (
	DefaultSuspiciousDwellSeconds      = 0
	DefaultRestrictedDwellSeconds      = 120
	DefaultQuarantinedDwellSeconds     = 120
	DefaultDeescalationCooldownSeconds = 600
)

// DefaultFSM returns the Story 2.2 production defaults (AC2/AC3) plus the
// Story 2.3 persistence defaults (enabled, Redis at the canonical address).
func DefaultFSM() FSMConfig {
	sd := DefaultSuspiciousDwellSeconds
	rd := DefaultRestrictedDwellSeconds
	qd := DefaultQuarantinedDwellSeconds
	cd := DefaultDeescalationCooldownSeconds
	pe := true
	return FSMConfig{
		SuspiciousDwellSeconds:      &sd,
		RestrictedDwellSeconds:      &rd,
		QuarantinedDwellSeconds:     &qd,
		DeescalationCooldownSeconds: &cd,
		PersistenceEnabled:          &pe,
		RedisAddr:                   "redis:6379",
	}
}

// PersistenceEnabledOrDefault reports the effective FSM-persistence state,
// treating a nil pointer as the default (true) per BaselinesConfig precedent.
func (f FSMConfig) PersistenceEnabledOrDefault() bool {
	if f.PersistenceEnabled == nil {
		return true
	}
	return *f.PersistenceEnabled
}

// RedisAddrOrDefault returns the effective Redis address for FSM
// persistence, substituting the canonical default when omitted.
func (f FSMConfig) RedisAddrOrDefault() string {
	if f.RedisAddr == "" {
		return "redis:6379"
	}
	return f.RedisAddr
}

// SuspiciousDwellSecondsOrDefault returns the effective SUSPICIOUS dwell,
// substituting the default when omitted.
func (f FSMConfig) SuspiciousDwellSecondsOrDefault() int {
	if f.SuspiciousDwellSeconds == nil {
		return DefaultSuspiciousDwellSeconds
	}
	return *f.SuspiciousDwellSeconds
}

// RestrictedDwellSecondsOrDefault returns the effective RESTRICTED dwell,
// substituting the default when omitted.
func (f FSMConfig) RestrictedDwellSecondsOrDefault() int {
	if f.RestrictedDwellSeconds == nil {
		return DefaultRestrictedDwellSeconds
	}
	return *f.RestrictedDwellSeconds
}

// QuarantinedDwellSecondsOrDefault returns the effective QUARANTINED
// dwell, substituting the default when omitted.
func (f FSMConfig) QuarantinedDwellSecondsOrDefault() int {
	if f.QuarantinedDwellSeconds == nil {
		return DefaultQuarantinedDwellSeconds
	}
	return *f.QuarantinedDwellSeconds
}

// DeescalationCooldownSecondsOrDefault returns the effective
// de-escalation cooldown, substituting the default when omitted.
func (f FSMConfig) DeescalationCooldownSecondsOrDefault() int {
	if f.DeescalationCooldownSeconds == nil {
		return DefaultDeescalationCooldownSeconds
	}
	return *f.DeescalationCooldownSeconds
}

// validate enforces FSMConfig invariants: every duration must be
// non-negative (BI-4). A fully-omitted block (all four pointers nil)
// skips validation so in-memory test fixtures can leave it zero; the
// Load path substitutes DefaultFSM before Validate so production configs
// always reach validate with non-nil pointers.
func (f FSMConfig) validate() error {
	// Story 2.3: when persistence is explicitly enabled, a Redis address
	// is required. Checked before the dwell-only early return so a fixture
	// that sets only the persistence knobs is still validated.
	if f.PersistenceEnabled != nil && *f.PersistenceEnabled && f.RedisAddr == "" {
		return errors.New("detection.fsm.redis_addr: required when fsm.persistence_enabled=true")
	}
	if f.SuspiciousDwellSeconds == nil && f.RestrictedDwellSeconds == nil &&
		f.QuarantinedDwellSeconds == nil && f.DeescalationCooldownSeconds == nil {
		return nil
	}
	checks := []struct {
		name string
		val  *int
	}{
		{"detection.fsm.suspicious_dwell_seconds", f.SuspiciousDwellSeconds},
		{"detection.fsm.restricted_dwell_seconds", f.RestrictedDwellSeconds},
		{"detection.fsm.quarantined_dwell_seconds", f.QuarantinedDwellSeconds},
		{"detection.fsm.deescalation_cooldown_seconds", f.DeescalationCooldownSeconds},
	}
	for _, c := range checks {
		if c.val != nil && *c.val < 0 {
			return fmt.Errorf("%s: must be >= 0 (got %d)", c.name, *c.val)
		}
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
	// Story 2.4: network_policy sub-block configures the RESTRICTED-state
	// NetworkPolicyManager (FR33/NFR6). Enabled is pointer-tagged so an
	// explicit `false` survives the loader (Story 2.3 PersistenceEnabled
	// precedent); the manager is opt-in and defaults off until Story 2.10
	// wires the graduated-isolation mode.
	NetworkPolicy NetworkPolicyConfig `yaml:"network_policy,omitempty"`
	// Story 2.7: override sub-block configures the operator-override
	// controller (FR38/FR39). Enabled is pointer-tagged so an explicit
	// `false` survives the loader; the controller is opt-in and defaults off.
	Override OverrideConfig `yaml:"override,omitempty"`
	// Story 2.8: audit sub-block gates the three append-only SIEM audit
	// subjects (AUDIT.transitions/overrides/policies, FR40/NFR16). Enabled is
	// pointer-tagged so an explicit `false` survives the loader; auditing is
	// opt-in and defaults off. The per-subject retention days drive the
	// AUDIT_* JetStream stream MaxAge (AC4 Helm-tunability).
	Audit AuditConfig `yaml:"audit,omitempty"`
}

// NetworkPolicyConfig configures the Story 2.4 RESTRICTED-state
// NetworkPolicy enforcement (FR33). The RESTRICTED policy allows egress
// only to the RFC 1918 private ranges (always allowed), the cluster's pod
// and service CIDRs (ClusterCIDRs), and any operator-supplied extra CIDRs,
// and blocks all other (external) egress.
//
// Enabled is pointer-tagged so an explicit `false` survives the loader;
// the default is OFF (the manager is opt-in; Story 2.10 turns it on per
// graduated-isolation mode). ReconcileIntervalSeconds is pointer-tagged so
// an explicit small value survives; it sets the orphan-GC reconcile
// cadence and must stay well inside the 60 s AC4 budget.
type NetworkPolicyConfig struct {
	Enabled                  *bool    `yaml:"enabled,omitempty"`
	ClusterCIDRs             []string `yaml:"cluster_cidrs,omitempty"`
	ExtraAllowedCIDRs        []string `yaml:"extra_allowed_cidrs,omitempty"`
	ReconcileIntervalSeconds *int     `yaml:"reconcile_interval_seconds,omitempty"`
}

// DefaultNetworkPolicyReconcileSeconds is the orphan-GC reconcile cadence;
// 30 s is comfortably inside the 60 s AC4 garbage-collection budget.
const DefaultNetworkPolicyReconcileSeconds = 30

// DefaultNetworkPolicyClusterCIDRs are the pod and service CIDRs allowed
// for egress by default. They match the kind/Calico evaluation cluster
// (pod CIDR 10.244.0.0/16, service CIDR 10.96.0.0/12). Operators on other
// clusters MUST override these to their own pod and service CIDRs so that
// in-cluster traffic (including DNS to the service-CIDR-resident CoreDNS)
// survives the RESTRICTED egress block.
var DefaultNetworkPolicyClusterCIDRs = []string{"10.244.0.0/16", "10.96.0.0/12"}

// DefaultNetworkPolicy returns the Story 2.4 defaults: disabled, the
// kind/Calico cluster CIDRs, and a 30 s reconcile cadence.
func DefaultNetworkPolicy() NetworkPolicyConfig {
	enabled := false
	ri := DefaultNetworkPolicyReconcileSeconds
	cidrs := make([]string, len(DefaultNetworkPolicyClusterCIDRs))
	copy(cidrs, DefaultNetworkPolicyClusterCIDRs)
	return NetworkPolicyConfig{
		Enabled:                  &enabled,
		ClusterCIDRs:             cidrs,
		ReconcileIntervalSeconds: &ri,
	}
}

// EnabledOrDefault reports whether the NetworkPolicy manager is enabled,
// treating a nil pointer as the default (false).
func (n NetworkPolicyConfig) EnabledOrDefault() bool {
	if n.Enabled == nil {
		return false
	}
	return *n.Enabled
}

// ReconcileIntervalSecondsOrDefault returns the effective orphan-GC
// reconcile cadence, substituting the default when omitted.
func (n NetworkPolicyConfig) ReconcileIntervalSecondsOrDefault() int {
	if n.ReconcileIntervalSeconds == nil {
		return DefaultNetworkPolicyReconcileSeconds
	}
	return *n.ReconcileIntervalSeconds
}

// ClusterCIDRsOrDefault returns the effective cluster CIDRs, substituting
// the kind/Calico defaults when omitted.
func (n NetworkPolicyConfig) ClusterCIDRsOrDefault() []string {
	if len(n.ClusterCIDRs) == 0 {
		out := make([]string, len(DefaultNetworkPolicyClusterCIDRs))
		copy(out, DefaultNetworkPolicyClusterCIDRs)
		return out
	}
	return n.ClusterCIDRs
}

// validate enforces NetworkPolicyConfig invariants: every CIDR must parse,
// and the reconcile interval (when set) must be in [1, 60] so orphan GC
// always meets the AC4 60 s budget. A fully-omitted block skips validation
// so in-memory test fixtures can leave it zero; the Load path substitutes
// DefaultNetworkPolicy before Validate when the manager is enabled.
func (n NetworkPolicyConfig) validate() error {
	for i, c := range n.ClusterCIDRs {
		if _, _, err := net.ParseCIDR(c); err != nil {
			return fmt.Errorf("response.network_policy.cluster_cidrs[%d]: invalid CIDR %q: %w", i, c, err)
		}
	}
	for i, c := range n.ExtraAllowedCIDRs {
		if _, _, err := net.ParseCIDR(c); err != nil {
			return fmt.Errorf("response.network_policy.extra_allowed_cidrs[%d]: invalid CIDR %q: %w", i, c, err)
		}
	}
	if n.ReconcileIntervalSeconds != nil {
		if v := *n.ReconcileIntervalSeconds; v < 1 || v > 60 {
			return fmt.Errorf("response.network_policy.reconcile_interval_seconds: must be in [1, 60] to meet the 60 s orphan-GC budget (got %d)", v)
		}
	}
	// When the manager is explicitly enabled, at least one cluster CIDR is
	// required so in-cluster traffic and DNS are not blocked.
	if n.Enabled != nil && *n.Enabled && len(n.ClusterCIDRs) == 0 {
		return errors.New("response.network_policy.cluster_cidrs: at least one cluster CIDR (pod and/or service CIDR) is required when network_policy.enabled=true")
	}
	return nil
}

// OverrideConfig configures the Story 2.7 operator-override controller
// (FR38/FR39). The controller polls (LISTs) pods for the
// olaitan.io/state-override annotation, pins the FSM, and records an
// override:{workload_id} Redis key with a native TTL.
//
// Enabled is pointer-tagged so an explicit `false` survives the loader (the
// NetworkPolicyConfig.Enabled precedent); the default is OFF (opt-in).
// PollIntervalSeconds is the reconcile cadence (default 15) and bounds the
// release-detection latency to one tick (BI-4 / Open Assumption 1).
// DefaultTTLSeconds is the override duration applied when the
// olaitan.io/state-override-ttl annotation is absent or unparseable (default
// 3600 = 1h, AC2 / BI-8).
type OverrideConfig struct {
	Enabled             *bool `yaml:"enabled,omitempty"`
	PollIntervalSeconds *int  `yaml:"poll_interval_seconds,omitempty"`
	DefaultTTLSeconds   *int  `yaml:"default_ttl_seconds,omitempty"`
}

// DefaultOverridePollSeconds is the override poll/reconcile cadence; 15 s is
// well inside any operator-meaningful manual-override latency (BI-1).
const DefaultOverridePollSeconds = 15

// DefaultOverrideTTLSeconds is the override duration applied when the TTL
// annotation is absent or unparseable (AC2 "default 1 hour if absent").
const DefaultOverrideTTLSeconds = 3600

// DefaultOverride returns the Story 2.7 defaults: disabled, a 15 s poll, and
// a 1 h default TTL.
func DefaultOverride() OverrideConfig {
	enabled := false
	poll := DefaultOverridePollSeconds
	ttl := DefaultOverrideTTLSeconds
	return OverrideConfig{
		Enabled:             &enabled,
		PollIntervalSeconds: &poll,
		DefaultTTLSeconds:   &ttl,
	}
}

// EnabledOrDefault reports whether the override controller is enabled,
// treating a nil pointer as the default (false).
func (o OverrideConfig) EnabledOrDefault() bool {
	if o.Enabled == nil {
		return false
	}
	return *o.Enabled
}

// PollIntervalSecondsOrDefault returns the effective poll cadence,
// substituting the default when omitted.
func (o OverrideConfig) PollIntervalSecondsOrDefault() int {
	if o.PollIntervalSeconds == nil {
		return DefaultOverridePollSeconds
	}
	return *o.PollIntervalSeconds
}

// DefaultTTLSecondsOrDefault returns the effective default override TTL,
// substituting the 1 h default when omitted.
func (o OverrideConfig) DefaultTTLSecondsOrDefault() int {
	if o.DefaultTTLSeconds == nil {
		return DefaultOverrideTTLSeconds
	}
	return *o.DefaultTTLSeconds
}

// validate enforces OverrideConfig invariants: a set poll interval and
// default TTL must be positive. A fully-omitted block skips validation so
// in-memory fixtures can leave it zero; Load substitutes DefaultOverride
// before Validate.
func (o OverrideConfig) validate() error {
	if o.PollIntervalSeconds != nil && *o.PollIntervalSeconds < 1 {
		return fmt.Errorf("response.override.poll_interval_seconds: must be >= 1 (got %d)", *o.PollIntervalSeconds)
	}
	if o.DefaultTTLSeconds != nil && *o.DefaultTTLSeconds < 1 {
		return fmt.Errorf("response.override.default_ttl_seconds: must be >= 1 (got %d)", *o.DefaultTTLSeconds)
	}
	return nil
}

// AuditConfig configures the Story 2.8 append-only SIEM audit subjects
// (FR40/NFR16). A single Enabled flag gates all three seams together (the
// transitions sink, the override second-publish, and the netpol policy
// publisher, BI-8 / Open Assumption 1). The three retention-days fields set the
// MaxAge of the corresponding AUDIT_* JetStream streams (BI-7), so an operator
// tunes each subject's append-only retention independently; the defaults are
// 90/365/365 days (AC4, reconciling the architecture's generalised "AUDIT.* 365
// d" with the AC's specific 90 d transitions retention).
//
// Enabled is pointer-tagged so an explicit `false` survives the loader (the
// OverrideConfig.Enabled precedent); the default is OFF (opt-in). The retention
// fields are pointer-tagged so an explicit value survives and a zero is
// distinguishable from omitted.
type AuditConfig struct {
	Enabled                  *bool `yaml:"enabled,omitempty"`
	RetentionTransitionsDays *int  `yaml:"retention_transitions_days,omitempty"`
	RetentionOverridesDays   *int  `yaml:"retention_overrides_days,omitempty"`
	RetentionPoliciesDays    *int  `yaml:"retention_policies_days,omitempty"`
}

// Default audit retention days (AC4). Transitions default to 90 d (matching the
// STATE_TRANSITIONS.applied operational audit-trail retention); overrides and
// policies default to 365 d.
const (
	DefaultAuditRetentionTransitionsDays = 90
	DefaultAuditRetentionOverridesDays   = 365
	DefaultAuditRetentionPoliciesDays    = 365
)

// DefaultAudit returns the Story 2.8 defaults: disabled, with 90/365/365 d
// retention.
func DefaultAudit() AuditConfig {
	enabled := false
	t := DefaultAuditRetentionTransitionsDays
	o := DefaultAuditRetentionOverridesDays
	p := DefaultAuditRetentionPoliciesDays
	return AuditConfig{
		Enabled:                  &enabled,
		RetentionTransitionsDays: &t,
		RetentionOverridesDays:   &o,
		RetentionPoliciesDays:    &p,
	}
}

// EnabledOrDefault reports whether the audit subjects are enabled, treating a
// nil pointer as the default (false).
func (a AuditConfig) EnabledOrDefault() bool {
	if a.Enabled == nil {
		return false
	}
	return *a.Enabled
}

// RetentionTransitionsDaysOrDefault returns the effective transitions retention
// in days, substituting the 90 d default when omitted.
func (a AuditConfig) RetentionTransitionsDaysOrDefault() int {
	if a.RetentionTransitionsDays == nil {
		return DefaultAuditRetentionTransitionsDays
	}
	return *a.RetentionTransitionsDays
}

// RetentionOverridesDaysOrDefault returns the effective overrides retention in
// days, substituting the 365 d default when omitted.
func (a AuditConfig) RetentionOverridesDaysOrDefault() int {
	if a.RetentionOverridesDays == nil {
		return DefaultAuditRetentionOverridesDays
	}
	return *a.RetentionOverridesDays
}

// RetentionPoliciesDaysOrDefault returns the effective policies retention in
// days, substituting the 365 d default when omitted.
func (a AuditConfig) RetentionPoliciesDaysOrDefault() int {
	if a.RetentionPoliciesDays == nil {
		return DefaultAuditRetentionPoliciesDays
	}
	return *a.RetentionPoliciesDays
}

// validate enforces AuditConfig invariants: every set retention must be
// positive (a non-positive MaxAge would mean "never expire" on some JetStream
// versions and is never an operator intent for an append-only audit window). A
// fully-omitted block skips validation so in-memory fixtures can leave it zero;
// Load substitutes DefaultAudit before Validate when auditing is enabled.
func (a AuditConfig) validate() error {
	if a.RetentionTransitionsDays != nil && *a.RetentionTransitionsDays < 1 {
		return fmt.Errorf("response.audit.retention_transitions_days: must be >= 1 (got %d)", *a.RetentionTransitionsDays)
	}
	if a.RetentionOverridesDays != nil && *a.RetentionOverridesDays < 1 {
		return fmt.Errorf("response.audit.retention_overrides_days: must be >= 1 (got %d)", *a.RetentionOverridesDays)
	}
	if a.RetentionPoliciesDays != nil && *a.RetentionPoliciesDays < 1 {
		return fmt.Errorf("response.audit.retention_policies_days: must be >= 1 (got %d)", *a.RetentionPoliciesDays)
	}
	return nil
}

// ReportConfig configures the Ring-5 report layer. Story 3.1 adds the redact
// sub-block; Epic 4 extends this block with the S3/forensic-persistence knobs.
type ReportConfig struct {
	// Redact gates the Story 3.1 AUDIT.redactions SIEM emission (FR41). The
	// redaction itself is ALWAYS applied at every LLM/persistence boundary
	// regardless of config (turning it off would violate NFR15 and is
	// forbidden); only the SIEM publish is config-gated, off by default (the
	// Story 2.8 response.audit.enabled precedent, BI-7).
	Redact RedactConfig `yaml:"redact,omitempty"`
}

// RedactConfig configures the Story 3.1 AUDIT.redactions emission (BI-7.1). A
// single AuditEnabled flag gates the SIEM publish; RetentionRedactionsDays sets
// the MaxAge of the AUDIT_REDACTIONS JetStream stream (365 d default, BI-3.2).
//
// AuditEnabled is pointer-tagged so an explicit `false` survives the loader (the
// AuditConfig.Enabled precedent); the default is OFF (opt-in). The retention
// field is pointer-tagged so an explicit value survives and a zero is
// distinguishable from omitted.
//
// Open Assumption 3 / BI-7.2: there is NO flag to disable redaction. An
// operator without a SIEM leaves audit_enabled false and pays no NATS-publish
// cost while STILL getting full redaction at every boundary.
type RedactConfig struct {
	AuditEnabled            *bool `yaml:"audit_enabled,omitempty"`
	RetentionRedactionsDays *int  `yaml:"retention_redactions_days,omitempty"`
}

// DefaultRedactionsRetentionDays is the Story 3.1 redactions retention default
// (BI-3.2): 365 d, the architecture's generalised "AUDIT.* 365 d".
const DefaultRedactionsRetentionDays = 365

// DefaultRedact returns the Story 3.1 defaults: audit emission disabled, 365 d
// retention.
func DefaultRedact() RedactConfig {
	enabled := false
	r := DefaultRedactionsRetentionDays
	return RedactConfig{
		AuditEnabled:            &enabled,
		RetentionRedactionsDays: &r,
	}
}

// AuditEnabledOrDefault reports whether the AUDIT.redactions emission is
// enabled, treating a nil pointer as the default (false).
func (r RedactConfig) AuditEnabledOrDefault() bool {
	if r.AuditEnabled == nil {
		return false
	}
	return *r.AuditEnabled
}

// RetentionRedactionsDaysOrDefault returns the effective redactions retention in
// days, substituting the 365 d default when omitted.
func (r RedactConfig) RetentionRedactionsDaysOrDefault() int {
	if r.RetentionRedactionsDays == nil {
		return DefaultRedactionsRetentionDays
	}
	return *r.RetentionRedactionsDays
}

// validate enforces RedactConfig invariants: a set retention must be positive
// (a non-positive MaxAge is never an operator intent for an append-only audit
// window). A fully-omitted block skips validation; Load substitutes
// DefaultRedact before Validate.
func (r RedactConfig) validate() error {
	if r.RetentionRedactionsDays != nil && *r.RetentionRedactionsDays < 1 {
		return fmt.Errorf("report.redact.retention_redactions_days: must be >= 1 (got %d)", *r.RetentionRedactionsDays)
	}
	return nil
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

	// Per-role provider routing (Story 3.8, FR25). Each *Provider names a
	// CONCRETE family {claude, openai, ollama, none} or "" to inherit the
	// top-level Provider mapping (api -> claude, local -> ollama). This is
	// distinct from the top-level Provider enum {api, local, none}: the
	// concrete family is what lets a role route to openai per FR25.
	// L2Enabled / SeniorEnabled are *bool so an unset flag defaults to
	// true while an explicit false (the AC4 ablation toggle) is honoured
	// rather than swallowed (the Story 3.4 falsy-value lesson).
	L1Provider     string `yaml:"l1_provider"`
	L1Model        string `yaml:"l1_model"`
	L2Provider     string `yaml:"l2_provider"`
	L2Model        string `yaml:"l2_model"`
	L2Enabled      *bool  `yaml:"l2_enabled"`
	SeniorProvider string `yaml:"senior_provider"`
	SeniorModel    string `yaml:"senior_model"`
	SeniorEnabled  *bool  `yaml:"senior_enabled"`

	// CheckpointRetention is the INVESTIGATIONS stream MaxAge (Story 3.9
	// FR29/AC4): how long L1/L2 checkpoints survive for controller-restart
	// resume. Zero/unset selects the architecture's 6h default at the
	// wiring layer; a negative value is rejected by validate().
	CheckpointRetention DurationYAML `yaml:"checkpoint_retention"`
}

// L2EnabledOrDefault reports whether the L2 role runs. Unset = true; an
// explicit false is the RSLT L1-only ablation toggle (Story 3.8 AC4).
func (a AnalystConfig) L2EnabledOrDefault() bool {
	return a.L2Enabled == nil || *a.L2Enabled
}

// SeniorEnabledOrDefault reports whether the Senior role runs. Unset =
// true; an explicit false is the RSLT L1+L2 ablation (Story 3.8 AC4).
// Precedence: when L2 is disabled the chain is L1-only, so Senior is
// implicitly off regardless of SeniorEnabled.
func (a AnalystConfig) SeniorEnabledOrDefault() bool {
	if !a.L2EnabledOrDefault() {
		return false
	}
	return a.SeniorEnabled == nil || *a.SeniorEnabled
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

		// Story 2.1: substitute score defaults before Validate so an
		// operator who omits the detection.score block inherits the
		// FR30 defaults 0.4 / 0.3 / 0.3 with LLMCap 35. The pointer-
		// tagged fields let an explicit `llm_weight: 0` survive
		// intact (e.g. sensing-only deployments that disable the LLM
		// contribution explicitly).
		defScore := DefaultScore()
		if cfg.Detection.Score.RuleWeight == nil {
			cfg.Detection.Score.RuleWeight = defScore.RuleWeight
		}
		if cfg.Detection.Score.BaselineWeight == nil {
			cfg.Detection.Score.BaselineWeight = defScore.BaselineWeight
		}
		if cfg.Detection.Score.LLMWeight == nil {
			cfg.Detection.Score.LLMWeight = defScore.LLMWeight
		}
		if cfg.Detection.Score.LLMCap == nil {
			cfg.Detection.Score.LLMCap = defScore.LLMCap
		}

		// Story 2.2: substitute FSM dwell/cooldown defaults before
		// Validate so an operator who omits the detection.fsm block
		// inherits the AC2/AC3 defaults (RESTRICTED/QUARANTINED dwell
		// 120 s, de-escalation cooldown 600 s, SUSPICIOUS dwell 0). The
		// pointer-tagged fields let an explicit `suspicious_dwell_seconds:
		// 0` survive intact.
		defFSM := DefaultFSM()
		if cfg.Detection.FSM.SuspiciousDwellSeconds == nil {
			cfg.Detection.FSM.SuspiciousDwellSeconds = defFSM.SuspiciousDwellSeconds
		}
		if cfg.Detection.FSM.RestrictedDwellSeconds == nil {
			cfg.Detection.FSM.RestrictedDwellSeconds = defFSM.RestrictedDwellSeconds
		}
		if cfg.Detection.FSM.QuarantinedDwellSeconds == nil {
			cfg.Detection.FSM.QuarantinedDwellSeconds = defFSM.QuarantinedDwellSeconds
		}
		if cfg.Detection.FSM.DeescalationCooldownSeconds == nil {
			cfg.Detection.FSM.DeescalationCooldownSeconds = defFSM.DeescalationCooldownSeconds
		}
		// Story 2.3: substitute FSM-persistence defaults (enabled, Redis at
		// redis:6379) before Validate. The pointer-tagged PersistenceEnabled
		// lets an explicit `persistence_enabled: false` survive intact.
		if cfg.Detection.FSM.PersistenceEnabled == nil {
			cfg.Detection.FSM.PersistenceEnabled = defFSM.PersistenceEnabled
		}
		if cfg.Detection.FSM.RedisAddr == "" {
			cfg.Detection.FSM.RedisAddr = defFSM.RedisAddr
		}

		// Story 2.4: substitute NetworkPolicy defaults before Validate. The
		// pointer-tagged Enabled lets an explicit `enabled: false` survive;
		// ClusterCIDRs and the reconcile interval inherit the kind/Calico
		// defaults when omitted so an operator who enables the manager
		// without listing CIDRs still gets a working (if cluster-specific)
		// egress allow-list rather than a hard rejection.
		defNP := DefaultNetworkPolicy()
		if cfg.Response.NetworkPolicy.Enabled == nil {
			cfg.Response.NetworkPolicy.Enabled = defNP.Enabled
		}
		if len(cfg.Response.NetworkPolicy.ClusterCIDRs) == 0 {
			cfg.Response.NetworkPolicy.ClusterCIDRs = defNP.ClusterCIDRs
		}
		if cfg.Response.NetworkPolicy.ReconcileIntervalSeconds == nil {
			cfg.Response.NetworkPolicy.ReconcileIntervalSeconds = defNP.ReconcileIntervalSeconds
		}

		// Story 2.7: substitute Override defaults before Validate. The
		// pointer-tagged Enabled lets an explicit `enabled: false` survive;
		// the poll interval and default TTL inherit the 15 s / 1 h defaults
		// when omitted.
		defOvr := DefaultOverride()
		if cfg.Response.Override.Enabled == nil {
			cfg.Response.Override.Enabled = defOvr.Enabled
		}
		if cfg.Response.Override.PollIntervalSeconds == nil {
			cfg.Response.Override.PollIntervalSeconds = defOvr.PollIntervalSeconds
		}
		if cfg.Response.Override.DefaultTTLSeconds == nil {
			cfg.Response.Override.DefaultTTLSeconds = defOvr.DefaultTTLSeconds
		}
	}

	// Story 2.8: substitute the audit defaults so an enabled audit block with
	// omitted retentions inherits the 90/365/365 d defaults, and an omitted
	// Enabled stays off.
	{
		defAudit := DefaultAudit()
		if cfg.Response.Audit.Enabled == nil {
			cfg.Response.Audit.Enabled = defAudit.Enabled
		}
		if cfg.Response.Audit.RetentionTransitionsDays == nil {
			cfg.Response.Audit.RetentionTransitionsDays = defAudit.RetentionTransitionsDays
		}
		if cfg.Response.Audit.RetentionOverridesDays == nil {
			cfg.Response.Audit.RetentionOverridesDays = defAudit.RetentionOverridesDays
		}
		if cfg.Response.Audit.RetentionPoliciesDays == nil {
			cfg.Response.Audit.RetentionPoliciesDays = defAudit.RetentionPoliciesDays
		}
	}

	// Story 3.1: substitute the redact defaults so an enabled redact block with
	// an omitted retention inherits the 365 d default, and an omitted
	// AuditEnabled stays off (redaction itself is always on, BI-7).
	{
		defRedact := DefaultRedact()
		if cfg.Report.Redact.AuditEnabled == nil {
			cfg.Report.Redact.AuditEnabled = defRedact.AuditEnabled
		}
		if cfg.Report.Redact.RetentionRedactionsDays == nil {
			cfg.Report.Redact.RetentionRedactionsDays = defRedact.RetentionRedactionsDays
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
	if err := c.Report.Redact.validate(); err != nil {
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
	if err := d.Score.validate(); err != nil {
		return err
	}
	if err := d.FSM.validate(); err != nil {
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
	if err := r.NetworkPolicy.validate(); err != nil {
		return err
	}
	if err := r.Override.validate(); err != nil {
		return err
	}
	if err := r.Audit.validate(); err != nil {
		return err
	}
	return nil
}

// validRoleProvider reports whether p is an acceptable per-role provider
// family (Story 3.8 BI-3): a concrete family, "none", or "" to inherit
// the top-level provider mapping.
func validRoleProvider(p string) bool {
	switch strings.ToLower(p) {
	case "", "claude", "openai", "ollama", "none":
		return true
	}
	return false
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
	for _, rp := range []struct{ field, val string }{
		{"l1_provider", a.L1Provider},
		{"l2_provider", a.L2Provider},
		{"senior_provider", a.SeniorProvider},
	} {
		if !validRoleProvider(rp.val) {
			return fmt.Errorf("analyst.%s: must be one of [claude openai ollama none] or empty to inherit (got %q)", rp.field, rp.val)
		}
	}
	if a.Timeout.Duration() <= 0 {
		return fmt.Errorf("analyst.timeout: must be > 0 (got %s)", a.Timeout.Duration())
	}
	// checkpoint_retention is optional: zero/unset selects the 6h default at
	// the wiring layer; a negative value is a misconfiguration.
	if a.CheckpointRetention.Duration() < 0 {
		return fmt.Errorf("analyst.checkpoint_retention: must be >= 0 (got %s)", a.CheckpointRetention.Duration())
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
