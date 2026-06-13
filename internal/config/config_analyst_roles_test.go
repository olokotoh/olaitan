package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/config"
)

const analystRolesBaseYAML = `detection:
  confidence_bands: {watch: 40, alert: 70, act: 90}
  baseline_window: "1h"
response:
  excluded_namespaces: []
analyst:
  provider: api
  score_cap: 35
  timeout: 10s
`

// TestAnalystPerRoleDecode pins that the Story 3.8 per-role routing
// fields decode through config.Load with their flat AC2 yaml keys, and
// that an explicit l2_enabled: false survives (the *bool falsy-value
// guarantee).
func TestAnalystPerRoleDecode(t *testing.T) {
	yaml := analystRolesBaseYAML +
		"  l1_provider: claude\n" +
		"  l1_model: claude-haiku-4-5\n" +
		"  l2_provider: openai\n" +
		"  l2_model: gpt-4o-mini\n" +
		"  l2_enabled: false\n" +
		"  senior_provider: ollama\n" +
		"  senior_model: gemma:2b\n"
	cfg, err := config.Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	a := cfg.Analyst
	if a.L1Provider != "claude" || a.L1Model != "claude-haiku-4-5" {
		t.Errorf("l1 = %q/%q", a.L1Provider, a.L1Model)
	}
	if a.L2Provider != "openai" || a.L2Model != "gpt-4o-mini" {
		t.Errorf("l2 = %q/%q", a.L2Provider, a.L2Model)
	}
	if a.SeniorProvider != "ollama" || a.SeniorModel != "gemma:2b" {
		t.Errorf("senior = %q/%q", a.SeniorProvider, a.SeniorModel)
	}
	if a.L2Enabled == nil || *a.L2Enabled {
		t.Errorf("l2_enabled: false must decode to a non-nil false, got %v", a.L2Enabled)
	}
}

// TestAnalystRoleProviderEnumRejected: a per-role provider outside
// {claude, openai, ollama, none, ""} is a load-time error.
func TestAnalystRoleProviderEnumRejected(t *testing.T) {
	yaml := analystRolesBaseYAML + "  l1_provider: bogus\n"
	_, err := config.Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("Load: got nil, want rejection of l1_provider: bogus")
	}
	if !strings.Contains(err.Error(), "l1_provider") {
		t.Errorf("error does not name the offending field: %v", err)
	}
}

// TestAnalystStrictDecodeRejectsTypo: KnownFields(true) means a
// misspelled per-role key is a hard decode error, not a silent drop.
func TestAnalystStrictDecodeRejectsTypo(t *testing.T) {
	yaml := analystRolesBaseYAML + "  l1_provder: claude\n"
	if _, err := config.Load(writeConfig(t, yaml)); err == nil {
		t.Fatal("Load: got nil, want strict-decode rejection of typo'd key l1_provder")
	}
}

// TestAnalystCheckpointRetention (Story 3.9): a valid duration round-trips,
// an unset value is 0 (the wiring layer applies the 6h default), and a
// negative duration is rejected at load.
func TestAnalystCheckpointRetention(t *testing.T) {
	cfg, err := config.Load(writeConfig(t, analystRolesBaseYAML+"  checkpoint_retention: 2h\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Analyst.CheckpointRetention.Duration() != 2*time.Hour {
		t.Errorf("checkpoint_retention = %s, want 2h", cfg.Analyst.CheckpointRetention.Duration())
	}
	if _, err := config.Load(writeConfig(t, analystRolesBaseYAML+"  checkpoint_retention: -1h\n")); err == nil {
		t.Error("negative checkpoint_retention must be rejected")
	}
}

// TestAnalystCircuitBreaker (Story 3.12) pins the breaker defaults (10/min,
// 60s, enabled) and the validate() rejection of an enabled breaker with an
// out-of-range threshold.
func TestAnalystCircuitBreaker(t *testing.T) {
	cfg, err := config.Load(writeConfig(t, analystRolesBaseYAML+"  circuit_breaker:\n    rate_per_min: 25\n    cooling_seconds: 90\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Analyst.CircuitBreaker.RatePerMinOrDefault() != 25 || cfg.Analyst.CircuitBreaker.CoolingSecondsOrDefault() != 90 {
		t.Errorf("breaker = %d/%d, want 25/90", cfg.Analyst.CircuitBreaker.RatePerMinOrDefault(), cfg.Analyst.CircuitBreaker.CoolingSecondsOrDefault())
	}
	// Unset = defaults (10/60, enabled).
	cfgD, err := config.Load(writeConfig(t, analystRolesBaseYAML))
	if err != nil {
		t.Fatalf("Load defaults: %v", err)
	}
	if cfgD.Analyst.CircuitBreaker.RatePerMinOrDefault() != 10 || cfgD.Analyst.CircuitBreaker.CoolingSecondsOrDefault() != 60 || !cfgD.Analyst.CircuitBreaker.EnabledOrDefault() {
		t.Errorf("breaker defaults = %d/%d/%v, want 10/60/true", cfgD.Analyst.CircuitBreaker.RatePerMinOrDefault(), cfgD.Analyst.CircuitBreaker.CoolingSecondsOrDefault(), cfgD.Analyst.CircuitBreaker.EnabledOrDefault())
	}
	// An enabled breaker with rate_per_min < 1 is rejected.
	if _, err := config.Load(writeConfig(t, analystRolesBaseYAML+"  circuit_breaker:\n    rate_per_min: 0\n")); err == nil {
		t.Error("enabled breaker with rate_per_min 0 must be rejected")
	}
	// A DISABLED breaker does not validate its thresholds.
	if _, err := config.Load(writeConfig(t, analystRolesBaseYAML+"  circuit_breaker:\n    enabled: false\n    rate_per_min: 0\n")); err != nil {
		t.Errorf("disabled breaker must skip threshold validation: %v", err)
	}
}

// TestAnalystEnabledAccessors pins the ablation default + precedence
// (Story 3.8 BI-3): unset = enabled; senior_enabled: false = L1+L2;
// l2_enabled: false forces L1-only (Senior implicitly off).
func TestAnalystEnabledAccessors(t *testing.T) {
	f, tr := false, true

	if a := (config.AnalystConfig{}); !a.L2EnabledOrDefault() || !a.SeniorEnabledOrDefault() {
		t.Error("unset toggles must default to enabled")
	}
	if a := (config.AnalystConfig{SeniorEnabled: &f}); !a.L2EnabledOrDefault() || a.SeniorEnabledOrDefault() {
		t.Error("senior_enabled:false with L2 on must be L1+L2 (L2 on, Senior off)")
	}
	// l2 disabled forces Senior off even when senior_enabled is true.
	if a := (config.AnalystConfig{L2Enabled: &f, SeniorEnabled: &tr}); a.L2EnabledOrDefault() || a.SeniorEnabledOrDefault() {
		t.Error("l2_enabled:false must force L1-only (both L2 and Senior off)")
	}
}
