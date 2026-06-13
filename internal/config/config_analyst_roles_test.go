package config_test

import (
	"strings"
	"testing"

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
