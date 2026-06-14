package config_test

import (
	"strings"
	"testing"

	"github.com/olokotoh/olaitan/internal/config"
)

const dfirBaseYAML = `detection:
  confidence_bands: {watch: 40, alert: 70, act: 90}
  baseline_window: "1h"
response:
  excluded_namespaces: []
analyst:
  provider: api
  score_cap: 35
  timeout: 10s
`

// TestAnalystDFIRRoleDecode pins that the Story 4.4 analyst.dfir_provider /
// analyst.dfir_model knobs decode through config.Load with their flat yaml
// keys, mirroring the L1/L2/Senior per-role routing fields.
func TestAnalystDFIRRoleDecode(t *testing.T) {
	yaml := dfirBaseYAML +
		"  dfir_provider: claude\n" +
		"  dfir_model: claude-opus-4-8\n"
	cfg, err := config.Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Analyst.DFIRProvider != "claude" || cfg.Analyst.DFIRModel != "claude-opus-4-8" {
		t.Errorf("dfir = %q/%q, want claude/claude-opus-4-8", cfg.Analyst.DFIRProvider, cfg.Analyst.DFIRModel)
	}
}

// TestAnalystDFIRRoleDefaults: an omitted dfir block leaves both knobs empty
// (the DFIR provider inherits the top-level mapping at the wiring layer).
func TestAnalystDFIRRoleDefaults(t *testing.T) {
	cfg, err := config.Load(writeConfig(t, dfirBaseYAML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Analyst.DFIRProvider != "" || cfg.Analyst.DFIRModel != "" {
		t.Errorf("unset dfir knobs must be empty, got %q/%q", cfg.Analyst.DFIRProvider, cfg.Analyst.DFIRModel)
	}
}

// TestAnalystDFIRProviderEnumRejected: a dfir_provider outside the
// {claude, openai, ollama, none, ""} enum is a load-time error.
func TestAnalystDFIRProviderEnumRejected(t *testing.T) {
	yaml := dfirBaseYAML + "  dfir_provider: bogus\n"
	_, err := config.Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("Load: got nil, want rejection of dfir_provider: bogus")
	}
	if !strings.Contains(err.Error(), "dfir_provider") {
		t.Errorf("error does not name the offending field: %v", err)
	}
}

// TestDFIRConfig_Defaults: the gate defaults to OFF (opt-in).
func TestDFIRConfig_Defaults(t *testing.T) {
	if config.DefaultDFIR().EnabledOrDefault() {
		t.Fatal("default DFIR gate must be disabled (opt-in)")
	}
	var empty config.DFIRConfig
	if empty.EnabledOrDefault() {
		t.Fatal("nil Enabled must default to false")
	}
}

// dfirGateYAML builds a config with response.dfir.enabled set to enabled.
func dfirGateYAML(enabled string) string {
	return `detection:
  confidence_bands: {watch: 40, alert: 70, act: 90}
  baseline_window: "1h"
response:
  excluded_namespaces: []
  dfir:
    enabled: ` + enabled + `
analyst:
  provider: api
  score_cap: 35
  timeout: 10s
`
}

// TestDFIRConfig_EnabledSurvives: an explicit response.dfir.enabled survives
// the loader (the *bool falsy-value guarantee) in both directions.
func TestDFIRConfig_EnabledSurvives(t *testing.T) {
	on, err := config.Load(writeConfig(t, dfirGateYAML("true")))
	if err != nil {
		t.Fatalf("Load enabled: %v", err)
	}
	if !on.Response.DFIR.EnabledOrDefault() {
		t.Fatal("explicit dfir.enabled: true must be honoured")
	}

	off, err := config.Load(writeConfig(t, dfirGateYAML("false")))
	if err != nil {
		t.Fatalf("Load disabled: %v", err)
	}
	if off.Response.DFIR.Enabled == nil || *off.Response.DFIR.Enabled {
		t.Fatalf("explicit dfir.enabled: false must decode to a non-nil false, got %v", off.Response.DFIR.Enabled)
	}
}
