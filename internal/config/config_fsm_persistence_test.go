package config_test

import (
	"testing"

	"github.com/olokotoh/olaitan/internal/config"
)

// TestFSMConfig_PersistenceDefaultsOnOmittedBlock pins the Story 2.3
// default-on-omission behaviour: an operator who omits the persistence
// knobs inherits enabled=true and the canonical Redis address after Load.
func TestFSMConfig_PersistenceDefaultsOnOmittedBlock(t *testing.T) {
	cfg, err := config.Load(writeConfig(t, validYAML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	f := cfg.Detection.FSM
	if !f.PersistenceEnabledOrDefault() {
		t.Error("PersistenceEnabledOrDefault() = false, want true on omission")
	}
	if got := f.RedisAddrOrDefault(); got != "redis:6379" {
		t.Errorf("RedisAddrOrDefault() = %q, want redis:6379", got)
	}
	if f.PersistenceEnabled == nil || f.RedisAddr == "" {
		t.Error("Load left FSM persistence fields unset; defaults must be substituted before Validate")
	}
}

// TestFSMConfig_PersistenceExplicitDisabledSurvives pins that an explicit
// persistence_enabled: false is not overwritten by the default.
func TestFSMConfig_PersistenceExplicitDisabledSurvives(t *testing.T) {
	body := `
detection:
  confidence_bands:
    watch: 20
    alert: 40
    act: 70
  baseline_window: 24h
  fsm:
    persistence_enabled: false
response:
  excluded_namespaces: []
analyst:
  provider: api
  score_cap: 35
  timeout: 10s
`
	cfg, err := config.Load(writeConfig(t, body))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Detection.FSM.PersistenceEnabledOrDefault() {
		t.Error("explicit persistence_enabled: false was overwritten to true")
	}
}

// TestFSMConfig_RejectsPersistenceEnabledWithoutRedisAddr pins the
// fail-fast: persistence enabled with an empty Redis address is invalid.
func TestFSMConfig_RejectsPersistenceEnabledWithoutRedisAddr(t *testing.T) {
	cfg, err := config.Load(writeConfig(t, validYAML))
	if err != nil {
		t.Fatalf("Load base: %v", err)
	}
	enabled := true
	cfg.Detection.FSM.PersistenceEnabled = &enabled
	cfg.Detection.FSM.RedisAddr = ""
	if verr := cfg.Validate(); verr == nil {
		t.Fatal("expected validate error: persistence enabled with empty redis_addr")
	}
}

// TestFSMConfig_PersistenceAccessors covers the pure accessor semantics.
func TestFSMConfig_PersistenceAccessors(t *testing.T) {
	var zero config.FSMConfig
	if !zero.PersistenceEnabledOrDefault() {
		t.Error("nil PersistenceEnabled should default to true")
	}
	if got := zero.RedisAddrOrDefault(); got != "redis:6379" {
		t.Errorf("zero RedisAddrOrDefault() = %q, want redis:6379", got)
	}
	f := false
	if (config.FSMConfig{PersistenceEnabled: &f}).PersistenceEnabledOrDefault() {
		t.Error("explicit false should report false")
	}
}
