package config_test

import (
	"strings"
	"testing"

	"github.com/olokotoh/olaitan/internal/config"
)

// notificationsBaseYAML is the minimal valid config the Story 4.8
// notification-webhook tests overlay a response.notifications block onto.
const notificationsBaseYAML = `detection:
  confidence_bands: {watch: 40, alert: 70, act: 90}
  baseline_window: "1h"
response:
  excluded_namespaces: []
analyst:
  provider: api
  score_cap: 35
  timeout: 10s
`

// TestNotificationsConfig_Defaults: the gate defaults to OFF (opt-in) and the
// retry/timeout knobs default to the ollama-style values (5 / 1s / 30s / 5s).
func TestNotificationsConfig_Defaults(t *testing.T) {
	if config.DefaultNotifications().EnabledOrDefault() {
		t.Fatal("default notifications gate must be disabled (opt-in)")
	}
	var empty config.NotificationsConfig
	if empty.EnabledOrDefault() {
		t.Fatal("nil Enabled must default to false")
	}
	def := config.DefaultNotifications()
	if def.RetryMaxAttemptsOrDefault() != 5 {
		t.Errorf("default retry_max_attempts = %d, want 5", def.RetryMaxAttemptsOrDefault())
	}
	if def.RetryMinSecondsOrDefault() != 1 {
		t.Errorf("default retry_min_seconds = %d, want 1", def.RetryMinSecondsOrDefault())
	}
	if def.RetryMaxSecondsOrDefault() != 30 {
		t.Errorf("default retry_max_seconds = %d, want 30", def.RetryMaxSecondsOrDefault())
	}
	if def.TimeoutSecondsOrDefault() != 5 {
		t.Errorf("default timeout_seconds = %d, want 5", def.TimeoutSecondsOrDefault())
	}
	// An omitted block loaded through config.Load also defaults off with the
	// knobs substituted.
	cfg, err := config.Load(writeConfig(t, notificationsBaseYAML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Response.Notifications.EnabledOrDefault() {
		t.Fatal("an omitted notifications block must default to disabled")
	}
	if cfg.Response.Notifications.RetryMaxAttemptsOrDefault() != 5 {
		t.Errorf("loaded default retry_max_attempts = %d, want 5", cfg.Response.Notifications.RetryMaxAttemptsOrDefault())
	}
}

// notificationsGateYAML overlays a full response.notifications block.
func notificationsGateYAML(body string) string {
	return notificationsBaseYAML[:strings.Index(notificationsBaseYAML, "analyst:")] +
		"  notifications:\n" + body +
		notificationsBaseYAML[strings.Index(notificationsBaseYAML, "analyst:"):]
}

// TestNotificationsConfig_EnabledSurvives: an explicit response.notifications.
// enabled survives the loader in both directions (the *bool falsy guarantee).
func TestNotificationsConfig_EnabledSurvives(t *testing.T) {
	on, err := config.Load(writeConfig(t, notificationsGateYAML("    enabled: true\n    webhook_url: \"https://hooks.example.com/services/abc\"\n")))
	if err != nil {
		t.Fatalf("Load enabled: %v", err)
	}
	if !on.Response.Notifications.EnabledOrDefault() {
		t.Fatal("explicit notifications.enabled: true must be honoured")
	}
	if on.Response.Notifications.WebhookURL != "https://hooks.example.com/services/abc" {
		t.Errorf("webhook_url = %q", on.Response.Notifications.WebhookURL)
	}

	off, err := config.Load(writeConfig(t, notificationsGateYAML("    enabled: false\n")))
	if err != nil {
		t.Fatalf("Load disabled: %v", err)
	}
	if off.Response.Notifications.Enabled == nil || *off.Response.Notifications.Enabled {
		t.Fatalf("explicit notifications.enabled: false must decode to a non-nil false, got %v", off.Response.Notifications.Enabled)
	}
}

// TestNotificationsConfig_KnobsParseAndDefault: the retry/timeout knobs parse
// when set and inherit the defaults when omitted.
func TestNotificationsConfig_KnobsParseAndDefault(t *testing.T) {
	cfg, err := config.Load(writeConfig(t, notificationsGateYAML(
		"    enabled: true\n"+
			"    webhook_url: \"https://hooks.example.com/x\"\n"+
			"    retry_max_attempts: 3\n"+
			"    retry_min_seconds: 2\n"+
			"    retry_max_seconds: 20\n"+
			"    timeout_seconds: 8\n")))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	n := cfg.Response.Notifications
	if n.RetryMaxAttemptsOrDefault() != 3 || n.RetryMinSecondsOrDefault() != 2 ||
		n.RetryMaxSecondsOrDefault() != 20 || n.TimeoutSecondsOrDefault() != 8 {
		t.Errorf("knobs did not parse: %d/%d/%d/%d", n.RetryMaxAttemptsOrDefault(),
			n.RetryMinSecondsOrDefault(), n.RetryMaxSecondsOrDefault(), n.TimeoutSecondsOrDefault())
	}
}

// TestNotificationsConfig_RejectsNonPositiveKnob: a non-positive retry knob is a
// load-time error.
func TestNotificationsConfig_RejectsNonPositiveKnob(t *testing.T) {
	_, err := config.Load(writeConfig(t, notificationsGateYAML(
		"    enabled: true\n    webhook_url: \"https://hooks.example.com/x\"\n    retry_max_attempts: 0\n")))
	if err == nil {
		t.Fatal("Load: a non-positive retry_max_attempts must be rejected")
	}
	if !strings.Contains(err.Error(), "retry_max_attempts") {
		t.Errorf("error does not name the offending field: %v", err)
	}
}

// TestNotificationsConfig_RejectsMalformedURL: a non-http(s) webhook_url is a
// load-time error.
func TestNotificationsConfig_RejectsMalformedURL(t *testing.T) {
	_, err := config.Load(writeConfig(t, notificationsGateYAML(
		"    enabled: true\n    webhook_url: \"not-a-url\"\n")))
	if err == nil {
		t.Fatal("Load: a malformed webhook_url must be rejected")
	}
	if !strings.Contains(err.Error(), "webhook_url") {
		t.Errorf("error does not name the offending field: %v", err)
	}
}

// TestNotificationsConfig_RejectsMaxLessThanMin: retry_max_seconds below
// retry_min_seconds is a load-time error.
func TestNotificationsConfig_RejectsMaxLessThanMin(t *testing.T) {
	_, err := config.Load(writeConfig(t, notificationsGateYAML(
		"    enabled: true\n    webhook_url: \"https://hooks.example.com/x\"\n    retry_min_seconds: 30\n    retry_max_seconds: 5\n")))
	if err == nil {
		t.Fatal("Load: retry_max_seconds < retry_min_seconds must be rejected")
	}
	if !strings.Contains(err.Error(), "retry_max_seconds") {
		t.Errorf("error does not name the offending field: %v", err)
	}
}
