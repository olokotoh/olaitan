package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/config"
)

// validYAML is the minimum valid YAML body. Every field set to the
// repo-default shape so individual table-driven subtests can tweak one
// field without tripping unrelated validators.
const validYAML = `
detection:
  confidence_bands:
    watch: 40
    alert: 70
    act: 90
  baseline_window: 24h
response:
  excluded_namespaces:
    - kube-system
    - olaitan
analyst:
  provider: api
  api:
    endpoint: "https://llm.example.com"
    model: gpt-4
    api_key_secret: olaitan-llm
  local:
    endpoint: "http://ollama:11434"
    model: gemma:2b
  score_cap: 35
  timeout: 10s
  chain:
    enabled: false
    l1:
      prompt: config/prompts/l1-triage.tmpl
    l2:
      prompt: config/prompts/l2-review.tmpl
  subtasks:
    enabled: false
    max_per_assessment: 3
    severity_threshold: 70
    timeout: 10s
    available_types:
      - network_forensics
`

// writeYAML atomically replaces path with body using the same tmp +
// rename pattern the Kubernetes kubelet uses for projected ConfigMap
// volumes. Tests that simulate a reload rely on this semantic.
func writeYAML(t *testing.T, path, body string) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		t.Fatalf("write tmp: %v", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatalf("rename: %v", err)
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "olaitan.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestLoadHappyPath(t *testing.T) {
	path := writeConfig(t, validYAML)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Detection.ConfidenceBands.Watch != 40 ||
		cfg.Detection.ConfidenceBands.Alert != 70 ||
		cfg.Detection.ConfidenceBands.Act != 90 {
		t.Errorf("bands = %+v", cfg.Detection.ConfidenceBands)
	}
	if cfg.Detection.BaselineWindow.Duration() != 24*time.Hour {
		t.Errorf("baseline_window = %s", cfg.Detection.BaselineWindow.Duration())
	}
	if got := cfg.Response.ExcludedNamespaces; len(got) != 2 || got[0] != "kube-system" || got[1] != "olaitan" {
		t.Errorf("excluded_namespaces = %v", got)
	}
	if cfg.Analyst.Provider != "api" {
		t.Errorf("provider = %q", cfg.Analyst.Provider)
	}
	if cfg.Analyst.API.Endpoint != "https://llm.example.com" {
		t.Errorf("api.endpoint = %q", cfg.Analyst.API.Endpoint)
	}
	if cfg.Analyst.ScoreCap != 35 {
		t.Errorf("score_cap = %d", cfg.Analyst.ScoreCap)
	}
	if cfg.Analyst.Timeout.Duration() != 10*time.Second {
		t.Errorf("timeout = %s", cfg.Analyst.Timeout.Duration())
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := config.Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("err not os.ErrNotExist-wrapped: %v", err)
	}
	if !strings.HasPrefix(err.Error(), "config: open") {
		t.Errorf("err prefix = %q", err)
	}
}

func TestLoadBadYAML(t *testing.T) {
	path := writeConfig(t, "detection: [this is not a map")

	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected decode error")
	}
	if !strings.Contains(err.Error(), "config: decode") {
		t.Errorf("want decode wrap, got %q", err)
	}
}

func TestLoadUnknownKey(t *testing.T) {
	path := writeConfig(t, validYAML+"\nfoo: bar\n")

	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected unknown-key rejection")
	}
	if !strings.Contains(err.Error(), "config: decode") {
		t.Errorf("want decode wrap, got %q", err)
	}
	if !strings.Contains(err.Error(), "foo") {
		t.Errorf("want err to name %q, got %q", "foo", err)
	}
}

// TestValidateTable exercises every rule from AC3 by mutating one field
// of the known-valid baseline and asserting the error message names the
// offending field. Each subtest is parallel-safe.
func TestValidateTable(t *testing.T) {
	path := writeConfig(t, validYAML)
	baseline, err := config.Load(path)
	if err != nil {
		t.Fatalf("baseline Load: %v", err)
	}

	tests := []struct {
		name    string
		mutate  func(*config.Config)
		wantSub string
	}{
		{
			"baseline-window-zero",
			func(c *config.Config) { c.Detection.BaselineWindow = 0 },
			"detection.baseline_window",
		},
		{
			"baseline-window-negative",
			func(c *config.Config) { c.Detection.BaselineWindow = config.DurationYAML(-time.Second) },
			"detection.baseline_window",
		},
		{
			"band-watch-negative",
			func(c *config.Config) { c.Detection.ConfidenceBands.Watch = -1 },
			"detection.confidence_bands.watch",
		},
		{
			"band-alert-over-100",
			func(c *config.Config) { c.Detection.ConfidenceBands.Alert = 101 },
			"detection.confidence_bands.alert",
		},
		{
			"band-act-over-100",
			func(c *config.Config) { c.Detection.ConfidenceBands.Act = 200 },
			"detection.confidence_bands.act",
		},
		{
			"band-ordering-watch-ge-alert",
			func(c *config.Config) {
				c.Detection.ConfidenceBands.Watch = 80
				c.Detection.ConfidenceBands.Alert = 70
			},
			"watch(80) must be < alert(70)",
		},
		{
			"band-ordering-alert-ge-act",
			func(c *config.Config) {
				c.Detection.ConfidenceBands.Alert = 95
				c.Detection.ConfidenceBands.Act = 90
			},
			"alert(95) must be < act(90)",
		},
		{
			"excluded-ns-empty",
			func(c *config.Config) { c.Response.ExcludedNamespaces = []string{"ok", ""} },
			"response.excluded_namespaces",
		},
		{
			"excluded-ns-whitespace",
			func(c *config.Config) { c.Response.ExcludedNamespaces = []string{" kube-system"} },
			"whitespace",
		},
		{
			"provider-invalid",
			func(c *config.Config) { c.Analyst.Provider = "gemini" },
			"analyst.provider",
		},
		{
			"score-cap-negative",
			func(c *config.Config) { c.Analyst.ScoreCap = -1 },
			"analyst.score_cap",
		},
		{
			"score-cap-over-100",
			func(c *config.Config) { c.Analyst.ScoreCap = 101 },
			"analyst.score_cap",
		},
		{
			"analyst-timeout-zero",
			func(c *config.Config) { c.Analyst.Timeout = 0 },
			"analyst.timeout",
		},
		{
			"chain-enabled-empty-l1",
			func(c *config.Config) {
				c.Analyst.Chain.Enabled = true
				c.Analyst.Chain.L1.Prompt = ""
				c.Analyst.Chain.L2.Prompt = "x"
			},
			"analyst.chain.l1.prompt",
		},
		{
			"chain-enabled-empty-l2",
			func(c *config.Config) {
				c.Analyst.Chain.Enabled = true
				c.Analyst.Chain.L1.Prompt = "x"
				c.Analyst.Chain.L2.Prompt = ""
			},
			"analyst.chain.l2.prompt",
		},
		{
			"subtasks-max-zero",
			func(c *config.Config) {
				c.Analyst.Subtasks.Enabled = true
				c.Analyst.Subtasks.MaxPerAssessment = 0
			},
			"analyst.subtasks.max_per_assessment",
		},
		{
			"subtasks-severity-over-100",
			func(c *config.Config) {
				c.Analyst.Subtasks.Enabled = true
				c.Analyst.Subtasks.SeverityThreshold = 150
			},
			"analyst.subtasks.severity_threshold",
		},
		{
			"subtasks-timeout-zero",
			func(c *config.Config) {
				c.Analyst.Subtasks.Enabled = true
				c.Analyst.Subtasks.Timeout = 0
			},
			"analyst.subtasks.timeout",
		},
		{
			"subtasks-available-empty",
			func(c *config.Config) {
				c.Analyst.Subtasks.Enabled = true
				c.Analyst.Subtasks.AvailableTypes = nil
			},
			"analyst.subtasks.available_types",
		},
		{
			"calico-enabled-no-addr",
			func(c *config.Config) {
				c.Detection.Sources.Calico = config.CalicoSourceConfig{
					Enabled:        true,
					CABundlePath:   "/etc/olaitan/cni/ca.crt",
					ClientCertPath: "/etc/olaitan/cni/client.crt",
					ClientKeyPath:  "/etc/olaitan/cni/client.key",
				}
			},
			"detection.sources.calico.goldmane_addr",
		},
		{
			"calico-enabled-no-ca",
			func(c *config.Config) {
				c.Detection.Sources.Calico = config.CalicoSourceConfig{
					Enabled:        true,
					GoldmaneAddr:   "goldmane.calico-system.svc:7443",
					ClientCertPath: "/etc/olaitan/cni/client.crt",
					ClientKeyPath:  "/etc/olaitan/cni/client.key",
				}
			},
			"detection.sources.calico.ca_bundle_path",
		},
		{
			"calico-enabled-no-client-cert",
			func(c *config.Config) {
				c.Detection.Sources.Calico = config.CalicoSourceConfig{
					Enabled:       true,
					GoldmaneAddr:  "goldmane.calico-system.svc:7443",
					CABundlePath:  "/etc/olaitan/cni/ca.crt",
					ClientKeyPath: "/etc/olaitan/cni/client.key",
				}
			},
			"detection.sources.calico.client_cert_path",
		},
		{
			"calico-enabled-no-client-key",
			func(c *config.Config) {
				c.Detection.Sources.Calico = config.CalicoSourceConfig{
					Enabled:        true,
					GoldmaneAddr:   "goldmane.calico-system.svc:7443",
					CABundlePath:   "/etc/olaitan/cni/ca.crt",
					ClientCertPath: "/etc/olaitan/cni/client.crt",
				}
			},
			"detection.sources.calico.client_key_path",
		},
		{
			"calico-enabled-max-event-bytes-below-floor",
			func(c *config.Config) {
				c.Detection.Sources.Calico = config.CalicoSourceConfig{
					Enabled:        true,
					GoldmaneAddr:   "goldmane.calico-system.svc:7443",
					CABundlePath:   "/etc/olaitan/cni/ca.crt",
					ClientCertPath: "/etc/olaitan/cni/client.crt",
					ClientKeyPath:  "/etc/olaitan/cni/client.key",
					MaxEventBytes:  1024,
				}
			},
			"detection.sources.calico.max_event_bytes",
		},
		{
			"calico-disabled-zero-block-ok",
			func(c *config.Config) {
				// Zero block with Enabled=false must not error -- this is
				// the "operator hasn't touched the chart calicoSensor
				// block" baseline.
				c.Detection.Sources.Calico = config.CalicoSourceConfig{}
			},
			"", // empty wantSub: expect NO error.
		},
		{
			"calico-aggregation-interval-non-15-rejected",
			func(c *config.Config) {
				c.Detection.Sources.Calico = config.CalicoSourceConfig{
					Enabled:             true,
					GoldmaneAddr:        "goldmane.calico-system.svc:7443",
					CABundlePath:        "/etc/olaitan/cni/ca.crt",
					ClientCertPath:      "/etc/olaitan/cni/client.crt",
					ClientKeyPath:       "/etc/olaitan/cni/client.key",
					AggregationInterval: 30,
				}
			},
			"must be 15s per Goldmane proto",
		},
		{
			"calico-start-time-gte-positive-rejected",
			func(c *config.Config) {
				positive := int64(60)
				c.Detection.Sources.Calico = config.CalicoSourceConfig{
					Enabled:        true,
					GoldmaneAddr:   "goldmane.calico-system.svc:7443",
					CABundlePath:   "/etc/olaitan/cni/ca.crt",
					ClientCertPath: "/etc/olaitan/cni/client.crt",
					ClientKeyPath:  "/etc/olaitan/cni/client.key",
					StartTimeGte:   &positive,
				}
			},
			"start_time_gte: must be <= 0",
		},
		{
			"calico-start-time-gte-explicit-zero-ok",
			func(c *config.Config) {
				zero := int64(0)
				c.Detection.Sources.Calico = config.CalicoSourceConfig{
					Enabled:        true,
					GoldmaneAddr:   "goldmane.calico-system.svc:7443",
					CABundlePath:   "/etc/olaitan/cni/ca.crt",
					ClientCertPath: "/etc/olaitan/cni/client.crt",
					ClientKeyPath:  "/etc/olaitan/cni/client.key",
					StartTimeGte:   &zero,
				}
			},
			"", // explicit 0 reaches Goldmane's "now" semantic per proto line 91
		},
		{
			"calico-start-time-gte-negative-ok",
			func(c *config.Config) {
				neg := int64(-300)
				c.Detection.Sources.Calico = config.CalicoSourceConfig{
					Enabled:        true,
					GoldmaneAddr:   "goldmane.calico-system.svc:7443",
					CABundlePath:   "/etc/olaitan/cni/ca.crt",
					ClientCertPath: "/etc/olaitan/cni/client.crt",
					ClientKeyPath:  "/etc/olaitan/cni/client.key",
					StartTimeGte:   &neg,
				}
			},
			"", // negative is relative seconds; -300 = "last 5 minutes"
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := *baseline
			// deep-copy the slices we mutate so sibling subtests don't share storage
			cfg.Response.ExcludedNamespaces = append([]string(nil), baseline.Response.ExcludedNamespaces...)
			cfg.Analyst.Subtasks.AvailableTypes = append([]string(nil), baseline.Analyst.Subtasks.AvailableTypes...)

			tt.mutate(&cfg)

			err := cfg.Validate()
			if tt.wantSub == "" {
				// Sentinel for "this mutation must validate cleanly".
				if err != nil {
					t.Fatalf("unexpected validation error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected validation error containing %q", tt.wantSub)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("err %q missing %q", err, tt.wantSub)
			}
		})
	}
}

// TestDefaultConfigYAMLPasses guarantees the shipped config/olaitan.yaml
// is load-and-validate clean — the repo's public default must never
// drift out of sync with the loader's rules.
func TestDefaultConfigYAMLPasses(t *testing.T) {
	path := defaultConfigPath(t)
	if _, err := os.Stat(path); err != nil {
		t.Skipf("default config not reachable from %s: %v", path, err)
	}
	if _, err := config.Load(path); err != nil {
		t.Fatalf("shipped config failed to load: %v", err)
	}
}

// defaultConfigPath resolves ../../config/olaitan.yaml relative to the
// current test file so `go test` works no matter which cwd the runner
// chose. runtime.Caller keeps this portable between local runs and CI.
func defaultConfigPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "config", "olaitan.yaml")
}

// TestErrorWrapPattern — every exported exit must wrap with "config:"
// so log grep and errors.Is work uniformly.
func TestErrorWrapPattern(t *testing.T) {
	path := writeConfig(t, "detection:\n  baseline_window: -1s\n")
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected validate error")
	}
	if !strings.HasPrefix(err.Error(), "config:") {
		t.Errorf("err %q missing config: prefix", err)
	}
}

func TestDurationYAMLRejectsInteger(t *testing.T) {
	path := writeConfig(t, "detection:\n  confidence_bands: {watch: 40, alert: 70, act: 90}\n  baseline_window: 60\nresponse:\n  excluded_namespaces: []\nanalyst:\n  provider: api\n  score_cap: 35\n  timeout: 10s\n")
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected decode error for bare-int duration")
	}
	if !strings.Contains(err.Error(), "config: decode") {
		t.Errorf("want decode wrap, got %q", err)
	}
}

func TestProviderCaseInsensitive(t *testing.T) {
	body := strings.Replace(validYAML, "provider: api", "provider: API", 1)
	path := writeConfig(t, body)
	if _, err := config.Load(path); err != nil {
		t.Errorf("provider=API should validate (case-insensitive): %v", err)
	}
}

func TestPostureConfigOmittedAccepted(t *testing.T) {
	// Omitting the posture block should validate; it is omitempty
	// and downstream callers receive a zero-valued PostureConfig.
	path := writeConfig(t, validYAML)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Detection.Posture.Enabled {
		t.Errorf("Posture.Enabled: got true (default zero), want false")
	}
}

func TestCorrelatorConfigOmittedSubstitutesDefault(t *testing.T) {
	path := writeConfig(t, validYAML)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Detection.Correlator.WindowDuration.Duration() != 60*time.Second {
		t.Errorf("WindowDuration: got %s, want 60s", cfg.Detection.Correlator.WindowDuration.Duration())
	}
	if got := cfg.Detection.Correlator.MaxPackageBytesOrDefault(); got != 128*1024 {
		t.Errorf("MaxPackageBytes: got %d, want 131072", got)
	}
	if got := cfg.Detection.Correlator.MultiSignalMinSourcesOrDefault(); got != 2 {
		t.Errorf("MultiSignalMinSources: got %d, want 2", got)
	}
	if got := cfg.Detection.Correlator.HighSeverityThresholdOrDefault(); got != 50 {
		t.Errorf("HighSeverityThreshold: got %d, want 50", got)
	}
}

func TestCorrelatorConfigExplicitKnobsHonoured(t *testing.T) {
	body := strings.Replace(validYAML, "  baseline_window: 24h", "  baseline_window: 24h\n  correlator:\n    window_duration: 45s\n    max_package_bytes: 131072\n    multi_signal_min_sources: 3\n    high_severity_threshold: 60", 1)
	path := writeConfig(t, body)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Detection.Correlator.WindowDuration.Duration() != 45*time.Second {
		t.Errorf("WindowDuration: got %s, want 45s", cfg.Detection.Correlator.WindowDuration.Duration())
	}
	if got := cfg.Detection.Correlator.MultiSignalMinSourcesOrDefault(); got != 3 {
		t.Errorf("MultiSignalMinSources: got %d, want 3", got)
	}
}

// TestCorrelatorMaxPackageBytesExplicitZeroRejected covers the P24
// closure: an operator who explicitly sets max_package_bytes to 0
// must be rejected by Validate, not silently overridden by the Load
// default substitution.
func TestCorrelatorMaxPackageBytesExplicitZeroRejected(t *testing.T) {
	body := strings.Replace(validYAML, "  baseline_window: 24h", "  baseline_window: 24h\n  correlator:\n    max_package_bytes: 0", 1)
	path := writeConfig(t, body)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("Load: got nil, want rejection for explicit max_package_bytes=0")
	}
	if !strings.Contains(err.Error(), "max_package_bytes") {
		t.Errorf("error does not mention max_package_bytes: %v", err)
	}
}

// TestCorrelatorHighSeverityThresholdExplicitZeroPreserved covers P24:
// an operator who sets high_severity_threshold to 0 must have the
// explicit zero survive Load (0 is inside the [0,100] band), not be
// silently replaced by the default 50.
func TestCorrelatorHighSeverityThresholdExplicitZeroPreserved(t *testing.T) {
	body := strings.Replace(validYAML, "  baseline_window: 24h", "  baseline_window: 24h\n  correlator:\n    high_severity_threshold: 0", 1)
	path := writeConfig(t, body)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Detection.Correlator.HighSeverityThresholdOrDefault(); got != 0 {
		t.Errorf("HighSeverityThreshold: got %d, want 0 (explicit zero must be honoured)", got)
	}
}

// TestCorrelatorMultiSignalMinSourcesExplicitOneRejected covers P24:
// an explicit 1 must fail Validate's >=2 guard, not be silently
// replaced by the default 2.
func TestCorrelatorMultiSignalMinSourcesExplicitOneRejected(t *testing.T) {
	body := strings.Replace(validYAML, "  baseline_window: 24h", "  baseline_window: 24h\n  correlator:\n    multi_signal_min_sources: 1", 1)
	path := writeConfig(t, body)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("Load: got nil, want rejection for multi_signal_min_sources=1")
	}
	if !strings.Contains(err.Error(), "multi_signal_min_sources") {
		t.Errorf("error does not mention multi_signal_min_sources: %v", err)
	}
}

func TestCorrelatorConfigRejectsInvalidKnobs(t *testing.T) {
	cases := []struct {
		name   string
		block  string
		wantIn string
	}{
		{"negative window", "window_duration: -1s\n    max_package_bytes: 131072\n    multi_signal_min_sources: 2\n    high_severity_threshold: 50", "window_duration"},
		{"wrong cap", "window_duration: 60s\n    max_package_bytes: 65536\n    multi_signal_min_sources: 2\n    high_severity_threshold: 50", "max_package_bytes"},
		{"one source", "window_duration: 60s\n    max_package_bytes: 131072\n    multi_signal_min_sources: 1\n    high_severity_threshold: 50", "multi_signal_min_sources"},
		{"threshold high", "window_duration: 60s\n    max_package_bytes: 131072\n    multi_signal_min_sources: 2\n    high_severity_threshold: 101", "high_severity_threshold"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := strings.Replace(validYAML, "  baseline_window: 24h", "  baseline_window: 24h\n  correlator:\n    "+tc.block, 1)
			path := writeConfig(t, body)
			_, err := config.Load(path)
			if err == nil {
				t.Fatalf("Load: got nil, want error containing %q", tc.wantIn)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("error %q missing %q", err, tc.wantIn)
			}
		})
	}
}

func TestPostureConfigValidDefaults(t *testing.T) {
	body := strings.Replace(validYAML, "  baseline_window: 24h", "  baseline_window: 24h\n  posture:\n    enabled: true\n    cache_ttl: 60s\n    fetch_timeout: 5s", 1)
	path := writeConfig(t, body)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Detection.Posture.Enabled {
		t.Errorf("Posture.Enabled: got false, want true")
	}
	if cfg.Detection.Posture.CacheTTL.Duration() != 60*time.Second {
		t.Errorf("cache_ttl: got %s, want 60s", cfg.Detection.Posture.CacheTTL.Duration())
	}
}

func TestPostureConfigCacheTTLAboveCeilingRejected(t *testing.T) {
	body := strings.Replace(validYAML, "  baseline_window: 24h", "  baseline_window: 24h\n  posture:\n    enabled: true\n    cache_ttl: 90s\n    fetch_timeout: 5s", 1)
	path := writeConfig(t, body)
	_, err := config.Load(path)
	if err == nil {
		t.Fatalf("expected validate error for cache_ttl > 60s")
	}
	if !strings.Contains(err.Error(), "cache_ttl") {
		t.Errorf("err %q should mention cache_ttl", err)
	}
}

func TestPostureConfigNegativeFetchTimeoutRejected(t *testing.T) {
	body := strings.Replace(validYAML, "  baseline_window: 24h", "  baseline_window: 24h\n  posture:\n    enabled: true\n    cache_ttl: 60s\n    fetch_timeout: -1s", 1)
	path := writeConfig(t, body)
	_, err := config.Load(path)
	if err == nil {
		t.Fatalf("expected validate error for negative fetch_timeout")
	}
}

func TestPostureConfigZeroBlockWhenDisabledAccepted(t *testing.T) {
	body := strings.Replace(validYAML, "  baseline_window: 24h", "  baseline_window: 24h\n  posture:\n    enabled: false", 1)
	path := writeConfig(t, body)
	if _, err := config.Load(path); err != nil {
		t.Errorf("posture block with enabled:false should validate: %v", err)
	}
}

// TestMetricsConfigOmittedSubstitutesDefault asserts the Story 1.12
// default-on-omission behaviour: a chart-deploy that has not yet
// adopted the metrics block still gets a valid Address binding.
func TestMetricsConfigOmittedSubstitutesDefault(t *testing.T) {
	path := writeConfig(t, validYAML)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Metrics.Address != config.DefaultMetricsAddress {
		t.Errorf("Metrics.Address: got %q, want %q",
			cfg.Metrics.Address, config.DefaultMetricsAddress)
	}
}

// TestMetricsConfigExplicitAddressHonoured asserts the operator-set
// address survives Load.
func TestMetricsConfigExplicitAddressHonoured(t *testing.T) {
	body := validYAML + "\nmetrics:\n  address: \"127.0.0.1:9092\"\n"
	path := writeConfig(t, body)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Metrics.Address != "127.0.0.1:9092" {
		t.Errorf("Metrics.Address: got %q, want 127.0.0.1:9092", cfg.Metrics.Address)
	}
}

// TestMetricsConfigValidateRejectsEmptyAddress exercises Validate
// directly so the guardrail-27 invariant is locked in independent of
// the Load default-substitution. Callers that construct Config in
// memory (cmd/olaitan/metrics.go tests; future programmatic config
// builders) hit this path before the metrics server is started.
func TestMetricsConfigValidateRejectsEmptyAddress(t *testing.T) {
	// Reuse the validYAML path to construct a fully-populated Config,
	// then zero out the Metrics.Address to exercise Validate's
	// rejection independent of the Load default-substitution.
	path := writeConfig(t, validYAML)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cfg.Metrics.Address = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate with empty Metrics.Address: got nil, want rejection")
	} else if !strings.Contains(err.Error(), "metrics.address") {
		t.Errorf("error does not mention metrics.address: %v", err)
	}
}

// TestRateLimitOmittedSubstitutesDefault asserts the Story 1.13
// default-on-omission behaviour: a chart deploy that has not yet
// adopted the rate_limit block inherits the production defaults
// (enabled=true, threshold=1000, cooldown=60s, sampling_rate=0.1).
func TestRateLimitOmittedSubstitutesDefault(t *testing.T) {
	path := writeConfig(t, validYAML)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.RateLimit.EnabledOrDefault() {
		t.Errorf("RateLimit.Enabled: got false, want true (default)")
	}
	if cfg.RateLimit.ThresholdEventsPerSec != 1000 {
		t.Errorf("RateLimit.ThresholdEventsPerSec: got %d, want 1000", cfg.RateLimit.ThresholdEventsPerSec)
	}
	if cfg.RateLimit.CooldownSeconds != 60 {
		t.Errorf("RateLimit.CooldownSeconds: got %d, want 60", cfg.RateLimit.CooldownSeconds)
	}
	if cfg.RateLimit.SamplingRate != 0.1 {
		t.Errorf("RateLimit.SamplingRate: got %v, want 0.1", cfg.RateLimit.SamplingRate)
	}
}

// TestRateLimitExplicitlySetHonoured asserts operator-set knobs survive
// Load and Validate; the per-knob default substitution must not
// overwrite a value the operator deliberately tuned.
func TestRateLimitExplicitlySetHonoured(t *testing.T) {
	body := validYAML + "\nrate_limit:\n  enabled: true\n  threshold_events_per_sec: 500\n  cooldown_seconds: 30\n  sampling_rate: 0.05\n"
	path := writeConfig(t, body)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.RateLimit.ThresholdEventsPerSec != 500 {
		t.Errorf("threshold: got %d, want 500", cfg.RateLimit.ThresholdEventsPerSec)
	}
	if cfg.RateLimit.CooldownSeconds != 30 {
		t.Errorf("cooldown: got %d, want 30", cfg.RateLimit.CooldownSeconds)
	}
	if cfg.RateLimit.SamplingRate != 0.05 {
		t.Errorf("sampling_rate: got %v, want 0.05", cfg.RateLimit.SamplingRate)
	}
	if !cfg.RateLimit.EnabledOrDefault() {
		t.Errorf("enabled: got false, want true")
	}
}

// TestRateLimitDisabledShortCircuitsValidation asserts an operator can
// disable the breaker without satisfying the (0, 1] sampling-rate
// bound; the runtime layer short-circuits to "publish unmodified" so
// the validator should not block a sampling_rate=0 disable.
func TestRateLimitDisabledShortCircuitsValidation(t *testing.T) {
	body := validYAML + "\nrate_limit:\n  enabled: false\n  threshold_events_per_sec: 0\n  cooldown_seconds: 0\n  sampling_rate: 0\n"
	path := writeConfig(t, body)
	if _, err := config.Load(path); err != nil {
		t.Fatalf("Load: got %v, want nil (disabled state should not require positive thresholds)", err)
	}
}

// TestRateLimitValidateRejectsBadKnobs covers the four invariants:
// threshold >= 1, cooldown >= 1, sampling_rate in (0, 1].
func TestRateLimitValidateRejectsBadKnobs(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		wantIn string
	}{
		{
			"threshold zero when enabled",
			validYAML + "\nrate_limit:\n  enabled: true\n  threshold_events_per_sec: 0\n  cooldown_seconds: 60\n  sampling_rate: 0.1\n",
			"threshold_events_per_sec",
		},
		{
			"cooldown zero when enabled",
			validYAML + "\nrate_limit:\n  enabled: true\n  threshold_events_per_sec: 1000\n  cooldown_seconds: 0\n  sampling_rate: 0.1\n",
			"cooldown_seconds",
		},
		{
			"sampling_rate above 1",
			validYAML + "\nrate_limit:\n  enabled: true\n  threshold_events_per_sec: 1000\n  cooldown_seconds: 60\n  sampling_rate: 1.5\n",
			"sampling_rate",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			path := writeConfig(t, tc.body)
			_, err := config.Load(path)
			if err == nil {
				t.Fatal("Load: got nil, want rejection")
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("error does not mention %q: %v", tc.wantIn, err)
			}
		})
	}

	// Direct Validate exercise: zero ints survive default substitution
	// at Load, so prove the validator catches them when in-memory
	// callers construct a Config.
	t.Run("validate directly rejects zero threshold when enabled", func(t *testing.T) {
		enabled := true
		c := &config.Config{
			Detection: config.DetectionConfig{
				ConfidenceBands: config.ConfidenceBands{Watch: 40, Alert: 70, Act: 90},
				BaselineWindow:  config.DurationYAML(24 * time.Hour),
				Correlator:      config.DefaultCorrelator(),
			},
			Analyst: config.AnalystConfig{
				Provider: "api",
				ScoreCap: 35,
				Timeout:  config.DurationYAML(10 * time.Second),
			},
			Metrics: config.MetricsConfig{Address: ":9090"},
			RateLimit: config.RateLimitConfig{
				Enabled:               &enabled,
				ThresholdEventsPerSec: 0,
				CooldownSeconds:       60,
				SamplingRate:          0.1,
			},
		}
		if err := c.Validate(); err == nil {
			t.Fatal("Validate with zero threshold + enabled: got nil, want rejection")
		} else if !strings.Contains(err.Error(), "threshold_events_per_sec") {
			t.Errorf("error: %v", err)
		}
	})
}

func TestRateLimitUnknownKeyRejected(t *testing.T) {
	path := writeConfig(t, validYAML+"\nrate_limit:\n  threshold_events_per_second: 500\n")
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("Load: got nil, want unknown-key rejection")
	}
	if !strings.Contains(err.Error(), "threshold_events_per_second") {
		t.Errorf("error does not mention unknown key: %v", err)
	}
}
