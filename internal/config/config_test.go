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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := *baseline
			// deep-copy the slices we mutate so sibling subtests don't share storage
			cfg.Response.ExcludedNamespaces = append([]string(nil), baseline.Response.ExcludedNamespaces...)
			cfg.Analyst.Subtasks.AvailableTypes = append([]string(nil), baseline.Analyst.Subtasks.AvailableTypes...)

			tt.mutate(&cfg)

			err := cfg.Validate()
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
