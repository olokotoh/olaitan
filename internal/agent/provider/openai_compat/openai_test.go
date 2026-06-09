package openaicompat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/olokotoh/olaitan/internal/agent/provider"
	"github.com/olokotoh/olaitan/internal/metrics"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

func validConfig() Config {
	return Config{Model: "test-model"}
}

func TestNewValidation(t *testing.T) {
	if _, err := New(validConfig(), "", metrics.NewRegistry(), nil, discardLogger()); !errors.Is(err, ErrNoAPIKey) {
		t.Errorf("empty key: err = %v, want ErrNoAPIKey", err)
	}
	if _, err := New(Config{}, "test-key", metrics.NewRegistry(), nil, discardLogger()); !errors.Is(err, ErrNoModel) {
		t.Errorf("empty model: err = %v, want ErrNoModel (no cross-vendor default exists, BI-4.1)", err)
	}
	var nilReg *metrics.Registry
	if _, err := New(validConfig(), "test-key", nilReg, nil, discardLogger()); err == nil {
		t.Error("nil registry: err = nil, want metric-registration error")
	}
}

func TestNewDefaultsAndAccessors(t *testing.T) {
	p, err := New(validConfig(), "test-key", metrics.NewRegistry(), nil, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := p.Name(); got != "openai" {
		t.Errorf("Name() = %q, want openai (the family identity, not the package name)", got)
	}
	if got := p.Model(); got != "test-model" {
		t.Errorf("Model() = %q", got)
	}
	if got := p.MaxContextTokens(); got != DefaultMaxContextTokens {
		t.Errorf("MaxContextTokens() = %d, want %d", got, DefaultMaxContextTokens)
	}
	if got := p.ScoreCap(); got != DefaultScoreCap {
		t.Errorf("ScoreCap() = %d, want %d", got, DefaultScoreCap)
	}
	if p.SupportsStreaming() {
		t.Error("SupportsStreaming() = true, want false (Phase-3 flag)")
	}
	if p.baseURL != DefaultBaseURL {
		t.Errorf("baseURL = %q, want default %q", p.baseURL, DefaultBaseURL)
	}
}

func TestNewConfigOverridesAndNormalisation(t *testing.T) {
	p, err := New(Config{
		Model:            "vendor/model-x",
		BaseURL:          "https://api.together.xyz/v1///",
		MaxTokens:        1024,
		ScoreCap:         20,
		MaxContextTokens: 32_000,
	}, "test-key", metrics.NewRegistry(), nil, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p.baseURL != "https://api.together.xyz/v1" {
		t.Errorf("baseURL not normalised: %q", p.baseURL)
	}
	if p.maxTokens != 1024 || p.ScoreCap() != 20 || p.MaxContextTokens() != 32_000 {
		t.Errorf("overrides not honoured: maxTokens=%d scoreCap=%d maxCtx=%d", p.maxTokens, p.ScoreCap(), p.MaxContextTokens())
	}
	// Negative values coerce to defaults, mirroring the Claude provider.
	p2, err := New(Config{Model: "m", MaxTokens: -1, ScoreCap: -1, MaxContextTokens: -1}, "k", metrics.NewRegistry(), nil, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p2.maxTokens != DefaultMaxTokens || p2.ScoreCap() != DefaultScoreCap || p2.MaxContextTokens() != DefaultMaxContextTokens {
		t.Errorf("negative coercion broken: %d/%d/%d", p2.maxTokens, p2.ScoreCap(), p2.MaxContextTokens())
	}
}

// TestIsPermanentClassificationTable proves the shared BI-2.4 table row by
// row on the typed *apiError status code, never substring matching.
func TestIsPermanentClassificationTable(t *testing.T) {
	cases := []struct {
		status int
		want   bool
	}{
		{400, true},
		{401, true},
		{403, true},
		{404, true},
		{413, true},
		{408, false},
		{429, false},
		{500, false},
		{502, false},
		{503, false},
		{529, false},
	}
	for _, tc := range cases {
		err := &apiError{StatusCode: tc.status, Snippet: "x"}
		if got := isPermanent(err); got != tc.want {
			t.Errorf("isPermanent(%d) = %v, want %v", tc.status, got, tc.want)
		}
		wrapped := fmt.Errorf("attempt failed: %w", err)
		if got := isPermanent(wrapped); got != tc.want {
			t.Errorf("isPermanent(wrapped %d) = %v, want %v", tc.status, got, tc.want)
		}
	}
	if isPermanent(errors.New("dial tcp: connection refused")) {
		t.Error("transport error classified permanent, want transient")
	}
	if isPermanent(nil) {
		t.Error("isPermanent(nil) = true")
	}
}

func TestConstructionLogNeverContainsAPIKey(t *testing.T) {
	const sentinel = "SENTINEL-OPENAI-KEY-c2VjcmV0LXZhbHVl"
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	if _, err := New(validConfig(), sentinel, metrics.NewRegistry(), nil, log); err != nil {
		t.Fatalf("New: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, sentinel) {
		t.Fatalf("construction log contains the API key (NFR18 violation): %s", out)
	}
	if !strings.Contains(out, `"api_key_set":true`) {
		t.Errorf("construction log missing api_key_set boolean: %s", out)
	}
}

func TestInvalidRoleRejectedWithoutMetricSeries(t *testing.T) {
	reg := metrics.NewRegistry()
	p, err := New(validConfig(), "test-key", reg, nil, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = p.Analyse(context.Background(), provider.Request{Role: provider.Role("bogus")})
	if err == nil || !strings.Contains(err.Error(), "invalid analyst role") {
		t.Fatalf("Analyse(bogus role) err = %v, want invalid-role error", err)
	}
	mfs, gerr := reg.Gatherer().Gather()
	if gerr != nil {
		t.Fatalf("gather: %v", gerr)
	}
	for _, mf := range mfs {
		if mf.GetName() == provider.CallsMetricName && len(mf.GetMetric()) != 0 {
			t.Errorf("invalid-role call minted %d metric series, want 0", len(mf.GetMetric()))
		}
	}
}

// chatWireText decodes a /chat/completions request body and returns the
// concatenated message contents the model would see.
func chatWireText(t *testing.T, body []byte) string {
	t.Helper()
	var wire struct {
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatalf("unmarshal wire body: %v", err)
	}
	var sb strings.Builder
	for _, m := range wire.Messages {
		sb.WriteString(m.Content)
		sb.WriteString("\n")
	}
	return sb.String()
}
