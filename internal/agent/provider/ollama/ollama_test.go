package ollama

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
	"unicode/utf8"

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
	if _, err := New(Config{}, metrics.NewRegistry(), nil, discardLogger()); !errors.Is(err, ErrNoModel) {
		t.Errorf("empty model: err = %v, want ErrNoModel (operator must pin the provisioned model, BI-3.2)", err)
	}
	var nilReg *metrics.Registry
	if _, err := New(validConfig(), nilReg, nil, discardLogger()); err == nil {
		t.Error("nil registry: err = nil, want metric-registration error")
	}
}

// TestNewRejectsBadEndpoint: a relative, scheme-less, non-http(s), or
// userinfo-bearing endpoint must fail at construction (fail-fast) and
// the error must never echo the offending value (Story 3.3 round-1
// lesson, binding per BI-2.5).
func TestNewRejectsBadEndpoint(t *testing.T) {
	cases := []struct{ name, endpoint string }{
		{"scheme-less", "ollama.olaitan.svc:11434"},
		{"relative path", "/api"},
		{"unparseable", "://nope"},
		{"non-http scheme", "grpc://host:11434"},
		{"userinfo credentials", "http://user:secret-cred@host:11434"},
		{"query string", "http://host:11434?keep_alive=5m"},
		{"bare query", "http://host:11434?"},
		{"fragment", "http://host:11434#frag"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(Config{Model: "test-model", Endpoint: tc.endpoint}, metrics.NewRegistry(), nil, discardLogger())
			if !errors.Is(err, ErrBadEndpoint) {
				t.Fatalf("New(Endpoint=%q): err = %v, want ErrBadEndpoint", tc.endpoint, err)
			}
			if strings.Contains(err.Error(), "secret-cred") {
				t.Error("constructor error echoes the endpoint userinfo credential")
			}
		})
	}
}

func TestNewDefaultsAndAccessors(t *testing.T) {
	p, err := New(validConfig(), metrics.NewRegistry(), nil, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := p.Name(); got != "ollama" {
		t.Errorf("Name() = %q, want ollama (the family identity)", got)
	}
	if got := p.Model(); got != "test-model" {
		t.Errorf("Model() = %q", got)
	}
	if got := p.ScoreCap(); got != DefaultScoreCap {
		t.Errorf("ScoreCap() = %d, want the Ollama-tier default %d (AC2)", got, DefaultScoreCap)
	}
	if got := p.MaxContextTokens(); got != DefaultMaxContextTokens {
		t.Errorf("MaxContextTokens() = %d, want the num_ctx-honest default %d (BI-3.4)", got, DefaultMaxContextTokens)
	}
	if p.SupportsStreaming() {
		t.Error("SupportsStreaming() = true, want false (Phase-3 flag)")
	}
	if p.endpoint != DefaultEndpoint {
		t.Errorf("endpoint = %q, want default %q (AC1)", p.endpoint, DefaultEndpoint)
	}
	if p.numPredict != DefaultNumPredict {
		t.Errorf("numPredict = %d, want %d", p.numPredict, DefaultNumPredict)
	}

	p2, err := New(Config{Model: "m", Endpoint: "http://host:11434/", NumPredict: 64, ScoreCap: 10, MaxContextTokens: 8192}, metrics.NewRegistry(), nil, discardLogger())
	if err != nil {
		t.Fatalf("New explicit: %v", err)
	}
	if p2.endpoint != "http://host:11434" {
		t.Errorf("trailing slash not normalised: %q", p2.endpoint)
	}
	if p2.numPredict != 64 || p2.ScoreCap() != 10 || p2.MaxContextTokens() != 8192 {
		t.Errorf("explicit knobs not honoured: numPredict=%d scoreCap=%d maxCtx=%d", p2.numPredict, p2.ScoreCap(), p2.MaxContextTokens())
	}
}

// TestConstructionLogFields: the NFR18 log carries provider, model,
// endpoint, num_predict, audit_sink_wired and deliberately NO
// api_key_set field (no credential exists for this provider, BI-3.1).
func TestConstructionLogFields(t *testing.T) {
	var buf bytes.Buffer
	if _, err := New(validConfig(), metrics.NewRegistry(), nil, slog.New(slog.NewJSONHandler(&buf, nil))); err != nil {
		t.Fatalf("New: %v", err)
	}
	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("unmarshal construction log: %v", err)
	}
	for _, key := range []string{"provider", "model", "endpoint", "num_predict", "audit_sink_wired"} {
		if _, ok := entry[key]; !ok {
			t.Errorf("construction log missing %q", key)
		}
	}
	if _, ok := entry["api_key_set"]; ok {
		t.Error("construction log carries api_key_set; no credential exists for this provider (BI-3.1)")
	}
	if got := entry["provider"]; got != "ollama" {
		t.Errorf("provider field = %v, want ollama", got)
	}
}

func TestClassification(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		permanent bool
	}{
		{"400 bad request", &apiError{StatusCode: 400}, true},
		{"401 unauthorized", &apiError{StatusCode: 401}, true},
		{"404 model not provisioned", &apiError{StatusCode: 404}, true},
		{"413 too large", &apiError{StatusCode: 413}, true},
		{"408 request timeout", &apiError{StatusCode: 408}, false},
		{"429 rate limit", &apiError{StatusCode: 429}, false},
		{"500 internal", &apiError{StatusCode: 500}, false},
		{"503 unavailable", &apiError{StatusCode: 503}, false},
		{"301 redirect surfaced", &apiError{StatusCode: 301}, false},
		{"wrapped 404", fmt.Errorf("outer: %w", &apiError{StatusCode: 404}), true},
		{"plain transport error", errors.New("dial tcp: connection refused"), false},
		{"nil-adjacent decode error", errors.New("ollama: missing message in 200 response"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPermanent(tc.err); got != tc.permanent {
				t.Errorf("isPermanent(%v) = %v, want %v", tc.err, got, tc.permanent)
			}
		})
	}
}

// TestSanitizeSnippet: control characters flattened, bounded rune-safe
// cut (at an ODD byte offset so the UTF-8 guard actually bites - the
// Story 3.3 round-2 lesson). No key scrub exists: no key exists.
func TestSanitizeSnippet(t *testing.T) {
	got := sanitizeSnippet([]byte("line1\r\nline2\x00 tail"))
	if strings.ContainsAny(got, "\r\n\x00") {
		t.Errorf("snippet = %q, want control characters flattened", got)
	}

	long := "x" + strings.Repeat("é", maxErrorBodyBytes)
	got = sanitizeSnippet([]byte(long))
	if len(got) > maxErrorBodyBytes {
		t.Errorf("snippet length = %d, want <= %d", len(got), maxErrorBodyBytes)
	}
	if !utf8.ValidString(got) {
		t.Error("snippet is not valid UTF-8 after the length cut")
	}
}

func TestAnalyseInvalidRoleRecordsNoSeries(t *testing.T) {
	reg := metrics.NewRegistry()
	p, err := New(validConfig(), reg, nil, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := p.Analyse(context.Background(), provider.Request{Role: provider.Role("unbounded")}); err == nil {
		t.Fatal("Analyse with invalid role: err = nil, want rejection")
	}
	mfs, err := reg.Gatherer().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == provider.CallsMetricName && len(mf.GetMetric()) != 0 {
			t.Error("invalid role produced a metric series; the label set must stay bounded")
		}
	}
}
