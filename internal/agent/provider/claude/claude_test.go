package claude

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
	"time"

	"github.com/anthropics/anthropic-sdk-go"

	"github.com/olokotoh/olaitan/internal/agent/provider"
	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/schema"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

// wireText decodes a /v1/messages request body and returns the
// concatenated system + user text the model would actually see. Asserting
// on the decoded text (not the raw bytes) keeps the checks independent of
// encoding/json's HTML escaping of < and >.
func wireText(t *testing.T, body []byte) string {
	t.Helper()
	var wire struct {
		System []struct {
			Text string `json:"text"`
		} `json:"system"`
		Messages []struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatalf("unmarshal wire body: %v", err)
	}
	var sb strings.Builder
	for _, s := range wire.System {
		sb.WriteString(s.Text)
		sb.WriteString("\n")
	}
	for _, m := range wire.Messages {
		for _, c := range m.Content {
			if c.Type == "text" {
				sb.WriteString(c.Text)
			}
		}
	}
	return sb.String()
}

func TestNewEmptyKeyReturnsErrNoAPIKey(t *testing.T) {
	_, err := New(Config{}, "", metrics.NewRegistry(), nil, discardLogger())
	if !errors.Is(err, ErrNoAPIKey) {
		t.Fatalf("New with empty key: err = %v, want ErrNoAPIKey", err)
	}
}

func TestNewNilRegistryFails(t *testing.T) {
	var reg *metrics.Registry
	_, err := New(Config{}, "test-key", reg, nil, discardLogger())
	if err == nil {
		t.Fatal("New with nil registry: err = nil, want metric-registration error")
	}
}

func TestNewDefaultsAndAccessors(t *testing.T) {
	p, err := New(Config{}, "test-key", metrics.NewRegistry(), nil, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := p.Name(); got != "claude" {
		t.Errorf("Name() = %q, want claude", got)
	}
	if got := p.Model(); got != DefaultModel {
		t.Errorf("Model() = %q, want %q", got, DefaultModel)
	}
	if got := p.MaxContextTokens(); got != 1_000_000 {
		t.Errorf("MaxContextTokens() = %d, want 1000000 for %s", got, DefaultModel)
	}
	if got := p.ScoreCap(); got != DefaultScoreCap {
		t.Errorf("ScoreCap() = %d, want %d", got, DefaultScoreCap)
	}
	if p.SupportsStreaming() {
		t.Error("SupportsStreaming() = true, want false (BI-9.2 Phase-3 flag)")
	}
}

func TestMaxContextTokensPerModel(t *testing.T) {
	cases := []struct {
		model string
		want  int
	}{
		{"claude-opus-4-8", 1_000_000},
		{"claude-sonnet-4-6", 1_000_000},
		{"claude-haiku-4-5", 200_000},
		{"some-future-model", fallbackContextWindow},
	}
	for _, tc := range cases {
		p, err := New(Config{Model: tc.model}, "test-key", metrics.NewRegistry(), nil, discardLogger())
		if err != nil {
			t.Fatalf("New(%s): %v", tc.model, err)
		}
		if got := p.MaxContextTokens(); got != tc.want {
			t.Errorf("MaxContextTokens(%s) = %d, want %d", tc.model, got, tc.want)
		}
	}
}

func TestRoleTimeoutContract(t *testing.T) {
	// AC2: 30s L1, 30s L2, 60s Senior, 120s reserved DFIR. These constants
	// are the Story 3.2 contract (config routing is Story 3.8).
	want := map[provider.Role]time.Duration{
		provider.RoleL1:     30 * time.Second,
		provider.RoleL2:     30 * time.Second,
		provider.RoleSenior: 60 * time.Second,
		provider.RoleDFIR:   120 * time.Second,
	}
	for role, d := range want {
		if got := roleTimeouts[role]; got != d {
			t.Errorf("roleTimeouts[%s] = %v, want %v", role, got, d)
		}
	}
	if len(roleTimeouts) != len(want) {
		t.Errorf("roleTimeouts has %d entries, want %d", len(roleTimeouts), len(want))
	}
}

// TestIsPermanentClassificationTable proves the BI-3 table row by row using
// the SDK's typed *anthropic.Error (StatusCode), never substring matching.
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
		{408, false}, // request timeout: transient
		{429, false}, // rate limit: transient
		{500, false},
		{529, false},
	}
	for _, tc := range cases {
		apiErr := &anthropic.Error{StatusCode: tc.status}
		if got := isPermanent(apiErr); got != tc.want {
			t.Errorf("isPermanent(status=%d) = %v, want %v", tc.status, got, tc.want)
		}
		// errors.As must reach through wrapping.
		wrapped := fmt.Errorf("attempt failed: %w", apiErr)
		if got := isPermanent(wrapped); got != tc.want {
			t.Errorf("isPermanent(wrapped status=%d) = %v, want %v", tc.status, got, tc.want)
		}
	}
	if isPermanent(errors.New("dial tcp: connection refused")) {
		t.Error("isPermanent(non-API transport error) = true, want false (transient)")
	}
	if isPermanent(nil) {
		t.Error("isPermanent(nil) = true, want false")
	}
}

func TestResolveStatusMapping(t *testing.T) {
	p, err := New(Config{}, "test-key", metrics.NewRegistry(), nil, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	parent := context.Background()

	t.Run("success", func(t *testing.T) {
		cctx, cancel := context.WithTimeout(parent, time.Minute)
		defer cancel()
		if got := p.resolveStatus(nil, cctx, parent); got != statusSuccess {
			t.Errorf("resolveStatus(nil) = %q, want %q", got, statusSuccess)
		}
	})

	t.Run("role timeout", func(t *testing.T) {
		cctx, cancel := context.WithTimeout(parent, time.Nanosecond)
		defer cancel()
		<-cctx.Done()
		err := fmt.Errorf("retry: ctx cancelled during op: %w", context.DeadlineExceeded)
		if got := p.resolveStatus(err, cctx, parent); got != statusTimeout {
			t.Errorf("resolveStatus(role deadline) = %q, want %q (BI-5.2)", got, statusTimeout)
		}
	})

	t.Run("parent cancellation is not a timeout", func(t *testing.T) {
		pctx, pcancel := context.WithCancel(context.Background())
		cctx, cancel := context.WithTimeout(pctx, time.Minute)
		defer cancel()
		pcancel()
		err := fmt.Errorf("retry: ctx cancelled during op: %w", context.DeadlineExceeded)
		if got := p.resolveStatus(err, cctx, pctx); got != statusTransient {
			t.Errorf("resolveStatus(parent cancel) = %q, want %q (shutdown, never timeout)", got, statusTransient)
		}
	})

	t.Run("permanent", func(t *testing.T) {
		cctx, cancel := context.WithTimeout(parent, time.Minute)
		defer cancel()
		err := fmt.Errorf("claude: analyse: %w", &anthropic.Error{StatusCode: 401})
		if got := p.resolveStatus(err, cctx, parent); got != statusPermanent {
			t.Errorf("resolveStatus(401) = %q, want %q", got, statusPermanent)
		}
	})

	t.Run("exhausted retries", func(t *testing.T) {
		cctx, cancel := context.WithTimeout(parent, time.Minute)
		defer cancel()
		err := fmt.Errorf("retry: max attempts (3) exhausted: %w", &anthropic.Error{StatusCode: 529})
		if got := p.resolveStatus(err, cctx, parent); got != statusTransient {
			t.Errorf("resolveStatus(exhausted 529) = %q, want %q", got, statusTransient)
		}
	})
}

func TestInvalidRoleRejectedWithoutMetricSeries(t *testing.T) {
	reg := metrics.NewRegistry()
	p, err := New(Config{}, "test-key", reg, nil, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = p.Analyse(context.Background(), provider.Request{Role: provider.Role("bogus")})
	if err == nil || !strings.Contains(err.Error(), "invalid analyst role") {
		t.Fatalf("Analyse(bogus role) err = %v, want invalid-role error", err)
	}
	// The bounded-label rule: no series may be minted for an unbounded
	// caller-supplied role string.
	mfs, gerr := reg.Gatherer().Gather()
	if gerr != nil {
		t.Fatalf("gather: %v", gerr)
	}
	for _, mf := range mfs {
		if mf.GetName() == metricName && len(mf.GetMetric()) != 0 {
			t.Errorf("invalid-role call minted %d metric series, want 0", len(mf.GetMetric()))
		}
	}
}

func TestConstructionLogNeverContainsAPIKey(t *testing.T) {
	const sentinel = "SENTINEL-API-KEY-c3VwZXJzZWNyZXQ"
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	if _, err := New(Config{}, sentinel, metrics.NewRegistry(), nil, log); err != nil {
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

func TestBuildParamsCarriesRedactedEvidenceSchemaAndPrior(t *testing.T) {
	p, err := New(Config{}, "test-key", metrics.NewRegistry(), nil, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pkg := schema.EvidencePackage{
		PackageID:  "pkg-42",
		WorkloadID: "default/nginx",
	}
	req := provider.Request{
		Role:   provider.RoleL2,
		Prompt: provider.Prompt{System: "you are the L2 analyst", User: "verify this hypothesis"},
		Schema: provider.JSONSchema(`{"type":"object","required":["verdict"]}`),
		PriorAssessment: &schema.ThreatAssessment{
			ThreatType: "crypto_miner",
			Mode:       schema.ModeLLM,
		},
	}
	params, err := p.buildParams(pkg, req)
	if err != nil {
		t.Fatalf("buildParams: %v", err)
	}
	if len(params.System) != 1 || params.System[0].Text != "you are the L2 analyst" {
		t.Errorf("System not threaded: %+v", params.System)
	}
	if params.MaxTokens != DefaultMaxTokens {
		t.Errorf("MaxTokens = %d, want %d", params.MaxTokens, DefaultMaxTokens)
	}
	if params.Thinking.OfDisabled == nil {
		t.Error("Thinking is not the explicit disabled union (BI-9)")
	}
	if params.Temperature.Valid() || params.TopP.Valid() || params.TopK.Valid() {
		t.Error("sampling parameter set; temperature/top_p/top_k are removed on Opus 4.8 (BI-2.4)")
	}
	body, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	text := wireText(t, body)
	for _, want := range []string{"pkg-42", "default/nginx", "verify this hypothesis", "crypto_miner", `"required":["verdict"]`} {
		if !strings.Contains(text, want) {
			t.Errorf("wire payload text missing %q", want)
		}
	}
	for _, forbidden := range []string{`"temperature"`, `"top_p"`, `"top_k"`, `"budget_tokens"`} {
		if strings.Contains(string(body), forbidden) {
			t.Errorf("wire payload contains removed Opus 4.8 param %s (would 400)", forbidden)
		}
	}
}
