package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/olokotoh/olaitan/internal/agent/provider"
	"github.com/olokotoh/olaitan/internal/config"
	"github.com/olokotoh/olaitan/internal/decision/analyst"
	"github.com/olokotoh/olaitan/internal/metrics"
	responseaudit "github.com/olokotoh/olaitan/internal/response/audit"
	"github.com/olokotoh/olaitan/internal/schema"
)

func chainTestLogger() *slog.Logger { return slog.New(slog.NewJSONHandler(new(bytes.Buffer), nil)) }

func TestResolveRoleFamily(t *testing.T) {
	cases := []struct{ role, global, want string }{
		{"openai", "api", "openai"},
		{"OLLAMA", "api", "ollama"},
		{"", "api", "claude"},
		{"", "local", "ollama"},
		{"", "none", "none"},
	}
	for _, tc := range cases {
		if got := resolveRoleFamily(tc.role, tc.global); got != tc.want {
			t.Errorf("resolveRoleFamily(%q,%q) = %q, want %q", tc.role, tc.global, got, tc.want)
		}
	}
}

// TestRoleScoreCap pins the DW3.7-1 trust ladder: family defaults
// (35/30/25) with a tighter global cap acting as a ceiling, so an
// openai-routed role caps at 30 even under the shipped global 35.
func TestRoleScoreCap(t *testing.T) {
	cases := []struct {
		family string
		global int
		want   int
	}{
		{"claude", 35, 35},
		{"openai", 35, 30},
		{"ollama", 35, 25},
		{"claude", 0, 35},
		{"claude", 20, 20},
		{"openai", 20, 20},
		{"openai", 0, 30},
	}
	for _, tc := range cases {
		if got := roleScoreCap(tc.family, tc.global); got != tc.want {
			t.Errorf("roleScoreCap(%q,%d) = %d, want %d", tc.family, tc.global, got, tc.want)
		}
	}
}

func TestRoleSpecDegrade(t *testing.T) {
	cfg := &config.Config{}
	cfg.Analyst.Provider = "api"
	cfg.Analyst.API.Model = "claude-opus-4-8"

	if _, _, d := roleSpec("", "", cfg, ""); !strings.Contains(d, "api key") {
		t.Errorf("claude no key: degrade = %q, want api-key reason", d)
	}
	if _, _, d := roleSpec("", "", cfg, "k"); d != "" {
		t.Errorf("claude with key+inherited model: degrade = %q, want none", d)
	}
	if _, _, d := roleSpec("openai", "", cfg, "k"); d != "" {
		// openai inherits api.model (claude-opus-4-8); model present.
		t.Errorf("openai with model: degrade = %q, want none", d)
	}
	if _, m, d := roleSpec("ollama", "", cfg, "k"); d == "" || m != "" {
		t.Errorf("ollama no model: degrade = %q model = %q, want degrade", d, m)
	}
}

func apiCfg(model string) *config.Config {
	cfg := &config.Config{}
	cfg.Analyst.Provider = "api"
	cfg.Analyst.API.Model = model
	cfg.Analyst.ScoreCap = 35
	return cfg
}

func TestBuildInvestigationChainNoneDisabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.Analyst.Provider = "none"
	chain, enabled, err := buildInvestigationChain(cfg, "k", metrics.NewRegistry(), nil, chainTestLogger())
	if err != nil || enabled || chain != nil {
		t.Errorf("provider=none: chain=%v enabled=%v err=%v, want nil/false/nil", chain, enabled, err)
	}
}

func TestBuildInvestigationChainFull(t *testing.T) {
	chain, enabled, err := buildInvestigationChain(apiCfg("claude-opus-4-8"), "test-key", metrics.NewRegistry(), nil, chainTestLogger())
	if err != nil || !enabled || chain == nil {
		t.Fatalf("full chain: enabled=%v err=%v chain=%v", enabled, err, chain)
	}
	if chain.Mode() != analyst.ChainModeFull {
		t.Errorf("mode = %q, want full", chain.Mode())
	}
}

func TestBuildInvestigationChainAblation(t *testing.T) {
	f := false
	// l2_enabled: false => L1-only.
	cfg := apiCfg("claude-opus-4-8")
	cfg.Analyst.L2Enabled = &f
	chain, _, err := buildInvestigationChain(cfg, "k", metrics.NewRegistry(), nil, chainTestLogger())
	if err != nil || chain == nil || chain.Mode() != analyst.ChainModeL1Only {
		t.Errorf("l2_enabled=false: mode=%v err=%v, want l1_only", chainModeOrNil(chain), err)
	}
	// senior_enabled: false => L1+L2.
	cfg2 := apiCfg("claude-opus-4-8")
	cfg2.Analyst.SeniorEnabled = &f
	chain2, _, err2 := buildInvestigationChain(cfg2, "k", metrics.NewRegistry(), nil, chainTestLogger())
	if err2 != nil || chain2 == nil || chain2.Mode() != analyst.ChainModeL1L2 {
		t.Errorf("senior_enabled=false: mode=%v err=%v, want l1_l2", chainModeOrNil(chain2), err2)
	}
}

func chainModeOrNil(c *analyst.Chain) string {
	if c == nil {
		return "<nil>"
	}
	return c.Mode()
}

func TestBuildInvestigationChainEmptyKeyDegrades(t *testing.T) {
	var buf bytes.Buffer
	chain, enabled, err := buildInvestigationChain(apiCfg("claude-opus-4-8"), "", metrics.NewRegistry(), nil, slog.New(slog.NewJSONHandler(&buf, nil)))
	if err != nil || enabled || chain != nil {
		t.Fatalf("empty key must degrade to rules-only: enabled=%v err=%v", enabled, err)
	}
	if !strings.Contains(buf.String(), `"api_key_set":false`) {
		t.Errorf("degrade log missing api_key_set=false: %s", buf.String())
	}
}

// TestBuildInvestigationChainOpenAIReachable proves the openai_compat
// provider is now wired into cmd (the previously-unreachable gap): an
// openai-routed L1 in an otherwise-claude chain constructs cleanly.
func TestBuildInvestigationChainOpenAIReachable(t *testing.T) {
	cfg := apiCfg("claude-opus-4-8")
	cfg.Analyst.L1Provider = "openai"
	cfg.Analyst.L1Model = "gpt-4o-mini"
	chain, enabled, err := buildInvestigationChain(cfg, "k", metrics.NewRegistry(), nil, chainTestLogger())
	if err != nil || !enabled || chain == nil {
		t.Fatalf("openai-routed L1: enabled=%v err=%v", enabled, err)
	}
}

// scriptedProvider replies per role so a real analyst.Chain can be driven
// end to end without a network call.
type scriptedProvider struct {
	byRole map[provider.Role]string
}

func (s *scriptedProvider) Name() string                 { return "scripted" }
func (s *scriptedProvider) Model() string                { return "scripted-model" }
func (s *scriptedProvider) MaxContextTokens() int        { return 200000 }
func (s *scriptedProvider) ScoreCap() int                { return 35 }
func (s *scriptedProvider) SupportsStreaming() bool      { return false }
func (s *scriptedProvider) Health(context.Context) error { return nil }
func (s *scriptedProvider) Analyse(_ context.Context, req provider.Request) (provider.Response, error) {
	return provider.Response{Raw: s.byRole[req.Role]}, nil
}

func scriptedFullChain(t *testing.T) *analyst.Chain {
	t.Helper()
	sp := &scriptedProvider{byRole: map[provider.Role]string{
		provider.RoleL1:     `{"hypothesis":"crypto miner","cited_evidence":[{"event_id":"evt-1"}],"confidence":70}`,
		provider.RoleL2:     `{"verdict":"confirmed","verified_evidence":[{"event_id":"evt-1","finding":"confirmed"}],"confidence":66}`,
		provider.RoleSenior: `{"threat_type":"cryptomining","reasoning":"miner confirmed","confidence":80}`,
	}}
	reg := metrics.NewRegistry()
	l1, err := analyst.NewL1(sp, analyst.PromptSpec{System: "s", Version: "v"}, reg, nil)
	if err != nil {
		t.Fatalf("NewL1: %v", err)
	}
	l2, err := analyst.NewL2(sp, analyst.PromptSpec{System: "s", Version: "v"}, reg, nil)
	if err != nil {
		t.Fatalf("NewL2: %v", err)
	}
	sr, err := analyst.NewSenior(sp, analyst.PromptSpec{System: "s", Version: "v"}, reg, nil)
	if err != nil {
		t.Fatalf("NewSenior: %v", err)
	}
	chain, err := analyst.NewChain(l1, l2, sr, reg, nil)
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	return chain
}

func triggeringPackage(severity string) schema.EvidencePackage {
	return schema.EvidencePackage{
		PackageID:   "pkg-1",
		WorkloadID:  "wl-1",
		RuleMatches: []schema.RuleMatch{{RuleID: "r1", Severity: severity, EventID: "evt-1"}},
		Events:      []schema.Event{{ID: "evt-1"}},
	}
}

func TestProcessChainPackageAssessedAndAudited(t *testing.T) {
	chain := scriptedFullChain(t)
	pub := &fakeAssessmentPub{}
	out := processChainPackage(context.Background(), triggeringPackage("80"), chain, chain.Mode(), pub, nil, chainTestLogger())
	if out != analyst.ChainOutcomeAssessed {
		t.Errorf("outcome = %q, want assessed", out)
	}
	if len(pub.got) != 1 {
		t.Fatalf("audit publishes = %d, want 1", len(pub.got))
	}
	evt := pub.got[0]
	if evt.PackageID != "pkg-1" || evt.Mode != analyst.ChainModeFull {
		t.Errorf("audit event = %+v", evt)
	}
	if strings.Join(evt.AgentsAvailable, ",") != "l1,l2,senior" {
		t.Errorf("agents_available = %v, want l1,l2,senior", evt.AgentsAvailable)
	}
}

func TestProcessChainPackageNotTriggered(t *testing.T) {
	chain := scriptedFullChain(t)
	pub := &fakeAssessmentPub{}
	out := processChainPackage(context.Background(), triggeringPackage("10"), chain, chain.Mode(), pub, nil, chainTestLogger())
	if out != analyst.ChainOutcomeNotTriggered {
		t.Errorf("outcome = %q, want not_triggered", out)
	}
	if len(pub.got) != 0 {
		t.Errorf("a non-triggering package must not publish an assessment: %v", pub.got)
	}
}

type fakeAssessmentPub struct {
	got []responseaudit.AuditAssessment
}

func (f *fakeAssessmentPub) PublishAuditAssessment(_ context.Context, evt responseaudit.AuditAssessment) error {
	f.got = append(f.got, evt)
	return nil
}
