package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/olokotoh/olaitan/internal/agent/prompts"
	"github.com/olokotoh/olaitan/internal/agent/provider"
	"github.com/olokotoh/olaitan/internal/config"
	"github.com/olokotoh/olaitan/internal/decision/analyst"
	"github.com/olokotoh/olaitan/internal/metrics"
	responseaudit "github.com/olokotoh/olaitan/internal/response/audit"
	"github.com/olokotoh/olaitan/internal/response/risk"
	"github.com/olokotoh/olaitan/internal/schema"
)

func chainTestLogger() *slog.Logger { return slog.New(slog.NewJSONHandler(new(bytes.Buffer), nil)) }

// testPromptSet returns the binary-embedded default prompt set (an empty
// temp dir makes every role fall back to its default), so chain-builder
// tests run with the Story 3.13 prompt seam without a mounted ConfigMap.
func testPromptSet(t *testing.T) *prompts.Set {
	t.Helper()
	s := prompts.New(t.TempDir(), nil)
	if err := s.Load(); err != nil {
		t.Fatalf("load default prompts: %v", err)
	}
	return s.Get()
}

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
	if _, _, d := roleSpec("openai", "", cfg, "k"); d == "" {
		t.Error("openai with no explicit model must degrade (api.model is a claude id, not inheritable)")
	}
	if _, m, d := roleSpec("openai", "gpt-4o-mini", cfg, "k"); d != "" || m != "gpt-4o-mini" {
		t.Errorf("openai with explicit model: degrade=%q model=%q, want none/gpt-4o-mini", d, m)
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
	chain, enabled, err := buildInvestigationChain(cfg, "k", testPromptSet(t), metrics.NewRegistry(), nil, chainTestLogger())
	if err != nil || enabled || chain != nil {
		t.Errorf("provider=none: chain=%v enabled=%v err=%v, want nil/false/nil", chain, enabled, err)
	}
}

func TestBuildInvestigationChainFull(t *testing.T) {
	chain, enabled, err := buildInvestigationChain(apiCfg("claude-opus-4-8"), "test-key", testPromptSet(t), metrics.NewRegistry(), nil, chainTestLogger())
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
	chain, _, err := buildInvestigationChain(cfg, "k", testPromptSet(t), metrics.NewRegistry(), nil, chainTestLogger())
	if err != nil || chain == nil || chain.Mode() != analyst.ChainModeL1Only {
		t.Errorf("l2_enabled=false: mode=%v err=%v, want l1_only", chainModeOrNil(chain), err)
	}
	// senior_enabled: false => L1+L2.
	cfg2 := apiCfg("claude-opus-4-8")
	cfg2.Analyst.SeniorEnabled = &f
	chain2, _, err2 := buildInvestigationChain(cfg2, "k", testPromptSet(t), metrics.NewRegistry(), nil, chainTestLogger())
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
	chain, enabled, err := buildInvestigationChain(apiCfg("claude-opus-4-8"), "", testPromptSet(t), metrics.NewRegistry(), nil, slog.New(slog.NewJSONHandler(&buf, nil)))
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
	chain, enabled, err := buildInvestigationChain(cfg, "k", testPromptSet(t), metrics.NewRegistry(), nil, chainTestLogger())
	if err != nil || !enabled || chain == nil {
		t.Fatalf("openai-routed L1: enabled=%v err=%v", enabled, err)
	}
}

// TestChainAdjustedScore_EnabledWindowSumsAcrossPackages drives the ACTUAL
// FSM-consumer wiring with an ENABLED risk window (PR #92 review: every prior
// test through the call site passed risk.New(0), recreating the exact
// unprotected-call-site hazard). A rule-only package then a baseline-only
// package for the same workload must score, through this call site, as one
// aggregate exceeding either solo score. Story 7.4: the call site is now
// fsmDriver.handlePackage (the deterministic path); the name is kept so the
// traceability row stays stable.
func TestChainAdjustedScore_EnabledWindowSumsAcrossPackages(t *testing.T) {
	f := newDriverFixture(t, nil, risk.New(60*time.Second), 0, 0)
	rulePkg := schema.EvidencePackage{PackageID: "p1", WorkloadID: "t/Deployment/w", RuleMatches: []schema.RuleMatch{{RuleID: "OLT-EXEC-001", Severity: "90"}}}
	basePkg := schema.EvidencePackage{PackageID: "p2", WorkloadID: "t/Deployment/w", BaselineDeviations: []schema.BaselineDeviation{{Metric: "m", Sigma: 3.8}}}

	f.handle(rulePkg)
	s1 := f.d.last
	f.handle(basePkg)
	s2 := f.d.last
	if s2.Total <= s1.Total {
		t.Fatalf("enabled window at the real call site did not sum: rule-only=%v then rule+baseline=%v", s1.Total, s2.Total)
	}
	if s2.Rules <= 0 || s2.Baseline <= 0 {
		t.Fatalf("aggregate must carry both terms, got rules=%v baseline=%v", s2.Rules, s2.Baseline)
	}
}

// TestFSMConsumerFoldsChainConfidenceIntoScore is the Story 3.11 round-1
// integration proof that the chain's capped confidence actually RAISES the
// FSM-driving Total while the Trust-Bound (LLM contribution <= 10.5) holds.
// Story 7.4 changed WHEN the fold happens (the spec, issue #186): the
// deterministic score drives the FSM first, and the chain's verdict is folded
// and re-evaluated when it returns. So this test now drives the real chain
// through the production worker run func and asserts on the RE-SCORE.
func TestFSMConsumerFoldsChainConfidenceIntoScore(t *testing.T) {
	chain := scriptedFullChain(t)
	pub := &fakeAssessmentPub{}
	pkg := triggeringPackage("80")

	runs, err := analyst.RegisterChainRunsMetric(metrics.NewRegistry())
	if err != nil {
		t.Fatalf("runs metric: %v", err)
	}
	f := newDriverFixture(t, newChainRunFunc(chain, chain.Mode(), pub, runs, chainTestLogger()), risk.New(0), 1, 0)
	f.d.chainRuns = runs
	f.handle(pkg)
	noChain := f.d.last
	f.awaitResult(t)
	withChain := f.d.last

	if withChain.LLM <= 0 || withChain.Total <= noChain.Total {
		t.Errorf("the chain's capped confidence did not raise the FSM-driving Total: with=%+v deterministic=%+v", withChain, noChain)
	}
	if withChain.LLM > 10.5 {
		t.Errorf("LLM contribution %v exceeds the 10.5 Trust-Bound", withChain.LLM)
	}
	// The deterministic score folds a zero LLM term.
	if noChain.LLM != 0 {
		t.Errorf("deterministic LLM term = %v, want 0", noChain.LLM)
	}
	if v := testutil.ToFloat64(runs.WithLabelValues(chain.Mode(), analyst.ChainOutcomeAssessed)); v != 1 {
		t.Errorf("chain runs assessed = %v, want 1 (metric recorded on the worker)", v)
	}
}

// TestProcessChainPackageBreakerBypass (Story 3.12): when the LLM-tier breaker
// is engaged, an LLM-eligible package bypasses the chain (no chain.Run, no
// assessment published, folds 0) and records the breaker_bypassed outcome.
func TestProcessChainPackageBreakerBypass(t *testing.T) {
	chain, cp := countingChain(t)
	pub := &fakeAssessmentPub{}
	breaker := analyst.NewCircuitBreaker(analyst.CircuitBreakerOptions{RatePerMin: 1, Cooling: 60 * time.Second, Enabled: true})
	// Pre-engage: 2 admits exceed the rate of 1/min.
	breaker.Admit()
	breaker.Admit()
	if !breaker.IsEngaged() {
		t.Fatal("setup: breaker should be engaged")
	}

	ok, out := admitChainPackage(triggeringPackage("80"), chain.Mode(), breaker, nil)
	if out != analyst.ChainOutcomeBreakerBypassed || ok {
		t.Errorf("engaged breaker: out=%q admitted=%v, want breaker_bypassed/false", out, ok)
	}
	// The cost-amplification guarantee: NO LLM call was made.
	if cp.calls.Load() != 0 {
		t.Errorf("a bypassed package must not invoke the LLM, got %d Analyse calls", cp.calls.Load())
	}
	if len(pub.got) != 0 {
		t.Errorf("a bypassed package must not publish an assessment, got %d publishes", len(pub.got))
	}
}

// TestProcessChainPackageBreakerDisengagedRuns: a disengaged breaker lets an
// eligible package run the chain normally.
func TestProcessChainPackageBreakerDisengagedRuns(t *testing.T) {
	chain := scriptedFullChain(t)
	pub := &fakeAssessmentPub{}
	breaker := analyst.NewCircuitBreaker(analyst.CircuitBreakerOptions{RatePerMin: 100, Cooling: 60 * time.Second, Enabled: true})
	if ok, out := admitChainPackage(triggeringPackage("80"), chain.Mode(), breaker, nil); !ok {
		t.Fatalf("disengaged breaker must admit, got %q", out)
	}
	llm, out := runChainPackage(context.Background(), triggeringPackage("80"), chain, pub, nil, chainTestLogger())
	if out != analyst.ChainOutcomeAssessed || llm <= 0 {
		t.Errorf("disengaged breaker: out=%q llm=%d, want assessed/>0", out, llm)
	}
}

// countingProvider replies per role like scriptedProvider but counts Analyse
// calls so a bypass test can assert the LLM was never invoked.
type countingProvider struct {
	calls  atomic.Int64
	byRole map[provider.Role]string
}

func (c *countingProvider) Name() string                 { return "counting" }
func (c *countingProvider) Model() string                { return "m" }
func (c *countingProvider) MaxContextTokens() int        { return 200000 }
func (c *countingProvider) ScoreCap() int                { return 35 }
func (c *countingProvider) SupportsStreaming() bool      { return false }
func (c *countingProvider) Health(context.Context) error { return nil }
func (c *countingProvider) Analyse(_ context.Context, req provider.Request) (provider.Response, error) {
	c.calls.Add(1)
	return provider.Response{Raw: c.byRole[req.Role]}, nil
}

func countingChain(t *testing.T) (*analyst.Chain, *countingProvider) {
	t.Helper()
	cp := &countingProvider{byRole: map[provider.Role]string{
		provider.RoleL1:     `{"hypothesis":"crypto miner","cited_evidence":[{"event_id":"evt-1"}],"confidence":70}`,
		provider.RoleL2:     `{"verdict":"confirmed","verified_evidence":[{"event_id":"evt-1","finding":"confirmed"}],"confidence":66}`,
		provider.RoleSenior: `{"threat_type":"cryptomining","reasoning":"miner confirmed","confidence":80}`,
	}}
	reg := metrics.NewRegistry()
	l1, _ := analyst.NewL1(cp, analyst.PromptSpec{System: "s", Version: "v"}, reg, nil)
	l2, _ := analyst.NewL2(cp, analyst.PromptSpec{System: "s", Version: "v"}, reg, nil)
	sr, _ := analyst.NewSenior(cp, analyst.PromptSpec{System: "s", Version: "v"}, reg, nil)
	chain, err := analyst.NewChain(l1, l2, sr, reg, nil)
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	return chain, cp
}

// panicProvider panics on every Analyse, to prove the merge's recover guard.
type panicProvider struct{}

func (panicProvider) Name() string                 { return "panic" }
func (panicProvider) Model() string                { return "panic" }
func (panicProvider) MaxContextTokens() int        { return 1000 }
func (panicProvider) ScoreCap() int                { return 35 }
func (panicProvider) SupportsStreaming() bool      { return false }
func (panicProvider) Health(context.Context) error { return nil }
func (panicProvider) Analyse(context.Context, provider.Request) (provider.Response, error) {
	panic("provider boom")
}

// TestSafeChainConfidenceRecoversFromPanic proves the round-1 guard: a panic
// in the LLM tier (now on the single FSM-driver goroutine after the merge)
// degrades to a zero LLM contribution rather than crashing the FSM ring, so
// the deterministic rules+baselines score still drives containment (NFR27).
func TestSafeChainConfidenceRecoversFromPanic(t *testing.T) {
	pp := panicProvider{}
	reg := metrics.NewRegistry()
	l1, _ := analyst.NewL1(pp, analyst.PromptSpec{System: "s", Version: "v"}, reg, nil)
	l2, _ := analyst.NewL2(pp, analyst.PromptSpec{System: "s", Version: "v"}, reg, nil)
	sr, _ := analyst.NewSenior(pp, analyst.PromptSpec{System: "s", Version: "v"}, reg, nil)
	chain, err := analyst.NewChain(l1, l2, sr, reg, nil)
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	pub := &fakeAssessmentPub{}

	capped, _ := newChainRunFunc(chain, chain.Mode(), pub, nil, chainTestLogger())(context.Background(), triggeringPackage("80"))
	if capped != 0 {
		t.Errorf("a panicking chain must fold 0 (deterministic-only), got %d", capped)
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
	llm, out := runChainPackage(context.Background(), triggeringPackage("80"), chain, pub, nil, chainTestLogger())
	if out != analyst.ChainOutcomeAssessed {
		t.Errorf("outcome = %q, want assessed", out)
	}
	// Story 3.11: an assessed run returns the per-provider-capped LLM
	// confidence to fold into the ThreatScore (> 0 for this scripted verdict).
	if llm <= 0 {
		t.Errorf("assessed run returned llm_capped_confidence = %d, want > 0", llm)
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
	ok, out := admitChainPackage(triggeringPackage("10"), chain.Mode(), nil, nil)
	if out != analyst.ChainOutcomeNotTriggered {
		t.Errorf("outcome = %q, want not_triggered", out)
	}
	if ok {
		t.Errorf("a non-triggering package must not be admitted to the chain")
	}
	if len(pub.got) != 0 {
		t.Errorf("a non-triggering package must not publish an assessment: %v", pub.got)
	}
}

// fakeAssessmentPub records published assessments. Story 7.4: the chain now
// publishes from worker goroutines, so it is mutex-guarded.
type fakeAssessmentPub struct {
	mu  sync.Mutex
	got []responseaudit.AuditAssessment
}

func (f *fakeAssessmentPub) PublishAuditAssessment(_ context.Context, evt responseaudit.AuditAssessment) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, evt)
	return nil
}

func (f *fakeAssessmentPub) all() []responseaudit.AuditAssessment {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]responseaudit.AuditAssessment(nil), f.got...)
}
