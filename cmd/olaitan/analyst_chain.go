package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/olokotoh/olaitan/internal/agent/prompts"
	"github.com/olokotoh/olaitan/internal/agent/provider"
	claudeprovider "github.com/olokotoh/olaitan/internal/agent/provider/claude"
	ollamaprovider "github.com/olokotoh/olaitan/internal/agent/provider/ollama"
	openaiprovider "github.com/olokotoh/olaitan/internal/agent/provider/openai_compat"
	"github.com/olokotoh/olaitan/internal/config"
	"github.com/olokotoh/olaitan/internal/decision/analyst"
	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/report/dfir"
	reportredact "github.com/olokotoh/olaitan/internal/report/redact"
	responseaudit "github.com/olokotoh/olaitan/internal/response/audit"
	"github.com/olokotoh/olaitan/internal/schema"
)

// promptSpecFor builds the analyst PromptSpec for a role from the loaded
// prompt set (Story 3.13). The System text is the role's ConfigMap-mounted
// (or binary-embedded default) prompt; the Version is its content hash, so
// every investigation is traceable to a specific prompt revision (NFR41).
// The Story 3.8 default prompt text now lives in
// internal/agent/prompts/defaults/<role>.txt and is byte-identical to the
// former built-in consts (the Version changes from a static string to the
// content hash).
func promptSpecFor(set *prompts.Set, role prompts.Role) analyst.PromptSpec {
	p := set.Prompt(role)
	return analyst.PromptSpec{System: p.Text, Version: p.Hash}
}

// resolveRoleFamily maps a per-role provider value onto a concrete
// provider family (Story 3.8 BI-3). A non-empty value is the explicit
// family; an empty value inherits the top-level provider mapping
// (api -> claude, local -> ollama). A global "none" is the kill-switch
// handled by the caller before this is reached.
func resolveRoleFamily(roleProvider, globalProvider string) string {
	if roleProvider != "" {
		return strings.ToLower(roleProvider)
	}
	switch {
	case analystSelectsAPIProvider(globalProvider):
		return "claude"
	case analystSelectsLocalProvider(globalProvider):
		return "ollama"
	}
	return "none"
}

// roleScoreCap returns the per-provider anti-hallucination cap for a role
// (Story 3.8 DW3.7-1). Each family has a trust-ladder default (claude 35,
// openai 30, ollama 25); a globally-configured analyst.score_cap that is
// TIGHTER than the family default lowers it (an operator ceiling). This
// closes DW3.7-1: an openai-routed role caps at 30 rather than inheriting
// the claude-tier 35, even when the shipped global score_cap is 35.
func roleScoreCap(family string, globalCap int) int {
	def := 35
	switch strings.ToLower(family) {
	case "openai":
		def = 30
	case "ollama":
		def = 25
	}
	if globalCap > 0 && globalCap < def {
		return globalCap
	}
	return def
}

// firstNonEmpty returns a if non-empty, else b.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// roleSpec resolves a role's (family, model) and a degrade reason. A
// non-empty reason means the role cannot be constructed and the whole
// chain degrades to rules-and-baselines-only (Story 3.8 BI-4). claude
// tolerates an empty model (its constructor defaults it); openai and
// ollama require a model.
func roleSpec(roleProvider, roleModel string, cfg *config.Config, apiKey string) (family, model, degrade string) {
	family = resolveRoleFamily(roleProvider, cfg.Analyst.Provider)
	switch family {
	case "claude":
		// claude inherits analyst.api.model when the role model is empty;
		// the constructor defaults it further (to claude-opus-4-8) if still
		// empty, so claude tolerates an empty model.
		model = firstNonEmpty(roleModel, cfg.Analyst.API.Model)
	case "openai":
		// openai does NOT inherit analyst.api.model: that field carries a
		// claude model id which an OpenAI-compatible endpoint would reject
		// (round-1 review). An openai-routed role must set its own
		// l1/l2/senior_model; an empty model degrades the chain.
		model = roleModel
	case "ollama":
		model = firstNonEmpty(roleModel, cfg.Analyst.Local.Model)
	}
	switch family {
	case "claude":
		if apiKey == "" {
			return family, model, "api key not set"
		}
	case "openai":
		if apiKey == "" {
			return family, model, "api key not set"
		}
		if model == "" {
			return family, model, "model not set"
		}
	case "ollama":
		if model == "" {
			return family, model, "model not set"
		}
	default:
		return family, model, "provider resolved to none"
	}
	return family, model, ""
}

// buildRoleProvider constructs the concrete provider for a resolved role
// family + model (Story 3.8 BI-4). It assumes roleSpec already cleared
// the degrade preconditions (key/model presence); the errors it returns
// are genuine misconfiguration (e.g. a bad endpoint) and are fatal.
//
// CONSTRAINT (round-1 review): the api-family providers (claude, openai)
// SHARE the single analyst.api.{endpoint,api_key_secret}. The supported
// topologies are therefore: an all-claude chain on the native Anthropic
// SDK with one key (the primary FR25 Haiku/Opus case); an all-openai
// chain behind one OpenAI-compatible gateway (LiteLLM/vLLM/Together) with
// one key+endpoint; or an all-ollama chain (no key). Mixing the NATIVE
// claude provider and an openai_compat endpoint in one chain only works
// when they share auth (e.g. both behind one gateway); per-role
// endpoint/key secrets are a future enhancement.
func buildRoleProvider(family, model string, cfg *config.Config, apiKey string, reg *metrics.Registry, sink *reportredact.RedactionAuditSink, log *slog.Logger) (provider.Provider, error) {
	scoreCap := roleScoreCap(family, cfg.Analyst.ScoreCap)
	switch strings.ToLower(family) {
	case "claude":
		return claudeprovider.New(claudeprovider.Config{
			Model:    model,
			BaseURL:  cfg.Analyst.API.Endpoint,
			ScoreCap: scoreCap,
		}, apiKey, reg, sink, log)
	case "openai":
		return openaiprovider.New(openaiprovider.Config{
			Model:    model,
			BaseURL:  cfg.Analyst.API.Endpoint,
			ScoreCap: scoreCap,
		}, apiKey, reg, sink, log)
	case "ollama":
		return ollamaprovider.New(ollamaprovider.Config{
			Model:    model,
			Endpoint: cfg.Analyst.Local.Endpoint,
			ScoreCap: scoreCap,
		}, reg, sink, log)
	default:
		return nil, fmt.Errorf("analyst: unknown provider family %q", family)
	}
}

// dfirAuditRecorder projects a DFIR generation record onto AUDIT.assessments
// via the role-keyed "dfir" maps, alongside the existing l1/l2/senior keys
// (Story 4.4 AC5). It is the cmd-side ring bridge: cmd is the only ring that
// imports both internal/report/dfir and internal/response/audit (+ redact), so
// the projection lives here, keeping the dfir package free of an audit/redact
// import. It satisfies dfir.AuditRecorder.
type dfirAuditRecorder struct {
	pub responseaudit.AssessmentAuditPublisher
	log *slog.Logger
}

// RecordDFIRAssessment redacts the evidence at the audit boundary (the same pure
// Redact() the provider ran, reproducing the bytes the LLM saw) and publishes a
// minimal AUDIT.assessments event carrying the "dfir" prompt-version / provider
// / model row. The mode is "dfir" so an audit consumer can distinguish the DFIR
// post-mortem row from the L1/L2/Senior chain rows. No L1/L2/Senior verdict and
// no LLM-capped confidence is carried (the trust-bound fence: the report never
// produces a ThreatAssessment or a confidence the FSM could fold).
func (r dfirAuditRecorder) RecordDFIRAssessment(ctx context.Context, rec dfir.DFIRAuditRecord) error {
	redacted, _ := reportredact.Redact(rec.RedactedEvidence)
	evt := responseaudit.AssessmentFromChain(responseaudit.AssessmentInput{
		PackageID:        rec.PackageID,
		WorkloadID:       rec.WorkloadID,
		Mode:             "dfir",
		AgentsAvailable:  []string{"dfir"},
		PromptVersions:   nonEmptyRoleMap("dfir", rec.PromptVersion),
		Providers:        nonEmptyRoleMap("dfir", rec.Provider),
		Models:           nonEmptyRoleMap("dfir", rec.Model),
		RedactedEvidence: redacted,
		RedactionApplied: true,
		Now:              rec.Now,
	})
	return r.pub.PublishAuditAssessment(ctx, evt)
}

// nonEmptyRoleMap returns a single-entry {role: val} map, or nil when val is
// empty (a fail-closed degrade may carry no model/version), so omitempty omits
// the field rather than emitting a "" value.
func nonEmptyRoleMap(role, val string) map[string]string {
	if val == "" {
		return nil
	}
	return map[string]string{role: val}
}

// dfirMaxTokens is the per-construction output ceiling for the DFIR claude
// provider (BI-7). A forensic report is long-form, so the shared
// DefaultMaxTokens=4096 is too small; 16000 is the long-form floor well within
// the SAFE NON-STREAMING band (the provider is hard-wired non-streaming, and the
// claude-api guidance warns non-streaming requests risk SDK HTTP timeouts above
// ~16K; Opus 4.8's 128K ceiling would require streaming, which is out of scope).
// Raised via per-construction Config.MaxTokens WITHOUT mutating the shared
// default. The runner treats a max_tokens truncation as a fail-closed failure.
const dfirMaxTokens int64 = 16000

// buildDFIRProvider constructs the DFIR agent's own LLM provider from
// analyst.dfir_provider / analyst.dfir_model (FR43), mirroring the per-role
// chain providers but with the raised dfirMaxTokens output ceiling on the claude
// path. It returns ("", degrade) semantics via roleSpec: a degraded resolution
// (no key, no model, provider:none) yields (nil, nil) so the caller skips DFIR
// wiring and the aggregator runs without the DFIR agent (the chain-degrade
// precedent). A genuine misconfiguration is fatal.
func buildDFIRProvider(cfg *config.Config, apiKey string, reg *metrics.Registry, sink *reportredact.RedactionAuditSink, log *slog.Logger) (provider.Provider, error) {
	family, model, degrade := roleSpec(cfg.Analyst.DFIRProvider, cfg.Analyst.DFIRModel, cfg, apiKey)
	if degrade != "" {
		log.Info("aggregator: DFIR agent not wired; no forensic reports generated",
			"role", "dfir", "reason", degrade, "provider", family, "api_key_set", apiKey != "", "model_set", model != "")
		return nil, nil
	}
	scoreCap := roleScoreCap(family, cfg.Analyst.ScoreCap)
	switch strings.ToLower(family) {
	case "claude":
		return claudeprovider.New(claudeprovider.Config{
			Model:     model,
			BaseURL:   cfg.Analyst.API.Endpoint,
			MaxTokens: dfirMaxTokens,
			ScoreCap:  scoreCap,
		}, apiKey, reg, sink, log)
	case "openai":
		return openaiprovider.New(openaiprovider.Config{
			Model:    model,
			BaseURL:  cfg.Analyst.API.Endpoint,
			ScoreCap: scoreCap,
		}, apiKey, reg, sink, log)
	case "ollama":
		return ollamaprovider.New(ollamaprovider.Config{
			Model:    model,
			Endpoint: cfg.Analyst.Local.Endpoint,
			ScoreCap: scoreCap,
		}, reg, sink, log)
	default:
		return nil, fmt.Errorf("aggregator: unknown DFIR provider family %q", family)
	}
}

// buildInvestigationChain wires the per-role investigation chain from
// config (Story 3.8 AC2/AC3/AC4). It returns (nil, false, nil) when the
// chain is disabled or any enabled role cannot be configured (the chain
// degrades to rules-and-baselines-only, NFR27); a non-nil error is a
// fatal misconfiguration. Ablation toggles (l2_enabled / senior_enabled)
// truncate the chain by leaving the runner nil.
func buildInvestigationChain(cfg *config.Config, apiKey string, promptSet *prompts.Set, reg *metrics.Registry, sink *reportredact.RedactionAuditSink, log *slog.Logger) (*analyst.Chain, bool, error) {
	a := cfg.Analyst
	if strings.EqualFold(a.Provider, "none") {
		log.Info("aggregator: investigation chain disabled (analyst.provider=none); running rules+baselines only (FR27/NFR27)")
		return nil, false, nil
	}

	// L1 is always required for a chain.
	l1Family, l1Model, degrade := roleSpec(a.L1Provider, a.L1Model, cfg, apiKey)
	if degrade != "" {
		log.Info("aggregator: investigation chain not wired; running rules+baselines only",
			"role", "l1", "reason", degrade, "provider", l1Family, "api_key_set", apiKey != "", "model_set", l1Model != "")
		return nil, false, nil
	}
	l1p, err := buildRoleProvider(l1Family, l1Model, cfg, apiKey, reg, sink, log)
	if err != nil {
		return nil, false, fmt.Errorf("aggregator: L1 provider: %w", err)
	}
	l1, err := analyst.NewL1(l1p, promptSpecFor(promptSet, prompts.RoleL1), reg, log)
	if err != nil {
		return nil, false, fmt.Errorf("aggregator: L1 runner: %w", err)
	}

	var l2 *analyst.L2
	if a.L2EnabledOrDefault() {
		l2Family, l2Model, degrade := roleSpec(a.L2Provider, a.L2Model, cfg, apiKey)
		if degrade != "" {
			log.Info("aggregator: investigation chain not wired; running rules+baselines only",
				"role", "l2", "reason", degrade, "provider", l2Family, "api_key_set", apiKey != "", "model_set", l2Model != "")
			return nil, false, nil
		}
		l2p, perr := buildRoleProvider(l2Family, l2Model, cfg, apiKey, reg, sink, log)
		if perr != nil {
			return nil, false, fmt.Errorf("aggregator: L2 provider: %w", perr)
		}
		l2, err = analyst.NewL2(l2p, promptSpecFor(promptSet, prompts.RoleL2), reg, log)
		if err != nil {
			return nil, false, fmt.Errorf("aggregator: L2 runner: %w", err)
		}
	}

	var senior *analyst.Senior
	if a.SeniorEnabledOrDefault() {
		srFamily, srModel, degrade := roleSpec(a.SeniorProvider, a.SeniorModel, cfg, apiKey)
		if degrade != "" {
			log.Info("aggregator: investigation chain not wired; running rules+baselines only",
				"role", "senior", "reason", degrade, "provider", srFamily, "api_key_set", apiKey != "", "model_set", srModel != "")
			return nil, false, nil
		}
		srp, perr := buildRoleProvider(srFamily, srModel, cfg, apiKey, reg, sink, log)
		if perr != nil {
			return nil, false, fmt.Errorf("aggregator: Senior provider: %w", perr)
		}
		senior, err = analyst.NewSenior(srp, promptSpecFor(promptSet, prompts.RoleSenior), reg, log)
		if err != nil {
			return nil, false, fmt.Errorf("aggregator: Senior runner: %w", err)
		}
	}

	chain, err := analyst.NewChain(l1, l2, senior, reg, log)
	if err != nil {
		return nil, false, fmt.Errorf("aggregator: chain: %w", err)
	}

	// Story 3.10 (FR28): wire a shared Ollama fallback for every role NOT
	// already on Ollama, when analyst.local is configured (model set). A
	// role on Ollama needs no fallback (it IS the local resilience tier);
	// an unconfigured analyst.local means no fallback (the chain still runs,
	// just without the fall-through). One Ollama provider instance backs all
	// fallback runners (it is stateless across roles; the role rides the
	// Request).
	if cfg.Analyst.Local.Model != "" {
		fbp, ferr := buildRoleProvider("ollama", cfg.Analyst.Local.Model, cfg, "", reg, sink, log)
		if ferr != nil {
			return nil, false, fmt.Errorf("aggregator: Ollama fallback provider: %w", ferr)
		}
		var l1fb *analyst.L1
		var l2fb *analyst.L2
		var srfb *analyst.Senior
		if l1Family != "ollama" {
			if l1fb, err = analyst.NewL1(fbp, promptSpecFor(promptSet, prompts.RoleL1), reg, log); err != nil {
				return nil, false, fmt.Errorf("aggregator: L1 Ollama fallback runner: %w", err)
			}
		}
		if l2 != nil && resolveRoleFamily(a.L2Provider, a.Provider) != "ollama" {
			if l2fb, err = analyst.NewL2(fbp, promptSpecFor(promptSet, prompts.RoleL2), reg, log); err != nil {
				return nil, false, fmt.Errorf("aggregator: L2 Ollama fallback runner: %w", err)
			}
		}
		if senior != nil && resolveRoleFamily(a.SeniorProvider, a.Provider) != "ollama" {
			if srfb, err = analyst.NewSenior(fbp, promptSpecFor(promptSet, prompts.RoleSenior), reg, log); err != nil {
				return nil, false, fmt.Errorf("aggregator: Senior Ollama fallback runner: %w", err)
			}
		}
		chain.WithFallbacks(l1fb, l2fb, srfb)
		log.Info("aggregator: investigation chain wired with Ollama fallback (FR28)",
			"mode", chain.Mode(), "l1_fallback", l1fb != nil, "l2_fallback", l2fb != nil, "senior_fallback", srfb != nil)
		return chain, true, nil
	}

	log.Info("aggregator: investigation chain wired (no Ollama fallback; analyst.local model unset)", "mode", chain.Mode())
	return chain, true, nil
}

// processChainPackage applies the FR19 trigger gate, runs the chain on a
// qualifying package, publishes the assessment to AUDIT.assessments, and
// records the outcome metric. It is the per-message body of the merged FSM
// driver (Story 3.11), factored out so it is unit-testable without a live
// JetStream connection. It returns the per-provider-capped LLM confidence to
// fold into the ThreatScore (0 when not triggered / errored / unavailable)
// and the recorded outcome label.
func processChainPackage(ctx context.Context, pkg schema.EvidencePackage, chain *analyst.Chain, mode string, breaker *analyst.CircuitBreaker, auditPub responseaudit.AssessmentAuditPublisher, runs *prometheus.CounterVec, log *slog.Logger) (int, string) {
	if !analyst.ShouldTriggerChain(pkg) {
		analyst.RecordChainRun(runs, mode, analyst.ChainOutcomeNotTriggered)
		return 0, analyst.ChainOutcomeNotTriggered
	}

	// Story 3.12: the LLM-tier circuit breaker counts every LLM-eligible
	// package; when the global rate exceeds the threshold it engages and the
	// chain is BYPASSED (deterministic-only) for the cooling window, so an
	// attacker spraying triggering events cannot amplify LLM cost (FR51/NFR23).
	// The engage/disengage log + olaitan_llm_circuit_breaker_engaged_total are
	// emitted by the breaker's transition callback, NOT per package.
	if breaker != nil && !breaker.Admit() {
		analyst.RecordChainRun(runs, mode, analyst.ChainOutcomeBreakerBypassed)
		return 0, analyst.ChainOutcomeBreakerBypassed
	}

	res, rerr := chain.Run(ctx, pkg)
	if rerr != nil {
		outcome := analyst.ChainOutcomeError
		if errors.Is(rerr, analyst.ErrNoCitableEvents) {
			outcome = analyst.ChainOutcomeNoCitable
		}
		analyst.RecordChainRun(runs, res.Mode, outcome)
		log.Warn("aggregator: investigation chain run failed; folding zero LLM confidence", "err", rerr, "package_id", pkg.PackageID)
		return 0, outcome
	}

	evt := responseaudit.AssessmentFromChain(buildAssessmentInput(pkg, res, time.Now().UTC()))
	pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	if perr := auditPub.PublishAuditAssessment(pctx, evt); perr != nil {
		log.Warn("aggregator: investigation-chain assessment audit publish failed", "err", perr, "package_id", pkg.PackageID)
	}
	cancel()
	analyst.RecordChainRun(runs, res.Mode, analyst.ChainOutcomeAssessed)
	// LLMCappedConfidence is 0 on the llm_unavailable degrade (Story 3.10),
	// so a degraded assessment folds a zero LLM term -> deterministic-only.
	return res.Assessment.LLMCappedConfidence, analyst.ChainOutcomeAssessed
}

// applyPromptVersionGauge maintains the olaitan_llm_prompt_version info gauge
// (Story 3.15): it retires the prior {role,oldHash} series (a no-op for the
// seed call where oldHash is "") and lights the current {role,newHash} at 1,
// so exactly one series per role is live at a time.
func applyPromptVersionGauge(g *prometheus.GaugeVec, role, oldHash, newHash string) {
	if oldHash != "" && oldHash != newHash {
		g.DeleteLabelValues(role, oldHash)
	}
	g.WithLabelValues(role, newHash).Set(1)
}

// buildAssessmentInput flattens a successful ChainResult onto the ring-clean
// audit.AssessmentInput (Story 3.14 BI-2a/BI-3): cmd is the only ring that
// imports both internal/decision/analyst and internal/response/audit, so the
// projection lives here, keeping the audit package free of an analyst import.
// It redacts the package at the audit boundary (redact.Redact is the same
// pure redaction the providers ran, so this reproduces the bytes the LLM
// saw) and records redaction_applied=true; the RAW pkg is never put on the
// event. Per-role prompt-version/provider/model entries are added only for
// roles that actually ran in this mode (ablation omits the rest).
func buildAssessmentInput(pkg schema.EvidencePackage, res analyst.ChainResult, now time.Time) responseaudit.AssessmentInput {
	redacted, _ := reportredact.Redact(pkg)
	assessment := res.Assessment
	in := responseaudit.AssessmentInput{
		PackageID:        pkg.PackageID,
		WorkloadID:       pkg.WorkloadID,
		Mode:             res.Mode,
		AgentsAvailable:  assessment.AgentsAvailable,
		PromptVersions:   map[string]string{},
		Providers:        map[string]string{},
		Models:           map[string]string{},
		RawConfidence:    assessment.RawConfidence,
		CappedConfidence: assessment.LLMCappedConfidence,
		ThreatAssessment: &assessment,
		RedactedEvidence: redacted,
		RedactionApplied: true,
		Now:              now,
	}
	// A role's per-role metadata is recorded only for roles that actually
	// CONTRIBUTED to the assessment -- the authoritative set is the
	// assessment's AgentsAvailable. This keeps the maps consistent with
	// agents_available (round-1: a full-mode Senior that DEGRADED has its
	// provider set before the failed call, but is excluded from
	// AgentsAvailable, so it must not appear in the maps). Within a
	// contributing role, an EMPTY metadata value is omitted rather than
	// recorded as "" (round-1: a Story 3.9 checkpoint-RESUMED role carries
	// its real hypothesis/verification but zero provider/model/version,
	// since no provider call was made on resume).
	contributed := make(map[string]bool, len(assessment.AgentsAvailable))
	for _, r := range assessment.AgentsAvailable {
		contributed[r] = true
	}
	addRole := func(role, version, provider, model string) {
		if !contributed[role] {
			return
		}
		if version != "" {
			in.PromptVersions[role] = version
		}
		if provider != "" {
			in.Providers[role] = provider
		}
		if model != "" {
			in.Models[role] = model
		}
	}
	if res.L1 != nil && contributed["l1"] {
		addRole("l1", res.L1.PromptVersion, res.L1.Provider, res.L1.Model)
		hyp := res.L1.Hypothesis
		in.L1Hypothesis = &hyp
	}
	if res.L2 != nil && contributed["l2"] {
		addRole("l2", res.L2.PromptVersion, res.L2.Provider, res.L2.Model)
		ver := res.L2.Verification
		in.L2Verification = &ver
	}
	addRole("senior", res.Senior.PromptVersion, res.Senior.Provider, res.Senior.Model)
	// Drop empty (non-nil) maps so omitempty omits them entirely rather than
	// emitting "prompt_versions":{} on a metadata-less run.
	if len(in.PromptVersions) == 0 {
		in.PromptVersions = nil
	}
	if len(in.Providers) == 0 {
		in.Providers = nil
	}
	if len(in.Models) == 0 {
		in.Models = nil
	}
	return in
}

// safeChainConfidence runs processChainPackage inside a recover so a panic in
// the LLM tier (a provider SDK, JSON handling, etc.) degrades to a zero LLM
// contribution rather than tearing down the single FSM-driver goroutine the
// merge (Story 3.11) put it on. The Trust-Bound's promise is that the LLM tier
// can never break containment; that must include a crashing LLM tier. On a
// panic the deterministic rules+baselines score still drives the FSM (NFR27).
func safeChainConfidence(ctx context.Context, pkg schema.EvidencePackage, chain *analyst.Chain, mode string, breaker *analyst.CircuitBreaker, auditPub responseaudit.AssessmentAuditPublisher, runs *prometheus.CounterVec, log *slog.Logger) (capped int) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("aggregator: investigation chain panicked; folding zero LLM confidence (deterministic-only)", "panic", r, "package_id", pkg.PackageID)
			capped = 0
		}
	}()
	capped, _ = processChainPackage(ctx, pkg, chain, mode, breaker, auditPub, runs, log)
	return capped
}
