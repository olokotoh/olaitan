package analyst

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/olokotoh/olaitan/internal/agent/provider"
	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/schema"
)

// fallbackCounter reads olaitan_llm_fallback_total for a (from, to, role) tuple.
func fallbackCounter(t *testing.T, reg *metrics.Registry, from, to, role string) float64 {
	t.Helper()
	mfs, err := reg.Gatherer().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != FallbackMetricName {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["from_provider"] == from && labels["to_provider"] == to && labels["role"] == role {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// chainWithFallbacks wires a chain (fast retry) plus per-role Ollama fallback
// runners built from the given fallback fakes (nil = no fallback for that role).
func chainWithFallbacks(t *testing.T, l1fp, l2fp, srfp, l1fb, l2fb, srfb *fakeProvider) (*Chain, *metrics.Registry) {
	t.Helper()
	chain, reg := newTestChain(t, l1fp, l2fp, srfp)
	var fl1 *L1
	var fl2 *L2
	var fsr *Senior
	if l1fb != nil {
		fl1, _ = NewL1(l1fb, PromptSpec{System: "fb-l1", Version: "fv1"}, reg, nil)
	}
	if l2fb != nil {
		fl2, _ = NewL2(l2fb, PromptSpec{System: "fb-l2", Version: "fv2"}, reg, nil)
	}
	if srfb != nil {
		fsr, _ = NewSenior(srfb, PromptSpec{System: "fb-sr", Version: "fv3"}, reg, nil)
	}
	chain.WithFallbacks(fl1, fl2, fsr)
	return chain, reg
}

// TestChainRetrySchemaViolationThenSuccess (AC1/AC2): an L1 schema violation
// on the first attempt is retried; the second attempt succeeds. No fallback
// is wired, so the fall-through metric stays at zero.
func TestChainRetrySchemaViolationThenSuccess(t *testing.T) {
	l1fp := &fakeProvider{name: "claude", model: "m", resp: provider.Response{Raw: validVerdict}, failTimes: 1, failResp: provider.Response{Raw: "not json at all"}}
	l2fp := &fakeProvider{name: "claude", model: "m", resp: provider.Response{Raw: validL2Verdict}}
	srfp := &fakeProvider{name: "claude", model: "m", resp: provider.Response{Raw: validSeniorVerdict}}
	chain, reg := newTestChain(t, l1fp, l2fp, srfp)

	res, err := chain.Run(context.Background(), testPackage())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if l1fp.calls != 2 {
		t.Errorf("L1 calls = %d, want 2 (one schema violation + one success)", l1fp.calls)
	}
	if res.Assessment.ThreatType == "" {
		t.Errorf("retry-then-success must produce a full assessment, got %+v", res.Assessment)
	}
	if fallbackCounter(t, reg, "claude", "ollama", "l1") != 0 {
		t.Error("no fallback was wired; the fall-through metric must stay 0")
	}
}

// TestChainRetryTransientThenSuccess (AC2): a transient provider error on the
// first attempt is retried; the second attempt succeeds.
func TestChainRetryTransientThenSuccess(t *testing.T) {
	l1fp := &fakeProvider{name: "claude", model: "m", resp: provider.Response{Raw: validVerdict}, failTimes: 2, failErr: errors.New("upstream 529")}
	l2fp := &fakeProvider{name: "claude", model: "m", resp: provider.Response{Raw: validL2Verdict}}
	srfp := &fakeProvider{name: "claude", model: "m", resp: provider.Response{Raw: validSeniorVerdict}}
	chain, _ := newTestChain(t, l1fp, l2fp, srfp)

	res, err := chain.Run(context.Background(), testPackage())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if l1fp.calls != 3 {
		t.Errorf("L1 calls = %d, want 3 (two transient + one success on the last allowed strike)", l1fp.calls)
	}
	if res.Assessment.ThreatType == "" {
		t.Error("retry-then-success on the third strike must still produce an assessment")
	}
}

// TestChainRetryExhaustNoFallback (AC2): a persistently-failing L1 with no
// fallback exhausts all 3 strikes (provider reached 3 times) and the chain
// degrades to the L1-unavailable path (skip L2, Senior evidence-only).
func TestChainRetryExhaustNoFallback(t *testing.T) {
	l1fp := &fakeProvider{name: "claude", model: "m", err: errors.New("upstream 529")}
	l2fp := &fakeProvider{name: "claude", model: "m", resp: provider.Response{Raw: validL2Verdict}}
	srfp := &fakeProvider{name: "claude", model: "m", resp: provider.Response{Raw: validSeniorVerdict}}
	chain, reg := newTestChain(t, l1fp, l2fp, srfp)

	res, err := chain.Run(context.Background(), testPackage())
	if err != nil {
		t.Fatalf("Run: %v (L1-unavailable evidence-only mode must still produce an assessment)", err)
	}
	if l1fp.calls != 3 {
		t.Errorf("L1 calls = %d, want 3 (the full 3-strike retry)", l1fp.calls)
	}
	if !res.L2Skipped || res.SkipReason != L2SkipReasonL1Unavailable {
		t.Errorf("skip state = %v/%q, want L1-unavailable", res.L2Skipped, res.SkipReason)
	}
	if fallbackCounter(t, reg, "claude", "ollama", "l1") != 0 {
		t.Error("no fallback wired; metric must stay 0")
	}
}

// TestChainPreconditionNoRetry (BI-2): a precondition abort (no citable
// events) is marked permanent, so the provider is never reached and no retry
// burns attempts.
func TestChainPreconditionNoRetry(t *testing.T) {
	l1fp := &fakeProvider{name: "claude", model: "m", resp: provider.Response{Raw: validVerdict}}
	l2fp := &fakeProvider{name: "claude", model: "m", resp: provider.Response{Raw: validL2Verdict}}
	srfp := &fakeProvider{name: "claude", model: "m", resp: provider.Response{Raw: validSeniorVerdict}}
	chain, _ := newTestChain(t, l1fp, l2fp, srfp)

	_, err := chain.Run(context.Background(), schema.EvidencePackage{PackageID: "pkg-empty"})
	if !errors.Is(err, ErrNoCitableEvents) {
		t.Fatalf("err = %v, want ErrNoCitableEvents", err)
	}
	if l1fp.calls != 0 {
		t.Errorf("L1 provider reached %d times for an unassessable package; a precondition must not retry", l1fp.calls)
	}
}

// TestChainFallbackL1Success (AC3): the primary L1 exhausts its retries and
// the chain falls through to the Ollama fallback, which succeeds. The
// fall-through metric increments once and the full chain runs.
func TestChainFallbackL1Success(t *testing.T) {
	l1fp := &fakeProvider{name: "claude", model: "m", err: errors.New("upstream 529")}
	l2fp := &fakeProvider{name: "claude", model: "m", resp: provider.Response{Raw: validL2Verdict}}
	srfp := &fakeProvider{name: "claude", model: "m", resp: provider.Response{Raw: validSeniorVerdict}}
	l1fb := &fakeProvider{name: "ollama", model: "gemma", resp: provider.Response{Raw: validVerdict}}
	chain, reg := chainWithFallbacks(t, l1fp, l2fp, srfp, l1fb, nil, nil)

	res, err := chain.Run(context.Background(), testPackage())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if l1fp.calls != 3 || l1fb.calls != 1 {
		t.Errorf("primary/fallback L1 calls = %d/%d, want 3/1", l1fp.calls, l1fb.calls)
	}
	if got := fallbackCounter(t, reg, "claude", "ollama", "l1"); got != 1 {
		t.Errorf("fallback counter = %v, want 1", got)
	}
	if res.Assessment.ThreatType == "" || res.L2Skipped {
		t.Errorf("a successful L1 fallback must run the full chain, got %+v skipped=%v", res.Assessment, res.L2Skipped)
	}
}

// TestChainFallbackL1AlsoFails (AC4): primary and fallback both exhaust; the
// metric still increments once at the fall-through, and the role is treated as
// unavailable (skip L2, Senior evidence-only).
func TestChainFallbackL1AlsoFails(t *testing.T) {
	l1fp := &fakeProvider{name: "claude", model: "m", err: errors.New("primary down")}
	l2fp := &fakeProvider{name: "claude", model: "m", resp: provider.Response{Raw: validL2Verdict}}
	srfp := &fakeProvider{name: "claude", model: "m", resp: provider.Response{Raw: validSeniorVerdict}}
	l1fb := &fakeProvider{name: "ollama", model: "gemma", err: errors.New("ollama down too")}
	chain, reg := chainWithFallbacks(t, l1fp, l2fp, srfp, l1fb, nil, nil)

	res, err := chain.Run(context.Background(), testPackage())
	if err != nil {
		t.Fatalf("Run: %v (both-unavailable still degrades to evidence-only, not abort)", err)
	}
	if l1fp.calls != 3 || l1fb.calls != 3 {
		t.Errorf("primary/fallback L1 calls = %d/%d, want 3/3", l1fp.calls, l1fb.calls)
	}
	if got := fallbackCounter(t, reg, "claude", "ollama", "l1"); got != 1 {
		t.Errorf("fallback counter = %v, want 1 (incremented once at the fall-through, regardless of fallback outcome)", got)
	}
	if !res.L2Skipped || res.SkipReason != L2SkipReasonL1Unavailable {
		t.Errorf("skip state = %v/%q, want L1-unavailable", res.L2Skipped, res.SkipReason)
	}
}

// TestChainFallbackL2Success (AC3, L2 role): the primary L2 exhausts and the
// Ollama fallback succeeds; the metric records the l2 fall-through.
func TestChainFallbackL2Success(t *testing.T) {
	l1fp := &fakeProvider{name: "claude", model: "m", resp: provider.Response{Raw: validVerdict}}
	l2fp := &fakeProvider{name: "claude", model: "m", err: errors.New("l2 down")}
	srfp := &fakeProvider{name: "claude", model: "m", resp: provider.Response{Raw: validSeniorVerdict}}
	l2fb := &fakeProvider{name: "ollama", model: "gemma", resp: provider.Response{Raw: validL2Verdict}}
	chain, reg := chainWithFallbacks(t, l1fp, l2fp, srfp, nil, l2fb, nil)

	res, err := chain.Run(context.Background(), testPackage())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if l2fp.calls != 3 || l2fb.calls != 1 {
		t.Errorf("primary/fallback L2 calls = %d/%d, want 3/1", l2fp.calls, l2fb.calls)
	}
	if got := fallbackCounter(t, reg, "claude", "ollama", "l2"); got != 1 {
		t.Errorf("fallback counter = %v, want 1", got)
	}
	if strings.Join(res.Assessment.AgentsAvailable, ",") != "l1,l2,senior" {
		t.Errorf("agents_available = %v, want l1,l2,senior (L2 recovered via fallback)", res.Assessment.AgentsAvailable)
	}
}

// TestChainFallbackSeniorSuccess (AC3, Senior role): the primary Senior
// exhausts and the Ollama fallback succeeds, so the chain produces a real
// verdict rather than the llm_unavailable degrade.
func TestChainFallbackSeniorSuccess(t *testing.T) {
	l1fp := &fakeProvider{name: "claude", model: "m", resp: provider.Response{Raw: validVerdict}}
	l2fp := &fakeProvider{name: "claude", model: "m", resp: provider.Response{Raw: validL2Verdict}}
	srfp := &fakeProvider{name: "claude", model: "m", err: errors.New("senior down")}
	srfb := &fakeProvider{name: "ollama", model: "gemma", resp: provider.Response{Raw: validSeniorVerdict}}
	chain, reg := chainWithFallbacks(t, l1fp, l2fp, srfp, nil, nil, srfb)

	res, err := chain.Run(context.Background(), testPackage())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if srfp.calls != 3 || srfb.calls != 1 {
		t.Errorf("primary/fallback Senior calls = %d/%d, want 3/1", srfp.calls, srfb.calls)
	}
	if got := fallbackCounter(t, reg, "claude", "ollama", "senior"); got != 1 {
		t.Errorf("fallback counter = %v, want 1", got)
	}
	if res.Assessment.LLMUnavailable || res.Assessment.ThreatType == "" {
		t.Errorf("a successful Senior fallback must produce a real verdict, got %+v", res.Assessment)
	}
}

// TestChainNoFallbackWiringIsByteIdentical (BI-1): WithFallbacks(nil,nil,nil)
// plus a first-try success keeps the Story 3.9 behaviour — no fall-through
// metric series, a normal full assessment.
func TestChainNoFallbackWiringIsByteIdentical(t *testing.T) {
	l1fp := &fakeProvider{name: "claude", model: "m", resp: provider.Response{Raw: validVerdict}}
	l2fp := &fakeProvider{name: "claude", model: "m", resp: provider.Response{Raw: validL2Verdict}}
	srfp := &fakeProvider{name: "claude", model: "m", resp: provider.Response{Raw: validSeniorVerdict}}
	chain, reg := chainWithFallbacks(t, l1fp, l2fp, srfp, nil, nil, nil)

	res, err := chain.Run(context.Background(), testPackage())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if l1fp.calls != 1 || l2fp.calls != 1 || srfp.calls != 1 {
		t.Errorf("first-try success must call each role once, got %d/%d/%d", l1fp.calls, l2fp.calls, srfp.calls)
	}
	if res.Assessment.ThreatType == "" || res.Assessment.LLMUnavailable {
		t.Errorf("first-try success must be a normal assessment, got %+v", res.Assessment)
	}
	if fallbackCounter(t, reg, "claude", "ollama", "l1") != 0 {
		t.Error("no fall-through happened; metric must stay 0")
	}
}
