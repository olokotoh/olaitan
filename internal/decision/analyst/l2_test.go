package analyst

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/olokotoh/olaitan/internal/agent/provider"
	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/schema"
)

const validL2Verdict = `{"verdict":"confirmed","verified_evidence":[{"event_id":"evt-1","finding":"ancestry confirms the chain"}],"confidence":66}`

const refutedL2Verdict = `{"verdict":"refuted","verified_evidence":[{"event_id":"evt-1","finding":"hash matches a log shipper"},{"event_id":"evt-2","finding":"documented startup path"}],"contradictory_findings":["L1 cited evt-1 as a miner; it is fluent-bit"],"confidence":80}`

func testL1Hypothesis() schema.L1Hypothesis {
	return schema.L1Hypothesis{
		SchemaVersion: schema.L1HypothesisSchemaVersion,
		Hypothesis:    "crypto miner launched",
		CitedEvidence: []schema.EvidenceCitation{{EventID: "evt-1"}},
		Confidence:    70,
	}
}

func newL2Runner(t *testing.T, fp *fakeProvider) (*L2, *metrics.Registry) {
	t.Helper()
	reg := metrics.NewRegistry()
	l2, err := NewL2(fp, PromptSpec{System: "you are the L2 verifier", Version: "test.v2"}, reg, nil)
	if err != nil {
		t.Fatalf("NewL2: %v", err)
	}
	return l2, reg
}

func TestL2RunSuccessVerdicts(t *testing.T) {
	for _, verdict := range []string{"confirmed", "refuted", "inconclusive"} {
		raw := `{"verdict":"` + verdict + `","verified_evidence":[{"event_id":"evt-1","finding":"checked"}],"confidence":40}`
		fp := &fakeProvider{name: "fake", model: "fake-model", resp: provider.Response{Raw: raw}}
		l2, reg := newL2Runner(t, fp)
		res, err := l2.Run(context.Background(), testPackage(), testL1Hypothesis())
		if err != nil {
			t.Fatalf("verdict %s: %v", verdict, err)
		}
		if res.Verification.Verdict != verdict {
			t.Errorf("verdict = %q, want %q", res.Verification.Verdict, verdict)
		}
		if res.Verification.SchemaVersion != schema.L2VerificationSchemaVersion {
			t.Errorf("schema_version = %q, want the runner stamp", res.Verification.SchemaVersion)
		}
		if got := counterValue(t, reg, "fake", "l2", StatusSuccess); got != 1 {
			t.Errorf("success series = %v, want 1", got)
		}
		if got := familyTotal(t, reg); got != 1 {
			t.Errorf("family total = %v, want 1", got)
		}
	}
}

// TestL2RunRequestPropagation pins the BI-2/BI-4 transport contract:
// role, schema bytes, verbatim prompts, the package, and the L1
// hypothesis pointer all reach the provider; evidence and hypothesis
// never enter prompt text.
func TestL2RunRequestPropagation(t *testing.T) {
	fp := &fakeProvider{name: "fake", model: "fake-model", resp: provider.Response{Raw: validL2Verdict}}
	l2, _ := newL2Runner(t, fp)
	pkg := testPackage()
	hyp := testL1Hypothesis()
	if _, err := l2.Run(context.Background(), pkg, hyp); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if fp.got.Role != provider.RoleL2 {
		t.Errorf("request role = %q, want %q", fp.got.Role, provider.RoleL2)
	}
	if !bytes.Equal([]byte(fp.got.Schema), l2SchemaJSON) {
		t.Error("request schema is not the embedded l2_verification schema")
	}
	if fp.got.Prompt.System != "you are the L2 verifier" {
		t.Errorf("system prompt not passed verbatim: %q", fp.got.Prompt.System)
	}
	if fp.got.Prompt.User != l2UserInstruction {
		t.Errorf("user instruction not the fixed const: %q", fp.got.Prompt.User)
	}
	if fp.got.Package.PackageID != pkg.PackageID {
		t.Errorf("package not propagated: %q", fp.got.Package.PackageID)
	}
	if fp.got.PriorHypothesis == nil || fp.got.PriorHypothesis.Hypothesis != hyp.Hypothesis {
		t.Errorf("L1 hypothesis not propagated on Request.PriorHypothesis: %+v", fp.got.PriorHypothesis)
	}
	if fp.got.PriorAssessment != nil {
		t.Error("L2 must not carry a prior assessment")
	}
	if strings.Contains(fp.got.Prompt.User, hyp.Hypothesis) || strings.Contains(fp.got.Prompt.System, hyp.Hypothesis) {
		t.Error("L1 hypothesis leaked into prompt text; it must travel only on Request.PriorHypothesis")
	}
}

// TestL2RunContradictionPreserved pins AC3: a refuted verdict with
// contradictory findings survives into L2Result verbatim for the
// Story 3.14 audit publisher.
func TestL2RunContradictionPreserved(t *testing.T) {
	fp := &fakeProvider{name: "fake", model: "fake-model", resp: provider.Response{Raw: refutedL2Verdict}}
	l2, _ := newL2Runner(t, fp)
	res, err := l2.Run(context.Background(), testPackage(), testL1Hypothesis())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Verification.Verdict != schema.VerdictRefuted {
		t.Errorf("verdict = %q", res.Verification.Verdict)
	}
	if len(res.Verification.ContradictoryFindings) != 1 ||
		res.Verification.ContradictoryFindings[0] != "L1 cited evt-1 as a miner; it is fluent-bit" {
		t.Errorf("contradictory findings not preserved verbatim: %+v", res.Verification.ContradictoryFindings)
	}
	if len(res.Verification.VerifiedEvidence) != 2 {
		t.Errorf("verified evidence not preserved: %+v", res.Verification.VerifiedEvidence)
	}
	if res.RawOutput != refutedL2Verdict {
		t.Error("raw output not captured")
	}
	if res.PromptVersion != "test.v2" || res.Provider != "fake" || res.Status != StatusSuccess {
		t.Errorf("audit record incomplete: %+v", res)
	}
}

func TestL2RunSchemaViolations(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"empty body", ""},
		{"not json", "looks fine to me"},
		{"bad verdict", `{"verdict":"maybe","verified_evidence":[{"event_id":"evt-1","finding":"x"}],"confidence":50}`},
		{"missing verdict", `{"verified_evidence":[{"event_id":"evt-1","finding":"x"}],"confidence":50}`},
		{"empty verified_evidence", `{"verdict":"confirmed","verified_evidence":[],"confidence":50}`},
		{"missing finding", `{"verdict":"confirmed","verified_evidence":[{"event_id":"evt-1"}],"confidence":50}`},
		{"whitespace finding", `{"verdict":"confirmed","verified_evidence":[{"event_id":"evt-1","finding":"   "}],"confidence":50}`},
		{"whitespace contradictory entry", `{"verdict":"refuted","verified_evidence":[{"event_id":"evt-1","finding":"x"}],"contradictory_findings":["  "],"confidence":50}`},
		{"unknown event_id", `{"verdict":"confirmed","verified_evidence":[{"event_id":"evt-999","finding":"x"}],"confidence":50}`},
		{"extra top-level field", `{"verdict":"confirmed","verified_evidence":[{"event_id":"evt-1","finding":"x"}],"confidence":50,"threat_type":"miner"}`},
		{"extra item field", `{"verdict":"confirmed","verified_evidence":[{"event_id":"evt-1","finding":"x","severity":"high"}],"confidence":50}`},
		{"confidence above range", `{"verdict":"confirmed","verified_evidence":[{"event_id":"evt-1","finding":"x"}],"confidence":101}`},
		{"non-integer confidence", `{"verdict":"confirmed","verified_evidence":[{"event_id":"evt-1","finding":"x"}],"confidence":55.5}`},
		{"oversized finding", `{"verdict":"confirmed","verified_evidence":[{"event_id":"evt-1","finding":"` + strings.Repeat("f", 501) + `"}],"confidence":50}`},
		{"too many contradictions", `{"verdict":"refuted","verified_evidence":[{"event_id":"evt-1","finding":"x"}],"contradictory_findings":[` + manyProbes(21) + `],"confidence":50}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fp := &fakeProvider{name: "fake", model: "fake-model", resp: provider.Response{Raw: tc.raw}}
			l2, reg := newL2Runner(t, fp)
			res, err := l2.Run(context.Background(), testPackage(), testL1Hypothesis())
			if !errors.Is(err, ErrSchemaViolation) {
				t.Fatalf("err = %v, want ErrSchemaViolation", err)
			}
			if res.Status != StatusSchemaViolation {
				t.Errorf("status = %q", res.Status)
			}
			if res.RawOutput != tc.raw {
				t.Error("audit record lost the raw output")
			}
			if got := counterValue(t, reg, "fake", "l2", StatusSchemaViolation); got != 1 {
				t.Errorf("schema_violation series = %v, want 1", got)
			}
			if got := familyTotal(t, reg); got != 1 {
				t.Errorf("family total = %v, want exactly 1", got)
			}
		})
	}
}

func TestL2RunAcceptanceVariants(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"fence wrapped", "```json\n" + validL2Verdict + "\n```"},
		{"cr-only fence", "```json\r" + validL2Verdict + "\r```"},
		{"integer-valued float confidence", `{"verdict":"confirmed","verified_evidence":[{"event_id":"evt-1","finding":"x"}],"confidence":66.0}`},
		{"null schema_version", `{"schema_version":null,"verdict":"confirmed","verified_evidence":[{"event_id":"evt-1","finding":"x"}],"confidence":66}`},
		{"trigger event id accepted", `{"verdict":"confirmed","verified_evidence":[{"event_id":"evt-trigger","finding":"x"}],"confidence":66}`},
		{"confidence bound 0", `{"verdict":"inconclusive","verified_evidence":[{"event_id":"evt-1","finding":"x"}],"confidence":0}`},
		{"confidence bound 100", `{"verdict":"confirmed","verified_evidence":[{"event_id":"evt-1","finding":"x"}],"confidence":100}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fp := &fakeProvider{name: "fake", model: "fake-model", resp: provider.Response{Raw: tc.raw}}
			l2, _ := newL2Runner(t, fp)
			res, err := l2.Run(context.Background(), testPackage(), testL1Hypothesis())
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if res.Verification.SchemaVersion != schema.L2VerificationSchemaVersion {
				t.Errorf("schema_version = %q, want the runner stamp", res.Verification.SchemaVersion)
			}
		})
	}
}

func TestL2RunProviderError(t *testing.T) {
	fp := &fakeProvider{name: "fake", model: "fake-model", err: errors.New("upstream 529")}
	l2, reg := newL2Runner(t, fp)
	res, err := l2.Run(context.Background(), testPackage(), testL1Hypothesis())
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("err = %v, want ErrProviderUnavailable", err)
	}
	if res.Status != StatusUnavailable || res.Provider != "fake" || res.Model != "fake-model" || res.PromptVersion != "test.v2" {
		t.Errorf("failure record incomplete: %+v", res)
	}
	if got := counterValue(t, reg, "fake", "l2", StatusUnavailable); got != 1 {
		t.Errorf("unavailable series = %v, want 1", got)
	}
}

func TestL2RunTruncatedReply(t *testing.T) {
	for _, stop := range []string{"max_tokens", "length"} {
		fp := &fakeProvider{name: "fake", model: "fake-model", resp: provider.Response{Raw: `{"verdict":"conf`, StopReason: stop}}
		l2, reg := newL2Runner(t, fp)
		_, err := l2.Run(context.Background(), testPackage(), testL1Hypothesis())
		if !errors.Is(err, ErrProviderUnavailable) {
			t.Fatalf("stop_reason %q: err = %v, want ErrProviderUnavailable", stop, err)
		}
		if got := counterValue(t, reg, "fake", "l2", StatusUnavailable); got != 1 {
			t.Errorf("unavailable series = %v, want 1", got)
		}
	}
}

func TestL2RunNoCitableEvents(t *testing.T) {
	fp := &fakeProvider{name: "fake", model: "fake-model", resp: provider.Response{Raw: validL2Verdict}}
	l2, reg := newL2Runner(t, fp)
	pkg := schema.EvidencePackage{PackageID: "pkg-empty"}
	_, err := l2.Run(context.Background(), pkg, testL1Hypothesis())
	if !errors.Is(err, ErrNoCitableEvents) {
		t.Fatalf("err = %v, want ErrNoCitableEvents", err)
	}
	if fp.calls != 0 {
		t.Errorf("provider called %d times; the guard must fire first", fp.calls)
	}
	if got := familyTotal(t, reg); got != 0 {
		t.Errorf("family total = %v, want 0", got)
	}
}

func TestL2RunSchemaNotAliased(t *testing.T) {
	fp := &fakeProvider{name: "fake", model: "fake-model", resp: provider.Response{Raw: validL2Verdict}}
	l2, _ := newL2Runner(t, fp)
	if _, err := l2.Run(context.Background(), testPackage(), testL1Hypothesis()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	original := l2SchemaJSON[0]
	fp.got.Schema[0] = '!'
	if l2SchemaJSON[0] != original {
		t.Error("mutating the request schema corrupted the embedded schema")
	}
}

func TestL2RunOversizedEventIDInErrorBounded(t *testing.T) {
	longID := strings.Repeat("z", 100)
	raw := `{"verdict":"confirmed","verified_evidence":[{"event_id":"` + longID + `","finding":"x"}],"confidence":50}`
	fp := &fakeProvider{name: "fake", model: "fake-model", resp: provider.Response{Raw: raw}}
	l2, _ := newL2Runner(t, fp)
	_, err := l2.Run(context.Background(), testPackage(), testL1Hypothesis())
	if !errors.Is(err, ErrSchemaViolation) {
		t.Fatalf("err = %v, want ErrSchemaViolation", err)
	}
	if strings.Contains(err.Error(), longID) {
		t.Error("error carries the full 100-byte event_id; boundForLog not applied")
	}
}

func TestNewL2Validation(t *testing.T) {
	reg := metrics.NewRegistry()
	if _, err := NewL2(nil, PromptSpec{}, reg, nil); err == nil {
		t.Error("nil provider: err = nil, want error")
	}
	if _, err := NewL2(&fakeProvider{name: "fake", model: "m"}, PromptSpec{}, nil, nil); err == nil {
		t.Error("nil registry: err = nil, want error")
	}
}

// TestL1AndL2ShareTheDecisionFamily pins the BI-4 reuse requirement
// with REAL increments (Story 3.4 lesson): both runners on one registry
// feed the same olaitan_decision_llm_calls_total family under their own
// role labels.
func TestL1AndL2ShareTheDecisionFamily(t *testing.T) {
	reg := metrics.NewRegistry()
	fp1 := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: validVerdict}}
	fp2 := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: validL2Verdict}}
	l1, err := NewL1(fp1, PromptSpec{Version: "v"}, reg, nil)
	if err != nil {
		t.Fatalf("NewL1: %v", err)
	}
	l2, err := NewL2(fp2, PromptSpec{Version: "v"}, reg, nil)
	if err != nil {
		t.Fatalf("NewL2 on the same registry: %v (registration must be idempotent)", err)
	}
	if _, err := l1.Run(context.Background(), testPackage()); err != nil {
		t.Fatalf("L1 Run: %v", err)
	}
	if _, err := l2.Run(context.Background(), testPackage(), testL1Hypothesis()); err != nil {
		t.Fatalf("L2 Run: %v", err)
	}
	if got := counterValue(t, reg, "fake", "l1", StatusSuccess); got != 1 {
		t.Errorf("l1 series = %v, want 1", got)
	}
	if got := counterValue(t, reg, "fake", "l2", StatusSuccess); got != 1 {
		t.Errorf("l2 series = %v, want 1", got)
	}
	if got := familyTotal(t, reg); got != 2 {
		t.Errorf("family total = %v, want 2", got)
	}
}

func TestShouldSkipL2(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		skip   bool
		reason string
	}{
		{"nil error", nil, false, ""},
		{"provider unavailable wrapped", fmt.Errorf("%w: %w", ErrProviderUnavailable, errors.New("529")), true, L2SkipReasonL1Unavailable},
		{"schema violation does not skip pre-3.10", fmt.Errorf("%w: bad json", ErrSchemaViolation), false, ""},
		{"plain error does not skip", errors.New("boom"), false, ""},
		{"no citable events does not skip here (3.8 owns it)", fmt.Errorf("%w: empty", ErrNoCitableEvents), false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			skip, reason := ShouldSkipL2(tc.err)
			if skip != tc.skip || reason != tc.reason {
				t.Errorf("ShouldSkipL2 = (%v, %q), want (%v, %q)", skip, reason, tc.skip, tc.reason)
			}
		})
	}
}

func TestRegisterL2SkippedMetric(t *testing.T) {
	reg := metrics.NewRegistry()
	first, err := RegisterL2SkippedMetric(reg)
	if err != nil {
		t.Fatalf("first registration: %v", err)
	}
	second, err := RegisterL2SkippedMetric(reg)
	if err != nil {
		t.Fatalf("second registration: %v", err)
	}
	if first != second {
		t.Error("second registration returned a different collector")
	}
	first.WithLabelValues(L2SkipReasonL1Unavailable).Inc()
	mfs, err := reg.Gatherer().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == L2SkippedMetricName {
			if got := mf.GetMetric()[0].GetCounter().GetValue(); got != 1 {
				t.Errorf("skip counter = %v, want 1 (real increment, Story 3.4 lesson)", got)
			}
			return
		}
	}
	t.Fatalf("%s not found in registry", L2SkippedMetricName)
}

func TestRegisterL2SkippedMetricNilRegistry(t *testing.T) {
	var reg *metrics.Registry
	if _, err := RegisterL2SkippedMetric(reg); err == nil {
		t.Fatal("nil registry: err = nil, want error")
	}
}
