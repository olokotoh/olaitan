package analyst

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/olokotoh/olaitan/internal/agent/provider"
	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/report/redact"
	"github.com/olokotoh/olaitan/internal/schema"
)

// fakeProvider is the AC5 fake transport: it records the Request it was
// handed and replies with a canned Response or error. No redaction, no
// retries, no timeout; those are real-provider concerns the L1 runner
// must not depend on.
type fakeProvider struct {
	name  string
	model string
	resp  provider.Response
	err   error
	got   provider.Request
	calls int
}

func (f *fakeProvider) Name() string                 { return f.name }
func (f *fakeProvider) Model() string                { return f.model }
func (f *fakeProvider) MaxContextTokens() int        { return 200000 }
func (f *fakeProvider) ScoreCap() int                { return 25 }
func (f *fakeProvider) SupportsStreaming() bool      { return false }
func (f *fakeProvider) Health(context.Context) error { return nil }

func (f *fakeProvider) Analyse(_ context.Context, req provider.Request) (provider.Response, error) {
	f.calls++
	f.got = req
	return f.resp, f.err
}

func testPackage() schema.EvidencePackage {
	return schema.EvidencePackage{
		PackageID: "pkg-l1-test",
		Trigger:   schema.EvidenceTrigger{Type: "rule_match", EventID: "evt-trigger"},
		Events: []schema.Event{
			{ID: "evt-1", Source: schema.SourceFalco, Category: schema.CategorySyscall, Summary: "execve xmrig"},
			{ID: "evt-2", Source: schema.SourceAudit, Category: schema.CategoryAPI, Summary: "secret read"},
		},
	}
}

const validVerdict = `{"hypothesis":"crypto miner launched","cited_evidence":[{"event_id":"evt-1","note":"miner binary"}],"follow_up_probes":["check outbound connections"],"confidence":70}`

func newRunner(t *testing.T, fp *fakeProvider) (*L1, *metrics.Registry) {
	t.Helper()
	reg := metrics.NewRegistry()
	l1, err := NewL1(fp, PromptSpec{System: "you are the L1 analyst", Version: "test.v1"}, reg, nil)
	if err != nil {
		t.Fatalf("NewL1: %v", err)
	}
	return l1, reg
}

// counterValue gathers reg and returns the olaitan_decision_llm_calls_total
// sample for the given label values (0 when the series does not exist).
func counterValue(t *testing.T, reg *metrics.Registry, providerLabel, role, status string) float64 {
	t.Helper()
	mfs, err := reg.Gatherer().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != DecisionCallsMetricName {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["provider"] == providerLabel && labels["role"] == role && labels["status"] == status {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// familyTotal sums every series of the decision family.
func familyTotal(t *testing.T, reg *metrics.Registry) float64 {
	t.Helper()
	mfs, err := reg.Gatherer().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	var total float64
	for _, mf := range mfs {
		if mf.GetName() != DecisionCallsMetricName {
			continue
		}
		for _, m := range mf.GetMetric() {
			total += m.GetCounter().GetValue()
		}
	}
	return total
}

func TestL1RunSuccess(t *testing.T) {
	fp := &fakeProvider{name: "fake", model: "fake-model", resp: provider.Response{Raw: validVerdict, Model: "fake-model-served"}}
	l1, reg := newRunner(t, fp)
	pkg := testPackage()

	res, err := l1.Run(context.Background(), pkg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Request propagation (BI-10).
	if fp.got.Role != provider.RoleL1 {
		t.Errorf("request role = %q, want %q", fp.got.Role, provider.RoleL1)
	}
	if !bytes.Equal([]byte(fp.got.Schema), l1SchemaJSON) {
		t.Error("request schema is not the embedded l1_hypothesis schema")
	}
	if fp.got.Prompt.System != "you are the L1 analyst" {
		t.Errorf("system prompt not passed verbatim: %q", fp.got.Prompt.System)
	}
	if fp.got.Prompt.User != l1UserInstruction {
		t.Errorf("user instruction not the fixed const: %q", fp.got.Prompt.User)
	}
	if fp.got.Package.PackageID != pkg.PackageID {
		t.Errorf("package not propagated: %q", fp.got.Package.PackageID)
	}
	if fp.got.PriorAssessment != nil {
		t.Error("L1 must not carry a prior assessment")
	}

	// Verdict (AC2) and the BI-4 stamp.
	if res.Hypothesis.Hypothesis != "crypto miner launched" {
		t.Errorf("hypothesis = %q", res.Hypothesis.Hypothesis)
	}
	if res.Hypothesis.SchemaVersion != schema.L1HypothesisSchemaVersion {
		t.Errorf("schema_version = %q, want %q (runner stamp)", res.Hypothesis.SchemaVersion, schema.L1HypothesisSchemaVersion)
	}
	if res.Hypothesis.Confidence != 70 {
		t.Errorf("confidence = %d, want 70", res.Hypothesis.Confidence)
	}

	// Audit record (AC4, BI-9).
	if res.PromptVersion != "test.v1" {
		t.Errorf("prompt version = %q", res.PromptVersion)
	}
	if res.System != "you are the L1 analyst" || res.User != l1UserInstruction {
		t.Error("audit record does not carry the full input prompt pair")
	}
	if res.Provider != "fake" {
		t.Errorf("provider = %q", res.Provider)
	}
	if res.Model != "fake-model-served" {
		t.Errorf("model = %q, want the Response-echoed model", res.Model)
	}
	if res.RawOutput != validVerdict {
		t.Error("raw output not captured")
	}
	if res.Latency < 0 {
		t.Errorf("latency = %v", res.Latency)
	}
	if res.Status != StatusSuccess {
		t.Errorf("status = %q", res.Status)
	}

	// Metric (AC4): exactly one increment, on the success series.
	if got := counterValue(t, reg, "fake", "l1", StatusSuccess); got != 1 {
		t.Errorf("success series = %v, want 1", got)
	}
	if got := familyTotal(t, reg); got != 1 {
		t.Errorf("family total = %v, want 1 (exactly one increment per Run)", got)
	}
}

func TestL1RunModelFallsBackToPinned(t *testing.T) {
	fp := &fakeProvider{name: "fake", model: "fake-model", resp: provider.Response{Raw: validVerdict}}
	l1, _ := newRunner(t, fp)
	res, err := l1.Run(context.Background(), testPackage())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Model != "fake-model" {
		t.Errorf("model = %q, want the pinned constructor model when Response.Model is empty", res.Model)
	}
}

func TestL1RunFenceWrappedAccepted(t *testing.T) {
	raw := "```json\n" + validVerdict + "\n```"
	fp := &fakeProvider{name: "fake", model: "fake-model", resp: provider.Response{Raw: raw}}
	l1, _ := newRunner(t, fp)
	res, err := l1.Run(context.Background(), testPackage())
	if err != nil {
		t.Fatalf("Run on fence-wrapped JSON: %v", err)
	}
	if res.Hypothesis.Confidence != 70 {
		t.Errorf("confidence = %d", res.Hypothesis.Confidence)
	}
}

func TestL1RunTriggerEventIDAccepted(t *testing.T) {
	// The trigger event may have been dropped by the overflow cap; citing
	// it must not be a violation (BI-6.5 union).
	raw := `{"hypothesis":"trigger event cited","cited_evidence":[{"event_id":"evt-trigger"}],"confidence":33}`
	fp := &fakeProvider{name: "fake", model: "fake-model", resp: provider.Response{Raw: raw}}
	l1, _ := newRunner(t, fp)
	if _, err := l1.Run(context.Background(), testPackage()); err != nil {
		t.Fatalf("Run citing the trigger event id: %v", err)
	}
}

func TestL1RunSchemaViolations(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"empty body", ""},
		{"whitespace body", "   \n\t  "},
		{"empty fence body", "```json\n```"},
		{"not json", "the pod is probably mining crypto, confidence high"},
		{"missing hypothesis", `{"cited_evidence":[{"event_id":"evt-1"}],"confidence":50}`},
		{"whitespace-only hypothesis", `{"hypothesis":"   ","cited_evidence":[{"event_id":"evt-1"}],"confidence":50}`},
		{"oversized hypothesis", `{"hypothesis":"` + strings.Repeat("a", 2001) + `","cited_evidence":[{"event_id":"evt-1"}],"confidence":50}`},
		{"empty citations", `{"hypothesis":"x","cited_evidence":[],"confidence":50}`},
		{"duplicate identical citations", `{"hypothesis":"x","cited_evidence":[{"event_id":"evt-1"},{"event_id":"evt-1"}],"confidence":50}`},
		{"too many citations", `{"hypothesis":"x","cited_evidence":[` + manyCitations(51) + `],"confidence":50}`},
		{"too many probes", `{"hypothesis":"x","cited_evidence":[{"event_id":"evt-1"}],"follow_up_probes":[` + manyProbes(21) + `],"confidence":50}`},
		{"oversized probe", `{"hypothesis":"x","cited_evidence":[{"event_id":"evt-1"}],"follow_up_probes":["` + strings.Repeat("p", 501) + `"],"confidence":50}`},
		{"confidence above range", `{"hypothesis":"x","cited_evidence":[{"event_id":"evt-1"}],"confidence":101}`},
		{"confidence below range", `{"hypothesis":"x","cited_evidence":[{"event_id":"evt-1"}],"confidence":-1}`},
		{"non-integer confidence", `{"hypothesis":"x","cited_evidence":[{"event_id":"evt-1"}],"confidence":55.5}`},
		{"extra top-level field", `{"hypothesis":"x","cited_evidence":[{"event_id":"evt-1"}],"confidence":50,"recommended_state":"QUARANTINED"}`},
		{"extra citation field", `{"hypothesis":"x","cited_evidence":[{"event_id":"evt-1","severity":"high"}],"confidence":50}`},
		{"unknown event_id", `{"hypothesis":"x","cited_evidence":[{"event_id":"evt-999"}],"confidence":50}`},
		{"unclosed fence", "```json\n" + `{"hypothesis":"x"`},
		{"payload crammed onto the fence line", "```json " + validVerdict + "\n```"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fp := &fakeProvider{name: "fake", model: "fake-model", resp: provider.Response{Raw: tc.raw}}
			l1, reg := newRunner(t, fp)
			res, err := l1.Run(context.Background(), testPackage())
			if !errors.Is(err, ErrSchemaViolation) {
				t.Fatalf("err = %v, want ErrSchemaViolation", err)
			}
			if errors.Is(err, ErrProviderUnavailable) {
				t.Error("violation must not also classify as provider unavailability")
			}
			if res.Status != StatusSchemaViolation {
				t.Errorf("status = %q", res.Status)
			}
			if res.RawOutput != tc.raw {
				t.Error("audit record lost the raw output on the violation path")
			}
			if res.Hypothesis.Hypothesis != "" {
				t.Error("violation path returned a non-zero hypothesis")
			}
			if got := counterValue(t, reg, "fake", "l1", StatusSchemaViolation); got != 1 {
				t.Errorf("schema_violation series = %v, want 1", got)
			}
			if got := familyTotal(t, reg); got != 1 {
				t.Errorf("family total = %v, want exactly 1", got)
			}
		})
	}
}

func TestL1RunProviderError(t *testing.T) {
	fp := &fakeProvider{name: "fake", model: "fake-model", err: errors.New("upstream 529")}
	l1, reg := newRunner(t, fp)
	res, err := l1.Run(context.Background(), testPackage())
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("err = %v, want ErrProviderUnavailable", err)
	}
	if errors.Is(err, ErrSchemaViolation) {
		t.Error("provider failure must not also classify as a schema violation")
	}
	if res.Status != StatusUnavailable {
		t.Errorf("status = %q", res.Status)
	}
	if res.Provider != "fake" || res.Model != "fake-model" {
		t.Errorf("failure record incomplete: provider=%q model=%q", res.Provider, res.Model)
	}
	if res.PromptVersion != "test.v1" {
		t.Error("failure record lost the prompt version")
	}
	if res.RawOutput != "" {
		t.Error("no raw output exists on the unavailable path")
	}
	if got := counterValue(t, reg, "fake", "l1", StatusUnavailable); got != 1 {
		t.Errorf("unavailable series = %v, want 1", got)
	}
	if got := familyTotal(t, reg); got != 1 {
		t.Errorf("family total = %v, want exactly 1", got)
	}
}

func TestL1RunSchemaVersionOverwritten(t *testing.T) {
	raw := `{"schema_version":"bogus.v9","hypothesis":"x","cited_evidence":[{"event_id":"evt-1"}],"confidence":50}`
	fp := &fakeProvider{name: "fake", model: "fake-model", resp: provider.Response{Raw: raw}}
	l1, _ := newRunner(t, fp)
	res, err := l1.Run(context.Background(), testPackage())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Hypothesis.SchemaVersion != schema.L1HypothesisSchemaVersion {
		t.Errorf("schema_version = %q, want the runner stamp to override the model's value", res.Hypothesis.SchemaVersion)
	}
}

// manyCitations builds n distinct citation objects (ids evt-gen-0..n-1)
// for schema-stage maxItems checks (the schema runs before the
// referential check, so the unknown ids never reach it).
func manyCitations(n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = `{"event_id":"evt-gen-` + string(rune('a'+i%26)) + strings.Repeat("x", i/26+1) + `"}`
	}
	return strings.Join(parts, ",")
}

func manyProbes(n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = `"probe"`
	}
	return strings.Join(parts, ",")
}

// TestL1RunIntegerValuedFloatConfidence pins the round-1 review fix:
// draft 2020-12 "integer" accepts any number with a zero fractional
// part, so a reply carrying 70.0 or 1e2 conforms to the published
// contract and must NOT burn a Story 3.10 strike.
func TestL1RunIntegerValuedFloatConfidence(t *testing.T) {
	for _, raw := range []string{
		`{"hypothesis":"x","cited_evidence":[{"event_id":"evt-1"}],"confidence":70.0}`,
		`{"hypothesis":"x","cited_evidence":[{"event_id":"evt-1"}],"confidence":1e2}`,
	} {
		fp := &fakeProvider{name: "fake", model: "fake-model", resp: provider.Response{Raw: raw}}
		l1, _ := newRunner(t, fp)
		res, err := l1.Run(context.Background(), testPackage())
		if err != nil {
			t.Fatalf("Run(%s): %v (schema-conformant reply rejected)", raw, err)
		}
		want := 70
		if strings.Contains(raw, "1e2") {
			want = 100
		}
		if res.Hypothesis.Confidence != want {
			t.Errorf("confidence = %d, want %d", res.Hypothesis.Confidence, want)
		}
	}
}

// TestL1RunConfidenceBounds pins inclusive acceptance at 0 and 100, so
// a future schema edit to exclusive bounds cannot pass the suite.
func TestL1RunConfidenceBounds(t *testing.T) {
	for _, conf := range []string{"0", "100"} {
		raw := `{"hypothesis":"x","cited_evidence":[{"event_id":"evt-1"}],"confidence":` + conf + `}`
		fp := &fakeProvider{name: "fake", model: "fake-model", resp: provider.Response{Raw: raw}}
		l1, _ := newRunner(t, fp)
		if _, err := l1.Run(context.Background(), testPackage()); err != nil {
			t.Errorf("confidence %s rejected: %v", conf, err)
		}
	}
}

func TestL1RunNullSchemaVersionAccepted(t *testing.T) {
	raw := `{"schema_version":null,"hypothesis":"x","cited_evidence":[{"event_id":"evt-1"}],"confidence":5}`
	fp := &fakeProvider{name: "fake", model: "fake-model", resp: provider.Response{Raw: raw}}
	l1, _ := newRunner(t, fp)
	res, err := l1.Run(context.Background(), testPackage())
	if err != nil {
		t.Fatalf("null schema_version burned a strike: %v", err)
	}
	if res.Hypothesis.SchemaVersion != schema.L1HypothesisSchemaVersion {
		t.Errorf("schema_version = %q, want the runner stamp", res.Hypothesis.SchemaVersion)
	}
}

func TestL1RunCROnlyFenceAccepted(t *testing.T) {
	raw := "```json\r" + validVerdict + "\r```"
	fp := &fakeProvider{name: "fake", model: "fake-model", resp: provider.Response{Raw: raw}}
	l1, _ := newRunner(t, fp)
	if _, err := l1.Run(context.Background(), testPackage()); err != nil {
		t.Fatalf("CR-only fenced reply rejected: %v", err)
	}
}

// TestL1RunTruncatedReply pins the round-1 review fix: an
// output-token-ceiling truncation is a transport/config condition
// (unavailable), not a model schema violation.
func TestL1RunTruncatedReply(t *testing.T) {
	for _, stop := range []string{"max_tokens", "length", "MAX_TOKENS"} {
		fp := &fakeProvider{name: "fake", model: "fake-model", resp: provider.Response{Raw: `{"hypothesis":"cut of`, StopReason: stop}}
		l1, reg := newRunner(t, fp)
		res, err := l1.Run(context.Background(), testPackage())
		if !errors.Is(err, ErrProviderUnavailable) {
			t.Fatalf("stop_reason %q: err = %v, want ErrProviderUnavailable", stop, err)
		}
		if errors.Is(err, ErrSchemaViolation) {
			t.Error("truncation must not classify as a schema violation")
		}
		if res.Status != StatusUnavailable {
			t.Errorf("status = %q", res.Status)
		}
		if res.RawOutput == "" {
			t.Error("truncated raw output not captured for audit")
		}
		if got := counterValue(t, reg, "fake", "l1", StatusUnavailable); got != 1 {
			t.Errorf("unavailable series = %v, want 1", got)
		}
	}
}

// TestL1RunNoCitableEvents pins the round-1 review guard: an empty
// citable set makes a conformant reply impossible, so no provider call
// is spent and no decision outcome is recorded.
func TestL1RunNoCitableEvents(t *testing.T) {
	fp := &fakeProvider{name: "fake", model: "fake-model", resp: provider.Response{Raw: validVerdict}}
	l1, reg := newRunner(t, fp)
	pkg := schema.EvidencePackage{PackageID: "pkg-empty", Trigger: schema.EvidenceTrigger{Type: "baseline_deviation"}}
	res, err := l1.Run(context.Background(), pkg)
	if !errors.Is(err, ErrNoCitableEvents) {
		t.Fatalf("err = %v, want ErrNoCitableEvents", err)
	}
	if fp.calls != 0 {
		t.Errorf("provider was called %d times; the guard must fire before the call", fp.calls)
	}
	if got := familyTotal(t, reg); got != 0 {
		t.Errorf("family total = %v, want 0 (no provider-reaching run)", got)
	}
	if res.Provider != "fake" || res.PromptVersion != "test.v1" {
		t.Error("precondition-failure record lost provider/prompt fields")
	}
}

// TestRedactionPreservesEventIDs pins the load-bearing cross-boundary
// invariant the AC3 referential check rests on (round-1 review): the
// Story 3.1 redaction pipeline runs provider-side on the same package
// whose UN-redacted copy supplies the citable id set, so redaction must
// never rewrite or drop Event.ID or Trigger.EventID.
func TestRedactionPreservesEventIDs(t *testing.T) {
	pkg := testPackage()
	pkg.Events[0].Raw = json.RawMessage(`{"password":"hunter2","jwt":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.x"}`)
	pkg.Events[1].Summary = "read Secret api-key=sk-something-secret"

	redacted, _ := redact.Redact(pkg)

	if len(redacted.Events) != len(pkg.Events) {
		t.Fatalf("redaction changed the event count: %d -> %d", len(pkg.Events), len(redacted.Events))
	}
	for i := range pkg.Events {
		if redacted.Events[i].ID != pkg.Events[i].ID {
			t.Errorf("redaction rewrote Events[%d].ID: %q -> %q", i, pkg.Events[i].ID, redacted.Events[i].ID)
		}
	}
	if redacted.Trigger.EventID != pkg.Trigger.EventID {
		t.Errorf("redaction rewrote Trigger.EventID: %q -> %q", pkg.Trigger.EventID, redacted.Trigger.EventID)
	}
}

func TestNewL1Validation(t *testing.T) {
	reg := metrics.NewRegistry()
	if _, err := NewL1(nil, PromptSpec{}, reg, nil); err == nil {
		t.Error("nil provider: err = nil, want error")
	}
	if _, err := NewL1(&fakeProvider{name: "fake", model: "m"}, PromptSpec{}, nil, nil); err == nil {
		t.Error("nil registry: err = nil, want error")
	}
}
