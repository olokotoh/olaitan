package analyst

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"

	"github.com/olokotoh/olaitan/internal/agent/provider"
	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/schema"
)

const validSeniorVerdict = `{"threat_type":"crypto_miner","reasoning":"hash evidence outweighs the L2 refutation","mitre_techniques":["T1496"],"noted_disagreements":["L2 refuted L1 on evt-1"],"confidence":85}`

func testL2Verification() schema.L2Verification {
	return schema.L2Verification{
		SchemaVersion:    schema.L2VerificationSchemaVersion,
		Verdict:          schema.VerdictConfirmed,
		VerifiedEvidence: []schema.EvidenceVerification{{EventID: "evt-1", Finding: "confirmed"}},
		Confidence:       75,
	}
}

func newSeniorRunner(t *testing.T, fp *fakeProvider) (*Senior, *metrics.Registry) {
	t.Helper()
	reg := metrics.NewRegistry()
	sr, err := NewSenior(fp, PromptSpec{System: "you are the senior analyst", Version: "test.v3"}, reg, nil)
	if err != nil {
		t.Fatalf("NewSenior: %v", err)
	}
	return sr, reg
}

func TestSeniorRunSuccess(t *testing.T) {
	fp := &fakeProvider{name: "fake", model: "fake-model", resp: provider.Response{Raw: validSeniorVerdict, Model: "fake-model-served"}}
	sr, reg := newSeniorRunner(t, fp)
	pkg := testPackage()
	hyp := testL1Hypothesis()
	ver := testL2Verification()

	res, err := sr.Run(context.Background(), pkg, &hyp, &ver)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if fp.got.Role != provider.RoleSenior {
		t.Errorf("request role = %q, want %q", fp.got.Role, provider.RoleSenior)
	}
	if !bytes.Equal([]byte(fp.got.Schema), seniorSchemaJSON) {
		t.Error("request schema is not the embedded senior schema")
	}
	if fp.got.Prompt.System != "you are the senior analyst" || fp.got.Prompt.User != seniorUserInstruction {
		t.Error("prompt pair not passed verbatim")
	}
	if fp.got.PriorHypothesis == nil || fp.got.PriorVerification == nil {
		t.Error("prior hypothesis/verification not propagated on the Request")
	}
	if fp.got.PriorAssessment != nil {
		t.Error("Senior must not carry a prior assessment in 3.7")
	}
	if strings.Contains(fp.got.Prompt.User, hyp.Hypothesis) || strings.Contains(fp.got.Prompt.User, ver.VerifiedEvidence[0].Finding) {
		t.Error("prior content leaked into prompt text")
	}
	if res.Verdict.ThreatType != "crypto_miner" || res.Verdict.Confidence != 85 {
		t.Errorf("verdict round-trip mismatch: %+v", res.Verdict)
	}
	if res.Verdict.SchemaVersion != schema.ThreatAssessmentSchemaVersion {
		t.Errorf("schema_version = %q, want the runner stamp", res.Verdict.SchemaVersion)
	}
	if res.Model != "fake-model-served" || res.Provider != "fake" || res.PromptVersion != "test.v3" {
		t.Errorf("audit record incomplete: %+v", res)
	}
	if res.System != "you are the senior analyst" || res.User != seniorUserInstruction {
		t.Error("audit record does not carry the prompt-pair inputs")
	}
	if got := counterValue(t, reg, "fake", "senior", StatusSuccess); got != 1 {
		t.Errorf("success series = %v, want 1", got)
	}
	if got := familyTotal(t, reg); got != 1 {
		t.Errorf("family total = %v, want 1", got)
	}
}

// TestSeniorRunDegradedModes pins AC4's nil-pointer legality: evidence
// only (both nil) and hypothesis-only (ver nil) are legal modes.
func TestSeniorRunDegradedModes(t *testing.T) {
	hyp := testL1Hypothesis()
	cases := []struct {
		name string
		hyp  *schema.L1Hypothesis
		ver  *schema.L2Verification
	}{
		{"evidence only", nil, nil},
		{"hypothesis only", &hyp, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fp := &fakeProvider{name: "fake", model: "fake-model", resp: provider.Response{Raw: validSeniorVerdict}}
			sr, _ := newSeniorRunner(t, fp)
			if _, err := sr.Run(context.Background(), testPackage(), tc.hyp, tc.ver); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if tc.hyp == nil && fp.got.PriorHypothesis != nil {
				t.Error("nil hypothesis rendered a Request field")
			}
			if tc.ver == nil && fp.got.PriorVerification != nil {
				t.Error("nil verification rendered a Request field")
			}
		})
	}
}

func TestSeniorRunSchemaViolations(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"empty body", ""},
		{"whitespace body", "  \n "},
		{"empty fence body", "```json\n```"},
		{"not json", "looks dangerous"},
		{"missing threat_type", `{"reasoning":"x","confidence":50}`},
		{"missing reasoning", `{"threat_type":"miner","confidence":50}`},
		{"whitespace threat_type", `{"threat_type":"  ","reasoning":"x","confidence":50}`},
		{"whitespace reasoning", `{"threat_type":"miner","reasoning":"   ","confidence":50}`},
		{"bad mitre id", `{"threat_type":"miner","reasoning":"x","mitre_techniques":["TA0002"],"confidence":50}`},
		{"lowercase mitre id", `{"threat_type":"miner","reasoning":"x","mitre_techniques":["t1496"],"confidence":50}`},
		{"too many mitre ids", `{"threat_type":"miner","reasoning":"x","mitre_techniques":[` + manyMitre(21) + `],"confidence":50}`},
		{"whitespace disagreement", `{"threat_type":"miner","reasoning":"x","noted_disagreements":["  "],"confidence":50}`},
		{"oversized reasoning", `{"threat_type":"miner","reasoning":"` + strings.Repeat("r", 2001) + `","confidence":50}`},
		{"oversized threat_type", `{"threat_type":"` + strings.Repeat("t", 129) + `","reasoning":"x","confidence":50}`},
		{"confidence above range", `{"threat_type":"miner","reasoning":"x","confidence":101}`},
		{"confidence below range", `{"threat_type":"miner","reasoning":"x","confidence":-1}`},
		{"non-integer confidence", `{"threat_type":"miner","reasoning":"x","confidence":55.5}`},
		{"extra field", `{"threat_type":"miner","reasoning":"x","recommended_state":"QUARANTINED","confidence":50}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fp := &fakeProvider{name: "fake", model: "fake-model", resp: provider.Response{Raw: tc.raw}}
			sr, reg := newSeniorRunner(t, fp)
			res, err := sr.Run(context.Background(), testPackage(), nil, nil)
			if !errors.Is(err, ErrSchemaViolation) {
				t.Fatalf("err = %v, want ErrSchemaViolation", err)
			}
			if res.Status != StatusSchemaViolation || res.RawOutput != tc.raw {
				t.Errorf("audit record incomplete: %+v", res)
			}
			if got := familyTotal(t, reg); got != 1 {
				t.Errorf("family total = %v, want exactly 1", got)
			}
		})
	}
}

func manyMitre(n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = `"T1` + string(rune('0'+i/100%10)) + string(rune('0'+i/10%10)) + string(rune('0'+i%10)) + `"`
	}
	return strings.Join(parts, ",")
}

func TestSeniorRunAcceptanceVariants(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"fence wrapped", "```json\n" + validSeniorVerdict + "\n```"},
		{"cr-only fence", "```json\r" + validSeniorVerdict + "\r```"},
		{"integer-valued float confidence", `{"threat_type":"miner","reasoning":"x","confidence":85.0}`},
		{"exponent confidence", `{"threat_type":"miner","reasoning":"x","confidence":1e2}`},
		{"null schema_version", `{"schema_version":null,"threat_type":"miner","reasoning":"x","confidence":5}`},
		{"model schema_version overwritten", `{"schema_version":"bogus.v9","threat_type":"miner","reasoning":"x","confidence":5}`},
		{"sub-technique mitre id", `{"threat_type":"miner","reasoning":"x","mitre_techniques":["T1059.004"],"confidence":50}`},
		{"confidence bound 0", `{"threat_type":"benign","reasoning":"x","confidence":0}`},
		{"confidence bound 100", `{"threat_type":"miner","reasoning":"x","confidence":100}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fp := &fakeProvider{name: "fake", model: "fake-model", resp: provider.Response{Raw: tc.raw}}
			sr, _ := newSeniorRunner(t, fp)
			res, err := sr.Run(context.Background(), testPackage(), nil, nil)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if res.Verdict.SchemaVersion != schema.ThreatAssessmentSchemaVersion {
				t.Errorf("schema_version = %q, want the runner stamp", res.Verdict.SchemaVersion)
			}
		})
	}
}

func TestSeniorRunProviderErrorAndTruncation(t *testing.T) {
	fp := &fakeProvider{name: "fake", model: "fake-model", err: errors.New("upstream 529")}
	sr, reg := newSeniorRunner(t, fp)
	res, err := sr.Run(context.Background(), testPackage(), nil, nil)
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("err = %v, want ErrProviderUnavailable", err)
	}
	if res.Status != StatusUnavailable || res.Model != "fake-model" {
		t.Errorf("failure record incomplete: %+v", res)
	}
	if got := familyTotal(t, reg); got != 1 {
		t.Errorf("family total = %v, want 1", got)
	}

	for _, stop := range []string{"max_tokens", "length", "MAX_TOKENS"} {
		fp2 := &fakeProvider{name: "fake", model: "fake-model", resp: provider.Response{Raw: `{"threat_ty`, StopReason: stop}}
		sr2, reg2 := newSeniorRunner(t, fp2)
		if _, err := sr2.Run(context.Background(), testPackage(), nil, nil); !errors.Is(err, ErrProviderUnavailable) {
			t.Fatalf("stop_reason %q: err = %v, want ErrProviderUnavailable", stop, err)
		}
		if got := familyTotal(t, reg2); got != 1 {
			t.Errorf("family total = %v, want 1", got)
		}
	}
}

func TestSeniorRunNoCitableEvents(t *testing.T) {
	fp := &fakeProvider{name: "fake", model: "fake-model", resp: provider.Response{Raw: validSeniorVerdict}}
	sr, reg := newSeniorRunner(t, fp)
	_, err := sr.Run(context.Background(), schema.EvidencePackage{PackageID: "pkg-empty"}, nil, nil)
	if !errors.Is(err, ErrNoCitableEvents) {
		t.Fatalf("err = %v, want ErrNoCitableEvents", err)
	}
	if fp.calls != 0 {
		t.Errorf("provider called %d times", fp.calls)
	}
	if got := familyTotal(t, reg); got != 0 {
		t.Errorf("family total = %v, want 0", got)
	}
}

func TestSeniorRunSchemaNotAliased(t *testing.T) {
	fp := &fakeProvider{name: "fake", model: "fake-model", resp: provider.Response{Raw: validSeniorVerdict}}
	sr, _ := newSeniorRunner(t, fp)
	if _, err := sr.Run(context.Background(), testPackage(), nil, nil); err != nil {
		t.Fatalf("Run: %v", err)
	}
	original := seniorSchemaJSON[0]
	fp.got.Schema[0] = '!'
	if seniorSchemaJSON[0] != original {
		t.Error("mutating the request schema corrupted the embedded schema")
	}
}

func TestSeniorRecordLogLevels(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	reg := metrics.NewRegistry()
	fp := &fakeProvider{name: "fake", model: "fake-model", err: errors.New("boom")}
	sr, err := NewSenior(fp, PromptSpec{System: "s", Version: "v"}, reg, logger)
	if err != nil {
		t.Fatalf("NewSenior: %v", err)
	}
	_, _ = sr.Run(context.Background(), testPackage(), nil, nil)
	out := buf.String()
	if !strings.Contains(out, "level=WARN") || !strings.Contains(out, `msg="senior analyst call"`) {
		t.Errorf("failure log missing level or role message: %s", out)
	}
}

func TestNewSeniorValidation(t *testing.T) {
	reg := metrics.NewRegistry()
	if _, err := NewSenior(nil, PromptSpec{}, reg, nil); err == nil {
		t.Error("nil provider: err = nil, want error")
	}
	if _, err := NewSenior(&fakeProvider{name: "fake", model: "m"}, PromptSpec{}, nil, nil); err == nil {
		t.Error("nil registry: err = nil, want error")
	}
}

// Schema guard tests (BI-2, mirroring the L1/L2 pattern).

func TestEmbeddedSeniorSchemaMatchesDocs(t *testing.T) {
	docs, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "schemas", "threat_assessment.json"))
	if err != nil {
		t.Fatalf("read docs schema: %v", err)
	}
	if !bytes.Equal(docs, seniorSchemaJSON) {
		t.Error("embedded senior schema differs from docs/schemas/threat_assessment.json")
	}
}

func TestSeniorSchemaJSONYAMLAgreement(t *testing.T) {
	jb, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "schemas", "threat_assessment.json"))
	if err != nil {
		t.Fatalf("read json schema: %v", err)
	}
	var jdoc struct {
		Properties map[string]any `json:"properties"`
		Required   []string       `json:"required"`
	}
	if err := json.Unmarshal(jb, &jdoc); err != nil {
		t.Fatalf("unmarshal json schema: %v", err)
	}
	yb, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "schemas", "threat_assessment.yaml"))
	if err != nil {
		t.Fatalf("read yaml mirror: %v", err)
	}
	var ydoc struct {
		Fields map[string]struct {
			Required bool `yaml:"required"`
		} `yaml:"fields"`
	}
	if err := yaml.Unmarshal(yb, &ydoc); err != nil {
		t.Fatalf("unmarshal yaml mirror: %v", err)
	}
	jrequired := map[string]bool{}
	for _, k := range jdoc.Required {
		jrequired[k] = true
	}
	for k := range jdoc.Properties {
		f, ok := ydoc.Fields[k]
		if !ok {
			t.Errorf("json property %q missing from yaml mirror", k)
			continue
		}
		if f.Required != jrequired[k] {
			t.Errorf("required-ness disagrees for %q", k)
		}
	}
	for k := range ydoc.Fields {
		if _, ok := jdoc.Properties[k]; !ok {
			t.Errorf("yaml field %q missing from json schema", k)
		}
	}
}

var invalidSeniorExemplarKeyword = map[string]string{
	"threat_assessment_invalid_missing_threat_type.json": "missing property",
	"threat_assessment_invalid_bad_mitre.json":           "does not match pattern",
	"threat_assessment_invalid_confidence_range.json":    "maximum",
	"threat_assessment_invalid_extra_field.json":         "additional properties",
}

func TestSeniorVerdictExemplars(t *testing.T) {
	sch, err := seniorSchema.compiled()
	if err != nil {
		t.Fatalf("compile embedded schema: %v", err)
	}
	paths, err := filepath.Glob(filepath.Join("testdata", "threat_assessment_*.json"))
	if err != nil {
		t.Fatalf("glob testdata: %v", err)
	}
	var valid, invalid int
	for _, p := range paths {
		p := p
		base := filepath.Base(p)
		t.Run(base, func(t *testing.T) {
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatalf("read exemplar: %v", err)
			}
			inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
			if err != nil {
				t.Fatalf("exemplar is not JSON: %v", err)
			}
			verr := sch.Validate(inst)
			switch {
			case strings.HasPrefix(base, "threat_assessment_invalid_"):
				invalid++
				if verr == nil {
					t.Fatalf("invalid exemplar %s passed", p)
				}
				keyword, known := invalidSeniorExemplarKeyword[base]
				if !known {
					t.Fatalf("invalid exemplar %s has no expected-keyword entry", base)
				}
				if !strings.Contains(verr.Error(), keyword) {
					t.Errorf("exemplar %s failed for the wrong reason: want %q, got: %v", base, keyword, verr)
				}
			case strings.HasPrefix(base, "threat_assessment_valid_"):
				valid++
				if verr != nil {
					t.Errorf("valid exemplar %s failed: %v", p, verr)
				}
			default:
				t.Fatalf("exemplar %s matches neither prefix; rename it", base)
			}
		})
	}
	if valid < 2 || invalid < 4 {
		t.Errorf("exemplar coverage too thin: %d valid, %d invalid", valid, invalid)
	}
}
