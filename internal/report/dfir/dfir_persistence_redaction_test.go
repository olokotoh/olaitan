package dfir

// This file is the Story 4.5 persistence-bound extension of the Story 3.1
// redaction property suite (AC2/AC3, BI-5/BI-6). It asserts over the RENDERED-
// AND-REDACTED report string (the in-memory "S3 fixture" the Story 4.6 writer
// would PUT; 4.5 performs no real S3 write, BI-9), across the four source classes
// (evidence / llm_response / posture / audit), reusing the gopter harness style
// (pinned seed, MinSuccessfulTests >= 500, whole-string substring scan,
// token-presence + benign-survival, non-vacuous). The redaction runs through the
// SAME redact.RedactText pattern engine (BI-1); there is no second code path.

import (
	"context"
	"encoding/base64"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"

	"github.com/olokotoh/olaitan/internal/agent/provider"
	"github.com/olokotoh/olaitan/internal/report/redact"
	"github.com/olokotoh/olaitan/internal/response/settling"
)

const redactedToken = "<REDACTED>"
const redactedJWTToken = "<REDACTED:JWT>"

// capturingRedactionPublisher captures persistence-bound AUDIT.redactions events
// for inspection (the dfir-local analogue of the redact captureSink).
type capturingRedactionPublisher struct {
	mu       sync.Mutex
	captured []redact.AuditRedaction
}

func (c *capturingRedactionPublisher) PublishAuditRedaction(_ context.Context, evt redact.AuditRedaction) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.captured = append(c.captured, evt)
	return nil
}

func (c *capturingRedactionPublisher) events() []redact.AuditRedaction {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]redact.AuditRedaction, len(c.captured))
	copy(out, c.captured)
	return out
}

// pinnedDFIRParams mirrors the Story 3.1 pinnedParams: a fixed RNG seed and
// MinSuccessfulTests >= 500 so the persistence-bound property is reproducible.
func pinnedDFIRParams() *gopter.TestParameters {
	p := gopter.DefaultTestParameters()
	p.Rng.Seed(3131)
	p.MinSuccessfulTests = 500
	return p
}

// sanitiseSeed strips characters that would break a JWT body JSON (the redact
// sanitise analogue; redact's helper is package-private).
func sanitiseSeed(s string) string {
	if s == "" {
		return "x"
	}
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return 'x'
	}, s)
}

// makeJWT builds a structurally valid JWT keyed off seed (the redact genJWT
// analogue): header + body decode to JSON objects, so redact.RedactText's JWT
// scan replaces it with <REDACTED:JWT>.
func makeJWT(seed string) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"` + sanitiseSeed(seed) + `","exp":9999999999}`))
	sig := base64.RawURLEncoding.EncodeToString([]byte("sig-" + sanitiseSeed(seed)))
	return hdr + "." + body + "." + sig
}

// seededReport plants secrets into the FOUR source classes of a ForensicReport
// and records the ground-truth secrets for the survivor scan.
type seededReport struct {
	report  ForensicReport
	event   settling.IncidentFinalised
	secrets []string
}

// genSeededReport produces a ForensicReport whose narrative (llm_response),
// posture findings (posture), evidence-derived lists (evidence), and
// audit-metadata fields (audit) each carry a planted secret, plus the
// ground-truth secret set so the property can substring-scan the redacted
// persisted bytes for any survivor (the genSecretBearingPackage precedent).
func genSeededReport() gopter.Gen {
	return gen.SliceOf(gen.AlphaString()).Map(func(seeds []string) seededReport {
		if len(seeds) == 0 {
			seeds = []string{"seed"}
		}
		if len(seeds) > 4 {
			seeds = seeds[:4]
		}
		s := sanitiseSeed(seeds[0]) + strconv.Itoa(len(seeds))

		// (1) llm_response: the model narrative embeds a secret-keyed key=value,
		// a JWT inside a Bearer string, and a bearer token.
		narrSecretKV := "supersecret-" + s
		narrJWT := makeJWT("narr" + s)
		narrPosture := "postureleak-" + s
		narrTech := "techleak-" + s
		narrContain := "containleak-" + s
		auditSecret := "auditleak-" + s

		// The narrative is multi-line (a realistic analyst write-up): each secret
		// shape sits on its own line so the line-oriented scans tag each one. The
		// key=value scan redacts the whole right-hand side of its line (the Story
		// 3.1 behaviour, unchanged), so the JWT is isolated on its own line to keep
		// its <REDACTED:JWT> tag distinct.
		narrative := strings.Join([]string{
			"The miner ran.",
			"password=" + narrSecretKV,
			"The egress header carried Authorization: Bearer " + narrJWT + " trailing.",
		}, "\n")

		report := ForensicReport{
			SchemaVersion:         SchemaVersionForensicReport,
			IncidentID:            "pkg-prop-" + s,
			FinalFSMState:         "QUARANTINED",
			ThreatScoreAtDecision: 42.5,
			// (3) evidence-derived lists.
			AttackTechniques:   []string{"T1611", "token=" + narrTech},
			ContainmentActions: []string{"applied QUARANTINED", "api_key=" + narrContain},
			// (2) posture (force-stamped; secret planted to prove the boundary).
			ContributingPostureFindings: []string{"cluster-role binding grants admin", "secret=" + narrPosture},
			ReportGeneratedAt:           time.Date(2026, 6, 14, 10, 0, 5, 0, time.UTC),
			// (4) audit-metadata field carrying a planted secret.
			PromptHash:   "credential=" + auditSecret,
			DFIRProvider: "claude",
			DFIRModel:    "claude-opus-4-8",
			Narrative:    narrative,
		}
		event := settling.IncidentFinalised{
			SchemaVersion: settling.SchemaVersionIncidentFinalised,
			PackageID:     report.IncidentID,
			WorkloadID:    "ns/Deployment/web",
			FinalState:    "QUARANTINED",
			ThreatScore:   42.5,
		}
		return seededReport{
			report:  report,
			event:   event,
			secrets: []string{narrSecretKV, narrJWT, narrPosture, narrTech, narrContain, auditSecret},
		}
	})
}

// TestProperty_NoSecretReachesPersistedReport is the persistence-bound NFR15 core
// (AC2/AC3): for every generated report seeding secrets into the four source
// classes, the RENDERED-AND-REDACTED report string (the 4.6 PUT bytes) contains
// NO injected secret and DOES carry the redaction tokens. The scan is over the
// WHOLE persisted string so a leak through ANY rendered region is caught.
func TestProperty_NoSecretReachesPersistedReport(t *testing.T) {
	props := gopter.NewProperties(pinnedDFIRParams())
	props.Property("no injected secret survives persistence-side redaction", prop.ForAll(
		func(sr seededReport) bool {
			a := persistenceAgent(t)
			redacted := a.redactReport(sr.report)
			persisted := redacted.Render(sr.event)
			for _, secret := range sr.secrets {
				if secret != "" && strings.Contains(persisted, secret) {
					return false
				}
			}
			// Non-vacuous: the redaction tokens must be present (something fired).
			if !strings.Contains(persisted, redactedToken) || !strings.Contains(persisted, redactedJWTToken) {
				return false
			}
			// Benign control-plane facts must SURVIVE (no over-redaction).
			if !strings.Contains(persisted, "QUARANTINED") || !strings.Contains(persisted, "T1611") {
				return false
			}
			return true
		},
		genSeededReport(),
	))
	props.TestingRun(t)
}

// persistenceAgent builds a DFIR agent with a real RedactionAuditSink wired to a
// discard publisher, used by the property test where audit capture is not
// asserted (only the redacted bytes are).
func persistenceAgent(t *testing.T) *Agent {
	t.Helper()
	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8"}
	a := newAgent(t, fp, &fakeReportPublisher{}, &fakeAuditRecorder{})
	return a
}

// TestRedactReport_AdversarialSyntheticNarrative is the AC3 adversarial test: a
// synthetic DFIR narrative embedding the four canonical secret shapes (an
// AWS-style secret-keyed value, a JWT inside a Bearer string, a private-key /
// secret-key token, and a bearer token) is redacted before persistence; the
// in-memory "S3 fixture" (the redacted rendered report; 4.5 does no real S3
// write, BI-9) carries NO unredacted secret and DOES carry the redaction tokens.
func TestRedactReport_AdversarialSyntheticNarrative(t *testing.T) {
	jwt := makeJWT("adversarial")
	awsSecret := "AKIAIOSFODNN7EXAMPLEKEYDATA"
	bearer := makeJWT("bearer")
	pemSecret := "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQ"

	narrative := strings.Join([]string{
		"The attacker exfiltrated credentials.",
		"aws_secret_access_key=" + awsSecret,
		"The session token was Authorization: Bearer " + jwt + " in the request.",
		"private_key=" + pemSecret,
		"token=" + bearer,
	}, "\n")

	report := ForensicReport{
		SchemaVersion: SchemaVersionForensicReport,
		IncidentID:    "pkg-adv-1",
		FinalFSMState: "QUARANTINED",
		PromptHash:    "dfir.test.v1",
		DFIRProvider:  "claude",
		DFIRModel:     "claude-opus-4-8",
		Narrative:     narrative,
	}
	event := settling.IncidentFinalised{PackageID: "pkg-adv-1", WorkloadID: "ns/Deployment/web", FinalState: "QUARANTINED"}

	cap := &capturingRedactionPublisher{}
	sink, err := redact.NewRedactionAuditSink(cap, nil, redact.RedactionAuditSinkConfig{DrainEvery: 10 * time.Millisecond})
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sink.Run(ctx) }()

	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8"}
	a := newAgent(t, fp, &fakeReportPublisher{}, &fakeAuditRecorder{})
	a.redactSink = sink

	redacted := a.redactReport(report)
	persisted := redacted.Render(event)

	// No unredacted secret reaches the in-memory S3 fixture.
	for _, secret := range []string{awsSecret, jwt, pemSecret, bearer} {
		if strings.Contains(persisted, secret) {
			t.Errorf("unredacted secret %q reached the persisted report:\n%s", secret, persisted)
		}
	}
	// The redaction tokens are present.
	if !strings.Contains(persisted, redactedToken) || !strings.Contains(persisted, redactedJWTToken) {
		t.Errorf("redaction tokens missing from the persisted report:\n%s", persisted)
	}

	// Drain and assert the AUDIT.redactions events carry source=llm_response and
	// the incident_id, and NO secret value (NFR18).
	deadline := time.After(2 * time.Second)
	for len(cap.events()) == 0 {
		select {
		case <-deadline:
			t.Fatal("AUDIT.redactions drain timed out")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done

	for _, e := range cap.events() {
		if e.Source != redact.SourceLLMResponse {
			t.Errorf("narrative redaction source = %q, want llm_response", e.Source)
		}
		if e.IncidentID != "pkg-adv-1" {
			t.Errorf("incident_id = %q, want pkg-adv-1", e.IncidentID)
		}
		for _, secret := range []string{awsSecret, jwt, pemSecret, bearer} {
			if strings.Contains(e.FieldPath, secret) {
				t.Errorf("secret leaked into AUDIT.redactions field_path: %s", e.FieldPath)
			}
		}
	}
}

// TestRedactReport_PerRegionSource asserts the per-region source discriminator is
// derived correctly (Open Assumption 4, BI-8): a narrative redaction is
// llm_response, a posture redaction is posture, an evidence-list redaction is
// evidence, and an audit-metadata redaction is audit.
func TestRedactReport_PerRegionSource(t *testing.T) {
	jwt := makeJWT("region")
	report := ForensicReport{
		IncidentID:                  "pkg-region-1",
		Narrative:                   "narrative Bearer " + jwt,
		ContributingPostureFindings: []string{"secret=postureval123456"},
		AttackTechniques:            []string{"token=techval1234567"},
		PromptHash:                  "credential=auditval123456",
		DFIRProvider:                "claude",
		DFIRModel:                   "claude-opus-4-8",
	}

	cap := &capturingRedactionPublisher{}
	sink, err := redact.NewRedactionAuditSink(cap, nil, redact.RedactionAuditSinkConfig{DrainEvery: 10 * time.Millisecond})
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sink.Run(ctx) }()

	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8"}
	a := newAgent(t, fp, &fakeReportPublisher{}, &fakeAuditRecorder{})
	a.redactSink = sink

	_ = a.redactReport(report)

	deadline := time.After(2 * time.Second)
	for len(cap.events()) < 4 {
		select {
		case <-deadline:
			t.Fatalf("drain timed out, got %d events", len(cap.events()))
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done

	bySource := map[string][]string{}
	for _, e := range cap.events() {
		bySource[e.Source] = append(bySource[e.Source], e.FieldPath)
		if e.IncidentID != "pkg-region-1" {
			t.Errorf("incident_id = %q, want pkg-region-1", e.IncidentID)
		}
	}
	for _, src := range []string{redact.SourceLLMResponse, redact.SourcePosture, redact.SourceEvidence, redact.SourceAudit} {
		if len(bySource[src]) == 0 {
			t.Errorf("no AUDIT.redactions event with source=%q (got %+v)", src, bySource)
		}
	}
}

// TestRedactReport_CleanReportUnchanged asserts a clean report is not
// over-redacted and its rendered bytes (and thus its SHA) are byte-identical to
// the pre-redaction render (Task 3.5: no over-redaction, SHA stable when no
// secret present).
func TestRedactReport_CleanReportUnchanged(t *testing.T) {
	report := ForensicReport{
		SchemaVersion:               SchemaVersionForensicReport,
		IncidentID:                  "pkg-clean-1",
		FinalFSMState:               "QUARANTINED",
		ThreatScoreAtDecision:       42.5,
		AttackTechniques:            []string{"T1611"},
		ContainmentActions:          []string{"applied QUARANTINED"},
		ContributingPostureFindings: []string{"cluster-role binding grants admin"},
		ReportGeneratedAt:           time.Date(2026, 6, 14, 10, 0, 5, 0, time.UTC),
		PromptHash:                  "dfir.test.v1",
		DFIRProvider:                "claude",
		DFIRModel:                   "claude-opus-4-8",
		Narrative:                   "The miner ran and was contained.",
	}
	event := settling.IncidentFinalised{PackageID: "pkg-clean-1", WorkloadID: "ns/Deployment/web", FinalState: "QUARANTINED"}

	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8"}
	a := newAgent(t, fp, &fakeReportPublisher{}, &fakeAuditRecorder{})

	before := report.Render(event)
	redacted := a.redactReport(report)
	after := redacted.Render(event)
	if before != after {
		t.Errorf("a clean report must render byte-identically after redaction\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if reportSHA256(before) != reportSHA256(after) {
		t.Error("the SHA-of-redacted-bytes must equal the render SHA when no secret was present")
	}
}

// TestGenerate_PersistenceRedactionBeforeSHA asserts the end-to-end Generate path
// redacts the narrative before the SHA/announce: the announced SHA and content
// key are over the REDACTED bytes (BI-4/OA1), and the secret never reaches the
// rendered report.
func TestGenerate_PersistenceRedactionBeforeSHA(t *testing.T) {
	jwt := makeJWT("gen")
	resp := `{"narrative": "egress carried Authorization: Bearer ` + jwt + ` and password=topsecretvalue123."}`
	fp := &fakeProvider{name: "claude", model: "claude-opus-4-8", resp: provider.Response{Raw: resp, StopReason: "end_turn", Model: "claude-opus-4-8"}}
	rp := &fakeReportPublisher{}
	a := newAgent(t, fp, rp, &fakeAuditRecorder{})

	rendered, reported, err := a.Generate(context.Background(), testIncident())
	if err != nil || !reported {
		t.Fatalf("Generate: reported=%v err=%v", reported, err)
	}
	if strings.Contains(rendered, jwt) || strings.Contains(rendered, "topsecretvalue123") {
		t.Errorf("a secret in the narrative reached the rendered report:\n%s", rendered)
	}
	if !strings.Contains(rendered, redactedJWTToken) {
		t.Error("the JWT redaction token is missing from the rendered report")
	}
	if len(rp.events) != 1 {
		t.Fatalf("want 1 REPORTS.generated, got %d", len(rp.events))
	}
	// SHA-OF-REDACTED-BYTES: the announced SHA is the SHA of the redacted render.
	if got := reportSHA256(rendered); rp.events[0].ReportSHA256 != got {
		t.Errorf("announced SHA %q != SHA of the redacted render %q", rp.events[0].ReportSHA256, got)
	}
}
