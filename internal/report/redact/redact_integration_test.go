package redact

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/olokotoh/olaitan/internal/schema"
)

// validateAgainstSchema compiles the committed draft-2020-12 JSON-Schema at
// schemaPath and validates payload against it (the Story 2.8 harness). With
// additionalProperties:false + the required set, a renamed/removed/added field
// or an out-of-enum reason FAILS here, which is the AC4 drift trap.
func validateAgainstSchema(t *testing.T, schemaPath string, payload []byte) error {
	t.Helper()
	sb, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read schema %s: %v", schemaPath, err)
	}
	schemaDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(sb))
	if err != nil {
		t.Fatalf("unmarshal schema %s: %v", schemaPath, err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(schemaPath, schemaDoc); err != nil {
		t.Fatalf("add schema resource %s: %v", schemaPath, err)
	}
	sch, err := c.Compile(schemaPath)
	if err != nil {
		t.Fatalf("compile schema %s: %v", schemaPath, err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return sch.Validate(inst)
}

// TestRedactions_RealRedactValidatesAgainstSchema drives a REAL Redact() over a
// secret-bearing package through a capturing sink, then validates each captured
// AuditRedaction against the committed schema (NFR36: real boundary, no mock-only
// crossing).
func TestRedactions_RealRedactValidatesAgainstSchema(t *testing.T) {
	schemaPath := filepath.Join(schemaDir, "redactions.json")
	jwt := validJWT(t)
	b64 := base64.StdEncoding.EncodeToString([]byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e})
	pkg := schema.EvidencePackage{
		PackageID:  "pkg-int-1",
		WorkloadID: "ns/Deployment/web",
		Events: []schema.Event{{ID: "e1", Raw: mustRaw(t, map[string]any{
			"api_key":       "sk-secret",
			"authorization": jwt,
			"payload":       b64,
			"file":          map[string]any{"path": "/etc/x", "contents": "data"},
		})}},
	}

	cap := &captureSink{}
	sink, err := NewRedactionAuditSink(cap, nil, RedactionAuditSinkConfig{DrainEvery: 10 * time.Millisecond})
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sink.Run(ctx) }()

	_, events := RedactAndAudit(pkg, sink)
	if len(events) != 4 {
		t.Fatalf("expected 4 redactions (secret/jwt/raw/file), got %d: %+v", len(events), events)
	}

	deadline := time.After(2 * time.Second)
	for len(cap.events()) < 4 {
		select {
		case <-deadline:
			t.Fatalf("drain timed out, got %d", len(cap.events()))
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done

	seen := map[string]bool{}
	for _, e := range cap.events() {
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if verr := validateAgainstSchema(t, schemaPath, b); verr != nil {
			t.Errorf("captured AuditRedaction failed schema validation: %v\npayload=%s", verr, b)
		}
		seen[e.Reason] = true
	}
	for _, r := range []string{ReasonSecretPattern, ReasonJWTBody, ReasonRawPayload, ReasonFileContents} {
		if !seen[r] {
			t.Errorf("reason %q not observed across the redaction batch", r)
		}
	}
}

// TestRedactions_DriftFailsValidation proves the drift trap is NOT vacuous: a
// renamed field and an out-of-enum reason both FAIL validation.
func TestRedactions_DriftFailsValidation(t *testing.T) {
	schemaPath := filepath.Join(schemaDir, "redactions.json")
	// A renamed field ("field" instead of "field_path") -> additionalProperties
	// :false rejects it AND the required "field_path" is now missing.
	drifted := []byte(`{"schema_version":"audit.redactions.v1","package_id":"p","field":"events[0].raw.x","reason":"secret_pattern","redacted_at":"2026-06-09T12:00:00Z","published_at":"2026-06-09T12:00:01Z"}`)
	if err := validateAgainstSchema(t, schemaPath, drifted); err == nil {
		t.Fatal("expected schema validation to FAIL on a renamed field, but it passed (drift trap would be vacuous)")
	}
	// A value outside the closed reason enum must also fail.
	badEnum := []byte(`{"schema_version":"audit.redactions.v1","package_id":"p","field_path":"events[0].raw.x","reason":"frobnicate","redacted_at":"2026-06-09T12:00:00Z","published_at":"2026-06-09T12:00:01Z"}`)
	if err := validateAgainstSchema(t, schemaPath, badEnum); err == nil {
		t.Fatal("expected schema validation to FAIL on an out-of-enum reason, but it passed")
	}
}
