package ollama

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/olokotoh/olaitan/internal/agent/provider"
)

// Story 10.6: the full profile runs a 3B model on CPU. The role's JSON
// Schema already rides in the user turn, but a small model given only a
// prose instruction drifts: an extra key, a string where an integer is
// required, prose around the object. Ollama (>= 0.5) accepts the schema
// itself as the native `format` field and constrains decoding to it, so
// the provider sends it there too. The runners still validate every reply;
// the grammar is what makes a valid reply the likely one.

// TestAnalyseSendsRoleSchemaAsNativeFormat pins the wire contract: the
// request carries the exact schema bytes of the role as `format`, as a JSON
// object (not a string, which Ollama would read as the legacy "json" mode
// name), and the schema is still in the user turn for providers and models
// that ignore `format`.
func TestAnalyseSendsRoleSchemaAsNativeFormat(t *testing.T) {
	h := &capturingHandler{script: []scriptedResponse{{200, successBody}}}
	ts := httptest.NewServer(h)
	defer ts.Close()

	p, _ := newTestProvider(t, ts.URL, nil)
	req := analyseRequest(provider.RoleSenior)
	req.Schema = provider.JSONSchema(`{"type":"object","required":["threat_type"],"properties":{"threat_type":{"type":"string"}}}`)
	if _, err := p.Analyse(context.Background(), req); err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	wire := wireRequest(t, h.lastBody())
	format, present := wire["format"]
	if !present {
		t.Fatal("format absent from the wire; the role schema must be sent as the native structured-output format")
	}
	obj, ok := format.(map[string]any)
	if !ok {
		t.Fatalf("format = %T %v, want the schema as a JSON object", format, format)
	}
	got, _ := json.Marshal(obj)
	var want map[string]any
	if err := json.Unmarshal(req.Schema, &want); err != nil {
		t.Fatalf("test schema: %v", err)
	}
	wantBytes, _ := json.Marshal(want)
	if string(got) != string(wantBytes) {
		t.Errorf("format = %s, want the role schema %s", got, wantBytes)
	}
	if content := wireUserContent(t, h.lastBody()); !strings.Contains(content, string(req.Schema)) {
		t.Error("the schema must stay in the user turn as well; format is additive")
	}
}

// TestAnalyseWithoutSchemaSendsNoFormat: a request with no schema (none of
// the chain roles today, but the Request type allows it) must not send an
// empty or null `format`, which Ollama rejects or reads as "no constraint"
// depending on version.
func TestAnalyseWithoutSchemaSendsNoFormat(t *testing.T) {
	h := &capturingHandler{script: []scriptedResponse{{200, successBody}}}
	ts := httptest.NewServer(h)
	defer ts.Close()

	p, _ := newTestProvider(t, ts.URL, nil)
	req := analyseRequest(provider.RoleL1)
	req.Schema = nil
	if _, err := p.Analyse(context.Background(), req); err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if _, present := wireRequest(t, h.lastBody())["format"]; present {
		t.Error("format present on the wire for a request with no schema")
	}
}

// TestAnalyseRejectsSchemaThatIsNotJSON: a schema that does not parse can
// never be sent as `format` (json.RawMessage would fail the marshal). It is
// a programming error in the caller, so it is permanent and makes no call.
func TestAnalyseRejectsSchemaThatIsNotJSON(t *testing.T) {
	h := &capturingHandler{script: []scriptedResponse{{200, successBody}}}
	ts := httptest.NewServer(h)
	defer ts.Close()

	p, _ := newTestProvider(t, ts.URL, nil)
	req := analyseRequest(provider.RoleL2)
	req.Schema = provider.JSONSchema(`{not json`)
	if _, err := p.Analyse(context.Background(), req); err == nil {
		t.Fatal("Analyse with a non-JSON schema: err = nil, want a permanent error")
	}
	if got := h.attempts.Load(); got != 0 {
		t.Errorf("attempts = %d, want 0 (a malformed schema must not reach the wire)", got)
	}
}

// TestHealthSendsNoFormat: the health probe is a one-token ping; a schema
// would only slow it down.
func TestHealthSendsNoFormat(t *testing.T) {
	h := &capturingHandler{script: []scriptedResponse{{200, successBody}}}
	ts := httptest.NewServer(h)
	defer ts.Close()

	p, _ := newTestProvider(t, ts.URL, nil)
	if err := p.Health(context.Background()); err != nil {
		t.Fatalf("Health: %v", err)
	}
	if _, present := wireRequest(t, h.lastBody())["format"]; present {
		t.Error("format present on the health probe")
	}
}
