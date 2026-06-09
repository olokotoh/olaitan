package redact

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/olokotoh/olaitan/internal/schema"
)

// pkgWithRaw builds a single-event EvidencePackage whose Event.Raw is the JSON
// encoding of raw, for the rule-in-isolation tests.
func pkgWithRaw(t *testing.T, raw any) schema.EvidencePackage {
	t.Helper()
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal raw: %v", err)
	}
	return schema.EvidencePackage{
		PackageID:  "pkg-1",
		WorkloadID: "ns/Deployment/web",
		Events:     []schema.Event{{ID: "e1", Raw: json.RawMessage(b)}},
	}
}

// rawOf returns the decoded redacted Event.Raw of the first event as a tree.
func rawOf(t *testing.T, pkg schema.EvidencePackage) map[string]any {
	t.Helper()
	var tree map[string]any
	if err := json.Unmarshal(pkg.Events[0].Raw, &tree); err != nil {
		t.Fatalf("unmarshal redacted raw: %v", err)
	}
	return tree
}

// validJWT builds a structurally valid JWT (decodable JSON header).
func validJWT(t *testing.T) string {
	t.Helper()
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"system:serviceaccount:ns:sa","exp":9999999999}`))
	sig := base64.RawURLEncoding.EncodeToString([]byte("signature-bytes"))
	return hdr + "." + body + "." + sig
}

func TestRedact_SecretKeyValue(t *testing.T) {
	pkg := pkgWithRaw(t, map[string]any{"API_KEY": "sk-supersecret", "host": "10.0.0.1"})
	out, events := Redact(pkg)
	tree := rawOf(t, out)
	if tree["API_KEY"] != redactedToken {
		t.Errorf("API_KEY = %v, want %q", tree["API_KEY"], redactedToken)
	}
	if tree["host"] != "10.0.0.1" {
		t.Errorf("non-secret host was altered: %v", tree["host"])
	}
	if len(events) != 1 || events[0].Reason != ReasonSecretPattern {
		t.Fatalf("events = %+v, want one secret_pattern", events)
	}
	if events[0].FieldPath != "events[0].raw.API_KEY" {
		t.Errorf("field_path = %q", events[0].FieldPath)
	}
}

func TestRedact_NestedObjectSecretValueRedactedWhole(t *testing.T) {
	pkg := pkgWithRaw(t, map[string]any{
		"credentials": map[string]any{"user": "bob", "pass": "hunter2"},
	})
	out, events := Redact(pkg)
	tree := rawOf(t, out)
	// The whole subtree under a secret-matching key is replaced with the token.
	if tree["credentials"] != redactedToken {
		t.Errorf("credentials subtree = %v, want %q", tree["credentials"], redactedToken)
	}
	if len(events) != 1 || events[0].Reason != ReasonSecretPattern {
		t.Fatalf("events = %+v, want one secret_pattern", events)
	}
}

func TestRedact_JWTInValue(t *testing.T) {
	jwt := validJWT(t)
	pkg := pkgWithRaw(t, map[string]any{"authorization": jwt})
	// "authorization" does not match the secret regex, so this exercises the
	// value-based JWT detector, not the key-based path... actually it does NOT
	// contain a secret keyword, so the JWT rule applies.
	out, events := Redact(pkg)
	tree := rawOf(t, out)
	if tree["authorization"] != redactedJWTToken {
		t.Errorf("authorization = %v, want %q", tree["authorization"], redactedJWTToken)
	}
	if len(events) != 1 || events[0].Reason != ReasonJWTBody {
		t.Fatalf("events = %+v, want one jwt_body", events)
	}
}

func TestRedact_JWTInSummary(t *testing.T) {
	jwt := validJWT(t)
	pkg := schema.EvidencePackage{
		PackageID:  "pkg-1",
		WorkloadID: "w",
		Events:     []schema.Event{{ID: "e1", Summary: "token observed: " + jwt + " in request"}},
	}
	out, events := Redact(pkg)
	if strings.Contains(out.Events[0].Summary, jwt) {
		t.Errorf("JWT survived in Summary: %q", out.Events[0].Summary)
	}
	if !strings.Contains(out.Events[0].Summary, redactedJWTToken) {
		t.Errorf("Summary missing JWT token: %q", out.Events[0].Summary)
	}
	if len(events) != 1 || events[0].Reason != ReasonJWTBody || events[0].FieldPath != "events[0].summary" {
		t.Fatalf("events = %+v, want one jwt_body on summary", events)
	}
}

func TestRedact_RawPayloadHashed(t *testing.T) {
	payloadBytes := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	b64 := base64.StdEncoding.EncodeToString(payloadBytes)
	pkg := pkgWithRaw(t, map[string]any{"payload": b64})
	out, events := Redact(pkg)
	tree := rawOf(t, out)
	ph, ok := tree["payload"].(map[string]any)
	if !ok {
		t.Fatalf("payload not reduced to placeholder: %v", tree["payload"])
	}
	if ph["redacted"] != ReasonRawPayload {
		t.Errorf("placeholder redacted = %v", ph["redacted"])
	}
	if int(ph["len"].(float64)) != len(payloadBytes) {
		t.Errorf("len = %v, want %d", ph["len"], len(payloadBytes))
	}
	wantSum := sha256.Sum256(payloadBytes)
	if ph["sha256"] != hex.EncodeToString(wantSum[:]) {
		t.Errorf("sha256 = %v", ph["sha256"])
	}
	if len(events) != 1 || events[0].Reason != ReasonRawPayload {
		t.Fatalf("events = %+v, want one raw_payload", events)
	}
}

func TestRedact_FileRefReducedToPathSizeSha(t *testing.T) {
	contents := "the quick brown fox secret data"
	pkg := pkgWithRaw(t, map[string]any{
		"file": map[string]any{"path": "/etc/secret.conf", "contents": contents},
	})
	out, events := Redact(pkg)
	tree := rawOf(t, out)
	ref, ok := tree["file"].(map[string]any)
	if !ok {
		t.Fatalf("file not reduced: %v", tree["file"])
	}
	if ref["path"] != "/etc/secret.conf" {
		t.Errorf("path = %v", ref["path"])
	}
	if _, has := ref["contents"]; has {
		t.Error("file contents survived redaction (AC2 violated)")
	}
	if int(ref["size"].(float64)) != len(contents) {
		t.Errorf("size = %v, want %d", ref["size"], len(contents))
	}
	wantSum := sha256.Sum256([]byte(contents))
	if ref["sha256"] != hex.EncodeToString(wantSum[:]) {
		t.Errorf("sha256 = %v", ref["sha256"])
	}
	if len(events) != 1 || events[0].Reason != ReasonFileContents {
		t.Fatalf("events = %+v, want one file_contents", events)
	}
}

func TestRedact_DeterministicOrdering(t *testing.T) {
	pkg := pkgWithRaw(t, map[string]any{
		"zeta_token":  "a",
		"alpha_key":   "b",
		"middle_pass": "c", // "pass" does not match; "password" does. keep distinct
		"password":    "d",
	})
	_, e1 := Redact(pkg)
	_, e2 := Redact(pkg)
	if len(e1) != len(e2) {
		t.Fatalf("event counts differ: %d vs %d", len(e1), len(e2))
	}
	for i := range e1 {
		if e1[i].FieldPath != e2[i].FieldPath || e1[i].Reason != e2[i].Reason {
			t.Fatalf("ordering not deterministic at %d: %+v vs %+v", i, e1[i], e2[i])
		}
	}
	// Field paths must be in sorted-key order.
	for i := 1; i < len(e1); i++ {
		if e1[i-1].FieldPath > e1[i].FieldPath {
			t.Errorf("paths not sorted: %q then %q", e1[i-1].FieldPath, e1[i].FieldPath)
		}
	}
}

func TestRedact_NoMutationOfInput(t *testing.T) {
	pkg := pkgWithRaw(t, map[string]any{"api_key": "secret", "ok": "v"})
	before := append(json.RawMessage(nil), pkg.Events[0].Raw...)
	_, _ = Redact(pkg)
	if !bytes.Equal(before, pkg.Events[0].Raw) {
		t.Errorf("input Event.Raw was mutated:\n before %s\n after  %s", before, pkg.Events[0].Raw)
	}
}

func TestRedact_MalformedRawFailsClosed(t *testing.T) {
	malformed := []byte(`{"api_key": "leaked-secret", BROKEN`)
	pkg := schema.EvidencePackage{
		PackageID:  "pkg-1",
		WorkloadID: "w",
		Events:     []schema.Event{{ID: "e1", Raw: json.RawMessage(malformed)}},
	}
	out, events := Redact(pkg)
	if bytes.Contains(out.Events[0].Raw, []byte("leaked-secret")) {
		t.Fatalf("malformed Raw forwarded a secret: %s", out.Events[0].Raw)
	}
	var ph map[string]any
	if err := json.Unmarshal(out.Events[0].Raw, &ph); err != nil {
		t.Fatalf("placeholder not valid JSON: %v", err)
	}
	if ph["redacted"] != ReasonRawPayload {
		t.Errorf("placeholder = %v", ph)
	}
	wantSum := sha256.Sum256(malformed)
	if ph["sha256"] != hex.EncodeToString(wantSum[:]) {
		t.Errorf("sha256 mismatch")
	}
	if len(events) != 1 || events[0].Reason != ReasonRawPayload || events[0].FieldPath != "events[0].raw" {
		t.Fatalf("events = %+v, want one raw_payload on events[0].raw", events)
	}
}

func TestRedact_EmptyPackage(t *testing.T) {
	out, events := Redact(schema.EvidencePackage{PackageID: "pkg-empty"})
	if len(events) != 0 {
		t.Errorf("empty package produced events: %+v", events)
	}
	if out.PackageID != "pkg-empty" {
		t.Errorf("package id lost")
	}
}

func TestRedact_DeeplyNestedTree(t *testing.T) {
	// Build a >= 8-level nested tree with a secret leaf.
	leaf := map[string]any{"secret": "deep-secret"}
	cur := leaf
	for i := 0; i < 9; i++ {
		cur = map[string]any{"child": cur}
	}
	pkg := pkgWithRaw(t, cur)
	out, events := Redact(pkg)
	if bytes.Contains(out.Events[0].Raw, []byte("deep-secret")) {
		t.Fatalf("deep secret survived: %s", out.Events[0].Raw)
	}
	if len(events) != 1 || events[0].Reason != ReasonSecretPattern {
		t.Fatalf("events = %+v, want one secret_pattern", events)
	}
	if !strings.HasSuffix(events[0].FieldPath, ".secret") {
		t.Errorf("deep field_path = %q", events[0].FieldPath)
	}
}

func TestRedact_ArrayIndexing(t *testing.T) {
	pkg := pkgWithRaw(t, map[string]any{
		"containers": []any{
			map[string]any{"name": "app"},
			map[string]any{"env_token": "t"},
		},
	})
	_, events := Redact(pkg)
	if len(events) != 1 {
		t.Fatalf("events = %+v, want one", events)
	}
	if events[0].FieldPath != "events[0].raw.containers[1].env_token" {
		t.Errorf("indexed field_path = %q", events[0].FieldPath)
	}
}

func TestIsJWT(t *testing.T) {
	if !isJWT(validJWT(t)) {
		t.Error("valid JWT not detected")
	}
	for _, s := range []string{
		"a.b.c",     // segments do not decode to a JSON header
		"not-a-jwt", // no dots
		"one.two",   // two segments
		"",          // empty
		"a.b.c.d",   // four segments
		base64.RawURLEncoding.EncodeToString([]byte("notjson")) + ".x.y", // header not JSON
	} {
		if isJWT(s) {
			t.Errorf("isJWT(%q) = true, want false", s)
		}
	}
}
