package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/olokotoh/olaitan/internal/schema"
)

// TestRedact_KubeEnvNameValuePair is the ROUND-1 fix #1 regression: the K8s/CRI
// env shape {"name":"DB_PASSWORD","value":"topsecret"} carries the secret in the
// SIBLING value, not under a secret-matching key. Before the fix the value
// "topsecret" was forwarded to the LLM.
func TestRedact_KubeEnvNameValuePair(t *testing.T) {
	pkg := pkgWithRaw(t, map[string]any{
		"containers": []any{
			map[string]any{
				"env": []any{
					map[string]any{"name": "DB_PASSWORD", "value": "topsecret"},
					map[string]any{"name": "LOG_LEVEL", "value": "debug"},
					map[string]any{"key": "API_KEY", "val": "sk-leak"},
				},
			},
		},
	})
	out, events := Redact(pkg)
	raw := out.Events[0].Raw
	if bytes.Contains(raw, []byte("topsecret")) {
		t.Fatalf("secret env value 'topsecret' leaked: %s", raw)
	}
	if bytes.Contains(raw, []byte("sk-leak")) {
		t.Fatalf("secret env value 'sk-leak' leaked: %s", raw)
	}
	// The benign LOG_LEVEL=debug pair must be preserved (no over-redaction).
	if !bytes.Contains(raw, []byte("debug")) {
		t.Errorf("benign env value 'debug' was over-redacted: %s", raw)
	}
	// The name labels themselves are preserved (they are labels, not secrets).
	if !bytes.Contains(raw, []byte("DB_PASSWORD")) {
		t.Errorf("env name label DB_PASSWORD was dropped: %s", raw)
	}
	secretPatternCount := 0
	for _, e := range events {
		if e.Reason == ReasonSecretPattern {
			secretPatternCount++
		}
	}
	if secretPatternCount != 2 {
		t.Fatalf("expected 2 secret_pattern redactions (the two secret env values), got %d: %+v", secretPatternCount, events)
	}
}

// TestRedact_JWTInsideLargerRawString is the ROUND-1 fix #2 regression: a JWT
// embedded inside a larger Raw string value (e.g. an "authorization":"Bearer
// eyJ..." header) was leaked because the Raw walk used a whole-string match.
func TestRedact_JWTInsideLargerRawString(t *testing.T) {
	jwt := validJWT(t)
	pkg := pkgWithRaw(t, map[string]any{
		"authorization": "Bearer " + jwt,
	})
	out, events := Redact(pkg)
	raw := out.Events[0].Raw
	if bytes.Contains(raw, []byte(jwt)) {
		t.Fatalf("JWT embedded in a larger string leaked: %s", raw)
	}
	tree := rawOf(t, out)
	authz, _ := tree["authorization"].(string)
	if !strings.Contains(authz, redactedJWTToken) {
		t.Errorf("JWT token not substituted: %q", authz)
	}
	// The "Bearer " prefix is benign and preserved.
	if !strings.Contains(authz, "Bearer ") {
		t.Errorf("benign 'Bearer ' prefix over-redacted: %q", authz)
	}
	jwtCount := 0
	for _, e := range events {
		if e.Reason == ReasonJWTBody {
			jwtCount++
		}
	}
	if jwtCount != 1 {
		t.Fatalf("expected 1 jwt_body redaction, got %d: %+v", jwtCount, events)
	}
}

// TestRedact_TagsScanned is the ROUND-1 fix #3 regression: Event.Tags bypassed
// redaction entirely; a JWT in a tag was forwarded.
func TestRedact_TagsScanned(t *testing.T) {
	jwt := validJWT(t)
	pkg := schema.EvidencePackage{
		PackageID:  "pkg-1",
		WorkloadID: "w",
		Events: []schema.Event{{
			ID:   "e1",
			Tags: []string{"benign-tag", "auth=" + jwt, "another"},
		}},
	}
	out, events := Redact(pkg)
	for _, tag := range out.Events[0].Tags {
		if strings.Contains(tag, jwt) {
			t.Fatalf("JWT in tag leaked: %q", tag)
		}
	}
	if out.Events[0].Tags[0] != "benign-tag" || out.Events[0].Tags[2] != "another" {
		t.Errorf("benign tags altered: %+v", out.Events[0].Tags)
	}
	if !strings.Contains(out.Events[0].Tags[1], redactedJWTToken) {
		t.Errorf("JWT tag not redacted: %q", out.Events[0].Tags[1])
	}
	if len(events) != 1 || events[0].Reason != ReasonJWTBody || events[0].FieldPath != "events[0].tags[1]" {
		t.Fatalf("expected one jwt_body on events[0].tags[1], got %+v", events)
	}
}

// TestRedact_NoMutationTagsAndRaw is the ROUND-1 fix #6 regression: when an
// event has no redactions, the returned copy must NOT alias the caller's Tags /
// Raw backing arrays. Mutating the returned copy must not affect the input.
func TestRedact_NoMutationTagsAndRaw(t *testing.T) {
	pkg := schema.EvidencePackage{
		PackageID:  "pkg-1",
		WorkloadID: "w",
		Events: []schema.Event{{
			ID:   "e1",
			Tags: []string{"a", "b"},
			Raw:  mustRaw(t, map[string]any{"safe": "value"}),
		}},
	}
	beforeTags := append([]string(nil), pkg.Events[0].Tags...)
	beforeRaw := append(json.RawMessage(nil), pkg.Events[0].Raw...)

	out, _ := Redact(pkg)
	// Mutate the returned copy aggressively.
	out.Events[0].Tags[0] = "MUTATED"
	for i := range out.Events[0].Raw {
		out.Events[0].Raw[i] = 'X'
	}

	for i := range beforeTags {
		if pkg.Events[0].Tags[i] != beforeTags[i] {
			t.Fatalf("input Tags mutated via returned copy: %+v", pkg.Events[0].Tags)
		}
	}
	if !bytes.Equal(beforeRaw, pkg.Events[0].Raw) {
		t.Fatalf("input Raw mutated via returned copy:\n before %s\n after  %s", beforeRaw, pkg.Events[0].Raw)
	}
}

// TestSecretKeyBoundary is the ROUND-1 fix #5 regression: the secret-key match
// is boundary-anchored, so benign keys are no longer shredded while real secret
// keys still match.
func TestSecretKeyBoundary(t *testing.T) {
	matched := []string{
		"API_KEY", "api_key", "apiKey", "db_password", "access_token",
		"client_secret", "secret", "TOKEN", "credential", "credentials",
		"passwd", "secretKey", "AWS_SECRET_ACCESS_KEY",
	}
	for _, k := range matched {
		if !isSecretKey(k) {
			t.Errorf("isSecretKey(%q) = false, want true (under-redaction)", k)
		}
	}
	notMatched := []string{
		"monkey", "donkey", "keyboard", "tokenizer", "PUBLIC_KEY",
		"public_key", "publicKey", "publickey", "hostname", "namespace",
		"message", "duration", "keyName",
	}
	// Note: tokenizer must NOT match (it is one segment "tokenizer", not
	// "token"); a bare "key"/"keyboard"/"monkey"/"keyName" must not match.
	// passwordHint is DELIBERATELY treated as a secret key (it splits to
	// password+Hint and `password` matches): redacting a password hint is the
	// safer fail-closed direction, so it is intentionally NOT in this list
	// (documented as a deviation from the spec's illustrative over-redaction
	// list in the Dev Agent Record).
	for _, k := range notMatched {
		if isSecretKey(k) {
			t.Errorf("isSecretKey(%q) = true, want false (over-redaction)", k)
		}
	}
}

// TestRedact_PlainTextUnderDataNotShredded is the ROUND-1 fix #8 regression: a
// plain human-readable string under data/payload/bytes must NOT be reduced to a
// {sha256,len} placeholder.
func TestRedact_PlainTextUnderDataNotShredded(t *testing.T) {
	plain := "hello world this is an ordinary log line"
	pkg := pkgWithRaw(t, map[string]any{"data": plain})
	out, events := Redact(pkg)
	tree := rawOf(t, out)
	if tree["data"] != plain {
		t.Fatalf("plain text under data was shredded: %v", tree["data"])
	}
	for _, e := range events {
		if e.Reason == ReasonRawPayload {
			t.Errorf("plain text wrongly reduced to raw_payload: %+v", e)
		}
	}
}

// TestRedact_BinaryBlobUnderDataReduced confirms a genuine byte blob under
// data is still hashed-and-dropped (fix #8 keeps real blobs reduced).
func TestRedact_BinaryBlobUnderDataReduced(t *testing.T) {
	blob := base64.StdEncoding.EncodeToString([]byte{0x00, 0x01, 0xff, 0xfe, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11})
	pkg := pkgWithRaw(t, map[string]any{"data": blob})
	out, _ := Redact(pkg)
	tree := rawOf(t, out)
	ph, ok := tree["data"].(map[string]any)
	if !ok || ph["redacted"] != ReasonRawPayload {
		t.Fatalf("binary blob under data was not reduced: %v", tree["data"])
	}
}

// TestRedact_FileRefNonStringPath is the ROUND-1 fix #4a regression: a file-ref
// with a non-string path no longer makes the reducer bail and leak contents.
func TestRedact_FileRefNonStringPath(t *testing.T) {
	pkg := pkgWithRaw(t, map[string]any{
		"file": map[string]any{
			"path":     123, // non-string path
			"contents": "leaked-file-secret",
		},
	})
	out, events := Redact(pkg)
	if bytes.Contains(out.Events[0].Raw, []byte("leaked-file-secret")) {
		t.Fatalf("file contents leaked with non-string path: %s", out.Events[0].Raw)
	}
	found := false
	for _, e := range events {
		if e.Reason == ReasonFileContents {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a file_contents redaction, got %+v", events)
	}
}

// TestRedact_FileRefContentAliases is the ROUND-1 fix #4b regression: realistic
// content-key aliases (body/text/blob) also trigger the reduction.
func TestRedact_FileRefContentAliases(t *testing.T) {
	for _, ck := range []string{"body", "text", "blob"} {
		pkg := pkgWithRaw(t, map[string]any{
			"file": map[string]any{"path": "/etc/x", ck: "leaked-via-" + ck},
		})
		out, _ := Redact(pkg)
		if bytes.Contains(out.Events[0].Raw, []byte("leaked-via-"+ck)) {
			t.Fatalf("file contents under %q leaked: %s", ck, out.Events[0].Raw)
		}
	}
}

// TestRedact_FileRefNonStringContent is the ROUND-1 fix #4c regression: a
// non-string content value is hashed (not emitted as size:0 + empty hash) and
// not leaked.
func TestRedact_FileRefNonStringContent(t *testing.T) {
	pkg := pkgWithRaw(t, map[string]any{
		"file": map[string]any{
			"path":     "/etc/x",
			"contents": map[string]any{"nested": "leaked-nested-secret"},
		},
	})
	out, _ := Redact(pkg)
	if bytes.Contains(out.Events[0].Raw, []byte("leaked-nested-secret")) {
		t.Fatalf("nested file contents leaked: %s", out.Events[0].Raw)
	}
	tree := rawOf(t, out)
	ref, ok := tree["file"].(map[string]any)
	if !ok {
		t.Fatalf("file not reduced: %v", tree["file"])
	}
	if int(ref["size"].(float64)) == 0 {
		t.Errorf("non-string content emitted size:0 (fix #4c violated)")
	}
}

// TestRedact_FileRefPreservesScalarSiblings is the ROUND-1 fix #4d regression:
// non-content sibling scalar keys (mode, owner) are preserved.
func TestRedact_FileRefPreservesScalarSiblings(t *testing.T) {
	pkg := pkgWithRaw(t, map[string]any{
		"file": map[string]any{
			"path":     "/etc/x",
			"contents": "secret-bytes",
			"mode":     "0644",
			"owner":    "root",
		},
	})
	out, _ := Redact(pkg)
	tree := rawOf(t, out)
	ref := tree["file"].(map[string]any)
	if ref["mode"] != "0644" {
		t.Errorf("mode sibling dropped: %v", ref["mode"])
	}
	if ref["owner"] != "root" {
		t.Errorf("owner sibling dropped: %v", ref["owner"])
	}
	if _, has := ref["contents"]; has {
		t.Error("contents survived reduction")
	}
}

// TestIsJWT_BodyMustBeJSONObject is the ROUND-1 fix #7 regression: a token whose
// body does not decode to a JSON object is no longer misclassified as a JWT.
func TestIsJWT_BodyMustBeJSONObject(t *testing.T) {
	// Valid header object, but body "AAAA" does not decode to a JSON object.
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	falsePositive := hdr + ".AAAA.BBBB"
	if isJWT(falsePositive) {
		t.Errorf("isJWT(%q) = true; body is not a JSON object (false positive)", falsePositive)
	}
	// eyJhIjoxfQ is {"a":1}; following segments are not JSON objects.
	if isJWT("eyJhIjoxfQ.AAAA.BBBB") {
		t.Error("isJWT misclassified eyJhIjoxfQ.AAAA.BBBB as a JWT")
	}
	// A real JWT (header + body both JSON objects) still matches.
	if !isJWT(validJWT(t)) {
		t.Error("real JWT no longer detected")
	}
}

// TestRedact_MultipleJWTsInSummary is the ROUND-1 minor regression: multiple
// JWTs in one Summary emit ONE event each (per-occurrence audit).
func TestRedact_MultipleJWTsInSummary(t *testing.T) {
	jwt := validJWT(t)
	pkg := schema.EvidencePackage{
		PackageID:  "pkg-1",
		WorkloadID: "w",
		Events:     []schema.Event{{ID: "e1", Summary: "first " + jwt + " second " + jwt}},
	}
	_, events := Redact(pkg)
	if len(events) != 2 {
		t.Fatalf("expected 2 per-occurrence jwt_body events, got %d: %+v", len(events), events)
	}
}
