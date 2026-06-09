package redact

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/olokotoh/olaitan/internal/schema"
)

// TestRedact_DottedSlashedSecretKeys is the ROUND-2 fix #1 regression: a secret
// key carrying `.` or `/` separators (or annotation-style keys) segmented into a
// single non-matching token under the round-1 splitter and forwarded its value.
// `db.password`, `app.secret`, `auth.token`, `service.api.key` and the
// annotation `app.kubernetes.io/secret` must now redact; benign dotted/slashed
// keys must NOT.
func TestRedact_DottedSlashedSecretKeys(t *testing.T) {
	secretKeys := []string{
		"db.password", "app.secret", "auth.token", "service.api.key",
		"app.kubernetes.io/secret",
	}
	for _, k := range secretKeys {
		if !isSecretKey(k) {
			t.Errorf("isSecretKey(%q) = false, want true (under-redaction leak)", k)
		}
	}
	benignKeys := []string{
		"app.kubernetes.io/name", "region.code", "service.endpoint",
		"node.role", "monkey.business",
	}
	for _, k := range benignKeys {
		if isSecretKey(k) {
			t.Errorf("isSecretKey(%q) = true, want false (over-redaction)", k)
		}
	}

	// End-to-end through Redact(): the value under a dotted secret key is dropped.
	pkg := pkgWithRaw(t, map[string]any{
		"db.password":              "DOTLEAK",
		"app.kubernetes.io/secret": "ANNOTATIONLEAK",
		"app.kubernetes.io/name":   "benign-app",
		"region.code":              "eu-west-1",
	})
	out, _ := Redact(pkg)
	raw := out.Events[0].Raw
	if bytes.Contains(raw, []byte("DOTLEAK")) {
		t.Fatalf("dotted secret key value leaked: %s", raw)
	}
	if bytes.Contains(raw, []byte("ANNOTATIONLEAK")) {
		t.Fatalf("annotation-style secret key value leaked: %s", raw)
	}
	if !bytes.Contains(raw, []byte("benign-app")) {
		t.Errorf("benign annotation value over-redacted: %s", raw)
	}
	if !bytes.Contains(raw, []byte("eu-west-1")) {
		t.Errorf("benign dotted value over-redacted: %s", raw)
	}
}

// TestRedact_Base64SecretUnderDataReduced is the ROUND-2 fix #2 regression: the
// canonical K8s Secret shape carries a base64 of a PRINTABLE ASCII secret. The
// round-1 heuristic only reduced values whose decoded bytes were non-printable,
// so this leaked verbatim. It must now be reduced to a raw_payload placeholder.
func TestRedact_Base64SecretUnderDataReduced(t *testing.T) {
	decoded := "hunter2-the-db-password"
	b64 := base64.StdEncoding.EncodeToString([]byte(decoded))
	pkg := pkgWithRaw(t, map[string]any{"kind": "Secret", "data": b64})
	out, events := Redact(pkg)
	raw := out.Events[0].Raw
	if bytes.Contains(raw, []byte(b64)) {
		t.Fatalf("base64-encoded secret survived under data: %s", raw)
	}
	if bytes.Contains(raw, []byte(decoded)) {
		t.Fatalf("decoded secret string leaked under data: %s", raw)
	}
	tree := rawOf(t, out)
	ph, ok := tree["data"].(map[string]any)
	if !ok || ph["redacted"] != ReasonRawPayload {
		t.Fatalf("base64 secret under data not reduced: %v", tree["data"])
	}
	rawPayloadCount := 0
	for _, e := range events {
		if e.Reason == ReasonRawPayload {
			rawPayloadCount++
		}
	}
	if rawPayloadCount != 1 {
		t.Fatalf("expected 1 raw_payload redaction, got %d: %+v", rawPayloadCount, events)
	}
}

// TestRedact_Base64SecretUnderPayloadAndBytes covers the other raw-payload keys:
// an AWS-key-id-looking base64 under payload and a GitHub-token base64 under
// bytes are both reduced (ROUND-2 fix #2).
func TestRedact_Base64SecretUnderPayloadAndBytes(t *testing.T) {
	awsKey := "AKIAIOSFODNN7EXAMPLE-and-more-bytes"
	ghToken := "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
	pkg := pkgWithRaw(t, map[string]any{
		"payload": base64.StdEncoding.EncodeToString([]byte(awsKey)),
		"bytes":   base64.StdEncoding.EncodeToString([]byte(ghToken)),
	})
	out, _ := Redact(pkg)
	raw := out.Events[0].Raw
	if bytes.Contains(raw, []byte(awsKey)) || bytes.Contains(raw, []byte(ghToken)) {
		t.Fatalf("base64 secret under payload/bytes leaked: %s", raw)
	}
}

// TestRedact_PlainTextUnderDataStillSurvives is the ROUND-2 fix #2 BALANCE
// guard: a plain human-readable sentence under data is NOT valid base64/hex and
// must still survive (no over-redaction reintroduced by fix #2).
func TestRedact_PlainTextUnderDataStillSurvives(t *testing.T) {
	plain := "user logged in from 10.0.0.1"
	pkg := pkgWithRaw(t, map[string]any{"data": plain})
	out, events := Redact(pkg)
	tree := rawOf(t, out)
	if tree["data"] != plain {
		t.Fatalf("plain text under data was wrongly reduced: %v", tree["data"])
	}
	for _, e := range events {
		if e.Reason == ReasonRawPayload {
			t.Errorf("plain text wrongly reduced to raw_payload: %+v", e)
		}
	}
}

// TestRedact_TagKeyValueSecret is the ROUND-2 fix #3 regression: a key=value
// secret in a Tag (e.g. `password=hunter2plaintext`) received only a JWT scan
// under round-1 and forwarded verbatim. It must now redact the right-hand side.
func TestRedact_TagKeyValueSecret(t *testing.T) {
	pkg := schema.EvidencePackage{
		PackageID:  "pkg-1",
		WorkloadID: "w",
		Events: []schema.Event{{
			ID:   "e1",
			Tags: []string{"password=hunter2plaintext", "env=prod", "nokv", "token=abc123secret"},
		}},
	}
	out, events := Redact(pkg)
	tags := out.Events[0].Tags
	if tags[0] != "password="+redactedToken {
		t.Fatalf("password tag not redacted: %q", tags[0])
	}
	if tags[3] != "token="+redactedToken {
		t.Fatalf("token tag not redacted: %q", tags[3])
	}
	// Benign tags survive (no over-redaction).
	if tags[1] != "env=prod" {
		t.Errorf("benign env=prod tag altered: %q", tags[1])
	}
	if tags[2] != "nokv" {
		t.Errorf("benign no-`=` tag altered: %q", tags[2])
	}
	secretPatternCount := 0
	for _, e := range events {
		if e.Reason == ReasonSecretPattern {
			secretPatternCount++
		}
	}
	if secretPatternCount != 2 {
		t.Fatalf("expected 2 secret_pattern redactions (tags 0 and 3), got %d: %+v", secretPatternCount, events)
	}
	if events[0].FieldPath != "events[0].tags[0]" {
		t.Errorf("first redaction field_path = %q, want events[0].tags[0]", events[0].FieldPath)
	}
}

// TestRedact_SummaryKeyValueSecret confirms the same key=value scan applies to
// Event.Summary free text (ROUND-2 fix #3).
func TestRedact_SummaryKeyValueSecret(t *testing.T) {
	pkg := schema.EvidencePackage{
		PackageID:  "pkg-1",
		WorkloadID: "w",
		Events:     []schema.Event{{ID: "e1", Summary: "apikey=sk-leakingsecretvalue"}},
	}
	out, events := Redact(pkg)
	if out.Events[0].Summary != "apikey="+redactedToken {
		t.Fatalf("summary key=value secret not redacted: %q", out.Events[0].Summary)
	}
	if len(events) != 1 || events[0].Reason != ReasonSecretPattern || events[0].FieldPath != "events[0].summary" {
		t.Fatalf("expected one secret_pattern on summary, got %+v", events)
	}
}

// TestLooksLikeEncodedPayload_Branches exercises the round-2 fix #2 heuristic
// branches the reviewer flagged as low-covered: short strings, non-printable
// blobs, std base64, raw-url base64, hex, and plain text.
func TestLooksLikeEncodedPayload_Branches(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"too_short", "AAAA", false},
		{"plain_sentence", "user logged in from 10.0.0.1", false},
		{"nonprintable_raw", "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11", true},
		{"std_base64_of_printable", base64.StdEncoding.EncodeToString([]byte("hunter2-the-db-password")), true},
		{"raw_url_base64", base64.RawURLEncoding.EncodeToString([]byte("hunter2-the-db-password-x")), true},
		{"hex_blob", "0123456789abcdef0123456789abcdef0123456789", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := looksLikeEncodedPayload(c.in); got != c.want {
				t.Errorf("looksLikeEncodedPayload(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

// TestDecodePayloadBytes_Branches exercises the decode fallbacks: std base64,
// raw-url base64, hex-not-base64 (raw-string fallback), and plain non-encoded
// (raw-string fallback). The decoded byte length drives the placeholder `len`.
func TestDecodePayloadBytes_Branches(t *testing.T) {
	std := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123"))
	if got := decodePayloadBytes(std); len(got) != 20 {
		t.Errorf("std base64 decoded len = %d, want 20", len(got))
	}
	// A raw-url base64 value that is NOT valid std base64 (contains '-'/'_').
	rawURL := base64.RawURLEncoding.EncodeToString([]byte{0xfb, 0xff, 0xbf, 0x00, 0x01, 0x02})
	if got := decodePayloadBytes(rawURL); len(got) != 6 {
		t.Errorf("raw-url base64 decoded len = %d, want 6", len(got))
	}
	// A non-encodable plain string falls back to its raw bytes.
	plain := "not base64 at all !!!"
	if got := decodePayloadBytes(plain); string(got) != plain {
		t.Errorf("plain fallback = %q, want %q", got, plain)
	}
}

// TestRedact_GluedKeysNotMatched documents the NOTED round-2 decision: glued
// keys (xapikey, apikeyv2) are deliberately NOT matched (substring matching
// would reintroduce the round-2 over-redaction class). This pins the decision.
func TestRedact_GluedKeysNotMatched(t *testing.T) {
	for _, k := range []string{"xapikey", "apikeyv2"} {
		if isSecretKey(k) {
			t.Errorf("isSecretKey(%q) = true; glued keys are intentionally NOT matched", k)
		}
	}
}
