// Package redact is the Ring-5 redaction pipeline (Story 3.1, FR44/NFR15).
// It hosts the single reusable Redact() entry point that strips secrets, JWTs,
// and raw payloads out of an EvidencePackage before the data leaves the
// controller process: pre-LLM by the Ring-3 decision tier (Stories 3.5-3.7) and
// pre-persistence by Ring 5 (Epic 4 reuses the same Redact(), AC5).
//
// Ring discipline (BI-1, architecture.md:111 "internal/report (Ring 5)"):
// although redaction LIVES in Ring 5, it is CALLED inward by higher rings, so
// the call direction is always consumer -> redact, never the reverse. This
// package imports ONLY the substrate it operates over and the audit publish
// seam (internal/schema for EvidencePackage, internal/nats + internal/subjects
// for the audit publish); it MAY import internal/config and internal/metrics
// within the same allow-set. It MUST NOT import internal/decision/*,
// internal/agent/*, internal/collector/*, or the sibling internal/report/dfir
// |archive (those are CONSUMERS of redact).
//
// Redaction is DEEP, DETERMINISTIC, and returns a redacted COPY (BI-4): it
// never mutates the caller's EvidencePackage, so the un-redacted original stays
// in-process for forensic use while the redacted copy is what crosses the
// LLM/persistence boundary.
//
// REAL-CODE NOTE (BI-4.2/BI-4.5): the shipped EvidencePackage has NO
// first-class env-map / JWT / raw-payload-bytes / file-reference fields. The
// secret-bearing free-form material lives in Event.Raw (the per-source vendor
// blob) and the human-readable Event.Summary. The redactor is therefore a deep
// generic-JSON walker over each Event.Raw tree plus a scan of Event.Summary.
// If a later story adds typed env/file/payload fields to the schema, the
// redactor MUST gain a typed pass for them; the property tests (AC3) catch any
// new field that bypasses redaction by construction.
//
// The four redaction reasons map one-to-one to the AC1/AC2 rules and the closed
// schema enum (BI-4.3): ReasonSecretPattern (a key matched the secret regex),
// ReasonJWTBody (a value parsed as a JWT), ReasonRawPayload (raw network bytes
// hashed) and ReasonFileContents (a file reference reduced to path+size+sha256).
//
// ROUND-1 REVIEW AMENDMENTS (broadened redaction, recorded here so the
// behaviour is documented and not silent; see the spec Dev Agent Record):
//
//   - K8s/CRI name/value env shape (fix #1): an object carrying a string
//     `name`/`key` whose VALUE matches the secret-key pattern AND a sibling
//     `value`/`val` has that sibling value redacted (reason secret_pattern).
//     The K8s env-var shape {"name":"DB_PASSWORD","value":"topsecret"} no
//     longer forwards the value. The original key-based pass is kept.
//   - JWT anywhere in a string (fix #2/#3): the Summary search-and-replace JWT
//     scan is now the SINGLE shared scan applied to EVERY string value in the
//     Event.Raw walk, to Event.Summary, and to each Event.Tags entry, so a JWT
//     embedded inside a larger string (e.g. "Bearer eyJ...") is redacted, not
//     only whole-string JWT values.
//   - Event.Tags (fix #3): each tag is scanned (JWT scan) and redacted in
//     place on the returned copy (field_path events[i].tags[j]). The original
//     per-event loop processed only Summary and Raw.
//   - secretKeyRe is boundary-anchored (fix #5): segment/word-anchored rather
//     than an unanchored substring, and public_key/publickey is excluded, so
//     benign keys (monkey, keyboard, tokenizer, publicKey) are no longer
//     shredded while real secret keys still match.
//   - raw-payload reduction is heuristic-gated (fix #8): a string under
//     data/payload/bytes is reduced to {sha256,len} ONLY when it decodes as
//     base64/hex of meaningful length or carries a high non-printable ratio;
//     a plain human-readable string under `data` is left intact (and still
//     gets JWT/secret scanning as an ordinary string value).
//
// PACKAGE-ROOT SCOPE DECISION (fix #10): the EvidencePackage root string fields
// (WorkloadIdentity {namespace, owner kind/name}, RuleMatches[].RuleName,
// Trigger, BaselineDeviation metrics, WorkloadPosture) are analyst-derived /
// structured controller metadata, not free-form tenant/secret surfaces:
// posture is already redaction-aware by construction (Story 1.11: class-not-
// text unavailable reasons, union-capped verbs, omitted secret-bearing paths),
// identity is namespace/owner names, rule names are analyst-authored, baseline
// deviations are numeric. They cannot carry secret material today, so the walk
// deliberately covers only Event.Raw/Summary/Tags (the free-form vendor
// surfaces). The property suite nonetheless asserts over the WHOLE marshalled
// EvidencePackage, so any future leak through a root field is caught by
// construction (AC3/NFR15). A schema-widening story that adds a free-form root
// field MUST extend the walk to cover it.
package redact

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/olokotoh/olaitan/internal/schema"
)

// Reason* are the four closed redaction reasons (BI-4.3/BI-5.1). They are the
// authoritative source for the docs/schemas/audit/redactions.json reason enum;
// keeping them as constants means a call site and the schema cannot drift.
const (
	ReasonSecretPattern = "secret_pattern"
	ReasonJWTBody       = "jwt_body"
	ReasonRawPayload    = "raw_payload"
	ReasonFileContents  = "file_contents"
)

// redactedToken is the literal replacement for a secret-keyed value (AC1).
const redactedToken = "<REDACTED>"

// redactedJWTToken is the literal replacement for a JWT value (AC1).
const redactedJWTToken = "<REDACTED:JWT>"

// secretKeyRe matches an object KEY (or a key SEGMENT) whose value must be
// replaced with <REDACTED> (AC1, key-based). Compiled once as a package var.
//
// ROUND-1 REVIEW AMENDMENT (over-redaction fix): the original unanchored
// substring regex matched benign keys such as `monkey`, `donkey`, `keyboard`,
// `tokenizer`, `passwordHint` and `PUBLIC_KEY`. The match is now anchored to
// key word/segment boundaries: the key is split into segments on `_`, `-` and
// camelCase transitions, and a segment is compared against the secret word set.
// `apikey`/`api_key`/`apiKey` all reduce to an `apikey` or `api`+`key` segment
// sequence, matched by the apikey alternative. A public key is NOT a secret, so
// `public_key`/`publickey` is explicitly excluded.
//
// NOTE: a BARE `key` segment is deliberately NOT in the word set (matching the
// spec's recommended boundary regex), because the bare-`key` substring is what
// produced the original `monkey`/`keyboard`/`donkey` false positives. Secret
// keys that end in `key` are matched via the `apikey`/`access_key`-style
// alternatives below or via another secret segment (e.g. `secret` in
// `AWS_SECRET_ACCESS_KEY`).
var secretKeyRe = regexp.MustCompile(`^(secret|secrets|token|tokens|password|passwd|passwords|apikey|credential|credentials|accesskey|seckey|privkey|privatekey)$`)

// publicKeyKeyRe matches a key that denotes a PUBLIC key, which is not a secret
// and must NOT be redacted (ROUND-1 over-redaction fix). It is checked against
// the joined lowered key before the segment scan.
var publicKeyKeyRe = regexp.MustCompile(`^public[_-]?keys?$`)

// camelBoundaryRe inserts a split point at a lowerUPPER camelCase transition so
// `apiKey` splits into `api`/`Key` and `accessToken` into `access`/`Token`.
var camelBoundaryRe = regexp.MustCompile(`([a-z0-9])([A-Z])`)

// isSecretKey reports whether an object key denotes a secret value (AC1,
// key-based, ROUND-1 boundary-anchored). It splits the key into word segments
// (on `_`, `-` and camelCase) and matches any segment against the secret word
// set, after excluding the public-key case. This catches real secret keys
// (`API_KEY`, `db_password`, `access_token`, `client_secret`, `apiKey`) while
// leaving benign keys (`monkey`, `keyboard`, `tokenizer`, `passwordHint` ->
// `password`+`hint` still matches `password`; `publicKey` excluded) intact.
func isSecretKey(key string) bool {
	lower := strings.ToLower(key)
	if publicKeyKeyRe.MatchString(lower) {
		return false
	}
	// Split on camelCase first, then on the separators.
	spaced := camelBoundaryRe.ReplaceAllString(key, "$1 $2")
	segs := strings.FieldsFunc(spaced, func(r rune) bool {
		return r == '_' || r == '-' || r == ' '
	})
	for i, seg := range segs {
		s := strings.ToLower(seg)
		if secretKeyRe.MatchString(s) {
			return true
		}
		// Adjacent-segment join so `api`+`key`, `access`+`key`, `private`+`key`
		// (i.e. API_KEY / apiKey / access_key / private_key) match the joined
		// secret word even though no single segment does.
		if i+1 < len(segs) {
			if secretKeyRe.MatchString(s + strings.ToLower(segs[i+1])) {
				return true
			}
		}
	}
	return false
}

// nameValueNameKeys are the keys whose STRING VALUE names a field (e.g. the
// K8s/CRI env-var shape `{"name":"DB_PASSWORD","value":"topsecret"}`).
var nameValueNameKeys = []string{"name", "key"}

// nameValueValueKeys are the sibling keys carrying the value to redact when the
// name denotes a secret.
var nameValueValueKeys = []string{"value", "val"}

// rawPayloadKeys is the documented key set under which a raw network payload
// blob is recognised and hashed-and-dropped (AC1). These are the byte-blob
// fields carried by SourceNetwork / CategoryFlow events (and the CRI/CNI raw
// shapes), e.g. {"payload": "<base64 bytes>"}.
var rawPayloadKeys = map[string]struct{}{
	"payload": {},
	"data":    {},
	"bytes":   {},
}

// jwtSegmentRe matches a single base64url segment of a JWT (no padding).
var jwtSegmentRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// RedactionEvent is the in-process result of a single redaction (BI-5.1),
// returned in a deterministic-ordered slice from Redact(). It carries the
// dotted/indexed path to the redacted field and the closed reason; it NEVER
// carries the redacted secret value (NFR18). AuditRedaction (audit.go) is its
// versioned wire projection.
type RedactionEvent struct {
	// FieldPath is the stable dotted/indexed path from the EvidencePackage root
	// to the redacted field, e.g. events[3].raw.spec.containers[0].env.API_KEY
	// (BI-4.4).
	FieldPath string
	// Reason is one of the Reason* constants (BI-4.3).
	Reason string
	// WorkloadID is the package's WorkloadID, carried for SIEM correlation.
	WorkloadID string
	// RedactedAt is the redaction decision time (distinct from the audit
	// emission time, BI-5.2/BI-3.4).
	RedactedAt time.Time
}

// Redact returns a redacted COPY of pkg plus the deterministic-ordered list of
// redaction events (BI-4.1). It NEVER mutates the caller's pkg: the un-redacted
// original stays in-process for forensic use while the returned copy is what
// crosses the LLM/persistence boundary.
//
// It deep-walks each Event.Raw JSON tree (unmarshal to a generic tree, recurse,
// redact, re-marshal) and scans each Event.Summary, applying the four AC1/AC2
// rules. The walk is fail-CLOSED on the data (BI-6.1): a malformed/un-parseable
// Event.Raw is replaced wholesale by a {redacted, sha256, len} placeholder
// rather than forwarded, so "I could not parse it" degrades to "I redacted all
// of it", never to "I forwarded it".
func Redact(pkg schema.EvidencePackage) (schema.EvidencePackage, []RedactionEvent) {
	now := time.Now().UTC()
	out := pkg
	// Detach the Events slice so the redacted copy never shares backing storage
	// with the caller's package (BI-4.1 no-mutation).
	if len(pkg.Events) == 0 {
		return out, nil
	}
	out.Events = make([]schema.Event, len(pkg.Events))
	copy(out.Events, pkg.Events)

	var events []RedactionEvent
	for i := range out.Events {
		ev := &out.Events[i]
		base := "events[" + strconv.Itoa(i) + "]"

		// Scan the free-form Summary text for an embedded JWT (BI-4.2). The
		// scan emits one jwt_body event per JWT occurrence (ROUND-1 minor:
		// per-occurrence audit, not one collapsed event).
		if ev.Summary != "" {
			redacted, n := jwtScan(ev.Summary)
			if n > 0 {
				ev.Summary = redacted
				for j := 0; j < n; j++ {
					events = append(events, RedactionEvent{
						FieldPath:  base + ".summary",
						Reason:     ReasonJWTBody,
						WorkloadID: pkg.WorkloadID,
						RedactedAt: now,
					})
				}
			}
		}

		// Scan each Tag with the shared JWT scan (ROUND-1 fix #3). Tags
		// previously bypassed redaction entirely. The Tags slice is cloned so
		// the redacted copy never shares backing storage with the caller
		// (BI-4.1 no-mutation), even when no tag is redacted.
		if len(ev.Tags) > 0 {
			tags := make([]string, len(ev.Tags))
			copy(tags, ev.Tags)
			for j := range tags {
				redacted, n := jwtScan(tags[j])
				if n > 0 {
					tags[j] = redacted
					for k := 0; k < n; k++ {
						events = append(events, RedactionEvent{
							FieldPath:  base + ".tags[" + strconv.Itoa(j) + "]",
							Reason:     ReasonJWTBody,
							WorkloadID: pkg.WorkloadID,
							RedactedAt: now,
						})
					}
				}
			}
			ev.Tags = tags
		}

		// Deep-walk the decoded Event.Raw tree (BI-4.2). Event.Raw is always
		// re-marshalled (or replaced by the fail-closed placeholder) below, so
		// the returned Raw is a fresh backing array and never aliases the
		// caller's (BI-4.1 no-mutation, ROUND-1 fix #6).
		if len(ev.Raw) == 0 {
			continue
		}
		var tree any
		if err := json.Unmarshal(ev.Raw, &tree); err != nil {
			// Fail-closed (BI-6.1): a blob the walker cannot reason about is
			// hashed-and-dropped, never forwarded.
			ev.Raw = rawPlaceholderJSON(ev.Raw)
			events = append(events, RedactionEvent{
				FieldPath:  base + ".raw",
				Reason:     ReasonRawPayload,
				WorkloadID: pkg.WorkloadID,
				RedactedAt: now,
			})
			continue
		}
		w := &walker{workloadID: pkg.WorkloadID, now: now}
		redactedTree := w.walk(tree, base+".raw")
		// Re-marshal deterministically: encoding/json sorts object keys, so the
		// same input bytes yield the same output bytes (BI-4.2 determinism).
		reb, err := json.Marshal(redactedTree)
		if err != nil {
			// Defensive: a tree built only from unmarshalled JSON + string/map
			// replacements always re-marshals, but stay fail-closed if it ever
			// does not.
			ev.Raw = rawPlaceholderJSON(ev.Raw)
			events = append(events, RedactionEvent{
				FieldPath:  base + ".raw",
				Reason:     ReasonRawPayload,
				WorkloadID: pkg.WorkloadID,
				RedactedAt: now,
			})
			continue
		}
		ev.Raw = reb
		events = append(events, w.events...)
	}
	return out, events
}

// RedactAndAudit is the wired entry point that Stories 3.2/3.5-3.7 call: it
// runs Redact() and, when sink is non-nil, enqueues each RedactionEvent to the
// AUDIT.redactions sink (BI-7.3). A nil sink (off-by-default, the audit-disabled
// path) emits nothing. The audit enqueue is best-effort and NEVER fails or
// blocks the redaction (BI-6.2): Redact() has already returned the redacted
// copy before the sink is touched, so the security guarantee stands regardless
// of the audit outcome.
func RedactAndAudit(pkg schema.EvidencePackage, sink *RedactionAuditSink) (schema.EvidencePackage, []RedactionEvent) {
	redacted, events := Redact(pkg)
	if sink != nil && len(events) > 0 {
		sink.Enqueue(events, pkg.PackageID)
	}
	return redacted, events
}

// walker carries the per-package redaction context while recursing an Event.Raw
// tree. It accumulates the ordered redaction events and threads the immutable
// workload id / decision time onto each.
type walker struct {
	workloadID string
	now        time.Time
	events     []RedactionEvent
}

// walk recurses a decoded-JSON value at path, returning the redacted value.
// Map keys are sorted before descent so the event order (and thus the
// AUDIT.redactions ordering) is deterministic (BI-4.2/BI-4.4).
func (w *walker) walk(v any, path string) any {
	switch t := v.(type) {
	case map[string]any:
		return w.walkObject(t, path)
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = w.walk(e, path+"["+strconv.Itoa(i)+"]")
		}
		return out
	case string:
		// Apply the shared JWT search-scan to EVERY string value (ROUND-1
		// fix #2): a JWT embedded inside a larger string (e.g. an
		// "authorization":"Bearer eyJ..." value) is redacted, not only a
		// whole-string JWT. One jwt_body event per occurrence.
		redacted, n := jwtScan(t)
		for j := 0; j < n; j++ {
			w.record(path, ReasonJWTBody)
		}
		return redacted
	default:
		return v
	}
}

// walkObject handles a JSON object: a file-reference shape collapses to
// {path,size,sha256}; otherwise each key is inspected (secret-key match,
// raw-payload key) before recursing the value. Keys are visited in sorted order
// for deterministic event ordering.
func (w *walker) walkObject(m map[string]any, path string) any {
	if ref, ok := w.fileRef(m, path); ok {
		w.record(path, ReasonFileContents)
		return ref
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Name/value-pair pass (ROUND-1 fix #1): the K8s/CRI env shape
	// {"name":"DB_PASSWORD","value":"topsecret"} carries the secret in the
	// SIBLING value, not under a secret-matching key. Pre-compute which sibling
	// value key (if any) must be force-redacted because a name/key sibling's
	// VALUE denotes a secret. This is evaluated against the ORIGINAL object so
	// it does not depend on map-walk order.
	forceRedactValueKey := secretNameValueSibling(m)

	out := make(map[string]any, len(m))
	for _, k := range keys {
		child := path + "." + k
		val := m[k]
		switch {
		case isSecretKey(k):
			// Key-based redaction (AC1): the WHOLE value (a string or a nested
			// subtree) is replaced with the literal token.
			w.record(child, ReasonSecretPattern)
			out[k] = redactedToken
		case forceRedactValueKey != "" && k == forceRedactValueKey:
			// Name/value-pair redaction (ROUND-1 fix #1): a sibling name/key
			// named a secret, so this value field is redacted.
			w.record(child, ReasonSecretPattern)
			out[k] = redactedToken
		case isRawPayloadKey(k, val):
			// A recognised raw-network-payload blob -> hash-and-drop (AC1),
			// gated by the binary/encoding heuristic (ROUND-1 fix #8) so a
			// plain human-readable string under data/payload/bytes is NOT
			// shredded.
			w.record(child, ReasonRawPayload)
			out[k] = rawPayloadPlaceholder(val)
		default:
			out[k] = w.walk(val, child)
		}
	}
	return out
}

// secretNameValueSibling implements the K8s/CRI name/value-pair detection
// (ROUND-1 fix #1). When the object has a string field under a name key
// (`name`/`key`) whose VALUE denotes a secret (matches isSecretKey) AND a
// sibling value field (`value`/`val`) exists, it returns the sibling value key
// whose value must be redacted; otherwise "". The name/key field itself is left
// intact (it is a label, not the secret).
func secretNameValueSibling(m map[string]any) string {
	nameDenotesSecret := false
	for _, nk := range nameValueNameKeys {
		if nv, ok := m[nk].(string); ok && isSecretKey(nv) {
			nameDenotesSecret = true
			break
		}
	}
	if !nameDenotesSecret {
		return ""
	}
	for _, vk := range nameValueValueKeys {
		if _, ok := m[vk]; ok {
			return vk
		}
	}
	return ""
}

// record appends a redaction event in walk order.
func (w *walker) record(path, reason string) {
	w.events = append(w.events, RedactionEvent{
		FieldPath:  path,
		Reason:     reason,
		WorkloadID: w.workloadID,
		RedactedAt: w.now,
	})
}

// jwtScan is the SINGLE shared JWT search-and-replace scan (ROUND-1 fix #2/#3).
// It finds every JWT-looking candidate inside s, replaces each structurally
// valid JWT with the literal JWT token, and returns the rewritten string plus
// the COUNT of JWTs replaced (for per-occurrence audit events). It is applied
// uniformly to every string value in the Event.Raw walk, to Event.Summary, and
// to each Event.Tags entry, so a JWT embedded inside a larger string is caught
// rather than only a whole-string JWT value.
func jwtScan(s string) (string, int) {
	count := 0
	out := jwtCandidateRe.ReplaceAllStringFunc(s, func(tok string) string {
		if isJWT(tok) {
			count++
			return redactedJWTToken
		}
		return tok
	})
	return out, count
}

// jwtCandidateRe matches a three-segment dot-separated base64url candidate
// inside free text, so an embedded JWT in any string value is detected. The
// signature segment may be empty (an unsigned JWT, header.body.) so the third
// segment uses `*`; isJWT then confirms the header AND body decode to JSON
// objects (ROUND-1 fix #2/#7).
var jwtCandidateRe = regexp.MustCompile(`[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)

// isJWT reports whether s is a structurally valid JWT: three base64url segments
// separated by dots, where BOTH the header (parts[0]) AND the body (parts[1])
// decode to a JSON object (BI-4.2). Value-based detection (AC1).
//
// ROUND-1 fix #7 (false positives): the original predicate only decoded the
// header, so a token like eyJhIjoxfQ.AAAA.BBBB (a valid-JSON header followed by
// arbitrary segments) was misclassified as a JWT. Requiring the BODY to also
// be a decodable JSON object removes those false positives while still matching
// real JWTs (a real claims set is always a JSON object). The signature segment
// is left unchecked because it is opaque bytes (and may be empty for an unsigned
// JWT).
func isJWT(s string) bool {
	parts := splitDot(s)
	if len(parts) != 3 {
		return false
	}
	// Header and body must be present base64url segments; the signature may be
	// empty (unsigned JWT) but must be base64url when present.
	if parts[0] == "" || parts[1] == "" {
		return false
	}
	for _, p := range parts[:2] {
		if !jwtSegmentRe.MatchString(p) {
			return false
		}
	}
	if parts[2] != "" && !jwtSegmentRe.MatchString(parts[2]) {
		return false
	}
	if !decodesToJSONObject(parts[0]) || !decodesToJSONObject(parts[1]) {
		return false
	}
	return true
}

// decodesToJSONObject reports whether a base64url segment decodes to a non-empty
// JSON object.
func decodesToJSONObject(seg string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return false
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return false
	}
	return len(obj) > 0
}

// splitDot splits on '.' without allocating via strings.Split semantics drift.
func splitDot(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

// isRawPayloadKey reports whether key k under value val is a recognised raw
// network payload blob that should be hashed-and-dropped (AC1).
//
// ROUND-1 fix #8 (over-redaction): a plain human-readable string under
// data/payload/bytes (e.g. {"data":"hello world ..."}) is NOT a byte blob and
// must be left intact (it still gets JWT/secret scanning as an ordinary string
// value). The reduction is therefore gated behind a binary/encoding heuristic:
// the value must be a string that decodes as base64/hex of meaningful length OR
// has a high non-printable ratio. A non-string value under one of these keys
// is left to the normal recursive walk.
func isRawPayloadKey(k string, val any) bool {
	if _, ok := rawPayloadKeys[k]; !ok {
		return false
	}
	s, isStr := val.(string)
	if !isStr {
		return false
	}
	return looksLikeBinaryBlob(s)
}

// minBlobLen is the smallest string length we treat as a candidate byte blob.
// Below this a base64/hex "match" is far more likely to be a short benign word.
const minBlobLen = 16

// looksLikeBinaryBlob reports whether s looks like an encoded byte blob (the
// ROUND-1 fix #8 heuristic). True when s decodes as base64 or hex to a
// meaningful length, or when the raw string has a high non-printable ratio.
// A plain human-readable ASCII string returns false.
func looksLikeBinaryBlob(s string) bool {
	if len(s) < minBlobLen {
		return false
	}
	if nonPrintableRatio(s) > 0.15 {
		return true
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) >= minBlobLen {
		// Base64 of plain ASCII text decodes back to printable text; only treat
		// it as a blob when the decoded bytes are themselves non-printable.
		if nonPrintableRatio(string(b)) > 0.15 {
			return true
		}
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil && len(b) >= minBlobLen {
		if nonPrintableRatio(string(b)) > 0.15 {
			return true
		}
	}
	if isHexString(s) && len(s) >= 2*minBlobLen {
		return true
	}
	return false
}

// nonPrintableRatio returns the fraction of bytes in s outside the printable
// ASCII range (and not common whitespace).
func nonPrintableRatio(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	nonPrintable := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		if c < 0x20 || c > 0x7e {
			nonPrintable++
		}
	}
	return float64(nonPrintable) / float64(len(s))
}

// isHexString reports whether s is all hex digits (even length).
func isHexString(s string) bool {
	if len(s)%2 != 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isHexDigit := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHexDigit {
			return false
		}
	}
	return true
}

// fileRefContentKeys is the documented set of keys under which a file-reference
// object carries its (to-be-dropped) contents (AC2). ROUND-1 fix #4(b) broadens
// it beyond content/contents/data to realistic aliases.
var fileRefContentKeys = []string{"content", "contents", "data", "body", "text", "blob"}

// fileRefPathKeys is the set of path-like keys a file reference may carry.
var fileRefPathKeys = []string{"path", "filename", "file", "filepath"}

// fileRef reports whether m is a file-reference object (a path-like key plus a
// content-bearing key) and, if so, returns the reduced {path, size, sha256}
// form dropping the contents (AC2). The contents are hashed so the forensic
// chain keeps a content-addressable reference without the bytes.
//
// ROUND-1 fix #4: the reduction is triggered by the PRESENCE of a
// content-bearing key together with a path-like key, REGARDLESS of the path
// value's type (a non-string path no longer makes fileRef bail and leak the
// contents). The content value may be a non-string (object/array): its
// marshalled bytes are hashed rather than emitting size:0 + empty hash.
// Non-content sibling SCALAR keys (e.g. mode, owner) are preserved on the
// reduced form rather than silently dropped.
func (w *walker) fileRef(m map[string]any, path string) (map[string]any, bool) {
	// Find a content-bearing key (the trigger).
	contentKey := ""
	for _, ck := range fileRefContentKeys {
		if _, ok := m[ck]; ok {
			contentKey = ck
			break
		}
	}
	if contentKey == "" {
		return nil, false
	}
	// Require a path-like key so we do not collapse an arbitrary object that
	// merely carries a `data` field (those go through the raw-payload / normal
	// walk). The path-like key may hold a non-string value (fix #4a).
	pathKey := ""
	for _, pk := range fileRefPathKeys {
		if _, ok := m[pk]; ok {
			pathKey = pk
			break
		}
	}
	if pathKey == "" {
		return nil, false
	}

	// Hash the content bytes. A string hashes its bytes; a non-string
	// (object/array/number/bool) hashes its marshalled JSON bytes so we never
	// emit size:0 + empty-hash for structured contents (fix #4c).
	var contentBytes []byte
	if cs, ok := m[contentKey].(string); ok {
		contentBytes = []byte(cs)
	} else if b, err := json.Marshal(m[contentKey]); err == nil {
		contentBytes = b
	} else {
		contentBytes = []byte{}
	}
	sum := sha256.Sum256(contentBytes)

	ref := map[string]any{
		"path":   m[pathKey],
		"size":   len(contentBytes),
		"sha256": hex.EncodeToString(sum[:]),
	}
	// Preserve non-content sibling SCALAR keys (mode, owner, ...) rather than
	// silently dropping them (fix #4d). A scalar sibling that itself matches a
	// secret key or a JWT is redacted; object/array siblings are NOT carried
	// (they could re-introduce un-walked contents).
	for k, v := range m {
		if k == contentKey || k == pathKey {
			continue
		}
		switch v.(type) {
		case string, float64, bool, nil:
			if isSecretKey(k) {
				w.record(path+"."+k, ReasonSecretPattern)
				ref[k] = redactedToken
				continue
			}
			ref[k] = w.walk(v, path+"."+k)
		default:
			// Skip non-scalar siblings: carrying them risks forwarding
			// un-reduced nested contents.
		}
	}
	return ref, true
}

// rawPayloadPlaceholder hashes-and-drops a recognised raw-payload string value,
// returning {redacted:"raw_payload", sha256, len} (AC1). The byte length is the
// decoded length when the value is valid base64, else the raw string length.
func rawPayloadPlaceholder(val any) map[string]any {
	s, _ := val.(string)
	raw := decodePayloadBytes(s)
	sum := sha256.Sum256(raw)
	return map[string]any{
		"redacted": ReasonRawPayload,
		"sha256":   hex.EncodeToString(sum[:]),
		"len":      len(raw),
	}
}

// decodePayloadBytes returns the decoded bytes of a payload string, trying
// base64 (std then raw-url) and falling back to the raw string bytes so a
// non-base64 blob is still hashed-and-dropped rather than forwarded.
func decodePayloadBytes(s string) []byte {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b
	}
	return []byte(s)
}

// rawPlaceholderJSON builds the fail-closed placeholder for an un-parseable
// Event.Raw blob (BI-6.1): the whole blob is hashed-and-dropped. The result is
// valid JSON so the redacted Event.Raw stays a well-formed json.RawMessage.
func rawPlaceholderJSON(raw []byte) json.RawMessage {
	sum := sha256.Sum256(raw)
	b, _ := json.Marshal(map[string]any{
		"redacted": ReasonRawPayload,
		"sha256":   hex.EncodeToString(sum[:]),
		"len":      len(raw),
	})
	return b
}
