// Package redact is the Ring-5 redaction pipeline (Story 3.1, FR44/NFR15).
// It hosts the single reusable Redact() entry point that strips secrets, JWTs,
// and raw payloads out of an EvidencePackage before the data leaves the
// controller process: pre-LLM by the Ring-3 decision tier (Stories 3.5-3.7) and
// pre-persistence by Ring 5 (Epic 4 reuses the same Redact(), AC5).
//
// Ring discipline (BI-1, architecture.md:111 "internal/report (Ring 5)"):
// although redaction LIVES in Ring 5, it is CALLED inward by higher rings, so
// the call direction is always consumer -> redact, never the reverse. This
// package therefore imports ONLY the substrate it operates over
// (internal/schema for EvidencePackage, internal/nats + internal/subjects for
// the audit publish, internal/config). It MUST NOT import internal/decision/*,
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
package redact

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
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

// secretKeyRe matches an object KEY whose value must be replaced with
// <REDACTED> (AC1, key-based). Compiled once as a package var.
var secretKeyRe = regexp.MustCompile(`(?i)(secret|token|password|key|credential|apikey)`)

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

		// Scan the free-form Summary text for an embedded JWT (BI-4.2).
		if ev.Summary != "" {
			redacted, found := redactSummary(ev.Summary)
			if found {
				ev.Summary = redacted
				events = append(events, RedactionEvent{
					FieldPath:  base + ".summary",
					Reason:     ReasonJWTBody,
					WorkloadID: pkg.WorkloadID,
					RedactedAt: now,
				})
			}
		}

		// Deep-walk the decoded Event.Raw tree (BI-4.2).
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
		if isJWT(t) {
			w.record(path, ReasonJWTBody)
			return redactedJWTToken
		}
		return t
	default:
		return v
	}
}

// walkObject handles a JSON object: a file-reference shape collapses to
// {path,size,sha256}; otherwise each key is inspected (secret-key match,
// raw-payload key) before recursing the value. Keys are visited in sorted order
// for deterministic event ordering.
func (w *walker) walkObject(m map[string]any, path string) any {
	if ref, ok := fileRef(m); ok {
		w.record(path, ReasonFileContents)
		return ref
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make(map[string]any, len(m))
	for _, k := range keys {
		child := path + "." + k
		val := m[k]
		switch {
		case secretKeyRe.MatchString(k):
			// Key-based redaction (AC1): the WHOLE value (a string or a nested
			// subtree) is replaced with the literal token.
			w.record(child, ReasonSecretPattern)
			out[k] = redactedToken
		case isRawPayloadKey(k, val):
			// A recognised raw-network-payload blob -> hash-and-drop (AC1).
			w.record(child, ReasonRawPayload)
			out[k] = rawPayloadPlaceholder(val)
		default:
			out[k] = w.walk(val, child)
		}
	}
	return out
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

// redactSummary scans free-form text for an embedded JWT and, if found,
// replaces every JWT-looking token with the literal JWT token (BI-9 edge case).
func redactSummary(s string) (string, bool) {
	found := false
	out := jwtCandidateRe.ReplaceAllStringFunc(s, func(tok string) string {
		if isJWT(tok) {
			found = true
			return redactedJWTToken
		}
		return tok
	})
	return out, found
}

// jwtCandidateRe matches a three-segment dot-separated base64url candidate
// inside free text, so an embedded JWT in Event.Summary is detected.
var jwtCandidateRe = regexp.MustCompile(`[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)

// isJWT reports whether s is a structurally valid JWT: three base64url segments
// separated by dots, where the first segment decodes to a JSON object header
// (BI-4.2). Value-based detection (AC1).
func isJWT(s string) bool {
	parts := splitDot(s)
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" || !jwtSegmentRe.MatchString(p) {
			return false
		}
	}
	hdr, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var header map[string]any
	if err := json.Unmarshal(hdr, &header); err != nil {
		return false
	}
	// A JWT header is a JSON object; requiring a decodable object rules out an
	// arbitrary three-dotted token.
	return len(header) > 0
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
// network payload blob (a documented key carrying a base64/hex byte string).
func isRawPayloadKey(k string, val any) bool {
	if _, ok := rawPayloadKeys[k]; !ok {
		return false
	}
	_, isStr := val.(string)
	return isStr
}

// fileRef reports whether m is a file-reference object ({path, content|contents
// |data}) and, if so, returns the reduced {path, size, sha256} form dropping
// the contents (AC2). The contents are hashed so the forensic chain keeps a
// content-addressable reference without the bytes.
func fileRef(m map[string]any) (map[string]any, bool) {
	pathVal, hasPath := m["path"].(string)
	if !hasPath {
		return nil, false
	}
	var contents string
	for _, ck := range []string{"content", "contents", "data"} {
		if c, ok := m[ck].(string); ok {
			contents = c
			break
		}
	}
	if contents == "" {
		// A {path} with no contents key is an ordinary path field, not a file
		// capture; leave it to the normal walk.
		_, hasContent := m["content"]
		_, hasContents := m["contents"]
		_, hasData := m["data"]
		if !hasContent && !hasContents && !hasData {
			return nil, false
		}
	}
	sum := sha256.Sum256([]byte(contents))
	return map[string]any{
		"path":   pathVal,
		"size":   len(contents),
		"sha256": hex.EncodeToString(sum[:]),
	}, true
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
