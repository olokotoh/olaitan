// Package applog implements the Olaitan agent's application log sidecar
// adapter (Story 1.9 / FR5). The adapter runs as a sidecar container in
// an opt-in workload Pod (annotation olaitan.io/log-sidecar: "enabled"),
// tails the cooperating application's stdout and stderr from a shared
// emptyDir log volume, translates each line into the canonical
// schema.Event of source=applog / category=log, and publishes to
// subjects.RawAppLog via JetStream with best-effort at-least-once
// semantics under a bounded retry budget.
//
// Why source=applog: the schema package (internal/schema/event.go) was
// bootstrapped in Story 1.6 with SourceAppLog = "applog" so the source
// constant matches the architectural axis (application-layer logging,
// distinct from kernel syscalls, audit events, runtime lifecycle, and
// network flows). The story epic text reads "source APP_LOG"; the
// binding interpretation lands here so the PR description and
// APPLOG.md are the single source of truth for the reviewer.
//
// Sidecar topology: the adapter runs as a multi-call binary subcommand
// of the main olaitan image (olaitan applog-sidecar [flags]) so the
// chart ships one image rather than two; the cooperation contract is
// that the application writes its stdout/stderr to a shared emptyDir
// volume at /var/log/app/stdout.log and /var/log/app/stderr.log. The
// MutatingAdmissionWebhook in internal/admission/applog injects the
// sidecar as a native Kubernetes 1.28+ sidecar container (KEP-753
// initContainer with restartPolicy: Always) when the annotation is
// present.
//
// Concurrency model: a single Adapter spawns three goroutines under an
// errgroup -- one tailer per stream (stdout, stderr) plus a consumer
// goroutine that drains the bounded line channel and publishes. The
// bounded channel is the back-pressure surface (Task 4.3 of Story 1.9):
// when the consumer stalls, the tailers enter shed-mode rather than
// buffering unboundedly, because stdout/stderr is user-controlled
// content and a misbehaving application emitting at line-rates above
// NATS publish capacity must not OOM the sidecar.
//
// Watchdog design: app-log streams are quiet by design (a stable batch
// job can run for hours emitting no lines), so the staleness watchdog
// must NOT flip unhealthy on staleness alone. Mirrors the Story 1.8
// CRI watchdog quiet-by-design contract; differs from the Story 1.7
// audit watchdog which required steady traffic.
//
// Failure-domain note: a sidecar runs INSIDE the workload pod and
// shares the workload's failure domain. A panicking sidecar must NOT
// take down the workload pod. Adapter.Run wraps the goroutine body in
// defer recover() so a panic flips the source unhealthy and exits
// cleanly; the native-sidecar restartPolicy: Always then restarts the
// sidecar without affecting the workload (Story 1.9 guardrail item 18).
//
// Workload identity (FR13): the adapter populates schema.Event.Pod
// from the downward API at sidecar startup (K8S_POD_NAME,
// K8S_POD_NAMESPACE, K8S_POD_UID, K8S_NODE_NAME) and treats it as
// constant for the process lifetime. The canonical workload-id
// resolver (internal/keys.WorkloadID, when it lands in Story 1.11+)
// reads PodRef and adds owner-ref resolution at the point workload
// identity is needed; the adapter does NOT perform K8s API calls in
// the hot path. This matches Stories 1.6 (Falco), 1.7 (audit), and
// 1.8 (CRI) which are also pure transforms over their respective wire
// formats.
package applog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/olokotoh/olaitan/internal/schema"
)

// minValidEventTime is the floor below which a Translate-supplied
// timestamp is treated as garbage. Mirrors Stories 1.6 (Falco), 1.7
// (audit), and 1.8 (CRI): a timestamp before 2010 indicates either an
// unset zero (Unix epoch) or severe clock skew on the node, both of
// which would mis-bucket events in the downstream sliding-window
// correlator. Reject early.
var minValidEventTime = time.Date(2010, time.January, 1, 0, 0, 0, 0, time.UTC)

// maxFutureSkew caps how far past "now" a translate-time timestamp
// may land. The 24h ceiling matches Stories 1.6 / 1.7 / 1.8 (single
// common guard across all sources).
const maxFutureSkew = 24 * time.Hour

// MaxLineBytes is the per-line payload cap applied at translate time.
// Lines longer than the cap are truncated to MaxLineBytes; the truncated
// suffix is dropped and a "truncated:true" tag is appended. The cap
// (64 KiB) sits well below JetStream's 256 KiB MaxMsgSize so the
// envelope plus tags plus summary always fit.
const MaxLineBytes = 64 * 1024

// summaryLinePreview caps the line preview embedded in the human-
// readable Summary string. Keep small for log readability; the full
// content lives in Event.Raw.
const summaryLinePreview = 128

// maxSanitizedTagLen caps a single sanitized tag value (label values,
// container names, pod names) at 256 bytes. Mirrors Stories 1.7 / 1.8.
// User-controlled strings can otherwise carry crash-vector inputs
// (newlines, NUL, control sequences) that derail downstream tag-string
// parsers.
const maxSanitizedTagLen = 256

// labelPrefixesAllowed is the whitelist of pod-label prefixes the
// adapter forwards to schema.Event.Tags. User-controlled label values
// can carry crash-vector strings; only labels under prefixes the
// operator already vetted as safe (kubernetes.io conventions and
// olaitan.io/* opt-in markers) are forwarded.
var labelPrefixesAllowed = []string{
	"app.kubernetes.io/",
	"olaitan.io/",
}

// ErrInvalidTimestamp is returned by Translate when the supplied
// timestamp is zero, before minValidEventTime, or further than
// maxFutureSkew in the future. Callers (the adapter consumer loop)
// log+drop and continue.
var ErrInvalidTimestamp = errors.New("applog: invalid timestamp")

// ErrInvalidStream is returned by Translate when the LineRecord.Stream
// value is not one of {"stdout", "stderr"}. The tail layer is the only
// in-tree producer and always sets one of the two; a future code change
// that introduces a third stream classification trips this defensively.
var ErrInvalidStream = errors.New("applog: invalid stream classification")

// ErrEmptyContainer is returned by Translate when LineRecord.Container
// is empty. The adapter populates it from the downward API at startup;
// an empty value indicates a misconfigured Helm template.
var ErrEmptyContainer = errors.New("applog: empty container name")

// ErrNilLine is returned by Translate when LineRecord.Line is nil.
// Empty lines (zero-length but non-nil byte slice) are legal and emit
// successfully; nil indicates a producer bug.
var ErrNilLine = errors.New("applog: nil line bytes")

// ErrNegativeOffset is returned by Translate when LineRecord.Offset is
// negative. The tailer increments Offset by one per scanned line
// starting from 1; a negative value indicates either an overflow (the
// adapter has run long enough that a 63-bit counter wrapped, which is
// not currently realistic) or a producer bug. Rejecting protects the
// stableEventID dedup-collision guarantee.
var ErrNegativeOffset = errors.New("applog: negative offset")

// LineRecord is the input value-type to Translate. The adapter's tail
// layer constructs one per scanned line and pushes it onto the bounded
// in-process channel; the consumer goroutine pulls and translates.
// Every field is set by the producer; Translate has no defaults.
type LineRecord struct {
	// Line carries the raw line bytes as scanned from the log file.
	// Translate handles UTF-8 sanitization, embedded NUL handling, and
	// length capping deterministically; producers do NOT pre-sanitize.
	// A nil slice is rejected with ErrNilLine; an empty (zero-length
	// but non-nil) slice is legal and produces an empty-Raw event.
	Line []byte

	// Stream identifies which pipe produced the line. The only valid
	// values are "stdout" and "stderr"; Translate rejects any other
	// value with ErrInvalidStream so a future code change that quietly
	// introduces a third classification trips the test net rather than
	// silently producing untagged events.
	Stream string

	// Timestamp is the wall-clock time at which the tailer scanned the
	// line off the underlying log file. Producers capture this at
	// scan time (preferring the monotonic-preserving time.Now()) and
	// pass it through; Translate does NOT read time.Now() for this
	// field. Translate does read time.Now() for the maxFutureSkew
	// guard, which is the single wall-clock dependency in this
	// transform.
	Timestamp time.Time

	// Pod identifies the workload pod the sidecar is attached to. The
	// adapter populates it from the downward API (K8S_POD_NAME,
	// K8S_POD_NAMESPACE, K8S_POD_UID, K8S_NODE_NAME) at sidecar
	// startup and treats it as constant for the process lifetime.
	Pod schema.PodRef

	// Container is the application (peer) container name the sidecar
	// is targeting. It comes from the OLAITAN_TARGET_CONTAINER env var
	// injected by the admission webhook. NOT this sidecar's own name.
	Container string

	// Offset is a per-stream monotonic counter held by the tailer. It
	// participates in stableEventID derivation so two distinct lines
	// with byte-identical content emitted within the same nanosecond
	// produce different IDs (no spurious JetStream dedup collisions).
	// The tailer increments Offset by one per scanned line; the
	// in-process counter is reset only on Adapter Run-loop entry.
	Offset int64

	// Labels carries the workload pod's labels for the tag-forwarding
	// step. Only labels under the labelPrefixesAllowed whitelist are
	// forwarded; the rest are dropped. The adapter populates this from
	// the downward API at startup (typically via a /etc/podinfo/labels
	// projected volume) so the map is constant for the process
	// lifetime; nil is legal (pod has no labels of interest).
	Labels map[string]string

	// MaxLineBytes is the operator-tuned per-event line cap. Zero means
	// "use the package default" (the MaxLineBytes constant, 64 KiB). The
	// adapter populates this from Config.MaxLineBytesOverride; the
	// recBuilder closure forwards it on every record. Translate clamps
	// any non-zero value below 1 KiB up to 1 KiB defensively.
	MaxLineBytes int
}

// Translate converts a LineRecord into the canonical schema.Event.
//
// Determinism: the field-mapping is purely a function of the input.
// The future-skew check reads time.Now() to reject events more than
// maxFutureSkew ahead of wall clock; this is the single wall-clock
// dependency. Two calls within the same maxFutureSkew window with the
// same LineRecord produce byte-equal outputs (modulo the canonicalised
// Tags slice, which is sorted lexicographically post-prefix, so the
// output is deterministic regardless of Labels-map iteration order).
//
// Translation contract:
//
//   - Event.ID is a 128-bit (32 hex char) SHA-256 prefix over
//     (pod_uid, container, stream, timestamp_unix_nano, offset,
//     truncated_line_bytes). The 128-bit prefix matches the
//     post-Story-1.6-follow-up collision-resistance bound. The
//     truncated line bytes (rather than the original) participate so
//     that the published payload's Raw can be re-hashed to derive the
//     same ID at consume time.
//   - Event.Source is pinned to schema.SourceAppLog ("applog") and
//     Event.Category to schema.CategoryLog ("log").
//   - Event.Pod is copied from LineRecord.Pod (PodRef is a value type,
//     so the assignment is a deep copy of all fields).
//   - Event.Severity is always "informational". Severity escalation
//     based on log content (e.g. matching "ERROR" prefix) is the OLT
//     Sigma rule engine's job (Story 1.15) operating against the
//     windowed event buffer assembled by Story 1.14. The adapter MUST
//     NOT parse line text to assign severity; that path produces
//     unstable severity contracts under user log-format changes.
//   - Event.Summary is a short human-readable line including a
//     128-byte preview of the sanitised line content.
//   - Event.Raw carries the line bytes after UTF-8 sanitization
//     (invalid bytes replaced with U+FFFD via utf8.ToValidUTF8) and
//     after length capping at MaxLineBytes. A line longer than
//     MaxLineBytes is truncated and a "truncated:true" tag is
//     appended. NUL bytes are preserved in Raw (legal UTF-8) but
//     stripped from Summary by sanitizeForTag.
//   - Event.Tags include stream:<stdout|stderr>, container:<name>,
//     optional truncated:true, optional encoding:replaced (when
//     UTF-8 sanitization replaced any invalid byte sequences), and
//     any pod labels under labelPrefixesAllowed.
//
// Returns one of the sentinel errors (ErrInvalidTimestamp,
// ErrInvalidStream, ErrEmptyContainer, ErrNilLine) for the well-known
// invalid-input cases; a wrapped fmt.Errorf for any other failure.
func Translate(rec LineRecord) (schema.Event, error) {
	if rec.Line == nil {
		return schema.Event{}, fmt.Errorf("applog: translate: %w", ErrNilLine)
	}
	if rec.Stream != "stdout" && rec.Stream != "stderr" {
		return schema.Event{}, fmt.Errorf("applog: translate: stream=%q: %w", rec.Stream, ErrInvalidStream)
	}
	if rec.Container == "" {
		return schema.Event{}, fmt.Errorf("applog: translate: %w", ErrEmptyContainer)
	}
	if rec.Offset < 0 {
		return schema.Event{}, fmt.Errorf("applog: translate: offset=%d: %w", rec.Offset, ErrNegativeOffset)
	}
	if rec.Timestamp.IsZero() {
		return schema.Event{}, fmt.Errorf("applog: translate: zero timestamp: %w", ErrInvalidTimestamp)
	}
	if rec.Timestamp.Before(minValidEventTime) {
		return schema.Event{}, fmt.Errorf("applog: translate: timestamp %s is before %s: %w",
			rec.Timestamp.Format(time.RFC3339Nano), minValidEventTime.Format(time.RFC3339), ErrInvalidTimestamp)
	}
	if rec.Timestamp.After(time.Now().Add(maxFutureSkew)) {
		return schema.Event{}, fmt.Errorf("applog: translate: timestamp %s is more than %s in the future: %w",
			rec.Timestamp.Format(time.RFC3339Nano), maxFutureSkew, ErrInvalidTimestamp)
	}

	sanitised, replaced, truncated := sanitizeLine(rec.Line, effectiveMaxLineBytes(rec.MaxLineBytes))

	id := stableEventID(rec, sanitised)
	summary := buildSummary(rec.Stream, rec.Container, rec.Pod, sanitised)
	tags := buildTags(rec.Stream, rec.Container, truncated, replaced, rec.Labels)

	rawJSON, err := marshalRaw(sanitised)
	if err != nil {
		return schema.Event{}, fmt.Errorf("applog: translate: marshal raw: %w", err)
	}

	return schema.Event{
		ID:        id,
		Timestamp: rec.Timestamp,
		Source:    schema.SourceAppLog,
		Pod:       rec.Pod,
		Severity:  "informational",
		Category:  schema.CategoryLog,
		Summary:   summary,
		Raw:       rawJSON,
		Tags:      tags,
	}, nil
}

// sanitizeLine returns the UTF-8-sanitised, length-capped line bytes
// plus two flags: replaced=true when invalid UTF-8 byte sequences were
// substituted with U+FFFD, truncated=true when the line was longer than
// MaxLineBytes and the suffix was dropped.
//
// NUL bytes are preserved in the sanitised slice (NUL is legal UTF-8;
// some legacy daemons emit NUL-delimited records, and the downstream
// Sigma rules can match them). The Summary path strips NUL via
// sanitizeForTag.
//
// The returned slice is freshly allocated; it never aliases the input
// slice's backing array, so callers can safely retain a reference even
// if the input came from a scanner's reusable buffer.
func sanitizeLine(line []byte, max int) (out []byte, replaced bool, truncated bool) {
	if max <= 0 {
		max = MaxLineBytes
	}
	if len(line) > max {
		line = line[:max]
		truncated = true
	}
	if utf8.Valid(line) {
		// Even on the valid path return a fresh copy so callers cannot
		// alias a scanner buffer that may be overwritten on the next
		// scan iteration.
		out = append([]byte(nil), line...)
		return out, false, truncated
	}
	out = bytes.ToValidUTF8(line, []byte{0xEF, 0xBF, 0xBD}) // U+FFFD encoded
	replaced = true
	return out, replaced, truncated
}

// stableEventID derives a 128-bit SHA-256 prefix over the unique
// per-line tuple. The line offset participates so two byte-identical
// lines emitted within the same nanosecond produce different IDs (no
// spurious JetStream dedup collisions). Use fmt.Fprintf with a stable
// \x00 separator so a container name or pod UID containing a literal
// "|" or ":" cannot be reordered into a colliding hash input. The
// truncated line bytes (rather than the original) participate so the
// published Raw can be re-hashed to derive the same ID. hash.Hash.Write
// returns nil per its contract; errors are explicitly discarded so
// errcheck does not flag them (Story 1.6 follow-up patch precedent).
func stableEventID(rec LineRecord, sanitised []byte) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s\x00%s\x00%s\x00%d\x00%d\x00",
		rec.Pod.UID, rec.Container, rec.Stream, rec.Timestamp.UnixNano(), rec.Offset)
	_, _ = h.Write(sanitised)
	sum := h.Sum(nil)
	return hex.EncodeToString(sum)[:32]
}

// buildSummary renders a short human-readable line: e.g.
// `stdout default/payments-7f8b9c container=payments line="..."`. The
// line preview is sanitised via sanitizeForTag (control-char strip and
// 256-byte cap) and quoted with %q so a newline-bearing log line
// cannot inject control characters into structured log lines.
func buildSummary(stream, container string, pod schema.PodRef, sanitised []byte) string {
	preview := sanitised
	if len(preview) > summaryLinePreview {
		preview = preview[:summaryLinePreview]
	}
	previewStr := sanitizeForTag(string(preview))
	ns := sanitizeForTag(pod.Namespace)
	name := sanitizeForTag(pod.Name)
	containerSan := sanitizeForTag(container)
	if ns == "" && name == "" {
		return fmt.Sprintf("%s container=%s line=%q", stream, containerSan, previewStr)
	}
	return fmt.Sprintf("%s %s/%s container=%s line=%q", stream, ns, name, containerSan, previewStr)
}

// buildTags assembles schema.Event.Tags. Returns a freshly allocated
// slice so callers cannot retain a reference that aliases any
// underlying map or scanner-buffer memory.
//
//   - stream:<stdout|stderr>            always present
//   - container:<sanitised name>        always present
//   - truncated:true                    when the line was capped at
//     MaxLineBytes
//   - encoding:replaced                 when UTF-8 sanitization replaced
//     any invalid byte sequence
//   - app.kubernetes.io/* / olaitan.io/* labels  forwarded under the
//     prefix whitelist; copied via slice append-from-nil and value-
//     sanitised so a downstream tag-string parser cannot be derailed
//     by a newline-bearing label value.
func buildTags(stream, container string, truncated, replaced bool, labels map[string]string) []string {
	tags := make([]string, 0, 4+len(labels))
	tags = append(tags, "stream:"+stream)
	tags = append(tags, "container:"+sanitizeForTag(container))
	if truncated {
		tags = append(tags, "truncated:true")
	}
	if replaced {
		tags = append(tags, "encoding:replaced")
	}

	if len(labels) > 0 {
		// Iterate keys in sorted order so two translations of the same
		// LineRecord produce byte-equal Tags slices regardless of
		// Go-map iteration randomisation.
		keys := make([]string, 0, len(labels))
		for k := range labels {
			if !labelHasAllowedPrefix(k) {
				continue
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			tags = append(tags, k+":"+sanitizeForTag(labels[k]))
		}
	}
	return append([]string(nil), tags...)
}

// effectiveMaxLineBytes returns the per-record effective cap. Zero
// uses the package default (MaxLineBytes constant, 64 KiB). Any value
// below 1 KiB is clamped up to 1 KiB so an operator misconfiguration
// in the chart values cannot wire through a cap that breaks the bench
// gate or starves the Sigma engine of context.
func effectiveMaxLineBytes(override int) int {
	if override <= 0 {
		return MaxLineBytes
	}
	if override < 1024 {
		return 1024
	}
	return override
}

// labelHasAllowedPrefix returns true when k starts with any prefix in
// labelPrefixesAllowed. Linear scan is fine: the whitelist has only
// two entries.
func labelHasAllowedPrefix(k string) bool {
	for _, p := range labelPrefixesAllowed {
		if strings.HasPrefix(k, p) {
			return true
		}
	}
	return false
}

// sanitizeForTag strips control characters (Unicode category Cc apart
// from \t) and caps the result at maxSanitizedTagLen bytes. Used on
// every user-controlled string that ends up inside a tag entry, the
// summary log line, or any other downstream-parsed text. Newlines, NUL
// bytes, and arbitrary control sequences would otherwise let a
// pod-label, line-preview, or pod-name value break the tag-string
// format expected by the OLT Sigma rule engine and the structured
// logger. Mirrors cri.sanitizeForTag exactly.
func sanitizeForTag(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\t' {
			b.WriteRune(r)
			continue
		}
		if unicode.IsControl(r) {
			continue
		}
		b.WriteRune(r)
	}
	out := b.String()
	if len(out) > maxSanitizedTagLen {
		out = out[:maxSanitizedTagLen]
	}
	return out
}

// marshalRaw wraps the sanitised line bytes as a JSON-encoded string
// inside Event.Raw. Using a JSON string (rather than a JSON object) is
// deliberate: the raw payload is opaque application content that
// downstream consumers (OLT Sigma rules, the LLM analyst chain) read
// as a literal text body, not a structured object. encoding/json
// handles NUL and other low-control bytes by escaping them as \u00XX
// sequences automatically.
func marshalRaw(sanitised []byte) (json.RawMessage, error) {
	return json.Marshal(string(sanitised))
}
