package falco

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/olokotoh/olaitan/internal/collector/falco/falcopb"
	"github.com/olokotoh/olaitan/internal/schema"
)

// minValidEventTime is the floor below which a Falco-supplied timestamp
// is treated as garbage. Falco's grpc_output stamps events with the
// node's wall clock; in practice a value before 2010 indicates either
// an unset Timestamp{Seconds:0} (Unix epoch) or severe clock skew on
// the node. Either way, downstream sliding-window correlation would
// mis-bucket the event, so reject early.
var minValidEventTime = time.Date(2010, time.January, 1, 0, 0, 0, 0, time.UTC)

// unknownPriorityOnce ensures the warn for an unknown Falco priority
// enum value fires at most once per process lifetime; without this a
// runaway upstream that ships 10k events with an unknown enum would
// flood the operator's log aggregator.
var unknownPriorityOnce sync.Once

// Translate converts a Falco gRPC Response into the canonical schema.Event.
//
// Pure: no I/O (apart from a one-shot warn on the first unknown
// priority enum value), deterministic given the same input. The
// hostname argument is the node-level identifier the caller already
// knows (typically read from the K8S_NODE_NAME env var injected by the
// Helm chart's downward API); it lands in Event.Pod.Node so events
// without Kubernetes context still record where they were observed.
//
// Translation contract (Story 1.6 Task 3.2):
//
//   - Event.ID is `output_fields["evt.uuid"]` if present; otherwise the
//     first 32 hex chars of SHA-256 (128 bits) over a deterministic
//     concatenation of stable fields. The 128-bit prefix gives the
//     consumer-side dedup hook collision-resistance well past the
//     architecture's per-cluster lifetime event budget; 64-bit
//     truncation reached non-negligible birthday probability within
//     days at the architecture's per-source rates.
//   - Event.Source / Event.Category are pinned to (SourceFalco,
//     CategorySyscall) regardless of Response.Source. The AC's
//     "source SYS_CALL" reads as Source=falco + Category=syscall.
//   - Event.Severity is the Falco priority lowercased so it matches
//     the project's severity vocabulary (emergency..debug).
//   - Event.Raw is the marshalled output_fields plus rule, priority
//     name, tags, the Falco source string, and falco_hostname (the
//     hostname Falco itself observed, preserved here for forensic
//     debugging when it disagrees with K8S_NODE_NAME), so downstream
//     forensic callers do not need a second gRPC round-trip. The
//     output_fields map is keyed deterministically (alphabetical) so
//     repeated translations of the same Response produce byte-for-byte
//     identical Raw payloads.
//
// Returns a wrapped "falco: ..." error for nil resp, missing or
// pre-epoch Time, or JSON marshal failure (currently unreachable for
// the chosen shape but kept defensive in case the schema grows).
func Translate(resp *falcopb.Response, hostname string) (schema.Event, error) {
	if resp == nil {
		return schema.Event{}, fmt.Errorf("falco: translate: nil response")
	}
	if resp.GetTime() == nil {
		return schema.Event{}, fmt.Errorf("falco: translate: missing Time on response (rule=%q)", resp.GetRule())
	}

	ts := resp.GetTime().AsTime()
	if ts.IsZero() || ts.Before(minValidEventTime) {
		return schema.Event{}, fmt.Errorf("falco: translate: timestamp %s is before %s (likely clock skew or unset Timestamp{Seconds:0}, rule=%q)",
			ts.Format(time.RFC3339Nano), minValidEventTime.Format(time.RFC3339), resp.GetRule())
	}

	id := stableEventID(resp)

	fields := resp.GetOutputFields()
	pod := schema.PodRef{
		Name:      fields["k8s.pod.name"],
		Namespace: fields["k8s.ns.name"],
		Node:      hostname,
		UID:       fields["k8s.pod.uid"],
	}

	// Defensive copy: resp.GetTags() returns a slice that aliases proto-
	// runtime memory. If the gRPC runtime ever pools messages, the
	// published Event.Tags would alias mutated buffer contents. Copy by
	// append-from-nil to fully detach.
	tags := append([]string(nil), resp.GetTags()...)

	priorityName := canonicalPriorityName(resp.GetPriority())
	rawPayload := map[string]any{
		"rule":           resp.GetRule(),
		"priority":       priorityName,
		"output_fields":  sortedFields(fields),
		"tags":           tags,
		"source":         resp.GetSource(),
		"falco_hostname": resp.GetHostname(),
	}
	rawJSON, err := json.Marshal(rawPayload)
	if err != nil {
		return schema.Event{}, fmt.Errorf("falco: translate: marshal raw: %w", err)
	}

	return schema.Event{
		ID:        id,
		Timestamp: ts,
		Source:    schema.SourceFalco,
		Pod:       pod,
		Severity:  severityFromPriority(resp.GetPriority()),
		Category:  schema.CategorySyscall,
		Summary:   resp.GetOutput(),
		Raw:       rawJSON,
		Tags:      tags,
	}, nil
}

// stableEventID prefers Falco's own evt.uuid when present (Falco can be
// configured to emit one per syscall record). When absent, falls back
// to a 128-bit (32 hex char) SHA-256 prefix over fields that are
// stable for the same logical event across retries: time, proc.pid,
// proc.tid (when present), proc.exe, evt.num (Falco's monotonic event
// number, when present), and the rendered output. evt.num is the
// strongest deduplication input because it is unique per Falco event
// even when proc fields and output coincide; including it eliminates
// the realistic collision case the previous 64-bit truncation could
// produce within days at the architecture's per-source rates.
func stableEventID(resp *falcopb.Response) string {
	fields := resp.GetOutputFields()
	if uuid := fields["evt.uuid"]; uuid != "" {
		return uuid
	}
	h := sha256.New()
	if t := resp.GetTime(); t != nil {
		fmt.Fprintf(h, "%d.%d|", t.GetSeconds(), t.GetNanos())
	}
	fmt.Fprintf(h, "%s|", fields["evt.num"])
	fmt.Fprintf(h, "%s|", fields["proc.pid"])
	fmt.Fprintf(h, "%s|", fields["proc.tid"])
	fmt.Fprintf(h, "%s|", fields["proc.exe"])
	fmt.Fprintf(h, "%s", resp.GetOutput())
	sum := h.Sum(nil)
	return hex.EncodeToString(sum)[:32]
}

// canonicalPriorityName returns the uppercase canonical name for a
// Falco priority enum, looking the value up via the proto-generated
// name table rather than relying on `Priority.String()`. The Falco
// proto declares `option allow_alias = true` with three case variants
// (`EMERGENCY`, `emergency`, `Emergency`) per level; `String()` returns
// whichever the proto reflection chose at build time, which depends on
// declaration order and would break downstream string matchers if
// upstream re-orders the aliases. Using the explicit uppercase form
// keeps the contract pinned regardless of regeneration order. Unknown
// enum values fall back to a numeric form and trigger a one-shot warn
// so a Falco upgrade adding a new priority does not silently
// mis-attribute severity.
func canonicalPriorityName(p falcopb.Priority) string {
	switch p {
	case falcopb.Priority_EMERGENCY:
		return "EMERGENCY"
	case falcopb.Priority_ALERT:
		return "ALERT"
	case falcopb.Priority_CRITICAL:
		return "CRITICAL"
	case falcopb.Priority_ERROR:
		return "ERROR"
	case falcopb.Priority_WARNING:
		return "WARNING"
	case falcopb.Priority_NOTICE:
		return "NOTICE"
	case falcopb.Priority_INFORMATIONAL:
		return "INFORMATIONAL"
	case falcopb.Priority_DEBUG:
		return "DEBUG"
	default:
		unknownPriorityOnce.Do(func() {
			slog.Warn("falco: translate: unknown Falco priority enum, falling back to informational",
				"priority_int", int32(p))
		})
		return fmt.Sprintf("UNKNOWN(%d)", int32(p))
	}
}

// sortedFields returns a stable JSON-marshaller-friendly representation
// of output_fields. Go's encoding/json already sorts map[string]string
// keys alphabetically, but copying into a sorted slice of pairs makes
// the determinism explicit and survives any future encoder change.
// The returned shape is a slice of [key, value] pairs ordered by key
// so byte-level equality holds across repeated marshalling of the same
// input.
func sortedFields(fields map[string]string) [][2]string {
	if len(fields) == 0 {
		return [][2]string{}
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([][2]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, [2]string{k, fields[k]})
	}
	return out
}

// severityFromPriority maps Falco's priority enum to the project's
// severity vocabulary (lowercase, matches the canonical severity
// strings the rest of the pipeline already speaks). Unknown enum
// values fall through to "informational" rather than the zero-value
// "emergency" that would mis-attribute severity on a future Falco-side
// enum extension; the unknown-warn fires through canonicalPriorityName
// when it is called for the same Response.
func severityFromPriority(p falcopb.Priority) string {
	switch p {
	case falcopb.Priority_EMERGENCY:
		return "emergency"
	case falcopb.Priority_ALERT:
		return "alert"
	case falcopb.Priority_CRITICAL:
		return "critical"
	case falcopb.Priority_ERROR:
		return "error"
	case falcopb.Priority_WARNING:
		return "warning"
	case falcopb.Priority_NOTICE:
		return "notice"
	case falcopb.Priority_INFORMATIONAL:
		return "informational"
	case falcopb.Priority_DEBUG:
		return "debug"
	default:
		return "informational"
	}
}
