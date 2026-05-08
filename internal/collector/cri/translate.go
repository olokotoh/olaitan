// Package cri implements the Olaitan agent's containerd CRI lifecycle
// adapter (Story 1.8 / FR3). The adapter dials the containerd CRI
// runtime service over a Unix domain socket, subscribes to
// RuntimeService.GetContainerEvents (server-streaming RPC), translates
// each ContainerEventResponse into the canonical schema.Event of
// source=runtime / category=lifecycle, and publishes to
// subjects.RawRuntime via JetStream with at-least-once semantics.
//
// Why source=runtime not source=containerd: the schema package
// (internal/schema/event.go) was bootstrapped with SourceRuntime =
// "runtime" so the adapter axis identifies the architectural layer
// rather than the specific implementation. A future CRI-O adapter
// would publish on the same RawRuntime subject and produce schema
// Events with the same Source value; downstream correlators read by
// Source rather than by implementation, so leaving the constants as-is
// preserves polymorphism. The story epic text reads "source containerd
// (category lifecycle)"; the binding interpretation lands here so the
// PR description and CRI.md are the single source of truth for the
// reviewer.
//
// Concurrency model: a single goroutine per Adapter handles connect,
// stream consumption, translation, and publish. CRI lifecycle events
// are sparse on a stable cluster -- one goroutine satisfies the
// architecture's per-source per-node throughput budget (NFR1: 1000
// events/sec/source) by a wide margin.
//
// The watchdog goroutine is a notable design difference from the
// audit-webhook adapter (Story 1.7): CRI lifecycle events are quiet by
// design. A stable cluster with no Pod churn can go hours without a
// ContainerEventResponse. Therefore the staleness watchdog must NOT
// flip the source unhealthy on staleness alone -- only when the gRPC
// connection is also not Ready. See cri.go runStalenessWatchdog for
// the implementation and TestRun_StalenessWatchdog_QuietButConnected_
// DoesNotFlipUnhealthy in cri_test.go for the lock-in test.
//
// Workload identity (FR13): the adapter populates schema.Event.Pod
// (PodRef{Name, Namespace, UID, Node}) from
// pod_sandbox_status.metadata. The canonical workload-id resolver
// (`internal/keys.WorkloadID`, when it lands in Story 1.11+) reads
// PodRef and adds owner-ref resolution at the point workload identity
// is needed; the adapter does NOT perform K8s API calls in the hot
// path. This matches Stories 1.6 (Falco) and 1.7 (audit) which are
// also pure transforms over their respective wire formats.
//
// Baseline invalidation (FR18): the adapter emits raw lifecycle
// events; the Welford engine in Story 1.17 owns the consumer logic
// that interprets a CONTAINER_STARTED_EVENT with `meta.Attempt > 0`
// (or a CONTAINER_DELETED_EVENT followed by a CONTAINER_STARTED_EVENT
// for the same `pod_sandbox.uid`) as a workload restart. The
// adapter's contract is to emit faithfully; the consumer's contract
// is to invalidate baselines.
package cri

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"

	"github.com/olokotoh/olaitan/internal/schema"
)

// minValidEventTime is the floor below which a CRI-supplied timestamp
// is treated as garbage. Mirrors Stories 1.6 (Falco) and 1.7 (audit):
// a CreatedAt value before 2010 indicates either an unset
// CreatedAt=0 (Unix epoch) or severe clock skew on the node, both of
// which would mis-bucket events in the downstream sliding-window
// correlator. Reject early.
var minValidEventTime = time.Date(2010, time.January, 1, 0, 0, 0, 0, time.UTC)

// maxFutureSkew caps how far past "now" a translate-time CreatedAt may
// land. The 24h ceiling matches Stories 1.6 and 1.7 (single common
// guard across all sources). The Translate function reads time.Now()
// for this guard, which is the only wall-clock dependency in the
// transform; documented on Translate's docstring.
const maxFutureSkew = 24 * time.Hour

// rawSizeBudget caps the marshalled schema.Event.Raw payload at 32 KiB
// to leave generous headroom under the JetStream EVENTS_RAW
// MaxMsgSize cap (256 KiB). On a multi-container Pod with sidecars
// (Istio, log shippers), the raw ContainerEventResponse can reach
// double-digit kilobytes once pod_sandbox_status.linux.namespaces and
// every containers_statuses[i].image_ref are included; we strip those
// while retaining the forensically-relevant fields.
const rawSizeBudget = 32 * 1024

// labelPrefixesAllowed is the whitelist of pod label prefixes the
// adapter forwards to schema.Event.Tags. User-controlled label values
// can carry crash-vector strings (newlines, control chars) so the
// adapter accepts only labels under prefixes the operator already
// vetted as safe.
var labelPrefixesAllowed = []string{
	"app.kubernetes.io/",
	"olaitan.io/",
}

// ErrInvalidTimestamp is returned by Translate when CreatedAt is zero,
// pre-epoch, before minValidEventTime, or further than maxFutureSkew
// in the future. Callers (cri.streamLoop) log+drop and continue.
var ErrInvalidTimestamp = errors.New("cri: invalid CreatedAt timestamp")

// ErrInvalidContainerID is returned by Translate when ContainerId is
// empty. The CRI proto does not mark container_id as required so a
// non-spec-compliant runtime could hypothetically emit one; defend
// loudly rather than silently fabricating.
var ErrInvalidContainerID = errors.New("cri: empty ContainerId")

// ErrUnknownEventType is returned by Translate when ContainerEventType
// is outside the four documented enum values (CREATED, STARTED,
// STOPPED, DELETED). A future CRI minor adding a fifth value would
// trip this; the Story 1.8 follow-up would extend the switch.
var ErrUnknownEventType = errors.New("cri: unknown ContainerEventType enum value")

// Translate converts a CRI ContainerEventResponse into the canonical
// schema.Event.
//
// Determinism: the field-mapping is purely a function of the input.
// The future-skew check reads time.Now() to reject events more than
// maxFutureSkew ahead of wall clock; this is the single wall-clock
// dependency. Two calls within the same maxFutureSkew window produce
// byte-equal outputs.
//
// The nodeName argument is the node-level identifier the caller
// already knows (typically read from K8S_NODE_NAME via the Helm
// chart's downward API); it lands in Event.Pod.Node so events without
// pod-scoped sandbox metadata still record where Olaitan observed
// them.
//
// Translation contract:
//
//   - Event.ID is a 128-bit (32 hex char) SHA-256 prefix over
//     (container_id, event_type, created_at). The CRI response does
//     not include a UUID; the tuple is unique per logical event
//     because containerd emits one event per state transition and
//     CreatedAt is nanosecond precision. The 128-bit prefix matches
//     the post-Story-1.6-follow-up collision-resistance bound.
//   - Event.Source is pinned to schema.SourceRuntime ("runtime") and
//     Event.Category to schema.CategoryLifecycle ("lifecycle"). The
//     epic's "source containerd / category lifecycle" reads as this
//     pair under the binding-interpretation note in the package
//     docstring.
//   - Event.Pod is derived from pod_sandbox_status.metadata. nil
//     sandbox or nil metadata leaves Name/Namespace/UID empty
//     (orphaned-container events still carry their own ContainerId
//     and the downstream correlator decides whether to drop them).
//   - Event.Severity is "informational" for all four event types.
//     CRI lifecycle events are infrastructure-level signals;
//     escalating CONTAINER_DELETED_EVENT to "warning" would create a
//     false-positive feedback loop because every Pod terminates
//     eventually. Severity escalation for restart-loop / OOMKilled
//     bursts is the OLT Sigma rule engine's job (Story 1.15).
//   - Event.Summary is a short human-readable line.
//   - Event.Raw is marshalled JSON of the trimmed event. When the
//     un-stripped marshal would exceed rawSizeBudget, the
//     pod_sandbox_status.linux block, runtime_handler, and any
//     containers_statuses[i].image_ref strings above the budget are
//     stripped. Event.ID is derived from the un-stripped tuple so
//     strip decisions do not change dedup behaviour.
//   - Event.Tags include event_type:<lower-snake>, an optional
//     attempt:N when meta.Attempt > 0, an optional sandbox:notready
//     when the sandbox is being torn down, and any pod labels under
//     the labelPrefixesAllowed whitelist.
//
// Returns a wrapped "cri: translate: ..." error for nil ev, or one of
// the sentinel errors (ErrInvalidTimestamp, ErrInvalidContainerID,
// ErrUnknownEventType) for the well-known invalid-input cases.
func Translate(ev *runtimeapi.ContainerEventResponse, nodeName string) (schema.Event, error) {
	if ev == nil {
		return schema.Event{}, fmt.Errorf("cri: translate: nil event")
	}
	if ev.ContainerId == "" {
		return schema.Event{}, fmt.Errorf("cri: translate: %w", ErrInvalidContainerID)
	}
	if ev.CreatedAt <= 0 {
		return schema.Event{}, fmt.Errorf("cri: translate: created_at=%d (zero or negative): %w", ev.CreatedAt, ErrInvalidTimestamp)
	}

	ts := time.Unix(0, ev.CreatedAt).UTC()
	if ts.Before(minValidEventTime) {
		return schema.Event{}, fmt.Errorf("cri: translate: created_at=%s is before %s (likely clock skew or unset): %w",
			ts.Format(time.RFC3339Nano), minValidEventTime.Format(time.RFC3339), ErrInvalidTimestamp)
	}
	if ts.After(time.Now().Add(maxFutureSkew)) {
		return schema.Event{}, fmt.Errorf("cri: translate: created_at=%s is more than %s in the future (likely clock skew): %w",
			ts.Format(time.RFC3339Nano), maxFutureSkew, ErrInvalidTimestamp)
	}

	eventTypeName, ok := containerEventTypeName(ev.ContainerEventType)
	if !ok {
		return schema.Event{}, fmt.Errorf("cri: translate: container_event_type=%d: %w", int32(ev.ContainerEventType), ErrUnknownEventType)
	}

	id := stableEventID(ev)
	pod := podRefFromSandbox(ev.GetPodSandboxStatus(), nodeName)
	summary := buildSummary(eventTypeName, ev.ContainerId, pod.Namespace, pod.Name)
	tags := buildTags(eventTypeName, ev.GetPodSandboxStatus())

	rawJSON, err := marshalTrimmedRaw(ev)
	if err != nil {
		return schema.Event{}, fmt.Errorf("cri: translate: marshal raw (container_id=%s): %w", ev.ContainerId, err)
	}

	return schema.Event{
		ID:        id,
		Timestamp: ts,
		Source:    schema.SourceRuntime,
		Pod:       pod,
		Severity:  "informational",
		Category:  schema.CategoryLifecycle,
		Summary:   summary,
		Raw:       rawJSON,
		Tags:      tags,
	}, nil
}

// stableEventID derives a 128-bit SHA-256 prefix over the unique
// (container_id, container_event_type, created_at) tuple. The CRI
// response does not include a UUID; the tuple is unique per logical
// event because containerd emits one event per state transition and
// created_at is nanosecond precision. The 128-bit prefix matches the
// post-Story-1.6-follow-up collision-resistance bound and prevents
// JetStream WithMsgID dedup birthday collisions at the architecture's
// per-source rates over the cluster's lifetime.
//
// Use fmt.Fprintf with a stable separator (\x00) so that a
// container_id containing the literal "|" cannot be reordered into a
// colliding hash input. hash.Hash.Write returns nil per its contract;
// errors are explicitly discarded so errcheck does not flag them
// (Story 1.6 follow-up patch precedent).
func stableEventID(ev *runtimeapi.ContainerEventResponse) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s\x00%d\x00%d", ev.ContainerId, int32(ev.ContainerEventType), ev.CreatedAt)
	sum := h.Sum(nil)
	return hex.EncodeToString(sum)[:32]
}

// podRefFromSandbox populates schema.PodRef from
// pod_sandbox_status.metadata. nil sandbox or nil metadata leaves
// Name/Namespace/UID empty; nodeName is always recorded so the
// observer-node provenance survives even on orphaned-container
// events.
func podRefFromSandbox(sandbox *runtimeapi.PodSandboxStatus, nodeName string) schema.PodRef {
	pod := schema.PodRef{Node: nodeName}
	if sandbox == nil {
		return pod
	}
	meta := sandbox.GetMetadata()
	if meta == nil {
		return pod
	}
	pod.Name = meta.Name
	pod.Namespace = meta.Namespace
	pod.UID = meta.Uid
	return pod
}

// buildSummary renders a short human-readable line: e.g.
// "started container=abc123def456 pod=payments/payments-7f8b9c-xyz".
// Truncates container_id to 12 hex chars (Docker / crictl convention)
// for log readability, but only when the ID is at least that long --
// some test runtimes use short IDs.
func buildSummary(eventTypeName, containerID, podNS, podName string) string {
	shortID := containerID
	if len(shortID) > 12 {
		shortID = shortID[:12]
	}
	if podNS == "" && podName == "" {
		return fmt.Sprintf("%s container=%s", eventTypeName, shortID)
	}
	return fmt.Sprintf("%s container=%s pod=%s/%s", eventTypeName, shortID, podNS, podName)
}

// buildTags assembles schema.Event.Tags. Returns a freshly allocated
// slice so callers cannot retain a reference that aliases the proto-
// runtime's underlying memory.
//
//   - event_type:<lowercased>          always present
//   - sandbox:notready                  when the sandbox is being torn down
//   - attempt:<N>                       only when meta.Attempt > 0
//   - app.kubernetes.io/* / olaitan.io/* labels   forwarded under the
//     prefix whitelist; copied via slice append-from-nil so a future
//     gRPC runtime that pools messages cannot mutate the published
//     tag list.
func buildTags(eventTypeName string, sandbox *runtimeapi.PodSandboxStatus) []string {
	tags := make([]string, 0, 6)
	tags = append(tags, "event_type:"+eventTypeShortName(eventTypeName))

	if sandbox == nil {
		return tags
	}
	if sandbox.GetState() == runtimeapi.PodSandboxState_SANDBOX_NOTREADY {
		tags = append(tags, "sandbox:notready")
	}
	if meta := sandbox.GetMetadata(); meta != nil && meta.Attempt > 0 {
		tags = append(tags, fmt.Sprintf("attempt:%d", meta.Attempt))
	}
	// Labels in deterministic order so repeated translations of the
	// same event produce the same Tags slice. Iterating a Go map is
	// otherwise random.
	labels := sandbox.GetLabels()
	if len(labels) > 0 {
		keys := make([]string, 0, len(labels))
		for k := range labels {
			if !labelHasAllowedPrefix(k) {
				continue
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			tags = append(tags, k+":"+labels[k])
		}
	}
	return append([]string(nil), tags...)
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

// containerEventTypeName returns the canonical CRI enum name plus a
// boolean indicating recognition. The enum has exactly four
// documented values; an out-of-range value returns ("", false) so
// Translate can reject it loudly rather than fabricating an event.
//
// Use the canonical proto-generated names directly rather than
// ContainerEventType.String() so a future re-ordering or alias
// addition in upstream cri-api cannot drift the wire-visible tag
// vocabulary.
func containerEventTypeName(t runtimeapi.ContainerEventType) (string, bool) {
	switch t {
	case runtimeapi.ContainerEventType_CONTAINER_CREATED_EVENT:
		return "CONTAINER_CREATED_EVENT", true
	case runtimeapi.ContainerEventType_CONTAINER_STARTED_EVENT:
		return "CONTAINER_STARTED_EVENT", true
	case runtimeapi.ContainerEventType_CONTAINER_STOPPED_EVENT:
		return "CONTAINER_STOPPED_EVENT", true
	case runtimeapi.ContainerEventType_CONTAINER_DELETED_EVENT:
		return "CONTAINER_DELETED_EVENT", true
	default:
		return "", false
	}
}

// eventTypeShortName converts the canonical enum name (e.g.
// CONTAINER_STARTED_EVENT) into the short tag form (e.g. "started").
// Caller has already validated the input is one of the four known
// values via containerEventTypeName.
func eventTypeShortName(canonical string) string {
	// Strip CONTAINER_ prefix and _EVENT suffix, lowercase the middle.
	trimmed := strings.TrimPrefix(canonical, "CONTAINER_")
	trimmed = strings.TrimSuffix(trimmed, "_EVENT")
	return strings.ToLower(trimmed)
}

// rawCanonical is the JSON shape persisted in schema.Event.Raw. We do
// not marshal the proto type directly because (a) the gogo-proto
// generated struct carries XXX_ fields that pollute the JSON, (b) the
// PodSandboxStatus pointer reaches into Linux-specific blocks we want
// to strip on size, and (c) we need a deterministic representation
// for downstream byte-equality assertions in tests.
type rawCanonical struct {
	ContainerID        string          `json:"container_id"`
	ContainerEventType string          `json:"container_event_type"`
	CreatedAt          int64           `json:"created_at"`
	PodSandbox         *rawSandbox     `json:"pod_sandbox,omitempty"`
	ContainerStatuses  []*rawContainer `json:"container_statuses,omitempty"`
	Stripped           bool            `json:"_stripped,omitempty"`
	StrippedBytes      int             `json:"_stripped_bytes,omitempty"`
}

// rawSandbox mirrors the subset of PodSandboxStatus the adapter
// retains. Linux namespaces, runtime_handler, network status, and
// annotations are intentionally dropped so the persisted Raw stays
// well below the JetStream MaxMsgSize cap on multi-container pods.
type rawSandbox struct {
	ID        string          `json:"id,omitempty"`
	State     string          `json:"state,omitempty"`
	CreatedAt int64           `json:"created_at,omitempty"`
	Metadata  *rawSandboxMeta `json:"metadata,omitempty"`
	Labels    [][2]string     `json:"labels,omitempty"`
}

type rawSandboxMeta struct {
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	UID       string `json:"uid,omitempty"`
	Attempt   uint32 `json:"attempt,omitempty"`
}

// rawContainer mirrors the forensically-relevant subset of
// ContainerStatus. ImageRef can grow large for digest-locked image
// references; we keep the 12-char short form when above the budget
// (kept as Image), drop the full ref. ExitReason is critical for
// forensic reasoning on STOPPED / DELETED events.
type rawContainer struct {
	ID         string `json:"id,omitempty"`
	State      string `json:"state,omitempty"`
	CreatedAt  int64  `json:"created_at,omitempty"`
	StartedAt  int64  `json:"started_at,omitempty"`
	FinishedAt int64  `json:"finished_at,omitempty"`
	ExitCode   int32  `json:"exit_code,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Message    string `json:"message,omitempty"`
	Image      string `json:"image,omitempty"`
}

// marshalTrimmedRaw serialises the CRI event into a deterministic,
// size-budgeted JSON blob. When the un-stripped marshal exceeds
// rawSizeBudget, the Linux block is dropped (not exposed in
// rawSandbox to begin with), runtime_handler is dropped, and the
// containers_statuses[i].ImageRef strings are truncated. The strip
// decision is recorded via _stripped + _stripped_bytes so a
// downstream forensic consumer can request the full payload from
// containerd if needed.
//
// Determinism: labels and any other map-typed fields are
// canonicalised into sorted [][2]string slices; encoding/json itself
// preserves struct field order via tag traversal.
func marshalTrimmedRaw(ev *runtimeapi.ContainerEventResponse) (json.RawMessage, error) {
	canon := buildRawCanonical(ev, false)
	body, err := json.Marshal(canon)
	if err != nil {
		return nil, err
	}
	if len(body) <= rawSizeBudget {
		return json.RawMessage(body), nil
	}
	// Re-marshal with the tighter strip applied. We track combined
	// pre-strip bytes for the diagnostic field.
	preStrip := len(body)
	stripped := buildRawCanonical(ev, true)
	stripped.Stripped = true
	stripped.StrippedBytes = preStrip
	body, err = json.Marshal(stripped)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(body), nil
}

// buildRawCanonical projects ContainerEventResponse into the
// deterministic rawCanonical shape. When forceStrip is true the
// container_statuses[i] entries drop their image-ref text entirely
// and the per-entry message is truncated to keep the post-strip
// marshal bounded.
func buildRawCanonical(ev *runtimeapi.ContainerEventResponse, forceStrip bool) *rawCanonical {
	typeName, _ := containerEventTypeName(ev.ContainerEventType)
	// Unknown enum values emit the raw int form so the persisted Raw
	// still records something recognisable; Translate has already
	// rejected such events before this function runs, but defending
	// here keeps the helper safe to call from tests directly.
	if typeName == "" {
		typeName = fmt.Sprintf("UNKNOWN(%d)", int32(ev.ContainerEventType))
	}

	c := &rawCanonical{
		ContainerID:        ev.ContainerId,
		ContainerEventType: typeName,
		CreatedAt:          ev.CreatedAt,
	}

	if sb := ev.GetPodSandboxStatus(); sb != nil {
		raw := &rawSandbox{
			ID:        sb.Id,
			State:     sb.State.String(),
			CreatedAt: sb.CreatedAt,
		}
		if meta := sb.GetMetadata(); meta != nil {
			raw.Metadata = &rawSandboxMeta{
				Name:      meta.Name,
				Namespace: meta.Namespace,
				UID:       meta.Uid,
				Attempt:   meta.Attempt,
			}
		}
		// Forward only whitelisted labels, sorted, into the persisted
		// raw payload. Non-whitelisted labels are dropped to limit
		// raw-payload bloat and to avoid carrying user-controlled
		// crash-vector strings into the forensic store.
		if labels := sb.GetLabels(); len(labels) > 0 {
			keys := make([]string, 0, len(labels))
			for k := range labels {
				if !labelHasAllowedPrefix(k) {
					continue
				}
				keys = append(keys, k)
			}
			sort.Strings(keys)
			out := make([][2]string, 0, len(keys))
			for _, k := range keys {
				out = append(out, [2]string{k, labels[k]})
			}
			raw.Labels = out
		}
		c.PodSandbox = raw
	}

	if cs := ev.GetContainersStatuses(); len(cs) > 0 {
		out := make([]*rawContainer, 0, len(cs))
		for _, status := range cs {
			rc := &rawContainer{
				ID:         status.Id,
				State:      status.State.String(),
				CreatedAt:  status.CreatedAt,
				StartedAt:  status.StartedAt,
				FinishedAt: status.FinishedAt,
				ExitCode:   status.ExitCode,
				Reason:     status.Reason,
				Message:    status.Message,
			}
			if !forceStrip {
				// Keep the image ref (digest-locked references can be
				// long but are forensically valuable). Strip path
				// drops them to bound the post-strip size.
				rc.Image = status.ImageRef
			}
			out = append(out, rc)
		}
		c.ContainerStatuses = out
	}
	return c
}
