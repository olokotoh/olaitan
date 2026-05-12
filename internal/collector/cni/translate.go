// Package cni implements the Olaitan agent's Calico flow adapter.
//
// The adapter dials the Calico Goldmane gRPC API
// (`goldmane.Flows.Stream`) over mutual TLS, reads `FlowResult`
// messages, translates each into a canonical schema.Event of
// source=network / category=flow, and publishes to
// subjects.RawNetwork via the project's NATS client with JetStream
// at-least-once semantics.
//
// Flow record semantics. Goldmane aggregates Calico flow data over a
// configurable interval (15s minimum). Each FlowResult therefore
// represents a window of aggregated flow statistics, not a per-packet
// observation. Event.Timestamp records the START of that window, not
// per-packet wall-time; downstream consumers (the OLT Sigma rule
// engine in Story 1.15, the Welford baseline in Story 1.17) must
// account for the aggregation window when interpreting timestamp
// semantics.
//
// Workload identity. Goldmane's FlowKey.SourceName is a
// GenerateName-derived identifier ("a set of pods that share a
// GenerateName"), not a single pod name. The canonical Olaitan
// workload identity (namespace/owner-kind/owner-name) cannot be
// derived from a FlowKey alone; enrichment requires a K8s API
// lookup against the namespace and the set. The adapter populates
// Event.Pod from FlowKey verbatim and emits a
// "pod_name_kind:generatename" tag so the correlator (Story 1.14)
// can detect the GenerateName-derived identity and call the
// on-demand workload posture client (Story 1.11) at
// EvidencePackage assembly time. Doing the K8s API lookup inline
// would violate the read-on-demand posture pattern and break the
// NFR1 50 ms receive-to-publish budget.
//
// Source-health naming. The schema enum value is "network" (the
// abstract category, mirroring the five-source enum bootstrap in
// Story 1.6); the source-health gauge label is "calico" (the
// human-facing provider name an operator sees in Grafana). The
// asymmetry is intentional and documented in
// `docs/deferred-decisions.md` ADR-2026-04-30-01 -- a future reader
// should not "fix" it.
//
// mTLS cert reload. Goldmane enforces mTLS; the chart wires three
// TLS file paths to a Secret mount under /etc/olaitan/cni/. The
// adapter loads the TLS material from disk on every connect-loop
// iteration so cert-manager-driven Secret rotations are picked up
// without an adapter restart (Story 1.7 audit-webhook TLS reload
// pattern, adapted to a per-connect rather than per-handshake
// schedule because the gRPC client dials a fresh connection per
// connect-loop iteration).
//
// Watchdog quiet-by-design. Like Story 1.8 (containerd CRI) and
// Story 1.9 (applog), Goldmane flow records are quiet by design in
// a low-traffic cluster. A stable cluster with little east-west
// traffic produces no FlowResults for long stretches. The watchdog
// therefore must NOT flip unhealthy on staleness alone; only
// stale-AND-not-Ready trips the source. The inversion from Story
// 1.7's audit-webhook watchdog (which flips on stale-AND-no-recent-
// heartbeat because audit events are near-continuous on any
// non-trivial cluster) is documented in the watchdog's docstring.
package cni

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/olokotoh/olaitan/internal/collector/cni/goldmanepb"
	"github.com/olokotoh/olaitan/internal/schema"
)

// Errors returned by Translate. Wrapped via fmt.Errorf at call sites
// so errors.Is can detect them when callers need to branch on the
// failure mode (publishWithRetry treats ErrEventTooLarge as
// retry.Permanent so an oversize event is log+dropped rather than
// crashing the consume loop).
var (
	// ErrNilFlowResult is returned when the FlowResult, its inner
	// Flow, or the FlowKey is nil. Per the spike's defensive guard
	// at translate.go:22-24: a malformed FlowResult must produce a
	// wrapped error rather than panic.
	ErrNilFlowResult = errors.New("translate: nil flow result")

	// ErrInvalidTimestamp is returned when Flow.StartTime is zero,
	// before 2010-01-01 UTC, or more than 24 hours in the future
	// from now. Mirrors the Story 1.6 / 1.7 / 1.8 / 1.9 timestamp
	// guards: a misconfigured Goldmane (clock skew, NTP failure
	// during early boot) could emit a pre-epoch or far-future value
	// that would poison the downstream timestamp invariant.
	ErrInvalidTimestamp = errors.New("translate: invalid timestamp")

	// ErrEventTooLarge is returned when the marshalled schema.Event
	// exceeds the per-event size cap (MaxEventBytes). The caller
	// wraps via retry.Permanent so the consume loop log+drops the
	// event rather than wedging on an unmarshallable-for-JetStream
	// payload. Mirrors the Story 1.9 P22 MaxLineBytesAbsoluteCap
	// precedent.
	ErrEventTooLarge = errors.New("translate: event exceeds max bytes")
)

// DefaultMaxEventBytes caps a marshalled schema.Event at 192 KiB,
// leaving 64 KiB of envelope headroom under JetStream's 256 KiB
// MaxMsgSize ceiling. Lifted from Story 1.9 P22's
// MaxLineBytesAbsoluteCap rationale: the cap is sized so an honest
// flow record (a few hundred bytes) and even a pathological one
// with every optional field populated cannot accidentally exceed
// the stream-level invariant.
const DefaultMaxEventBytes = 192 * 1024

// maxSanitizedTagLen caps a single sanitised tag value. Mirrors
// applog.maxSanitizedTagLen / cri.maxSanitizedTagLen.
const maxSanitizedTagLen = 256

// minValidTimestamp is the earliest accepted Flow.StartTime,
// expressed as a Unix-second value (2010-01-01 UTC = 1262304000).
// Mirrors the Story 1.6 / 1.7 / 1.8 / 1.9 pre-epoch guards.
var minValidTimestamp = time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC).Unix()

// maxFutureSkew bounds how far ahead of the local clock a
// Flow.StartTime may be before Translate rejects it. 24 hours
// matches Story 1.6 / 1.7 / 1.8 / 1.9.
const maxFutureSkew = 24 * time.Hour

// protojsonOpts is package-level so the canonical-encoding allocation
// is not repeated per call. Story 1.6 review M7 precedent: anything
// reusable in a hot per-record path should be hoisted out of the
// function body.
var protojsonOpts = protojson.MarshalOptions{
	UseProtoNames:   true,
	EmitUnpopulated: false,
}

// nowFunc is package-level for test-time substitution of the wall
// clock when validating far-future timestamps. Production uses
// time.Now.
var nowFunc = time.Now

// Translate converts a Goldmane FlowResult into the canonical
// internal/schema.Event the rest of Olaitan consumes. The exported
// function is callable from the adapter's consume loop and from the
// translate_test.go unit tests in the test package. maxEventBytes
// caps the marshalled Event; pass 0 to use DefaultMaxEventBytes.
//
// Edge cases (each gets a unit test):
//
//   - fr == nil OR fr.Flow == nil OR fr.Flow.Key == nil -> ErrNilFlowResult.
//   - flow.StartTime == 0 OR before 2010-01-01 UTC -> ErrInvalidTimestamp.
//   - flow.StartTime > now + 24h -> ErrInvalidTimestamp.
//   - key.Proto == "" -> emit "proto:unknown" tag (defensive; flow
//     records always have a proto, but defence in depth).
//   - key.Action == Action_ActionUnspecified -> emit
//     "action:unspecified" tag, do not reject.
//   - key.DestPort == 0 -> emit "dst-port:0" tag (legal for ICMP).
//   - key.DestPort out of uint16 range -> emit "dst-port:invalid"
//     tag, retain the flow.
//   - empty key.SourceName / key.SourceNamespace -> emit empty PodRef
//     plus "unknown_source:true" tag (defensive; some Goldmane flows
//     carry network-set sources rather than workload sources).
//   - marshalled Event exceeds maxEventBytes -> ErrEventTooLarge.
//
// The function is pure: no I/O, no allocation beyond what
// protojson.Marshal and json.Marshal require.
func Translate(fr *goldmanepb.FlowResult, maxEventBytes int) (schema.Event, error) {
	if fr == nil || fr.GetFlow() == nil || fr.GetFlow().GetKey() == nil {
		return schema.Event{}, ErrNilFlowResult
	}
	flow := fr.GetFlow()
	key := flow.GetKey()

	if maxEventBytes <= 0 {
		maxEventBytes = DefaultMaxEventBytes
	}

	if err := validateTimestamp(flow.GetStartTime()); err != nil {
		return schema.Event{}, err
	}
	ts := time.Unix(flow.GetStartTime(), 0).UTC()

	id := fmt.Sprintf("calico-flow-%d-%d", flow.GetStartTime(), fr.GetId())

	rawBytes, err := protojsonOpts.Marshal(fr)
	if err != nil {
		return schema.Event{}, fmt.Errorf("translate: marshal raw: %w", err)
	}
	var rawObj map[string]any
	if err := json.Unmarshal(rawBytes, &rawObj); err != nil {
		return schema.Event{}, fmt.Errorf("translate: re-decode raw: %w", err)
	}
	canonRaw, err := json.Marshal(rawObj)
	if err != nil {
		return schema.Event{}, fmt.Errorf("translate: re-marshal raw: %w", err)
	}

	tags := buildTags(key, flow)

	srcNS := sanitizeForTag(key.GetSourceNamespace())
	srcName := sanitizeForTag(key.GetSourceName())
	dstNS := sanitizeForTag(key.GetDestNamespace())
	dstName := sanitizeForTag(key.GetDestName())

	summary := fmt.Sprintf("%s/%s -> %s/%s:%d (%s, %s, %s)",
		nonEmpty(srcNS, "-"),
		nonEmpty(srcName, "-"),
		nonEmpty(dstNS, "-"),
		nonEmpty(dstName, "-"),
		key.GetDestPort(),
		strings.ToLower(sanitizeForTag(key.GetProto())),
		actionString(key.GetAction()),
		reporterString(key.GetReporter()),
	)
	summary = sanitizeForTag(summary)

	ev := schema.Event{
		ID:        id,
		Timestamp: ts,
		Source:    schema.SourceNetwork,
		Pod: schema.PodRef{
			Name:      srcName,
			Namespace: srcNS,
		},
		Severity: "informational",
		Category: schema.CategoryFlow,
		Summary:  summary,
		Raw:      canonRaw,
		Tags:     tags,
	}

	// Size guard: the JetStream MaxMsgSize cap is the load-bearing
	// ceiling; this guard catches an Event whose marshalled form
	// would be log+dropped at publish time anyway, but lets the
	// adapter log+drop early via retry.Permanent at the translate
	// boundary so the consume loop never carries an unpublishable
	// payload past Translate.
	marshalled, mErr := json.Marshal(ev)
	if mErr != nil {
		return schema.Event{}, fmt.Errorf("translate: marshal event for size guard: %w", mErr)
	}
	if len(marshalled) > maxEventBytes {
		return schema.Event{}, fmt.Errorf("%w: %d bytes > %d cap", ErrEventTooLarge, len(marshalled), maxEventBytes)
	}

	return ev, nil
}

// validateTimestamp enforces the pre-2010 / far-future timestamp
// guard. The 2010 floor mirrors Stories 1.6 / 1.7 / 1.8 / 1.9; the
// 24h ceiling defends against clock skew on a misconfigured
// Goldmane (NTP failure during early boot, container clock not yet
// synced).
func validateTimestamp(startTime int64) error {
	if startTime <= 0 {
		return fmt.Errorf("%w: start_time=%d", ErrInvalidTimestamp, startTime)
	}
	if startTime < minValidTimestamp {
		return fmt.Errorf("%w: start_time=%d before 2010-01-01 UTC", ErrInvalidTimestamp, startTime)
	}
	skew := time.Unix(startTime, 0).Sub(nowFunc())
	if skew > maxFutureSkew {
		return fmt.Errorf("%w: start_time=%d is %s in the future", ErrInvalidTimestamp, startTime, skew)
	}
	return nil
}

// buildTags returns the deterministic tag set for a FlowResult.
// Lifted from the spike's buildTags with three additions:
//   - "pod_name_kind:generatename" so the correlator (Story 1.14)
//     can detect the GenerateName-derived FlowKey.source_name and
//     drive K8s API enrichment via the posture client (Story 1.11).
//   - "unknown_source:true" when both SourceName and
//     SourceNamespace are empty (Goldmane network-set / network
//     EndpointType case).
//   - "dst-port:invalid" when the port falls outside the uint16
//     range (defensive: the proto declares int64 for DestPort).
//
// Each sanitised value passes through sanitizeForTag to strip
// control characters and cap length, defending against a hostile
// or merely malformed FlowKey.
func buildTags(key *goldmanepb.FlowKey, flow *goldmanepb.Flow) []string {
	proto := sanitizeForTag(strings.ToLower(key.GetProto()))
	if proto == "" {
		proto = "unknown"
	}
	tags := []string{
		"proto:" + proto,
		"action:" + actionString(key.GetAction()),
		"reporter:" + reporterString(key.GetReporter()),
		"src-type:" + endpointTypeString(key.GetSourceType()),
		"dst-type:" + endpointTypeString(key.GetDestType()),
		"dst-port:" + destPortTag(key.GetDestPort()),
		// Story 1.10 guardrail 19: the FR13 GenerateName-derived
		// FlowKey.source_name escape hatch. Story 1.14 reads this
		// tag to trigger K8s API enrichment via Story 1.11.
		"pod_name_kind:generatename",
	}
	if key.GetSourceName() == "" && key.GetSourceNamespace() == "" {
		tags = append(tags, "unknown_source:true")
	}
	if svc := sanitizeForTag(key.GetDestServiceName()); svc != "" {
		ns := sanitizeForTag(key.GetDestServiceNamespace())
		tags = append(tags, "svc:"+ns+"/"+svc)
	}
	if cs := flow.GetNumConnectionsStarted(); cs > 0 {
		tags = append(tags, "conns-started:"+strconv.FormatInt(cs, 10))
	}
	return tags
}

// destPortTag returns the tag-suffix for FlowKey.DestPort.
// uint16 range (0-65535) is the IANA-port universe; anything else
// is a malformed FlowResult (the proto declares int64 but a port
// > 65535 violates the network-layer invariant). Defensive
// "invalid" tag retains the flow rather than dropping it.
func destPortTag(p int64) string {
	if p < 0 || p > 65535 {
		return "invalid"
	}
	return strconv.FormatInt(p, 10)
}

// actionString maps the Goldmane Action enum to the stable
// tag-suffix string. The mapping is canonical; downstream Sigma
// rules pattern-match on these literals. Action_ActionUnspecified
// produces "unspecified" (rather than rejecting the flow) so
// transitional Goldmane releases that introduce a new action
// variant degrade gracefully.
func actionString(a goldmanepb.Action) string {
	switch a {
	case goldmanepb.Action_Allow:
		return "allow"
	case goldmanepb.Action_Deny:
		return "deny"
	case goldmanepb.Action_Pass:
		return "pass"
	default:
		return "unspecified"
	}
}

// reporterString maps the Goldmane Reporter enum to the stable
// tag-suffix string. "src" or "dst" indicates which side of the
// flow Calico observed; "unspecified" is the default fallback.
func reporterString(r goldmanepb.Reporter) string {
	switch r {
	case goldmanepb.Reporter_Src:
		return "src"
	case goldmanepb.Reporter_Dst:
		return "dst"
	default:
		return "unspecified"
	}
}

// endpointTypeString maps the Goldmane EndpointType enum to the
// stable tag-suffix string. The four valid variants are
// "workload", "host", "networkset", and "network"; anything else
// degrades to "unspecified".
func endpointTypeString(t goldmanepb.EndpointType) string {
	switch t {
	case goldmanepb.EndpointType_WorkloadEndpoint:
		return "workload"
	case goldmanepb.EndpointType_HostEndpoint:
		return "host"
	case goldmanepb.EndpointType_NetworkSet:
		return "networkset"
	case goldmanepb.EndpointType_Network:
		return "network"
	default:
		return "unspecified"
	}
}

// nonEmpty returns s when non-empty, otherwise fallback. Mirrors
// the spike's nonEmpty helper.
func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// sanitizeForTag strips control characters (tab is preserved) and
// caps the result at maxSanitizedTagLen bytes. Mirrors
// applog.sanitizeForTag exactly so all five adapters apply the
// same defence-in-depth tag-sanitisation contract.
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
