package baseline

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"

	"github.com/olokotoh/olaitan/internal/schema"
)

// The five default metric names. They are the Redis hash field prefixes
// (baseline:<ns>:<workload>:metrics), the {metric} label on
// olaitan_decision_baseline_deviations_total and the BaselineDeviation.Metric
// value, so they are kept stable even where Story 10.12 changed what they
// measure (see the per-metric comments below and docs/runbook.md).
const (
	MetricOutboundUniqueDst  = "outbound_unique_dst_ips"
	MetricDistinctExecPaths  = "distinct_exec_paths"
	MetricOutboundBytes      = "outbound_bytes"
	MetricAuditEventsPerMin  = "audit_events_per_min"
	MetricRestartsPerHour    = "container_restarts_per_hour"
	selfActorPrefixSA        = "system:serviceaccount:"
	falcoNotAvailable        = "<NA>"
	reporterTagSrc           = "reporter:src"
	reporterTagDst           = "reporter:dst"
	restartTagSandboxAttempt = "attempt:"
	// restartTagContainerAttempt is emitted by the CRI adapter (Story
	// 10.12) from the event's own ContainerStatus.Metadata.Attempt, so an
	// in-place container restart (CrashLoopBackOff) is visible. The
	// sandbox "attempt:" tag only changes when the whole sandbox is
	// recreated.
	restartTagContainerAttempt = "container_attempt:"
)

// metricNames lists the canonical names of the five default metrics.
// The engine iterates this slice so per-bucket emission order is
// deterministic across runs.
var metricNames = []string{
	MetricOutboundUniqueDst,
	MetricDistinctExecPaths,
	MetricOutboundBytes,
	MetricAuditEventsPerMin,
	MetricRestartsPerHour,
}

// MetricNames returns a copy of the five default metric names in the
// canonical iteration order.
func MetricNames() []string {
	out := make([]string, len(metricNames))
	copy(out, metricNames)
	return out
}

// metricSource is the event source whose liveness gates sampling of a
// metric (Story 10.12 D2): a metric is sampled for a workload only once
// its source has been seen from any workload since the engine started,
// so a cluster without, for example, Calico Goldmane does not teach
// every workload a meaningless constant-zero flow baseline.
var metricSource = map[string]schema.EventSource{
	MetricOutboundUniqueDst: schema.SourceNetwork,
	MetricDistinctExecPaths: schema.SourceFalco,
	MetricOutboundBytes:     schema.SourceNetwork,
	MetricAuditEventsPerMin: schema.SourceAudit,
	MetricRestartsPerHour:   schema.SourceRuntime,
}

// stdFloor is the absolute standard-deviation floor per metric (Story
// 10.12 D4): the smallest change that counts as one sigma. Without it a
// perfectly steady workload (std near zero) turns a +1 change into a huge
// sigma. Counts use 1 (so at least +3 at the default 3 sigma), API calls
// 2 (at least +6: an operator's kubectl describe or logs on a quiet pod is
// a handful of calls, Story 10.12 review); bytes per minute use 1 KiB.
var stdFloor = map[string]float64{
	MetricOutboundUniqueDst: 1,
	MetricDistinctExecPaths: 1,
	MetricOutboundBytes:     1024,
	MetricAuditEventsPerMin: 2,
	MetricRestartsPerHour:   1,
}

// relStdFloor scales the floor with the mean so a high-volume steady
// metric needs a change of at least 30% of its mean (3 x 10%) to fire.
const relStdFloor = 0.10

// effectiveStdDev applies the absolute and relative floors to the
// observed standard deviation.
func effectiveStdDev(metric string, std, mean float64) float64 {
	eff := std
	if f := stdFloor[metric]; f > eff {
		eff = f
	}
	if r := relStdFloor * math.Abs(mean); r > eff {
		eff = r
	}
	return eff
}

// decodeRaw unmarshals ev.Raw into a generic map. nil on empty or
// malformed input.
func decodeRaw(ev *schema.Event) map[string]any {
	if len(ev.Raw) == 0 {
		return nil
	}
	var raw map[string]any
	if err := json.Unmarshal(ev.Raw, &raw); err != nil {
		return nil
	}
	return raw
}

// lookupRaw returns the first candidate present in raw. Each candidate is
// tried, in order, as (1) a literal top-level key, which is how the OLT
// canonical projection is written ("process.exe", "network.bytes_out" are
// flat keys with dots in them, Story 10.3 and Story 11.2b), (2) a nested
// dotted path ("flow.Key.dest_name", main's protojson CNI shape), and
// (3) a key of the Falco output_fields [[key, value], ...] pairs
// ("proc.exepath"). There is no leaf-token fallback: an ambiguous suffix
// match is how the pre-10.12 lookup could read the wrong field.
func lookupRaw(raw map[string]any, candidates ...string) (any, bool) {
	if raw == nil {
		return nil, false
	}
	for _, c := range candidates {
		if v, ok := raw[c]; ok && v != nil {
			return v, true
		}
		if strings.Contains(c, ".") {
			if v, ok := walkPath(raw, strings.Split(c, ".")); ok && v != nil {
				return v, true
			}
		}
		if of, ok := raw["output_fields"]; ok {
			if v, ok := lookupOutputFieldsPair(of, c); ok {
				return v, true
			}
		}
	}
	return nil, false
}

// lookupString is lookupRaw restricted to non-empty, non-"<NA>" strings.
// A candidate that is present but empty or "<NA>" (Falco's marker for an
// unavailable field) does not stop the search: the next candidate is
// tried.
func lookupString(raw map[string]any, candidates ...string) string {
	for _, c := range candidates {
		v, ok := lookupRaw(raw, c)
		if !ok {
			continue
		}
		if s := stringOf(v); s != "" && s != falcoNotAvailable {
			return s
		}
	}
	return ""
}

// execPath returns the executable path a Falco event names, or "".
//
// Order (Story 10.12 B4): the flat canonical "process.exe", which the
// Falco adapter projects from proc.exepath then proc.exe
// (internal/collector/falco/translate.go canonicalFieldSources); then the
// raw output_fields "proc.exepath" (what most Falco rules print) and
// "proc.exe". proc.name is deliberately NOT a fallback: it is a
// 15-character comm, not a path, so "/bin/sh" and "/tmp/sh" would
// collapse, and a path-bearing and a name-only event for the same binary
// would count as two distinct executables.
func execPath(raw map[string]any) string {
	return lookupString(raw, "process.exe", "proc.exepath", "proc.exe")
}

// flowReportedByDestination reports whether a CNI flow event is the
// destination-side report of a flow. Goldmane reports every in-cluster
// flow twice, once per reporter, with bytes_in and bytes_out swapped
// (verified on the 2026-10-19 S4 flows). Only the source-side report
// describes the workload's OUTBOUND traffic. The reporter is read from
// the adapter's "reporter:" tag, then the flat "network.reporter" (Story
// 11.2b, which also sets network.bytes_out on the Src record only), then
// the nested flow.Key.reporter. A
// flow whose reporter is unknown is kept (it cannot be shown to be a
// duplicate).
func flowReportedByDestination(ev *schema.Event, raw map[string]any) bool {
	for _, t := range ev.Tags {
		switch t {
		case reporterTagDst:
			return true
		case reporterTagSrc:
			return false
		}
	}
	return strings.EqualFold(lookupString(raw, "network.reporter", "flow.Key.reporter"), "dst")
}

// flowDestination returns a stable identity for a flow's destination
// endpoint, or "". Goldmane carries no destination IP, so the identity is
// type/namespace/name:port: the flat Story 11.2b projection first
// ("network.dest_type", "network.dest_name", "network.dst_port"), then
// main's nested protojson (flow.Key.*). A canonical "network.dst_ip"
// (or a legacy top-level "dst_ip") stands in for the name when an adapter
// supplies one.
func flowDestination(raw map[string]any) string {
	name := lookupString(raw, "network.dest_name", "flow.Key.dest_name", "network.dst_ip", "dst_ip")
	if name == "" {
		return ""
	}
	typ := lookupString(raw, "network.dest_type", "flow.Key.dest_type")
	ns := lookupString(raw, "network.dest_namespace", "flow.Key.dest_namespace")
	port := lookupString(raw, "network.dst_port", "flow.Key.dest_port")
	return strings.ToLower(typ) + "/" + ns + "/" + name + ":" + port
}

// flowBytesOut returns the bytes the source sent in a flow record:
// "network.bytes_out" (Story 11.2b flat projection), then main's nested
// flow.bytes_out, then a legacy top-level bytes_out. Negative values are
// rejected.
func flowBytesOut(raw map[string]any) (float64, bool) {
	for _, c := range []string{"network.bytes_out", "flow.bytes_out", "bytes_out"} {
		v, ok := lookupRaw(raw, c)
		if !ok {
			continue
		}
		if n, ok := numberOf(v); ok && n >= 0 {
			return n, true
		}
	}
	return 0, false
}

// auditActor returns the authenticated username of an audit event.
func auditActor(raw map[string]any) string {
	return lookupString(raw, "user.username")
}

// serviceAccountNamespace returns the namespace of a ServiceAccount
// username ("system:serviceaccount:<ns>:<name>"), or "".
func serviceAccountNamespace(username string) string {
	rest, ok := strings.CutPrefix(username, selfActorPrefixSA)
	if !ok {
		return ""
	}
	ns, _, ok := strings.Cut(rest, ":")
	if !ok {
		return ""
	}
	return ns
}

// restartedContainer reports whether a CRI lifecycle event marks a
// restart and returns a key for it, so one restart counts once however
// many events report it.
//
// Only container creation and start count (Story 10.12 review): the CRI
// adapter puts the attempt tags on every event of the container or
// sandbox, so a STOPPED or DELETED event of a container that restarted
// an hour ago would otherwise count as a new restart and reset the
// baseline. A container restart (container_attempt:N) is keyed by the
// container id; a sandbox restart (attempt:N, the whole pod recreated) by
// sandbox id and attempt, so the sandbox and each of its containers do
// not count as separate restarts.
func restartedContainer(ev *schema.Event) (string, bool) {
	if ev.Category != schema.CategoryLifecycle {
		return "", false
	}
	if !hasTag(ev.Tags, "event_type:created") && !hasTag(ev.Tags, "event_type:started") {
		return "", false
	}
	containerAttempt := positiveTagValue(ev.Tags, restartTagContainerAttempt)
	sandboxAttempt := positiveTagValue(ev.Tags, restartTagSandboxAttempt)
	if containerAttempt == "" && sandboxAttempt == "" {
		return "", false
	}
	raw := decodeRaw(ev)
	if containerAttempt != "" {
		if id := lookupString(raw, "container_id"); id != "" {
			return "container/" + id + "/" + containerAttempt, true
		}
		return "event/" + ev.ID, true
	}
	if id := lookupString(raw, "pod_sandbox.id"); id != "" {
		return "sandbox/" + id + "/" + sandboxAttempt, true
	}
	return "sandbox/" + ev.Pod.Namespace + "/" + ev.Pod.Name + "/" + sandboxAttempt, true
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}

// positiveTagValue returns N for the first "<prefix>N" tag whose N is a
// positive decimal, else "".
func positiveTagValue(tags []string, prefix string) string {
	for _, t := range tags {
		rest, ok := strings.CutPrefix(t, prefix)
		if ok && positiveDecimal(rest) {
			return rest
		}
	}
	return ""
}

// hasRestartAttemptTag returns true when tags contains an "attempt:N"
// (sandbox) or "container_attempt:N" (container) entry with N > 0.
//
// Copilot C3 + Edge Case Hunter E2 (Story 1.17): a malformed attempt tag
// (e.g. "attempt:abc") must NOT short-circuit the scan; a later valid
// entry in the same slice would otherwise be missed.
func hasRestartAttemptTag(tags []string) bool {
	for _, t := range tags {
		var rest string
		switch {
		case strings.HasPrefix(t, restartTagContainerAttempt):
			rest = strings.TrimPrefix(t, restartTagContainerAttempt)
		case strings.HasPrefix(t, restartTagSandboxAttempt):
			rest = strings.TrimPrefix(t, restartTagSandboxAttempt)
		default:
			continue
		}
		if positiveDecimal(rest) {
			return true
		}
	}
	return false
}

// positiveDecimal reports whether s is all ASCII digits with at least one
// non-zero digit.
func positiveDecimal(s string) bool {
	if s == "" {
		return false
	}
	nonZero := false
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
		if r != '0' {
			nonZero = true
		}
	}
	return nonZero
}

// walkPath descends m by path segments. Returns the leaf value and
// true when every segment is found.
func walkPath(m map[string]any, path []string) (any, bool) {
	cur := any(m)
	for _, seg := range path {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		next, found := obj[seg]
		if !found {
			return nil, false
		}
		cur = next
	}
	return cur, true
}

// lookupOutputFieldsPair handles the Falco shape where output_fields
// is a slice of [key, value] pairs (sortedFields returns [][2]string
// which JSON-marshals as [["k","v"], ...]). Returns the value for
// the first pair whose key equals key.
func lookupOutputFieldsPair(of any, key string) (any, bool) {
	arr, ok := of.([]any)
	if !ok {
		return nil, false
	}
	for _, item := range arr {
		pair, ok := item.([]any)
		if !ok || len(pair) != 2 {
			continue
		}
		k, ok := pair[0].(string)
		if !ok {
			continue
		}
		if k == key {
			return pair[1], true
		}
	}
	return nil, false
}

func stringOf(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return ""
}

// numberOf coerces a JSON-decoded value into a float64 sample for
// metric aggregation. NaN and +/-Inf are explicitly rejected (Story
// 1.17 Edge Case Hunter E7): a stringified "NaN" or "Inf" from a
// malformed adapter would otherwise feed Welford.Update and silently
// disarm the metric.
func numberOf(v any) (float64, bool) {
	var f float64
	switch x := v.(type) {
	case float64:
		f = x
	case int:
		f = float64(x)
	case int64:
		f = float64(x)
	case json.Number:
		var err error
		f, err = x.Float64()
		if err != nil {
			return 0, false
		}
	case string:
		// Adapters stringify int64 (protojson does for every int64
		// field); strconv.ParseFloat rejects nothing that matters and
		// the NaN guard below catches "NaN"/"Inf".
		var err error
		f, err = strconv.ParseFloat(x, 64)
		if err != nil {
			return 0, false
		}
	default:
		return 0, false
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}
