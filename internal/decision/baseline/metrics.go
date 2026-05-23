package baseline

import (
	"encoding/json"
	"strings"

	"github.com/olokotoh/olaitan/internal/schema"
)

// metricNames lists the canonical names of the five default
// extractors. The engine iterates this slice (rather than a map) so
// per-package emission order is deterministic across runs.
var metricNames = []string{
	"outbound_unique_dst_ips",
	"distinct_exec_paths",
	"outbound_bytes",
	"audit_events_per_min",
	"container_restarts_per_hour",
}

// MetricNames returns a copy of the five default metric names in the
// canonical iteration order. Callers must not mutate the result.
func MetricNames() []string {
	out := make([]string, len(metricNames))
	copy(out, metricNames)
	return out
}

// MetricExtractor projects a single metric value out of an
// EvidencePackage. present=false signals "no observation this
// window" (insufficient signal layer) and the engine skips both
// Welford update and sigma check for that metric.
type MetricExtractor func(pkg *schema.EvidencePackage) (value float64, present bool)

// defaultExtractors registers the five default extractors keyed by
// metric name. The engine reads this map under the canonical
// MetricNames() iteration order.
var defaultExtractors = map[string]MetricExtractor{
	"outbound_unique_dst_ips":     extractOutboundUniqueDstIPs,
	"distinct_exec_paths":         extractDistinctExecPaths,
	"outbound_bytes":              extractOutboundBytes,
	"audit_events_per_min":        extractAuditEventsPerMin,
	"container_restarts_per_hour": extractContainerRestartsPerHour,
}

// DefaultExtractors returns a shallow copy of the registry. Callers
// must not mutate the returned map's keys, but may safely substitute
// values for testing.
func DefaultExtractors() map[string]MetricExtractor {
	out := make(map[string]MetricExtractor, len(defaultExtractors))
	for k, v := range defaultExtractors {
		out[k] = v
	}
	return out
}

func extractOutboundUniqueDstIPs(pkg *schema.EvidencePackage) (float64, bool) {
	if pkg == nil {
		return 0, false
	}
	present := false
	seen := map[string]struct{}{}
	for i := range pkg.Events {
		ev := &pkg.Events[i]
		if ev.Source != schema.SourceNetwork || ev.Category != schema.CategoryFlow {
			continue
		}
		present = true
		// BI-2: canonical "network.dst_ip" first, then source-native
		// CNI shape (Goldmane FlowKey's dest_name or top-level dst_ip).
		if v, ok := lookupRawField(ev, "network.dst_ip", "dst_ip", "dest_ip", "dest_name"); ok {
			if s := stringOf(v); s != "" {
				seen[s] = struct{}{}
			}
		}
	}
	if !present {
		return 0, false
	}
	return float64(len(seen)), true
}

func extractDistinctExecPaths(pkg *schema.EvidencePackage) (float64, bool) {
	if pkg == nil {
		return 0, false
	}
	present := false
	seen := map[string]struct{}{}
	for i := range pkg.Events {
		ev := &pkg.Events[i]
		if ev.Source != schema.SourceFalco {
			continue
		}
		present = true
		// BI-2: canonical "process.exe" first, then Falco-native
		// "proc.exe" nested under output_fields.
		if v, ok := lookupRawField(ev, "process.exe", "proc.exe"); ok {
			if s := stringOf(v); s != "" {
				seen[s] = struct{}{}
			}
		}
	}
	if !present {
		return 0, false
	}
	return float64(len(seen)), true
}

func extractOutboundBytes(pkg *schema.EvidencePackage) (float64, bool) {
	if pkg == nil {
		return 0, false
	}
	netPresent := false
	carriesBytes := false
	var sum float64
	for i := range pkg.Events {
		ev := &pkg.Events[i]
		if ev.Source != schema.SourceNetwork || ev.Category != schema.CategoryFlow {
			continue
		}
		netPresent = true
		if v, ok := lookupRawField(ev, "network.bytes_out", "bytes_out", "bytesOut"); ok {
			if n, ok := numberOf(v); ok {
				sum += n
				carriesBytes = true
			}
		}
	}
	if !netPresent || !carriesBytes {
		return 0, false
	}
	return sum, true
}

func extractAuditEventsPerMin(pkg *schema.EvidencePackage) (float64, bool) {
	if pkg == nil {
		return 0, false
	}
	mins := pkg.WindowEnd.Sub(pkg.WindowStart).Minutes()
	if mins <= 0 {
		return 0, false
	}
	count := 0
	for i := range pkg.Events {
		if pkg.Events[i].Source == schema.SourceAudit {
			count++
		}
	}
	if count == 0 {
		return 0, false
	}
	return float64(count) / mins, true
}

func extractContainerRestartsPerHour(pkg *schema.EvidencePackage) (float64, bool) {
	if pkg == nil {
		return 0, false
	}
	hours := pkg.WindowEnd.Sub(pkg.WindowStart).Hours()
	if hours <= 0 {
		return 0, false
	}
	count := 0
	for i := range pkg.Events {
		ev := &pkg.Events[i]
		if ev.Category != schema.CategoryLifecycle {
			continue
		}
		if hasRestartAttemptTag(ev.Tags) {
			count++
		}
	}
	if count == 0 {
		return 0, false
	}
	return float64(count) / hours, true
}

// hasRestartAttemptTag returns true when tags contains an
// "attempt:N" entry with N > 0. The CRI adapter emits this tag on
// CONTAINER_STARTED_EVENT records whose meta.Attempt > 0 per
// internal/collector/cri/translate.go:51-57.
func hasRestartAttemptTag(tags []string) bool {
	for _, t := range tags {
		if !strings.HasPrefix(t, "attempt:") {
			continue
		}
		rest := strings.TrimPrefix(t, "attempt:")
		if rest == "" || rest == "0" {
			continue
		}
		// A non-zero numeric suffix counts as a restart.
		nonZero := false
		for _, r := range rest {
			if r < '0' || r > '9' {
				return false
			}
			if r != '0' {
				nonZero = true
			}
		}
		if nonZero {
			return true
		}
	}
	return false
}

// lookupRawField scans ev.Raw for the first present candidate path.
// Candidates may be top-level keys ("dst_ip") or dotted paths
// ("network.dst_ip"). The Falco adapter nests proc.exe under
// output_fields as a [][key,value] pair slice; lookupRawField scans
// that pair shape too when no top-level candidate hits.
func lookupRawField(ev *schema.Event, candidates ...string) (any, bool) {
	if len(ev.Raw) == 0 {
		return nil, false
	}
	var raw map[string]any
	if err := json.Unmarshal(ev.Raw, &raw); err != nil {
		return nil, false
	}
	for _, c := range candidates {
		if v, ok := walkPath(raw, strings.Split(c, ".")); ok {
			return v, true
		}
	}
	// Fall back to scanning output_fields for each candidate (Falco
	// shape, BI-2 explicit). Falco field names include their own
	// dotted prefix (e.g. "proc.exe", "k8s.pod.name") so we look for
	// the full candidate string first, then the leaf token.
	if ofRaw, ok := raw["output_fields"]; ok {
		for _, c := range candidates {
			if v, ok := lookupOutputFieldsPair(ofRaw, c); ok {
				return v, true
			}
			if i := strings.LastIndex(c, "."); i >= 0 {
				if v, ok := lookupOutputFieldsPair(ofRaw, c[i+1:]); ok {
					return v, true
				}
			}
		}
	}
	return nil, false
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
// the first pair whose key equals leaf.
func lookupOutputFieldsPair(of any, leaf string) (any, bool) {
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
		if k == leaf {
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
	}
	return ""
}

func numberOf(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case json.Number:
		f, err := x.Float64()
		if err != nil {
			return 0, false
		}
		return f, true
	case string:
		// Some adapters stringify numerics; tolerate that shape.
		var f float64
		if _, err := json.Number(x).Float64(); err == nil {
			f, _ = json.Number(x).Float64()
			return f, true
		}
		return 0, false
	}
	return 0, false
}
