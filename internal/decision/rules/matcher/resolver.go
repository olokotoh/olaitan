// Package matcher provides the OLT-side field resolver that bridges
// sigmalite's FieldResolver contract onto OLT's two-half lookup
// space: the workload-posture half (k8s.* fields, resolved from
// *schema.WorkloadPosture) and the streaming-event half (process.*,
// network.*, file.*, etc., resolved from per-event field maps).
//
// FieldResolver-only contract (ADR-2026-04-28-01 risk record): when
// MatchOptions.FieldResolver is non-nil, sigmalite uses ONLY the
// resolver for field lookups. It does NOT fall back to
// LogEntry.Fields for missing-from-resolver fields. The OLTResolver
// therefore MUST resolve every field referenced by every rule,
// including non-k8s.* fields. The LogEntry.Fields mirror still
// matters for sigmalite's internal bookkeeping (notably the `re`
// modifier's field-name reporting and the `expand` placeholder
// substitution), so the engine populates both surfaces with the
// same case-folded values at evaluation time.
//
// Case handling: the OLT dialect spec uses lowercase exclusively
// (docs/sigma-extensions.md §3). Source maps are lowered at load
// time; lookups lower the requested field name. Two source keys
// that collide on case (e.g. `Image` and `image`) are rejected at
// load time: silent shadowing is a footgun the spike POC already
// flagged.
package matcher

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	sigma "github.com/runreveal/sigmalite"

	"github.com/olokotoh/olaitan/internal/schema"
)

// OLTResolver implements sigma.FieldResolver. It owns two pre-lowered
// indices: posture (k8s.* fields, source = WorkloadPosture) and
// fields (everything else, source = schema.Event). Both are
// case-insensitive on the lookup side, exact-string on the storage
// side.
type OLTResolver struct {
	// posture maps lower-case "k8s.*" key → stringified value.
	posture map[string]string
	// fields maps lower-case non-"k8s.*" key → stringified value.
	fields map[string]string
}

// Resolve implements sigma.FieldResolver. The entry argument is
// ignored on the hot path: every lookup goes through the resolver's
// own indices so a caller cannot accidentally short-circuit the
// case-fold contract via LogEntry.Fields.
func (r *OLTResolver) Resolve(field string, _ *sigma.LogEntry) []string {
	lower := strings.ToLower(field)
	if strings.HasPrefix(lower, "k8s.") {
		if v, ok := r.posture[lower]; ok {
			return []string{v}
		}
		return nil
	}
	if v, ok := r.fields[lower]; ok {
		return []string{v}
	}
	return nil
}

// NewResolver builds an OLTResolver from a WorkloadPosture (optional;
// may be nil for the degraded path) and a streaming-event field map.
// The eventFields argument is the union of fields the caller intends
// to expose for this single-event evaluation; keys colliding on case
// against another entry in eventFields are rejected.
//
// The returned *sigma.LogEntry is the dual-write mirror sigmalite
// expects: every event-side field is present on LogEntry.Fields with
// its original-case key so the `re` and `expand` modifier paths can
// still report and substitute correctly when MatchOptions.FieldResolver
// is set. Posture fields are NOT mirrored on LogEntry.Fields because
// the k8s.* namespace is resolver-only; sigmalite's bookkeeping never
// reaches for them by name except through the resolver.
func NewResolver(posture *schema.WorkloadPosture, eventFields map[string]string) (*OLTResolver, *sigma.LogEntry, error) {
	r := &OLTResolver{
		posture: map[string]string{},
		fields:  map[string]string{},
	}
	entry := &sigma.LogEntry{Fields: map[string]string{}}

	for k, v := range eventFields {
		lower := strings.ToLower(k)
		if _, dup := r.fields[lower]; dup {
			return nil, nil, fmt.Errorf("event key %q collides on case", k)
		}
		r.fields[lower] = v
		entry.Fields[k] = v
	}

	if posture != nil {
		for k, v := range PostureFields(posture) {
			lower := strings.ToLower(k)
			if _, dup := r.posture[lower]; dup {
				return nil, nil, fmt.Errorf("posture key %q collides on case", k)
			}
			r.posture[lower] = v
		}
	}
	return r, entry, nil
}

// PostureFields projects a *schema.WorkloadPosture onto the k8s.*
// field map per docs/sigma-extensions.md §3. The projection is total
// (every always-present field is present in the map, even if its
// value is the zero string) so a rule asking for an absent posture
// field gets a nil resolve rather than a missing-key inconsistency
// between two rule invocations.
//
// A nil posture returns an empty map.
func PostureFields(p *schema.WorkloadPosture) map[string]string {
	out := map[string]string{}
	if p == nil {
		return out
	}
	id := p.Identity
	out["k8s.pod.namespace"] = id.Namespace
	out["k8s.workload.owner_kind"] = id.OwnerKind
	out["k8s.workload.owner_name"] = id.OwnerName
	if id.PodName != "" {
		out["k8s.pod.name"] = id.PodName
	}
	if p.ServiceAccount != "" {
		out["k8s.pod.serviceaccount"] = p.ServiceAccount
	}
	// First container's name. docs/sigma-extensions.md §3 also lists
	// k8s.container.image as a supported posture field, but
	// schema.WorkloadPosture has no Image field today (Story 1.11
	// scope). Story 1.16 rule-corpus authors should consult
	// docs/sigma-extensions.md and, if they need k8s.container.image,
	// plumb an Image field onto WorkloadPosture via the posture
	// client and project it here. Until then, rules referencing
	// k8s.container.image silently miss; this is a known gap
	// recorded as code-review D2 against Story 1.15.
	if len(p.ContainerSecurityContexts) > 0 {
		out["k8s.container.name"] = p.ContainerSecurityContexts[0].ContainerName
	}
	return out
}

// EventFields projects a schema.Event onto a stringified field map
// suitable for NewResolver. Every value is stringified per the
// sigmalite pattern-match contract; numeric ports and severities
// must compare against integer literals in YAML as strings, so the
// conversion is unconditional.
//
// Keys produced here mirror the dialect spec: process.*, network.*,
// file.* etc. Where the streaming Event carries a structured Raw
// payload, the caller is responsible for flattening that into the
// returned map before handing it to NewResolver (the spike POC's
// loadFixture does this for JSON fixtures; the engine path lets each
// adapter supply its own flattener).
//
// Precedence: schema-canonical fields (event.id, event.source, etc.)
// always win over a Raw-JSON field of the same name. The Raw flatten
// runs first, then the canonical projection overwrites; otherwise an
// adapter-emitted "event.id" key in Raw would silently shadow the
// schema-authoritative ev.ID.
func EventFields(ev schema.Event) map[string]string {
	out := map[string]string{}
	// Flatten Event.Raw if it's a JSON object. The OLT adapter
	// contract (Stories 1.6-1.10) is that Raw carries an
	// adapter-specific snake_case JSON object; flattening it onto
	// the resolver lets rules reference adapter-specific fields
	// (process.exe, network.dst_port, etc.) by their canonical names.
	if len(ev.Raw) > 0 {
		var flat map[string]any
		if err := json.Unmarshal(ev.Raw, &flat); err == nil {
			for k, v := range flat {
				out[k] = stringify(v)
			}
		}
	}
	// Canonical projection runs AFTER the Raw flatten so the
	// schema-authoritative event fields always win.
	if ev.ID != "" {
		out["event.id"] = ev.ID
	}
	if ev.Source != "" {
		out["event.source"] = string(ev.Source)
	}
	if ev.Category != "" {
		out["event.category"] = string(ev.Category)
	}
	if ev.Severity != "" {
		out["event.severity"] = ev.Severity
	}
	if ev.Summary != "" {
		out["event.summary"] = ev.Summary
	}
	return out
}

// stringify renders an arbitrary JSON-decoded scalar as the string
// form sigmalite's pattern matcher compares against. Numeric integers
// keep their natural decimal form (3333 not "3333.000000"); floats
// preserve precision; nil becomes the empty string; complex values
// fall back to their JSON encoding so a rule referencing a structured
// field gets stable behaviour rather than Go's default %v.
func stringify(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	case nil:
		return ""
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}
