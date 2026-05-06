// Package audit implements the Olaitan agent's Kubernetes API server
// audit-webhook backend receiver. The kube-apiserver pushes batches of
// audit.k8s.io/v1 EventList JSON to this receiver over mTLS; each event
// is translated to a canonical schema.Event of source=audit /
// category=audit and published to subjects.RawAudit via JetStream with
// at-least-once semantics. Layer 1 sensing for control-plane intent.
//
// This file holds the pure translate transform. The HTTP receiver and
// adapter lifecycle live in audit.go; the in-process source-health
// tracker is consumed from internal/sourcehealth (Story 1.7 graduated
// it from the Falco package).
package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"

	"github.com/olokotoh/olaitan/internal/schema"
)

// minValidEventTime mirrors the Falco translate floor. A timestamp
// before 2010 indicates either an unset Time{} (Unix epoch) or severe
// clock skew on the apiserver pod; either way, downstream sliding-
// window correlation would mis-bucket the event, so reject early.
var minValidEventTime = time.Date(2010, time.January, 1, 0, 0, 0, 0, time.UTC)

// maxFutureSkew caps how far past "now" a translate-time timestamp may
// land. The apiserver and the Olaitan pod run on the same cluster (NTP
// in practice), but a badly skewed apiserver clock would otherwise
// admit events the correlator can never bucket in its sliding window.
// The 24h ceiling matches the Story 1.6 patch precedent.
const maxFutureSkew = 24 * time.Hour

// maxRequestObjectBytes caps the inline RequestObject + ResponseObject
// payload retained in Event.Raw. Above this combined size the bodies
// are stripped (Secret data, ConfigMap content, full Pod specs are the
// usual culprits) but the GVK is retained so the downstream forensic
// agent (Epic 4 DFIR) knows what was redacted.
const maxRequestObjectBytes = 64 * 1024

// ErrSkipNonResponseComplete is the sentinel returned by Translate when
// the audit Event is not at the ResponseComplete stage. The receiver
// loop treats this as "skip, do not retry, do not unhealthy". Earlier
// stages (RequestReceived, ResponseStarted) carry incomplete data;
// Panic is rare and indicates apiserver-internal failure.
var ErrSkipNonResponseComplete = errors.New("audit: skip non-ResponseComplete stage")

// Translate converts an audit.k8s.io/v1 Event into the canonical
// schema.Event.
//
// Determinism: the field-mapping is purely a function of the input.
// The future-skew check reads `time.Now()` to reject events that
// arrive with a RequestReceivedTimestamp more than maxFutureSkew
// ahead of wall clock; this is the one wall-clock dependency. Every
// other field of the returned schema.Event is determined entirely by
// the input ev. Two calls within the same maxFutureSkew window
// produce byte-equal outputs.
//
// The nodeName argument is the node-level identifier the caller
// already knows (typically read from the K8S_NODE_NAME env var
// injected by the Helm chart's downward API); it lands in
// Event.Pod.Node so events without a pod-scoped ObjectRef still
// record where Olaitan observed them.
//
// Translation contract (Story 1.7 Task 1):
//
//   - Event.ID is the apiserver-generated AuditID UUID. Empty AuditID
//     is rejected rather than silently fabricated, defending against a
//     non-spec-compliant upstream.
//   - Event.Source is pinned to schema.SourceAudit; Event.Category to
//     schema.CategoryAudit. The AC text's "source KUBE_AUDIT" is
//     shorthand for this pair; the schema package's enum uses the
//     lowercase identifier "audit" for stable wire compatibility.
//   - Event.Severity is a coarse triage hint derived from the verb +
//     resource, NOT a final classification. The OLT Sigma rule engine
//     in Story 1.15 does the real classification; this is just an
//     early signal so non-rule-engine consumers (alerting baseline,
//     eval harness) have a level. Default is "informational"; RBAC
//     mutations, NetworkPolicy mutations, Secret access, and
//     exec/portforward all bump to "warning".
//   - Event.Pod is derived from ObjectRef. For ObjectRef.Resource ==
//     "pods" with a non-empty Name, populates the full PodRef. For
//     non-pod resources, leaves Name and UID empty (control-plane
//     events are not pod-scoped); for cluster-scoped resources also
//     leaves Namespace empty.
//   - Event.Raw is the marshalled audit Event, with RequestObject.Raw
//     and ResponseObject.Raw stripped (GVK retained) when the combined
//     size exceeds maxRequestObjectBytes. Critical: event_id is
//     deterministic regardless of strip decision because it comes
//     from AuditID, not the body.
//   - Event.Tags include the verb, resource, stage, plus optional
//     authorization-decision and PSA tags from Annotations.
//
// Returns ErrSkipNonResponseComplete when ev.Stage is not
// ResponseComplete. The receiver loop uses errors.Is to skip silently
// without retrying or marking unhealthy.
//
// Other errors are wrapped "audit: translate: ..." for nil ev, missing
// or pre-epoch RequestReceivedTimestamp, empty AuditID, or JSON
// marshal failure (currently unreachable for well-formed audit Events
// but kept defensive).
func Translate(ev *auditv1.Event, nodeName string) (schema.Event, error) {
	if ev == nil {
		return schema.Event{}, fmt.Errorf("audit: translate: nil event")
	}

	// Stage filter: only ResponseComplete events become schema.Events.
	// The default audit policy sets omitStages: [RequestReceived] but
	// receivers must defensively handle whatever stages a non-default
	// policy emits. The sentinel signals "skip silently" upstream.
	if ev.Stage != auditv1.StageResponseComplete {
		return schema.Event{}, ErrSkipNonResponseComplete
	}

	if ev.AuditID == "" {
		return schema.Event{}, fmt.Errorf("audit: translate: empty AuditID (rule=verb=%q resource=%q)",
			ev.Verb, refResource(ev.ObjectRef))
	}

	ts := ev.RequestReceivedTimestamp.Time
	if ts.IsZero() || ts.Before(minValidEventTime) {
		return schema.Event{}, fmt.Errorf("audit: translate: RequestReceivedTimestamp %s is before %s (likely clock skew or unset Time, audit_id=%s)",
			ts.Format(time.RFC3339Nano), minValidEventTime.Format(time.RFC3339), ev.AuditID)
	}
	if ts.After(time.Now().Add(maxFutureSkew)) {
		return schema.Event{}, fmt.Errorf("audit: translate: RequestReceivedTimestamp %s is more than %s in the future (likely clock skew, audit_id=%s)",
			ts.Format(time.RFC3339Nano), maxFutureSkew, ev.AuditID)
	}

	pod := podRefFromObjectRef(ev.ObjectRef, nodeName)
	severity := severityFromEvent(ev)
	summary := summaryFromEvent(ev)
	tags := tagsFromEvent(ev)

	rawJSON, err := marshalTrimmedRaw(ev)
	if err != nil {
		return schema.Event{}, fmt.Errorf("audit: translate: marshal raw (audit_id=%s): %w", ev.AuditID, err)
	}

	return schema.Event{
		ID:        string(ev.AuditID),
		Timestamp: ts,
		Source:    schema.SourceAudit,
		Pod:       pod,
		Severity:  severity,
		Category:  schema.CategoryAudit,
		Summary:   summary,
		Raw:       rawJSON,
		Tags:      tags,
	}, nil
}

// podRefFromObjectRef derives the Event.Pod field from the audit
// Event's ObjectRef. The contract is documented on Translate:
//
//   - pods: full PodRef with Name and UID.
//   - non-pod namespaced resources (RoleBinding, NetworkPolicy,
//     ConfigMap, Secret, ...): Name and UID empty; Namespace populated.
//   - cluster-scoped resources (ClusterRole, ClusterRoleBinding,
//     Node, ...): Name, UID, and Namespace all empty.
//   - nil ObjectRef (non-resource API paths like /healthz): everything
//     empty except Node, which is always the caller-supplied nodeName.
func podRefFromObjectRef(ref *auditv1.ObjectReference, nodeName string) schema.PodRef {
	pod := schema.PodRef{Node: nodeName}
	if ref == nil {
		return pod
	}
	pod.Namespace = ref.Namespace
	if strings.EqualFold(ref.Resource, "pods") && ref.Name != "" {
		pod.Name = ref.Name
		pod.UID = string(ref.UID)
	}
	return pod
}

// severityFromEvent maps the audit event to a coarse severity hint.
// Defaults to "informational"; bumps to "warning" for the
// privilege-relevant operations. Additionally bumps to "warning" when
// the request was issued via impersonation (a common
// privilege-escalation pattern), regardless of the underlying
// resource severity.
func severityFromEvent(ev *auditv1.Event) string {
	if ev.ImpersonatedUser != nil && ev.ImpersonatedUser.Username != "" {
		return "warning"
	}
	return severityFromVerbResource(ev.Verb, ev.ObjectRef)
}

// severityFromVerbResource maps the audit verb + resource to a coarse
// severity hint. Defaults to "informational"; bumps to "warning" for
// the privilege-relevant operations.
func severityFromVerbResource(verb string, ref *auditv1.ObjectReference) string {
	if ref == nil {
		return "informational"
	}
	resource := strings.ToLower(ref.Resource)
	subresource := strings.ToLower(ref.Subresource)
	v := strings.ToLower(verb)

	// RBAC resources: any mutating verb is a warning. Read access to
	// RBAC is informational; the rule engine in Story 1.15 may
	// promote based on rule corpus.
	switch resource {
	case "rolebindings", "clusterrolebindings", "roles", "clusterroles":
		switch v {
		case "create", "update", "patch", "delete", "deletecollection":
			return "warning"
		}
	case "networkpolicies":
		switch v {
		case "create", "update", "patch", "delete", "deletecollection":
			return "warning"
		}
	case "secrets":
		// Any verb on secrets is a warning -- including get/list/watch
		// because credential exfiltration patterns rely on those.
		return "warning"
	}

	// pods subresources that indicate privilege use:
	//   - exec, portforward, attach: shell / direct connection
	//   - log: credential leakage via stdout/stderr scrape
	if resource == "pods" {
		switch subresource {
		case "exec", "portforward", "attach", "log":
			return "warning"
		}
	}

	return "informational"
}

// summaryFromEvent renders the human-readable one-liner. Falls back to
// RequestURI for non-resource API paths (e.g. /healthz) where
// ObjectRef is nil, and to "<anonymous>" / "<system>" for the user
// segment when User.Username is empty.
func summaryFromEvent(ev *auditv1.Event) string {
	user := ev.User.Username
	if user == "" {
		user = "<anonymous>"
	}
	if ev.ObjectRef == nil || ev.ObjectRef.Resource == "" {
		uri := ev.RequestURI
		if uri == "" {
			uri = "<no-uri>"
		}
		return fmt.Sprintf("%s %s by %s", strings.ToLower(ev.Verb), uri, user)
	}
	resource := ev.ObjectRef.Resource
	if ev.ObjectRef.Subresource != "" {
		resource = resource + "/" + ev.ObjectRef.Subresource
	}
	name := ev.ObjectRef.Name
	if name == "" {
		name = "<unnamed>"
	}
	ns := ev.ObjectRef.Namespace
	if ns == "" {
		return fmt.Sprintf("%s %s/%s by %s",
			strings.ToLower(ev.Verb), resource, name, user)
	}
	return fmt.Sprintf("%s %s/%s/%s by %s",
		strings.ToLower(ev.Verb), ns, resource, name, user)
}

// tagsFromEvent derives the schema.Event.Tags slice. Always includes
// verb, resource, and stage (when non-empty). Adds decision:allow /
// decision:forbid from Annotations and psa:<value> from the
// pod-security-admission enforce-policy annotation.
//
// The slice is freshly allocated so callers cannot retain a reference
// that aliases the audit Event's Annotations map.
func tagsFromEvent(ev *auditv1.Event) []string {
	tags := make([]string, 0, 6)
	if ev.Verb != "" {
		tags = append(tags, "verb:"+strings.ToLower(ev.Verb))
	}
	if ev.ObjectRef != nil && ev.ObjectRef.Resource != "" {
		resource := strings.ToLower(ev.ObjectRef.Resource)
		if ev.ObjectRef.Subresource != "" {
			resource = resource + "/" + strings.ToLower(ev.ObjectRef.Subresource)
		}
		tags = append(tags, "resource:"+resource)
	}
	if ev.Stage != "" {
		tags = append(tags, "stage:"+string(ev.Stage))
	}
	if dec := ev.Annotations["authorization.k8s.io/decision"]; dec != "" {
		tags = append(tags, "decision:"+strings.ToLower(dec))
	}
	if psa := ev.Annotations["pod-security.kubernetes.io/enforce-policy"]; psa != "" {
		tags = append(tags, "psa:"+psa)
	}
	return tags
}

// marshalTrimmedRaw serialises the audit Event for storage in
// schema.Event.Raw, stripping RequestObject.Raw and ResponseObject.Raw
// when their combined size exceeds maxRequestObjectBytes. The GVK is
// retained on strip so the downstream forensic agent (Epic 4 DFIR)
// knows what was redacted.
//
// Determinism: the audit.k8s.io/v1 Event has stable JSON field
// ordering via encoding/json's struct-tag traversal, but Annotations
// is a map and would otherwise serialise in random order. We reshape
// the Event into a small map[string]any with the same fields and
// canonicalise Annotations into a sorted [][2]string slice so repeated
// translations produce byte-equal Raw payloads.
func marshalTrimmedRaw(ev *auditv1.Event) (json.RawMessage, error) {
	combined := 0
	if ev.RequestObject != nil {
		combined += len(ev.RequestObject.Raw)
	}
	if ev.ResponseObject != nil {
		combined += len(ev.ResponseObject.Raw)
	}

	// Build a canonical, deterministic shape. We keep the full Event
	// minus the two heavy bodies (which we replace with a GVK-only
	// stub when stripped) and a sorted Annotations slice.
	stripped := combined > maxRequestObjectBytes

	type objStub struct {
		GVK      string `json:"gvk,omitempty"`
		Bytes    int    `json:"bytes,omitempty"`
		Stripped bool   `json:"stripped"`
	}

	type canonical struct {
		Kind                     string                   `json:"kind"`
		APIVersion               string                   `json:"apiVersion"`
		Level                    auditv1.Level            `json:"level"`
		AuditID                  string                   `json:"auditID"`
		Stage                    auditv1.Stage            `json:"stage"`
		RequestURI               string                   `json:"requestURI"`
		Verb                     string                   `json:"verb"`
		User                     authnv1.UserInfo         `json:"user"`
		ImpersonatedUser         *authnv1.UserInfo        `json:"impersonatedUser,omitempty"`
		SourceIPs                []string                 `json:"sourceIPs,omitempty"`
		UserAgent                string                   `json:"userAgent,omitempty"`
		ObjectRef                *auditv1.ObjectReference `json:"objectRef,omitempty"`
		ResponseStatus           interface{}              `json:"responseStatus,omitempty"`
		RequestObject            interface{}              `json:"requestObject,omitempty"`
		ResponseObject           interface{}              `json:"responseObject,omitempty"`
		RequestReceivedTimestamp string                   `json:"requestReceivedTimestamp"`
		StageTimestamp           string                   `json:"stageTimestamp,omitempty"`
		Annotations              [][2]string              `json:"annotations,omitempty"`
		Stripped                 bool                     `json:"_stripped,omitempty"`
		StrippedBytes            int                      `json:"_stripped_bytes,omitempty"`
	}

	c := canonical{
		Kind:                     "Event",
		APIVersion:               "audit.k8s.io/v1",
		Level:                    ev.Level,
		AuditID:                  string(ev.AuditID),
		Stage:                    ev.Stage,
		RequestURI:               ev.RequestURI,
		Verb:                     ev.Verb,
		User:                     ev.User,
		ImpersonatedUser:         ev.ImpersonatedUser,
		SourceIPs:                append([]string(nil), ev.SourceIPs...),
		UserAgent:                ev.UserAgent,
		ObjectRef:                ev.ObjectRef,
		ResponseStatus:           ev.ResponseStatus,
		RequestReceivedTimestamp: ev.RequestReceivedTimestamp.UTC().Format(time.RFC3339Nano),
		Annotations:              sortedAnnotations(ev.Annotations),
		Stripped:                 stripped,
	}
	if !ev.StageTimestamp.IsZero() {
		c.StageTimestamp = ev.StageTimestamp.UTC().Format(time.RFC3339Nano)
	}

	if stripped {
		c.StrippedBytes = combined
		if ev.RequestObject != nil {
			c.RequestObject = objStub{
				GVK:      gvkOf(ev.RequestObject),
				Bytes:    len(ev.RequestObject.Raw),
				Stripped: true,
			}
		}
		if ev.ResponseObject != nil {
			c.ResponseObject = objStub{
				GVK:      gvkOf(ev.ResponseObject),
				Bytes:    len(ev.ResponseObject.Raw),
				Stripped: true,
			}
		}
	} else {
		if ev.RequestObject != nil {
			c.RequestObject = ev.RequestObject
		}
		if ev.ResponseObject != nil {
			c.ResponseObject = ev.ResponseObject
		}
	}

	b, err := json.Marshal(&c)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

// sortedAnnotations renders Annotations as a deterministic
// [][2]string. Returns nil for nil or empty input so omitempty in the
// JSON tag elides the field.
func sortedAnnotations(annotations map[string]string) [][2]string {
	if len(annotations) == 0 {
		return nil
	}
	keys := make([]string, 0, len(annotations))
	for k := range annotations {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([][2]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, [2]string{k, annotations[k]})
	}
	return out
}

// gvkOf extracts the runtime.Unknown's APIVersion + Kind. Returns the
// empty string when the body has no recorded type metadata.
func gvkOf(u *runtime.Unknown) string {
	if u == nil {
		return ""
	}
	if u.APIVersion == "" && u.Kind == "" {
		return ""
	}
	return u.APIVersion + "," + u.Kind
}

// refResource returns the resource name from an ObjectRef or the
// empty string for a nil ref. Convenience helper for error messages.
func refResource(ref *auditv1.ObjectReference) string {
	if ref == nil {
		return ""
	}
	return ref.Resource
}
