package falco

import (
	"context"

	"github.com/olokotoh/olaitan/internal/collector/falco/falcopb"
)

// PodIdentity is the pod a container belongs to.
type PodIdentity struct {
	Namespace string
	Name      string
	UID       string
}

// PodIdentityResolver maps a Falco container.id to its pod. The collector
// passes a node-scoped, watch-fed cache (internal/collector/podidentity);
// an implementation must not make an unbounded API call per alert, and
// may wait only a short bounded time for a container it has not seen yet.
type PodIdentityResolver interface {
	ResolvePodIdentity(ctx context.Context, containerID string) (PodIdentity, bool)
}

// EnrichedByField is the output_fields key set on an alert whose pod was
// filled by the collector rather than Falco, so the event's Raw payload
// records where the attribution came from.
const EnrichedByField = "olaitan.k8s.enriched_by"

// EnrichedByPodCache is the EnrichedByField value for the pod cache.
const EnrichedByPodCache = "collector-pod-cache"

// EnrichPodIdentity fills k8s.ns.name, k8s.pod.name and k8s.pod.uid on a
// Falco alert that has a container.id but no pod (Story 11.2d, #195: the
// pinned Falco leaves these null for pods created after it started). It
// runs before Translate, so the translated event carries the pod and the
// Story 10.3 field mapping is unchanged. An alert Falco already attributed,
// a host alert, or a cache miss is left as it is. Returns true when it
// filled the pod.
func EnrichPodIdentity(ctx context.Context, resp *falcopb.Response, r PodIdentityResolver) bool {
	if r == nil || resp == nil {
		return false
	}
	fields := resp.GetOutputFields()
	cid := fields["container.id"]
	if missing(cid) || cid == "host" {
		return false
	}
	if !missing(fields["k8s.ns.name"]) && !missing(fields["k8s.pod.name"]) {
		return false
	}
	id, ok := r.ResolvePodIdentity(ctx, cid)
	if !ok || id.Namespace == "" || id.Name == "" {
		return false
	}
	if resp.OutputFields == nil {
		resp.OutputFields = map[string]string{}
	}
	resp.OutputFields["k8s.ns.name"] = id.Namespace
	resp.OutputFields["k8s.pod.name"] = id.Name
	if id.UID != "" {
		resp.OutputFields["k8s.pod.uid"] = id.UID
	}
	resp.OutputFields[EnrichedByField] = EnrichedByPodCache
	return true
}

// missing reports a field Falco had no value for: absent (JSON null is
// dropped at decode), empty, or Falco's "<NA>" placeholder.
func missing(v string) bool { return v == "" || v == "<NA>" }
