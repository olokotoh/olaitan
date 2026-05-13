// WorkloadPosture and its sub-types describe the read-on-demand
// posture context attached to an EvidencePackage at investigation
// time (FR7). Posture is the sixth Ring 1 source: a synchronous
// K8s-API client (internal/collector/posture) populates this struct
// per architecture.md:45 ("five streaming adapters plus one
// read-on-demand posture client"), architecture.md:751 (production
// path internal/collector/posture/), and architecture.md:324 ("posture
// is read on-demand at investigation time, not via continuous Watch").
//
// The struct is wire-format facing: it travels inside
// EvidencePackage.workload_posture once Story 1.14 assembles the
// package, and downstream consumers (the L1/L2/Senior LLM chain in
// Epic 3, the DFIR agent in Epic 4) read it via the schema-on-read
// envelope. Field naming therefore follows the snake-case JSON
// convention from internal/schema/event.go.
//
// Three correctness rules are encoded in the field shape:
//
//  1. Pointer fields preserve the Kubernetes API's "nil means not set"
//     semantics. The K8s API distinguishes "operator left runAsNonRoot
//     unset" from "operator explicitly set runAsNonRoot=false"; a Go
//     bool collapses both into the zero value. *bool keeps them apart.
//
//  2. The owner-kind / owner-name pair is the canonical workload
//     identity (architecture.md:457). Two pods of the same Deployment
//     share a WorkloadIdentity; this is what makes the posture cache
//     amortise well at O(100) workloads.
//
//  3. UnavailableReason carries a class, never a raw error message
//     (NFR15). The four classes are transient, permission_denied,
//     not_found, permanent. The full err.Error() lives in the
//     structured slog log; the payload that flows into the LLM prompt
//     carries only the class.
//
// The JSON-Schema mirror at docs/schemas/workload_posture.yaml is
// deferred to Epic 6 Story 6.3 per architecture.md:904.
package schema

import "time"

// WorkloadPosture is the read-on-demand posture snapshot for a single
// workload. CapturedAt records when the underlying K8s API queries
// resolved; consumers compare this against the posture cache TTL
// (default 60s, architecture.md:324) to decide whether to bypass.
type WorkloadPosture struct {
	Identity                  WorkloadIdentity                  `json:"identity"`
	OrphanPod                 bool                              `json:"orphan_pod,omitempty"`
	Unavailable               bool                              `json:"unavailable,omitempty"`
	UnavailableReason         string                            `json:"unavailable_reason,omitempty"`
	CapturedAt                time.Time                         `json:"captured_at"`
	ServiceAccount            string                            `json:"service_account,omitempty"`
	RoleBindings              []RoleBindingRef                  `json:"role_bindings,omitempty"`
	ClusterRoleBindings       []ClusterRoleBindingRef           `json:"cluster_role_bindings,omitempty"`
	NetworkPolicies           []NetworkPolicyRef                `json:"network_policies,omitempty"`
	PodSecurityContext        *PodSecurityContextSummary        `json:"pod_security_context,omitempty"`
	ContainerSecurityContexts []ContainerSecurityContextSummary `json:"container_security_contexts,omitempty"`
}

// WorkloadIdentity is the canonical identifier the architecture pins
// at architecture.md:457: "namespace/owner-kind/owner-name URL-encoded,
// fallback to namespace/pod-name for orphan pods". OwnerKind is the
// literal Kubernetes kind ("Deployment", "StatefulSet", "DaemonSet",
// "Job", "CronJob", or "Pod" on the orphan-pod fallback) so consumers
// can distinguish resolved vs orphan via a string compare without
// inspecting the OrphanPod boolean on the parent struct (both are
// carried for ergonomic clarity).
type WorkloadIdentity struct {
	Namespace string `json:"namespace"`
	OwnerKind string `json:"owner_kind"`
	OwnerName string `json:"owner_name"`
	// PodName is populated only on orphan-pod fallback so the
	// correlator can still log the underlying pod alongside the
	// fallback identity.
	PodName string `json:"pod_name,omitempty"`
}

// PostureUnavailableReason enumerates the four error classes carried
// on UnavailableReason. The class is what the LLM prompt sees; the
// raw error message is logged separately per NFR15.
const (
	PostureUnavailableTransient        = "transient"
	PostureUnavailablePermissionDenied = "permission_denied"
	PostureUnavailableNotFound         = "not_found"
	PostureUnavailablePermanent        = "permanent"
)

// RoleBindingRef references a RoleBinding whose subjects include the
// workload's ServiceAccount. The Verbs and Resources slices are the
// flattened union across the referenced Role's rules, capped at the
// caller's union-cap (default 32 entries each, bounded by memory).
//
// VerbsTruncated signals to the LLM consumer that the verbs/resources
// slices were trimmed to the cap; without this flag, an alphabetically-
// late dangerous verb (e.g., "update", "watch") could be silently
// dropped and the consumer would reason about an incomplete privilege
// set. VerbsUnavailable signals that the referenced Role could not be
// resolved (deletion, RBAC denial, transient apiserver error) and
// distinguishes "binding exists with no rules" from "binding exists,
// rules unknown" for the NFR15 honesty boundary.
type RoleBindingRef struct {
	Name             string   `json:"name"`
	RoleKind         string   `json:"role_kind"` // "Role" or "ClusterRole"
	RoleName         string   `json:"role_name"`
	Verbs            []string `json:"verbs,omitempty"`
	Resources        []string `json:"resources,omitempty"`
	VerbsTruncated   bool     `json:"verbs_truncated,omitempty"`
	VerbsUnavailable bool     `json:"verbs_unavailable,omitempty"`
}

// ClusterRoleBindingRef references a ClusterRoleBinding whose subjects
// include the workload's ServiceAccount (with the workload's
// namespace). VerbsTruncated and VerbsUnavailable have the same
// semantics as on RoleBindingRef.
type ClusterRoleBindingRef struct {
	Name             string   `json:"name"`
	RoleName         string   `json:"role_name"`
	Verbs            []string `json:"verbs,omitempty"`
	Resources        []string `json:"resources,omitempty"`
	VerbsTruncated   bool     `json:"verbs_truncated,omitempty"`
	VerbsUnavailable bool     `json:"verbs_unavailable,omitempty"`
}

// NetworkPolicyRef references a NetworkPolicy whose spec.podSelector
// matches the workload's pod labels. The full rule bodies are
// intentionally not surfaced; the count plus PolicyTypes is enough for
// the LLM chain to reason about "missing egress restriction" or
// "ingress is restricted" without exploding the prompt size.
type NetworkPolicyRef struct {
	Name         string   `json:"name"`
	PolicyTypes  []string `json:"policy_types"`
	IngressRules int      `json:"ingress_rules"`
	EgressRules  int      `json:"egress_rules"`
}

// PodSecurityContextSummary projects the pod-level
// corev1.PodSecurityContext onto a stable, snake-case JSON surface.
// All fields are pointers to preserve "unset vs explicitly zero"
// (RunAsNonRoot=false is meaningfully different from "operator did not
// set RunAsNonRoot").
type PodSecurityContextSummary struct {
	RunAsUser          *int64  `json:"run_as_user,omitempty"`
	RunAsGroup         *int64  `json:"run_as_group,omitempty"`
	RunAsNonRoot       *bool   `json:"run_as_non_root,omitempty"`
	FSGroup            *int64  `json:"fs_group,omitempty"`
	SupplementalGroups []int64 `json:"supplemental_groups,omitempty"`
	// SeccompProfile is the type name from
	// corev1.SeccompProfileType: "Localhost", "RuntimeDefault", or
	// "Unconfined". The localhost profile path is NOT surfaced
	// because it can encode operator filesystem paths (NFR15).
	SeccompProfile string `json:"seccomp_profile,omitempty"`
	// SELinuxLevel surfaces only the level field, not user / role /
	// type, because the level is the routinely-relevant signal for
	// posture reasoning and the other three risk leaking
	// site-specific identifiers.
	SELinuxLevel string `json:"selinux_level,omitempty"`
}

// ContainerSecurityContextSummary projects corev1.SecurityContext per
// container (init, regular, ephemeral). Container-level fields
// override the pod-level equivalents per K8s semantics; consumers must
// merge with the pod-level summary at evaluation time.
//
// Inherits=true is set when the container has no SecurityContext set
// at all (the K8s default: all pod-level settings apply unmodified).
// This is preserved in the surface because the absence of an override
// is itself a posture finding (operators who omit SecurityContext are
// inheriting defaults that may be permissive). All pointer fields are
// nil in that case; consumers MUST consult Inherits before reasoning
// about specific values.
type ContainerSecurityContextSummary struct {
	ContainerName            string   `json:"container_name"`
	Kind                     string   `json:"kind"` // "init", "regular", "ephemeral"
	Inherits                 bool     `json:"inherits,omitempty"`
	Privileged               *bool    `json:"privileged,omitempty"`
	AllowPrivilegeEscalation *bool    `json:"allow_privilege_escalation,omitempty"`
	ReadOnlyRootFilesystem   *bool    `json:"read_only_root_filesystem,omitempty"`
	RunAsUser                *int64   `json:"run_as_user,omitempty"`
	RunAsGroup               *int64   `json:"run_as_group,omitempty"`
	RunAsNonRoot             *bool    `json:"run_as_non_root,omitempty"`
	AddedCapabilities        []string `json:"added_capabilities,omitempty"`
	DroppedCapabilities      []string `json:"dropped_capabilities,omitempty"`
	SeccompProfile           string   `json:"seccomp_profile,omitempty"`
}

// Container kind constants for ContainerSecurityContextSummary.Kind.
const (
	ContainerKindInit      = "init"
	ContainerKindRegular   = "regular"
	ContainerKindEphemeral = "ephemeral"
)
