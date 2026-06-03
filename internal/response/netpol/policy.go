package netpol

import (
	"crypto/sha256"
	"encoding/hex"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/olokotoh/olaitan/internal/schema"
)

const (
	// LabelManagedBy / ManagedByValue mark every policy Olaitan applies so
	// the orphan-GC reconcile can list exactly its own policies (AC3, BI-9).
	LabelManagedBy = "app.kubernetes.io/managed-by"
	ManagedByValue = "olaitan"
	labelName      = "app.kubernetes.io/name"
	labelComponent = "app.kubernetes.io/component"

	// AnnFSMState carries the FSM state the policy enforces (AC3). AnnPackageID
	// carries the package_id that triggered it (AC3). AnnWorkloadID carries the
	// canonical workload id so the GC reconcile can resolve the owner (BI-10).
	AnnFSMState   = "olaitan.io/fsm-state"
	AnnPackageID  = "olaitan.io/package-id"
	AnnWorkloadID = "olaitan.io/workload-id"

	policyNamePrefix = "olaitan-restricted-"
	// quarantinedNamePrefix is the distinct deterministic prefix for the
	// QUARANTINED deny-all policy (Story 2.5, BI-3). It differs from the
	// RESTRICTED prefix so the two states' objects are independently
	// addressable during the apply-before-delete supersession (BI-5) and
	// for Story 2.6 de-escalation, while both remain collectable by the
	// single managed-by GC selector (BI-8).
	quarantinedNamePrefix = "olaitan-quarantined-"
)

// managedBySelector is the label selector the GC reconcile lists with.
const managedBySelector = LabelManagedBy + "=" + ManagedByValue

// rfc1918 are the private ranges always allowed for egress under RESTRICTED.
var rfc1918 = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

// PolicyName returns the deterministic RESTRICTED NetworkPolicy name for a
// workload: "olaitan-restricted-" + the first 12 hex chars of
// sha256(workloadID). The determinism makes apply idempotent (re-applying
// targets the same object, BI-6) and lets the GC reconcile and the Story 2.5
// QUARANTINED supersession address the right object. It delegates to the
// state-keyed policyNameFor so RESTRICTED has a single source of truth.
func PolicyName(workloadID string) string {
	return policyNameFor(schema.StateRestricted, workloadID)
}

// policyHashSuffix returns the first 12 hex chars of sha256(workloadID), the
// shared deterministic suffix both per-state policy names carry (BI-3). The
// same suffix means re-apply targets the same object (idempotent, BI-6) and
// the RESTRICTED and QUARANTINED names for a workload differ only by prefix.
func policyHashSuffix(workloadID string) string {
	sum := sha256.Sum256([]byte(workloadID))
	return hex.EncodeToString(sum[:])[:12]
}

// policyNameFor returns the deterministic, state-keyed NetworkPolicy name for
// a workload (Story 2.5, BI-3): the "olaitan-restricted-" prefix for
// RESTRICTED and the "olaitan-quarantined-" prefix for QUARANTINED, each
// followed by the shared 12-hex sha256 suffix. Any other state falls back to
// the RESTRICTED prefix; handle never builds a policy for a non-enforced
// state, so this default is unreachable in practice but keeps the helper
// total.
func policyNameFor(state schema.PodSecurityState, workloadID string) string {
	prefix := policyNamePrefix
	if state == schema.StateQuarantined {
		prefix = quarantinedNamePrefix
	}
	return prefix + policyHashSuffix(workloadID)
}

// buildEgressRules precomputes the RESTRICTED egress allow-list (BI-8).
// NetworkPolicy egress is an allow-list: an Egress policy selecting a pod
// with these rules permits egress only to the listed destinations and
// denies the rest (all external CIDRs). Rule 1 allows all ports to the
// internal/allowed CIDRs; rule 2 is an explicit DNS (UDP/TCP 53) allowance
// to the same destinations so name resolution survives even if rule 1 is
// later narrowed (CoreDNS resides in the service CIDR, which callers must
// include in clusterCIDRs).
func buildEgressRules(allowCIDRs []string) []networkingv1.NetworkPolicyEgressRule {
	peers := make([]networkingv1.NetworkPolicyPeer, 0, len(allowCIDRs))
	for _, c := range allowCIDRs {
		peers = append(peers, networkingv1.NetworkPolicyPeer{
			IPBlock: &networkingv1.IPBlock{CIDR: c},
		})
	}
	udp := corev1.ProtocolUDP
	tcp := corev1.ProtocolTCP
	dnsPort := intstr.FromInt32(53)
	return []networkingv1.NetworkPolicyEgressRule{
		{To: peers},
		{
			To: peers,
			Ports: []networkingv1.NetworkPolicyPort{
				{Protocol: &udp, Port: &dnsPort},
				{Protocol: &tcp, Port: &dnsPort},
			},
		},
	}
}

// managedLabels returns the label set every Olaitan-managed policy carries.
func managedLabels() map[string]string {
	return map[string]string{
		LabelManagedBy: ManagedByValue,
		labelName:      "olaitan",
		labelComponent: "response",
	}
}

// buildPolicy constructs the typed NetworkPolicy for a workload, keyed by the
// transition's target state (Story 2.5, BI-2). For RESTRICTED it renders the
// egress allow-list policy (policyTypes Egress only; ingress untouched;
// precomputed allow-list, BI-8), unchanged from Story 2.4. For QUARANTINED it
// renders the deny-all-ingress-and-egress policy (policyTypes [Ingress,
// Egress] with both rule slices left nil, BI-4). The name is state-keyed
// (BI-3) and the AnnFSMState annotation carries the actual target state so
// AC4's olaitan.io/fsm-state matches for both states from one code path. The
// managed labels and the annotation block are reused verbatim.
func (m *Manager) buildPolicy(ref workloadRef, sel *metav1.LabelSelector, st schema.StateTransition) *networkingv1.NetworkPolicy {
	var podSelector metav1.LabelSelector
	if sel != nil {
		podSelector = *sel
	}
	annotations := map[string]string{
		AnnFSMState:   string(st.ToState),
		AnnWorkloadID: st.WorkloadID,
	}
	// Mirror the schema's omitempty intent: only carry the package-id
	// annotation when a triggering package id is present.
	if st.PackageID != "" {
		annotations[AnnPackageID] = st.PackageID
	}
	spec := networkingv1.NetworkPolicySpec{PodSelector: podSelector}
	if st.ToState == schema.StateQuarantined {
		// Deny-all (BI-4): listing both policyTypes with NO rules of either
		// type denies all ingress and all egress FOR TRAFFIC GOVERNED BY THIS
		// POLICY. Kubernetes NetworkPolicies are additive allow-lists, so this
		// denial is not absolute on its own: another policy selecting the same
		// pod (notably the RESTRICTED egress allow-list during the
		// apply-before-delete overlap) can still ALLOW traffic, because the
		// allowed set is the UNION of all selecting policies' rules. Full egress
		// denial for a quarantined workload therefore requires the superseded
		// RESTRICTED policy to be removed, which the manager does inline and, if
		// that fails, via the reconcile backstop (reconcileGC). Ingress and
		// Egress are left nil; a stray empty rule struct ({}) would invert this
		// to allow-all and MUST NOT be emitted. No DNS carve-out: a
		// confirmed-malicious workload is cut off completely once the RESTRICTED
		// policy is gone, name resolution included.
		spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress}
	} else {
		spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}
		spec.Egress = m.egressRules
	}
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:        policyNameFor(st.ToState, st.WorkloadID),
			Namespace:   ref.namespace,
			Labels:      managedLabels(),
			Annotations: annotations,
		},
		Spec: spec,
	}
}
