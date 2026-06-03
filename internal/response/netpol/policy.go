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
)

// managedBySelector is the label selector the GC reconcile lists with.
const managedBySelector = LabelManagedBy + "=" + ManagedByValue

// rfc1918 are the private ranges always allowed for egress under RESTRICTED.
var rfc1918 = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

// PolicyName returns the deterministic NetworkPolicy name for a workload:
// "olaitan-restricted-" + the first 12 hex chars of sha256(workloadID). The
// determinism makes apply idempotent (re-applying targets the same object,
// BI-6) and lets the GC reconcile and the Story 2.5 QUARANTINED replacement
// address the same object.
func PolicyName(workloadID string) string {
	sum := sha256.Sum256([]byte(workloadID))
	return policyNamePrefix + hex.EncodeToString(sum[:])[:12]
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

// buildPolicy constructs the typed RESTRICTED NetworkPolicy for a workload.
// policyTypes is Egress only (RESTRICTED leaves ingress untouched; the full
// ingress+egress block is the Story 2.5 QUARANTINED state). The egress rules
// are the precomputed allow-list (BI-8).
func (m *Manager) buildPolicy(ref workloadRef, sel *metav1.LabelSelector, st schema.StateTransition) *networkingv1.NetworkPolicy {
	var podSelector metav1.LabelSelector
	if sel != nil {
		podSelector = *sel
	}
	annotations := map[string]string{
		AnnFSMState:   string(schema.StateRestricted),
		AnnWorkloadID: st.WorkloadID,
	}
	// Mirror the schema's omitempty intent: only carry the package-id
	// annotation when a triggering package id is present.
	if st.PackageID != "" {
		annotations[AnnPackageID] = st.PackageID
	}
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:        PolicyName(st.WorkloadID),
			Namespace:   ref.namespace,
			Labels:      managedLabels(),
			Annotations: annotations,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: podSelector,
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress:      m.egressRules,
		},
	}
}
