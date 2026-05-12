package posture_test

import (
	"context"
	"errors"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/olokotoh/olaitan/internal/collector/posture"
)

func netpol(name, namespace string, selector *metav1.LabelSelector, policyTypes []networkingv1.PolicyType) networkingv1.NetworkPolicy {
	spec := networkingv1.NetworkPolicySpec{}
	if selector != nil {
		spec.PodSelector = *selector
	}
	spec.PolicyTypes = policyTypes
	return networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       spec,
	}
}

func TestApplicableNetworkPolicies_MatchLabels(t *testing.T) {
	policies := []networkingv1.NetworkPolicy{
		netpol("matches-payments", "payments",
			&metav1.LabelSelector{MatchLabels: map[string]string{"app": "payments"}},
			[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress}),
		netpol("matches-backend", "payments",
			&metav1.LabelSelector{MatchLabels: map[string]string{"app": "backend"}},
			[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress}),
	}
	cs := fake.NewSimpleClientset(&policies[0], &policies[1])

	got, err := posture.ApplicableNetworkPolicies(context.Background(), cs, "payments", map[string]string{"app": "payments"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d policies, want 1: %+v", len(got), got)
	}
	if got[0].Name != "matches-payments" {
		t.Errorf("name: got %q, want matches-payments", got[0].Name)
	}
}

func TestApplicableNetworkPolicies_EmptySelectorMatchesAll(t *testing.T) {
	policies := []networkingv1.NetworkPolicy{
		netpol("catchall", "payments",
			&metav1.LabelSelector{}, // empty PodSelector matches all pods in ns
			[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress}),
	}
	cs := fake.NewSimpleClientset(&policies[0])

	got, err := posture.ApplicableNetworkPolicies(context.Background(), cs, "payments", map[string]string{"app": "anything"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Name != "catchall" {
		t.Errorf("empty selector should match all pods; got %+v", got)
	}
}

func TestApplicableNetworkPolicies_MatchExpressionsIn(t *testing.T) {
	policies := []networkingv1.NetworkPolicy{
		netpol("canary-or-prod", "payments",
			&metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "app", Operator: metav1.LabelSelectorOpIn, Values: []string{"payments", "payments-canary"}},
				},
			},
			[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress}),
	}
	cs := fake.NewSimpleClientset(&policies[0])

	for _, lab := range []map[string]string{{"app": "payments"}, {"app": "payments-canary"}} {
		got, err := posture.ApplicableNetworkPolicies(context.Background(), cs, "payments", lab)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 {
			t.Errorf("labels %v: got %d policies, want 1", lab, len(got))
		}
	}

	got, err := posture.ApplicableNetworkPolicies(context.Background(), cs, "payments", map[string]string{"app": "backend"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("labels app=backend: got %d policies, want 0", len(got))
	}
}

func TestApplicableNetworkPolicies_CrossNamespaceBleedGuarded(t *testing.T) {
	other := netpol("other-ns-policy", "other",
		&metav1.LabelSelector{}, // empty selector in `other` ns
		[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress})
	mine := netpol("mine", "payments",
		&metav1.LabelSelector{},
		[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress})
	cs := fake.NewSimpleClientset(&other, &mine)

	got, err := posture.ApplicableNetworkPolicies(context.Background(), cs, "payments", map[string]string{"app": "payments"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Namespace != "payments" {
		t.Errorf("cross-namespace bleed: got %+v, want only payments/mine", got)
	}
}

func TestApplicableNetworkPolicies_DeterministicSort(t *testing.T) {
	policies := []networkingv1.NetworkPolicy{
		netpol("zeta", "payments", &metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}),
		netpol("alpha", "payments", &metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}),
		netpol("mu", "payments", &metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}),
	}
	cs := fake.NewSimpleClientset(&policies[0], &policies[1], &policies[2])

	got, err := posture.ApplicableNetworkPolicies(context.Background(), cs, "payments", map[string]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantOrder := []string{"alpha", "mu", "zeta"}
	if len(got) != 3 {
		t.Fatalf("got %d policies, want 3", len(got))
	}
	for i, name := range wantOrder {
		if got[i].Name != name {
			t.Errorf("position %d: got %q, want %q", i, got[i].Name, name)
		}
	}
}

func TestApplicableNetworkPolicies_EmptyListReturnsEmpty(t *testing.T) {
	cs := fake.NewSimpleClientset()
	got, err := posture.ApplicableNetworkPolicies(context.Background(), cs, "payments", map[string]string{"app": "any"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Errorf("got nil, want empty non-nil slice")
	}
	if len(got) != 0 {
		t.Errorf("got %d policies, want 0", len(got))
	}
}

func TestApplicableNetworkPolicies_NilClientsetReturnsError(t *testing.T) {
	_, err := posture.ApplicableNetworkPolicies(context.Background(), nil, "ns", map[string]string{})
	if err == nil {
		t.Fatalf("expected error for nil clientset, got nil")
	}
}

func TestApplicableNetworkPolicies_EmptyNamespaceReturnsError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	_, err := posture.ApplicableNetworkPolicies(context.Background(), cs, "", map[string]string{})
	if err == nil {
		t.Fatalf("expected error for empty namespace, got nil")
	}
}

func TestApplicableNetworkPolicies_InvalidSelectorWraps(t *testing.T) {
	// Construct an inherently invalid selector: operator In with no
	// values is rejected by LabelSelectorAsSelector.
	bad := netpol("bad-selector", "payments",
		&metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "app", Operator: metav1.LabelSelectorOpIn, Values: nil},
			},
		}, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress})
	cs := fake.NewSimpleClientset(&bad)

	_, err := posture.ApplicableNetworkPolicies(context.Background(), cs, "payments", map[string]string{"app": "any"})
	if err == nil {
		t.Fatalf("expected error for invalid selector, got nil")
	}
	if !errors.Is(err, posture.ErrInvalidPodSelector) {
		t.Errorf("expected ErrInvalidPodSelector, got %v", err)
	}
}
