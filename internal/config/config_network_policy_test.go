package config

import "testing"

func TestNetworkPolicyConfig_Defaults(t *testing.T) {
	d := DefaultNetworkPolicy()
	if d.EnabledOrDefault() {
		t.Fatal("default NetworkPolicy must be disabled (opt-in until Story 2.10)")
	}
	if d.ReconcileIntervalSecondsOrDefault() != DefaultNetworkPolicyReconcileSeconds {
		t.Fatalf("default reconcile = %d, want %d", d.ReconcileIntervalSecondsOrDefault(), DefaultNetworkPolicyReconcileSeconds)
	}
	if len(d.ClusterCIDRsOrDefault()) == 0 {
		t.Fatal("default cluster CIDRs must be non-empty")
	}
}

func TestNetworkPolicyConfig_OrDefaultAccessors(t *testing.T) {
	var empty NetworkPolicyConfig
	if empty.EnabledOrDefault() {
		t.Fatal("nil Enabled must default to false")
	}
	if empty.ReconcileIntervalSecondsOrDefault() != DefaultNetworkPolicyReconcileSeconds {
		t.Fatal("nil reconcile must default")
	}
	enabled := true
	ri := 15
	set := NetworkPolicyConfig{Enabled: &enabled, ReconcileIntervalSeconds: &ri, ClusterCIDRs: []string{"10.0.0.0/8"}}
	if !set.EnabledOrDefault() || set.ReconcileIntervalSecondsOrDefault() != 15 {
		t.Fatal("explicit values must be honoured")
	}
}

func TestNetworkPolicyConfig_Validate(t *testing.T) {
	enabled := true
	good := 30
	bad := 0
	tooBig := 61
	tests := []struct {
		name    string
		cfg     NetworkPolicyConfig
		wantErr bool
	}{
		{"omitted block ok", NetworkPolicyConfig{}, false},
		{"valid cidrs", NetworkPolicyConfig{ClusterCIDRs: []string{"10.244.0.0/16", "10.96.0.0/12"}, ReconcileIntervalSeconds: &good}, false},
		{"invalid cluster cidr", NetworkPolicyConfig{ClusterCIDRs: []string{"not-a-cidr"}}, true},
		{"invalid extra cidr", NetworkPolicyConfig{ExtraAllowedCIDRs: []string{"10.0.0.0/99"}}, true},
		{"reconcile too small", NetworkPolicyConfig{ReconcileIntervalSeconds: &bad}, true},
		{"reconcile too big", NetworkPolicyConfig{ReconcileIntervalSeconds: &tooBig}, true},
		{"enabled without cidrs", NetworkPolicyConfig{Enabled: &enabled}, true},
		{"enabled with cidrs", NetworkPolicyConfig{Enabled: &enabled, ClusterCIDRs: []string{"10.96.0.0/12"}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.validate()
			if tc.wantErr && err == nil {
				t.Fatal("want error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestNetworkPolicyConfig_ValidateViaResponse confirms the block is reached
// through the ResponseConfig.validate() boundary used by Config.Validate.
func TestNetworkPolicyConfig_ValidateViaResponse(t *testing.T) {
	rc := ResponseConfig{NetworkPolicy: NetworkPolicyConfig{ClusterCIDRs: []string{"bad"}}}
	if err := rc.validate(); err == nil {
		t.Fatal("ResponseConfig.validate must surface a bad NetworkPolicy CIDR")
	}
}
