package config

import "testing"

func TestAuditConfig_Defaults(t *testing.T) {
	d := DefaultAudit()
	if d.EnabledOrDefault() {
		t.Error("audit must default to disabled")
	}
	if d.RetentionTransitionsDaysOrDefault() != 90 {
		t.Errorf("transitions retention default = %d, want 90", d.RetentionTransitionsDaysOrDefault())
	}
	if d.RetentionOverridesDaysOrDefault() != 365 {
		t.Errorf("overrides retention default = %d, want 365", d.RetentionOverridesDaysOrDefault())
	}
	if d.RetentionPoliciesDaysOrDefault() != 365 {
		t.Errorf("policies retention default = %d, want 365", d.RetentionPoliciesDaysOrDefault())
	}
}

func TestAuditConfig_OrDefaultOnNil(t *testing.T) {
	var a AuditConfig // all nil
	if a.EnabledOrDefault() {
		t.Error("nil Enabled must read as false")
	}
	if a.RetentionTransitionsDaysOrDefault() != 90 || a.RetentionOverridesDaysOrDefault() != 365 || a.RetentionPoliciesDaysOrDefault() != 365 {
		t.Error("nil retentions must read as 90/365/365")
	}
}

func TestAuditConfig_EnabledExplicit(t *testing.T) {
	enabled := true
	a := AuditConfig{Enabled: &enabled}
	if !a.EnabledOrDefault() {
		t.Error("explicit true must survive")
	}
}

func TestAuditConfig_ValidateRejectsNonPositive(t *testing.T) {
	zero := 0
	neg := -5
	cases := []AuditConfig{
		{RetentionTransitionsDays: &zero},
		{RetentionOverridesDays: &neg},
		{RetentionPoliciesDays: &zero},
	}
	for i, c := range cases {
		if err := c.validate(); err == nil {
			t.Errorf("case %d: expected validate error for non-positive retention", i)
		}
	}
}

func TestAuditConfig_ValidateAcceptsOmittedAndPositive(t *testing.T) {
	if err := (AuditConfig{}).validate(); err != nil {
		t.Errorf("omitted block must validate, got %v", err)
	}
	if err := DefaultAudit().validate(); err != nil {
		t.Errorf("defaults must validate, got %v", err)
	}
}
