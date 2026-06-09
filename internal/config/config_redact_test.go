package config

import "testing"

func TestDefaultRedact(t *testing.T) {
	d := DefaultRedact()
	if d.AuditEnabled == nil || *d.AuditEnabled {
		t.Errorf("DefaultRedact AuditEnabled = %v, want false", d.AuditEnabled)
	}
	if d.RetentionRedactionsDays == nil || *d.RetentionRedactionsDays != DefaultRedactionsRetentionDays {
		t.Errorf("DefaultRedact retention = %v, want %d", d.RetentionRedactionsDays, DefaultRedactionsRetentionDays)
	}
}

func TestRedactAuditEnabledOrDefault(t *testing.T) {
	if (RedactConfig{}).AuditEnabledOrDefault() {
		t.Error("nil AuditEnabled should default to false")
	}
	tr := true
	if !(RedactConfig{AuditEnabled: &tr}).AuditEnabledOrDefault() {
		t.Error("explicit true should be true")
	}
	fa := false
	if (RedactConfig{AuditEnabled: &fa}).AuditEnabledOrDefault() {
		t.Error("explicit false should be false")
	}
}

func TestRedactRetentionRedactionsDaysOrDefault(t *testing.T) {
	if got := (RedactConfig{}).RetentionRedactionsDaysOrDefault(); got != DefaultRedactionsRetentionDays {
		t.Errorf("nil retention = %d, want %d", got, DefaultRedactionsRetentionDays)
	}
	v := 30
	if got := (RedactConfig{RetentionRedactionsDays: &v}).RetentionRedactionsDaysOrDefault(); got != 30 {
		t.Errorf("explicit retention = %d, want 30", got)
	}
}

func TestRedactValidate(t *testing.T) {
	if err := (RedactConfig{}).validate(); err != nil {
		t.Errorf("omitted block should validate: %v", err)
	}
	ok := 365
	if err := (RedactConfig{RetentionRedactionsDays: &ok}).validate(); err != nil {
		t.Errorf("positive retention should validate: %v", err)
	}
	for _, bad := range []int{0, -1} {
		b := bad
		if err := (RedactConfig{RetentionRedactionsDays: &b}).validate(); err == nil {
			t.Errorf("retention %d should be rejected", bad)
		}
	}
}
