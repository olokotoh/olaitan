package config

import (
	"testing"
	"time"
)

func TestSettlingConfig_Defaults(t *testing.T) {
	d := DefaultSettling()
	if d.EnabledOrDefault() {
		t.Fatal("default Settling must be disabled (opt-in)")
	}
	if d.WindowOrDefault() != 60*time.Second {
		t.Fatalf("default window = %s, want 60s (FR42)", d.WindowOrDefault())
	}
	if d.RetentionOrZero() != 365*24*time.Hour {
		t.Fatalf("default retention = %s, want 365d", d.RetentionOrZero())
	}
}

func TestSettlingConfig_OrDefaultAccessors(t *testing.T) {
	var empty SettlingConfig
	if empty.EnabledOrDefault() {
		t.Fatal("nil Enabled must default to false")
	}
	if empty.WindowOrDefault() != 60*time.Second {
		t.Fatalf("nil window must default to 60s, got %s", empty.WindowOrDefault())
	}
	// RetentionOrZero returns 0 when unset so the stream's baked-in 365d default
	// applies at the wiring layer (the checkpoint_retention precedent).
	if empty.RetentionOrZero() != 0 {
		t.Fatalf("nil retention must yield 0 (keep stream default), got %s", empty.RetentionOrZero())
	}

	enabled := true
	w := 120
	r := 30
	set := SettlingConfig{Enabled: &enabled, WindowSeconds: &w, RetentionDays: &r}
	if !set.EnabledOrDefault() {
		t.Fatal("explicit enabled must be honoured")
	}
	if set.WindowOrDefault() != 120*time.Second {
		t.Fatalf("explicit window = %s, want 120s", set.WindowOrDefault())
	}
	if set.RetentionOrZero() != 30*24*time.Hour {
		t.Fatalf("explicit retention = %s, want 30d", set.RetentionOrZero())
	}
}

func TestSettlingConfig_Validate(t *testing.T) {
	enabled := true
	zero := 0
	neg := -5
	good := 90
	tests := []struct {
		name    string
		cfg     SettlingConfig
		wantErr bool
	}{
		{"omitted block ok", SettlingConfig{}, false},
		{"enabled with defaults ok", SettlingConfig{Enabled: &enabled}, false},
		{"non-positive window rejected", SettlingConfig{WindowSeconds: &zero}, true},
		{"negative window rejected", SettlingConfig{WindowSeconds: &neg}, true},
		{"non-positive retention rejected", SettlingConfig{RetentionDays: &zero}, true},
		{"positive window+retention ok", SettlingConfig{WindowSeconds: &good, RetentionDays: &good}, false},
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

// TestSettlingConfig_ValidateViaResponse confirms the block is reached through
// the ResponseConfig.validate() boundary used by Config.Validate.
func TestSettlingConfig_ValidateViaResponse(t *testing.T) {
	bad := 0
	rc := ResponseConfig{Settling: SettlingConfig{WindowSeconds: &bad}}
	if err := rc.validate(); err == nil {
		t.Fatal("ResponseConfig.validate must surface a non-positive settling window")
	}
}
