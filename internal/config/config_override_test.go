package config

import "testing"

func TestOverrideConfig_Defaults(t *testing.T) {
	d := DefaultOverride()
	if d.EnabledOrDefault() {
		t.Fatal("default Override must be disabled (opt-in)")
	}
	if d.PollIntervalSecondsOrDefault() != DefaultOverridePollSeconds {
		t.Fatalf("default poll = %d, want %d", d.PollIntervalSecondsOrDefault(), DefaultOverridePollSeconds)
	}
	if d.DefaultTTLSecondsOrDefault() != DefaultOverrideTTLSeconds {
		t.Fatalf("default ttl = %d, want %d (1h)", d.DefaultTTLSecondsOrDefault(), DefaultOverrideTTLSeconds)
	}
}

func TestOverrideConfig_OrDefaultAccessors(t *testing.T) {
	var empty OverrideConfig
	if empty.EnabledOrDefault() {
		t.Fatal("nil Enabled must default to false")
	}
	if empty.PollIntervalSecondsOrDefault() != DefaultOverridePollSeconds {
		t.Fatal("nil poll must default")
	}
	if empty.DefaultTTLSecondsOrDefault() != DefaultOverrideTTLSeconds {
		t.Fatal("nil ttl must default")
	}
	enabled := true
	poll := 5
	ttl := 7200
	set := OverrideConfig{Enabled: &enabled, PollIntervalSeconds: &poll, DefaultTTLSeconds: &ttl}
	if !set.EnabledOrDefault() || set.PollIntervalSecondsOrDefault() != 5 || set.DefaultTTLSecondsOrDefault() != 7200 {
		t.Fatal("explicit values must be honoured")
	}
}

func TestOverrideConfig_Validate(t *testing.T) {
	zero := 0
	neg := -1
	good := 15
	tests := []struct {
		name    string
		cfg     OverrideConfig
		wantErr bool
	}{
		{"omitted block ok", OverrideConfig{}, false},
		{"valid", OverrideConfig{PollIntervalSeconds: &good, DefaultTTLSeconds: &good}, false},
		{"poll zero", OverrideConfig{PollIntervalSeconds: &zero}, true},
		{"poll negative", OverrideConfig{PollIntervalSeconds: &neg}, true},
		{"ttl zero", OverrideConfig{DefaultTTLSeconds: &zero}, true},
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

// TestOverrideConfig_ValidateViaResponse confirms the block is reached
// through the ResponseConfig.validate() boundary used by Config.Validate.
func TestOverrideConfig_ValidateViaResponse(t *testing.T) {
	zero := 0
	rc := ResponseConfig{Override: OverrideConfig{PollIntervalSeconds: &zero}}
	if err := rc.validate(); err == nil {
		t.Fatal("ResponseConfig.validate must surface a bad Override poll interval")
	}
}
