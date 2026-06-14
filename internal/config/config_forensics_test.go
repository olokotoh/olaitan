package config

import "testing"

func TestForensicsConfig_Defaults(t *testing.T) {
	d := DefaultForensics()
	if d.EnabledOrDefault() {
		t.Fatal("default Forensics must be disabled (opt-in)")
	}
	if !d.S3UseSSLOrDefault() {
		t.Fatal("default s3_use_ssl must be true (production TLS)")
	}
}

func TestForensicsConfig_OrDefaultAccessors(t *testing.T) {
	var empty ForensicsConfig
	if empty.EnabledOrDefault() {
		t.Fatal("nil Enabled must default to false")
	}
	if !empty.S3UseSSLOrDefault() {
		t.Fatal("nil s3_use_ssl must default to true")
	}
	enabled := true
	ssl := false
	set := ForensicsConfig{Enabled: &enabled, S3UseSSL: &ssl}
	if !set.EnabledOrDefault() {
		t.Fatal("explicit enabled must be honoured")
	}
	if set.S3UseSSLOrDefault() {
		t.Fatal("explicit s3_use_ssl=false must be honoured")
	}
}

func TestForensicsConfig_Validate(t *testing.T) {
	enabled := true
	disabled := false
	tests := []struct {
		name    string
		cfg     ForensicsConfig
		wantErr bool
	}{
		{"omitted block ok", ForensicsConfig{}, false},
		{"disabled with empty fields ok", ForensicsConfig{Enabled: &disabled}, false},
		{"enabled missing endpoint", ForensicsConfig{Enabled: &enabled, S3Bucket: "b"}, true},
		{"enabled missing bucket", ForensicsConfig{Enabled: &enabled, S3Endpoint: "e"}, true},
		{"enabled complete", ForensicsConfig{Enabled: &enabled, S3Endpoint: "e", S3Bucket: "b"}, false},
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

// TestForensicsConfig_ValidateViaResponse confirms the block is reached through
// the ResponseConfig.validate() boundary used by Config.Validate.
func TestForensicsConfig_ValidateViaResponse(t *testing.T) {
	enabled := true
	rc := ResponseConfig{Forensics: ForensicsConfig{Enabled: &enabled}}
	if err := rc.validate(); err == nil {
		t.Fatal("ResponseConfig.validate must surface an enabled forensics block missing endpoint/bucket")
	}
}
