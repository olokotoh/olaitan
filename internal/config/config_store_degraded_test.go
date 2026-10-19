package config

import (
	"strings"
	"testing"
)

// Story 12.7 D5: forensics and the report archive are on by default, but an
// object store is a platform prerequisite the chart cannot provide. With the
// store fields ALL empty the consumer is "no store configured" (valid; the
// binary logs it DEGRADED and skips wiring it). A PARTIAL store config is
// still a load error: a typo must never degrade silently.
func TestForensicsConfig_NoStoreIsDegradedNotInvalid(t *testing.T) {
	on := true
	f := ForensicsConfig{Enabled: &on}
	if err := f.validate(); err != nil {
		t.Fatalf("enabled with no store at all must validate (degraded), got %v", err)
	}
	if f.StoreConfigured() {
		t.Fatal("StoreConfigured() = true with endpoint, bucket and KMS alias all empty")
	}
	for name, cfg := range map[string]ForensicsConfig{
		"bucket only":   {Enabled: &on, S3Bucket: "b"},
		"endpoint only": {Enabled: &on, S3Endpoint: "e"},
		"kms only":      {Enabled: &on, KMSKeyAlias: "alias/k"},
		"no kms":        {Enabled: &on, S3Endpoint: "e", S3Bucket: "b"},
	} {
		if err := cfg.validate(); err == nil {
			t.Errorf("%s: a partial store config validated; it must fail and name the missing field", name)
		}
	}
	full := ForensicsConfig{Enabled: &on, S3Endpoint: "e", S3Bucket: "b", KMSKeyAlias: "alias/k"}
	if !full.StoreConfigured() || full.validate() != nil {
		t.Fatal("a complete store config must be configured and valid")
	}
}

func TestReportArchiveConfig_NoStoreIsDegradedNotInvalid(t *testing.T) {
	on := true
	r := ReportArchiveConfig{Enabled: &on, DeferredEnabled: &on, DeferredRedisAddr: "redis:6379"}
	if err := r.validate(); err != nil {
		t.Fatalf("enabled with no store at all must validate (degraded), got %v", err)
	}
	if r.StoreConfigured() {
		t.Fatal("StoreConfigured() = true with endpoint, bucket and KMS alias all empty")
	}
	partial := ReportArchiveConfig{Enabled: &on, S3Bucket: "b"}
	if err := partial.validate(); err == nil || !strings.Contains(err.Error(), "s3_endpoint") {
		t.Errorf("a partial report archive store validated or did not name s3_endpoint: %v", err)
	}
}
