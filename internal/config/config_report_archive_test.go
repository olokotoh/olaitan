package config_test

import (
	"strings"
	"testing"

	"github.com/olokotoh/olaitan/internal/config"
)

// reportArchiveBaseYAML is a minimal valid config the report-archive cases
// extend. The response block is LAST so an appended `  report_archive:` block is
// a child of response (2-space indent under response:).
const reportArchiveBaseYAML = `detection:
  confidence_bands: {watch: 40, alert: 70, act: 90}
  baseline_window: "1h"
analyst:
  provider: api
  score_cap: 35
  timeout: 10s
response:
  excluded_namespaces: []
`

// TestReportArchiveConfig_Defaults: an omitted report_archive block defaults to
// disabled, TLS-on, 90-day retention, and GOVERNANCE object-lock mode (PO
// ratification 5).
func TestReportArchiveConfig_Defaults(t *testing.T) {
	cfg, err := config.Load(writeConfig(t, reportArchiveBaseYAML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	ra := cfg.Response.ReportArchive
	if ra.EnabledOrDefault() {
		t.Error("report archive must default to disabled (opt-in)")
	}
	if !ra.S3UseSSLOrDefault() {
		t.Error("s3_use_ssl must default to true (production)")
	}
	if ra.RetentionDaysOrDefault() != 90 {
		t.Errorf("retention_days must default to 90, got %d", ra.RetentionDaysOrDefault())
	}
	if ra.ObjectLockModeOrDefault() != "GOVERNANCE" {
		t.Errorf("object_lock_mode must default to GOVERNANCE, got %q", ra.ObjectLockModeOrDefault())
	}
}

// TestReportArchiveConfig_KnobsParse: the new knobs decode through Load with
// their flat yaml keys, including an explicit COMPLIANCE mode and a custom
// retention.
func TestReportArchiveConfig_KnobsParse(t *testing.T) {
	yaml := reportArchiveBaseYAML + `  report_archive:
    enabled: true
    s3_endpoint: "s3.example.com"
    s3_bucket: "olaitan-reports"
    s3_region: "eu-west-1"
    s3_use_ssl: false
    kms_key_alias: "alias/olaitan-reports"
    retention_days: 365
    object_lock_mode: COMPLIANCE
`
	cfg, err := config.Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	ra := cfg.Response.ReportArchive
	if !ra.EnabledOrDefault() {
		t.Error("enabled=true must survive the loader")
	}
	if ra.S3Endpoint != "s3.example.com" || ra.S3Bucket != "olaitan-reports" || ra.S3Region != "eu-west-1" {
		t.Errorf("endpoint/bucket/region wrong: %+v", ra)
	}
	if ra.S3UseSSLOrDefault() {
		t.Error("s3_use_ssl=false must survive the loader")
	}
	if ra.KMSKeyAlias != "alias/olaitan-reports" {
		t.Errorf("kms_key_alias = %q", ra.KMSKeyAlias)
	}
	if ra.RetentionDaysOrDefault() != 365 {
		t.Errorf("retention_days = %d, want 365", ra.RetentionDaysOrDefault())
	}
	if ra.ObjectLockModeOrDefault() != "COMPLIANCE" {
		t.Errorf("object_lock_mode = %q, want COMPLIANCE", ra.ObjectLockModeOrDefault())
	}
}

// TestReportArchiveConfig_RequiredWhenEnabled: enabling the archive without an
// endpoint / bucket / kms alias is a fail-fast load error (the ForensicsConfig
// precedent).
func TestReportArchiveConfig_RequiredWhenEnabled(t *testing.T) {
	for _, tc := range []struct {
		name, block, wantField string
	}{
		{
			"no endpoint",
			"  report_archive:\n    enabled: true\n    s3_bucket: b\n    kms_key_alias: alias/k\n",
			"s3_endpoint",
		},
		{
			"no bucket",
			"  report_archive:\n    enabled: true\n    s3_endpoint: e\n    kms_key_alias: alias/k\n",
			"s3_bucket",
		},
		{
			"no kms alias",
			"  report_archive:\n    enabled: true\n    s3_endpoint: e\n    s3_bucket: b\n",
			"kms_key_alias",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := config.Load(writeConfig(t, reportArchiveBaseYAML+tc.block))
			if err == nil {
				t.Fatalf("want a required-when-enabled error for %s", tc.wantField)
			}
			if !strings.Contains(err.Error(), tc.wantField) {
				t.Errorf("error does not name %q: %v", tc.wantField, err)
			}
		})
	}
}

// TestReportArchiveConfig_ObjectLockModeEnum: an object_lock_mode outside
// {GOVERNANCE, COMPLIANCE} is a load-time error.
func TestReportArchiveConfig_ObjectLockModeEnum(t *testing.T) {
	yaml := reportArchiveBaseYAML + "  report_archive:\n    object_lock_mode: LENIENT\n"
	_, err := config.Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("want rejection of object_lock_mode: LENIENT")
	}
	if !strings.Contains(err.Error(), "object_lock_mode") {
		t.Errorf("error does not name object_lock_mode: %v", err)
	}
}

// TestReportArchiveConfig_RetentionDaysPositive: a non-positive retention_days
// is a load-time error.
func TestReportArchiveConfig_RetentionDaysPositive(t *testing.T) {
	yaml := reportArchiveBaseYAML + "  report_archive:\n    retention_days: 0\n"
	_, err := config.Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("want rejection of retention_days: 0")
	}
	if !strings.Contains(err.Error(), "retention_days") {
		t.Errorf("error does not name retention_days: %v", err)
	}
}

// TestReportArchiveConfig_DeferredDefaults: the Story 4.7 deferred-queue knobs
// default to disabled, a 1000-report cap, and a 5s drain cadence.
func TestReportArchiveConfig_DeferredDefaults(t *testing.T) {
	cfg, err := config.Load(writeConfig(t, reportArchiveBaseYAML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	ra := cfg.Response.ReportArchive
	if ra.DeferredEnabledOrDefault() {
		t.Error("deferred queue must default to disabled (opt-in)")
	}
	if ra.DeferredMaxLenOrDefault() != 1000 {
		t.Errorf("deferred_max_len must default to 1000, got %d", ra.DeferredMaxLenOrDefault())
	}
	if ra.DeferredDrainSecondsOrDefault() != 5 {
		t.Errorf("deferred_drain_seconds must default to 5, got %d", ra.DeferredDrainSecondsOrDefault())
	}
}

// TestReportArchiveConfig_DeferredKnobsParse: the deferred-queue knobs decode
// through Load with their flat yaml keys.
func TestReportArchiveConfig_DeferredKnobsParse(t *testing.T) {
	yaml := reportArchiveBaseYAML + `  report_archive:
    enabled: true
    s3_endpoint: "s3.example.com"
    s3_bucket: "olaitan-reports"
    kms_key_alias: "alias/olaitan-reports"
    deferred_enabled: true
    deferred_redis_addr: "redis:6379"
    deferred_max_len: 500
    deferred_drain_seconds: 10
`
	cfg, err := config.Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	ra := cfg.Response.ReportArchive
	if !ra.DeferredEnabledOrDefault() {
		t.Error("deferred_enabled=true must survive the loader")
	}
	if ra.DeferredRedisAddr != "redis:6379" {
		t.Errorf("deferred_redis_addr = %q", ra.DeferredRedisAddr)
	}
	if ra.DeferredMaxLenOrDefault() != 500 {
		t.Errorf("deferred_max_len = %d, want 500", ra.DeferredMaxLenOrDefault())
	}
	if ra.DeferredDrainSecondsOrDefault() != 10 {
		t.Errorf("deferred_drain_seconds = %d, want 10", ra.DeferredDrainSecondsOrDefault())
	}
}

// TestReportArchiveConfig_DeferredRedisAddrRequired: enabling the deferred queue
// without a redis addr is a fail-fast load error.
func TestReportArchiveConfig_DeferredRedisAddrRequired(t *testing.T) {
	yaml := reportArchiveBaseYAML + "  report_archive:\n    enabled: true\n    s3_endpoint: e\n    s3_bucket: b\n    kms_key_alias: alias/k\n    deferred_enabled: true\n"
	_, err := config.Load(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("want a required-when-enabled error for deferred_redis_addr")
	}
	if !strings.Contains(err.Error(), "deferred_redis_addr") {
		t.Errorf("error does not name deferred_redis_addr: %v", err)
	}
}

// TestReportArchiveConfig_DeferredKnobsPositive: a non-positive deferred_max_len
// or deferred_drain_seconds is a load-time error.
func TestReportArchiveConfig_DeferredKnobsPositive(t *testing.T) {
	for _, tc := range []struct{ name, block, field string }{
		{"max_len zero", "  report_archive:\n    deferred_max_len: 0\n", "deferred_max_len"},
		{"drain seconds zero", "  report_archive:\n    deferred_drain_seconds: 0\n", "deferred_drain_seconds"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := config.Load(writeConfig(t, reportArchiveBaseYAML+tc.block))
			if err == nil {
				t.Fatalf("want rejection of %s", tc.field)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("error does not name %q: %v", tc.field, err)
			}
		})
	}
}
