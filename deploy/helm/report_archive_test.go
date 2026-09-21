//go:build helm

package helm_test

import (
	"strings"
	"testing"
)

// Story 10.7. Four defects found on 2026-09-04 (defence eve) stopped the
// report archive working unless full forensics was also switched on. These
// are the chart-side two; the fake-LLM DFIR role and the MinIO KMS fixture
// are covered by their own tests.

// TestReportArchiveGetsS3CredentialsWithoutForensics is AC1: report archiving
// must work with forensics off.
//
// The aggregator reads S3_ACCESS_KEY / S3_SECRET_KEY from the environment.
// Until this story the projection was gated solely on
// response.forensics.enabled (deployment.yaml), on the reasonable-sounding
// grounds that "a non-forensic deployment carries no S3 credentials". But the
// report archive is a SECOND consumer of the same bucket, and it is enabled by
// a different flag. An operator who wants archived reports without forensics
// therefore got a deployment whose archive uploader had no credentials at all,
// which surfaces at runtime rather than at install.
func TestReportArchiveGetsS3CredentialsWithoutForensics(t *testing.T) {
	out := helmTemplate(t, []string{
		"response.reportArchive.enabled=true",
		"response.forensics.enabled=false",
	})
	for _, key := range []string{"S3_ACCESS_KEY", "S3_SECRET_KEY"} {
		if !strings.Contains(out, "name: "+key) {
			t.Errorf("reportArchive.enabled=true with forensics.enabled=false renders no %s env var; "+
				"the archive uploader would start with no credentials", key)
		}
	}
}

// TestForensicsStillGetsS3CredentialsAlone guards the other direction, so the
// fix above cannot be implemented by simply projecting the credentials
// unconditionally: a deployment with neither consumer enabled must still carry
// no S3 credentials (NFR8).
func TestForensicsStillGetsS3CredentialsAlone(t *testing.T) {
	with := helmTemplate(t, []string{
		"response.forensics.enabled=true",
		"response.reportArchive.enabled=false",
	})
	if !strings.Contains(with, "name: S3_ACCESS_KEY") {
		t.Error("forensics.enabled=true alone must still project S3_ACCESS_KEY")
	}

	without := helmTemplate(t, []string{
		"response.forensics.enabled=false",
		"response.reportArchive.enabled=false",
	})
	if strings.Contains(without, "name: S3_ACCESS_KEY") {
		t.Error("with neither forensics nor reportArchive enabled the deployment must carry no S3 credentials (NFR8)")
	}
}

// TestStreamMaxBytesOverrideSurvivesSet is AC2. `--set` parses a bare integer
// as a float64, so a large byte count renders in scientific notation
// (5.36870912e+08) and NATS rejects it. The chart's own default is already a
// quoted string; the defect is that an operator following the documented
// `--set` route gets the float. The value must reach the rendered config as
// plain digits whichever route is used.
func TestStreamMaxBytesOverrideSurvivesSet(t *testing.T) {
	out := helmTemplate(t, []string{"nats.streamMaxBytesOverride=536870912"})
	if strings.Contains(out, "5.36870912e+08") || strings.Contains(out, "5.36870912e8") {
		t.Error("--set nats.streamMaxBytesOverride=536870912 rendered in scientific notation; " +
			"NATS cannot parse it. Type the value as a string in the schema, or parse the float.")
	}
	if !strings.Contains(out, "536870912") {
		t.Error("--set nats.streamMaxBytesOverride=536870912 did not reach the rendered manifest as plain digits")
	}
}
