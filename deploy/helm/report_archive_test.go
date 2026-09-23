//go:build helm

package helm_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

// streamOverrideEnv returns the value of every OLT_NATS_STREAM_MAXBYTES_OVERRIDE
// env entry in the rendered manifests, one per workload that carries it.
func streamOverrideEnv(rendered string) []string {
	re := regexp.MustCompile(`- name: OLT_NATS_STREAM_MAXBYTES_OVERRIDE\s*\n\s*value:\s*(.*)`)
	var got []string
	for _, m := range re.FindAllStringSubmatch(rendered, -1) {
		got = append(got, strings.TrimSpace(m[1]))
	}
	return got
}

// helmRender runs `helm template` with raw extra args (so a test can use -f
// and --set-json, not only --set) and returns stdout, stderr and the error.
func helmRender(t *testing.T, extra ...string) (string, string, error) {
	t.Helper()
	args := append([]string{"template", "olaitan", chartDir(t),
		"--set", "secrets.redisPassword=test-password"}, extra...)
	cmd := exec.Command("helm", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// TestStreamMaxBytesOverrideSurvivesEveryRoute is AC2. The aggregator
// (internal/nats/streams.go) parses OLT_NATS_STREAM_MAXBYTES_OVERRIDE with
// strconv.ParseInt and, on failure, silently drops the cap. A values file
// (-f, the normal operator route) and --set-json both hand Helm an unquoted
// integer as float64, and `quote` then renders "5.36870912e+08", so the cap
// vanished without any error and streams got production MaxBytes on a small
// PVC. `--set` happens to parse bare integers as int64 in Helm 3.16, which is
// why a --set-only probe looked clean. Every route must render plain digits.
//
// The value is deliberately NOT the chart default (536870912), so the check
// cannot pass by the operator's value being ignored.
func TestStreamMaxBytesOverrideSurvivesEveryRoute(t *testing.T) {
	const want = `"1073741824"`
	valuesFile := filepath.Join(t.TempDir(), "override.yaml")
	if err := os.WriteFile(valuesFile, []byte("nats:\n  streamMaxBytesOverride: 1073741824\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	routes := map[string][]string{
		"--set":        {"--set", "nats.streamMaxBytesOverride=1073741824"},
		"--set-string": {"--set-string", "nats.streamMaxBytesOverride=1073741824"},
		"--set-json":   {"--set-json", "nats.streamMaxBytesOverride=1073741824"},
		"-f values":    {"-f", valuesFile},
	}
	for name, args := range routes {
		t.Run(name, func(t *testing.T) {
			out, stderr, err := helmRender(t, args...)
			if err != nil {
				t.Fatalf("helm template %v failed: %v\n%s", args, err, stderr)
			}
			got := streamOverrideEnv(out)
			// Two consumers: the aggregator Deployment and the collector DaemonSet.
			if len(got) != 2 {
				t.Fatalf("want OLT_NATS_STREAM_MAXBYTES_OVERRIDE on the Deployment and the DaemonSet (2), got %d: %v", len(got), got)
			}
			for _, v := range got {
				if v != want {
					t.Errorf("%s: OLT_NATS_STREAM_MAXBYTES_OVERRIDE rendered as %s, want %s; "+
						"streams.go ParseInt would reject it and silently drop the cap", name, v, want)
				}
			}
		})
	}
}

// TestStreamMaxBytesOverrideRejectsNonDigits: a value that cannot be a byte
// count must fail the install instead of rendering something the aggregator
// silently ignores.
func TestStreamMaxBytesOverrideRejectsNonDigits(t *testing.T) {
	for _, bad := range []string{"512Mi", "-1", "1.5", "0"} {
		_, stderr, err := helmRender(t, "--set-string", "nats.streamMaxBytesOverride="+bad)
		if err == nil {
			t.Errorf("nats.streamMaxBytesOverride=%q rendered; want a fail-fast error", bad)
			continue
		}
		if !strings.Contains(stderr, "streamMaxBytesOverride") {
			t.Errorf("nats.streamMaxBytesOverride=%q failed without naming the value: %s", bad, stderr)
		}
	}
	// Empty stays the production path: no env var at all.
	out, stderr, err := helmRender(t, "--set-string", "nats.streamMaxBytesOverride=")
	if err != nil {
		t.Fatalf("empty override must render: %v\n%s", err, stderr)
	}
	if got := streamOverrideEnv(out); len(got) != 0 {
		t.Errorf("empty override must render no OLT_NATS_STREAM_MAXBYTES_OVERRIDE, got %v", got)
	}
}

// TestFixtureKMSKeyMatchesEveryAlias is AC3, found by the AC4 live run. The
// MinIO fixture's built-in KMS knows exactly one key, named in
// MINIO_KMS_SECRET_KEY as "<name>:<base64>", and rejects an SSE-KMS PUT that
// names any other. The fixture shipped the key "olaitan-e2e-key" while the
// forensics target and CI job still passed "alias/olaitan-e2e", so the
// validator was satisfiable on paper and every archive PUT would still have
// failed. Every place that points the chart at this fixture must name the
// fixture's key.
func TestFixtureKMSKeyMatchesEveryAlias(t *testing.T) {
	root := repoRoot(t)
	read := func(rel string) string {
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		return string(b)
	}

	m := regexp.MustCompile(`MINIO_KMS_SECRET_KEY\s*\n\s*value:\s*"([^":]+):`).FindStringSubmatch(read("tests/e2e/fixtures/minio.yaml"))
	if m == nil {
		t.Fatal("tests/e2e/fixtures/minio.yaml has no MINIO_KMS_SECRET_KEY \"<name>:<key>\" value")
	}
	key := m[1]

	aliasRE := regexp.MustCompile(`kms_key_alias[=:]\s*'?"?([^'"\s\\]+)`)
	for _, rel := range []string{
		"Makefile",
		".github/workflows/ci.yml",
		"tests/e2e/fixtures/report-archive-full-values.yaml",
	} {
		found := aliasRE.FindAllStringSubmatch(read(rel), -1)
		if len(found) == 0 {
			t.Errorf("%s sets no kms_key_alias; this guard expects it to point the chart at the MinIO fixture", rel)
		}
		for _, f := range found {
			if f[1] != key {
				t.Errorf("%s passes kms_key_alias %q, but the MinIO fixture's KMS only knows %q", rel, f[1], key)
			}
		}
	}
}

// makeTarget returns the recipe of one Makefile target: its rule line and
// every following tab-indented line.
func makeTarget(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(b), "\n")
	for i, l := range lines {
		if !strings.HasPrefix(l, name+":") {
			continue
		}
		out := []string{l}
		for _, r := range lines[i+1:] {
			if !strings.HasPrefix(r, "\t") {
				break
			}
			out = append(out, r)
		}
		return strings.Join(out, "\n")
	}
	t.Fatalf("Makefile has no %s target", name)
	return ""
}

// TestReportArchiveTargetIsRerunnable covers two review findings on the
// e2e-full-report-archive target (Story 10.7 round 1).
//
// fake-llm.yaml runs image olaitan:dev with imagePullPolicy Never, so after
// `kind load` of a new build an unchanged `kubectl apply` leaves the old pod
// (and the old fake-LLM binary) running. The target must restart it.
//
// The target layers its overlay with --reuse-values, so the fake-LLM
// endpoints, the 5s warm-up and the archive stay in the shared kind-full
// release afterwards. A later run that also reuses values (Story 10.6's
// real-LLM run) would talk to fake-llm without saying so. The target must
// tell the operator that, and how to restore the profile.
func TestReportArchiveTargetIsRerunnable(t *testing.T) {
	recipe := makeTarget(t, "e2e-full-report-archive")
	load := strings.Index(recipe, "kind load docker-image")
	restart := strings.Index(recipe, "rollout restart deploy/fake-llm")
	status := strings.Index(recipe, "rollout status deploy/fake-llm")
	if load < 0 || restart < load || status < restart {
		t.Errorf("e2e-full-report-archive must `kubectl rollout restart deploy/fake-llm` and wait on `rollout status` after `kind load`, "+
			"or a rerun tests the previous fake-LLM binary (load=%d restart=%d status=%d)", load, restart, status)
	}
	if !strings.Contains(recipe, "overlay stays in the release") || !strings.Contains(recipe, "make e2e-full restores") {
		t.Error("e2e-full-report-archive must print that its overlay stays in the kind-full release and that `make e2e-full` restores the profile")
	}
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "tests/e2e/fixtures/report-archive-full-values.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "make e2e-full restores") {
		t.Error("report-archive-full-values.yaml header must say the overlay persists and that `make e2e-full` restores the profile")
	}
}

// TestFullProfileVariablesDefinedOnce: e2e-full-report-archive once carried
// its own copies of Story 10.5's FULL_CLUSTER_NAME / FULL_OUT_DIR defaults so
// it could land before 10.5. Two `?=` definitions can drift apart silently
// (the first one wins), so there must be exactly one of each.
func TestFullProfileVariablesDefinedOnce(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"FULL_CLUSTER_NAME", "FULL_OUT_DIR"} {
		n := len(regexp.MustCompile(`(?m)^`+v+`\s*\?=`).FindAllString(string(b), -1))
		if n != 1 {
			t.Errorf("Makefile defines %s %d times, want exactly 1", v, n)
		}
	}
}
