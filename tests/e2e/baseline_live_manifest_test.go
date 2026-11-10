//go:build e2e

package e2e_test

import (
	"regexp"
	"strings"
	"testing"
)

// Story 12.8 (#230), no cluster. The 2026-10-20 live run's API burst never
// reached kube-apiserver: busybox wget failed the TLS handshake and
// `|| true` hid it. These pin the fixed manifest and the log the test now
// reads to prove the burst landed.

func TestBaselineLiveManifestAPIBurstUsesAVerifyingTLSClient(t *testing.T) {
	m := baselineLiveManifest("olt-bl-test")
	if !regexp.MustCompile(`(?m)^\s+image: curlimages/curl:[0-9.]+@sha256:[0-9a-f]{64}$`).MatchString(m) {
		t.Errorf("steady workload image is not curl pinned by tag and digest:\n%s", m)
	}
	// Nowhere in the manifest may certificate checks be skipped.
	if strings.Contains(m, "--no-check-certificate") || regexp.MustCompile(`\s-k(\s|$)|--insecure|-[a-zA-Z]*k[a-zA-Z]*\s+--cacert`).MatchString(m) {
		t.Error("the manifest skips certificate verification somewhere")
	}
	for _, line := range strings.Split(m, "\n") {
		if !strings.Contains(line, "kubernetes.default.svc") && !strings.Contains(line, `"$U"`) {
			continue
		}
		if strings.Contains(line, "|| true") {
			t.Errorf("the apiserver call swallows its error: %s", strings.TrimSpace(line))
		}
	}
	for _, want := range []string{`--cacert "$CA"`, "serviceaccount/ca.crt", "apiserver_get_failed", "gets=$n ok=$ok", "%{http_code}"} {
		if !strings.Contains(m, want) {
			t.Errorf("manifest misses %q", want)
		}
	}
}

func TestBaselineLiveSteadyLogParse(t *testing.T) {
	logs := strings.Join([]string{
		"2026-10-20T13:01:00Z cycle=1 mode=steady gets=2 ok=2",
		"apiserver_get_failed cycle=2 code=000 err=curl: (35) TLS connect error",
		"2026-10-20T13:02:00Z cycle=2 mode=steady gets=3 ok=0",
		"some unrelated line ok=1",
		"cycle=3 cycle=4 gets=3 ok=0",
		"2026-10-20T13:03:00Z cycle=3 mode= gets=3 ok=3",
		"2026-10-20T14:02:00Z cycle=61 mode=deviate gets=80 ok=80",
		"",
	}, "\n")
	got := parseSteadyLog(logs)
	want := []steadyCycle{{1, "steady", 2, 2}, {2, "steady", 3, 0}, {61, "deviate", 80, 80}}
	if len(got) != len(want) {
		t.Fatalf("parsed %d cycles %+v, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("cycle %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}
