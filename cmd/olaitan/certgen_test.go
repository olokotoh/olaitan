package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Story 12.7 D1: `olaitan certgen` is what the chart's certgen Job runs.
func TestParseCertgenFlags(t *testing.T) {
	var stderr bytes.Buffer
	spec, err := parseCertgenFlags([]string{
		"--namespace=olaitan",
		"--audit-secret=olaitan-audit-tls",
		"--audit-kubeconfig-secret=olaitan-audit-webhook-kubeconfig",
		"--audit-dns=a,a.olaitan.svc",
		"--audit-ip=127.0.0.1",
		"--audit-server=a.olaitan.svc.cluster.local:8443",
		"--applog-secret=olaitan-applog-injector-tls",
		"--applog-dns=b,b.olaitan.svc",
		"--mutating-webhook=olaitan-applog-injector",
		"--label=app.kubernetes.io/instance=olaitan",
		"--validity=87600h",
	}, &stderr)
	if err != nil {
		t.Fatalf("parseCertgenFlags: %v\n%s", err, stderr.String())
	}
	if spec.Namespace != "olaitan" || spec.AuditServer != "a.olaitan.svc.cluster.local:8443" ||
		!reflect.DeepEqual(spec.AuditDNSNames, []string{"a", "a.olaitan.svc"}) ||
		!reflect.DeepEqual(spec.AuditIPs, []string{"127.0.0.1"}) ||
		!reflect.DeepEqual(spec.ApplogDNSNames, []string{"b", "b.olaitan.svc"}) ||
		spec.Labels["app.kubernetes.io/instance"] != "olaitan" ||
		spec.Validity != 87600*time.Hour {
		t.Errorf("spec = %+v", spec)
	}
	if _, err := parseCertgenFlags([]string{"--namespace=olaitan"}, &stderr); err == nil {
		t.Error("a certgen run with nothing to do parsed")
	}
	// #155: the audit admission stub is gone. An older chart's Job may still
	// pass --validating-webhook; it parses, warns and changes nothing.
	stderr.Reset()
	old, err := parseCertgenFlags([]string{"--namespace=olaitan",
		"--audit-secret=a", "--audit-kubeconfig-secret=k", "--audit-dns=a", "--audit-server=a:8443",
		"--validating-webhook=olaitan-audit"}, &stderr)
	if err != nil {
		t.Errorf("--validating-webhook from an older chart failed the run: %v", err)
	}
	if !strings.Contains(stderr.String(), "deprecated and ignored") {
		t.Errorf("no deprecation warning for --validating-webhook: %q", stderr.String())
	}
	if old.AuditSecret != "a" || old.MutatingWebhook != "" {
		t.Errorf("spec = %+v", old)
	}
	if _, err := parseCertgenFlags([]string{"--namespace=olaitan", "--applog-secret=x", "--label=novalue"}, &stderr); err == nil {
		t.Error("a malformed --label parsed")
	}
}

func TestRun_DispatchesCertgen_BadFlags_Exits1(t *testing.T) {
	var stderr bytes.Buffer
	if code := run([]string{"certgen", "--namespace="}, &stderr); code != 1 {
		t.Errorf("certgen with no namespace exited %d, want 1", code)
	}
}
