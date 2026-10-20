//go:build helm

package helm_test

// #155: the chart rendered a ValidatingWebhookConfiguration (`<fullname>-audit`,
// webhook audit.olaitan.io) pointed at the audit receiver's :8443/audit. The
// receiver requires a client certificate signed by the audit CA with CN
// kube-apiserver (mTLS, internal/collector/audit/audit.go); the API server's
// admission client presents none, so every covered admission call failed with
// "tls: certificate required" and failed open. The stub is gone
// (ADR-2026-10-19-02). These tests pin that every admission webhook the chart
// renders can authenticate to what it dials: none of them may dial the mTLS
// audit receiver, in any shipped profile.

import (
	"path/filepath"
	"strings"
	"testing"
)

// admissionRenders renders the profiles an operator can install: the plain
// default, operator-supplied audit material, and every shipped values file
// that renders on its own.
func admissionRenders(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{
		"default":       renderArgs(t),
		"operator-tls":  helmTemplate(t, auditWebhookEnabledArgs()),
		"audit-enabled": renderArgs(t, "--set", "auditWebhook.enabled=true"),
	}
	for _, f := range []string{"values-full.yaml", "values-minimal.yaml", "values-kind.yaml", "values-production.yaml", "values-airgapped.yaml", "values-k3s.yaml"} {
		out[f] = renderArgs(t, "-f", filepath.Join(chartDir(t), f))
	}
	return out
}

func TestNoAdmissionWebhookDialsTheMTLSAuditReceiver(t *testing.T) {
	for name, rendered := range admissionRenders(t) {
		t.Run(name, func(t *testing.T) {
			if n := len(docsOfKind(t, rendered, "ValidatingWebhookConfiguration")); n != 0 {
				t.Errorf("%d ValidatingWebhookConfiguration rendered; the audit admission stub (#155) must not ship", n)
			}
			if strings.Contains(rendered, "audit.olaitan.io") {
				t.Error("webhook audit.olaitan.io is rendered (#155)")
			}
			for _, kind := range []string{"MutatingWebhookConfiguration", "ValidatingWebhookConfiguration"} {
				for _, w := range docsOfKind(t, rendered, kind) {
					for _, hook := range asList(w["webhooks"]) {
						svc, _ := dig(hook, "clientConfig", "service", "name").(string)
						path, _ := dig(hook, "clientConfig", "service", "path").(string)
						if strings.HasSuffix(svc, "-audit-webhook") || path == "/audit" {
							t.Errorf("%s %v webhook %v dials the audit receiver (%s%s), which requires an API-server client certificate the admission client never presents",
								kind, dig(w, "metadata", "name"), dig(hook, "name"), svc, path)
						}
					}
				}
			}
		})
	}
}

// certgen no longer patches, or holds RBAC on, a ValidatingWebhookConfiguration.
func TestCertgenTouchesNoValidatingWebhook(t *testing.T) {
	rendered := renderArgs(t)
	for _, j := range docsOfKind(t, rendered, "Job") {
		if n, _ := dig(j, "metadata", "name").(string); !strings.HasPrefix(n, "olaitan-certgen-") {
			continue
		}
		for _, c := range asList(dig(j, "spec", "template", "spec", "containers")) {
			for _, a := range toStrings(asList(dig(c, "args"))) {
				if strings.HasPrefix(a, "--validating-webhook") {
					t.Errorf("certgen still gets %q (#155)", a)
				}
			}
		}
	}
	cr := docNamed(t, rendered, "ClusterRole", "olaitan-certgen")
	for _, rule := range asList(cr["rules"]) {
		if containsAny(asList(dig(rule, "resources")), "validatingwebhookconfigurations") {
			t.Error("certgen ClusterRole still grants validatingwebhookconfigurations (#155)")
		}
	}
}
