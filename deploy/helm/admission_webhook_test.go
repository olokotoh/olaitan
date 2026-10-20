//go:build helm

package helm_test

// #155: the chart rendered a ValidatingWebhookConfiguration (`<fullname>-audit`,
// webhook audit.olaitan.io) pointed at the audit receiver's :8443/audit. The
// receiver requires a client certificate signed by the audit CA with CN
// kube-apiserver (mTLS, internal/collector/audit/audit.go); the API server's
// admission client presents none, so every covered admission call failed with
// "tls: certificate required" and failed open. The stub is gone
// (ADR-2026-10-19-02).
//
// The issue asks for a render test that the rendered admission webhooks can
// authenticate to what they dial. Both halves are pinned here, in every
// shipped profile: no admission webhook dials the mTLS audit receiver, and
// every admission webhook that is rendered dials a Service of the same render
// that routes to the applog injector (a server-auth-only TLS listener), with
// a generated serving cert that names the host the API server dials.

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// admissionRenders renders the plain default, the mode combinations that
// change what certgen and the webhooks render, and every shipped values file.
func admissionRenders(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{
		"default":      renderArgs(t),
		"operator-tls": helmTemplate(t, auditWebhookEnabledArgs()),
		"applog-off":   renderArgs(t, "--set", "applogSidecar.enabled=false"),
		"audit-off":    renderArgs(t, "--set", "auditWebhook.enabled=false"),
	}
	files, err := filepath.Glob(filepath.Join(chartDir(t), "values-*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no values-*.yaml overlays found: %v", err)
	}
	sort.Strings(files)
	for _, f := range files {
		out[filepath.Base(f)] = renderArgs(t, "-f", f)
	}
	return out
}

// dialsAuditReceiver reports whether a webhook clientConfig points at the
// audit receiver, by Service or by URL.
func dialsAuditReceiver(hook any) (bool, string) {
	svc, _ := dig(hook, "clientConfig", "service", "name").(string)
	path, _ := dig(hook, "clientConfig", "service", "path").(string)
	if strings.HasSuffix(svc, "-audit-webhook") || strings.HasPrefix(path, "/audit") {
		return true, svc + path
	}
	if url, _ := dig(hook, "clientConfig", "url").(string); strings.Contains(url, "audit-webhook") || strings.Contains(url, "/audit") {
		return true, url
	}
	return false, ""
}

func TestNoAdmissionWebhookDialsTheMTLSAuditReceiver(t *testing.T) {
	for name, rendered := range admissionRenders(t) {
		t.Run(name, func(t *testing.T) {
			if n := len(docsOfKind(t, rendered, "ValidatingWebhookConfiguration")); n != 0 {
				t.Errorf("%d ValidatingWebhookConfiguration rendered; the audit admission stub (#155) must not ship", n)
			}
			for _, kind := range []string{"MutatingWebhookConfiguration", "ValidatingWebhookConfiguration"} {
				for _, w := range docsOfKind(t, rendered, kind) {
					for _, hook := range asList(w["webhooks"]) {
						if dig(hook, "name") == "audit.olaitan.io" {
							t.Errorf("%s %v renders webhook audit.olaitan.io (#155)", kind, dig(w, "metadata", "name"))
						}
						if bad, target := dialsAuditReceiver(hook); bad {
							t.Errorf("%s %v webhook %v dials the audit receiver (%s), which requires an API-server client certificate the admission client never presents",
								kind, dig(w, "metadata", "name"), dig(hook, "name"), target)
						}
					}
				}
			}
		})
	}
}

// The positive half: every admission webhook that is rendered dials a
// Service in the same render, on a port that reaches the applog injector's
// container port, and (in the certgen mode) the generated serving cert names
// <service>.<namespace>.svc, the host the API server dials.
func TestEveryAdmissionWebhookDialsAServerItCanAuthenticateTo(t *testing.T) {
	for name, rendered := range admissionRenders(t) {
		t.Run(name, func(t *testing.T) {
			for _, kind := range []string{"MutatingWebhookConfiguration", "ValidatingWebhookConfiguration"} {
				for _, w := range docsOfKind(t, rendered, kind) {
					for _, hook := range asList(w["webhooks"]) {
						checkWebhookTarget(t, rendered, fmt.Sprintf("%s %v", kind, dig(w, "metadata", "name")), hook)
					}
				}
			}
		})
	}
}

func checkWebhookTarget(t *testing.T, rendered, what string, hook any) {
	t.Helper()
	svcName, _ := dig(hook, "clientConfig", "service", "name").(string)
	svcNS, _ := dig(hook, "clientConfig", "service", "namespace").(string)
	port := dig(hook, "clientConfig", "service", "port")
	if svcName == "" {
		t.Errorf("%s dials no in-release Service (url %v)", what, dig(hook, "clientConfig", "url"))
		return
	}
	var svc map[string]any
	for _, s := range docsOfKind(t, rendered, "Service") {
		if dig(s, "metadata", "name") == svcName {
			svc = s
		}
	}
	if svc == nil {
		t.Errorf("%s dials Service %s, which the render does not contain", what, svcName)
		return
	}
	var target any
	for _, p := range asList(dig(svc, "spec", "ports")) {
		if dig(p, "port") == port {
			target = dig(p, "targetPort")
		}
	}
	if target == nil {
		t.Errorf("%s dials %s:%v, a port the Service does not expose", what, svcName, port)
		return
	}
	// The selected workload must be the applog injector (the only admission
	// server the chart ships, server-auth TLS only), listening on targetPort.
	sel, _ := dig(svc, "spec", "selector").(map[string]any)
	if sel["app.kubernetes.io/component"] != "applog-injector" {
		t.Errorf("%s dials Service %s selecting %v, not the applog injector", what, svcName, sel)
		return
	}
	d := docNamed(t, rendered, "Deployment", svcName)
	c := podContainers(d, "containers")["applog-injector"]
	if c == nil || !containsAny(asList(c["args"]), "applog-webhook") {
		t.Errorf("%s: Deployment %s does not run `olaitan applog-webhook`", what, svcName)
		return
	}
	listening := false
	for _, cp := range asList(c["ports"]) {
		if dig(cp, "containerPort") == target || dig(cp, "name") == target {
			listening = true
		}
	}
	if !listening {
		t.Errorf("%s: Service %s targets %v, which the injector container does not expose", what, svcName, target)
	}
	// certgen mode: the generated serving cert covers the dialled host.
	for _, j := range docsOfKind(t, rendered, "Job") {
		if n, _ := dig(j, "metadata", "name").(string); !strings.HasPrefix(n, "olaitan-certgen-") {
			continue
		}
		for _, cc := range asList(dig(j, "spec", "template", "spec", "containers")) {
			for _, a := range toStrings(asList(dig(cc, "args"))) {
				if dns, ok := strings.CutPrefix(a, "--applog-dns="); ok {
					if !containsAny(toAny(strings.Split(dns, ",")), svcName+"."+svcNS+".svc") {
						t.Errorf("%s: certgen --applog-dns %q lacks %s.%s.svc, the host the API server dials", what, dns, svcName, svcNS)
					}
				}
			}
		}
	}
}

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// certgen no longer patches, or holds RBAC on, a ValidatingWebhookConfiguration,
// and with only the audit part generated it renders nothing cluster-scoped.
func TestCertgenTouchesNoValidatingWebhook(t *testing.T) {
	certgenJob := func(t *testing.T, rendered string) map[string]any {
		t.Helper()
		for _, j := range docsOfKind(t, rendered, "Job") {
			if n, _ := dig(j, "metadata", "name").(string); strings.HasPrefix(n, "olaitan-certgen-") {
				return j
			}
		}
		t.Fatal("no olaitan-certgen-* Job rendered")
		return nil
	}
	jobArgs := func(j map[string]any) string {
		var all []string
		for _, c := range asList(dig(j, "spec", "template", "spec", "containers")) {
			all = append(all, toStrings(asList(dig(c, "args")))...)
		}
		return strings.Join(all, " ")
	}
	clusterScoped := func(t *testing.T, rendered, kind string) map[string]any {
		t.Helper()
		for _, d := range docsOfKind(t, rendered, kind) {
			if dig(d, "metadata", "name") == "olaitan-certgen" {
				return d
			}
		}
		return nil
	}

	t.Run("default", func(t *testing.T) {
		rendered := renderArgs(t)
		if a := jobArgs(certgenJob(t, rendered)); strings.Contains(a, "--validating-webhook") {
			t.Errorf("certgen still gets --validating-webhook (#155): %s", a)
		}
		cr := clusterScoped(t, rendered, "ClusterRole")
		if cr == nil {
			t.Fatal("no certgen ClusterRole with the applog part generated")
		}
		for _, rule := range asList(cr["rules"]) {
			if containsAny(asList(dig(rule, "resources")), "validatingwebhookconfigurations") {
				t.Error("certgen ClusterRole still grants validatingwebhookconfigurations (#155)")
			}
		}
		if clusterScoped(t, rendered, "ClusterRoleBinding") == nil {
			t.Error("certgen ClusterRole rendered without its ClusterRoleBinding")
		}
	})

	// Audit generated, applog not (off, or cert-manager): Role, RoleBinding
	// and the Job only; no ClusterRole and no dangling ClusterRoleBinding.
	for name, args := range map[string][]string{
		"applog-off":          {"--set", "applogSidecar.enabled=false"},
		"applog-cert-manager": {"--set", "applogSidecar.tls.certManagerEnabled=true"},
	} {
		t.Run(name, func(t *testing.T) {
			rendered := renderArgs(t, args...)
			a := jobArgs(certgenJob(t, rendered))
			if !strings.Contains(a, "--audit-secret=olaitan-audit-tls") || strings.Contains(a, "--applog-secret") || strings.Contains(a, "--validating-webhook") {
				t.Errorf("certgen args %q: want the audit part only", a)
			}
			if clusterScoped(t, rendered, "ClusterRole") != nil || clusterScoped(t, rendered, "ClusterRoleBinding") != nil {
				t.Error("certgen renders cluster-scoped RBAC with nothing cluster-scoped to patch")
			}
			if docNamed(t, rendered, "Role", "olaitan-certgen") == nil || docNamed(t, rendered, "RoleBinding", "olaitan-certgen") == nil {
				t.Error("certgen Role/RoleBinding missing")
			}
		})
	}
}
