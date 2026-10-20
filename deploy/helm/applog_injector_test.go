//go:build helm

package helm_test

// #156, #157, #159: the applog injector on the default install (Story 12.7).
//
//   #156 a rollout dropped one admission call (connection refused): an old pod
//        stopped listening while it was still an endpoint. The pods now drain
//        (not-ready, keep serving for shutdownDelaySeconds), the rollout
//        surges before it removes a pod, and a PDB keeps one up on a drain.
//   #157 the injector reloads its serving cert from the mounted Secret, so the
//        readiness probe it answers is /readyz (drain-aware), not /healthz.
//   #159 the webhook no longer admits the injector's own pods, so under
//        failurePolicy Fail a broken injector cannot block its replacements.

import (
	"strconv"
	"strings"
	"testing"
)

const applogCABundle = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCg=="

func injectorDeployment(t *testing.T, rendered string) map[string]any {
	t.Helper()
	return docNamed(t, rendered, "Deployment", "olaitan-applog-injector")
}

func injectorContainer(t *testing.T, rendered string) map[string]any {
	t.Helper()
	c := podContainers(injectorDeployment(t, rendered), "containers")["applog-injector"]
	if c == nil {
		t.Fatal("no applog-injector container")
	}
	return c
}

// excludedBy reports whether a Pod with these labels is excluded
// by the objectSelector (every NotIn expression on a key the pod carries).
func excludedBy(selector map[string]any, labels map[string]any) bool {
	for _, ex := range asList(selector["matchExpressions"]) {
		key, _ := dig(ex, "key").(string)
		op, _ := dig(ex, "operator").(string)
		v, has := labels[key]
		if op == "NotIn" && has && containsAny(asList(dig(ex, "values")), v.(string)) {
			return true
		}
	}
	return false
}

// #159 across the TLS modes, including the two where failurePolicy Fail is
// allowed (operator material and cert-manager).
func TestApplogWebhookDoesNotAdmitItsOwnInjector(t *testing.T) {
	renders := map[string]string{
		"default": renderArgs(t),
		"fail-operator": renderArgs(t, "--set", "applogSidecar.webhook.failurePolicy=Fail",
			"--set", "applogSidecar.tls.caBundle="+applogCABundle,
			"--set", "applogSidecar.tls.servingCert="+applogCABundle,
			"--set", "applogSidecar.tls.servingKey="+applogCABundle),
		"fail-cert-manager": renderArgs(t, "--set", "applogSidecar.webhook.failurePolicy=Fail",
			"--set", "applogSidecar.tls.certManagerEnabled=true"),
	}
	for name, rendered := range renders {
		t.Run(name, func(t *testing.T) {
			mwc := docNamed(t, rendered, "MutatingWebhookConfiguration", "olaitan-applog-injector")
			hooks := asList(mwc["webhooks"])
			if len(hooks) != 1 {
				t.Fatalf("%d webhooks, want 1", len(hooks))
			}
			sel, _ := dig(hooks[0], "objectSelector").(map[string]any)
			if sel == nil {
				t.Fatal("applog webhook has no objectSelector: it admits its own injector pods (#159)")
			}
			podLabels, _ := dig(injectorDeployment(t, rendered), "spec", "template", "metadata", "labels").(map[string]any)
			if !excludedBy(sel, podLabels) {
				t.Errorf("objectSelector %v does not exclude the injector pod labels %v (#159)", sel, podLabels)
			}
			// A workload pod is still selected.
			if excludedBy(sel, map[string]any{"app": "web"}) {
				t.Error("objectSelector excludes ordinary workload pods")
			}
		})
	}
}

func TestApplogInjectorRolloutNeverDropsACall(t *testing.T) {
	rendered := renderArgs(t)
	d := injectorDeployment(t, rendered)

	// Surge first, never take a serving pod away before its replacement is ready.
	if mu := dig(d, "spec", "strategy", "rollingUpdate", "maxUnavailable"); mu != 0 {
		t.Errorf("strategy.rollingUpdate.maxUnavailable = %v, want 0 (#156)", mu)
	}
	if ms := dig(d, "spec", "strategy", "rollingUpdate", "maxSurge"); ms != 1 {
		t.Errorf("strategy.rollingUpdate.maxSurge = %v, want 1", ms)
	}

	// Drain: the binary keeps serving for the delay after SIGTERM, and the
	// grace period covers the delay plus the 10 s Shutdown and 5 s wait.
	c := injectorContainer(t, rendered)
	v, ok := envValue(c, "OLAITAN_WEBHOOK_SHUTDOWN_DELAY")
	if !ok || v != "5s" {
		t.Errorf("OLAITAN_WEBHOOK_SHUTDOWN_DELAY = %q (set %v), want 5s (#156)", v, ok)
	}
	grace, _ := dig(d, "spec", "template", "spec", "terminationGracePeriodSeconds").(int)
	if grace < 5+15 {
		t.Errorf("terminationGracePeriodSeconds = %d, want >= shutdown delay + 15", grace)
	}
	if p := dig(c, "readinessProbe", "httpGet", "path"); p != "/readyz" {
		t.Errorf("readinessProbe path = %v, want /readyz (drain-aware)", p)
	}
	if p := dig(c, "livenessProbe", "httpGet", "path"); p != "/healthz" {
		t.Errorf("livenessProbe path = %v, want /healthz", p)
	}

	// A PDB keeps one injector up through a node drain.
	pdb := docNamed(t, rendered, "PodDisruptionBudget", "olaitan-applog-injector")
	if ma := dig(pdb, "spec", "minAvailable"); ma != 1 {
		t.Errorf("PDB minAvailable = %v, want 1", ma)
	}
	podLabels, _ := dig(d, "spec", "template", "metadata", "labels").(map[string]any)
	sel, _ := dig(pdb, "spec", "selector", "matchLabels").(map[string]any)
	if len(sel) == 0 {
		t.Fatal("PDB has no selector")
	}
	for k, v := range sel {
		if podLabels[k] != v {
			t.Errorf("PDB selector %s=%v does not match the injector pods (%v)", k, v, podLabels[k])
		}
	}

	// The delay is a value, bounded.
	r := renderArgs(t, "--set", "applogSidecar.webhook.shutdownDelaySeconds=12")
	if v, _ := envValue(injectorContainer(t, r), "OLAITAN_WEBHOOK_SHUTDOWN_DELAY"); v != "12s" {
		t.Errorf("shutdownDelaySeconds=12 renders %q", v)
	}
	if g, _ := dig(injectorDeployment(t, r), "spec", "template", "spec", "terminationGracePeriodSeconds").(int); g < 12+15 {
		t.Errorf("grace %d does not cover a 12 s delay", g)
	}
	for _, bad := range []string{"-1", "121"} {
		if _, err := renderArgsErr(t, "--set", "applogSidecar.webhook.shutdownDelaySeconds="+bad); err == nil || !strings.Contains(err.Error(), "shutdownDelaySeconds") {
			t.Errorf("shutdownDelaySeconds=%s rendered (err %v)", bad, err)
		}
	}
}

// A single replica cannot have a minAvailable 1 PDB: it would block every
// node drain. One replica renders none (and NOTES-level docs say why).
func TestApplogInjectorPDBNeedsTwoReplicas(t *testing.T) {
	for n, want := range map[int]bool{1: false, 2: true, 3: true} {
		r := renderArgs(t, "--set", "applogSidecar.webhook.replicaCount="+strconv.Itoa(n))
		got := false
		for _, p := range docsOfKind(t, r, "PodDisruptionBudget") {
			if dig(p, "metadata", "name") == "olaitan-applog-injector" {
				got = true
			}
		}
		if got != want {
			t.Errorf("replicaCount=%d: PDB rendered=%v, want %v", n, got, want)
		}
	}
}
