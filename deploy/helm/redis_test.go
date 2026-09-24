//go:build helm

package helm_test

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Story 12.6: the bundled Redis is the chart's own templates/redis.yaml on
// the official redis image, replacing the Bitnami subchart (whose image
// could no longer be pinned to a version). These tests pin the contract
// that replacement has to keep.

// TestRedisKeepsTheBitnamiUpgradeContract: a StatefulSet's selector,
// serviceName and volume claim template are immutable. They must equal what
// the Bitnami chart rendered, or `helm upgrade` of an existing release fails
// (or, worse, a hand-rolled recreate orphans the data claim).
func TestRedisKeepsTheBitnamiUpgradeContract(t *testing.T) {
	rendered := helmTemplate(t, nil)
	sts := docNamed(t, rendered, "StatefulSet", "olaitan-redis-master")

	if got := dig(sts, "spec", "serviceName"); got != "olaitan-redis-headless" {
		t.Errorf("serviceName = %v, want olaitan-redis-headless", got)
	}
	wantSel := map[string]any{
		"app.kubernetes.io/instance":  "olaitan",
		"app.kubernetes.io/name":      "redis",
		"app.kubernetes.io/component": "master",
	}
	if got := dig(sts, "spec", "selector", "matchLabels"); !reflect.DeepEqual(got, wantSel) {
		t.Errorf("selector = %v, want %v", got, wantSel)
	}
	vcts := asList(dig(sts, "spec", "volumeClaimTemplates"))
	if len(vcts) != 1 {
		t.Fatalf("volumeClaimTemplates = %d, want 1", len(vcts))
	}
	wantVCT := map[string]any{
		"apiVersion": "v1",
		"kind":       "PersistentVolumeClaim",
		"metadata": map[string]any{
			"name":   "redis-data",
			"labels": wantSel,
		},
		"spec": map[string]any{
			"accessModes": []any{"ReadWriteOnce"},
			"resources":   map[string]any{"requests": map[string]any{"storage": "8Gi"}},
		},
	}
	if !reflect.DeepEqual(vcts[0], wantVCT) {
		t.Errorf("volumeClaimTemplate = %v\nwant %v", vcts[0], wantVCT)
	}

	// Same UID/GID/fsGroup as Bitnami's Redis, so its files under /data
	// stay readable after the upgrade.
	for _, k := range []string{"runAsUser", "runAsGroup", "fsGroup"} {
		if got := dig(sts, "spec", "template", "spec", "securityContext", k); got != 1001 {
			t.Errorf("pod securityContext.%s = %v, want 1001", k, got)
		}
	}
	c := asList(dig(sts, "spec", "template", "spec", "containers"))[0]
	for k, want := range map[string]any{"readOnlyRootFilesystem": true, "allowPrivilegeEscalation": false, "runAsNonRoot": true} {
		if got := dig(c, "securityContext", k); got != want {
			t.Errorf("container securityContext.%s = %v, want %v", k, got, want)
		}
	}
	if got := dig(c, "securityContext", "capabilities", "drop"); !reflect.DeepEqual(got, []any{"ALL"}) {
		t.Errorf("capabilities.drop = %v, want [ALL]", got)
	}

	// The endpoints the clients and CI use: <release>-redis-master:6379 and
	// the pod <release>-redis-master-0.
	svc := docNamed(t, rendered, "Service", "olaitan-redis-master")
	if p := asList(dig(svc, "spec", "ports")); len(p) != 1 || dig(p[0], "port") != 6379 {
		t.Errorf("olaitan-redis-master ports = %v, want 6379", p)
	}
	docNamed(t, rendered, "Service", "olaitan-redis-headless")
	if !strings.Contains(rendered, `value: "olaitan-redis-master:6379"`) {
		t.Error("clients are not pointed at olaitan-redis-master:6379")
	}

	// No Bitnami resource of any kind is left.
	if strings.Contains(rendered, "bitnami") || strings.Contains(rendered, "helm.sh/chart: redis-") {
		t.Error("default render still carries Bitnami Redis output")
	}
}

// TestRedisAuthFollowsTheReleaseSecret: the server reads the SAME
// Secret key the clients read. The Bitnami values hardcoded
// `olaitan-secrets`, which was wrong for any other release name.
func TestRedisAuthFollowsTheReleaseSecret(t *testing.T) {
	args := []string{"template", "foo", chartDir(t), "--set", "secrets.redisPassword=x"}
	rendered := runHelm(t, args...)
	sts := docNamed(t, rendered, "StatefulSet", "foo-redis-master")
	c := asList(dig(sts, "spec", "template", "spec", "containers"))[0]
	seen := 0
	for _, e := range asList(dig(c, "env")) {
		name := dig(e, "name")
		if name != "REDIS_PASSWORD" && name != "REDISCLI_AUTH" {
			continue
		}
		seen++
		ref := dig(e, "valueFrom", "secretKeyRef")
		if dig(ref, "name") != "foo-olaitan-secrets" || dig(ref, "key") != "redis-password" {
			t.Errorf("%v reads %v, want foo-olaitan-secrets/redis-password", name, ref)
		}
	}
	if seen != 2 {
		t.Errorf("found %d of REDIS_PASSWORD and REDISCLI_AUTH", seen)
	}
	cmd := strings.Join(asStrings(dig(c, "command")), " ")
	if !strings.Contains(cmd, `--requirepass "$REDIS_PASSWORD"`) {
		t.Errorf("server does not require the password: %q", cmd)
	}
	if !strings.Contains(rendered, `value: "foo-redis-master:6379"`) {
		t.Error("clients of release foo are not pointed at foo-redis-master:6379")
	}

	// An operator Secret overrides both sides' source for the server.
	rendered = helmTemplate(t, []string{"redis.auth.existingSecret=my-redis", "redis.auth.existingSecretPasswordKey=pw"})
	c = asList(dig(docNamed(t, rendered, "StatefulSet", "olaitan-redis-master"), "spec", "template", "spec", "containers"))[0]
	for _, e := range asList(dig(c, "env")) {
		if dig(e, "name") == "REDIS_PASSWORD" {
			if ref := dig(e, "valueFrom", "secretKeyRef"); dig(ref, "name") != "my-redis" || dig(ref, "key") != "pw" {
				t.Errorf("existingSecret override not honoured: %v", ref)
			}
		}
	}
}

// TestRedisNetworkPolicyHasNoEgress: 6379 from the release namespace only,
// and an empty egress in EVERY profile, not just the air-gapped overlay (the
// Bitnami policy allowed all egress unless an overlay closed it).
func TestRedisNetworkPolicyHasNoEgress(t *testing.T) {
	for name, rendered := range map[string]string{
		"default":   helmTemplate(t, nil),
		"airgapped": helmTemplateValues(t, posturePath(t, "airgapped")),
		"full":      renderFullProfile(t),
	} {
		np := docNamed(t, rendered, "NetworkPolicy", "olaitan-redis")
		if got := dig(np, "spec", "policyTypes"); !reflect.DeepEqual(got, []any{"Ingress", "Egress"}) {
			t.Errorf("%s: policyTypes = %v", name, got)
		}
		if eg, ok := dig(np, "spec").(map[string]any)["egress"]; !ok || len(asList(eg)) != 0 {
			t.Errorf("%s: egress = %v, want declared empty", name, eg)
		}
		in := asList(dig(np, "spec", "ingress"))
		if len(in) != 1 {
			t.Fatalf("%s: ingress rules = %d, want 1", name, len(in))
		}
		from := asList(dig(in[0], "from"))
		if len(from) != 1 || !reflect.DeepEqual(dig(from[0], "podSelector"), map[string]any{}) || dig(from[0], "namespaceSelector") != nil {
			t.Errorf("%s: ingress from = %v, want the release namespace's pods only", name, from)
		}
		if p := asList(dig(in[0], "ports")); len(p) != 1 || dig(p[0], "port") != 6379 {
			t.Errorf("%s: ingress ports = %v, want 6379", name, p)
		}
	}
	if strings.Contains(helmTemplate(t, []string{"redis.networkPolicy.enabled=false"}), "name: olaitan-redis\n") {
		t.Error("redis.networkPolicy.enabled=false still renders the policy")
	}
}

// TestRedisPersistenceKnobs: persistence off is an emptyDir (and no claim
// template); a storage class lands on the claim template.
func TestRedisPersistenceKnobs(t *testing.T) {
	off := docNamed(t, helmTemplate(t, []string{"redis.persistence.enabled=false"}), "StatefulSet", "olaitan-redis-master")
	if dig(off, "spec", "volumeClaimTemplates") != nil {
		t.Error("persistence off still renders a claim template")
	}
	found := false
	for _, v := range asList(dig(off, "spec", "template", "spec", "volumes")) {
		if dig(v, "name") == "redis-data" && dig(v, "emptyDir") != nil {
			found = true
		}
	}
	if !found {
		t.Error("persistence off: no redis-data emptyDir")
	}

	on := docNamed(t, helmTemplate(t, []string{"redis.persistence.storageClassName=fast", "redis.persistence.size=20Gi"}), "StatefulSet", "olaitan-redis-master")
	vct := asList(dig(on, "spec", "volumeClaimTemplates"))[0]
	if dig(vct, "spec", "storageClassName") != "fast" || dig(vct, "spec", "resources", "requests", "storage") != "20Gi" {
		t.Errorf("claim template = %v", dig(vct, "spec"))
	}
}

// TestRedisImageNeedsTagAndDigest: the chart-owned image is always pinned;
// clearing the digest fails the render rather than shipping a tag alone.
func TestRedisImageNeedsTagAndDigest(t *testing.T) {
	out, err := runHelmErr("template", "olaitan", chartDir(t), "--set", "secrets.redisPassword=x", "--set", "redis.image.digest=")
	if err == nil || !strings.Contains(out, "redis.image.digest is required") {
		t.Errorf("empty redis.image.digest rendered (err=%v):\n%s", err, out)
	}
	out, err = runHelmErr("template", "olaitan", chartDir(t), "--set", "secrets.redisPassword=x", "--set", "redis.image.digest=sha256:nothex")
	if err == nil || !strings.Contains(out, "redis.image.digest must be sha256:<64 lowercase hex>") {
		t.Errorf("malformed redis.image.digest rendered (err=%v):\n%s", err, out)
	}
}

// TestRedisDisabledRendersNoRedis: bring-your-own Redis leaves nothing
// named redis behind (stronger than TestRedisDisabledOnly, which predates
// the chart owning these resources and exempts olaitan-* names).
func TestRedisDisabledRendersNoRedis(t *testing.T) {
	for _, m := range parseManifests(t, helmTemplate(t, []string{"redis.enabled=false"})) {
		if strings.Contains(m.Metadata.Name, "redis") {
			t.Errorf("redis.enabled=false still renders %s/%s", m.Kind, m.Metadata.Name)
		}
	}
}

func asStrings(v any) []string {
	var out []string
	for _, e := range asList(v) {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// runHelm runs helm and fails the test on a non-zero exit.
func runHelm(t *testing.T, args ...string) string {
	t.Helper()
	out, err := runHelmErr(args...)
	if err != nil {
		t.Fatalf("helm %v failed: %v\n%s", args, err, out)
	}
	return out
}

// runHelmErr runs helm and returns stdout (or stderr on failure) and the error.
func runHelmErr(args ...string) (string, error) {
	cmd := exec.Command("helm", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stderr.String(), err
	}
	return stdout.String(), nil
}

// TestRedisOnOpenShiftLeavesTheUIDToTheSCC (review round 1, R1-P1): on
// OpenShift, restricted-v2 assigns the UID, GID and fsGroup from the
// namespace range and refuses a pod that asks for 1001. The Bitnami chart
// dropped the three fields there (adaptSecurityContext: auto), so the
// chart-owned Redis must too, whether the platform is detected from the
// API surface or declared. Everywhere else they stay 1001 (upgrade contract).
func TestRedisOnOpenShiftLeavesTheUIDToTheSCC(t *testing.T) {
	overlay := filepath.Join(chartDir(t), "values-openshift.yaml")
	for name, rendered := range map[string]string{
		"detected": runHelm(t, "template", "olaitan", chartDir(t), "--set", "secrets.redisPassword=x",
			"--api-versions", "security.openshift.io/v1"),
		"overlay": runHelm(t, "template", "olaitan", chartDir(t), "--set", "secrets.redisPassword=x",
			"--values", overlay, "--api-versions", "security.openshift.io/v1"),
		"declared": helmTemplate(t, []string{"platform=openshift"}),
	} {
		sts := docNamed(t, rendered, "StatefulSet", "olaitan-redis-master")
		podSC, _ := dig(sts, "spec", "template", "spec", "securityContext").(map[string]any)
		c := asList(dig(sts, "spec", "template", "spec", "containers"))[0]
		cSC, _ := dig(c, "securityContext").(map[string]any)
		for _, k := range []string{"runAsUser", "runAsGroup", "fsGroup"} {
			if v, ok := podSC[k]; ok {
				t.Errorf("%s: pod securityContext.%s = %v, want unset on OpenShift", name, k, v)
			}
			if v, ok := cSC[k]; ok {
				t.Errorf("%s: container securityContext.%s = %v, want unset on OpenShift", name, k, v)
			}
		}
		// Still non-root, read-only and capability-free: only the numbers go.
		if podSC["runAsNonRoot"] != true || cSC["runAsNonRoot"] != true || cSC["readOnlyRootFilesystem"] != true {
			t.Errorf("%s: hardening lost on OpenShift: pod %v container %v", name, podSC, cSC)
		}
	}
}

// TestRedisRejectsBitnamiOnlyKeys (review round 1, R1-P2): a Bitnami-era
// key would otherwise be ignored in silence, and a changed claim template
// makes Kubernetes reject the StatefulSet update. The render fails instead
// and names the key that replaced it.
func TestRedisRejectsBitnamiOnlyKeys(t *testing.T) {
	for set, want := range map[string]string{
		"redis.master.persistence.size=16Gi":         "redis.persistence.size",
		"redis.master.persistence.storageClass=fast": "redis.persistence.storageClassName",
		"redis.architecture=replication":             "redis.architecture",
		// Bitnami read these too; the chart-owned Redis does not.
		"global.storageClass=fast":       "redis.persistence.storageClassName",
		"redis.image.registry=mirror.io": "redis.image.repository",
	} {
		stderr := helmTemplateExpectError(t, []string{set})
		if !strings.Contains(stderr, want) || !strings.Contains(stderr, "--reset-then-reuse-values") {
			t.Errorf("--set %s: stderr does not name %q and the upgrade flag:\n%s", set, want, stderr)
		}
	}
}

// TestRedisReuseValuesFromTheBitnamiChartFailsClearly (R1-P2): Helm 3's
// `upgrade --reuse-values` renders the new templates against the OLD
// chart's defaults. Across Story 12.6 that is the Bitnami-era redis block
// (architecture: standalone, no image, no persistence). The render must stop
// with the fix, not a nil pointer or a silently emptyDir-backed Redis.
func TestRedisReuseValuesFromTheBitnamiChartFailsClearly(t *testing.T) {
	old := writeValues(t, `redis:
  enabled: true
  architecture: standalone
  auth:
    enabled: true
    existingSecret: olaitan-secrets
    existingSecretPasswordKey: redis-password
  image: null
  persistence: null
  resources: null
  networkPolicy: null
  nodeSelector: null
  tolerations: null
`)
	out, err := runHelmErr("template", "olaitan", chartDir(t), "--set", "secrets.redisPassword=x", "--values", old)
	if err == nil || !strings.Contains(out, "--reset-then-reuse-values") {
		t.Errorf("Bitnami-era values rendered or failed unclearly (err=%v):\n%s", err, out)
	}
	// Same with only the image missing (a hand-trimmed values file).
	out, err = runHelmErr("template", "olaitan", chartDir(t), "--set", "secrets.redisPassword=x", "--set", "redis.image=null")
	if err == nil || !strings.Contains(out, "--reset-then-reuse-values") {
		t.Errorf("missing redis.image rendered or failed unclearly (err=%v):\n%s", err, out)
	}
}
