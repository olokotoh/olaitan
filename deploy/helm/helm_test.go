//go:build helm

// Package helm_test exercises the Olaitan Helm chart via `helm template`
// and (optionally) kubeconform. Build tag `helm` gates it because the
// test suite shells out to the `helm` binary, which is not guaranteed on
// a plain `go test ./...` developer machine.
//
// Invoke locally:
//
//	make helm-deps                              # one-time: fetch subcharts
//	go test ./deploy/helm/... -tags=helm -v
//
// CI runs this via the `helm` job in .github/workflows/ci.yml. The
// kubeconform portion skips with t.Skip when the binary is absent;
// everything else is self-contained.
package helm_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/olokotoh/olaitan/internal/config"
	"github.com/olokotoh/olaitan/internal/decision/rules/parser"
)

// extractEmbeddedConfigYAML pulls the literal olaitan.yaml content out
// of the rendered olaitan-config ConfigMap. The chart embeds the file
// under data.olaitan.yaml using the `|-` block-scalar shape; we trim
// the leading 4-space indent each line carries inside the block-scalar
// so the result is a stand-alone YAML document parsable by config.Load.
func extractEmbeddedConfigYAML(t *testing.T, rendered string) string {
	t.Helper()
	marker := "olaitan.yaml: |-"
	idx := strings.Index(rendered, marker)
	if idx == -1 {
		t.Fatalf("olaitan.yaml block not found in rendered ConfigMap")
	}
	body := rendered[idx+len(marker):]
	// Stop at the next ConfigMap boundary (next `---` separator).
	if end := strings.Index(body, "\n---\n"); end >= 0 {
		body = body[:end]
	}
	var out strings.Builder
	for _, line := range strings.Split(body, "\n") {
		if len(line) >= 4 && line[:4] == "    " {
			out.WriteString(line[4:])
		} else {
			out.WriteString(strings.TrimLeft(line, " "))
		}
		out.WriteString("\n")
	}
	return out.String()
}

// configLoad runs the production config.Load path against the supplied
// file so the chart-side helm tests can round-trip the rendered
// ConfigMap through the same validator the aggregator binary uses at
// startup.
func configLoad(t *testing.T, path string) (*config.Config, error) {
	t.Helper()
	return config.Load(path)
}

// chartDir resolves to <this-test-file>/../olaitan, independent of the
// caller's working directory. `filepath.Abs("olaitan")` (the previous
// implementation) silently broke when `go test` was invoked from any
// directory other than `deploy/helm/` — for example a `-run` from the
// repo root, or coverage-mode reruns that chdir into a tmp dir.
func chartDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller(0) failed — cannot resolve chart dir")
	}
	return filepath.Join(filepath.Dir(thisFile), "olaitan")
}

// helmTemplate runs `helm template` with the provided --set overrides
// and returns the rendered manifest stream. Bails the test on any
// non-zero exit so callers can assume the stdout is valid.
func helmTemplate(t *testing.T, sets []string) string {
	t.Helper()
	// Every render must satisfy the chart's fail-fast guard for the
	// Bitnami Redis subchart auth. Inject a dummy password by default;
	// individual tests can override by prepending their own --set.
	args := []string{"template", "olaitan", chartDir(t),
		"--set", "secrets.redisPassword=test-password",
	}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	cmd := exec.Command("helm", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("helm template %v failed: %v\nstderr:\n%s", sets, err, stderr.String())
	}
	return stdout.String()
}

// manifest mirrors the subset of K8s object fields this suite inspects.
// Using yaml.Node for rules/containers lets us introspect nested arrays
// without declaring the full K8s API shape.
type manifest struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	// Raw captures the full document as yaml.Node for ad-hoc walks.
	Raw yaml.Node `yaml:"-"`
}

// parseManifests splits the rendered stream on YAML document markers
// and decodes each non-empty document. helm emits stray `---\n# Source:`
// headers around empty documents; skip any doc with no apiVersion.
func parseManifests(t *testing.T, rendered string) []manifest {
	t.Helper()
	dec := yaml.NewDecoder(strings.NewReader(rendered))
	var out []manifest
	for {
		var node yaml.Node
		if err := dec.Decode(&node); err != nil {
			break
		}
		var m manifest
		if err := node.Decode(&m); err != nil {
			continue
		}
		if m.APIVersion == "" || m.Kind == "" {
			continue
		}
		m.Raw = node
		out = append(out, m)
	}
	return out
}

// findByKind returns every manifest with the given kind. Used in
// assertions that scope checks to Deployment/DaemonSet only (pod
// specs), avoiding false positives on subchart resources.
func findByKind(ms []manifest, kind string) []manifest {
	var out []manifest
	for _, m := range ms {
		if m.Kind == kind {
			out = append(out, m)
		}
	}
	return out
}

// assertContains fails the test if needle is not present in haystack.
// Used for simple string assertions on rendered YAML.
func assertContains(t *testing.T, haystack, needle, why string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("%s: missing %q in rendered output", why, needle)
	}
}

// TestDefaultPermutation renders with default values (all subcharts
// enabled) and asserts the Olaitan-owned resources are all present.
func TestDefaultPermutation(t *testing.T) {
	rendered := helmTemplate(t, nil)
	ms := parseManifests(t, rendered)

	// Track kinds we own — subcharts add their own Deployments/Secrets,
	// so scope the assertions to our olaitan-* names.
	expectOurs := map[string]int{
		"DaemonSet":             1,
		"Deployment":            1,
		"ServiceAccount":        2,
		"Role":                  1,
		"RoleBinding":           1,
		"ClusterRole":           1,
		"ClusterRoleBinding":    1,
		"PersistentVolumeClaim": 1,
		"NetworkPolicy":         1,
	}
	gotOurs := make(map[string]int)
	for _, m := range ms {
		if strings.HasPrefix(m.Metadata.Name, "olaitan") {
			gotOurs[m.Kind]++
		}
	}
	for kind, want := range expectOurs {
		if gotOurs[kind] < want {
			t.Errorf("kind %s: got %d olaitan-* resources, want at least %d", kind, gotOurs[kind], want)
		}
	}

	// Our config ConfigMap must exist and be named deterministically.
	foundCfg := false
	for _, m := range ms {
		if m.Kind == "ConfigMap" && strings.HasSuffix(m.Metadata.Name, "-config") {
			foundCfg = true
			break
		}
	}
	if !foundCfg {
		t.Errorf("ConfigMap: olaitan-config not rendered")
	}
}

// TestSubchartsDisabled renders with every subchart off and asserts
// only the expected Olaitan-owned kinds show up. NFR: operators with
// existing Falco/NATS/Redis must be able to install without double-
// provisioning. The positive-list assertion below is load-bearing —
// without it, a stray subchart resource named `olaitan-anything`
// (e.g. a misconfigured RoleBinding to cluster-admin) would slip
// through the previous "name starts with olaitan" check.
func TestSubchartsDisabled(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"falco.enabled=false",
		"nats.enabled=false",
		"redis.enabled=false",
	})
	ms := parseManifests(t, rendered)

	// Every rendered resource must be Olaitan-scoped (name prefix).
	for _, m := range ms {
		if !strings.HasPrefix(m.Metadata.Name, "olaitan") {
			t.Errorf("unexpected non-olaitan resource when subcharts disabled: %s/%s", m.Kind, m.Metadata.Name)
		}
	}

	// Exact expected manifest kind counts. New chart resources MUST be
	// added here so a future PR that introduces an unintended kind
	// (e.g. an extra Secret) trips this test.
	want := map[string]int{
		"ServiceAccount":     2,
		"Role":               1,
		"RoleBinding":        1,
		"ClusterRole":        1,
		"ClusterRoleBinding": 1,
		"Secret":             1,
		// config + rules + prompts (Story 3.13 added the prompts ConfigMap).
		"ConfigMap":             3,
		"PersistentVolumeClaim": 1,
		"NetworkPolicy":         1,
		"DaemonSet":             1,
		"Deployment":            1,
	}
	got := map[string]int{}
	for _, m := range ms {
		got[m.Kind]++
	}
	for kind, n := range want {
		if got[kind] != n {
			t.Errorf("kind %s: got %d, want exactly %d", kind, got[kind], n)
		}
	}
	for kind := range got {
		if _, expected := want[kind]; !expected {
			t.Errorf("unexpected kind rendered with subcharts disabled: %s (count=%d)", kind, got[kind])
		}
	}
}

// TestRedisDisabledOnly renders with just redis off — covers the common
// operator case of bring-your-own-Redis while keeping Falco + NATS
// defaults on.
func TestRedisDisabledOnly(t *testing.T) {
	rendered := helmTemplate(t, []string{"redis.enabled=false"})
	ms := parseManifests(t, rendered)

	for _, m := range ms {
		if strings.Contains(strings.ToLower(m.Metadata.Name), "redis") &&
			!strings.Contains(m.Metadata.Name, "olaitan") {
			t.Errorf("redis subchart resource leaked through: %s/%s", m.Kind, m.Metadata.Name)
		}
	}
}

// TestRBACVerbs walks the ClusterRole and Role rules and asserts they
// match architecture.md:949-957 exactly — no wildcards, no privileged
// roles bound, collector is read-only on pods/events, aggregator is
// CREATE/UPDATE/DELETE on networkpolicies + PATCH on pods + GET/LIST
// on pods,events.
//
// The negative checks (no `*`, no cluster-admin) are NOT sufficient on
// their own: a rule that grants `delete` on `pods` to the collector
// would pass the wildcard check but break the architectural boundary.
// We therefore also assert the EXACT verb/resource set per role.
func TestRBACVerbs(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"falco.enabled=false", "nats.enabled=false", "redis.enabled=false",
	})
	ms := parseManifests(t, rendered)

	roleRules := map[string][]rbacRule{} // metadata.name -> rules

	// Collect Roles and ClusterRoles owned by Olaitan.
	for _, m := range ms {
		if m.Kind != "Role" && m.Kind != "ClusterRole" {
			continue
		}
		if !strings.HasPrefix(m.Metadata.Name, "olaitan") {
			continue
		}
		var obj struct {
			Rules []rbacRule `yaml:"rules"`
		}
		if err := m.Raw.Decode(&obj); err != nil {
			t.Fatalf("decode %s: %v", m.Metadata.Name, err)
		}
		roleRules[m.Metadata.Name] = obj.Rules

		// Negative check: no wildcard verbs or resources.
		for _, r := range obj.Rules {
			for _, v := range r.Verbs {
				if v == "*" {
					t.Errorf("RBAC wildcard verb in %s/%s (rule %+v) — NFR13 violation",
						m.Kind, m.Metadata.Name, r)
				}
			}
			for _, res := range r.Resources {
				if res == "*" {
					t.Errorf("RBAC wildcard resource in %s/%s (rule %+v) — NFR13 violation",
						m.Kind, m.Metadata.Name, r)
				}
			}
		}
	}

	// Positive assertion: the collector role grants ONLY get/list/watch
	// on the documented resources. Any extra verb is a regression.
	allowedCollectorVerbs := map[string]bool{"get": true, "list": true, "watch": true}
	collectorRolesFound := 0
	for name, rules := range roleRules {
		if !strings.Contains(name, "collector") {
			continue
		}
		collectorRolesFound++
		for _, r := range rules {
			for _, v := range r.Verbs {
				if !allowedCollectorVerbs[v] {
					t.Errorf("collector role %s grants verb %q on %v — must be read-only (get/list/watch)",
						name, v, r.Resources)
				}
			}
		}
	}
	if collectorRolesFound == 0 {
		t.Errorf("collector Role/ClusterRole not found in rendered chart")
	}

	// Positive assertion: aggregator ClusterRole grants the documented
	// write verbs on the documented resources. Construct a flat map
	// of (resource, verb) we expect to find — every entry must be
	// present at least once.
	wantAggregator := []struct {
		apiGroup string
		resource string
		verb     string
	}{
		{"networking.k8s.io", "networkpolicies", "create"},
		{"networking.k8s.io", "networkpolicies", "update"},
		{"networking.k8s.io", "networkpolicies", "delete"},
		{"", "pods", "patch"},
		{"", "pods", "get"},
		{"", "pods", "list"},
		{"", "events", "get"},
		{"", "events", "list"},
	}
	aggregatorRulesFound := false
	for name, rules := range roleRules {
		if !strings.Contains(name, "aggregator") {
			continue
		}
		aggregatorRulesFound = true
		for _, want := range wantAggregator {
			if !rulesGrant(rules, want.apiGroup, want.resource, want.verb) {
				t.Errorf("aggregator ClusterRole %s missing %q on %s.%s",
					name, want.verb, want.resource, want.apiGroup)
			}
		}
		// Negative: no `delete` on pods (architecture says PATCH only).
		if rulesGrant(rules, "", "pods", "delete") {
			t.Errorf("aggregator ClusterRole %s grants DELETE on pods — architecture says PATCH only", name)
		}
	}
	if !aggregatorRulesFound {
		t.Errorf("aggregator ClusterRole not found in rendered chart")
	}

	// No ClusterRoleBinding to cluster-admin or any built-in privileged role.
	assertContains(t, rendered, "olaitan-aggregator-binding", "expected aggregator ClusterRoleBinding name")
	for _, banned := range []string{"cluster-admin", "system:masters", "edit", "admin"} {
		// `admin` and `edit` are built-in K8s ClusterRoles; the bare
		// word would false-positive on metadata, so look for the
		// roleRef target shape: `name: <banned>` under a ClusterRoleBinding
		// section. Approximate via a quoted RoleRef name pattern.
		if strings.Contains(rendered, "  name: "+banned+"\n") &&
			strings.Contains(rendered, "kind: ClusterRoleBinding") {
			t.Errorf("RBAC: ClusterRoleBinding may reference privileged role %q — NFR13 violation", banned)
		}
	}
}

// rbacRule is a flattened view of an RBAC PolicyRule used by the
// helpers below. Lift this out of TestRBACVerbs so the helpers can
// take a slice without referencing a function-local type.
type rbacRule struct {
	APIGroups []string `yaml:"apiGroups"`
	Resources []string `yaml:"resources"`
	Verbs     []string `yaml:"verbs"`
}

// rulesGrant reports whether the given rule list grants the (apiGroup,
// resource, verb) triple. K8s rule semantics: a rule grants the verb
// when it lists the apiGroup, the resource, and the verb (each in its
// own slice).
func rulesGrant(rules []rbacRule, apiGroup, resource, verb string) bool {
	for _, r := range rules {
		hasGroup := false
		for _, g := range r.APIGroups {
			if g == apiGroup {
				hasGroup = true
				break
			}
		}
		if !hasGroup {
			continue
		}
		hasRes := false
		for _, res := range r.Resources {
			if res == resource {
				hasRes = true
				break
			}
		}
		if !hasRes {
			continue
		}
		for _, v := range r.Verbs {
			if v == verb {
				return true
			}
		}
	}
	return false
}

// TestPodSecurityContext verifies every pod spec sets runAsNonRoot,
// runAsUser/runAsGroup, drops all capabilities, forbids privilege
// escalation, makes root filesystem read-only, and pins the seccomp
// profile to RuntimeDefault. NFR11 compliance.
func TestPodSecurityContext(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"falco.enabled=false", "nats.enabled=false", "redis.enabled=false",
	})
	ms := parseManifests(t, rendered)

	for _, m := range ms {
		if m.Kind != "DaemonSet" && m.Kind != "Deployment" {
			continue
		}
		if !strings.HasPrefix(m.Metadata.Name, "olaitan") {
			continue
		}
		var obj struct {
			Spec struct {
				Template struct {
					Spec struct {
						AutomountServiceAccountToken *bool `yaml:"automountServiceAccountToken"`
						SecurityContext              struct {
							RunAsNonRoot   *bool  `yaml:"runAsNonRoot"`
							RunAsUser      *int64 `yaml:"runAsUser"`
							RunAsGroup     *int64 `yaml:"runAsGroup"`
							SeccompProfile struct {
								Type string `yaml:"type"`
							} `yaml:"seccompProfile"`
						} `yaml:"securityContext"`
						Containers []struct {
							SecurityContext struct {
								AllowPrivilegeEscalation *bool `yaml:"allowPrivilegeEscalation"`
								ReadOnlyRootFilesystem   *bool `yaml:"readOnlyRootFilesystem"`
								Capabilities             struct {
									Drop []string `yaml:"drop"`
								} `yaml:"capabilities"`
							} `yaml:"securityContext"`
						} `yaml:"containers"`
					} `yaml:"spec"`
				} `yaml:"template"`
			} `yaml:"spec"`
		}
		if err := m.Raw.Decode(&obj); err != nil {
			t.Fatalf("decode %s: %v", m.Metadata.Name, err)
		}
		podSec := obj.Spec.Template.Spec.SecurityContext
		if podSec.RunAsNonRoot == nil || !*podSec.RunAsNonRoot {
			t.Errorf("%s/%s: pod securityContext.runAsNonRoot must be true",
				m.Kind, m.Metadata.Name)
		}
		if podSec.RunAsUser == nil || *podSec.RunAsUser != 65532 {
			t.Errorf("%s/%s: pod securityContext.runAsUser must be 65532 (distroless nonroot)",
				m.Kind, m.Metadata.Name)
		}
		if podSec.RunAsGroup == nil || *podSec.RunAsGroup != 65532 {
			t.Errorf("%s/%s: pod securityContext.runAsGroup must be 65532",
				m.Kind, m.Metadata.Name)
		}
		if podSec.SeccompProfile.Type != "RuntimeDefault" {
			t.Errorf("%s/%s: pod securityContext.seccompProfile.type must be RuntimeDefault, got %q",
				m.Kind, m.Metadata.Name, podSec.SeccompProfile.Type)
		}
		for i, c := range obj.Spec.Template.Spec.Containers {
			sc := c.SecurityContext
			if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
				t.Errorf("%s/%s container[%d]: allowPrivilegeEscalation must be false",
					m.Kind, m.Metadata.Name, i)
			}
			if sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
				t.Errorf("%s/%s container[%d]: readOnlyRootFilesystem must be true",
					m.Kind, m.Metadata.Name, i)
			}
			if len(sc.Capabilities.Drop) != 1 || sc.Capabilities.Drop[0] != "ALL" {
				t.Errorf("%s/%s container[%d]: capabilities.drop must be [ALL], got %v",
					m.Kind, m.Metadata.Name, i, sc.Capabilities.Drop)
			}
		}
	}
}

// TestReplicasGuard confirms the chart refuses to render when the
// operator overrides aggregator.replicas above 1 — Ring 2 NATS
// JetStream checkpoint correctness depends on at-most-one-aggregator.
func TestReplicasGuard(t *testing.T) {
	args := []string{
		"template", "olaitan", chartDir(t),
		"--set", "secrets.redisPassword=test-password",
		"--set", "aggregator.replicas=2",
	}
	cmd := exec.Command("helm", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("helm template with replicas=2 succeeded; expected fail-fast guard to fire")
	}
	if !strings.Contains(stderr.String(), "aggregator.replicas must not exceed 1") {
		t.Errorf("expected aggregator.replicas guard message in stderr; got:\n%s", stderr.String())
	}
}

// TestRedisAuthGuard confirms the chart refuses to render when redis
// is enabled and the operator has not supplied a password — silent
// AUTH failure at runtime is worse than a loud chart-render error.
func TestRedisAuthGuard(t *testing.T) {
	args := []string{
		"template", "olaitan", chartDir(t),
		// no --set secrets.redisPassword — must trip the guard
	}
	cmd := exec.Command("helm", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("helm template without redisPassword succeeded; expected fail-fast guard to fire")
	}
	if !strings.Contains(stderr.String(), "secrets.redisPassword is required") {
		t.Errorf("expected secrets.redisPassword guard message in stderr; got:\n%s", stderr.String())
	}
}

// TestAuditWebhookCABundleGuard confirms enabling the audit webhook
// without a caBundle is refused at chart-render time, preventing a
// silent admission bypass under failurePolicy: Ignore.
func TestAuditWebhookCABundleGuard(t *testing.T) {
	args := []string{
		"template", "olaitan", chartDir(t),
		"--set", "secrets.redisPassword=test-password",
		"--set", "auditWebhook.enabled=true",
	}
	cmd := exec.Command("helm", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("helm template with audit webhook enabled but no caBundle succeeded; expected guard to fire")
	}
	if !strings.Contains(stderr.String(), "auditWebhook.caBundle is required") {
		t.Errorf("expected auditWebhook.caBundle guard message in stderr; got:\n%s", stderr.String())
	}
}

// TestEndpointsTemplated confirms the NATS_URL/REDIS_ADDR env vars
// derive from .Release.Name when no operator override is set, so a
// non-default release name produces correct service-DNS — the bug
// the previous hardcoded `olaitan-nats` string introduced.
func TestEndpointsTemplated(t *testing.T) {
	args := []string{
		"template", "foo", chartDir(t),
		"--set", "secrets.redisPassword=test-password",
		"--set", "redis.auth.existingSecret=foo-olaitan-secrets",
	}
	cmd := exec.Command("helm", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("helm template with foo release name failed: %v\nstderr: %s", err, stderr.String())
	}
	rendered := stdout.String()
	if !strings.Contains(rendered, `value: "nats://foo-nats:4222"`) {
		t.Errorf("NATS_URL did not template from release name 'foo'; rendered output sample:\n%s",
			snippet(rendered, "NATS_URL"))
	}
	if !strings.Contains(rendered, `value: "foo-redis-master:6379"`) {
		t.Errorf("REDIS_ADDR did not template from release name 'foo'; rendered output sample:\n%s",
			snippet(rendered, "REDIS_ADDR"))
	}
}

// TestCollectorDaemonsetHasK8sNodeNameDownwardAPI confirms the
// collector DaemonSet renders the K8S_NODE_NAME env var via the
// downward-API field path `spec.nodeName`. The collector subcommand
// fails fast on an empty K8S_NODE_NAME (cmd/olaitan/main.go's
// startCollectorRing); a refactor that silently strips the env block
// would otherwise crash-loop the pod with a non-obvious "K8S_NODE_NAME
// env var is empty" message at startup.
func TestCollectorDaemonsetHasK8sNodeNameDownwardAPI(t *testing.T) {
	args := []string{
		"template", "olaitan-test", chartDir(t),
		"--set", "secrets.redisPassword=test-password",
	}
	cmd := exec.Command("helm", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("helm template failed: %v\nstderr: %s", err, stderr.String())
	}
	rendered := stdout.String()
	// The downward-API block we expect, rendered tightly so a stray
	// re-indent or removal trips this test rather than passing on a
	// near-miss.
	want := `- name: K8S_NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName`
	if !strings.Contains(rendered, want) {
		t.Errorf("K8S_NODE_NAME downward-API env not rendered on collector daemonset; rendered output sample:\n%s",
			snippet(rendered, "K8S_NODE_NAME"))
	}
}

// TestCollectorDaemonsetMountsFalcoSocketWhenUnix verifies that the
// collector DaemonSet bind-mounts /run/falco from the host when
// endpoints.falco uses a unix:// scheme (the chart default). Without
// this mount the FALCO_SOCKET env points at a path that is not visible
// inside the pod, so every dial silently fails and the adapter loops
// "Falco unreachable" forever; the bug is invisible until an operator
// notices zero events. Guard tightly so a chart refactor that strips
// the volume or volumeMount trips this test.
func TestCollectorDaemonsetMountsFalcoSocketWhenUnix(t *testing.T) {
	args := []string{
		"template", "olaitan-test", chartDir(t),
		"--set", "secrets.redisPassword=test-password",
	}
	cmd := exec.Command("helm", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("helm template failed: %v\nstderr: %s", err, stderr.String())
	}
	rendered := stdout.String()
	wantMount := `- name: falco-socket
              mountPath: /run/falco
              readOnly: true`
	if !strings.Contains(rendered, wantMount) {
		t.Errorf("falco-socket volumeMount not rendered on collector daemonset; rendered output sample:\n%s",
			snippet(rendered, "falco-socket"))
	}
	wantVolume := `- name: falco-socket
          hostPath:
            path: /run/falco
            type: Directory`
	if !strings.Contains(rendered, wantVolume) {
		t.Errorf("falco-socket hostPath volume not rendered on collector daemonset; rendered output sample:\n%s",
			snippet(rendered, "hostPath"))
	}
}

// TestCollectorDaemonsetSkipsFalcoSocketMountWhenTCP verifies that
// when endpoints.falco is set to a tcp:// target (Falco gRPC over the
// pod network rather than a host socket) the collector DaemonSet does
// NOT bind-mount /run/falco. Avoiding an unnecessary host-path mount
// keeps the collector's blast radius small in TCP-mode deployments;
// the mount only makes sense when the target is a Unix-domain socket.
func TestCollectorDaemonsetSkipsFalcoSocketMountWhenTCP(t *testing.T) {
	args := []string{
		"template", "olaitan-test", chartDir(t),
		"--set", "secrets.redisPassword=test-password",
		"--set", "endpoints.falco=tcp://falco.svc.cluster.local:5060",
	}
	cmd := exec.Command("helm", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("helm template failed: %v\nstderr: %s", err, stderr.String())
	}
	rendered := stdout.String()
	if strings.Contains(rendered, "falco-socket") {
		t.Errorf("falco-socket volume/mount rendered for tcp:// endpoint; expected omission. Rendered sample:\n%s",
			snippet(rendered, "falco-socket"))
	}
}

// snippet returns a few lines around the first occurrence of needle
// in the rendered output, for human-friendly error messages.
func snippet(rendered, needle string) string {
	i := strings.Index(rendered, needle)
	if i == -1 {
		return "(needle not found)"
	}
	start := i - 100
	if start < 0 {
		start = 0
	}
	end := i + 200
	if end > len(rendered) {
		end = len(rendered)
	}
	return rendered[start:end]
}

// TestAggregatorIsSingletonRecreate checks the critical Epic-3 safety
// property: aggregator is replicas:1 with strategy Recreate. Docstring
// in deployment.yaml explains why this is load-bearing for checkpoint
// correctness.
func TestAggregatorIsSingletonRecreate(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"falco.enabled=false", "nats.enabled=false", "redis.enabled=false",
	})
	ms := parseManifests(t, rendered)

	deps := findByKind(ms, "Deployment")
	found := false
	for _, m := range deps {
		if !strings.Contains(m.Metadata.Name, "aggregator") {
			continue
		}
		found = true
		var obj struct {
			Spec struct {
				Replicas int `yaml:"replicas"`
				Strategy struct {
					Type string `yaml:"type"`
				} `yaml:"strategy"`
			} `yaml:"spec"`
		}
		if err := m.Raw.Decode(&obj); err != nil {
			t.Fatalf("decode aggregator: %v", err)
		}
		if obj.Spec.Replicas != 1 {
			t.Errorf("aggregator replicas: got %d, want 1 (Ring 2 checkpoint split-brain)",
				obj.Spec.Replicas)
		}
		if obj.Spec.Strategy.Type != "Recreate" {
			t.Errorf("aggregator strategy.type: got %q, want Recreate", obj.Spec.Strategy.Type)
		}
	}
	if !found {
		t.Errorf("aggregator Deployment not rendered")
	}
}

// TestNetworkPolicyDefault asserts the namespace-isolation NetworkPolicy
// renders by default and disappears when explicitly disabled. This is the
// baseline-control gate Story 1.1 added to the chart structure
// (architecture.md:355-360).
func TestNetworkPolicyDefault(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"falco.enabled=false", "nats.enabled=false", "redis.enabled=false",
	})
	ms := parseManifests(t, rendered)

	nps := findByKind(ms, "NetworkPolicy")
	found := false
	for _, m := range nps {
		if strings.HasPrefix(m.Metadata.Name, "olaitan") {
			found = true
		}
	}
	if !found {
		t.Errorf("NetworkPolicy: olaitan-* not rendered under default values")
	}

	disabled := helmTemplate(t, []string{
		"falco.enabled=false", "nats.enabled=false", "redis.enabled=false",
		"networkPolicy.enabled=false",
	})
	disabledMs := parseManifests(t, disabled)
	for _, m := range findByKind(disabledMs, "NetworkPolicy") {
		if strings.HasPrefix(m.Metadata.Name, "olaitan") {
			t.Errorf("NetworkPolicy: olaitan-* still rendered when networkPolicy.enabled=false (got %s)", m.Metadata.Name)
		}
	}
}

// auditWebhookEnabledArgs returns a --set list that satisfies every
// fail-fast guard the Story 1.7 templates introduce (caBundle,
// clusterCAData, apiserverClientCert/Key, servingCert/Key). All values
// are deliberately stub base64 — the tests exercise the rendering
// path, not real cert validation. Includes the Story 1.1 caBundle
// guard so this helper is the single source of truth for "audit
// webhook enabled" in the helm test suite.
func auditWebhookEnabledArgs() []string {
	const stub = "ZmFrZS1iYXNlNjQ="
	return []string{
		"auditWebhook.enabled=true",
		"auditWebhook.caBundle=" + stub,
		"auditWebhook.clusterCAData=" + stub,
		"auditWebhook.apiserverClientCert=" + stub,
		"auditWebhook.apiserverClientKey=" + stub,
		"auditWebhook.servingCert=" + stub,
		"auditWebhook.servingKey=" + stub,
	}
}

// TestAuditWebhookGate_AllResourcesGated asserts every audit-webhook
// resource (Service, ValidatingWebhookConfiguration stub, audit-policy
// ConfigMap, kubeconfig Secret, TLS Secret) is absent by default and
// present when the gate is flipped. All gated resources must come and
// go together — a partial render is a chart-rot signal.
func TestAuditWebhookGate_AllResourcesGated(t *testing.T) {
	defaultRender := helmTemplate(t, []string{
		"falco.enabled=false", "nats.enabled=false", "redis.enabled=false",
	})
	defaultMs := parseManifests(t, defaultRender)
	for _, m := range findByKind(defaultMs, "Service") {
		if strings.Contains(m.Metadata.Name, "audit-webhook") {
			t.Errorf("audit-webhook Service rendered with auditWebhook.enabled=false (got %s)", m.Metadata.Name)
		}
	}
	if len(findByKind(defaultMs, "ValidatingWebhookConfiguration")) != 0 {
		t.Errorf("ValidatingWebhookConfiguration rendered with auditWebhook.enabled=false")
	}
	for _, m := range findByKind(defaultMs, "ConfigMap") {
		if strings.Contains(m.Metadata.Name, "audit-policy") {
			t.Errorf("audit-policy ConfigMap rendered with auditWebhook.enabled=false (got %s)", m.Metadata.Name)
		}
	}
	for _, m := range findByKind(defaultMs, "Secret") {
		if strings.Contains(m.Metadata.Name, "audit-webhook-kubeconfig") ||
			strings.Contains(m.Metadata.Name, "audit-tls") {
			t.Errorf("audit-webhook secret rendered with auditWebhook.enabled=false (got %s)", m.Metadata.Name)
		}
	}

	enabledArgs := append([]string{"falco.enabled=false", "nats.enabled=false", "redis.enabled=false"}, auditWebhookEnabledArgs()...)
	enabledRender := helmTemplate(t, enabledArgs)
	enabledMs := parseManifests(t, enabledRender)

	svcFound := false
	for _, m := range findByKind(enabledMs, "Service") {
		if strings.Contains(m.Metadata.Name, "audit-webhook") {
			svcFound = true
		}
	}
	if !svcFound {
		t.Errorf("audit-webhook Service not rendered with auditWebhook.enabled=true")
	}
	if len(findByKind(enabledMs, "ValidatingWebhookConfiguration")) != 1 {
		t.Errorf("ValidatingWebhookConfiguration: got %d, want 1 with auditWebhook.enabled=true",
			len(findByKind(enabledMs, "ValidatingWebhookConfiguration")))
	}

	policyCMFound := false
	for _, m := range findByKind(enabledMs, "ConfigMap") {
		if strings.HasSuffix(m.Metadata.Name, "-audit-policy") {
			policyCMFound = true
		}
	}
	if !policyCMFound {
		t.Errorf("audit-policy ConfigMap not rendered with auditWebhook.enabled=true")
	}

	kubeconfigSecretFound := false
	tlsSecretFound := false
	for _, m := range findByKind(enabledMs, "Secret") {
		if strings.HasSuffix(m.Metadata.Name, "-audit-webhook-kubeconfig") {
			kubeconfigSecretFound = true
		}
		if strings.HasSuffix(m.Metadata.Name, "-audit-tls") {
			tlsSecretFound = true
		}
	}
	if !kubeconfigSecretFound {
		t.Errorf("audit kubeconfig Secret not rendered with auditWebhook.enabled=true")
	}
	if !tlsSecretFound {
		t.Errorf("audit-tls Secret not rendered with auditWebhook.enabled=true")
	}
}

// TestAuditPolicyConfigMapRenders_WhenEnabled checks the audit-policy
// ConfigMap embeds the chart's default policy YAML when no custom
// override is supplied.
func TestAuditPolicyConfigMapRenders_WhenEnabled(t *testing.T) {
	args := append([]string{"falco.enabled=false", "nats.enabled=false", "redis.enabled=false"}, auditWebhookEnabledArgs()...)
	rendered := helmTemplate(t, args)
	if !strings.Contains(rendered, "kind: ConfigMap") {
		t.Fatalf("expected ConfigMap kind in rendered output")
	}
	if !strings.Contains(rendered, "olaitan-audit-policy") {
		t.Errorf("expected ConfigMap name olaitan-audit-policy in rendered output\n%s", snippet(rendered, "audit-policy"))
	}
	// Default policy spot-check: rules + omitStages must survive.
	if !strings.Contains(rendered, "omitStages") {
		t.Errorf("default audit policy missing omitStages stanza\n%s", snippet(rendered, "audit-policy"))
	}
	if !strings.Contains(rendered, "rolebindings") {
		t.Errorf("default audit policy missing rolebindings rule")
	}
}

// TestPromptsConfigMapRenders_Default is the Story 3.13 golden assertion:
// with defaults the per-role prompts ConfigMap renders with all four role
// keys, the aggregator mounts it read-only at /etc/olaitan/prompts, and the
// rendered config's analyst.prompts_dir tracks the mountPath.
func TestPromptsConfigMapRenders_Default(t *testing.T) {
	rendered := helmTemplate(t, []string{"falco.enabled=false", "nats.enabled=false", "redis.enabled=false"})
	if !strings.Contains(rendered, "olaitan-prompts") {
		t.Fatalf("prompts ConfigMap not rendered\n%s", snippet(rendered, "prompts"))
	}
	for _, key := range []string{"l1.txt:", "l2.txt:", "senior.txt:", "dfir.txt:"} {
		if !strings.Contains(rendered, key) {
			t.Errorf("prompts ConfigMap missing key %q\n%s", key, snippet(rendered, "olaitan-prompts"))
		}
	}
	if !strings.Contains(rendered, "mountPath: /etc/olaitan/prompts") {
		t.Errorf("aggregator missing prompts mount\n%s", snippet(rendered, "prompts"))
	}
	if !strings.Contains(rendered, `prompts_dir: "/etc/olaitan/prompts"`) {
		t.Errorf("rendered config analyst.prompts_dir not bridged to mountPath\n%s", snippet(rendered, "prompts_dir"))
	}
}

// TestPromptsConfigMapDisabled proves analyst.prompts.enabled=false drops
// the ConfigMap and its mount so the controller runs on embedded defaults.
func TestPromptsConfigMapDisabled(t *testing.T) {
	rendered := helmTemplate(t, []string{"falco.enabled=false", "nats.enabled=false", "redis.enabled=false", "analyst.prompts.enabled=false"})
	if strings.Contains(rendered, "olaitan-prompts") {
		t.Errorf("prompts ConfigMap rendered despite analyst.prompts.enabled=false\n%s", snippet(rendered, "prompts"))
	}
	if strings.Contains(rendered, "mountPath: /etc/olaitan/prompts") {
		t.Errorf("prompts mount rendered despite analyst.prompts.enabled=false")
	}
}

// TestPromptsDirBridgeFollowsMountPath proves an operator-overridden
// mountPath flows into both the volumeMount and the rendered config, so the
// controller loads from the actual mount (no silent path skew).
func TestPromptsDirBridgeFollowsMountPath(t *testing.T) {
	rendered := helmTemplate(t, []string{"falco.enabled=false", "nats.enabled=false", "redis.enabled=false", "analyst.prompts.mountPath=/custom/prompts"})
	if !strings.Contains(rendered, "mountPath: /custom/prompts") {
		t.Errorf("custom prompts mountPath not applied to volumeMount\n%s", snippet(rendered, "prompts"))
	}
	if !strings.Contains(rendered, `prompts_dir: "/custom/prompts"`) {
		t.Errorf("custom mountPath not bridged into analyst.prompts_dir\n%s", snippet(rendered, "prompts_dir"))
	}
}

// TestAuditWebhookKubeconfigSecretRenders_WhenEnabled confirms the
// kubeconfig Secret renders the apiserver-side mTLS material plus the
// receiver Service FQDN.
func TestAuditWebhookKubeconfigSecretRenders_WhenEnabled(t *testing.T) {
	args := append([]string{"falco.enabled=false", "nats.enabled=false", "redis.enabled=false"}, auditWebhookEnabledArgs()...)
	rendered := helmTemplate(t, args)
	if !strings.Contains(rendered, "olaitan-audit-webhook-kubeconfig") {
		t.Fatalf("kubeconfig Secret not rendered\n%s", snippet(rendered, "audit-webhook-kubeconfig"))
	}
	if !strings.Contains(rendered, "audit-webhook.default.svc.cluster.local") {
		t.Errorf("kubeconfig server URL missing Service FQDN\n%s", snippet(rendered, "audit-webhook.default"))
	}
	if !strings.Contains(rendered, "client-certificate-data:") {
		t.Errorf("kubeconfig missing client-certificate-data field")
	}
}

// TestAuditWebhookTLSSecretRenders_WhenEnabled confirms the TLS Secret
// carries the receiver serving cert/key and the cluster CA bundle.
func TestAuditWebhookTLSSecretRenders_WhenEnabled(t *testing.T) {
	args := append([]string{"falco.enabled=false", "nats.enabled=false", "redis.enabled=false"}, auditWebhookEnabledArgs()...)
	rendered := helmTemplate(t, args)
	if !strings.Contains(rendered, "olaitan-audit-tls") {
		t.Fatalf("audit-tls Secret not rendered")
	}
	if !strings.Contains(rendered, "type: kubernetes.io/tls") {
		t.Errorf("audit-tls Secret missing kubernetes.io/tls type")
	}
}

// TestAuditWebhookFailsFast_WhenApiserverClientCertEmpty asserts the
// kubeconfig Secret guard fires when the operator forgets the
// apiserver client cert.
func TestAuditWebhookFailsFast_WhenApiserverClientCertEmpty(t *testing.T) {
	args := []string{"template", "olaitan", chartDir(t),
		"--set", "secrets.redisPassword=test-password",
		"--set", "auditWebhook.enabled=true",
		"--set", "auditWebhook.caBundle=ZmFrZQ==",
		"--set", "auditWebhook.clusterCAData=ZmFrZQ==",
		"--set", "auditWebhook.apiserverClientKey=ZmFrZQ==",
		"--set", "auditWebhook.servingCert=ZmFrZQ==",
		"--set", "auditWebhook.servingKey=ZmFrZQ==",
	}
	cmd := exec.Command("helm", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("helm template with empty apiserverClientCert succeeded; expected guard to fire")
	}
	if !strings.Contains(stderr.String(), "auditWebhook.apiserverClientCert is required") {
		t.Errorf("expected apiserverClientCert guard, got:\n%s", stderr.String())
	}
}

// TestAuditWebhookFailsFast_WhenClusterCADataEmpty asserts the TLS
// Secret guard fires when the operator forgets the cluster CA bundle.
func TestAuditWebhookFailsFast_WhenClusterCADataEmpty(t *testing.T) {
	args := []string{"template", "olaitan", chartDir(t),
		"--set", "secrets.redisPassword=test-password",
		"--set", "auditWebhook.enabled=true",
		"--set", "auditWebhook.caBundle=ZmFrZQ==",
		"--set", "auditWebhook.apiserverClientCert=ZmFrZQ==",
		"--set", "auditWebhook.apiserverClientKey=ZmFrZQ==",
		"--set", "auditWebhook.servingCert=ZmFrZQ==",
		"--set", "auditWebhook.servingKey=ZmFrZQ==",
	}
	cmd := exec.Command("helm", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("helm template with empty clusterCAData succeeded; expected guard to fire")
	}
	if !strings.Contains(stderr.String(), "auditWebhook.clusterCAData is required") {
		t.Errorf("expected clusterCAData guard, got:\n%s", stderr.String())
	}
}

// TestDaemonsetMountsAuditTLSSecret_WhenEnabled confirms the collector
// DaemonSet mounts the audit-tls Secret at /etc/olaitan/audit-tls when
// the gate is on, AND does not mount it when the gate is off. The
// asserts target the DaemonSet pod spec specifically (the same path
// string also appears in the baked olaitan.yaml ConfigMap, which is
// inert until the adapter is gated on).
func TestDaemonsetMountsAuditTLSSecret_WhenEnabled(t *testing.T) {
	disabledRender := helmTemplate(t, []string{"falco.enabled=false", "nats.enabled=false", "redis.enabled=false"})
	disabledMs := parseManifests(t, disabledRender)
	for _, m := range findByKind(disabledMs, "DaemonSet") {
		if strings.Contains(m.Metadata.Name, "collector") {
			yamlBytes, _ := yaml.Marshal(&m.Raw)
			if strings.Contains(string(yamlBytes), "name: audit-tls") {
				t.Errorf("audit-tls volume rendered on DaemonSet with auditWebhook.enabled=false")
			}
		}
	}

	enabledArgs := append([]string{"falco.enabled=false", "nats.enabled=false", "redis.enabled=false"}, auditWebhookEnabledArgs()...)
	enabledRender := helmTemplate(t, enabledArgs)
	enabledMs := parseManifests(t, enabledRender)
	mountFound := false
	portFound := false
	for _, m := range findByKind(enabledMs, "DaemonSet") {
		if !strings.Contains(m.Metadata.Name, "collector") {
			continue
		}
		yamlBytes, _ := yaml.Marshal(&m.Raw)
		dsText := string(yamlBytes)
		if strings.Contains(dsText, "name: audit-tls") &&
			strings.Contains(dsText, "/etc/olaitan/audit-tls") {
			mountFound = true
		}
		if strings.Contains(dsText, "name: audit-webhook") &&
			strings.Contains(dsText, "containerPort: 8443") {
			portFound = true
		}
	}
	if !mountFound {
		t.Errorf("audit-tls volume + mount not rendered on collector DaemonSet with auditWebhook.enabled=true")
	}
	if !portFound {
		t.Errorf("audit-webhook container port (8443) not rendered on collector DaemonSet with auditWebhook.enabled=true")
	}
}

// TestValidatingWebhookConfigurationUntouched is the negative
// regression test the Story 1.7 ACs require: enabling audit-webhook
// must NOT change the existing admission-webhook stub from Story 1.1.
// Specifically, the rule list (pods/services/configmaps/secrets +
// deployments/daemonsets/statefulsets + networkpolicies +
// rolebindings/clusterrolebindings) and the namespaceSelector
// exclusions must remain intact.
func TestValidatingWebhookConfigurationUntouched(t *testing.T) {
	args := append([]string{"falco.enabled=false", "nats.enabled=false", "redis.enabled=false"}, auditWebhookEnabledArgs()...)
	rendered := helmTemplate(t, args)
	for _, want := range []string{
		"audit.olaitan.io",
		"sideEffects: None",
		"failurePolicy: Ignore",
		"rolebindings",
		"clusterrolebindings",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("ValidatingWebhookConfiguration stub from Story 1.1 missing %q (Story 1.7 must NOT modify it)", want)
		}
	}
}

// TestContainerdSensorAbsent_WhenDisabled is the negative-default
// regression test for Story 1.8: with containerdSensor.enabled=false
// (the chart default) the rendered DaemonSet must NOT carry the
// containerd-socket volume or volumeMount. A regression that always
// renders the host-path mount would expand the agent's privilege
// surface on every existing install -- catching it here keeps the
// default-off promise honest.
func TestContainerdSensorAbsent_WhenDisabled(t *testing.T) {
	rendered := helmTemplate(t, nil)
	if strings.Contains(rendered, "containerd-socket") {
		t.Errorf("containerd-socket volume/mount rendered with containerdSensor disabled by default; rendered sample:\n%s",
			snippet(rendered, "containerd-socket"))
	}
}

// TestContainerdSensorRenders_WhenEnabled asserts the DaemonSet
// gains the host-path volume + (read-only, post-P2) volumeMount when
// the chart value is flipped to enabled. The host-side path mounts
// the PARENT directory of the socket file, mirroring the Falco
// socket mount: a containerd restart that removes-and-recreates the
// socket inode is observed without remount. Post-P3 the hostPath
// volume uses type: Directory (not DirectoryOrCreate) so a
// misconfigured node fails loudly instead of materialising an empty
// directory at the mount path.
func TestContainerdSensorRenders_WhenEnabled(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"containerdSensor.enabled=true",
	})
	if !strings.Contains(rendered, `- name: containerd-socket
              mountPath: "/run/containerd"`) {
		t.Errorf("containerd-socket volumeMount not rendered with containerdSensor.enabled=true; rendered sample:\n%s",
			snippet(rendered, "containerd-socket"))
	}
	if !strings.Contains(rendered, "readOnly: true") {
		t.Errorf("containerd-socket volumeMount missing readOnly: true (P2); rendered sample:\n%s",
			snippet(rendered, "containerd-socket"))
	}
	if !strings.Contains(rendered, `- name: containerd-socket
          hostPath:
            path: "/run/containerd"`) {
		t.Errorf("containerd-socket hostPath volume not rendered with containerdSensor.enabled=true; rendered sample:\n%s",
			snippet(rendered, "hostPath"))
	}
	if !strings.Contains(rendered, "type: Directory") {
		t.Errorf("containerd-socket hostPath missing type: Directory (P3); rendered sample:\n%s",
			snippet(rendered, "containerd-socket"))
	}
}

// TestContainerdSocketPathConfigurable verifies that overriding
// containerdSensor.socketPath flows through to both the volumeMount
// and the hostPath. Operators with non-standard install layouts
// (k3s under /run/k3s/containerd/...) need this knob; regression
// here would silently mount the wrong directory.
func TestContainerdSocketPathConfigurable(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"containerdSensor.enabled=true",
		"containerdSensor.socketPath=/run/k3s/containerd/containerd.sock",
	})
	if !strings.Contains(rendered, `mountPath: "/run/k3s/containerd"`) {
		t.Errorf("custom socketPath did not propagate to mountPath; rendered sample:\n%s",
			snippet(rendered, "containerd-socket"))
	}
	if !strings.Contains(rendered, `path: "/run/k3s/containerd"`) {
		t.Errorf("custom socketPath did not propagate to hostPath path; rendered sample:\n%s",
			snippet(rendered, "containerd-socket"))
	}
}

// TestContainerdSensorMountsParentDirectoryNotFile guards against a
// regression where the Olaitan collector's volume path would be the
// socket file itself ("/run/containerd/containerd.sock") rather than
// the parent directory. Mounting the file inode breaks across
// containerd restarts that recreate the inode; the parent-directory
// mount observes the new socket file without a pod restart.
//
// Scope: only the Olaitan-owned collector DaemonSet. The Falco
// subchart's own DaemonSet renders host-side socket paths
// (`/run/containerd/containerd.sock`, `/run/k3s/containerd/...`) for
// its own runtime-discovery feature; those are NOT this story's
// concern.
func TestContainerdSensorMountsParentDirectoryNotFile(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"containerdSensor.enabled=true",
	})
	ms := parseManifests(t, rendered)
	dss := findByKind(ms, "DaemonSet")
	for _, ds := range dss {
		// Scope to the Olaitan-owned collector DaemonSet; skip the
		// Falco subchart's DaemonSet (which has its own runtime
		// socket-discovery hostPath block).
		if !strings.Contains(ds.Metadata.Name, "olaitan") || !strings.Contains(ds.Metadata.Name, "collector") {
			continue
		}
		yamlBytes, _ := yaml.Marshal(&ds.Raw)
		text := string(yamlBytes)
		// Find the containerd-socket volume + mount entries inside
		// the Olaitan DaemonSet only and assert each path:/mountPath
		// inside that scope is the parent directory.
		idx := strings.Index(text, "name: containerd-socket")
		if idx == -1 {
			t.Fatalf("Olaitan collector DaemonSet missing containerd-socket entry; rendered:\n%s",
				snippet(text, "volumes"))
		}
		// Inspect the next 20 lines after each containerd-socket marker.
		remaining := text
		for {
			pos := strings.Index(remaining, "name: containerd-socket")
			if pos == -1 {
				break
			}
			window := remaining[pos:]
			if end := indexNthLine(window, 6); end > 0 {
				window = window[:end]
			}
			for _, line := range strings.Split(window, "\n") {
				stripped := strings.TrimSpace(line)
				if !strings.HasPrefix(stripped, "path:") && !strings.HasPrefix(stripped, "mountPath:") {
					continue
				}
				if strings.Contains(stripped, "/run/containerd/containerd.sock") {
					t.Errorf("Olaitan containerd-socket entry references the socket file: %q (must be the parent directory)",
						stripped)
				}
			}
			remaining = remaining[pos+1:]
		}
	}
}

// indexNthLine returns the byte offset of the n-th \n in s, or -1 if
// fewer newlines exist. Helper for slicing a fixed window of lines
// after a needle.
func indexNthLine(s string, n int) int {
	count := 0
	for i, r := range s {
		if r != '\n' {
			continue
		}
		count++
		if count == n {
			return i
		}
	}
	return -1
}

// TestContainerdSensorEmptySocketPathFails verifies the fail-fast
// guard added to daemonset.yaml: enabling the sensor without a
// socket path is a misconfiguration that must crashloop helm render
// rather than render a broken DaemonSet that mounts an empty path
// on every node.
func TestContainerdSensorEmptySocketPathFails(t *testing.T) {
	args := []string{
		"template", "olaitan-test", chartDir(t),
		"--set", "secrets.redisPassword=test-password",
		"--set", "containerdSensor.enabled=true",
		"--set", "containerdSensor.socketPath=",
	}
	cmd := exec.Command("helm", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("helm template succeeded with containerdSensor.enabled=true and empty socketPath; expected fail-fast")
	}
	if !strings.Contains(stderr.String(), "containerdSensor.socketPath is required") {
		t.Errorf("stderr did not mention the fail-fast guard; got:\n%s", stderr.String())
	}
}

// TestContainerdSensorConfigmapBridge_StalenessTimeout asserts the
// Story 1.8 P27 ConfigMap bridge propagates a `--set
// containerdSensor.stalenessTimeout=...` override into the rendered
// detection.sources.containerd.staleness_timeout field. Pre-P27 the
// chart only exposed `enabled` and `socketPath`; runtime knobs lived
// only in config/olaitan.yaml and `helm install --set` could not
// reach them, a silent operator trap.
func TestContainerdSensorConfigmapBridge_StalenessTimeout(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"falco.enabled=false",
		"nats.enabled=false",
		"redis.enabled=false",
		"containerdSensor.enabled=true",
		"containerdSensor.stalenessTimeout=42m",
	})
	if !strings.Contains(rendered, `staleness_timeout: "42m"`) {
		t.Errorf("staleness_timeout override did not propagate to ConfigMap; rendered sample:\n%s",
			snippet(rendered, "containerd:"))
	}
	// Audit block's staleness_timeout (5m default) must be untouched.
	if !strings.Contains(rendered, `staleness_timeout: "5m"`) {
		t.Errorf("audit block staleness_timeout was mutated by the containerd bridge; rendered sample:\n%s",
			snippet(rendered, "audit:"))
	}
}

// TestContainerdSensorConfigmapBridge_SocketPath asserts the bridge
// keeps Helm's containerdSensor.socketPath in sync with the rendered
// detection.sources.containerd.socket_path. Pre-P27 the operator had
// to set the path twice (once per file) and a desync would silently
// dial the wrong socket on each node.
func TestContainerdSensorConfigmapBridge_SocketPath(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"falco.enabled=false",
		"nats.enabled=false",
		"redis.enabled=false",
		"containerdSensor.enabled=true",
		"containerdSensor.socketPath=/run/k3s/containerd/containerd.sock",
	})
	if !strings.Contains(rendered, `socket_path: "/run/k3s/containerd/containerd.sock"`) {
		t.Errorf("socketPath override did not propagate to ConfigMap socket_path; rendered sample:\n%s",
			snippet(rendered, "containerd:"))
	}
	// And the chart's own enabled-flag bridge: containerdSensor.enabled=true
	// must flip detection.sources.containerd.enabled to true so the
	// adapter actually runs.
	if !strings.Contains(rendered, "containerd:\n          enabled: true") {
		t.Errorf("containerdSensor.enabled=true did not flip detection.sources.containerd.enabled; rendered sample:\n%s",
			snippet(rendered, "containerd:"))
	}
}

// TestContainerdSensorConfigmapBridge_RetryStrategies asserts both
// nested retry blocks (connect_retry / publish_retry) bridge their
// scalar fields into the ConfigMap. The two blocks share field names
// (min/max/multiplier/jitter/max_attempts), so the regex bridge has
// to disambiguate via the parent header; this test pins that
// behaviour.
func TestContainerdSensorConfigmapBridge_RetryStrategies(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"falco.enabled=false",
		"nats.enabled=false",
		"redis.enabled=false",
		"containerdSensor.enabled=true",
		"containerdSensor.connectRetry.min=3s",
		"containerdSensor.connectRetry.max=99s",
		"containerdSensor.publishRetry.min=222ms",
		"containerdSensor.publishRetry.maxAttempts=7",
	})
	for _, want := range []string{
		`min: "3s"`,
		`max: "99s"`,
		`min: "222ms"`,
		"max_attempts: 7",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("retry-strategy override %q did not propagate to ConfigMap; rendered sample:\n%s",
				want, snippet(rendered, "containerd:"))
		}
	}
}

// TestContainerdSensorMountReadOnly asserts the P2 fix landed: the
// containerd-socket volumeMount must be readOnly: true when the
// sensor is enabled. K8s hostPath best practice for runtime sockets;
// regression here would re-expose the unnecessary write surface.
func TestContainerdSensorMountReadOnly(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"containerdSensor.enabled=true",
	})
	if !strings.Contains(rendered, "readOnly: true") {
		t.Errorf("containerd-socket volumeMount missing readOnly: true; rendered sample:\n%s",
			snippet(rendered, "containerd-socket"))
	}
	if strings.Contains(rendered, `- name: containerd-socket
              mountPath: "/run/containerd"
              readOnly: false`) {
		t.Errorf("containerd-socket volumeMount still rendered with readOnly: false (P2 regression)")
	}
}

// TestContainerdSensorHostPathTypeDirectory asserts the P3 fix landed:
// the hostPath volume must use type: Directory (not
// DirectoryOrCreate). Pre-P3 a misconfigured node (no containerd, or
// CRI-O) would silently materialise an empty root-owned directory at
// the path; with type: Directory the pod fails loudly so the
// operator notices.
func TestContainerdSensorHostPathTypeDirectory(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"containerdSensor.enabled=true",
	})
	if !strings.Contains(rendered, `type: Directory`) {
		t.Errorf("containerd-socket hostPath missing type: Directory; rendered sample:\n%s",
			snippet(rendered, "containerd-socket"))
	}
	if strings.Contains(rendered, `type: DirectoryOrCreate`) {
		// The Olaitan-owned containerd-socket volume must NOT use
		// DirectoryOrCreate. The Falco subchart may legitimately use
		// it for its own runtime-discovery hostPaths; scope the
		// assertion to a window around the containerd-socket name to
		// keep that subchart's behaviour out of the assertion.
		idx := strings.Index(rendered, "name: containerd-socket")
		if idx >= 0 {
			window := rendered[idx:]
			if end := strings.Index(window, "---"); end > 0 && end < 600 {
				window = window[:end]
			}
			if strings.Contains(window, "DirectoryOrCreate") {
				t.Errorf("containerd-socket hostPath still rendered with DirectoryOrCreate (P3 regression); window:\n%s", window)
			}
		}
	}
}

// TestContainerdSocketPathFailsFast_RootOnly asserts the P16 fail-
// fast: setting socketPath to "/" (or any path whose parent dir is
// "/") must crash helm template rather than render a host-root
// mount.
func TestContainerdSocketPathFailsFast_RootOnly(t *testing.T) {
	args := []string{
		"template", "olaitan-test", chartDir(t),
		"--set", "secrets.redisPassword=test-password",
		"--set", "containerdSensor.enabled=true",
		"--set", "containerdSensor.socketPath=/foo",
	}
	cmd := exec.Command("helm", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatal("helm template succeeded with socketPath=/foo (parent dir = /); expected fail-fast")
	}
	if !strings.Contains(stderr.String(), "host root") {
		t.Errorf("stderr did not mention the host-root guard; got:\n%s", stderr.String())
	}
}

// TestContainerdSocketPathFailsFast_RelativePath asserts the P16
// fail-fast on a non-absolute path (which would be interpreted
// relative to the host's cwd, meaningless for hostPath).
func TestContainerdSocketPathFailsFast_RelativePath(t *testing.T) {
	args := []string{
		"template", "olaitan-test", chartDir(t),
		"--set", "secrets.redisPassword=test-password",
		"--set", "containerdSensor.enabled=true",
		"--set", "containerdSensor.socketPath=run/containerd/containerd.sock",
	}
	cmd := exec.Command("helm", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatal("helm template succeeded with relative socketPath; expected fail-fast")
	}
	if !strings.Contains(stderr.String(), "absolute path") {
		t.Errorf("stderr did not mention the absolute-path guard; got:\n%s", stderr.String())
	}
}

// TestKubeconform runs `kubeconform` against the rendered chart for
// K8s 1.29. Skips when kubeconform is not on PATH (local dev case) —
// CI installs it via `go install`.
func TestKubeconform(t *testing.T) {
	if _, err := exec.LookPath("kubeconform"); err != nil {
		t.Skip("kubeconform not on PATH; install via `go install github.com/yannh/kubeconform/cmd/kubeconform@v0.6.7`")
	}

	// Story 3.4 round-2 review: conditional objects must be validated
	// too, or new gated YAML (the ollama Deployment/Service/
	// NetworkPolicy and the release-policy matchExpressions exclusion)
	// ships schema-unchecked.
	for name, sets := range map[string][]string{
		"default":        nil,
		"ollama-enabled": {"ollama.enabled=true", "analyst.provider=local"},
	} {
		rendered := helmTemplate(t, sets)

		cmd := exec.Command("kubeconform",
			"-strict",
			"-summary",
			"-kubernetes-version", "1.29.0",
			"-schema-location", "default",
			"-skip", "CustomResourceDefinition",
		)
		cmd.Stdin = strings.NewReader(rendered)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("kubeconform (%s render) failed: %v\nstdout:\n%s\nstderr:\n%s",
				name, err, stdout.String(), stderr.String())
		}
	}
}

// applogSidecarEnabledArgs returns the minimum --set list to enable
// the applog admission webhook with manual self-signed TLS material.
// Tests append further --set entries to override individual knobs.
func applogSidecarEnabledArgs() []string {
	return []string{
		"applogSidecar.enabled=true",
		"applogSidecar.tls.servingCert=ZmFrZS1jZXJ0",
		"applogSidecar.tls.servingKey=ZmFrZS1rZXk=",
		"applogSidecar.tls.caBundle=ZmFrZS1jYQ==",
	}
}

// TestApplogSidecarRenders_WhenEnabled asserts the four chart resources
// (Deployment, Service, MutatingWebhookConfiguration, TLS Secret) are
// all present when applogSidecar.enabled=true.
func TestApplogSidecarRenders_WhenEnabled(t *testing.T) {
	args := append([]string{"falco.enabled=false", "nats.enabled=false", "redis.enabled=false"}, applogSidecarEnabledArgs()...)
	rendered := helmTemplate(t, args)
	for _, want := range []string{
		"olaitan/templates/applog-webhook-deployment.yaml",
		"olaitan/templates/applog-webhook-service.yaml",
		"olaitan/templates/applog-webhook-mutatingconfiguration.yaml",
		"olaitan/templates/applog-webhook-tls-secret.yaml",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("expected source comment %q in render", want)
		}
	}
}

// TestApplogSidecarAbsent_WhenDisabled asserts none of the four
// resources render when the gate is off (the default).
func TestApplogSidecarAbsent_WhenDisabled(t *testing.T) {
	rendered := helmTemplate(t, []string{"falco.enabled=false", "nats.enabled=false", "redis.enabled=false"})
	for _, off := range []string{
		"olaitan/templates/applog-webhook-deployment.yaml",
		"olaitan/templates/applog-webhook-service.yaml",
		"olaitan/templates/applog-webhook-mutatingconfiguration.yaml",
		"olaitan/templates/applog-webhook-tls-secret.yaml",
	} {
		if strings.Contains(rendered, off) {
			t.Errorf("template %q rendered when applogSidecar.enabled=false", off)
		}
	}
}

// TestApplogWebhookFailurePolicyDefaultIgnore asserts the rendered
// MutatingWebhookConfiguration carries failurePolicy: Ignore by default.
func TestApplogWebhookFailurePolicyDefaultIgnore(t *testing.T) {
	args := append([]string{"falco.enabled=false", "nats.enabled=false", "redis.enabled=false"}, applogSidecarEnabledArgs()...)
	rendered := helmTemplate(t, args)
	if !strings.Contains(rendered, "failurePolicy: Ignore") {
		t.Errorf("expected failurePolicy: Ignore in render\n%s", snippet(rendered, "failurePolicy"))
	}
}

// TestApplogWebhookNamespaceSelectorExcludesKubeSystem asserts the
// default namespaceSelector lists kube-system / kube-public exclusions.
func TestApplogWebhookNamespaceSelectorExcludesKubeSystem(t *testing.T) {
	args := append([]string{"falco.enabled=false", "nats.enabled=false", "redis.enabled=false"}, applogSidecarEnabledArgs()...)
	rendered := helmTemplate(t, args)
	if !strings.Contains(rendered, "kube-system") {
		t.Errorf("expected kube-system in namespaceSelector exclusion list")
	}
	if !strings.Contains(rendered, "kube-public") {
		t.Errorf("expected kube-public in namespaceSelector exclusion list")
	}
}

// TestApplogWebhookFailFast_OnEmptyCABundle asserts the chart rejects
// configurations missing the apiserver-side caBundle when manual TLS is
// in use.
func TestApplogWebhookFailFast_OnEmptyCABundle(t *testing.T) {
	args := []string{"template", "olaitan", chartDir(t),
		"--set", "secrets.redisPassword=test-password",
		"--set", "applogSidecar.enabled=true",
		"--set", "applogSidecar.tls.servingCert=ZmFrZQ==",
		"--set", "applogSidecar.tls.servingKey=ZmFrZQ==",
		// caBundle deliberately absent
	}
	cmd := exec.Command("helm", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("helm template with empty caBundle succeeded; expected guard to fire")
	}
	if !strings.Contains(stderr.String(), "applogSidecar.tls.caBundle") {
		t.Errorf("expected caBundle guard, got:\n%s", stderr.String())
	}
}

// TestApplogWebhookFailFast_OnRelativeStdoutPath asserts the chart
// rejects relative stdout paths.
func TestApplogWebhookFailFast_OnRelativeStdoutPath(t *testing.T) {
	args := append([]string{"template", "olaitan", chartDir(t),
		"--set", "secrets.redisPassword=test-password",
	}, "--set", "applogSidecar.enabled=true",
		"--set", "applogSidecar.tls.servingCert=ZmFrZQ==",
		"--set", "applogSidecar.tls.servingKey=ZmFrZQ==",
		"--set", "applogSidecar.tls.caBundle=ZmFrZQ==",
		"--set", "applogSidecar.stdoutPath=relative/path.log")
	cmd := exec.Command("helm", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("helm template with relative stdoutPath succeeded; expected guard to fire")
	}
	if !strings.Contains(stderr.String(), "stdoutPath must be absolute") {
		t.Errorf("expected stdoutPath guard, got:\n%s", stderr.String())
	}
}

// TestApplogWebhookFailFast_OnIdenticalPaths asserts the chart rejects
// stdout==stderr (would conflate two streams into one file).
func TestApplogWebhookFailFast_OnIdenticalPaths(t *testing.T) {
	args := append([]string{"template", "olaitan", chartDir(t),
		"--set", "secrets.redisPassword=test-password",
	}, "--set", "applogSidecar.enabled=true",
		"--set", "applogSidecar.tls.servingCert=ZmFrZQ==",
		"--set", "applogSidecar.tls.servingKey=ZmFrZQ==",
		"--set", "applogSidecar.tls.caBundle=ZmFrZQ==",
		"--set", "applogSidecar.stdoutPath=/var/log/app/same.log",
		"--set", "applogSidecar.stderrPath=/var/log/app/same.log")
	cmd := exec.Command("helm", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("helm template with identical paths succeeded; expected guard to fire")
	}
	if !strings.Contains(stderr.String(), "stdoutPath and") && !strings.Contains(stderr.String(), "must differ") {
		t.Errorf("expected identical-paths guard, got:\n%s", stderr.String())
	}
}

// TestApplogWebhookFailFast_OnShellMetachars asserts the chart rejects
// stdoutPath containing .. or ~ (path-traversal vector).
func TestApplogWebhookFailFast_OnShellMetachars(t *testing.T) {
	args := append([]string{"template", "olaitan", chartDir(t),
		"--set", "secrets.redisPassword=test-password",
	}, "--set", "applogSidecar.enabled=true",
		"--set", "applogSidecar.tls.servingCert=ZmFrZQ==",
		"--set", "applogSidecar.tls.servingKey=ZmFrZQ==",
		"--set", "applogSidecar.tls.caBundle=ZmFrZQ==",
		"--set", "applogSidecar.stdoutPath=/var/log/app/../escape.log")
	cmd := exec.Command("helm", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("helm template with .. in path succeeded; expected guard to fire")
	}
	if !strings.Contains(stderr.String(), "forbidden characters") {
		t.Errorf("expected forbidden-characters guard, got:\n%s", stderr.String())
	}
}

// TestApplogSidecarTLSCertManagerCertificateRendered asserts that
// when certManagerEnabled=true the chart renders a cert-manager
// Certificate resource (not a kubernetes.io/tls Secret).
func TestApplogSidecarTLSCertManagerCertificateRendered(t *testing.T) {
	args := []string{"falco.enabled=false", "nats.enabled=false", "redis.enabled=false",
		"applogSidecar.enabled=true",
		"applogSidecar.tls.certManagerEnabled=true",
		"applogSidecar.tls.issuerName=olaitan-ca",
	}
	rendered := helmTemplate(t, args)
	if !strings.Contains(rendered, "kind: Certificate") {
		t.Errorf("expected cert-manager Certificate kind in render\n%s", snippet(rendered, "applog-webhook-tls"))
	}
	if !strings.Contains(rendered, "cert-manager.io/v1") {
		t.Errorf("expected cert-manager.io/v1 apiVersion in render")
	}
	if !strings.Contains(rendered, "cert-manager.io/inject-ca-from") {
		t.Errorf("expected cainjector annotation on MutatingWebhookConfiguration")
	}
}

// TestApplogSidecarConfigMapBridgesValues asserts that the chart's
// applogSidecar knobs (stdoutPath, stderrPath, channelBuffer,
// maxLineBytes, publishStallTimeout, stalenessTimeout) flow through to
// the rendered injector Deployment as OLAITAN_WEBHOOK_SIDECAR_* env
// vars. Story 1.9 D1+D2+H3 closure: the prior implementation defined
// these in values.yaml but never propagated them; this test guards the
// bridge so a future regression fails fast.
//
// (Implementation note: the Story 1.9 spec named this test
// "ConfigMapBridgesValues" by analogy with Story 1.8's P27 pattern,
// but this story bridges via Deployment env vars rather than a
// ConfigMap. The spec name is preserved for traceability; the assertion
// is against the actual bridge.)
func TestApplogSidecarConfigMapBridgesValues(t *testing.T) {
	args := append([]string{"falco.enabled=false", "nats.enabled=false", "redis.enabled=false"}, applogSidecarEnabledArgs()...)
	args = append(args,
		"applogSidecar.stdoutPath=/var/log/app/custom-stdout.log",
		"applogSidecar.stderrPath=/var/log/app/custom-stderr.log",
		"applogSidecar.channelBuffer=2048",
		"applogSidecar.maxLineBytes=131072",
		"applogSidecar.publishStallTimeout=7s",
		"applogSidecar.stalenessTimeout=15m",
	)
	rendered := helmTemplate(t, args)

	cases := []struct {
		envName string
		want    string
	}{
		{"OLAITAN_WEBHOOK_SIDECAR_STDOUT_PATH", "/var/log/app/custom-stdout.log"},
		{"OLAITAN_WEBHOOK_SIDECAR_STDERR_PATH", "/var/log/app/custom-stderr.log"},
		{"OLAITAN_WEBHOOK_SIDECAR_CHANNEL_BUFFER", "2048"},
		{"OLAITAN_WEBHOOK_SIDECAR_MAX_LINE_BYTES", "131072"},
		{"OLAITAN_WEBHOOK_SIDECAR_PUBLISH_STALL_TIMEOUT", "7s"},
		{"OLAITAN_WEBHOOK_SIDECAR_STALENESS_TIMEOUT", "15m"},
	}
	for _, tc := range cases {
		if !strings.Contains(rendered, tc.envName) {
			t.Errorf("expected env var %q in rendered Deployment", tc.envName)
			continue
		}
		if !strings.Contains(rendered, tc.want) {
			t.Errorf("expected %s value %q in rendered Deployment", tc.envName, tc.want)
		}
	}
}

// TestApplogInjectorDeploymentRenamed asserts the rendered Deployment,
// Service, MutatingWebhookConfiguration, and TLS Secret all carry the
// olaitan-applog-injector suffix per D3 of the Story 1.9 code review.
func TestApplogInjectorDeploymentRenamed(t *testing.T) {
	args := append([]string{"falco.enabled=false", "nats.enabled=false", "redis.enabled=false"}, applogSidecarEnabledArgs()...)
	rendered := helmTemplate(t, args)
	for _, want := range []string{
		"name: olaitan-applog-injector",     // Deployment + Service + MWC resources
		"name: olaitan-applog-injector-tls", // TLS Secret
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("expected substring %q in rendered chart", want)
		}
	}
	// The old applog-webhook name should not appear as a metadata.name.
	if strings.Contains(rendered, "name: olaitan-applog-webhook\n") {
		t.Errorf("rendered chart still carries the old olaitan-applog-webhook resource name")
	}
}

// TestApplogSidecarHAReplicaCountDefault asserts the webhook
// Deployment defaults to replicas: 2 (HA per the K8s good-practice
// guidance).
func TestApplogSidecarHAReplicaCountDefault(t *testing.T) {
	args := append([]string{"falco.enabled=false", "nats.enabled=false", "redis.enabled=false"}, applogSidecarEnabledArgs()...)
	rendered := helmTemplate(t, args)
	if !strings.Contains(rendered, "replicas: 2") {
		t.Errorf("expected replicas: 2 default for HA, got\n%s", snippet(rendered, "applog-webhook"))
	}
}

// --- Story 1.10: Calico CNI flow sensor ---------------------------

// calicoSensorPathBArgs returns a minimal --set list that enables
// calicoSensor with Path B (operator-supplied PEMs). Used by tests
// that assert render of the rendered Secret, daemonset mount, and
// configmap bridge.
func calicoSensorPathBArgs() []string {
	// The PEM values are intentionally arbitrary base64 -- the
	// chart's required guard only enforces non-empty, not
	// well-formed.
	dummy := "Zm9vYmFy"
	return []string{
		"calicoSensor.enabled=true",
		"calicoSensor.tls.caBundle=" + dummy,
		"calicoSensor.tls.clientCert=" + dummy,
		"calicoSensor.tls.clientKey=" + dummy,
	}
}

// TestCalicoSensorAbsent_WhenDisabled asserts the chart renders no
// CNI TLS Secret and no /etc/olaitan/cni mount when calicoSensor is
// disabled (the default). The bundled olaitan.yaml ConfigMap
// references /etc/olaitan/cni paths as defaults for the calico
// block, so we check the daemonset mount line directly rather than
// the substring (which would false-positive on the embedded config).
func TestCalicoSensorAbsent_WhenDisabled(t *testing.T) {
	rendered := helmTemplate(t, nil)
	if strings.Contains(rendered, "mountPath: /etc/olaitan/cni") {
		t.Errorf("/etc/olaitan/cni mount rendered with calicoSensor disabled by default; rendered sample:\n%s",
			snippet(rendered, "olaitan/cni"))
	}
	if strings.Contains(rendered, "name: cni-tls") {
		t.Errorf("cni-tls volume rendered with calicoSensor disabled by default; rendered sample:\n%s",
			snippet(rendered, "cni-tls"))
	}
}

// TestCalicoSensorPathB_RendersTLSSecret asserts that with Path B
// configured the chart renders the cni-tls Secret carrying the three
// PEM keys at the expected names.
func TestCalicoSensorPathB_RendersTLSSecret(t *testing.T) {
	rendered := helmTemplate(t, calicoSensorPathBArgs())
	for _, want := range []string{
		"name: olaitan-cni-tls",
		"ca.crt:",
		"client.crt:",
		"client.key:",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("expected substring %q in rendered chart; sample:\n%s",
				want, snippet(rendered, "cni-tls"))
		}
	}
}

// TestCalicoSensorPathA_SkipsTLSSecret asserts that with Path A
// (cert-manager-issued Secret name supplied) the chart does NOT
// render an Opaque cni-tls Secret -- the chart consumes the cert-
// manager-managed Secret directly via the daemonset mount.
func TestCalicoSensorPathA_SkipsTLSSecret(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"calicoSensor.enabled=true",
		"calicoSensor.tls.certManagerSecretName=external-cni-tls",
	})
	// The Opaque Secret named <release>-cni-tls must NOT appear.
	if strings.Contains(rendered, "name: olaitan-cni-tls\n") {
		t.Errorf("Path A should not render a chart-owned cni-tls Secret; rendered carries it:\n%s",
			snippet(rendered, "cni-tls"))
	}
	// But the daemonset MUST mount the operator-supplied Secret.
	if !strings.Contains(rendered, "secretName: \"external-cni-tls\"") &&
		!strings.Contains(rendered, "secretName: external-cni-tls") {
		t.Errorf("DaemonSet missing external-cni-tls Secret mount under Path A; sample:\n%s",
			snippet(rendered, "cni-tls"))
	}
}

// TestCalicoSensorEnabled_RequiresTLS asserts the chart fails render
// with a clear message if calicoSensor.enabled=true but no TLS
// material is supplied (neither Path A nor Path B).
func TestCalicoSensorEnabled_RequiresTLS(t *testing.T) {
	cmd := exec.Command("helm", "template", chartDir(t),
		"--set", "redis.auth.password=test",
		"--set", "secrets.redisPassword=test",
		"--set", "calicoSensor.enabled=true",
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("expected helm template to fail when calicoSensor.enabled=true but no TLS configured")
	}
	if !strings.Contains(stderr.String(), "calicoSensor.tls.caBundle is required") {
		t.Errorf("expected fail-fast message mentioning caBundle; stderr:\n%s", stderr.String())
	}
}

// TestCalicoSensorDaemonsetMountsTLS asserts the DaemonSet mounts
// the cni-tls Secret at /etc/olaitan/cni under Path B.
func TestCalicoSensorDaemonsetMountsTLS(t *testing.T) {
	rendered := helmTemplate(t, calicoSensorPathBArgs())
	if !strings.Contains(rendered, "mountPath: /etc/olaitan/cni") {
		t.Errorf("DaemonSet missing /etc/olaitan/cni mount; sample:\n%s",
			snippet(rendered, "cni"))
	}
	if !strings.Contains(rendered, "name: cni-tls") {
		t.Errorf("DaemonSet missing cni-tls volume; sample:\n%s",
			snippet(rendered, "cni-tls"))
	}
}

// TestCalicoSensorNetworkPolicyAllowsGoldmaneEgress asserts the
// rendered NetworkPolicy permits egress from the agent namespace to
// calico-system/goldmane:7443 only when calicoSensor.enabled=true.
func TestCalicoSensorNetworkPolicyAllowsGoldmaneEgress(t *testing.T) {
	disabled := helmTemplate(t, nil)
	if strings.Contains(disabled, "k8s-app: goldmane") {
		t.Errorf("NetworkPolicy carries Goldmane egress rule by default; should be gated on calicoSensor")
	}
	enabled := helmTemplate(t, calicoSensorPathBArgs())
	if !strings.Contains(enabled, "k8s-app: goldmane") {
		t.Errorf("NetworkPolicy missing Goldmane egress rule when calicoSensor.enabled=true; sample:\n%s",
			snippet(enabled, "calico-system"))
	}
	if !strings.Contains(enabled, "port: 7443") {
		t.Errorf("NetworkPolicy missing port 7443 for Goldmane egress; sample:\n%s",
			snippet(enabled, "7443"))
	}
}

// TestCalicoSensorConfigMapBridgesStartTimeGte verifies the
// pointer-shape bridge added by Story 1.10 P31. The chart's
// `calicoSensor.startTimeGte` value can be a number (including 0),
// null, or omitted; the configmap bridge must surface each shape
// faithfully so the Go loader's *int64 distinguishes the three
// semantics per Goldmane proto line 91.
func TestCalicoSensorConfigMapBridgesStartTimeGte(t *testing.T) {
	cases := []struct {
		name     string
		override string
		wantLine string
	}{
		{
			"explicit-zero-now-semantic",
			"calicoSensor.startTimeGte=0",
			"start_time_gte: 0",
		},
		{
			"explicit-negative-replay",
			"calicoSensor.startTimeGte=-300",
			"start_time_gte: -300",
		},
		{
			"omitted-default-replay",
			"", // no startTimeGte override; chart default -60 stays
			"start_time_gte: -60",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := calicoSensorPathBArgs()
			if tc.override != "" {
				args = append(args, tc.override)
			}
			rendered := helmTemplate(t, args)
			if !strings.Contains(rendered, tc.wantLine) {
				t.Errorf("expected %q in rendered configmap; sample:\n%s",
					tc.wantLine, snippet(rendered, "start_time_gte"))
			}
		})
	}
}

// TestCalicoSensorConfigMapBridgesValues asserts that overriding
// chart-side calicoSensor knobs flows through into the rendered
// detection.sources.calico ConfigMap block. This is the dual-flag
// contract: operators flip one Helm value, both the chart-side
// mount and the adapter's runtime config track in lockstep.
func TestCalicoSensorConfigMapBridgesValues(t *testing.T) {
	args := append(
		calicoSensorPathBArgs(),
		`calicoSensor.goldmaneAddr=custom.calico-system.svc:7443`,
		`calicoSensor.stalenessTimeout=20m`,
	)
	rendered := helmTemplate(t, args)
	if !strings.Contains(rendered, `goldmane_addr: "custom.calico-system.svc:7443"`) {
		t.Errorf("ConfigMap bridge did not propagate goldmaneAddr; sample:\n%s",
			snippet(rendered, "goldmane_addr"))
	}
	if !strings.Contains(rendered, `staleness_timeout: "20m"`) {
		t.Errorf("ConfigMap bridge did not propagate stalenessTimeout; sample:\n%s",
			snippet(rendered, "staleness_timeout"))
	}
	// The calico-block enabled flag must flip to true. The block is
	// nested inside `data.olaitan.yaml:` so the indent depth varies;
	// match the canonical "calico:" + (any whitespace) + "enabled:
	// true" pattern via a substring check on the trimmed form.
	if !strings.Contains(strings.ReplaceAll(rendered, " ", ""), "calico:\nenabled:true") {
		t.Errorf("ConfigMap bridge did not flip calico.enabled; sample:\n%s",
			snippet(rendered, "calico:"))
	}
}

// TestPostureConfigMapBridgesValues asserts that overriding the
// chart-side posture knobs flows through into the rendered
// detection.posture ConfigMap block (Story 1.11 AC3 + Helm wiring).
func TestPostureConfigMapBridgesValues(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"posture.enabled=true",
		"posture.cacheTTL=45s",
		"posture.fetchTimeout=3s",
	})
	if !strings.Contains(rendered, `cache_ttl: "45s"`) {
		t.Errorf("ConfigMap bridge did not propagate cacheTTL; sample:\n%s",
			snippet(rendered, "cache_ttl"))
	}
	if !strings.Contains(rendered, `fetch_timeout: "3s"`) {
		t.Errorf("ConfigMap bridge did not propagate fetchTimeout; sample:\n%s",
			snippet(rendered, "fetch_timeout"))
	}
	// posture.enabled stays true; the bridge substitutes the bool
	// value, regardless of upstream yaml default.
	if !strings.Contains(strings.ReplaceAll(rendered, " ", ""), "posture:\nenabled:true") {
		t.Errorf("ConfigMap bridge did not flip posture.enabled; sample:\n%s",
			snippet(rendered, "posture:"))
	}
}

// TestPostureCacheTTLAboveCeilingFails asserts the chart-side
// fail-fast guard (Story 1.11 AC3 + architecture.md:324) rejects
// values above the 60s ceiling at render time, so a misconfigured
// operator value never reaches the Go-side validator.
func TestPostureCacheTTLAboveCeilingFails(t *testing.T) {
	cmd := exec.Command("helm", "template", chartDir(t),
		"--set", "secrets.redisPassword=test",
		"--set", "posture.cacheTTL=120s",
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("expected helm template to fail when posture.cacheTTL exceeds 60s ceiling")
	}
	if !strings.Contains(stderr.String(), "posture.cacheTTL must be <= 60s") {
		t.Errorf("expected fail-fast message naming the ceiling; stderr:\n%s", stderr.String())
	}
}

// TestPostureCacheTTLAtCeilingAcceptsMinuteForms asserts the chart-
// side guard does NOT reject equivalent representations of exactly
// 60s. The TTL ceiling rule is "<= 60s", not "Ns-only", so `1m`,
// `1m0s`, `0m60s`, and `60s` must all be accepted as equivalent
// Go-duration forms at the ceiling. The minute-form regex used to
// fail every `Nm[Ns]?` value unconditionally, blocking legitimate
// at-ceiling configurations; this test locks in the fix.
func TestPostureCacheTTLAtCeilingAcceptsMinuteForms(t *testing.T) {
	for _, ttl := range []string{"1m", "1m0s", "0m60s", "60s"} {
		ttl := ttl
		t.Run(ttl, func(t *testing.T) {
			rendered := helmTemplate(t, []string{
				"posture.enabled=true",
				"posture.cacheTTL=" + ttl,
			})
			want := `cache_ttl: "` + ttl + `"`
			if !strings.Contains(rendered, want) {
				t.Errorf("expected rendered cache_ttl to be %q at the ceiling; sample:\n%s",
					ttl, snippet(rendered, "cache_ttl"))
			}
		})
	}
}

// TestPostureCacheTTLMinuteFormAboveCeilingFails asserts the chart-
// side guard rejects minute-plus-second forms that exceed 60s.
func TestPostureCacheTTLMinuteFormAboveCeilingFails(t *testing.T) {
	for _, ttl := range []string{"2m", "1m30s", "10m"} {
		ttl := ttl
		t.Run(ttl, func(t *testing.T) {
			cmd := exec.Command("helm", "template", chartDir(t),
				"--set", "secrets.redisPassword=test",
				"--set", "posture.cacheTTL="+ttl,
			)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Run(); err == nil {
				t.Fatalf("expected helm template to fail for posture.cacheTTL=%s", ttl)
			}
			if !strings.Contains(stderr.String(), "posture.cacheTTL must be <= 60s") {
				t.Errorf("expected fail-fast message; stderr:\n%s", stderr.String())
			}
		})
	}
}

// TestPostureEnabledViaSetIsRenderedAsBoolLiteral asserts the bridge
// emits a literal `enabled: true` even when the value arrives via
// `--set posture.enabled=true` (a string in Helm coercion semantics).
// A direct `printf "%t"` on a string would emit `%!t(string=true)`
// and break the rendered YAML; the bridge uses an explicit `if` to
// project to "true"/"false".
func TestPostureEnabledViaSetIsRenderedAsBoolLiteral(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"posture.enabled=true",
	})
	if strings.Contains(rendered, "%!t(string=") {
		t.Errorf("printf-on-string artefact leaked into ConfigMap; sample:\n%s",
			snippet(rendered, "posture:"))
	}
	if !strings.Contains(strings.ReplaceAll(rendered, " ", ""), "posture:\nenabled:true") {
		t.Errorf("ConfigMap bridge did not render literal `enabled: true`; sample:\n%s",
			snippet(rendered, "posture:"))
	}
}

// TestPostureRBACRulesPresent asserts the aggregator ClusterRole
// carries the Story 1.11 read-only RBAC rules so the posture client
// can list bindings, network policies, and the owner-controller chain
// per architecture.md:257.
func TestPostureRBACRulesPresent(t *testing.T) {
	rendered := helmTemplate(t, nil)
	// Locate the aggregator ClusterRole rules block. The simplest
	// substring check is sufficient because the verbs/resources are
	// emitted as YAML lines with stable formatting.
	mustHave := []string{
		// rbac.authorization.k8s.io group rules for bindings + roles
		`["rolebindings", "clusterrolebindings", "roles", "clusterroles"]`,
		// apps group rules
		`["deployments", "replicasets", "statefulsets", "daemonsets"]`,
		// batch group rules
		`["jobs", "cronjobs"]`,
		// serviceaccounts read
		`["serviceaccounts"]`,
	}
	for _, want := range mustHave {
		if !strings.Contains(rendered, want) {
			t.Errorf("aggregator ClusterRole missing posture rule resources %q; sample:\n%s",
				want, snippet(rendered, "rolebindings"))
		}
	}
}

// TestMetricsContainerPortPresent gates Story 1.12 AC6: every olaitan
// ring template carries a metrics-named containerPort matching the
// metrics.containerPort knob.
func TestMetricsContainerPortPresent(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"metrics.containerPort=9091",
		"metrics.address=:9091",
	})
	ms := parseManifests(t, rendered)

	for _, kind := range []string{"DaemonSet", "Deployment"} {
		found := false
		for _, m := range findByKind(ms, kind) {
			if !strings.Contains(m.Metadata.Name, "olaitan") {
				continue
			}
			// helmTemplate returns the full stream; we re-scan for the
			// metrics port line below by searching the raw bytes for
			// the kind+name segment. Simpler than walking the yaml.Node.
			if strings.Contains(rendered, "name: metrics") &&
				strings.Contains(rendered, "containerPort: 9091") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s template missing metrics containerPort=9091 in:\n%s",
				kind, snippet(rendered, "name: metrics"))
		}
	}
}

// TestMetricsAnnotationsPresentByDefault asserts the default-on
// scrapeAnnotations flag emits the three prometheus.io annotations
// on every olaitan ring pod template.
func TestMetricsAnnotationsPresentByDefault(t *testing.T) {
	rendered := helmTemplate(t, nil)
	wants := []string{
		`prometheus.io/scrape: "true"`,
		`prometheus.io/port: "9090"`,
		`prometheus.io/path: "/metrics"`,
	}
	for _, w := range wants {
		if !strings.Contains(rendered, w) {
			t.Errorf("default-on scrapeAnnotations: missing %q", w)
		}
	}
}

// TestMetricsAnnotationsAbsentWhenDisabled gates the operator-side
// opt-out: with scrapeAnnotations=false, no prometheus.io annotation
// renders. Useful for clusters running a ServiceMonitor.
func TestMetricsAnnotationsAbsentWhenDisabled(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"metrics.scrapeAnnotations=false",
	})
	for _, w := range []string{
		`prometheus.io/scrape:`,
		`prometheus.io/port:`,
		`prometheus.io/path:`,
	} {
		if strings.Contains(rendered, w) {
			t.Errorf("scrapeAnnotations=false: should not render %q, rendered:\n%s",
				w, snippet(rendered, "prometheus.io"))
		}
	}
}

// TestMetricsBridgeRendersAddress asserts the configmap.yaml regex
// bridge propagates a --set metrics.address override into the
// rendered olaitan.yaml inside the olaitan-config ConfigMap.
func TestMetricsBridgeRendersAddress(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"metrics.address=127.0.0.1:19191",
	})
	want := `address: "127.0.0.1:19191"`
	if !strings.Contains(rendered, want) {
		t.Errorf("metrics.address bridge: missing %q in rendered olaitan.yaml; sample:\n%s",
			want, snippet(rendered, "address:"))
	}
}

// snippet helper for the four metrics tests above is shared with the
// posture tests; the canonical definition lives earlier in this file.

// TestRateLimitDefaultsRendered asserts the production defaults
// (enabled=true, threshold=1000, cooldown=60, sampling_rate=0.1) land
// in the rendered olaitan-config ConfigMap when no --set overrides
// are supplied. Story 1.13 AC4.
func TestRateLimitDefaultsRendered(t *testing.T) {
	rendered := helmTemplate(t, nil)
	idx := strings.Index(rendered, "rate_limit:")
	if idx == -1 {
		t.Fatalf("rate_limit block missing in rendered olaitan.yaml")
	}
	window := rendered[idx:]
	if end := strings.Index(window, "\nresponse:"); end > 0 {
		window = window[:end]
	}
	wants := []string{
		"enabled: true",
		"threshold_events_per_sec: 1000",
		"cooldown_seconds: 60",
		"sampling_rate: 0.1",
	}
	for _, w := range wants {
		if !strings.Contains(window, w) {
			t.Errorf("rateLimit defaults: missing %q in rate_limit block; got:\n%s", w, window)
		}
	}
}

// TestRateLimitBridgeRendersThreshold asserts the configmap.yaml regex
// bridge propagates a --set rateLimit.thresholdEventsPerSec override
// into the rendered olaitan.yaml inside the olaitan-config ConfigMap.
// Story 1.13 AC4.
func TestRateLimitBridgeRendersThreshold(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"rateLimit.thresholdEventsPerSec=500",
	})
	want := "threshold_events_per_sec: 500"
	if !strings.Contains(rendered, want) {
		t.Errorf("rateLimit.thresholdEventsPerSec bridge: missing %q in rendered olaitan.yaml; sample:\n%s",
			want, snippet(rendered, "threshold_events_per_sec"))
	}
}

// TestRateLimitDisabledRendered asserts --set rateLimit.enabled=false
// propagates as `enabled: false` in the rate_limit block of the
// rendered olaitan.yaml. Story 1.13 AC4.
func TestRateLimitDisabledRendered(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"rateLimit.enabled=false",
	})
	// Anchor on the rate_limit block specifically because plenty of
	// other blocks also carry `enabled: true|false` lines.
	idx := strings.Index(rendered, "rate_limit:")
	if idx == -1 {
		t.Fatalf("rate_limit block missing in rendered olaitan.yaml")
	}
	window := rendered[idx:]
	if end := strings.Index(window, "\nresponse:"); end > 0 {
		window = window[:end]
	}
	if !strings.Contains(window, "enabled: false") {
		t.Errorf("rateLimit.enabled=false: rate_limit block does not render 'enabled: false'; got:\n%s", window)
	}
}

func TestCorrelatorConfigMapBridgesValues(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"correlator.windowDuration=45s",
		"correlator.maxPackageBytes=131072",
		"correlator.multiSignalMinSources=3",
		"correlator.highSeverityThreshold=60",
	})
	idx := strings.Index(rendered, "correlator:")
	if idx == -1 {
		t.Fatalf("correlator block missing in rendered olaitan.yaml")
	}
	window := rendered[idx:]
	if end := strings.Index(window, "\n  sources:"); end > 0 {
		window = window[:end]
	}
	for _, want := range []string{
		`window_duration: "45s"`,
		"max_package_bytes: 131072",
		"multi_signal_min_sources: 3",
		"high_severity_threshold: 60",
	} {
		if !strings.Contains(window, want) {
			t.Errorf("rendered correlator block missing %q; got:\n%s", want, window)
		}
	}
}

// TestRulesConfigMapMountedOnAggregator verifies the aggregator
// Deployment template mounts the olaitan-rules ConfigMap at the
// canonical /etc/olaitan/rules path read-only. Story 1.15 AC2.
func TestRulesConfigMapMountedOnAggregator(t *testing.T) {
	rendered := helmTemplate(t, nil)
	// Walk every document looking for the aggregator Deployment
	// specifically. `name: olaitan-aggregator` also appears on the
	// PDB / ServiceAccount / Role / RoleBinding objects, so we have
	// to match on kind+name in the same document.
	var dep string
	for _, doc := range strings.Split(rendered, "\n---") {
		if strings.Contains(doc, "kind: Deployment") && strings.Contains(doc, "name: olaitan-aggregator") {
			dep = doc
			break
		}
	}
	if dep == "" {
		t.Fatalf("aggregator Deployment not rendered")
	}
	if !strings.Contains(dep, "- name: rules") {
		t.Errorf("aggregator Deployment does not declare the rules volume; got:\n%s", snippet(dep, "rules"))
	}
	if !strings.Contains(dep, "mountPath: /etc/olaitan/rules") {
		t.Errorf("aggregator Deployment does not mount rules at /etc/olaitan/rules")
	}
	roIdx := strings.Index(dep, "mountPath: /etc/olaitan/rules")
	if roIdx == -1 {
		t.Errorf("rules mount not found in Deployment")
		return
	}
	// Bound the slice end against len(dep) so a short rendering does
	// not panic the test (code-review P10).
	roEnd := roIdx + 200
	if roEnd > len(dep) {
		roEnd = len(dep)
	}
	if !strings.Contains(dep[roIdx:roEnd], "readOnly: true") {
		t.Errorf("rules mount is not readOnly: true; window:\n%s", dep[roIdx:roEnd])
	}
}

// TestRulesValuesBridgedIntoConfigMap propagates --set rules.enabled
// and --set rules.path overrides through the configmap.yaml bridge
// into the rendered olaitan.yaml. Story 1.15 AC2.
func TestRulesValuesBridgedIntoConfigMap(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"rules.enabled=false",
		"rules.path=/custom/rules/path",
	})
	// Anchor on the rules-block path literal so we land inside the
	// rendered olaitan-config ConfigMap rather than any of the
	// Falco subchart's `rules:` blocks. The path literal under the
	// detection.rules block is uniquely-formed in the chart.
	pathIdx := strings.Index(rendered, `path: "/custom/rules/path"`)
	if pathIdx == -1 {
		t.Fatalf("rules.path override did not propagate into rendered olaitan.yaml; sample:\n%s",
			snippet(rendered, "rules"))
	}
	// Look in a 200-byte window around the path literal for the
	// enabled: false sibling. The two lines render adjacent inside
	// the bridge, so the window comfortably covers both.
	from := pathIdx - 200
	if from < 0 {
		from = 0
	}
	to := pathIdx + 200
	if to > len(rendered) {
		to = len(rendered)
	}
	window := rendered[from:to]
	if !strings.Contains(window, "enabled: false") {
		t.Errorf("rules.enabled=false did not propagate near rules.path; window:\n%s", window)
	}
}

// TestRulesAnchorsPresentInOlaitanYAML asserts the literal anchors
// the configmap.yaml bridge depends on remain in
// config/olaitan.yaml's chart-side copy. Without this guard a
// future edit to the rules block in olaitan.yaml could silently
// break the bridge and operator --set values would be dropped.
// Mirrors Story 1.13's TestHelmRateLimitAnchorsPresent pattern.
func TestRulesAnchorsPresentInOlaitanYAML(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(chartDir(t), "files", "olaitan.yaml"))
	if err != nil {
		t.Fatalf("read olaitan.yaml: %v", err)
	}
	for _, want := range []string{
		"  rules:",
		"    enabled: true",
		`    path: "/etc/olaitan/rules"`,
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("rules-block anchor missing in chart olaitan.yaml: %q", want)
		}
	}
}

// olaitanRulesConfigMap deserialises the Story 1.16 olaitan-rules
// ConfigMap doc emitted by the chart. The Data map carries one entry
// per staged rule: key is the basename (OLT-<CAT>-NNN.yaml), value is
// the full YAML body so a round-trip parser.ParseRule confirms the
// chart did not corrupt the staged corpus.
type olaitanRulesConfigMap struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Data map[string]string `yaml:"data"`
}

// findRulesConfigMap locates the olaitan-rules ConfigMap doc in the
// rendered manifest stream and unmarshals it. Uses a proper multi-doc
// YAML decoder (not strings.Split on "\n---", which is brittle to
// leading "---" at byte 0 and to "---" inside YAML string values) and
// rejects ambiguous matches if more than one ConfigMap in the stream
// happens to be named "olaitan-rules". Bails the test if the doc is
// absent, malformed, or ambiguous.
func findRulesConfigMap(t *testing.T, rendered string) olaitanRulesConfigMap {
	t.Helper()
	dec := yaml.NewDecoder(strings.NewReader(rendered))
	var hits []olaitanRulesConfigMap
	for {
		var cm olaitanRulesConfigMap
		err := dec.Decode(&cm)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// A malformed doc earlier in the stream than the
			// olaitan-rules ConfigMap would previously surface as
			// "ConfigMap not found"; the typed-EOF branch above
			// terminates the loop on EOF only, so non-EOF errors
			// now produce an actionable diagnostic pointing at the
			// real failure.
			t.Fatalf("yaml decode in rendered manifest stream: %v", err)
		}
		if cm.Kind != "ConfigMap" || cm.Metadata.Name != "olaitan-rules" {
			continue
		}
		hits = append(hits, cm)
	}
	switch len(hits) {
	case 0:
		t.Fatalf("olaitan-rules ConfigMap not found in rendered output")
	case 1:
		return hits[0]
	default:
		t.Fatalf("olaitan-rules ConfigMap rendered %d times; expected exactly one", len(hits))
	}
	return olaitanRulesConfigMap{}
}

// TestRulesConfigMapPopulatedFromCorpus verifies Story 1.16 AC1: the
// olaitan-rules ConfigMap carries every rule staged from repo-root
// rules/<category>/, keyed by basename, and each value is faithful
// enough to round-trip through parser.ParseRule. The test also
// confirms every key matches the OLT rule-ID filename regex; a
// regression in the helm-prepare-rules Makefile flatten step would
// surface here with a clean diagnostic.
func TestRulesConfigMapPopulatedFromCorpus(t *testing.T) {
	// Precondition: the chart's olaitan-rules ConfigMap is populated
	// from deploy/helm/olaitan/files/rules/ which is staged by
	// `make helm-prepare-rules`. A developer running the helm test
	// suite standalone without first running the prep target would
	// otherwise see a `len(cm.Data) < 10` failure that points at
	// "missing rules" rather than at the actual cause. Check the
	// staged dir up front so the diagnostic is actionable.
	stagedDir := filepath.Join(chartDir(t), "files", "rules")
	stagedEntries, err := os.ReadDir(stagedDir)
	if err != nil || len(stagedEntries) == 0 {
		t.Fatalf("staged rules dir %s is missing or empty (err=%v); run `make helm-prepare-rules` from repo root before running the helm test suite", stagedDir, err)
	}

	// Canonical authority for the expected ConfigMap key count is the
	// repo-root rules/ tree. Counting on-disk rules separately from
	// the staged dir lets the assertion below catch a silent
	// rule-dropping bug in either the Makefile flatten step or the
	// chart's .Files.Glob; len(cm.Data) >= 10 alone would still
	// pass if the corpus had 11 rules on disk and one was silently
	// dropped, hiding the regression.
	onDiskCount := countOnDiskRules(t)
	rendered := helmTemplate(t, nil)
	cm := findRulesConfigMap(t, rendered)
	if len(cm.Data) < 10 {
		t.Fatalf("olaitan-rules ConfigMap has %d keys; Story 1.16 AC1 requires >=10", len(cm.Data))
	}
	if len(cm.Data) != onDiskCount {
		t.Errorf("olaitan-rules ConfigMap has %d keys but repo-root rules/ tree carries %d *.yaml files; the Makefile flatten step or the chart's .Files.Glob is silently dropping a rule", len(cm.Data), onDiskCount)
	}
	keyRegex := regexp.MustCompile(`^OLT-(EXEC|NET|FILE|PRIV|IMPACT|RECON|PERSIST|EXFIL|CRED|LATERAL)-[0-9]{3}\.yaml$`)
	for key := range cm.Data {
		if !keyRegex.MatchString(key) {
			t.Errorf("ConfigMap key %q does not match OLT rule-ID filename regex", key)
		}
	}
	// Round-trip EVERY staged rule through parser.ParseRule so a
	// staging corruption affecting any rule (encoding mutation, CRLF
	// injection, indentation drift from the template's nindent) is
	// surfaced. Previously only OLT-IMPACT-005 was checked, which let
	// drift on the other nine rules slip past helm CI.
	for key, body := range cm.Data {
		if _, err := parser.ParseRule([]byte(body)); err != nil {
			t.Errorf("ConfigMap key %q: staged content fails parser.ParseRule: %v", key, err)
		}
	}
}

// countOnDiskRules walks the repo-root rules/ tree and returns the
// number of *.yaml / *.yml files (case-insensitive on the extension to
// match the corpus_lint walker). Used as the authoritative key-count
// expectation for TestRulesConfigMapPopulatedFromCorpus.
func countOnDiskRules(t *testing.T) int {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller(0) failed; cannot resolve repo root")
	}
	root := filepath.Join(filepath.Dir(thisFile), "..", "..", "rules")
	n := 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" {
			n++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repo-root rules/ tree under %s: %v", root, err)
	}
	return n
}

// TestRulesConfigMapKeysAreFlatNoDirectory asserts no ConfigMap key
// contains a path separator. Kubernetes rejects ConfigMap data keys
// with `/` at apply time, but a regression in the Makefile flatten
// step would surface that failure deep in `helm install` rather than
// at chart-rendering time. The test catches it earlier with a clean
// diagnostic.
func TestRulesConfigMapKeysAreFlatNoDirectory(t *testing.T) {
	rendered := helmTemplate(t, nil)
	cm := findRulesConfigMap(t, rendered)
	for key := range cm.Data {
		if strings.Contains(key, "/") {
			t.Errorf("ConfigMap key %q contains '/'; K8s data keys cannot contain slashes", key)
		}
	}
}

// TestBaselinesConfigMapBridgedFromValues propagates --set
// baselines.warmupDuration and --set baselines.sigmaMultiplier
// through the configmap.yaml bridge into the rendered olaitan.yaml.
// Story 1.17 AC1/AC2.
// TestFSMPersistenceConfigMapBridgedFromValues asserts the Story 2.3
// fsm.persistenceEnabled / fsm.redisAddr Helm values reach the rendered
// ConfigMap via the configmap.yaml bridge.
func TestFSMPersistenceConfigMapBridgedFromValues(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"fsm.persistenceEnabled=false",
		"fsm.redisAddr=custom-redis:6379",
	})
	if !strings.Contains(rendered, "persistence_enabled: false") {
		t.Errorf("fsm.persistenceEnabled override did not propagate; snippet:\n%s", snippet(rendered, "fsm:"))
	}
	if !strings.Contains(rendered, `redis_addr: "custom-redis:6379"`) {
		t.Errorf("fsm.redisAddr override did not propagate; snippet:\n%s", snippet(rendered, "fsm:"))
	}
}

// TestFSMPersistenceRedisAddrResolvesEndpoint asserts the default empty
// fsm.redisAddr resolves to the bundled subchart Service address rather
// than leaving the dev-host "redis:6379" literal (the in-cluster
// addressing correctness fix).
func TestFSMPersistenceRedisAddrResolvesEndpoint(t *testing.T) {
	rendered := helmTemplate(t, []string{})
	if strings.Contains(rendered, `redis_addr: "redis:6379"`) {
		t.Errorf("fsm redis_addr left at the dev-host literal; the bridge must resolve the Service address. snippet:\n%s", snippet(rendered, "fsm:"))
	}
	if !strings.Contains(rendered, "redis-master:6379") {
		t.Errorf("fsm redis_addr did not resolve to the subchart Service; snippet:\n%s", snippet(rendered, "fsm:"))
	}
}

// TestFSMPersistenceAnchorsPresentInOlaitanYAML guards the literal anchors
// the configmap.yaml fsm-persistence bridge depends on. The persistence
// keys MUST sit directly below deescalation_cooldown_seconds with no
// intervening comment or the regex anchors break and --set values are
// silently dropped.
func TestFSMPersistenceAnchorsPresentInOlaitanYAML(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(chartDir(t), "files", "olaitan.yaml"))
	if err != nil {
		t.Fatalf("read olaitan.yaml: %v", err)
	}
	for _, want := range []string{
		"    deescalation_cooldown_seconds: 600\n    persistence_enabled: true",
		"    persistence_enabled: true\n    redis_addr: \"redis:6379\"",
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("fsm-block anchor missing/discontiguous in chart olaitan.yaml: %q", want)
		}
	}
}

func TestBaselinesConfigMapBridgedFromValues(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"baselines.warmupDuration=15m",
		"baselines.sigmaMultiplier=2.5",
	})
	if !strings.Contains(rendered, `warmup_duration: "15m"`) {
		t.Errorf("baselines.warmupDuration override did not propagate; snippet:\n%s",
			snippet(rendered, "baselines:"))
	}
	if !strings.Contains(rendered, `sigma_multiplier: 2.5`) {
		t.Errorf("baselines.sigmaMultiplier override did not propagate; snippet:\n%s",
			snippet(rendered, "baselines:"))
	}
}

// TestBaselinesAnchorsPresentInOlaitanYAML asserts the literal
// anchors the configmap.yaml bridge depends on remain in
// config/olaitan.yaml's chart-side copy. Without this guard a future
// edit to the baselines block could silently break the bridge and
// operator --set values would be dropped. Mirrors the Story 1.15
// TestRulesAnchorsPresentInOlaitanYAML pattern.
func TestBaselinesAnchorsPresentInOlaitanYAML(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(chartDir(t), "files", "olaitan.yaml"))
	if err != nil {
		t.Fatalf("read olaitan.yaml: %v", err)
	}
	for _, want := range []string{
		"  baselines:",
		"    enabled: true",
		`    warmup_duration: "30m"`,
		"    sigma_multiplier: 3.0",
		`    redis_addr: "redis:6379"`,
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("baselines-block anchor missing in chart olaitan.yaml: %q", want)
		}
	}
}

// TestBaselinesEnabledFalseDisablesAggregatorBlock renders the chart
// with `--set baselines.enabled=false` and asserts the engine is
// disabled while the WarmupDuration / SigmaMultiplier remain at the
// chart-internal defaults (the runtime engine is skipped by
// startAggregatorRing). Story 1.17 AC1/AC3 lock-in for sensing-only
// deployments.
func TestBaselinesEnabledFalseDisablesAggregatorBlock(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"baselines.enabled=false",
	})
	// Locate the baselines block in the rendered olaitan.yaml.
	idx := strings.Index(rendered, "  baselines:")
	if idx == -1 {
		t.Fatalf("baselines block missing from rendered ConfigMap; sample:\n%s",
			snippet(rendered, "baselines"))
	}
	// Window the next ~200 bytes after the block header.
	end := idx + 250
	if end > len(rendered) {
		end = len(rendered)
	}
	window := rendered[idx:end]
	if !strings.Contains(window, "enabled: false") {
		t.Errorf("baselines.enabled=false did not propagate; window:\n%s", window)
	}
}

// --- Story 2.1: deterministic ThreatScore calculator helm wiring ----

// TestScoreConfig_DefaultsRender pins AC2: the chart's default render
// carries the FR30 defaults (rule_weight 0.4, baseline_weight 0.3,
// llm_weight 0.3, llm_cap 35).
func TestScoreConfig_DefaultsRender(t *testing.T) {
	rendered := helmTemplate(t, nil)
	block := evalConfigBlock(t, rendered)
	for _, want := range []string{
		"rule_weight: 0.4",
		"baseline_weight: 0.3",
		"llm_weight: 0.3",
		"llm_cap: 35",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("score defaults render: missing %q in olaitan.yaml block", want)
		}
	}
}

// TestScoreConfig_OperatorOverride confirms the regex bridge in
// configmap.yaml plumbs `--set score.*` overrides through to the
// rendered detection.score.* keys.
func TestScoreConfig_OperatorOverride(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"score.ruleWeight=0.5",
		"score.baselineWeight=0.3",
		"score.llmWeight=0.2",
		"score.llmCap=40",
	})
	block := evalConfigBlock(t, rendered)
	for _, want := range []string{
		"rule_weight: 0.5",
		"baseline_weight: 0.3",
		"llm_weight: 0.2",
		"llm_cap: 40",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("score operator override: missing %q in olaitan.yaml block; block snippet:\n%s",
				want, snippet(block, "score:"))
		}
	}
}

// TestScoreConfig_FailsFast_OnInvalidSum renders the chart with score
// weights summing to > 1.0, then round-trips the embedded olaitan.yaml
// through config.Load to confirm the trust-bound validator rejects it.
// Helm itself does not validate semantic invariants; the rejection
// happens when the aggregator process loads the ConfigMap on startup.
func TestScoreConfig_FailsFast_OnInvalidSum(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"score.ruleWeight=0.5",
		"score.baselineWeight=0.5",
		"score.llmWeight=0.5",
	})
	embedded := extractEmbeddedConfigYAML(t, rendered)

	tmp := filepath.Join(t.TempDir(), "olaitan.yaml")
	if err := os.WriteFile(tmp, []byte(embedded), 0o600); err != nil {
		t.Fatalf("write tmp config: %v", err)
	}
	_, err := configLoad(t, tmp)
	if err == nil {
		t.Fatalf("expected config.Load to reject score weights summing > 1.0")
	}
	if !strings.Contains(err.Error(), "detection.score") {
		t.Errorf("expected error to mention detection.score; got: %v", err)
	}
}

func TestCorrelatorInvalidValuesFailFast(t *testing.T) {
	cases := []struct {
		name    string
		set     string
		wantErr string
	}{
		{"cap", "correlator.maxPackageBytes=65536", "correlator.maxPackageBytes"},
		{"sources", "correlator.multiSignalMinSources=1", "correlator.multiSignalMinSources"},
		{"threshold", "correlator.highSeverityThreshold=101", "correlator.highSeverityThreshold"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("helm", "template", "olaitan", chartDir(t),
				"--set", "secrets.redisPassword=test-password",
				"--set", tc.set,
			)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Run(); err == nil {
				t.Fatalf("helm template succeeded for %s; expected correlator fail-fast", tc.set)
			}
			if !strings.Contains(stderr.String(), tc.wantErr) {
				t.Errorf("stderr did not mention %q:\n%s", tc.wantErr, stderr.String())
			}
		})
	}
}

// --- Story 1.19: Evaluation-matrix and golden-file tests -------------
//
// The chart exposes a single top-level `evaluation.config` knob
// enumerating the canonical evaluation arms (F, RS, RSL, RSLT). When
// set, configmap.yaml's overlay bridges (driven by the four helpers in
// _helpers.tpl) clobber the operator-supplied rules.enabled,
// baselines.enabled, and analyst.provider with the per-arm canonical
// values. When unset, the operator's individual knobs flow through.
//
// These tests pin AC1 (default install), AC2 (F arm), AC3 (RS arm),
// AC4 (helm lint + golden-file diff, golden tests below), and the
// fail-fast guards behind invalid enum values.

// evalConfigBlock returns the segment of rendered olaitan.yaml between
// the `data.olaitan.yaml: |-` literal marker and the next ConfigMap
// boundary so assertions on rules/baselines/analyst do not collide
// with the chart-internal documentation block (which mentions the
// same knob names in comments).
func evalConfigBlock(t *testing.T, rendered string) string {
	t.Helper()
	idx := strings.Index(rendered, "olaitan.yaml: |-")
	if idx == -1 {
		t.Fatalf("olaitan.yaml literal block not found in render; got:\n%s", snippet(rendered, "olaitan-config"))
	}
	end := strings.Index(rendered[idx:], "\n---\n")
	if end == -1 {
		return rendered[idx:]
	}
	return rendered[idx : idx+end]
}

// findEvalLine returns the first `key: value` line under the named
// parent block (e.g. parent="rules", key="enabled") within the
// embedded olaitan.yaml literal. Used by the matrix tests below to
// assert the overlay landed on the right line.
func findEvalLine(t *testing.T, rendered, parent, key string) string {
	t.Helper()
	block := evalConfigBlock(t, rendered)
	// Match the parent header at any indent followed by the keyed line
	// directly underneath. Parent and key are both literal field names
	// from config/olaitan.yaml so no regex meta-escaping is needed.
	re := regexp.MustCompile(`(?m)^[ \t]*` + regexp.QuoteMeta(parent) + `:\s*\n(?:[ \t]*#.*\n)*[ \t]+` + regexp.QuoteMeta(key) + `:\s*(\S.*?)\s*$`)
	m := re.FindStringSubmatch(block)
	if m == nil {
		t.Fatalf("could not locate %s.%s under olaitan.yaml block; block head:\n%s", parent, key, block[:min(800, len(block))])
	}
	return m[1]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestEvaluationConfig_Default_NoOverlay locks AC1: with no
// evaluation.config and no individual overrides, the operator-supplied
// defaults flow through verbatim. The chart-side analyst.provider
// default is "none" (Task 2.2), so the analyst line bridges to "none"
// even with no explicit --set.
func TestEvaluationConfig_Default_NoOverlay(t *testing.T) {
	rendered := helmTemplate(t, nil)
	if got := findEvalLine(t, rendered, "rules", "enabled"); got != "true" {
		t.Errorf("default render: rules.enabled = %q, want true", got)
	}
	if got := findEvalLine(t, rendered, "baselines", "enabled"); got != "true" {
		t.Errorf("default render: baselines.enabled = %q, want true", got)
	}
	if got := findEvalLine(t, rendered, "analyst", "provider"); got != "none" {
		t.Errorf("default render: analyst.provider = %q, want none", got)
	}
}

// TestEvaluationConfig_F_DisablesRulesAndBaselines locks AC2: F mode
// is the Falco-only baseline arm of the Epic 5 evaluation matrix; the
// Olaitan rule engine and baseline engine are both disabled.
func TestEvaluationConfig_F_DisablesRulesAndBaselines(t *testing.T) {
	rendered := helmTemplate(t, []string{"evaluation.config=F"})
	if got := findEvalLine(t, rendered, "rules", "enabled"); got != "false" {
		t.Errorf("F render: rules.enabled = %q, want false", got)
	}
	if got := findEvalLine(t, rendered, "baselines", "enabled"); got != "false" {
		t.Errorf("F render: baselines.enabled = %q, want false", got)
	}
	if got := findEvalLine(t, rendered, "analyst", "provider"); got != "none" {
		t.Errorf("F render: analyst.provider = %q, want none", got)
	}
}

// TestEvaluationConfig_F_DisablesAllNonFalcoSources locks AC2's
// full intent: "only Falco sensor adapter remains active". Story 1.19
// D1 closure: the F arm must also disable the audit, containerd,
// calico source adapters and the posture on-demand sensor so the
// Epic 5 F-vs-Olaitan comparison measures Falco alone.
func TestEvaluationConfig_F_DisablesAllNonFalcoSources(t *testing.T) {
	rendered := helmTemplate(t, []string{"evaluation.config=F"})
	cases := []struct {
		parent, key, want string
	}{
		{"audit", "enabled", "false"},
		{"containerd", "enabled", "false"},
		{"calico", "enabled", "false"},
		{"posture", "enabled", "false"},
	}
	for _, tc := range cases {
		if got := findEvalLine(t, rendered, tc.parent, tc.key); got != tc.want {
			t.Errorf("F render: %s.%s = %q, want %q", tc.parent, tc.key, got, tc.want)
		}
	}
}

// TestEvaluationConfig_RS_DoesNotForceNonFalcoSourcesOff confirms the
// F-arm sources disable is gated to F only. Under RS the operator's
// audit/containerd/calico values flow through.
func TestEvaluationConfig_RS_DoesNotForceNonFalcoSourcesOff(t *testing.T) {
	// Default config/olaitan.yaml has audit/containerd/calico=false,
	// posture=true. Verify RS leaves posture at its file default.
	rendered := helmTemplate(t, []string{"evaluation.config=RS"})
	if got := findEvalLine(t, rendered, "posture", "enabled"); got != "true" {
		t.Errorf("RS render: posture.enabled = %q, want true (RS must not force-disable posture; that is the F arm's job)", got)
	}
}

// TestEvaluationConfig_FailsFast_OnCaseInsensitiveProvider locks the
// Story 1.19 D7 case-normalisation: analyst.provider=NONE is accepted
// (normalised to "none") while genuinely-invalid values still fail.
func TestEvaluationConfig_FailsFast_OnCaseInsensitiveProvider(t *testing.T) {
	// Upper-case "NONE" should succeed (normalised to "none").
	rendered := helmTemplate(t, []string{"analyst.provider=NONE"})
	if got := findEvalLine(t, rendered, "analyst", "provider"); got != "none" {
		t.Errorf("analyst.provider=NONE rendered as %q, want none (case-normalised)", got)
	}
	// Genuinely-invalid value still fails.
	cmd := exec.Command("helm", "template", "olaitan", chartDir(t),
		"--set", "secrets.redisPassword=test-password",
		"--set", "analyst.provider=NopeNope",
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("helm template succeeded with analyst.provider=NopeNope; expected fail-fast")
	}
	if !strings.Contains(stderr.String(), `analyst.provider must be one of`) {
		t.Errorf("stderr did not mention analyst.provider guard:\n%s", stderr.String())
	}
}

// TestEvaluationConfig_RS_EnablesRulesAndBaselinesNoLLM locks AC3:
// RS mode runs the deterministic detection layer end-to-end with the
// LLM tier bypassed.
func TestEvaluationConfig_RS_EnablesRulesAndBaselinesNoLLM(t *testing.T) {
	rendered := helmTemplate(t, []string{"evaluation.config=RS"})
	if got := findEvalLine(t, rendered, "rules", "enabled"); got != "true" {
		t.Errorf("RS render: rules.enabled = %q, want true", got)
	}
	if got := findEvalLine(t, rendered, "baselines", "enabled"); got != "true" {
		t.Errorf("RS render: baselines.enabled = %q, want true", got)
	}
	if got := findEvalLine(t, rendered, "analyst", "provider"); got != "none" {
		t.Errorf("RS render: analyst.provider = %q, want none", got)
	}
}

// TestEvaluationConfig_RSL_RaisesProviderToApi confirms the chart-side
// overlay wires RSL today even though the LLM driver does not yet
// exist (Epic 3 Story 3.x). Functionally equivalent to RS until the
// analyst chain lands; recorded here so the future Epic 3 wiring is a
// single-line story.
func TestEvaluationConfig_RSL_RaisesProviderToApi(t *testing.T) {
	rendered := helmTemplate(t, []string{"evaluation.config=RSL"})
	if got := findEvalLine(t, rendered, "rules", "enabled"); got != "true" {
		t.Errorf("RSL render: rules.enabled = %q, want true", got)
	}
	if got := findEvalLine(t, rendered, "baselines", "enabled"); got != "true" {
		t.Errorf("RSL render: baselines.enabled = %q, want true", got)
	}
	if got := findEvalLine(t, rendered, "analyst", "provider"); got != "api" {
		t.Errorf("RSL render: analyst.provider = %q, want api", got)
	}
}

// TestEvaluationConfig_RSLT_RaisesProviderToApi mirrors the RSL test
// for the full multi-agent arm. RSLT vs RSL chain shape is decided by
// config/olaitan.yaml's analyst.chain.enabled, not by the provider
// selector, so both arms share the api provider.
func TestEvaluationConfig_RSLT_RaisesProviderToApi(t *testing.T) {
	rendered := helmTemplate(t, []string{"evaluation.config=RSLT"})
	if got := findEvalLine(t, rendered, "rules", "enabled"); got != "true" {
		t.Errorf("RSLT render: rules.enabled = %q, want true", got)
	}
	if got := findEvalLine(t, rendered, "baselines", "enabled"); got != "true" {
		t.Errorf("RSLT render: baselines.enabled = %q, want true", got)
	}
	if got := findEvalLine(t, rendered, "analyst", "provider"); got != "api" {
		t.Errorf("RSLT render: analyst.provider = %q, want api", got)
	}
}

// TestEvaluationConfig_OperatorKnobs_RespectedWhenEmpty confirms the
// "no overlay; individual knobs apply verbatim" semantic in
// values.yaml. With evaluation.config="" the operator's
// rules.enabled / baselines.enabled / analyst.provider flow through.
func TestEvaluationConfig_OperatorKnobs_RespectedWhenEmpty(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"evaluation.config=",
		"rules.enabled=false",
		"baselines.enabled=false",
		"analyst.provider=api",
	})
	if got := findEvalLine(t, rendered, "rules", "enabled"); got != "false" {
		t.Errorf("empty-overlay render: rules.enabled = %q, want false", got)
	}
	if got := findEvalLine(t, rendered, "baselines", "enabled"); got != "false" {
		t.Errorf("empty-overlay render: baselines.enabled = %q, want false", got)
	}
	if got := findEvalLine(t, rendered, "analyst", "provider"); got != "api" {
		t.Errorf("empty-overlay render: analyst.provider = %q, want api", got)
	}
}

// TestEvaluationConfig_FailsFast_OnInvalidConfig asserts the chart
// rejects an unknown evaluation.config value at render time rather
// than silently letting the bridge fall through.
func TestEvaluationConfig_FailsFast_OnInvalidConfig(t *testing.T) {
	cmd := exec.Command("helm", "template", "olaitan", chartDir(t),
		"--set", "secrets.redisPassword=test-password",
		"--set", "evaluation.config=Q",
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("helm template succeeded with evaluation.config=Q; expected fail-fast")
	}
	if !strings.Contains(stderr.String(), `evaluation.config must be one of`) {
		t.Errorf("stderr did not mention evaluation.config guard:\n%s", stderr.String())
	}
}

// TestEvaluationConfig_FailsFast_OnInvalidProvider asserts the chart
// rejects an unknown analyst.provider value at render time.
func TestEvaluationConfig_FailsFast_OnInvalidProvider(t *testing.T) {
	cmd := exec.Command("helm", "template", "olaitan", chartDir(t),
		"--set", "secrets.redisPassword=test-password",
		"--set", "analyst.provider=openai",
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("helm template succeeded with analyst.provider=openai; expected fail-fast")
	}
	if !strings.Contains(stderr.String(), `analyst.provider must be one of`) {
		t.Errorf("stderr did not mention analyst.provider guard:\n%s", stderr.String())
	}
}

// TestAnalystProviderNone_StandaloneFlag confirms AC1's standalone
// --set analyst.provider=none install path independent of the
// evaluation matrix. With no evaluation.config but explicit
// analyst.provider=none, the rendered analyst block carries "none".
func TestAnalystProviderNone_StandaloneFlag(t *testing.T) {
	rendered := helmTemplate(t, []string{"analyst.provider=none"})
	if got := findEvalLine(t, rendered, "analyst", "provider"); got != "none" {
		t.Errorf("standalone analyst.provider=none: got %q, want none", got)
	}
}

// TestEvaluationAnchorsPresentInOlaitanYAML asserts the literal
// anchors the evaluation overlay depends on remain in
// config/olaitan.yaml's chart-side copy. Without this guard a future
// edit to the rules / baselines / analyst blocks could silently break
// the overlay and operator --set values would be dropped. Mirrors the
// Story 1.15 / 1.17 anchor-presence tests.
func TestEvaluationAnchorsPresentInOlaitanYAML(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(chartDir(t), "files", "olaitan.yaml"))
	if err != nil {
		t.Fatalf("read olaitan.yaml: %v", err)
	}
	for _, want := range []string{
		"  rules:",
		"  baselines:",
		"\nanalyst:\n",
		"  provider: api",
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("evaluation overlay anchor missing in chart olaitan.yaml: %q", want)
		}
	}
}

// --- Story 1.19 Task 6: Golden-file helm template diff harness -------
//
// Architecture.md:1008 makes "every PR runs helm template golden-file
// diff" a mandatory CI invariant. The golden files at
// deploy/helm/testdata/golden/ are byte-stable snapshots of the
// rendered chart for three canonical permutations: the F-arm
// (rules+baselines off, analyst.provider=none), the RS-arm
// (rules+baselines on, analyst.provider=none), and the default
// permutation (no evaluation.config overlay). Mismatch fails the test
// with a unified diff so a chart edit that materially changes
// rendered output is surfaced loudly in PR review.
//
// To regenerate after an intentional chart change, run:
//
//   HELM_GOLDEN_UPDATE=1 go test -tags=helm -run TestGoldenFile \
//     ./deploy/helm/... -count=1
//
// then commit the updated golden files.

// normaliseGolden strips dynamic fields from the rendered manifest so
// chart-version bumps and appVersion bumps do not force a golden
// refresh. Stripped fields:
//   - `# Source: olaitan/templates/...` comment lines (helm metadata)
//   - `helm.sh/chart: olaitan-<semver>` -> CHART_VERSION_REDACTED
//   - `app.kubernetes.io/version: "<semver>"` -> APP_VERSION_REDACTED
//
// Subchart helm.sh/chart labels are LEFT INTACT because those track
// the subchart pin in Chart.yaml; a subchart bump should force a
// golden refresh (NFR13 reproducibility invariant).
func normaliseGolden(rendered string) string {
	out := rendered
	// Strip every `# Source:` comment line (the entire line including
	// trailing newline).
	srcLine := regexp.MustCompile(`(?m)^# Source:.*\n`)
	out = srcLine.ReplaceAllString(out, "")
	// Redact olaitan-only chart-version label. The subchart labels use
	// `helm.sh/chart: redis-25.3.11` etc and remain intact. The
	// optional pre-release suffix accommodates future
	// `0.1.0-rc1`-style tags.
	chartLbl := regexp.MustCompile(`helm\.sh/chart: olaitan-[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.]+)?`)
	out = chartLbl.ReplaceAllString(out, "helm.sh/chart: olaitan-CHART_VERSION_REDACTED")
	// Redact olaitan app-version label only. The chart-side
	// appVersion is always emitted quoted (`"0.1.0"`); subchart
	// versions land unquoted (`8.6.2`) by upstream-Bitnami
	// convention. The quote anchor scopes the redaction to olaitan
	// and leaves subchart-version labels byte-stable so a subchart
	// pin bump still surfaces in the golden diff (NFR13).
	out = regexp.MustCompile(`app\.kubernetes\.io/version: "[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.]+)?"`).
		ReplaceAllString(out, `app.kubernetes.io/version: "APP_VERSION_REDACTED"`)
	return out
}

// goldenPath returns the absolute path to the golden file for the
// given permutation slug. Lives under deploy/helm/testdata/golden/
// rather than under the chart itself so `helm package` outputs stay
// minimal.
func goldenPath(t *testing.T, slug string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller(0) failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "testdata", "golden", slug+".golden.yaml")
}

// goldenUpdate is true when the developer has requested a regeneration
// pass via HELM_GOLDEN_UPDATE=1. We use an env var rather than a Go
// flag because `go test` injects test-only flags via the test binary
// and a custom flag conflicts with the parallel-execution harness.
func goldenUpdate() bool { return os.Getenv("HELM_GOLDEN_UPDATE") == "1" }

// runGolden renders the chart with the given --set values, normalises
// the output, and diffs against the file at deploy/helm/testdata/
// golden/<slug>.golden.yaml. Pass an empty sets slice for the default
// permutation.
func runGolden(t *testing.T, slug string, sets []string) {
	t.Helper()
	rendered := helmTemplate(t, sets)
	got := normaliseGolden(rendered)
	path := goldenPath(t, slug)
	if goldenUpdate() {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir golden dir: %v", err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden file: %v", err)
		}
		// Loud stderr line so accidental HELM_GOLDEN_UPDATE=1 runs
		// (e.g. CI mis-configuration) cannot silently overwrite a
		// golden the maintainer did not intend to regenerate.
		fmt.Fprintf(os.Stderr, "HELM_GOLDEN_UPDATE=1: wrote golden file %s (run `git diff deploy/helm/testdata/golden/` to inspect)\n", path)
		t.Logf("regenerated golden file: %s", path)
		return
	}
	wantBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden file %s: %v (regenerate with HELM_GOLDEN_UPDATE=1)", path, err)
	}
	want := string(wantBytes)
	if got == want {
		return
	}
	// Surface a short unified-diff-like preview so a CI failure log
	// is informative without dumping the whole render. Find the first
	// divergent line + 20 lines either side.
	const ctx = 20
	gotLines := strings.Split(got, "\n")
	wantLines := strings.Split(want, "\n")
	firstDiff := 0
	for firstDiff < len(gotLines) && firstDiff < len(wantLines) && gotLines[firstDiff] == wantLines[firstDiff] {
		firstDiff++
	}
	lo := firstDiff - ctx
	if lo < 0 {
		lo = 0
	}
	gotEnd := firstDiff + ctx
	if gotEnd > len(gotLines) {
		gotEnd = len(gotLines)
	}
	wantEnd := firstDiff + ctx
	if wantEnd > len(wantLines) {
		wantEnd = len(wantLines)
	}
	t.Errorf("golden mismatch for %s at line %d. Regenerate with HELM_GOLDEN_UPDATE=1.\n--- want (%s:%d-%d)\n%s\n--- got (line %d-%d)\n%s",
		slug, firstDiff+1, path, lo+1, wantEnd, strings.Join(wantLines[lo:wantEnd], "\n"),
		lo+1, gotEnd, strings.Join(gotLines[lo:gotEnd], "\n"))
}

// TestGoldenFile_Default pins the rendered chart with no
// evaluation.config overlay; the operator-supplied defaults flow
// through (rules+baselines enabled) and the chart-side
// analyst.provider="none" overlay applies.
func TestGoldenFile_Default(t *testing.T) {
	runGolden(t, "default", nil)
}

// TestGoldenFile_RS pins the rendered chart with the RS evaluation
// arm: rules+baselines enabled, LLM tier bypassed.
func TestGoldenFile_RS(t *testing.T) {
	runGolden(t, "rs", []string{"evaluation.config=RS"})
}

// TestGoldenFile_F pins the rendered chart with the F (Falco-only)
// evaluation arm: rules+baselines disabled, LLM tier bypassed.
func TestGoldenFile_F(t *testing.T) {
	runGolden(t, "f", []string{"evaluation.config=F"})
}

// TestGraduatedIsolationBridgesFromValues (Story 2.10, AC2): the fsm
// threshold/dwell/cooldown and response.{networkPolicy,override,audit} values
// are overlaid onto the rendered config by the configmap bridges.
func TestGraduatedIsolationBridgesFromValues(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"secrets.redisPassword=ci",
		"fsm.thresholds.suspicious=25",
		"fsm.thresholds.restricted=45",
		"fsm.thresholds.quarantined=80",
		"fsm.dwellSeconds.restricted=90",
		"fsm.deescalationCooldownSeconds=300",
		"response.networkPolicy.enabled=true",
		"response.networkPolicy.reconcileIntervalSeconds=20",
		"response.networkPolicy.clusterCidrs={10.0.0.0/8,172.16.0.0/12}",
		"response.networkPolicy.extraAllowedCidrs={8.8.8.8/32}",
		"response.override.enabled=true",
		"response.override.defaultTtlSeconds=60",
		"response.audit.enabled=true",
		"response.audit.retentionTransitionsDays=30",
	})
	for _, want := range []string{
		"watch: 25", "alert: 45", "act: 80",
		"restricted_dwell_seconds: 90",
		"deescalation_cooldown_seconds: 300",
		"reconcile_interval_seconds: 20",
		"- 10.0.0.0/8", "- 172.16.0.0/12", "- 8.8.8.8/32",
		"default_ttl_seconds: 60",
		"retention_transitions_days: 30",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("Story 2.10 bridge did not propagate %q; snippet:\n%s", want, snippet(rendered, "response:"))
		}
	}
	// Boolean enable-flag propagation + the audit-vs-detection-audit
	// disambiguation (the riskiest anchor): the response.* blocks must flip to
	// enabled: true. The audit regex pins the trailing retention key, which
	// exists ONLY under response.audit, so it proves the response block flipped
	// and NOT detection.sources.audit. Indentation-tolerant (the config is
	// embedded as an indented block scalar in the ConfigMap).
	for name, re := range map[string]string{
		"response.networkPolicy.enabled": `(?m)^\s+network_policy:\n\s+enabled: true`,
		"response.override.enabled":      `(?m)^\s+override:\n\s+enabled: true`,
		"response.audit.enabled":         `(?m)^\s+audit:\n\s+enabled: true\n\s+retention_transitions_days:`,
	} {
		if !regexp.MustCompile(re).MatchString(rendered) {
			t.Errorf("%s did not flip the right block (pattern %q); snippet:\n%s", name, re, snippet(rendered, "response:"))
		}
	}
}

// TestGraduatedIsolationDefaultsAreNoOp (Story 2.10, BI-3/BI-4): with no
// overrides, the bridges leave the config defaults untouched (off by default,
// 90/365/365 retention, 20/40/70 thresholds).
func TestGraduatedIsolationDefaultsAreNoOp(t *testing.T) {
	rendered := helmTemplate(t, []string{"secrets.redisPassword=ci"})
	for _, want := range []string{
		"watch: 20", "alert: 40", "act: 70",
		"retention_transitions_days: 90",
		"retention_overrides_days: 365",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("default render lost %q; snippet:\n%s", want, snippet(rendered, "confidence_bands:"))
		}
	}
}

// TestGraduatedIsolationAnchorsPresentInOlaitanYAML guards the literal anchors
// the Story 2.10 configmap bridges depend on; a config-shape drift that moves
// these would otherwise silently drop --set values (the bridges fail-fast at
// render, but this catches the drift at the unit-test layer too).
func TestGraduatedIsolationAnchorsPresentInOlaitanYAML(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(chartDir(t), "files", "olaitan.yaml"))
	if err != nil {
		t.Fatalf("read olaitan.yaml: %v", err)
	}
	for _, want := range []string{
		"  confidence_bands:\n    watch: 20",
		"  network_policy:\n    enabled: false",
		"  override:\n    enabled: false",
		"  audit:\n    enabled: false\n    retention_transitions_days:",
		"    extra_allowed_cidrs: []",
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("Story 2.10 bridge anchor missing/discontiguous in chart olaitan.yaml: %q", want)
		}
	}
}

// --- Story 3.4: optional in-cluster Ollama (FR48) ---

// TestOllamaGate_AllResourcesGated asserts the ollama Deployment,
// Service, and NetworkPolicy are absent by default and present when
// ollama.enabled=true. All gated resources come and go together (a
// partial render is a chart-rot signal), and the default render stays
// byte-identical to the pre-3.4 chart.
func TestOllamaGate_AllResourcesGated(t *testing.T) {
	defaultRender := helmTemplate(t, []string{
		"falco.enabled=false", "nats.enabled=false", "redis.enabled=false",
	})
	for _, m := range parseManifests(t, defaultRender) {
		if strings.HasSuffix(m.Metadata.Name, "-ollama") {
			t.Errorf("%s %s rendered with ollama.enabled=false (default)", m.Kind, m.Metadata.Name)
		}
	}

	enabledRender := helmTemplate(t, []string{
		"falco.enabled=false", "nats.enabled=false", "redis.enabled=false",
		"ollama.enabled=true",
	})
	enabledMs := parseManifests(t, enabledRender)
	want := map[string]bool{"Deployment": false, "Service": false, "NetworkPolicy": false}
	for _, m := range enabledMs {
		if strings.HasSuffix(m.Metadata.Name, "-ollama") {
			if _, ok := want[m.Kind]; ok {
				want[m.Kind] = true
			}
		}
	}
	for kind, found := range want {
		if !found {
			t.Errorf("ollama %s not rendered with ollama.enabled=true", kind)
		}
	}
}

// netpolDoc mirrors the NetworkPolicy spec subset the Story 3.4 tests
// assert STRUCTURALLY (round-1 review: substring assertions cannot
// prove exclusivity -- an extra allow-all peer or port would pass a
// Contains check).
type netpolDoc struct {
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		PodSelector struct {
			MatchLabels      map[string]string `yaml:"matchLabels"`
			MatchExpressions []struct {
				Key      string   `yaml:"key"`
				Operator string   `yaml:"operator"`
				Values   []string `yaml:"values"`
			} `yaml:"matchExpressions"`
		} `yaml:"podSelector"`
		Ingress []struct {
			From []struct {
				PodSelector *struct {
					MatchLabels map[string]string `yaml:"matchLabels"`
				} `yaml:"podSelector"`
				NamespaceSelector *struct{} `yaml:"namespaceSelector"`
				IPBlock           *struct{} `yaml:"ipBlock"`
			} `yaml:"from"`
			Ports []struct {
				Port int `yaml:"port"`
			} `yaml:"ports"`
		} `yaml:"ingress"`
		Egress *[]map[string]any `yaml:"egress"`
	} `yaml:"spec"`
}

func decodeNetpols(t *testing.T, rendered string) map[string]netpolDoc {
	t.Helper()
	out := map[string]netpolDoc{}
	dec := yaml.NewDecoder(strings.NewReader(rendered))
	for {
		var raw map[string]any
		if err := dec.Decode(&raw); err != nil {
			break
		}
		if raw["kind"] != "NetworkPolicy" {
			continue
		}
		b, err := yaml.Marshal(raw)
		if err != nil {
			t.Fatalf("re-marshal netpol: %v", err)
		}
		var np netpolDoc
		if err := yaml.Unmarshal(b, &np); err != nil {
			t.Fatalf("decode netpol: %v", err)
		}
		out[np.Metadata.Name] = np
	}
	return out
}

// TestOllamaNetworkPolicyRestrictsToAggregator: Story 3.4 AC3, asserted
// structurally - the ollama pod accepts EXACTLY ONE ingress rule from
// EXACTLY ONE peer (the aggregator pod selector, no namespace/ipBlock
// widening) on EXACTLY port 11434, its egress is declared and EMPTY
// (the air-gap statement; architecture.md:263 - the policy IS the auth
// boundary), and the RELEASE policy excludes the ollama component so
// the policy union cannot re-grant what this policy denies (round-1
// review HIGH: shared name/instance labels made the release policy's
// ingress/egress apply to the ollama pod too).
func TestOllamaNetworkPolicyRestrictsToAggregator(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"falco.enabled=false", "nats.enabled=false", "redis.enabled=false",
		"ollama.enabled=true",
	})
	nps := decodeNetpols(t, rendered)

	np, ok := nps["olaitan-ollama"]
	if !ok {
		t.Fatalf("olaitan-ollama NetworkPolicy not found; rendered policies: %d", len(nps))
	}
	if got := np.Spec.PodSelector.MatchLabels["app.kubernetes.io/component"]; got != "ollama" {
		t.Errorf("ollama policy podSelector component = %q, want ollama", got)
	}
	if len(np.Spec.Ingress) != 1 {
		t.Fatalf("ollama policy ingress rules = %d, want exactly 1", len(np.Spec.Ingress))
	}
	rule := np.Spec.Ingress[0]
	if len(rule.From) != 1 {
		t.Fatalf("ollama policy ingress peers = %d, want exactly 1", len(rule.From))
	}
	peer := rule.From[0]
	if peer.NamespaceSelector != nil || peer.IPBlock != nil {
		t.Error("ollama policy ingress peer widens beyond a pod selector")
	}
	if peer.PodSelector == nil || peer.PodSelector.MatchLabels["app.kubernetes.io/component"] != "aggregator" {
		t.Errorf("ollama policy ingress peer = %+v, want the aggregator pod selector only (AC3)", peer.PodSelector)
	}
	if len(rule.Ports) != 1 || rule.Ports[0].Port != 11434 {
		t.Errorf("ollama policy ingress ports = %+v, want exactly [11434]", rule.Ports)
	}
	if np.Spec.Egress == nil {
		t.Error("ollama policy egress is undeclared; want declared and EMPTY (the air-gap statement)")
	} else if len(*np.Spec.Egress) != 0 {
		t.Errorf("ollama policy egress = %+v, want empty", *np.Spec.Egress)
	}

	release, ok := nps["olaitan"]
	if !ok {
		t.Fatal("release NetworkPolicy not found in enabled render")
	}
	excluded := false
	for _, expr := range release.Spec.PodSelector.MatchExpressions {
		if expr.Key == "app.kubernetes.io/component" && expr.Operator == "NotIn" {
			for _, v := range expr.Values {
				if v == "ollama" {
					excluded = true
				}
			}
		}
	}
	if !excluded {
		t.Error("release NetworkPolicy does not exclude the ollama component; the policy union re-grants ingress/egress the ollama policy denies")
	}

	// And the exclusion must NOT appear in the default render (the
	// byte-identical fence).
	defaultRender := helmTemplate(t, []string{
		"falco.enabled=false", "nats.enabled=false", "redis.enabled=false",
	})
	defaultNps := decodeNetpols(t, defaultRender)
	if len(defaultNps["olaitan"].Spec.PodSelector.MatchExpressions) != 0 {
		t.Error("release NetworkPolicy carries matchExpressions in the default render; the exclusion must be gated on ollama.enabled")
	}
}

// TestAnalystLocalBridge: Story 3.4 BI-7.5 - Helm-set
// analyst.local.{endpoint,model} land in the rendered olaitan.yaml
// (never a silent no-op), unset values keep the file-side defaults,
// and the bridged config round-trips through the production
// config.Load validator.
func TestAnalystLocalBridge(t *testing.T) {
	overridden := helmTemplate(t, []string{
		"analyst.provider=local",
		"analyst.local.endpoint=http://my-ollama:11434",
		"analyst.local.model=llama3.1:70b",
	})
	embedded := extractEmbeddedConfigYAML(t, overridden)
	assertContains(t, embedded, `endpoint: "http://my-ollama:11434"`,
		"analyst.local.endpoint bridge must rewrite the rendered config")
	assertContains(t, embedded, `model: "llama3.1:70b"`,
		"analyst.local.model bridge must rewrite the rendered config")
	assertContains(t, embedded, "provider: local",
		"analyst.provider bridge must carry the local selector")

	tmp := filepath.Join(t.TempDir(), "olaitan.yaml")
	if err := os.WriteFile(tmp, []byte(embedded), 0o600); err != nil {
		t.Fatalf("write tmp config: %v", err)
	}
	cfg, err := configLoad(t, tmp)
	if err != nil {
		t.Fatalf("bridged config rejected by config.Load: %v", err)
	}
	if cfg.Analyst.Local.Endpoint != "http://my-ollama:11434" || cfg.Analyst.Local.Model != "llama3.1:70b" {
		t.Errorf("loaded analyst.local = %+v, want the bridged values", cfg.Analyst.Local)
	}

	defaults := helmTemplate(t, nil)
	embeddedDefaults := extractEmbeddedConfigYAML(t, defaults)
	assertContains(t, embeddedDefaults, `endpoint: "http://ollama:11434"`,
		"unset analyst.local.endpoint must keep the file-side default")
	assertContains(t, embeddedDefaults, `model: "gemma:2b"`,
		"unset analyst.local.model must keep the file-side default")
}

// TestEvaluationArmAblationToggles (Story 3.16, FR53) pins the LLM-bearing
// evaluation arms: each --set evaluation.config=<arm> renders the correct
// analyst.{provider,l2_enabled,senior_enabled}, round-trips through
// config.Load, and resolves to the intended chain ablation mode. The legacy
// "RSLT" alias maps to RSLT-full.
func TestEvaluationArmAblationToggles(t *testing.T) {
	cases := []struct {
		arm          string
		wantProvider string
		wantL2       bool // L2EnabledOrDefault
		wantSenior   bool // SeniorEnabledOrDefault (precedence: L2 off => Senior off)
	}{
		{"RSL", "api", false, false},          // Standard single-LLM (L1-as-Senior => L1-only)
		{"RSLT-full", "api", true, true},      // full L1 -> L2 -> Senior
		{"RSLT", "api", true, true},           // legacy alias for RSLT-full
		{"RSLT-L1-only", "api", false, false}, // L1-only ablation
		{"RSLT-L1+L2", "api", true, false},    // L1+L2 ablation (Senior off)
	}
	for _, tc := range cases {
		t.Run(tc.arm, func(t *testing.T) {
			rendered := helmTemplate(t, []string{"evaluation.config=" + tc.arm})
			embedded := extractEmbeddedConfigYAML(t, rendered)
			tmp := filepath.Join(t.TempDir(), "olaitan.yaml")
			if err := os.WriteFile(tmp, []byte(embedded), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			cfg, err := configLoad(t, tmp)
			if err != nil {
				t.Fatalf("arm %s config rejected by config.Load: %v", tc.arm, err)
			}
			if cfg.Analyst.Provider != tc.wantProvider {
				t.Errorf("arm %s: analyst.provider = %q, want %q", tc.arm, cfg.Analyst.Provider, tc.wantProvider)
			}
			if cfg.Analyst.L2EnabledOrDefault() != tc.wantL2 {
				t.Errorf("arm %s: L2EnabledOrDefault = %v, want %v", tc.arm, cfg.Analyst.L2EnabledOrDefault(), tc.wantL2)
			}
			if cfg.Analyst.SeniorEnabledOrDefault() != tc.wantSenior {
				t.Errorf("arm %s: SeniorEnabledOrDefault = %v, want %v", tc.arm, cfg.Analyst.SeniorEnabledOrDefault(), tc.wantSenior)
			}
		})
	}
}

// TestEvaluationArmRejectsUnknown pins the fail-fast enum: an unknown
// RSLT-style arm fails the render with the canonical message.
func TestEvaluationArmRejectsUnknown(t *testing.T) {
	cmd := exec.Command("helm", "template", "olaitan", chartDir(t),
		"--set", "secrets.redisPassword=test-password",
		"--set", "evaluation.config=RSLT-bogus",
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatal("helm template succeeded with evaluation.config=RSLT-bogus; expected fail-fast")
	}
	if !strings.Contains(stderr.String(), "evaluation.config must be one of") {
		t.Errorf("stderr did not mention the evaluation.config guard:\n%s", stderr.String())
	}
}

// TestOllamaModeRoutesLocalWithNetworkPolicy (Story 3.16 AC5/FR48): with
// analyst.provider=local + ollama.enabled the chart renders the in-cluster
// Ollama Deployment + the egress-restricting NetworkPolicy, and the analyst
// routes to the local provider (no external egress).
func TestOllamaModeRoutesLocalWithNetworkPolicy(t *testing.T) {
	rendered := helmTemplate(t, []string{"analyst.provider=local", "ollama.enabled=true"})
	if !strings.Contains(rendered, "olaitan-ollama") {
		t.Fatal("ollama Deployment/Service not rendered when ollama.enabled=true")
	}
	ms := parseManifests(t, rendered)
	var sawOllamaNetpol bool
	for _, m := range ms {
		if m.Kind == "NetworkPolicy" && strings.Contains(m.Metadata.Name, "ollama") {
			sawOllamaNetpol = true
		}
	}
	if !sawOllamaNetpol {
		t.Error("ollama NetworkPolicy must render to restrict Ollama reachability (FR48)")
	}
	embedded := extractEmbeddedConfigYAML(t, rendered)
	tmp := filepath.Join(t.TempDir(), "olaitan.yaml")
	if err := os.WriteFile(tmp, []byte(embedded), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := configLoad(t, tmp)
	if err != nil {
		t.Fatalf("ollama config rejected: %v", err)
	}
	if cfg.Analyst.Provider != "local" {
		t.Errorf("analyst.provider = %q, want local (Ollama)", cfg.Analyst.Provider)
	}
}

// loadEmbedded renders, extracts, and config.Loads the embedded config in
// one step (Story 3.16 helper).
func loadEmbedded(t *testing.T, sets []string) *config.Config {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), "olaitan.yaml")
	if err := os.WriteFile(tmp, []byte(extractEmbeddedConfigYAML(t, helmTemplate(t, sets))), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := configLoad(t, tmp)
	if err != nil {
		t.Fatalf("config.Load rejected the render: %v", err)
	}
	return cfg
}

// TestAnalystAPIEndpointAndKeyWiring (Story 3.16) pins the LLM-tier
// deployability gap round-1 review caught: the api provider must get both its
// endpoint (so it dials the configured server, not the vendor default) and
// its API key (projected from the Secret into the env var the analyst reads).
func TestAnalystAPIEndpointAndKeyWiring(t *testing.T) {
	rendered := helmTemplate(t, []string{"secrets.llmApiKey=k"})
	if !strings.Contains(rendered, "name: olaitan-llm") || !strings.Contains(rendered, "key: llm-api-key") {
		t.Errorf("aggregator must project the LLM key Secret into the olaitan-llm env var\n%s", snippet(rendered, "llm-api-key"))
	}
	cfg := loadEmbedded(t, []string{"analyst.api.endpoint=http://fake-llm:8080/v1", "analyst.api.model=fake"})
	if cfg.Analyst.API.Endpoint != "http://fake-llm:8080/v1" {
		t.Errorf("analyst.api.endpoint = %q, want the bridged value", cfg.Analyst.API.Endpoint)
	}
	if cfg.Analyst.API.Model != "fake" {
		t.Errorf("analyst.api.model = %q, want fake", cfg.Analyst.API.Model)
	}
	// A custom apiKeySecret renames the env var AND the config key in lockstep.
	renamed := helmTemplate(t, []string{"analyst.api.apiKeySecret=MY_LLM_KEY", "secrets.llmApiKey=k"})
	if !strings.Contains(renamed, "name: MY_LLM_KEY") {
		t.Errorf("custom apiKeySecret must rename the env var\n%s", snippet(renamed, "llm-api-key"))
	}
	cfg2 := loadEmbedded(t, []string{"analyst.api.apiKeySecret=MY_LLM_KEY"})
	if cfg2.Analyst.API.APIKeySecret != "MY_LLM_KEY" {
		t.Errorf("analyst.api.api_key_secret = %q, want MY_LLM_KEY (env name + config must agree)", cfg2.Analyst.API.APIKeySecret)
	}
}

// TestAnalystPerRoleBridge (Story 3.8) pins the per-role routing +
// ablation toggle bridges: each Helm value reaches the rendered config
// and round-trips through config.Load, an explicit l2_enabled: false is
// not swallowed, and the unset defaults stay byte-stable.
func TestAnalystPerRoleBridge(t *testing.T) {
	overridden := helmTemplate(t, []string{
		"analyst.provider=api",
		"analyst.l1_provider=openai",
		"analyst.l1_model=gpt-4o-mini",
		"analyst.l2_provider=claude",
		"analyst.l2_model=claude-haiku-4-5",
		"analyst.senior_provider=claude",
		"analyst.senior_model=claude-opus-4-8",
		"analyst.senior_enabled=false",
	})
	embedded := extractEmbeddedConfigYAML(t, overridden)
	tmp := filepath.Join(t.TempDir(), "olaitan.yaml")
	if err := os.WriteFile(tmp, []byte(embedded), 0o600); err != nil {
		t.Fatalf("write tmp config: %v", err)
	}
	cfg, err := configLoad(t, tmp)
	if err != nil {
		t.Fatalf("bridged per-role config rejected by config.Load: %v", err)
	}
	if cfg.Analyst.L1Provider != "openai" || cfg.Analyst.L1Model != "gpt-4o-mini" {
		t.Errorf("l1 = %q/%q, want openai/gpt-4o-mini", cfg.Analyst.L1Provider, cfg.Analyst.L1Model)
	}
	if cfg.Analyst.L2Provider != "claude" || cfg.Analyst.SeniorModel != "claude-opus-4-8" {
		t.Errorf("l2.provider/senior.model = %q/%q", cfg.Analyst.L2Provider, cfg.Analyst.SeniorModel)
	}
	if cfg.Analyst.SeniorEnabled == nil || *cfg.Analyst.SeniorEnabled {
		t.Errorf("senior_enabled: false must round-trip to a non-nil false, got %v", cfg.Analyst.SeniorEnabled)
	}
	// L1+L2 ablation: senior off, L2 on.
	if !cfg.Analyst.L2EnabledOrDefault() || cfg.Analyst.SeniorEnabledOrDefault() {
		t.Error("expected L1+L2 ablation (L2 on, Senior off)")
	}

	// L1-only ablation toggle.
	l1Only := helmTemplate(t, []string{"analyst.provider=api", "analyst.l2_enabled=false"})
	embL1 := extractEmbeddedConfigYAML(t, l1Only)
	tmp2 := filepath.Join(t.TempDir(), "olaitan.yaml")
	if err := os.WriteFile(tmp2, []byte(embL1), 0o600); err != nil {
		t.Fatalf("write tmp config: %v", err)
	}
	cfg2, err := configLoad(t, tmp2)
	if err != nil {
		t.Fatalf("l2_enabled=false config rejected: %v", err)
	}
	if cfg2.Analyst.L2EnabledOrDefault() || cfg2.Analyst.SeniorEnabledOrDefault() {
		t.Error("l2_enabled=false must be L1-only (both L2 and Senior off)")
	}

	// Unset per-role keys keep the file-side defaults and load cleanly.
	embDefaults := extractEmbeddedConfigYAML(t, helmTemplate(t, nil))
	tmp3 := filepath.Join(t.TempDir(), "olaitan.yaml")
	if err := os.WriteFile(tmp3, []byte(embDefaults), 0o600); err != nil {
		t.Fatalf("write tmp config: %v", err)
	}
	cfgD, err := configLoad(t, tmp3)
	if err != nil {
		t.Fatalf("default config rejected: %v", err)
	}
	if cfgD.Analyst.L1Provider != "" || !cfgD.Analyst.L2EnabledOrDefault() || !cfgD.Analyst.SeniorEnabledOrDefault() {
		t.Errorf("defaults drifted: l1_provider=%q l2=%v senior=%v", cfgD.Analyst.L1Provider, cfgD.Analyst.L2EnabledOrDefault(), cfgD.Analyst.SeniorEnabledOrDefault())
	}
}

// TestAnalystCheckpointRetentionBridge (Story 3.9) pins that the
// analyst.checkpoint_retention Helm value bridges into the rendered config
// and round-trips through config.Load; the unset default stays 6h.
func TestAnalystCheckpointRetentionBridge(t *testing.T) {
	embedded := extractEmbeddedConfigYAML(t, helmTemplate(t, []string{"analyst.checkpoint_retention=2h"}))
	tmp := filepath.Join(t.TempDir(), "olaitan.yaml")
	if err := os.WriteFile(tmp, []byte(embedded), 0o600); err != nil {
		t.Fatalf("write tmp config: %v", err)
	}
	cfg, err := configLoad(t, tmp)
	if err != nil {
		t.Fatalf("bridged checkpoint_retention rejected: %v", err)
	}
	if cfg.Analyst.CheckpointRetention.Duration() != 2*time.Hour {
		t.Errorf("checkpoint_retention = %s, want 2h", cfg.Analyst.CheckpointRetention.Duration())
	}
	embD := extractEmbeddedConfigYAML(t, helmTemplate(t, nil))
	tmpD := filepath.Join(t.TempDir(), "olaitan.yaml")
	if err := os.WriteFile(tmpD, []byte(embD), 0o600); err != nil {
		t.Fatalf("write tmp config: %v", err)
	}
	cfgD, err := configLoad(t, tmpD)
	if err != nil {
		t.Fatalf("default config rejected: %v", err)
	}
	if cfgD.Analyst.CheckpointRetention.Duration() != 6*time.Hour {
		t.Errorf("default checkpoint_retention = %s, want 6h", cfgD.Analyst.CheckpointRetention.Duration())
	}
}

// TestAnalystCircuitBreakerBridge (Story 3.12) pins that
// analyst.circuit_breaker.{rate_per_min,cooling_seconds} bridge into the
// rendered config as integers and round-trip through config.Load; the unset
// defaults stay 10 / 60.
func TestAnalystCircuitBreakerBridge(t *testing.T) {
	embedded := extractEmbeddedConfigYAML(t, helmTemplate(t, []string{
		"analyst.circuit_breaker.rate_per_min=25",
		"analyst.circuit_breaker.cooling_seconds=90",
	}))
	tmp := filepath.Join(t.TempDir(), "olaitan.yaml")
	if err := os.WriteFile(tmp, []byte(embedded), 0o600); err != nil {
		t.Fatalf("write tmp config: %v", err)
	}
	cfg, err := configLoad(t, tmp)
	if err != nil {
		t.Fatalf("bridged circuit_breaker rejected: %v", err)
	}
	if cfg.Analyst.CircuitBreaker.RatePerMinOrDefault() != 25 || cfg.Analyst.CircuitBreaker.CoolingSecondsOrDefault() != 90 {
		t.Errorf("bridged breaker = %d/%d, want 25/90", cfg.Analyst.CircuitBreaker.RatePerMinOrDefault(), cfg.Analyst.CircuitBreaker.CoolingSecondsOrDefault())
	}
	embD := extractEmbeddedConfigYAML(t, helmTemplate(t, nil))
	tmpD := filepath.Join(t.TempDir(), "olaitan.yaml")
	if err := os.WriteFile(tmpD, []byte(embD), 0o600); err != nil {
		t.Fatalf("write tmp config: %v", err)
	}
	cfgD, err := configLoad(t, tmpD)
	if err != nil {
		t.Fatalf("default config rejected: %v", err)
	}
	if cfgD.Analyst.CircuitBreaker.RatePerMinOrDefault() != 10 || cfgD.Analyst.CircuitBreaker.CoolingSecondsOrDefault() != 60 {
		t.Errorf("default breaker = %d/%d, want 10/60", cfgD.Analyst.CircuitBreaker.RatePerMinOrDefault(), cfgD.Analyst.CircuitBreaker.CoolingSecondsOrDefault())
	}
}

// TestValuesAirgappedOverlay renders with the FR48 reference overlay
// and asserts the complete air-gapped posture: ollama surface present,
// provider local with the overlay's endpoint/model bridged, and no
// extra egress CIDRs.
func TestValuesAirgappedOverlay(t *testing.T) {
	args := []string{
		"template", "olaitan", chartDir(t),
		"--set", "secrets.redisPassword=test-password",
		"-f", filepath.Join(chartDir(t), "values-airgapped.yaml"),
	}
	cmd := exec.Command("helm", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("helm template with values-airgapped.yaml failed: %v\nstderr:\n%s", err, stderr.String())
	}
	rendered := stdout.String()

	ms := parseManifests(t, rendered)
	found := map[string]bool{"Deployment": false, "Service": false, "NetworkPolicy": false}
	for _, m := range ms {
		if strings.HasSuffix(m.Metadata.Name, "-ollama") {
			if _, ok := found[m.Kind]; ok {
				found[m.Kind] = true
			}
		}
	}
	for kind, ok := range found {
		if !ok {
			t.Errorf("values-airgapped.yaml must render the in-cluster ollama %s", kind)
		}
	}

	// The overlay leaves the endpoint unset, so the bridge DERIVES the
	// rendered Service DNS for the actual release/namespace (round-1
	// review: the previous hardcoded release+namespace endpoint dialed
	// a nonexistent Service everywhere else). This render uses release
	// "olaitan" in namespace "default".
	embedded := extractEmbeddedConfigYAML(t, rendered)
	tmp := filepath.Join(t.TempDir(), "olaitan.yaml")
	if err := os.WriteFile(tmp, []byte(embedded), 0o600); err != nil {
		t.Fatalf("write tmp config: %v", err)
	}
	cfg, err := configLoad(t, tmp)
	if err != nil {
		t.Fatalf("air-gapped rendered config rejected by config.Load: %v", err)
	}
	if got := strings.ToLower(cfg.Analyst.Provider); got != "local" {
		t.Errorf("analyst.provider = %q, want local", cfg.Analyst.Provider)
	}
	if cfg.Analyst.Local.Endpoint != "http://olaitan-ollama.default.svc.cluster.local:11434" {
		t.Errorf("analyst.local.endpoint = %q, want the DERIVED rendered Service DNS", cfg.Analyst.Local.Endpoint)
	}
	if cfg.Analyst.Local.Model != "llama3.1:70b" {
		t.Errorf("analyst.local.model = %q, want the overlay's pinned model", cfg.Analyst.Local.Model)
	}
	if cfg.Analyst.ScoreCap != 25 {
		t.Errorf("analyst.score_cap = %d, want the Ollama-tier 25 (round-1 review: the file-side 35 silently won before the score_cap bridge)", cfg.Analyst.ScoreCap)
	}
}

// TestAnalystScoreCapBridge: round-1 review - the third bridge. A
// Helm-set analyst.score_cap lands in the rendered config; unset keeps
// the file-side 35; an EXPLICIT ZERO is honoured (round-2 review: a
// `with` gate would treat 0 as falsy and silently render 35 where the
// operator configured zero trust).
func TestAnalystScoreCapBridge(t *testing.T) {
	overridden := helmTemplate(t, []string{"analyst.score_cap=25"})
	embedded := extractEmbeddedConfigYAML(t, overridden)
	assertContains(t, embedded, "score_cap: 25",
		"analyst.score_cap bridge must rewrite the rendered config")

	zero := helmTemplate(t, []string{"analyst.score_cap=0"})
	embeddedZero := extractEmbeddedConfigYAML(t, zero)
	assertContains(t, embeddedZero, "score_cap: 0",
		"an explicit analyst.score_cap=0 must be honoured, not skipped as falsy")

	defaults := helmTemplate(t, nil)
	embeddedDefaults := extractEmbeddedConfigYAML(t, defaults)
	assertContains(t, embeddedDefaults, "score_cap: 35",
		"unset analyst.score_cap must keep the file-side default")
}

// TestAnalystLocalBridgeDollarEscape: round-1 review - a value carrying
// a $1-style sequence must land LITERALLY in the rendered config, not
// be expanded as a regex capture-group reference.
func TestAnalystLocalBridgeDollarEscape(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"analyst.provider=local",
		`analyst.local.model=weird$1model`,
	})
	embedded := extractEmbeddedConfigYAML(t, rendered)
	assertContains(t, embedded, `model: "weird$1model"`,
		"a $-bearing bridged value must survive literally (no capture-group expansion)")
}

// --- Story 4.10: forensic-mode VALUES FACADE tests -------------------
//
// The seven AC2 facade knobs (forensics.path,
// forensics.s3.{bucket,kms_key_alias,retention_days},
// forensics.settling_window_seconds, notifications.{enabled,webhook_url})
// overlay the existing response.* config blocks. These tests pin each knob's
// landing config path, the bucket/kms FAN-OUT to BOTH buckets, the report-only
// retention, the webhook-url-is-a-secret projection, the facade-wins-over-
// response.* precedence, the forensics.path=criu template-time reject, and the
// AC1 additive-off-by-default upgrade-safety property.

// helmTemplateExpectError renders with the given --set overrides and returns
// the combined stderr, failing the test if the render SUCCEEDS. The fail-fast
// facade validators (forensics.path) are exercised through this helper.
func helmTemplateExpectError(t *testing.T, sets []string) string {
	t.Helper()
	args := []string{"template", "olaitan", chartDir(t),
		"--set", "secrets.redisPassword=test-password",
	}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	cmd := exec.Command("helm", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("helm template %v succeeded; expected a fail-fast facade validator to fire", sets)
	}
	return stderr.String()
}

// TestForensicsFacade_S3BucketFansOutToBothBuckets pins BI-3: the facade
// forensics.s3.bucket sets BOTH the forensic-bundle bucket
// (response.forensics.s3_bucket) AND the durable-report bucket
// (response.report_archive.s3_bucket), the common single-bucket operator case.
func TestForensicsFacade_S3BucketFansOutToBothBuckets(t *testing.T) {
	cfg := loadEmbedded(t, []string{"forensics.s3.bucket=olaitan-forensics-shared"})
	if cfg.Response.Forensics.S3Bucket != "olaitan-forensics-shared" {
		t.Errorf("forensics.s3.bucket facade did not reach response.forensics.s3_bucket: got %q",
			cfg.Response.Forensics.S3Bucket)
	}
	if cfg.Response.ReportArchive.S3Bucket != "olaitan-forensics-shared" {
		t.Errorf("forensics.s3.bucket facade did not fan out to response.report_archive.s3_bucket: got %q",
			cfg.Response.ReportArchive.S3Bucket)
	}
}

// TestForensicsFacade_KMSKeyAliasFansOutToBothBuckets pins BI-3: the facade
// forensics.s3.kms_key_alias sets BOTH response.forensics.kms_key_alias AND
// response.report_archive.kms_key_alias.
func TestForensicsFacade_KMSKeyAliasFansOutToBothBuckets(t *testing.T) {
	cfg := loadEmbedded(t, []string{"forensics.s3.kms_key_alias=alias/olaitan-shared"})
	if cfg.Response.Forensics.KMSKeyAlias != "alias/olaitan-shared" {
		t.Errorf("forensics.s3.kms_key_alias facade did not reach response.forensics.kms_key_alias: got %q",
			cfg.Response.Forensics.KMSKeyAlias)
	}
	if cfg.Response.ReportArchive.KMSKeyAlias != "alias/olaitan-shared" {
		t.Errorf("forensics.s3.kms_key_alias facade did not fan out to response.report_archive.kms_key_alias: got %q",
			cfg.Response.ReportArchive.KMSKeyAlias)
	}
}

// TestForensicsFacade_RetentionDaysTargetsReportBucketOnly pins BI-3: object
// lock lives on the report bucket alone, so forensics.s3.retention_days maps
// ONLY to response.report_archive.retention_days. The forensic-bundle bucket
// has no retention knob; the settling.retention_days key must NOT be touched
// by this facade knob.
func TestForensicsFacade_RetentionDaysTargetsReportBucketOnly(t *testing.T) {
	rendered := helmTemplate(t, []string{"forensics.s3.retention_days=222"})
	embedded := extractEmbeddedConfigYAML(t, rendered)
	if !strings.Contains(embedded, "retention_days: 222") {
		t.Errorf("forensics.s3.retention_days facade did not reach the report bucket retention\n%s",
			snippet(embedded, "report_archive:"))
	}
	cfg := loadEmbedded(t, []string{"forensics.s3.retention_days=222"})
	if cfg.Response.ReportArchive.RetentionDays == nil || *cfg.Response.ReportArchive.RetentionDays != 222 {
		t.Errorf("response.report_archive.retention_days = %v, want 222",
			cfg.Response.ReportArchive.RetentionDays)
	}
	// The facade retention knob must NOT change the settling block's own
	// retention (the report-only-target invariant). Scope the check to the
	// settling: block region of the rendered config.
	settlingIdx := strings.Index(embedded, "\n  settling:\n")
	if settlingIdx < 0 {
		t.Fatalf("settling: block not found in rendered config")
	}
	settlingBlock := embedded[settlingIdx : settlingIdx+120]
	if strings.Contains(settlingBlock, "retention_days: 222") {
		t.Errorf("forensics.s3.retention_days leaked into the settling block (must target report bucket only)\n%s", settlingBlock)
	}
}

// TestReportArchive_RetentionDaysDoesNotClobberSettling is a regression test for
// the Story 4.6 bridge defect fixed in Story 4.10: the response.report_archive
// .retention_days bridge used a non-parent-scoped anchor that matched the FIRST
// `retention_days:` in the config, which is response.settling.retention_days (it
// appears earlier). Setting only the report-archive retention silently shortened
// the settling / INCIDENTS-stream retention from 365 to the report value. The
// fixed bridge is parent-scoped under report_archive:, so settling.retention_days
// (365) must be untouched while report_archive.retention_days takes the override.
func TestReportArchive_RetentionDaysDoesNotClobberSettling(t *testing.T) {
	// The default values set response.reportArchive.retentionDays (90), so the
	// report-archive retention bridge ALWAYS fires on a default render. Before the
	// fix its non-parent-scoped anchor matched settling.retention_days (which
	// appears first) and rewrote it from 365 to 90. The default render must keep
	// settling at 365 while the report bucket holds its own 90.
	cfg := loadEmbedded(t, []string{})
	if cfg.Response.Settling.RetentionDays == nil || *cfg.Response.Settling.RetentionDays != 365 {
		t.Errorf("response.settling.retention_days = %v, want 365 (must NOT be clobbered by the report-archive bridge)",
			cfg.Response.Settling.RetentionDays)
	}
	if cfg.Response.ReportArchive.RetentionDays == nil || *cfg.Response.ReportArchive.RetentionDays != 90 {
		t.Errorf("response.report_archive.retention_days = %v, want 90", cfg.Response.ReportArchive.RetentionDays)
	}
}

// TestForensicsFacade_SettlingWindowSeconds pins the
// forensics.settling_window_seconds -> response.settling.window_seconds bridge.
func TestForensicsFacade_SettlingWindowSeconds(t *testing.T) {
	cfg := loadEmbedded(t, []string{"forensics.settling_window_seconds=125"})
	if cfg.Response.Settling.WindowSeconds == nil || *cfg.Response.Settling.WindowSeconds != 125 {
		t.Errorf("response.settling.window_seconds = %v, want 125",
			cfg.Response.Settling.WindowSeconds)
	}
}

// TestNotificationsFacade_EnabledBridges pins the notifications.enabled ->
// response.notifications.enabled bridge (the one facade-level gate).
func TestNotificationsFacade_EnabledBridges(t *testing.T) {
	cfg := loadEmbedded(t, []string{"notifications.enabled=true"})
	if !cfg.Response.Notifications.EnabledOrDefault() {
		t.Errorf("notifications.enabled facade did not flip response.notifications.enabled")
	}
}

// TestNotificationsFacade_WebhookUrlIsSecretNeverConfigMap pins BI-3: the
// facade notifications.webhook_url overlays the secrets.notificationsWebhookUrl
// SECRET (projected as NOTIFICATIONS_WEBHOOK_URL via secretKeyRef), and is
// NEVER written into the ConfigMap (a Slack/PagerDuty URL embeds a token).
func TestNotificationsFacade_WebhookUrlIsSecretNeverConfigMap(t *testing.T) {
	const url = "https://hooks.example.invalid/TOKEN-DEADBEEF"
	rendered := helmTemplate(t, []string{"notifications.webhook_url=" + url})
	// It must land in the Secret stringData.
	if !strings.Contains(rendered, "notifications-webhook-url: \""+url+"\"") {
		t.Errorf("notifications.webhook_url facade did not reach the Secret stringData\n%s",
			snippet(rendered, "notifications-webhook-url"))
	}
	// It must NOT appear in the embedded olaitan.yaml ConfigMap (secret discipline).
	embedded := extractEmbeddedConfigYAML(t, rendered)
	if strings.Contains(embedded, "DEADBEEF") {
		t.Errorf("notifications.webhook_url leaked into the ConfigMap (must be a secret-only projection)\n%s",
			snippet(embedded, "notifications:"))
	}
}

// TestNotificationsFacade_WebhookUrlOverridesSecret pins the facade-wins
// precedence on the webhook secret: a non-empty facade webhook_url overrides
// secrets.notificationsWebhookUrl; an empty facade value falls back to it.
func TestNotificationsFacade_WebhookUrlOverridesSecret(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"notifications.webhook_url=https://facade.invalid/WIN",
		"secrets.notificationsWebhookUrl=https://legacy.invalid/LOSE",
	})
	if !strings.Contains(rendered, "notifications-webhook-url: \"https://facade.invalid/WIN\"") {
		t.Errorf("facade webhook_url must win over secrets.notificationsWebhookUrl\n%s",
			snippet(rendered, "notifications-webhook-url"))
	}
	fallback := helmTemplate(t, []string{"secrets.notificationsWebhookUrl=https://legacy.invalid/KEEP"})
	if !strings.Contains(fallback, "notifications-webhook-url: \"https://legacy.invalid/KEEP\"") {
		t.Errorf("an empty facade webhook_url must fall back to secrets.notificationsWebhookUrl\n%s",
			snippet(fallback, "notifications-webhook-url"))
	}
}

// TestForensicsFacade_WinsOverResponseBlock pins BI-1: when BOTH a facade key
// and its response.* counterpart are set, the facade WINS (it overlays last).
func TestForensicsFacade_WinsOverResponseBlock(t *testing.T) {
	cfg := loadEmbedded(t, []string{
		"response.forensics.s3Bucket=advanced-escape-hatch",
		"forensics.s3.bucket=facade-surface",
		"response.settling.windowSeconds=15",
		"forensics.settling_window_seconds=88",
	})
	if cfg.Response.Forensics.S3Bucket != "facade-surface" {
		t.Errorf("facade forensics.s3.bucket must win over response.forensics.s3Bucket: got %q",
			cfg.Response.Forensics.S3Bucket)
	}
	if cfg.Response.Settling.WindowSeconds == nil || *cfg.Response.Settling.WindowSeconds != 88 {
		t.Errorf("facade forensics.settling_window_seconds must win over response.settling.windowSeconds: got %v",
			cfg.Response.Settling.WindowSeconds)
	}
}

// TestForensicsFacade_PathFallbackRendersClean pins BI-2: forensics.path
// fallback (and the empty default) render with no error and bridge to NO
// config field (fallback is the only runtime path).
func TestForensicsFacade_PathFallbackRendersClean(t *testing.T) {
	// Explicit fallback.
	_ = helmTemplate(t, []string{"forensics.path=fallback"})
	// Default (unset) path renders clean too.
	_ = helmTemplate(t, nil)
}

// TestForensicsFacade_PathCriuRejectedAtTemplateTime pins BI-2 / PO
// Ratification 3: forensics.path=criu is REJECTED at template time with the
// helpful "not implemented; use fallback" message (fail-fast honesty, not a
// silent no-op). A value other than fallback/criu fails with the valid-values
// message.
func TestForensicsFacade_PathCriuRejectedAtTemplateTime(t *testing.T) {
	stderr := helmTemplateExpectError(t, []string{"forensics.path=criu"})
	if !strings.Contains(stderr, "CRIU forensic path is not implemented") {
		t.Errorf("forensics.path=criu must fail with the CRIU-not-implemented message; got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "Use forensics.path=fallback") {
		t.Errorf("the criu reject message must point the operator at forensics.path=fallback; got:\n%s", stderr)
	}
	badStderr := helmTemplateExpectError(t, []string{"forensics.path=zfs"})
	if !strings.Contains(badStderr, "forensics.path must be one of") {
		t.Errorf("an unknown forensics.path must fail with the valid-values message; got:\n%s", badStderr)
	}
}

// TestForensicsFacade_DefaultsAreAdditiveOffByDefault pins BI-7 (AC1
// upgrade-safety): under the default render the Epic-4 controller gates all
// default OFF, so a helm upgrade from an Epic-3 RSLT-full deployment installs
// the Epic-4 surface without disrupting in-flight investigations (the facade
// sets PARAMETERS only; it enables NO controller). Also asserts the default
// facade params overlay the SAME file-side values (idempotent render), which
// is why the goldens are unchanged for the rendered config.
func TestForensicsFacade_DefaultsAreAdditiveOffByDefault(t *testing.T) {
	cfg := loadEmbedded(t, nil)
	if cfg.Response.Forensics.EnabledOrDefault() {
		t.Error("response.forensics must default OFF (AC1 additive upgrade-safety)")
	}
	if cfg.Response.Settling.EnabledOrDefault() {
		t.Error("response.settling must default OFF (AC1)")
	}
	if cfg.Response.DFIR.Enabled != nil && *cfg.Response.DFIR.Enabled {
		t.Error("response.dfir must default OFF (AC1)")
	}
	if cfg.Response.ReportArchive.EnabledOrDefault() {
		t.Error("response.report_archive must default OFF (AC1)")
	}
	if cfg.Response.Notifications.EnabledOrDefault() {
		t.Error("response.notifications must default OFF (AC1)")
	}
}

// TestForensicsFacade_RSLTFullArmKeepsEpic4GatesOff pins BI-7: the Epic-3-arm
// render (evaluation.config=RSLT-full, no Epic-4 gates flipped) leaves every
// Epic-4 controller OFF, so the Epic-4 chart is a strict additive superset of
// the Epic-3 render. The settling window timers re-arm from the Redis-backed
// FSM on restart, so a rolling pod replacement during the upgrade does not drop
// an in-flight settling window (documented in the runbook upgrade-safety note).
func TestForensicsFacade_RSLTFullArmKeepsEpic4GatesOff(t *testing.T) {
	cfg := loadEmbedded(t, []string{"evaluation.config=RSLT-full"})
	if cfg.Response.Forensics.EnabledOrDefault() ||
		cfg.Response.Settling.EnabledOrDefault() ||
		cfg.Response.ReportArchive.EnabledOrDefault() ||
		cfg.Response.Notifications.EnabledOrDefault() {
		t.Error("the RSLT-full arm must NOT auto-enable any Epic-4 controller gate (AC1 additive upgrade-safety)")
	}
}
