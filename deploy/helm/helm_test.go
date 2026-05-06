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
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

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
		"ServiceAccount":        2,
		"Role":                  1,
		"RoleBinding":           1,
		"ClusterRole":           1,
		"ClusterRoleBinding":    1,
		"Secret":                1,
		"ConfigMap":             2,
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

// TestAuditWebhookGate asserts the audit-webhook Service and
// ValidatingWebhookConfiguration are absent by default (Story 1.1 ships
// them as scaffold) and present when the gate is flipped (Story 1.7
// will flip the default). Both kinds must come and go together.
func TestAuditWebhookGate(t *testing.T) {
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

	enabledRender := helmTemplate(t, []string{
		"falco.enabled=false", "nats.enabled=false", "redis.enabled=false",
		"auditWebhook.enabled=true",
		// caBundle is required when the webhook is enabled (see the
		// fail-fast guard in templates/validatingwebhookconfiguration.yaml
		// covered separately by TestAuditWebhookCABundleGuard). Use a
		// dummy base64 string so this test can exercise the rendering
		// path without standing up a real CA.
		"auditWebhook.caBundle=ZmFrZS1jYS1idW5kbGU=",
	})
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
}

// TestKubeconform runs `kubeconform` against the rendered chart for
// K8s 1.29. Skips when kubeconform is not on PATH (local dev case) —
// CI installs it via `go install`.
func TestKubeconform(t *testing.T) {
	if _, err := exec.LookPath("kubeconform"); err != nil {
		t.Skip("kubeconform not on PATH; install via `go install github.com/yannh/kubeconform/cmd/kubeconform@v0.6.7`")
	}

	rendered := helmTemplate(t, nil)

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
		t.Fatalf("kubeconform failed: %v\nstdout:\n%s\nstderr:\n%s",
			err, stdout.String(), stderr.String())
	}
}
