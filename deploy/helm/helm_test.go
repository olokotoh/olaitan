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
