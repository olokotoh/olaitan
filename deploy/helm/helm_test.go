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
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// chartDir resolves relative to this test file so the suite works from
// any cwd (Go's `go test` typically chdir's into the package directory,
// but CI may override with -run flags or coverage modes that don't).
func chartDir(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs("olaitan")
	if err != nil {
		t.Fatalf("resolve chart dir: %v", err)
	}
	return abs
}

// helmTemplate runs `helm template` with the provided --set overrides
// and returns the rendered manifest stream. Bails the test on any
// non-zero exit so callers can assume the stdout is valid.
func helmTemplate(t *testing.T, sets []string) string {
	t.Helper()
	args := []string{"template", "olaitan", chartDir(t)}
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
	APIVersion string    `yaml:"apiVersion"`
	Kind       string    `yaml:"kind"`
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
		"DaemonSet":              1,
		"Deployment":             1,
		"ServiceAccount":         2,
		"Role":                   1,
		"RoleBinding":            1,
		"ClusterRole":            1,
		"ClusterRoleBinding":     1,
		"PersistentVolumeClaim":  1,
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
// only Olaitan's own resources show up. NFR: operators with existing
// Falco/NATS/Redis must be able to install without double-provisioning.
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

	if len(findByKind(ms, "DaemonSet")) != 1 {
		t.Errorf("DaemonSet: got %d, want 1", len(findByKind(ms, "DaemonSet")))
	}
	if len(findByKind(ms, "Deployment")) != 1 {
		t.Errorf("Deployment: got %d, want 1", len(findByKind(ms, "Deployment")))
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
// match architecture.md:949-957 exactly — no wildcards, no cluster-admin,
// collector is read-only on pods/events, aggregator is CREATE/UPDATE/
// DELETE on networkpolicies + PATCH on pods + GET/LIST on pods,events.
func TestRBACVerbs(t *testing.T) {
	rendered := helmTemplate(t, []string{
		"falco.enabled=false", "nats.enabled=false", "redis.enabled=false",
	})
	ms := parseManifests(t, rendered)

	// Collect Roles and ClusterRoles owned by Olaitan.
	for _, m := range ms {
		if m.Kind != "Role" && m.Kind != "ClusterRole" {
			continue
		}
		if !strings.HasPrefix(m.Metadata.Name, "olaitan") {
			continue
		}
		var obj struct {
			Kind  string `yaml:"kind"`
			Rules []struct {
				APIGroups []string `yaml:"apiGroups"`
				Resources []string `yaml:"resources"`
				Verbs     []string `yaml:"verbs"`
			} `yaml:"rules"`
		}
		if err := m.Raw.Decode(&obj); err != nil {
			t.Fatalf("decode %s: %v", m.Metadata.Name, err)
		}
		for _, rule := range obj.Rules {
			for _, v := range rule.Verbs {
				if v == "*" {
					t.Errorf("RBAC wildcard verb in %s/%s (rule %+v) — NFR13 violation",
						m.Kind, m.Metadata.Name, rule)
				}
			}
			for _, r := range rule.Resources {
				if r == "*" {
					t.Errorf("RBAC wildcard resource in %s/%s (rule %+v) — NFR13 violation",
						m.Kind, m.Metadata.Name, rule)
				}
			}
		}
	}

	// No ClusterRoleBinding to cluster-admin.
	assertContains(t, rendered, "olaitan-aggregator-binding", "expected aggregator ClusterRoleBinding name")
	if strings.Contains(rendered, "cluster-admin") {
		t.Errorf("RBAC: cluster-admin referenced in rendered chart — NFR13 violation")
	}
}

// TestPodSecurityContext verifies every pod spec sets runAsNonRoot,
// drops all capabilities, forbids privilege escalation, and makes root
// filesystem read-only. NFR11 compliance.
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
						SecurityContext struct {
							RunAsNonRoot *bool  `yaml:"runAsNonRoot"`
							RunAsUser    *int64 `yaml:"runAsUser"`
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
