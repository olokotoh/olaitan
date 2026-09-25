//go:build helm

package helm_test

import (
	"strings"
	"testing"
)

// Story 11.2d (#195): the collector fills the pod for Falco alerts Falco left
// unattributed, from a node-scoped pod watch. The knobs reach the collector
// as env vars, with defaults.
func TestCollectorPodIdentityEnv(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		sets                      []string
		enabled, maxEntries, wait string
	}{
		{"defaults", nil, "true", "2048", "1s"},
		{"overridden", []string{"falcoIngest.podIdentity.maxEntries=64", "falcoIngest.podIdentity.missWait=250ms"}, "true", "64", "250ms"},
		{"disabled", []string{"falcoIngest.podIdentity.enabled=false"}, "false", "2048", "1s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := collectorEnv(t, helmTemplate(t, tc.sets))
			if env["FALCO_POD_IDENTITY_ENABLED"] != tc.enabled ||
				env["FALCO_POD_IDENTITY_MAX_ENTRIES"] != tc.maxEntries ||
				env["FALCO_POD_IDENTITY_MISS_WAIT"] != tc.wait {
				t.Errorf("FALCO_POD_IDENTITY_ENABLED=%q MAX_ENTRIES=%q MISS_WAIT=%q, want %s / %s / %s",
					env["FALCO_POD_IDENTITY_ENABLED"], env["FALCO_POD_IDENTITY_MAX_ENTRIES"], env["FALCO_POD_IDENTITY_MISS_WAIT"],
					tc.enabled, tc.maxEntries, tc.wait)
			}
		})
	}
}

// The watch needs cluster-wide get/list/watch on pods (RBAC cannot scope a
// grant to a field selector; the collector narrows each request to its own
// node with spec.nodeName). The grant is exactly that and nothing more, and
// it disappears when the feature is off.
func TestCollectorPodIdentityRBAC(t *testing.T) {
	const roleName = "olaitan-collector-pod-identity"

	t.Run("enabled", func(t *testing.T) {
		ms := parseManifests(t, helmTemplate(t, []string{"falco.enabled=false", "nats.enabled=false", "redis.enabled=false"}))
		var role, binding *manifest
		for i := range ms {
			switch {
			case ms[i].Kind == "ClusterRole" && ms[i].Metadata.Name == roleName:
				role = &ms[i]
			case ms[i].Kind == "ClusterRoleBinding" && ms[i].Metadata.Name == roleName:
				binding = &ms[i]
			}
		}
		if role == nil || binding == nil {
			t.Fatalf("ClusterRole and ClusterRoleBinding %s must render (role=%v binding=%v)", roleName, role != nil, binding != nil)
		}
		var obj struct {
			Rules []rbacRule `yaml:"rules"`
		}
		if err := role.Raw.Decode(&obj); err != nil {
			t.Fatal(err)
		}
		if len(obj.Rules) != 1 {
			t.Fatalf("rules = %+v, want exactly one", obj.Rules)
		}
		r := obj.Rules[0]
		if strings.Join(r.APIGroups, ",") != "" || strings.Join(r.Resources, ",") != "pods" ||
			strings.Join(r.Verbs, ",") != "get,list,watch" {
			t.Errorf("rule = %+v, want core pods get,list,watch only", r)
		}
		var b struct {
			RoleRef struct {
				Kind, Name string
			} `yaml:"roleRef"`
			Subjects []struct {
				Kind, Name, Namespace string
			} `yaml:"subjects"`
		}
		if err := binding.Raw.Decode(&b); err != nil {
			t.Fatal(err)
		}
		if b.RoleRef.Kind != "ClusterRole" || b.RoleRef.Name != roleName {
			t.Errorf("roleRef = %+v", b.RoleRef)
		}
		if len(b.Subjects) != 1 || b.Subjects[0].Kind != "ServiceAccount" || b.Subjects[0].Name != "olaitan-collector" {
			t.Errorf("subjects = %+v, want only the collector ServiceAccount", b.Subjects)
		}
	})

	t.Run("disabled", func(t *testing.T) {
		rendered := helmTemplate(t, []string{"falco.enabled=false", "nats.enabled=false", "redis.enabled=false", "falcoIngest.podIdentity.enabled=false"})
		if strings.Contains(rendered, roleName) {
			t.Errorf("%s rendered with falcoIngest.podIdentity.enabled=false; the collector must keep its namespace-only reads", roleName)
		}
	})
}
