//go:build helm

package helm_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Story 10.6: the full profile runs a real model in-cluster, with no API
// key, and DeepSeek or Claude are one overlay plus a Secret away. These
// tests pin the chart side of that; the live proof is the gated e2e test
// tests/e2e/real_llm_full_test.go.

// fullProfileModel is the model values-full.yaml pulls and routes every
// chain role to. Kept in one place so a model change is one edit here and
// one in the profile, and the two cannot silently disagree.
const fullProfileModel = "qwen2.5:3b-instruct"

// renderFullProfile renders values-full.yaml the way hack/install-full-kind.sh
// installs it, with a test-only stub in place of the three per-install
// key-material files (the chart refuses to render without them). Extra
// values files are layered after, as an operator would.
func renderFullProfile(t *testing.T, extra ...string) string {
	t.Helper()
	files := []string{
		filepath.Join(chartDir(t), "values-full.yaml"),
		filepath.Join(filepath.Dir(chartDir(t)), "testdata", "full-profile", "stub-key-material.yaml"),
	}
	files = append(files, extra...)
	return helmTemplateValuesMulti(t, files...)
}

// docsOfKind decodes every rendered document of kind into a generic map.
func docsOfKind(t *testing.T, rendered, kind string) []map[string]any {
	t.Helper()
	var out []map[string]any
	dec := yaml.NewDecoder(strings.NewReader(rendered))
	for {
		var raw map[string]any
		if err := dec.Decode(&raw); err != nil {
			break
		}
		if raw["kind"] == kind {
			out = append(out, raw)
		}
	}
	return out
}

func docNamed(t *testing.T, rendered, kind, name string) map[string]any {
	t.Helper()
	for _, d := range docsOfKind(t, rendered, kind) {
		if dig(d, "metadata", "name") == name {
			return d
		}
	}
	t.Fatalf("%s %q not rendered", kind, name)
	return nil
}

// dig walks nested maps by key; it returns nil for any missing step.
func dig(v any, keys ...string) any {
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

// podContainers returns the named containers of a pod template (containers
// or initContainers) keyed by container name.
func podContainers(workload map[string]any, field string) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, c := range asList(dig(workload, "spec", "template", "spec", field)) {
		cm, _ := c.(map[string]any)
		name, _ := cm["name"].(string)
		out[name] = cm
	}
	return out
}

func envValue(container map[string]any, name string) (string, bool) {
	for _, e := range asList(container["env"]) {
		em, _ := e.(map[string]any)
		if em["name"] == name {
			v, _ := em["value"].(string)
			return v, true
		}
	}
	return "", false
}

// pullJob returns the single model pull Job, failing if there is not
// exactly one.
func pullJob(t *testing.T, rendered string) map[string]any {
	t.Helper()
	var jobs []map[string]any
	for _, j := range docsOfKind(t, rendered, "Job") {
		if name, _ := dig(j, "metadata", "name").(string); strings.HasPrefix(name, "olaitan-ollama-pull-") {
			jobs = append(jobs, j)
		}
	}
	if len(jobs) != 1 {
		t.Fatalf("model pull Jobs rendered = %d, want exactly 1", len(jobs))
	}
	return jobs[0]
}

// TestFullProfileRunsAnInClusterModel is AC1 and AC2 on the chart side: the
// reference profile turns on the in-cluster Ollama, pulls the model it
// routes to, keeps it on a volume the chart creates, and routes every chain
// role to that model with no API key.
func TestFullProfileRunsAnInClusterModel(t *testing.T) {
	rendered := renderFullProfile(t)

	// The chain routes to the local provider and the model that is pulled.
	cfg := extractEmbeddedConfigYAML(t, rendered)
	path := filepath.Join(t.TempDir(), "olaitan.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := configLoad(t, path)
	if err != nil {
		t.Fatalf("rendered full-profile config does not load: %v", err)
	}
	if c.Analyst.Provider != "local" {
		t.Errorf("analyst.provider = %q, want local (the in-cluster model, no API key)", c.Analyst.Provider)
	}
	if c.Analyst.Local.Model != fullProfileModel {
		t.Errorf("analyst.local.model = %q, want %q", c.Analyst.Local.Model, fullProfileModel)
	}
	if want := "http://olaitan-ollama.default.svc.cluster.local:11434"; c.Analyst.Local.Endpoint != want {
		t.Errorf("analyst.local.endpoint = %q, want the chart-managed Service %q", c.Analyst.Local.Endpoint, want)
	}
	for role, p := range map[string]string{"l1": c.Analyst.L1Provider, "l2": c.Analyst.L2Provider, "senior": c.Analyst.SeniorProvider} {
		if p != "" && p != "ollama" {
			t.Errorf("analyst.%s_provider = %q, want empty (inherit local) or ollama", role, p)
		}
	}
	if !c.Analyst.L2EnabledOrDefault() || !c.Analyst.SeniorEnabledOrDefault() {
		t.Error("the full profile must run the whole L1 -> L2 -> Senior chain")
	}

	// The serving Deployment is pinned by digest and waits for the model.
	dep := docNamed(t, rendered, "Deployment", "olaitan-ollama")
	serving := podContainers(dep, "containers")["ollama"]
	if serving == nil {
		t.Fatal("olaitan-ollama has no ollama container")
	}
	image, _ := serving["image"].(string)
	if !strings.Contains(image, "@sha256:") {
		t.Errorf("ollama image %q is not pinned by digest", image)
	}
	wait := podContainers(dep, "initContainers")["wait-for-models"]
	if wait == nil {
		t.Fatal("olaitan-ollama has no wait-for-models init container; helm --wait would return before the model exists")
	}
	if img, _ := wait["image"].(string); img != image {
		t.Errorf("wait-for-models image %q differs from the serving image %q", img, image)
	}
	if v, ok := envValue(wait, "OLLAMA_NOPRUNE"); !ok || v == "" {
		t.Error("wait-for-models must set OLLAMA_NOPRUNE: its server shares the volume with a pull that may still be writing, and a pruning start deletes half-pulled blobs")
	}
	if v, _ := envValue(wait, "OLAITAN_OLLAMA_MODELS"); v != fullProfileModel {
		t.Errorf("wait-for-models waits for %q, want %q", v, fullProfileModel)
	}

	// The model volume is created by the chart and mounted by the server.
	pvc := docNamed(t, rendered, "PersistentVolumeClaim", "olaitan-ollama-models")
	if modes := asList(dig(pvc, "spec", "accessModes")); len(modes) != 1 || modes[0] != "ReadWriteOnce" {
		t.Errorf("model PVC accessModes = %v, want [ReadWriteOnce]", modes)
	}
	claimed := false
	for _, v := range asList(dig(dep, "spec", "template", "spec", "volumes")) {
		if dig(v, "persistentVolumeClaim", "claimName") == "olaitan-ollama-models" {
			claimed = true
		}
	}
	if !claimed {
		t.Error("olaitan-ollama does not mount the chart-created model claim")
	}

	// The pull Job pulls exactly that model into that claim.
	job := pullJob(t, rendered)
	pull := podContainers(job, "containers")["pull"]
	if pull == nil {
		t.Fatal("model pull Job has no pull container")
	}
	if img, _ := pull["image"].(string); img != image {
		t.Errorf("pull image %q differs from the serving image %q", img, image)
	}
	if v, _ := envValue(pull, "OLAITAN_OLLAMA_MODELS"); v != fullProfileModel {
		t.Errorf("pull Job pulls %q, want %q", v, fullProfileModel)
	}
	jobClaimed := false
	for _, v := range asList(dig(job, "spec", "template", "spec", "volumes")) {
		if dig(v, "persistentVolumeClaim", "claimName") == "olaitan-ollama-models" {
			jobClaimed = true
		}
	}
	if !jobClaimed {
		t.Error("the pull Job does not write into the model claim the server reads")
	}
	if dig(job, "spec", "template", "spec", "automountServiceAccountToken") != false {
		t.Error("the pull Job talks to no cluster API; it must not mount a ServiceAccount token")
	}

	// CPU inference is slow; the per-role budget is raised for it.
	agg := docNamed(t, rendered, "Deployment", "olaitan-aggregator")
	aggC := podContainers(agg, "containers")
	var aggregator map[string]any
	for _, c := range aggC {
		aggregator = c
	}
	if v, ok := envValue(aggregator, "OLT_LLM_ROLE_TIMEOUT_MULTIPLIER"); !ok || v == "" {
		t.Error("the full profile runs a CPU model; OLT_LLM_ROLE_TIMEOUT_MULTIPLIER must raise the Claude-calibrated per-role timeouts")
	}
}

// TestFullProfileDoesNotReferenceFakeLLM is AC4, on the file and on the
// render: the fixture stays a CI and unit fixture only.
func TestFullProfileDoesNotReferenceFakeLLM(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(chartDir(t), "values-full.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"fake-llm", "fakellm", "model: fake"} {
		if strings.Contains(string(raw), needle) {
			t.Errorf("values-full.yaml references %q", needle)
		}
	}
	if strings.Contains(renderFullProfile(t), "fake-llm") {
		t.Error("the rendered full profile references fake-llm")
	}
}

// TestModelPullKeepsTheServerAirGapped: only the short-lived pull pod may
// reach the internet (DNS + TCP 443 to fetch the model). The serving pod
// keeps the declared-empty egress Story 3.4 made the air-gap statement, and
// the release policy excludes the pull pod the same way it excludes the
// server, so the union cannot widen either.
func TestModelPullKeepsTheServerAirGapped(t *testing.T) {
	nps := decodeNetpols(t, renderFullProfile(t))

	server, ok := nps["olaitan-ollama"]
	if !ok {
		t.Fatal("olaitan-ollama NetworkPolicy not rendered")
	}
	if server.Spec.Egress == nil || len(*server.Spec.Egress) != 0 {
		t.Errorf("serving Ollama egress = %v, want declared and EMPTY", server.Spec.Egress)
	}

	pull, ok := nps["olaitan-ollama-pull"]
	if !ok {
		t.Fatal("olaitan-ollama-pull NetworkPolicy not rendered")
	}
	if got := pull.Spec.PodSelector.MatchLabels["app.kubernetes.io/component"]; got != "ollama-pull" {
		t.Errorf("pull policy selects component %q, want ollama-pull", got)
	}
	if len(pull.Spec.Ingress) != 0 {
		t.Errorf("pull policy ingress = %+v, want none (nothing dials the pull pod)", pull.Spec.Ingress)
	}
	if pull.Spec.Egress == nil {
		t.Fatal("pull policy egress undeclared")
	}
	ports := map[string]bool{}
	for _, rule := range *pull.Spec.Egress {
		for _, p := range asList(rule["ports"]) {
			pm, _ := p.(map[string]any)
			ports[strings.ToUpper(fmt.Sprint(pm["protocol"]))+"/"+fmt.Sprint(pm["port"])] = true
		}
		if len(asList(rule["ports"])) == 0 {
			t.Errorf("pull policy egress rule %v allows every port", rule)
		}
	}
	for _, want := range []string{"UDP/53", "TCP/53", "TCP/443"} {
		if !ports[want] {
			t.Errorf("pull policy egress lacks %s (have %v)", want, ports)
		}
	}
	for p := range ports {
		if p != "UDP/53" && p != "TCP/53" && p != "TCP/443" {
			t.Errorf("pull policy egress allows %s; only DNS and HTTPS are needed to pull a model", p)
		}
	}

	release := nps["olaitan"]
	excluded := map[string]bool{}
	for _, expr := range release.Spec.PodSelector.MatchExpressions {
		if expr.Key == "app.kubernetes.io/component" && expr.Operator == "NotIn" {
			for _, v := range expr.Values {
				excluded[v] = true
			}
		}
	}
	if !excluded["ollama"] || !excluded["ollama-pull"] {
		t.Errorf("release NetworkPolicy excludes %v, want both ollama and ollama-pull", excluded)
	}
}

// TestModelPullIsOptIn: without ollama.pull.models the chart renders no
// Job, no pull policy and no wait container, so the default render and the
// air-gapped overlay (model provisioned by the operator) are unchanged.
func TestModelPullIsOptIn(t *testing.T) {
	for name, rendered := range map[string]string{
		"default":   helmTemplate(t, nil),
		"airgapped": helmTemplateValues(t, filepath.Join(chartDir(t), "values-airgapped.yaml")),
	} {
		for _, j := range docsOfKind(t, rendered, "Job") {
			if n, _ := dig(j, "metadata", "name").(string); strings.Contains(n, "ollama-pull") {
				t.Errorf("%s render has a model pull Job %s", name, n)
			}
		}
		if _, ok := decodeNetpols(t, rendered)["olaitan-ollama-pull"]; ok {
			t.Errorf("%s render has the pull NetworkPolicy", name)
		}
		if strings.Contains(rendered, "wait-for-models") {
			t.Errorf("%s render has the wait-for-models init container", name)
		}
	}
}

// TestModelPullRequiresAVolume: a pull with nowhere to keep the model would
// download into the pull pod's own filesystem and vanish with it, leaving
// the server waiting forever. Fail the render instead.
func TestModelPullRequiresAVolume(t *testing.T) {
	out := helmTemplateExpectError(t, []string{
		"ollama.enabled=true",
		"ollama.pull.models={" + fullProfileModel + "}",
		"ollama.persistence.enabled=false",
	})
	if !strings.Contains(out, "ollama.pull.models needs ollama.persistence.enabled") {
		t.Errorf("render error = %q, want the pull/persistence message", out)
	}
}

// TestPullJobNameFollowsTheModelList: a Job's pod template is immutable, so
// a changed model list must be a new Job (new name) rather than an upgrade
// that fails on a field it may not change. Same list, same name, so a
// no-change upgrade leaves the finished Job alone.
func TestPullJobNameFollowsTheModelList(t *testing.T) {
	name := func(models string) string {
		r := helmTemplate(t, []string{
			"ollama.enabled=true",
			"ollama.persistence.enabled=true",
			"ollama.persistence.create=true",
			"ollama.pull.models={" + models + "}",
		})
		n, _ := dig(pullJob(t, r), "metadata", "name").(string)
		return n
	}
	a, a2, b := name(fullProfileModel), name(fullProfileModel), name("qwen2.5:7b-instruct")
	if a != a2 {
		t.Errorf("same model list gave two Job names: %s, %s", a, a2)
	}
	if a == b {
		t.Errorf("different model lists gave the same Job name %s", a)
	}
	if len(a) > 63 {
		t.Errorf("Job name %q is longer than 63 characters", a)
	}
}

// TestModelVolumeCreateAndExistingClaim: the chart creates the claim only
// when asked and never when the operator names their own.
func TestModelVolumeCreateAndExistingClaim(t *testing.T) {
	created := helmTemplate(t, []string{
		"ollama.enabled=true", "ollama.persistence.enabled=true", "ollama.persistence.create=true",
		"ollama.persistence.size=20Gi",
	})
	pvc := docNamed(t, created, "PersistentVolumeClaim", "olaitan-ollama-models")
	if got := dig(pvc, "spec", "resources", "requests", "storage"); got != "20Gi" {
		t.Errorf("model PVC size = %v, want 20Gi", got)
	}

	existing := helmTemplate(t, []string{
		"ollama.enabled=true", "ollama.persistence.enabled=true", "ollama.persistence.create=true",
		"ollama.persistence.existingClaim=my-models",
	})
	for _, p := range docsOfKind(t, existing, "PersistentVolumeClaim") {
		if dig(p, "metadata", "name") == "olaitan-ollama-models" {
			t.Error("chart created a model claim although existingClaim names the operator's own")
		}
	}
	dep := docNamed(t, existing, "Deployment", "olaitan-ollama")
	found := false
	for _, v := range asList(dig(dep, "spec", "template", "spec", "volumes")) {
		if dig(v, "persistentVolumeClaim", "claimName") == "my-models" {
			found = true
		}
	}
	if !found {
		t.Error("existingClaim is not the mounted claim")
	}
}

// TestHostedModelOverlays: DeepSeek and Claude are one overlay plus the
// chart Secret away from the full profile, and the in-cluster model stays
// on as the FR28 fallback when they are layered on it.
func TestHostedModelOverlays(t *testing.T) {
	cases := []struct {
		file, family, endpoint string
		models                 bool
	}{
		{"values-llm-deepseek.yaml", "openai", "https://api.deepseek.com/v1", true},
		{"values-llm-claude.yaml", "claude", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			rendered := renderFullProfile(t, filepath.Join(chartDir(t), tc.file))
			cfg := extractEmbeddedConfigYAML(t, rendered)
			path := filepath.Join(t.TempDir(), "olaitan.yaml")
			if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
				t.Fatal(err)
			}
			c, err := configLoad(t, path)
			if err != nil {
				t.Fatalf("config does not load: %v", err)
			}
			if c.Analyst.Provider != "api" {
				t.Errorf("analyst.provider = %q, want api", c.Analyst.Provider)
			}
			for role, p := range map[string]string{"l1": c.Analyst.L1Provider, "l2": c.Analyst.L2Provider, "senior": c.Analyst.SeniorProvider} {
				if p != tc.family {
					t.Errorf("analyst.%s_provider = %q, want %q", role, p, tc.family)
				}
			}
			if c.Analyst.API.Endpoint != tc.endpoint {
				t.Errorf("analyst.api.endpoint = %q, want %q", c.Analyst.API.Endpoint, tc.endpoint)
			}
			if tc.models {
				for role, m := range map[string]string{"l1": c.Analyst.L1Model, "l2": c.Analyst.L2Model, "senior": c.Analyst.SeniorModel} {
					if m == "" {
						t.Errorf("analyst.%s_model empty; an openai-family role has no model default", role)
					}
				}
			}
			if c.Analyst.Local.Model != fullProfileModel {
				t.Errorf("analyst.local.model = %q; the in-cluster model must stay configured as the fallback", c.Analyst.Local.Model)
			}
			if strings.Contains(rendered, "fake-llm") {
				t.Error("overlay render references fake-llm")
			}
			// The key comes from the chart Secret, never from the overlay.
			raw, err := os.ReadFile(filepath.Join(chartDir(t), tc.file))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), "llmApiKey:") {
				t.Errorf("%s sets secrets.llmApiKey; the key must be supplied at install time, not committed", tc.file)
			}
			// The aggregator can reach a hosted endpoint: HTTPS egress.
			https := false
			if eg := decodeNetpols(t, rendered)["olaitan"].Spec.Egress; eg != nil {
				for _, rule := range *eg {
					for _, p := range asList(rule["ports"]) {
						if fmt.Sprint(dig(p, "port")) == "443" {
							https = true
						}
					}
				}
			}
			if !https {
				t.Error("the release NetworkPolicy does not allow HTTPS egress to the hosted model")
			}
		})
	}
}

// TestRealLLMTargetRestoresTheProfile: `make e2e-full-real-llm` must run
// against the real-model profile, never the fake-LLM overlay that
// `make e2e-full-report-archive` leaves in the shared release. So it
// upgrades from values-full.yaml WITHOUT --reuse-values, with the same
// values files as `make e2e-full`, builds and loads the code under test,
// and sets both gates of the live test.
func TestRealLLMTargetRestoresTheProfile(t *testing.T) {
	recipe := makeTarget(t, "e2e-full-real-llm")
	head := strings.SplitN(recipe, "\n", 2)[0]
	for _, dep := range []string{"helm-prepare", "helm-deps", "docker-build"} {
		if !strings.Contains(head, dep) {
			t.Errorf("e2e-full-real-llm does not depend on %s: a green run would say nothing about the working tree", dep)
		}
	}
	if strings.Contains(recipe, "--reuse-values") {
		t.Error("e2e-full-real-llm reuses release values, so it would inherit the fake-LLM overlay")
	}
	for _, want := range []string{"kind load docker-image", "$(FULL_HELM_VALUES)", "OLT_E2E_FULL=1", "OLT_E2E_REAL_LLM=1", "TestRealLLM_RealIncidentOnFullProfile", "TestFalcoSourceIsLive"} {
		if !strings.Contains(recipe, want) {
			t.Errorf("e2e-full-real-llm recipe lacks %q", want)
		}
	}
	if full := makeTarget(t, "e2e-full"); !strings.Contains(full, "$(FULL_HELM_VALUES)") {
		t.Error("e2e-full must install from the same $(FULL_HELM_VALUES) as e2e-full-real-llm, or the two targets can drift apart")
	}
}
