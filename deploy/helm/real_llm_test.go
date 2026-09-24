//go:build helm

package helm_test

import (
	"fmt"
	"os"
	"os/exec"
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
	v, ok := envValue(aggregator, "OLT_LLM_ROLE_TIMEOUT_MULTIPLIER")
	if !ok || v == "" {
		t.Fatal("the full profile runs a CPU model; OLT_LLM_ROLE_TIMEOUT_MULTIPLIER must raise the Claude-calibrated per-role timeouts")
	}
	// Review round 1 (P2): the budget must cover the SLOW end of the
	// measured rates, not the middle. A role prompt is up to 10k tokens
	// read at as little as 17 tokens/s (588s), plus about 35s of output at
	// 8.5 tokens/s: 623s. L1 and L2 have the smallest base budget, 30s.
	var mult int
	if _, err := fmt.Sscanf(v, "%d", &mult); err != nil {
		t.Fatalf("OLT_LLM_ROLE_TIMEOUT_MULTIPLIER = %q is not an integer", v)
	}
	const slowestRoleSeconds = 10000/17 + 35
	if mult*30 < slowestRoleSeconds || mult > 100 {
		t.Errorf("OLT_LLM_ROLE_TIMEOUT_MULTIPLIER = %d gives L1/L2 %ds, want at least %ds (the measured slow end) and a multiplier within the code ceiling of 100", mult, mult*30, slowestRoleSeconds)
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
		// Review round 1 (P10): the Claude overlay pins its model too, so
		// the real-LLM e2e (wantFromConfig) can check the record against it.
		{"values-llm-claude.yaml", "claude", "", true},
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
						t.Errorf("analyst.%s_model empty; the e2e cannot check the recorded model of an unpinned role", role)
					}
				}
				if c.Analyst.L1Model != c.Analyst.L2Model || c.Analyst.L2Model != c.Analyst.SeniorModel {
					t.Errorf("per-role models %q/%q/%q differ; the real-LLM e2e proves one model at a time", c.Analyst.L1Model, c.Analyst.L2Model, c.Analyst.SeniorModel)
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

// aggregatorKeyRef returns the Secret name and key the aggregator's LLM key
// env var is read from.
func aggregatorKeyRef(t *testing.T, rendered string) (name, key string) {
	t.Helper()
	agg := docNamed(t, rendered, "Deployment", "olaitan-aggregator")
	if agg == nil {
		t.Fatal("no olaitan-aggregator Deployment rendered")
	}
	for _, c := range podContainers(agg, "containers") {
		for _, e := range asList(c["env"]) {
			if dig(e, "name") != "olaitan-llm" {
				continue
			}
			return fmt.Sprint(dig(e, "valueFrom", "secretKeyRef", "name")), fmt.Sprint(dig(e, "valueFrom", "secretKeyRef", "key"))
		}
	}
	t.Fatal("the aggregator has no olaitan-llm env var")
	return "", ""
}

// Story 10.6: a hosted model's key can live in a Secret the operator (or a
// test) creates out of band, so it never passes through helm values, a
// values file, or `helm get values`. Default: the chart's own Secret.
func TestLLMKeyFromAnExistingSecret(t *testing.T) {
	if name, key := aggregatorKeyRef(t, renderFullProfile(t)); name != "olaitan-secrets" || key != "llm-api-key" {
		t.Errorf("default key ref = %s/%s, want olaitan-secrets/llm-api-key", name, key)
	}
	dir := t.TempDir()
	extra := filepath.Join(dir, "existing.yaml")
	if err := os.WriteFile(extra, []byte("secrets:\n  llmApiKeyExistingSecret: my-llm-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rendered := renderFullProfile(t, filepath.Join(chartDir(t), "values-llm-deepseek.yaml"), extra)
	if name, key := aggregatorKeyRef(t, rendered); name != "my-llm-key" || key != "llm-api-key" {
		t.Errorf("existing-secret key ref = %s/%s, want my-llm-key/llm-api-key", name, key)
	}
}

// Story 10.6 (issue #151 part 2, the part 10.6 needs): kind-full installs
// into `default`, and without this its own aggregator and Ollama crossed the
// multi-signal threshold at startup and queued FR19 chains ahead of a real
// attack. values-full.yaml turns on correlator.neverScoreReleaseNamespace,
// which adds the release namespace to detection.correlator.
// never_scored_namespaces. Review round 1 (D3) split this from
// response.excluded_namespaces, which stays the never-ENFORCED list: the
// profile must not put its release namespace, or anything else, on it, and
// kube-system must stay detected (not never-scored) everywhere.
func TestFullProfileNeverScoresItsOwnNamespace(t *testing.T) {
	load := func(rendered string) (neverScored, excluded string) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "olaitan.yaml")
		if err := os.WriteFile(path, []byte(extractEmbeddedConfigYAML(t, rendered)), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := configLoad(t, path)
		if err != nil {
			t.Fatalf("config does not load: %v", err)
		}
		return strings.Join(c.Detection.Correlator.NeverScoredNamespaces, ","), strings.Join(c.Response.ExcludedNamespaces, ",")
	}
	ns, ex := load(renderFullProfile(t))
	if ns != "olaitan,default" {
		t.Errorf("values-full never_scored_namespaces = %q, want olaitan,default", ns)
	}
	if ex != "kube-system,olaitan" {
		t.Errorf("values-full excluded_namespaces = %q, want the shipped kube-system,olaitan (never-enforced is not never-scored)", ex)
	}
	ns, ex = load(helmTemplate(t, nil))
	if ns != "olaitan" || ex != "kube-system,olaitan" {
		t.Errorf("default render: never_scored %q excluded %q, want olaitan and kube-system,olaitan", ns, ex)
	}
	// Installed into olaitan, the release namespace is already listed:
	// no duplicate.
	dir := t.TempDir()
	extra := filepath.Join(dir, "ns.yaml")
	if err := os.WriteFile(extra, []byte("correlator:\n  neverScoreReleaseNamespace: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("helm", "template", "olaitan", chartDir(t), "-n", "olaitan", "-f", extra).CombinedOutput()
	if err != nil {
		t.Fatalf("helm template -n olaitan: %v\n%s", err, out)
	}
	if got, _ := load(string(out)); got != "olaitan" {
		t.Errorf("-n olaitan never_scored_namespaces = %q, want no duplicate", got)
	}
}

// TestRealLLMDeepSeekTarget: `make e2e-full-real-llm-deepseek` restores the
// profile the same way, layers the DeepSeek overlay, and reads the key from
// a Secret created out of band: it never takes a key file, a key variable
// or --set secrets.llmApiKey, so the key cannot land in the repo, a shell
// history line or the release's values.
func TestRealLLMDeepSeekTarget(t *testing.T) {
	recipe := makeTarget(t, "e2e-full-real-llm-deepseek")
	head := strings.SplitN(recipe, "\n", 2)[0]
	for _, dep := range []string{"helm-prepare", "helm-deps", "docker-build"} {
		if !strings.Contains(head, dep) {
			t.Errorf("e2e-full-real-llm-deepseek does not depend on %s", dep)
		}
	}
	if strings.Contains(recipe, "--reuse-values") {
		t.Error("e2e-full-real-llm-deepseek reuses release values, so it would inherit the fake-LLM overlay")
	}
	for _, want := range []string{"kind load docker-image", "$(FULL_HELM_VALUES)", "values-llm-deepseek.yaml",
		"secrets.llmApiKeyExistingSecret=$(LLM_KEY_SECRET)", "get secret $(LLM_KEY_SECRET)",
		"OLT_E2E_FULL=1", "OLT_E2E_REAL_LLM=1", "TestRealLLM_RealIncidentOnFullProfile", "TestFalcoSourceIsLive"} {
		if !strings.Contains(recipe, want) {
			t.Errorf("e2e-full-real-llm-deepseek recipe lacks %q", want)
		}
	}
	for _, bad := range []string{"secrets.llmApiKey=", "--set-file secrets.llmApiKey", "DEEPSEEK_API_KEY"} {
		if strings.Contains(recipe, bad) {
			t.Errorf("e2e-full-real-llm-deepseek recipe contains %q: the key must come from the out-of-band Secret only", bad)
		}
	}
}

// fullProfileModelID is the ID `ollama list` showed for fullProfileModel in
// the Story 10.6 live run. The registry tag is mutable; this is not.
const fullProfileModelID = "357c53fb659c"

// TestPullJobCoLocatesWithTheServer (review round 1, P4): the pull Job pod
// and the server pod mount the same ReadWriteOnce claim. RWO is per node,
// so that is only safe on one node; a node-local provisioner (kind
// local-path) forces it, but attachable block storage (EBS, PD, Azure Disk)
// does not, and the second pod would hit Multi-Attach while the server
// waits forever. A required podAffinity to the server pod pins the pull pod
// to the server's node (the server is bound to a node while it sits in
// Init, so the pull pod can follow it).
func TestPullJobCoLocatesWithTheServer(t *testing.T) {
	rendered := renderFullProfile(t)
	job := pullJob(t, rendered)
	terms := asList(dig(job, "spec", "template", "spec", "affinity", "podAffinity", "requiredDuringSchedulingIgnoredDuringExecution"))
	if len(terms) != 1 {
		t.Fatalf("pull Job pod has %d required podAffinity terms, want 1 (to the ollama server pod)", len(terms))
	}
	if got := dig(terms[0], "topologyKey"); got != "kubernetes.io/hostname" {
		t.Errorf("podAffinity topologyKey = %v, want kubernetes.io/hostname", got)
	}
	want, _ := dig(docNamed(t, rendered, "Deployment", "olaitan-ollama"), "spec", "template", "metadata", "labels").(map[string]any)
	got, _ := dig(terms[0], "labelSelector", "matchLabels").(map[string]any)
	if len(got) == 0 || fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("podAffinity selects %v, want the ollama server pod labels %v", got, want)
	}
	// And it must not select the pull pod itself (it would then satisfy
	// its own affinity nowhere, or everywhere).
	self, _ := dig(job, "spec", "template", "metadata", "labels").(map[string]any)
	if fmt.Sprint(self) == fmt.Sprint(got) {
		t.Error("the podAffinity selector matches the pull pod's own labels")
	}
}

// TestWaitForModelsIsBounded (review round 1, P5): a failed pull Job is not
// retried by `helm upgrade` (same name, same spec), so the server must not
// wait in Init forever. The wait gives up a little after the Job's own
// deadline, exits non-zero, and names the Job to delete.
func TestWaitForModelsIsBounded(t *testing.T) {
	rendered := renderFullProfile(t)
	jobName, _ := dig(pullJob(t, rendered), "metadata", "name").(string)
	wait := podContainers(docNamed(t, rendered, "Deployment", "olaitan-ollama"), "initContainers")["wait-for-models"]
	if wait == nil {
		t.Fatal("no wait-for-models init container")
	}
	if v, _ := envValue(wait, "OLAITAN_OLLAMA_WAIT_SECONDS"); v != "2100" {
		t.Errorf("OLAITAN_OLLAMA_WAIT_SECONDS = %q, want 2100 (activeDeadlineSeconds 1800 + 300)", v)
	}
	if v, _ := envValue(wait, "OLAITAN_OLLAMA_PULL_JOB"); v != jobName {
		t.Errorf("OLAITAN_OLLAMA_PULL_JOB = %q, want the rendered Job name %q", v, jobName)
	}
	script := fmt.Sprint(asList(wait["args"]))
	for _, want := range []string{"OLAITAN_OLLAMA_WAIT_SECONDS", "exit 1", "kubectl delete job"} {
		if !strings.Contains(script, want) {
			t.Errorf("wait-for-models script lacks %q:\n%s", want, script)
		}
	}
}

// TestPullJobVerifiesModelIDs (review round 1, P6): the image is pinned by
// digest, but a model is pulled by a registry tag that can be re-pushed.
// values-full records the ID the live run pulled; the pull Job compares
// `ollama list` against it after the pull and fails on drift, and a changed
// expectation is a new Job.
func TestPullJobVerifiesModelIDs(t *testing.T) {
	rendered := renderFullProfile(t)
	job := pullJob(t, rendered)
	c := podContainers(job, "containers")["pull"]
	if v, _ := envValue(c, "OLAITAN_OLLAMA_EXPECT"); v != fullProfileModel+"="+fullProfileModelID {
		t.Errorf("OLAITAN_OLLAMA_EXPECT = %q, want %s=%s", v, fullProfileModel, fullProfileModelID)
	}
	script := fmt.Sprint(asList(c["args"]))
	if !strings.Contains(script, "OLAITAN_OLLAMA_EXPECT") || !strings.Contains(script, "exit 1") {
		t.Errorf("pull script does not check the model IDs:\n%s", script)
	}

	base := []string{
		"ollama.enabled=true", "ollama.persistence.enabled=true", "ollama.persistence.create=true",
		"ollama.pull.models={" + fullProfileModel + "}",
	}
	name := func(extra ...string) string {
		n, _ := dig(pullJob(t, helmTemplate(t, append(append([]string{}, base...), extra...))), "metadata", "name").(string)
		return n
	}
	key := `ollama.pull.expectedIds.qwen2\.5:3b-instruct=`
	if name(key+fullProfileModelID) == name(key+"0123456789ab") {
		t.Error("a changed expected model ID kept the same Job name; the Job would not re-verify")
	}
	for _, bad := range []struct{ set, msg string }{
		{key + "not-hex", "ollama.pull.expectedIds"},
		{`ollama.pull.expectedIds.other:7b=` + fullProfileModelID, "not in ollama.pull.models"},
	} {
		out := helmTemplateExpectError(t, append(append([]string{}, base...), bad.set))
		if !strings.Contains(out, bad.msg) {
			t.Errorf("%s: render error = %q, want it to mention %q", bad.set, out, bad.msg)
		}
	}
}
