//go:build helm

package helm_test

// Story 12.7 (Aslim, 2026-10-19): a plain `helm install` of the chart, and the
// release install.yaml, turn every part on. Blocking stays off behind one
// flag, response.networkPolicy.enabled. A part whose platform prerequisite is
// missing comes up DEGRADED and says so; it never fails the render, blocks
// the install or crash-loops a pod.

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/olokotoh/olaitan/internal/config"
)

// The model the default install pulls and routes every chain role to
// (Story 10.6 measured it; values-full.yaml used to be the only place it was
// on).
const defaultModel = "qwen2.5:3b-instruct"

// renderArgs runs `helm template olaitan <chart>` with raw extra arguments
// (--set, -f, --api-versions, --namespace). It does NOT inject a Redis
// password: the default render generates one, exactly as a plain install does.
func renderArgs(t *testing.T, args ...string) string {
	t.Helper()
	out, err := renderArgsErr(t, args...)
	if err != nil {
		t.Fatalf("helm template %v: %v", args, err)
	}
	return out
}

func renderArgsErr(t *testing.T, args ...string) (string, error) {
	t.Helper()
	full := append([]string{"template", "olaitan", chartDir(t)}, args...)
	cmd := exec.Command("helm", full...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", &renderError{err: err, stderr: stderr.String()}
	}
	return stdout.String(), nil
}

type renderError struct {
	err    error
	stderr string
}

func (e *renderError) Error() string { return e.err.Error() + "\n" + e.stderr }

// renderedConfig loads the olaitan.yaml a render ships through the same
// config.Load the binary runs at startup, so "on" means on to the binary, and
// a config the binary would refuse fails here.
func renderedConfig(t *testing.T, rendered string) *config.Config {
	t.Helper()
	body := extractEmbeddedConfigYAML(t, rendered)
	p := filepath.Join(t.TempDir(), "olaitan.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("the rendered olaitan.yaml does not load: %v", err)
	}
	return cfg
}

// aggregatorGrants reports whether any ClusterRole or Role whose name contains
// "aggregator" grants verb on resource in the core API group.
func aggregatorGrants(t *testing.T, rendered, resource, verb string) bool {
	t.Helper()
	for _, kind := range []string{"ClusterRole", "Role"} {
		for _, r := range docsOfKind(t, rendered, kind) {
			name, _ := dig(r, "metadata", "name").(string)
			if !strings.Contains(name, "aggregator") {
				continue
			}
			for _, rule := range asList(r["rules"]) {
				rm, _ := rule.(map[string]any)
				if !containsAny(asList(rm["apiGroups"]), "") || !containsAny(asList(rm["resources"]), resource) {
					continue
				}
				if containsAny(asList(rm["verbs"]), verb) {
					return true
				}
			}
		}
	}
	return false
}

func containsAny(l []any, want string) bool {
	for _, v := range l {
		if s, _ := v.(string); s == want {
			return true
		}
	}
	return false
}

func volumeNamed(workload map[string]any, name string) map[string]any {
	for _, v := range asList(dig(workload, "spec", "template", "spec", "volumes")) {
		vm, _ := v.(map[string]any)
		if vm["name"] == name {
			return vm
		}
	}
	return nil
}

func envFromSecretOptional(container map[string]any, name string) (found, optional bool) {
	for _, e := range asList(container["env"]) {
		em, _ := e.(map[string]any)
		if em["name"] != name {
			continue
		}
		ref, _ := dig(em, "valueFrom", "secretKeyRef").(map[string]any)
		if ref == nil {
			return true, false
		}
		opt, _ := ref["optional"].(bool)
		return true, opt
	}
	return false, false
}

// TestDefaultTurnsEveryPartOn is AC1: no values at all, every part on.
func TestDefaultTurnsEveryPartOn(t *testing.T) {
	rendered := renderArgs(t)
	cfg := renderedConfig(t, rendered)

	src := cfg.Detection.Sources
	for name, on := range map[string]bool{
		"audit webhook source":    src.Audit.Enabled,
		"containerd source":       src.Containerd.Enabled,
		"calico source":           src.Calico.Enabled,
		"rules":                   cfg.Detection.Rules.EnabledOrDefault(),
		"baselines":               cfg.Detection.Baselines.EnabledOrDefault(),
		"response.audit":          cfg.Response.Audit.EnabledOrDefault(),
		"response.override":       cfg.Response.Override.EnabledOrDefault(),
		"response.forensics":      cfg.Response.Forensics.EnabledOrDefault(),
		"response.settling":       cfg.Response.Settling.EnabledOrDefault(),
		"response.dfir":           cfg.Response.DFIR.EnabledOrDefault(),
		"response.report_archive": cfg.Response.ReportArchive.EnabledOrDefault(),
		"report archive deferred": cfg.Response.ReportArchive.DeferredEnabledOrDefault(),
		"response.notifications":  cfg.Response.Notifications.EnabledOrDefault(),
		"analyst L2":              cfg.Analyst.L2EnabledOrDefault(),
		"analyst Senior":          cfg.Analyst.SeniorEnabledOrDefault(),
	} {
		if !on {
			t.Errorf("%s is off in the default render; Story 12.7 turns every part on", name)
		}
	}
	if cfg.Analyst.Provider != "local" {
		t.Errorf("analyst.provider = %q, want local (the self-contained in-cluster model, no API key)", cfg.Analyst.Provider)
	}
	if cfg.Analyst.Local.Model != defaultModel {
		t.Errorf("analyst.local.model = %q, want %q", cfg.Analyst.Local.Model, defaultModel)
	}
	if cfg.Response.ReportArchive.DeferredRedisAddr == "" {
		t.Error("the deferred report queue is on but has no Redis address; the bundled Redis must be filled in")
	}

	// The objects behind the parts.
	for _, want := range []struct{ kind, name string }{
		{"DaemonSet", "olaitan-falco"},
		{"DaemonSet", "olaitan-collector"},
		{"Deployment", "olaitan-aggregator"},
		{"Deployment", "olaitan-applog-injector"},
		{"MutatingWebhookConfiguration", "olaitan-applog-injector"},
		{"Service", "olaitan-audit-webhook"},
		{"Deployment", "olaitan-ollama"},
		{"PersistentVolumeClaim", "olaitan-ollama-models"},
	} {
		docNamed(t, rendered, want.kind, want.name)
	}
	job := pullJob(t, rendered)
	if !strings.Contains(toYAML(t, job), defaultModel) {
		t.Errorf("the model pull Job does not pull %s", defaultModel)
	}
	collector := podContainers(docNamed(t, rendered, "DaemonSet", "olaitan-collector"), "containers")["collector"]
	if v, _ := envValue(collector, "OLAITAN_APPLOG_ENABLED"); v != "true" {
		t.Errorf("collector OLAITAN_APPLOG_ENABLED = %q, want true", v)
	}
	agg := podContainers(docNamed(t, rendered, "Deployment", "olaitan-aggregator"), "containers")["aggregator"]
	if v, _ := envValue(agg, "OLT_LLM_ROLE_TIMEOUT_MULTIPLIER"); v == "" {
		t.Error("aggregator has no OLT_LLM_ROLE_TIMEOUT_MULTIPLIER; the CPU model needs the scaled role budgets")
	}
}

// TestBlockingIsOffByDefaultAndOneFlagTurnsItOn is AC2.
func TestBlockingIsOffByDefaultAndOneFlagTurnsItOn(t *testing.T) {
	def := renderArgs(t)
	if renderedConfig(t, def).Response.NetworkPolicy.EnabledOrDefault() {
		t.Error("response.network_policy.enabled is on by default; blocking must stay off")
	}
	if aggregatorGrants(t, def, "pods", "delete") {
		t.Error("the default aggregator can delete pods; with forensics on by default that would kill workloads with blocking off")
	}
	for _, kind := range []string{"ClusterRole", "Role"} {
		for _, r := range docsOfKind(t, def, kind) {
			for _, rule := range asList(r["rules"]) {
				rm, _ := rule.(map[string]any)
				if containsAny(asList(rm["resources"]), "networkpolicies") && (containsAny(asList(rm["verbs"]), "create") || containsAny(asList(rm["verbs"]), "delete")) {
					t.Errorf("%s %v can write NetworkPolicies with blocking off", kind, dig(r, "metadata", "name"))
				}
			}
		}
	}

	on := renderArgs(t, "--set", "response.networkPolicy.enabled=true")
	if !renderedConfig(t, on).Response.NetworkPolicy.EnabledOrDefault() {
		t.Error("--set response.networkPolicy.enabled=true did not turn enforcement on")
	}
	if !aggregatorGrants(t, on, "pods", "delete") {
		t.Error("with the blocking switch on, the aggregator cannot delete pods, so the post-capture kill cannot run")
	}
	for _, v := range []string{"create", "update", "delete"} {
		found := false
		for _, r := range docsOfKind(t, on, "ClusterRole") {
			for _, rule := range asList(r["rules"]) {
				rm, _ := rule.(map[string]any)
				if containsAny(asList(rm["resources"]), "networkpolicies") && containsAny(asList(rm["verbs"]), v) {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("with the blocking switch on, no ClusterRole grants %s on networkpolicies", v)
		}
	}
	if !aggregatorGrants(t, on, "pods/log", "get") {
		t.Error("forensic capture needs pods/log get")
	}
	if !aggregatorGrants(t, def, "pods/log", "get") {
		t.Error("forensic capture is on by default and needs pods/log get even with blocking off")
	}
}

// TestDefaultRenderHoldsNoKeyMaterial is AC4: TLS material is generated in
// the cluster, never in a render (Story 12.4 D5).
func TestDefaultRenderHoldsNoKeyMaterial(t *testing.T) {
	rendered := renderArgs(t)
	if strings.Contains(rendered, "PRIVATE KEY") {
		t.Fatal("the default render carries a private key")
	}
	for _, kind := range []string{"Secret"} {
		for _, s := range docsOfKind(t, rendered, kind) {
			name, _ := dig(s, "metadata", "name").(string)
			for _, tls := range []string{"-audit-tls", "-applog-injector-tls", "-cni-tls", "-audit-webhook-kubeconfig"} {
				if strings.HasSuffix(name, tls) {
					t.Errorf("Secret %s is rendered; in the default mode the certgen Job creates it in the cluster", name)
				}
			}
		}
	}
	for _, kind := range []string{"MutatingWebhookConfiguration", "ValidatingWebhookConfiguration"} {
		for _, w := range docsOfKind(t, rendered, kind) {
			for _, hook := range asList(w["webhooks"]) {
				cc, _ := dig(hook, "clientConfig").(map[string]any)
				if _, ok := cc["caBundle"]; ok {
					t.Errorf("%s %v renders a caBundle; certgen patches it and a rendered one would be reset on every apply", kind, dig(w, "metadata", "name"))
				}
			}
		}
	}
	vol := volumeNamed(docNamed(t, rendered, "DaemonSet", "olaitan-collector"), "audit-tls")
	if vol == nil {
		t.Fatal("collector has no audit-tls volume")
	}
	if opt, _ := dig(vol, "secret", "optional").(bool); !opt {
		t.Error("the collector's audit-tls volume is not optional: if the certgen Job has not run yet the collector (and Falco ingest) would not start")
	}

	// The certgen Job, its ServiceAccount and least-privilege RBAC.
	var job map[string]any
	for _, j := range docsOfKind(t, rendered, "Job") {
		if n, _ := dig(j, "metadata", "name").(string); strings.HasPrefix(n, "olaitan-certgen-") {
			job = j
		}
	}
	if job == nil {
		t.Fatal("no olaitan-certgen-* Job in the default render")
	}
	c := podContainers(job, "containers")["certgen"]
	if c == nil {
		t.Fatal("certgen Job has no certgen container")
	}
	args := strings.Join(toStrings(asList(c["args"])), " ")
	for _, want := range []string{"certgen", "--audit-secret=olaitan-audit-tls", "--audit-kubeconfig-secret=olaitan-audit-webhook-kubeconfig",
		"--applog-secret=olaitan-applog-injector-tls", "--mutating-webhook=olaitan-applog-injector"} {
		if !strings.Contains(args, want) {
			t.Errorf("certgen args %q lack %q", args, want)
		}
	}
	if sa, _ := dig(job, "spec", "template", "spec", "serviceAccountName").(string); sa != "olaitan-certgen" {
		t.Errorf("certgen runs as %q, want its own ServiceAccount olaitan-certgen", sa)
	}
	role := docNamed(t, rendered, "Role", "olaitan-certgen")
	for _, rule := range asList(role["rules"]) {
		rm, _ := rule.(map[string]any)
		verbs := toStrings(asList(rm["verbs"]))
		for _, v := range verbs {
			if v == "list" || v == "watch" || v == "delete" || v == "*" {
				t.Errorf("certgen Role grants %q; it needs create plus get/update on its own Secrets", v)
			}
		}
		if !containsAny(asList(rm["verbs"]), "create") && len(asList(rm["resourceNames"])) == 0 {
			t.Errorf("certgen Role rule %v is not limited by resourceNames", rm)
		}
	}
	cr := docNamed(t, rendered, "ClusterRole", "olaitan-certgen")
	for _, rule := range asList(cr["rules"]) {
		rm, _ := rule.(map[string]any)
		if len(asList(rm["resourceNames"])) == 0 {
			t.Errorf("certgen ClusterRole rule %v is not limited by resourceNames", rm)
		}
	}
}

func toStrings(l []any) []string {
	var out []string
	for _, v := range l {
		s, _ := v.(string)
		out = append(out, s)
	}
	return out
}

// TestOperatorTLSMaterialStillSelectsTheOldPaths is AC4's other half: an
// operator who supplies material (or cert-manager) gets what they got before,
// and half a set still fails the render.
func TestOperatorTLSMaterialStillSelectsTheOldPaths(t *testing.T) {
	stub := filepath.Join(filepath.Dir(chartDir(t)), "testdata", "full-profile", "stub-key-material.yaml")
	rendered := renderArgs(t, "-f", stub)
	for _, n := range []string{"olaitan-audit-tls", "olaitan-audit-webhook-kubeconfig", "olaitan-applog-injector-tls", "olaitan-cni-tls"} {
		docNamed(t, rendered, "Secret", n)
	}
	for _, j := range docsOfKind(t, rendered, "Job") {
		if n, _ := dig(j, "metadata", "name").(string); strings.HasPrefix(n, "olaitan-certgen-") {
			t.Errorf("certgen Job %s renders although every TLS value was supplied", n)
		}
	}
	if _, err := renderArgsErr(t, "--set", "auditWebhook.caBundle=Zm9v"); err == nil {
		t.Error("a partial audit TLS set (caBundle only) rendered; it must fail and name the missing values")
	}
	if _, err := renderArgsErr(t, "--set", "applogSidecar.tls.servingCert=Zm9v"); err == nil {
		t.Error("a partial applog TLS set (servingCert only) rendered; it must fail")
	}
	if _, err := renderArgsErr(t, "--set", "calicoSensor.tls.clientCert=Zm9v"); err == nil {
		t.Error("a partial Calico Path B set (clientCert only) rendered; it must fail")
	}
}

// TestDegradedPartsStillRender is AC3 on the chart side.
func TestDegradedPartsStillRender(t *testing.T) {
	def := renderArgs(t)
	ds := docNamed(t, def, "DaemonSet", "olaitan-collector")

	// containerd: never stop the collector pod over a missing socket dir.
	sock := volumeNamed(ds, "containerd-socket")
	if sock == nil {
		t.Fatal("no containerd-socket volume in the default render")
	}
	if typ, _ := dig(sock, "hostPath", "type").(string); typ != "DirectoryOrCreate" {
		t.Errorf("containerd hostPath type = %q, want DirectoryOrCreate: type Directory keeps the whole collector pod, Falco ingest included, from starting on a node without /run/containerd", typ)
	}

	// Calico with no Path A/B material: renders, mounts nothing, source on.
	if volumeNamed(ds, "cni-tls") != nil {
		t.Error("the default render mounts a cni-tls volume although no Calico material exists")
	}
	if !renderedConfig(t, def).Detection.Sources.Calico.Enabled {
		t.Error("the Calico source is not on in the default render")
	}

	// S3 credentials: optional refs, so install.yaml's Secret recipe holds.
	agg := podContainers(docNamed(t, def, "Deployment", "olaitan-aggregator"), "containers")["aggregator"]
	for _, env := range []string{"S3_ACCESS_KEY", "S3_SECRET_KEY", "NOTIFICATIONS_WEBHOOK_URL"} {
		found, opt := envFromSecretOptional(agg, env)
		if !found {
			t.Errorf("aggregator has no %s", env)
		} else if !opt {
			t.Errorf("aggregator %s secretKeyRef is not optional; an install without that key would sit in CreateContainerConfigError", env)
		}
	}

	// k3s: the socket lives under /run/k3s.
	k3s := renderArgs(t, "--set", "platform=k3s")
	if p, _ := dig(volumeNamed(docNamed(t, k3s, "DaemonSet", "olaitan-collector"), "containerd-socket"), "hostPath", "path").(string); p != "/run/k3s/containerd" {
		t.Errorf("k3s containerd hostPath = %q, want /run/k3s/containerd", p)
	}
	if got := renderedConfig(t, k3s).Detection.Sources.Containerd.SocketPath; got != "/run/k3s/containerd/containerd.sock" {
		t.Errorf("k3s containerd socket_path = %q", got)
	}

	// OpenShift runs CRI-O: no containerd mount, source off, said in NOTES.
	osr := renderArgs(t, "--api-versions", "security.openshift.io/v1")
	if volumeNamed(docNamed(t, osr, "DaemonSet", "olaitan-collector"), "containerd-socket") != nil {
		t.Error("OpenShift render mounts a containerd socket dir; OpenShift runs CRI-O")
	}
	if renderedConfig(t, osr).Detection.Sources.Containerd.Enabled {
		t.Error("OpenShift render runs the containerd adapter against a runtime that is not there")
	}
}

// TestNotesSayWhatIsOnAndWhatIsDegraded is AC3's NOTES half and AC2's
// documentation of the one switch.
func TestNotesSayWhatIsOnAndWhatIsDegraded(t *testing.T) {
	notes := renderNotes(t, nil)
	for _, want := range []string{
		"[ON ] Falco syscall events",
		"Kubernetes audit webhook",
		"containerd CRI sensor",
		"Calico CNI flow adapter",
		"Application log sidecar",
		"LLM analyst",
		defaultModel,
		"Forensic capture",
		"Report archive",
		"DFIR report",
		"SIEM audit trail",
		"[DEGRADED] Calico CNI flow adapter",
		"no Goldmane client certificate",
		"[DEGRADED] Forensic capture",
		"no object store",
		"--set response.networkPolicy.enabled=true",
	} {
		if !strings.Contains(notes, want) {
			t.Errorf("install notes lack %q", want)
		}
	}
	if strings.Contains(notes, "[OFF] Kubernetes audit webhook") || strings.Contains(notes, "[OFF] containerd") ||
		strings.Contains(notes, "[OFF] Calico") || strings.Contains(notes, "[OFF] Application log") {
		t.Error("install notes still report a source OFF by default")
	}

	managed := renderNotes(t, []string{"platform=eks"})
	if !strings.Contains(managed, "[DEGRADED] Kubernetes audit webhook") {
		t.Error("on a managed control plane the audit webhook must show DEGRADED")
	}
	oc := renderNotes(t, []string{"platform=openshift"})
	if !strings.Contains(oc, "[DEGRADED] containerd CRI sensor") || !strings.Contains(oc, "CRI-O") {
		t.Error("on OpenShift the containerd sensor must show DEGRADED and name CRI-O")
	}
	on := renderNotes(t, []string{"response.networkPolicy.enabled=true"})
	if !strings.Contains(on, "[ON ] NetworkPolicy isolation") {
		t.Error("with the blocking switch the notes do not say isolation is on")
	}
}

// TestInstallManifestTurnsEverythingOnWithNoKeys is AC1 + AC4 for the
// kubectl path (Story 12.4's install.yaml).
func TestInstallManifestTurnsEverythingOnWithNoKeys(t *testing.T) {
	stage := stageReleaseChart(t, "9.9.9", "ghcr.io/example/olaitan", "sha256:"+strings.Repeat("a", 64))
	m := renderInstallManifest(t, stage)
	if strings.Contains(m, "PRIVATE KEY") {
		t.Fatal("install.yaml carries a private key")
	}
	for _, want := range []string{"name: olaitan-ollama", "name: olaitan-applog-injector", "olaitan-certgen-", "provider: local"} {
		if !strings.Contains(m, want) {
			t.Errorf("install.yaml lacks %q", want)
		}
	}
}

// TestMinimalProfileIsThePreviousPosture (D9): values-minimal.yaml turns
// every newly-default part off again and leaves Falco on.
func TestMinimalProfileIsThePreviousPosture(t *testing.T) {
	r := renderArgs(t, "-f", filepath.Join(chartDir(t), "values-minimal.yaml"))
	cfg := renderedConfig(t, r)
	if cfg.Detection.Sources.Audit.Enabled || cfg.Detection.Sources.Containerd.Enabled || cfg.Detection.Sources.Calico.Enabled {
		t.Error("values-minimal.yaml leaves a non-Falco source on")
	}
	if cfg.Analyst.Provider != "none" || cfg.Response.Forensics.EnabledOrDefault() || cfg.Response.DFIR.EnabledOrDefault() {
		t.Error("values-minimal.yaml leaves the LLM tier or forensics on")
	}
	for _, d := range docsOfKind(t, r, "Deployment") {
		if n, _ := dig(d, "metadata", "name").(string); n == "olaitan-ollama" || n == "olaitan-applog-injector" {
			t.Errorf("values-minimal.yaml still deploys %s", n)
		}
	}
	docNamed(t, r, "DaemonSet", "olaitan-falco")
	for _, j := range docsOfKind(t, r, "Job") {
		t.Errorf("values-minimal.yaml renders Job %v", dig(j, "metadata", "name"))
	}
}

func toYAML(t *testing.T, v any) string {
	t.Helper()
	b, err := yaml.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// podAnnotation returns a pod-template annotation of a workload.
func podAnnotation(w map[string]any, key string) string {
	v, _ := dig(w, "spec", "template", "metadata", "annotations", key).(string)
	return v
}

// TestConfigChangeRollsThePods (live finding, 2026-10-19): a helm upgrade
// that changed analyst.provider left the aggregator running the old config
// until a manual rollout restart, because the rendered config lives in a
// ConfigMap and the pod template did not change. A checksum of the rendered
// config on the aggregator and collector pod templates rolls them on any
// config change, and only then.
func TestConfigChangeRollsThePods(t *testing.T) {
	sum := func(args ...string) (agg, col string) {
		r := renderArgs(t, args...)
		return podAnnotation(docNamed(t, r, "Deployment", "olaitan-aggregator"), "checksum/config"),
			podAnnotation(docNamed(t, r, "DaemonSet", "olaitan-collector"), "checksum/config")
	}
	a1, c1 := sum()
	if a1 == "" || c1 == "" {
		t.Fatalf("no checksum/config on the aggregator (%q) or the collector (%q) pod template", a1, c1)
	}
	a2, c2 := sum()
	if a1 != a2 || c1 != c2 {
		t.Error("the same values gave two different config checksums; every upgrade would roll the pods")
	}
	a3, c3 := sum("--set", "analyst.provider=none")
	if a3 == a1 || c3 == c1 {
		t.Error("changing analyst.provider did not change the config checksum, so helm upgrade would not restart the pods")
	}
	a4, _ := sum("--set", "rules.enabled=false")
	if a4 == a1 {
		t.Error("changing rules.enabled did not change the config checksum")
	}
}

// TestRiskWindowOnByDefault (live finding, 2026-10-19): without the risk
// window no single evidence package can reach RESTRICTED (the rule term
// alone tops out at 0.4 x 95 = 38), so the one blocking flag would never
// block. The window is on by default; the evaluation overlays and
// values-minimal.yaml pin it off so recorded campaigns stay reproducible.
func TestRiskWindowOnByDefault(t *testing.T) {
	envOf := func(args ...string) (string, int) {
		c := podContainers(docNamed(t, renderArgs(t, args...), "Deployment", "olaitan-aggregator"), "containers")["aggregator"]
		n := 0
		val := ""
		for _, e := range asList(c["env"]) {
			em, _ := e.(map[string]any)
			if em["name"] == "OLT_RISK_WINDOW_SECONDS" {
				n++
				val, _ = em["value"].(string)
			}
		}
		return val, n
	}
	if v, n := envOf(); v != "900" || n != 1 {
		t.Errorf("default OLT_RISK_WINDOW_SECONDS = %q (x%d), want 900 once", v, n)
	}
	if v, n := envOf("--set", "aggregator.riskWindowSeconds=0"); n != 0 {
		t.Errorf("riskWindowSeconds=0 still renders OLT_RISK_WINDOW_SECONDS=%q", v)
	}
	if v, n := envOf("--set", "aggregator.extraEnv[0].name=OLT_RISK_WINDOW_SECONDS", "--set-string", "aggregator.extraEnv[0].value=60"); v != "60" || n != 1 {
		t.Errorf("an extraEnv OLT_RISK_WINDOW_SECONDS must win, once: got %q (x%d)", v, n)
	}
	for _, bad := range []string{"-1", "604801", "15m"} {
		if _, err := renderArgsErr(t, "--set-string", "aggregator.riskWindowSeconds="+bad); err == nil {
			t.Errorf("riskWindowSeconds=%s rendered; want a render error", bad)
		}
	}
	files, _ := filepath.Glob(filepath.Join(chartDir(t), "values-eval*.yaml"))
	files = append(files, filepath.Join(chartDir(t), "values-minimal.yaml"))
	for _, f := range files {
		// values-eval-egress.yaml is not an arm: it only opens TCP 443
		// egress for a hosted model and is layered with an arm overlay,
		// which carries the pin.
		if filepath.Base(f) == "values-eval-egress.yaml" {
			continue
		}
		if v, n := envOf("-f", f); n != 0 {
			t.Errorf("%s leaves the risk window on (%s); the evaluation overlays pin the pre-12.7 per-package scoring", filepath.Base(f), v)
		}
	}
	notes := renderNotes(t, nil)
	for _, want := range []string{"risk window", "RESTRICTED blocks only egress outside the private ranges", "QUARANTINED blocks all"} {
		if !strings.Contains(notes, want) {
			t.Errorf("install notes lack %q next to the blocking switch", want)
		}
	}
}

// TestReviewRound1Guards pins the bmad-code-review round-1 patches.
func TestReviewRound1Guards(t *testing.T) {
	// E2: Fail + generated TLS would deadlock pod creation.
	if _, err := renderArgsErr(t, "--set", "applogSidecar.webhook.failurePolicy=Fail"); err == nil {
		t.Error("applog failurePolicy=Fail with generated TLS rendered; it deadlocks pod creation until certgen runs")
	}
	// E7: a deleted deferredRedisAddr is still auto-filled.
	cfg := renderedConfig(t, renderArgs(t, "--set", "response.reportArchive.deferredRedisAddr=null"))
	if cfg.Response.ReportArchive.DeferredRedisAddr == "" {
		t.Error("deferredRedisAddr=null left the deferred queue without an address; the aggregator would refuse its config")
	}
	// E12: a socket path outside /run keeps the loud Directory check.
	ds := docNamed(t, renderArgs(t, "--set", "containerdSensor.socketPath=/var/lib/custom/containerd.sock"), "DaemonSet", "olaitan-collector")
	if typ, _ := dig(volumeNamed(ds, "containerd-socket"), "hostPath", "type").(string); typ != "Directory" {
		t.Errorf("a custom socket path outside /run renders hostPath type %q, want Directory", typ)
	}
	// A1/A2: the default model server does not wait for the download; the
	// full profile does; the default CPU-limits the model, the full profile
	// does not.
	def := renderArgs(t)
	if strings.Contains(def, "wait-for-models") {
		t.Error("the default model server waits in Init for the download; a plain helm install --wait would block on 1.9 GB")
	}
	stub := filepath.Join(filepath.Dir(chartDir(t)), "testdata", "full-profile", "stub-key-material.yaml")
	full := renderArgs(t, "-f", filepath.Join(chartDir(t), "values-full.yaml"), "-f", stub)
	if !strings.Contains(full, "wait-for-models") {
		t.Error("the full profile lost the Story 10.6 wait for the model")
	}
	cpuLimit := func(r string) any {
		c := podContainers(docNamed(t, r, "Deployment", "olaitan-ollama"), "containers")["ollama"]
		return dig(c, "resources", "limits", "cpu")
	}
	if l := cpuLimit(def); l != "2" {
		t.Errorf("default Ollama CPU limit = %v, want 2 (an unlimited CPU model starves detection on a small node)", l)
	}
	if l := cpuLimit(full); l != nil {
		t.Errorf("full profile Ollama CPU limit = %v, want none", l)
	}
	// E6: any pod-template change renames the certgen Job.
	jobName := func(args ...string) string {
		for _, j := range docsOfKind(t, renderArgs(t, args...), "Job") {
			if n, _ := dig(j, "metadata", "name").(string); strings.HasPrefix(n, "olaitan-certgen-") {
				return n
			}
		}
		return ""
	}
	if a, b := jobName(), jobName("--set", "image.pullPolicy=Always"); a == "" || a == b {
		t.Errorf("certgen Job name did not change with the pod template (%q, %q); an upgrade would hit an immutable field", a, b)
	}
	// A11: an in-cluster model nobody provisions is DEGRADED in the notes.
	air := renderNotes(t, []string{"ollama.pull.models=null", "ollama.pull.expectedIds=null"})
	if !strings.Contains(air, "[DEGRADED] LLM analyst") {
		t.Error("notes report the LLM ON although no model is pulled or provided")
	}
}

// TestReviewRound2Guards pins the round-2 review (Chief of Staff) changes.
func TestReviewRound2Guards(t *testing.T) {
	aggEnv := func(args ...string) map[string]string {
		c := podContainers(docNamed(t, renderArgs(t, args...), "Deployment", "olaitan-aggregator"), "containers")["aggregator"]
		out := map[string]string{}
		for _, e := range asList(c["env"]) {
			em, _ := e.(map[string]any)
			n, _ := em["name"].(string)
			v, _ := em["value"].(string)
			out[n] = v
		}
		return out
	}
	// 1. The chain's worker count matches Ollama's OLLAMA_NUM_PARALLEL, so
	// concurrent chain calls do not queue inside one role timeout.
	if v := aggEnv()["OLT_LLM_CHAIN_WORKERS"]; v != "1" {
		t.Errorf("default OLT_LLM_CHAIN_WORKERS = %q, want 1 (OLLAMA_NUM_PARALLEL is 1)", v)
	}
	if v := aggEnv("--set", "ollama.extraEnv[0].name=OLLAMA_NUM_PARALLEL", "--set-string", "ollama.extraEnv[0].value=3")["OLT_LLM_CHAIN_WORKERS"]; v != "3" {
		t.Errorf("OLT_LLM_CHAIN_WORKERS = %q with OLLAMA_NUM_PARALLEL=3, want 3", v)
	}
	if v, ok := aggEnv("--set", "evaluation.config=RSL")["OLT_LLM_CHAIN_WORKERS"]; ok {
		t.Errorf("a hosted-provider arm renders OLT_LLM_CHAIN_WORKERS=%q; the cap is for the in-cluster model only", v)
	}

	// 3. certgen is out of the release policy (whose API-server egress needs
	// lookup) and has its own policy that does not.
	r := renderArgs(t)
	nps := decodeNetpols(t, r)
	release := nps["olaitan"]
	excluded := false
	for _, e := range release.Spec.PodSelector.MatchExpressions {
		if e.Key == "app.kubernetes.io/component" && e.Operator == "NotIn" {
			for _, v := range e.Values {
				if v == "certgen" {
					excluded = true
				}
			}
		}
	}
	if !excluded {
		t.Error("the release NetworkPolicy selects the certgen pod; under helm template its API-server egress is only 10.96.0.1/32")
	}
	cg := docNamed(t, r, "NetworkPolicy", "olaitan-certgen")
	if lbl, _ := dig(cg, "spec", "podSelector", "matchLabels", "app.kubernetes.io/component").(string); lbl != "certgen" {
		t.Errorf("certgen policy selects %v, want the certgen component", dig(cg, "spec", "podSelector"))
	}
	if len(asList(dig(cg, "spec", "ingress"))) != 0 {
		t.Error("certgen policy admits ingress; it serves nothing")
	}
	ports := map[any]bool{}
	for _, rule := range asList(dig(cg, "spec", "egress")) {
		if len(asList(dig(rule, "to"))) != 0 {
			t.Errorf("certgen egress rule %v is limited to peers; the API server address is not knowable at render", rule)
		}
		for _, p := range asList(dig(rule, "ports")) {
			ports[dig(p, "port")] = true
		}
	}
	for _, p := range []int{443, 6443} {
		if !ports[p] {
			t.Errorf("certgen policy lacks API-server egress on %d", p)
		}
	}
	if _, ok := decodeNetpols(t, renderArgs(t, "-f", filepath.Join(chartDir(t), "values-minimal.yaml")))["olaitan-certgen"]; ok {
		t.Error("certgen policy renders without the certgen Job")
	}

	// 3/4. NOTES make a certgen failure findable and say the socket is read-only.
	notes := renderNotes(t, nil)
	for _, want := range []string{"kubectl -n default get job -l app.kubernetes.io/component=certgen", "mounted read-only"} {
		if !strings.Contains(notes, want) {
			t.Errorf("install notes lack %q", want)
		}
	}
}
