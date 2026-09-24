//go:build helm

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
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Story 12.4 (#121): every release attaches one install.yaml, the chart's
// defaults rendered by release.yml, so `kubectl apply -f` gives the same
// install as the README's helm command without helm.

// installNamespace is the namespace install.yaml installs into. The README
// requires it for the helm path too: the agent's default excluded_namespaces
// list contains it (Story 12.4, D1).
const installNamespace = "olaitan"

// releaseManifestURL is where a release's install.yaml is downloaded from.
const releaseManifestURL = "https://github.com/olokotoh/olaitan/releases/download/v%s/install.yaml"

// clusterScopedKinds are the kinds that must NOT carry a namespace. Any other
// kind is treated as namespaced, so a kind this list does not know fails loud
// (a missing namespace) rather than passing quietly.
var clusterScopedKinds = map[string]bool{
	"Namespace":                      true,
	"ClusterRole":                    true,
	"ClusterRoleBinding":             true,
	"ValidatingWebhookConfiguration": true,
	"MutatingWebhookConfiguration":   true,
	"CustomResourceDefinition":       true,
	"PriorityClass":                  true,
	"StorageClass":                   true,
	"PersistentVolume":               true,
	"RuntimeClass":                   true,
	"APIService":                     true,
	"SecurityContextConstraints":     true,
}

// manifestObject is the part of a rendered object the install.yaml checks read.
type manifestObject struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name        string            `yaml:"name"`
		Namespace   string            `yaml:"namespace"`
		Annotations map[string]string `yaml:"annotations"`
	} `yaml:"metadata"`
}

func decodeManifestObjects(stream string) ([]manifestObject, error) {
	dec := yaml.NewDecoder(strings.NewReader(stream))
	var out []manifestObject
	for {
		var o manifestObject
		err := dec.Decode(&o)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if o.Kind == "" {
			continue // an empty document between separators
		}
		out = append(out, o)
	}
}

// installManifestProblems returns everything that stops stream from being a
// single file that `kubectl apply -f` installs into ns: the Namespace must come
// first, every namespaced object must name ns (kubectl apply puts an object
// with no namespace into the context's namespace, usually `default`), and no
// helm hook may be left in (kubectl runs a hook like any other object; the
// NATS `helm test` Pod would run once, complete, and never be Ready).
func installManifestProblems(stream, ns string) []string {
	objs, err := decodeManifestObjects(stream)
	if err != nil {
		return []string{"not a YAML stream: " + err.Error()}
	}
	if len(objs) == 0 {
		return []string{"no objects"}
	}
	var p []string
	if objs[0].Kind != "Namespace" || objs[0].Metadata.Name != ns {
		p = append(p, fmt.Sprintf("first object is %s/%s, want Namespace/%s (it must exist before anything is applied into it)", objs[0].Kind, objs[0].Metadata.Name, ns))
	}
	for _, o := range objs {
		id := o.Kind + "/" + o.Metadata.Name
		if hook, ok := o.Metadata.Annotations["helm.sh/hook"]; ok {
			p = append(p, fmt.Sprintf("%s is a helm %q hook; kubectl apply would run it as an ordinary object", id, hook))
		}
		if o.Kind == "Pod" {
			p = append(p, fmt.Sprintf("%s is a bare Pod; nothing in the default install is one", id))
		}
		switch {
		case clusterScopedKinds[o.Kind] && o.Metadata.Namespace != "":
			p = append(p, fmt.Sprintf("%s is cluster-scoped but names namespace %q", id, o.Metadata.Namespace))
		case !clusterScopedKinds[o.Kind] && o.Metadata.Namespace != ns:
			p = append(p, fmt.Sprintf("%s has namespace %q, want %q", id, o.Metadata.Namespace, ns))
		}
	}
	return p
}

// renderInstallManifest runs the script release.yml runs.
func renderInstallManifest(t *testing.T, chart string) string {
	t.Helper()
	root := filepath.Join(chartDir(t), "..", "..", "..")
	out := filepath.Join(t.TempDir(), "install.yaml")
	cmd := exec.Command("bash", filepath.Join(root, "hack", "render-install-manifest.sh"), chart, out)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("hack/render-install-manifest.sh %s: %v\n%s", chart, err, stderr.String())
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// stageReleaseChart copies the tree chart and stamps it the way release.yml's
// "Stage and stamp the chart" step does: version and appVersion from the tag,
// then the image repository and digest.
func stageReleaseChart(t *testing.T, version, repo, digest string) string {
	t.Helper()
	root := filepath.Join(chartDir(t), "..", "..", "..")
	stage := filepath.Join(t.TempDir(), "chart")
	if out, err := exec.Command("cp", "-r", chartDir(t), stage).CombinedOutput(); err != nil {
		t.Fatalf("copy chart: %v\n%s", err, out)
	}
	chartYAML := filepath.Join(stage, "Chart.yaml")
	raw, err := os.ReadFile(chartYAML)
	if err != nil {
		t.Fatal(err)
	}
	s := regexp.MustCompile(`(?m)^version: .*$`).ReplaceAllString(string(raw), "version: "+version)
	s = regexp.MustCompile(`(?m)^appVersion: .*$`).ReplaceAllString(s, `appVersion: "`+version+`"`)
	if err := os.WriteFile(chartYAML, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", filepath.Join(root, "hack", "stamp-chart-image.sh"),
		filepath.Join(chartDir(t), "values.yaml"), filepath.Join(stage, "values.yaml"), repo, digest)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("stamp: %v\n%s", err, out)
	}
	return stage
}

// TestInstallManifestIsOneApplyableFile (AC1, AC2): the script the release
// runs turns the stamped chart into one file kubectl can apply: namespaced,
// hook-free, the whole default install, every image pinned.
func TestInstallManifestIsOneApplyableFile(t *testing.T) {
	const (
		version = "9.9.9-rc1"
		repo    = "ghcr.io/example/olaitan"
		digest  = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	)
	manifest := renderInstallManifest(t, stageReleaseChart(t, version, repo, digest))

	for _, p := range installManifestProblems(manifest, installNamespace) {
		t.Error(p)
	}

	objs, err := decodeManifestObjects(manifest)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, o := range objs {
		have[o.Kind+"/"+o.Metadata.Name] = true
	}
	for _, want := range []string{
		"DaemonSet/olaitan-falco",
		"DaemonSet/olaitan-collector",
		"Deployment/olaitan-aggregator",
		"Deployment/olaitan-nats-box",
		"StatefulSet/olaitan-nats",
		"StatefulSet/olaitan-redis-master",
		"NetworkPolicy/olaitan",
	} {
		if !have[want] {
			t.Errorf("install.yaml has no %s; the default helm install does", want)
		}
	}

	olaitan := 0
	for _, img := range collectImages(t, manifest) {
		if strings.HasSuffix(strings.SplitN(img.ref, ":", 2)[0], "/olaitan") {
			olaitan++
			if want := repo + ":" + version + "@" + digest; img.ref != want {
				t.Errorf("%s = %q, want the released image %s", img.where, img.ref, want)
			}
			continue
		}
		if p := imagePinProblem(img.ref); p != "" {
			t.Errorf("%s: %q: %s", img.where, img.ref, p)
		}
	}
	if olaitan == 0 {
		t.Error("install.yaml runs no Olaitan image")
	}

	if !strings.Contains(strings.SplitN(manifest, "\n---", 2)[0], "olaitan "+version) {
		t.Errorf("install.yaml header does not name chart version %s:\n%s", version, strings.SplitN(manifest, "\n---", 2)[0])
	}
	t.Logf("%d objects, all in namespace %s or cluster-scoped, no hooks", len(objs), installNamespace)
}

// TestInstallManifestCheckBites proves the checker rejects the two ways a
// plain `helm template` of this chart breaks `kubectl apply -f`.
func TestInstallManifestCheckBites(t *testing.T) {
	ns := "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: olaitan\n"
	noNamespace := ns + "---\napiVersion: v1\nkind: Service\nmetadata:\n  name: olaitan-nats\n"
	if p := installManifestProblems(noNamespace, installNamespace); len(p) == 0 {
		t.Error("a Service with no namespace (the NATS subchart's default) was accepted")
	}
	hook := ns + "---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: t\n  namespace: olaitan\n  annotations:\n    helm.sh/hook: test\n"
	if p := installManifestProblems(hook, installNamespace); len(p) == 0 {
		t.Error("a helm test hook Pod was accepted")
	}
	late := "apiVersion: v1\nkind: Service\nmetadata:\n  name: s\n  namespace: olaitan\n---\n" + ns
	if p := installManifestProblems(late, installNamespace); len(p) == 0 {
		t.Error("a Namespace that comes after the objects it holds was accepted")
	}
	if p := installManifestProblems(ns, installNamespace); len(p) != 0 {
		t.Errorf("a lone Namespace was rejected: %v", p)
	}

	// The real chart, rendered plainly with a Namespace in front, is what
	// the script exists to fix: the NATS objects have no namespace and the
	// NATS test Pod is still there.
	plain := ns + "---\n" + renderChartAt(t, chartDir(t), "--namespace", installNamespace)
	p := strings.Join(installManifestProblems(plain, installNamespace), "\n")
	for _, want := range []string{`StatefulSet/olaitan-nats has namespace ""`, `Pod/olaitan-nats-test-request-reply is a helm "test" hook`} {
		if !strings.Contains(p, want) {
			t.Errorf("plain helm template: want a problem %q, got:\n%s", want, p)
		}
	}
}

// TestReleaseAttachesTheInstallManifest (AC2): release.yml renders
// install.yaml with the same script from the chart it packaged, checksums it
// and attaches it to the GitHub release.
func TestReleaseAttachesTheInstallManifest(t *testing.T) {
	root := filepath.Join(chartDir(t), "..", "..", "..")
	raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	wf := string(raw)
	for _, want := range []struct{ text, why string }{
		{`hack/render-install-manifest.sh "dist/olaitan-${VERSION}.tgz" dist/install.yaml`, "the manifest must be rendered by the release from the chart it packaged"},
		{`sha256sum ./*.tgz ./*.spdx.json ./install.yaml`, "checksums.txt must cover install.yaml"},
		{"kubectl apply -f https://github.com/${{ github.repository }}/releases/download/${{ github.ref_name }}/install.yaml", "the release notes must show the kubectl command"},
	} {
		if !strings.Contains(wf, want.text) {
			t.Errorf("release.yml lacks %q: %s", want.text, want.why)
		}
	}
	// Review F4: dist/install.yaml also appears in the render step, so a
	// plain search would pass with the release asset removed. Only the
	// `files: |` block of the step that creates the GitHub release counts.
	if !releaseAttaches(wf, "dist/install.yaml") {
		t.Errorf("the GitHub release step's `files: |` block does not list dist/install.yaml; the release must attach it (block: %q)", releaseFilesBlock(wf))
	}
	render := strings.Index(wf, "hack/render-install-manifest.sh")
	pkg := strings.Index(wf, "helm package build/chart")
	sums := strings.Index(wf, "sha256sum ./")
	if render < 0 || pkg < 0 || sums < 0 || !(pkg < render && render < sums) {
		t.Errorf("release.yml must render install.yaml after packaging the chart and before the checksums (package %d, render %d, checksums %d)", pkg, render, sums)
	}
}

// TestReadmeAppliesTheReleaseManifest (AC3): the README shows the kubectl
// command next to the helm command, at the version the helm command installs.
func TestReadmeAppliesTheReleaseManifest(t *testing.T) {
	root := filepath.Join(chartDir(t), "..", "..", "..")
	raw, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	readme := string(raw)
	want := "kubectl apply -f " + fmt.Sprintf(releaseManifestURL, chartVersion(t))
	at := strings.Index(readme, want)
	if at < 0 {
		t.Fatalf("README has no %q", want)
	}
	every := regexp.MustCompile(`kubectl apply -f https://github\.com/olokotoh/olaitan/releases/download/v([^/]+)/install\.yaml`)
	for _, m := range every.FindAllStringSubmatch(readme, -1) {
		if m[1] != chartVersion(t) {
			t.Errorf("README applies install.yaml of v%s, Chart.yaml is %s", m[1], chartVersion(t))
		}
	}
	helm := strings.Index(readme, "helm install olaitan "+publishedChartRef)
	install := strings.Index(readme, "## Install")
	if helm < 0 || install < 0 {
		t.Fatal("README has no Install section with the helm command")
	}
	// Review F5: compare before slicing; readme[helm:at] panics when the
	// kubectl command comes first.
	if at < helm {
		t.Fatalf("the kubectl command (byte %d) comes before the helm command (byte %d); it belongs under it in the Install section", at, helm)
	}
	between := readme[helm:at]
	if strings.Count(between, "\n") > 25 || strings.Contains(between, "\n## ") || strings.Contains(between, "\n### ") {
		t.Errorf("the kubectl command is not next to the helm command in the Install section (helm at byte %d, kubectl at byte %d)", helm, at)
	}
}

// releaseFilesBlock returns the entries of the `files: |` block in the step
// that uses softprops/action-gh-release, one per line, trimmed.
func releaseFilesBlock(wf string) []string {
	at := strings.Index(wf, "softprops/action-gh-release")
	if at < 0 {
		return nil
	}
	rest := wf[at:]
	f := strings.Index(rest, "files: |\n")
	if f < 0 {
		return nil
	}
	indent := f - (strings.LastIndex(rest[:f], "\n") + 1)
	var out []string
	for _, l := range strings.Split(rest[f+len("files: |\n"):], "\n") {
		if strings.TrimSpace(l) == "" || len(l)-len(strings.TrimLeft(l, " ")) <= indent {
			break
		}
		out = append(out, strings.TrimSpace(l))
	}
	return out
}

// releaseAttaches reports whether the release step's `files: |` block lists
// path as an entry of its own.
func releaseAttaches(wf, path string) bool {
	for _, e := range releaseFilesBlock(wf) {
		if e == path {
			return true
		}
	}
	return false
}

// TestReleaseFilesBlockCheckBites (review F4): with dist/install.yaml only in
// the render step and not in the release's `files: |` block, the check fails.
func TestReleaseFilesBlockCheckBites(t *testing.T) {
	render := "      - name: Render\n        run: |\n          hack/render-install-manifest.sh x dist/install.yaml\n"
	release := func(files string) string {
		return render + "      - uses: softprops/action-gh-release@v2\n        with:\n          files: |\n" + files + "          body: |\n            dist/install.yaml\n"
	}
	without := release("            dist/*.tgz\n            dist/checksums.txt\n")
	if releaseAttaches(without, "dist/install.yaml") {
		t.Errorf("a release whose files block has no dist/install.yaml was accepted: %q", releaseFilesBlock(without))
	}
	with := release("            dist/*.tgz\n            dist/install.yaml\n            dist/checksums.txt\n")
	if !releaseAttaches(with, "dist/install.yaml") {
		t.Errorf("a release whose files block lists dist/install.yaml was rejected: %q", releaseFilesBlock(with))
	}
}

// installSecretName is the Secret the install.yaml workloads read and the
// install docs tell people to create before applying it (Story 12.4, D5).
const installSecretName = "olaitan-secrets"

// generatedCredentialKeys are the keys templates/secret.yaml fills with
// randAlphaNum when no value is supplied. Under `helm template` that happens
// once per render, so in a release asset they would be one public value
// shared by every install (D5).
var generatedCredentialKeys = []string{"redis-password", "falco-http-token"}

// secretObject is the part of a Secret the credential check reads: its name
// and its key names, never the values.
type secretObject struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Data       map[string]any `yaml:"data"`
	StringData map[string]any `yaml:"stringData"`
}

// credentialSecretProblems returns every Secret in stream that holds a
// credential the chart generates at render time (D5): the chart's own
// olaitan-secrets, or any Secret with a generated key.
func credentialSecretProblems(stream string) []string {
	dec := yaml.NewDecoder(strings.NewReader(stream))
	var p []string
	for {
		var o secretObject
		err := dec.Decode(&o)
		if errors.Is(err, io.EOF) {
			return p
		}
		if err != nil {
			return append(p, "not a YAML stream: "+err.Error())
		}
		if o.Kind != "Secret" {
			continue
		}
		if o.Metadata.Name == installSecretName {
			p = append(p, fmt.Sprintf("Secret/%s ships in the file; it must be created per install (D5)", installSecretName))
		}
		for _, k := range generatedCredentialKeys {
			_, inData := o.Data[k]
			_, inStringData := o.StringData[k]
			if inData || inStringData {
				p = append(p, fmt.Sprintf("Secret/%s carries the render-time credential %q; a published file would give every install the same value", o.Metadata.Name, k))
			}
		}
	}
}

// secretKeysRead returns the keys of Secret name that stream's workloads
// read through secretKeyRef, and whether any of them mounts it as a volume.
func secretKeysRead(t *testing.T, stream, name string) (map[string]bool, bool) {
	t.Helper()
	keys := map[string]bool{}
	mounted := false
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if ref, ok := x["secretKeyRef"].(map[string]any); ok && ref["name"] == name {
				if opt, _ := ref["optional"].(bool); !opt {
					keys[fmt.Sprint(ref["key"])] = true
				}
			}
			if sec, ok := x["secret"].(map[string]any); ok && sec["secretName"] == name {
				mounted = true
			}
			for _, e := range x {
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	dec := yaml.NewDecoder(strings.NewReader(stream))
	for {
		var doc any
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return keys, mounted
		}
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		walk(doc)
	}
}

// TestInstallManifestHoldsNoCredentials (AC1 as amended 2026-09-24, D5): the
// release asset is public, so it must carry no Secret with a credential the
// chart generates at render time. The workloads still read that Secret; the
// install docs create it per install.
func TestInstallManifestHoldsNoCredentials(t *testing.T) {
	manifest := renderInstallManifest(t, stageReleaseChart(t, "9.9.9-rc1", "ghcr.io/example/olaitan",
		"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"))
	for _, p := range credentialSecretProblems(manifest) {
		t.Error(p)
	}
	keys, mounted := secretKeysRead(t, manifest, installSecretName)
	for _, k := range generatedCredentialKeys {
		if !keys[k] {
			t.Errorf("no workload in install.yaml reads %s key %q; the credential check no longer matches the chart", installSecretName, k)
		}
	}
	if !mounted {
		t.Errorf("no workload mounts Secret %s; the docs' create step would be pointless", installSecretName)
	}
}

// TestInstallManifestCredentialCheckBites: the checker rejects the chart's
// Secret and any Secret with a generated key, and accepts the NATS nats-box
// contexts Secret (a server URL, no credential).
func TestInstallManifestCredentialCheckBites(t *testing.T) {
	for name, doc := range map[string]string{
		"the chart Secret":             "apiVersion: v1\nkind: Secret\nmetadata:\n  name: olaitan-secrets\nstringData:\n  nats-creds: \"\"\n",
		"a renamed Secret, stringData": "apiVersion: v1\nkind: Secret\nmetadata:\n  name: other\nstringData:\n  redis-password: x\n",
		"a renamed Secret, data":       "apiVersion: v1\nkind: Secret\nmetadata:\n  name: other\ndata:\n  falco-http-token: eA==\n",
	} {
		if len(credentialSecretProblems(doc)) == 0 {
			t.Errorf("%s was accepted", name)
		}
	}
	natsBox := "apiVersion: v1\nkind: Secret\nmetadata:\n  name: olaitan-nats-box-contexts\nstringData:\n  default.json: '{\"url\": \"nats://olaitan-nats\"}'\n"
	if p := credentialSecretProblems(natsBox); len(p) != 0 {
		t.Errorf("the nats-box contexts Secret was rejected: %v", p)
	}
	// The chart as it renders today (the Secret included) is what the
	// script must strip.
	if len(credentialSecretProblems(renderChartAt(t, chartDir(t), "--namespace", installNamespace))) == 0 {
		t.Error("a plain helm template of the chart passed the credential check; the check no longer sees the chart Secret")
	}
}

// createSecretCommand returns the `kubectl create secret generic
// olaitan-secrets` command in text, backslash continuations included, and
// the keys it sets with --from-literal.
func createSecretCommand(text string) (string, map[string]string) {
	at := strings.Index(text, "kubectl create secret generic "+installSecretName)
	if at < 0 {
		return "", nil
	}
	var lines []string
	for _, l := range strings.Split(text[at:], "\n") {
		lines = append(lines, l)
		if !strings.HasSuffix(strings.TrimSpace(l), `\`) {
			break
		}
	}
	cmd := strings.Join(lines, "\n")
	keys := map[string]string{}
	for _, m := range regexp.MustCompile(`--from-literal=([A-Za-z0-9._-]+)=(\S*)`).FindAllStringSubmatch(cmd, -1) {
		keys[m[1]] = strings.TrimSuffix(m[2], `\`)
	}
	return cmd, keys
}

// installDocs returns the three places that tell people how to install
// from install.yaml: the README, the release notes in release.yml and the
// header of the rendered file itself.
func installDocs(t *testing.T, manifest string) map[string]string {
	t.Helper()
	root := filepath.Join(chartDir(t), "..", "..", "..")
	docs := map[string]string{"install.yaml header": strings.SplitN(manifest, "\n---", 2)[0]}
	for name, rel := range map[string]string{"README.md": "README.md", "release.yml": filepath.Join(".github", "workflows", "release.yml")} {
		raw, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		docs[name] = string(raw)
	}
	return docs
}

// TestInstallDocsCreateTheSecretTheManifestReads (AC1 as amended, AC3, D5):
// the README, the release notes and the file's header each give the same
// two-step install: create the namespace and olaitan-secrets with exactly
// the keys install.yaml's workloads read (each generated credential a fresh
// random value), then apply the file.
func TestInstallDocsCreateTheSecretTheManifestReads(t *testing.T) {
	manifest := renderInstallManifest(t, chartDir(t))
	want, _ := secretKeysRead(t, manifest, installSecretName)
	if len(want) == 0 {
		t.Fatalf("install.yaml reads no key of %s", installSecretName)
	}
	for name, doc := range installDocs(t, manifest) {
		cmd, keys := createSecretCommand(doc)
		if cmd == "" {
			t.Errorf("%s has no `kubectl create secret generic %s`", name, installSecretName)
			continue
		}
		if !strings.Contains(cmd, "-n "+installNamespace+" ") && !strings.Contains(cmd, "--namespace "+installNamespace+" ") {
			t.Errorf("%s: the secret command does not name namespace %s:\n%s", name, installNamespace, cmd)
		}
		for k := range want {
			if _, ok := keys[k]; !ok {
				t.Errorf("%s: the secret command does not set key %q, which install.yaml reads", name, k)
			}
		}
		for k := range keys {
			if !want[k] {
				t.Errorf("%s: the secret command sets key %q, which nothing in install.yaml reads", name, k)
			}
		}
		for _, k := range generatedCredentialKeys {
			if v := keys[k]; v != `"$(openssl rand -hex 32)"` {
				t.Errorf("%s: key %q is set to %q, want a fresh \"$(openssl rand -hex 32)\"", name, k, v)
			}
		}
		ns := strings.Index(doc, "kubectl create namespace "+installNamespace+" --save-config")
		sec := strings.Index(doc, cmd)
		apply := strings.Index(doc[sec:], "kubectl apply -f ")
		if ns < 0 || ns > sec || apply < 0 {
			t.Errorf("%s: want `kubectl create namespace %s --save-config`, then the secret command, then `kubectl apply -f` (namespace %d, secret %d, apply after secret %d)", name, installNamespace, ns, sec, apply)
		}
	}
}

// TestInstallDocsCoverUpgradeRotationAndAPIServer (review round 1, F1 F2 F3
// F6 F7 F8): what install.yaml cannot do for you is written down where
// people read it.
func TestInstallDocsCoverUpgradeRotationAndAPIServer(t *testing.T) {
	const (
		restart = "kubectl -n olaitan rollout restart daemonset,deployment,statefulset"
		slice   = "kubectl get endpointslice -n default kubernetes"
		patch   = "kubectl -n olaitan patch networkpolicy olaitan --type=json"
	)
	apiServer := []string{"10.96.0.1", "10.43.0.1", "k3s", "minikube", "8443", "Calico", "Cilium", slice, patch}
	docs := installDocs(t, renderInstallManifest(t, chartDir(t)))
	want := map[string][]string{
		"README.md":           append([]string{restart, "values-openshift.yaml", "OpenShift", "kubectl replace -f -"}, apiServer...),
		"release.yml":         append([]string{restart}, apiServer...),
		"install.yaml header": apiServer,
	}
	for name, phrases := range want {
		for _, w := range phrases {
			if !strings.Contains(docs[name], w) {
				t.Errorf("%s does not say %q", name, w)
			}
		}
	}
	if strings.Contains(docs["README.md"], "Before merge, the file was rendered") {
		t.Error("README still carries the pre-merge evidence paragraph (review F6); it belongs in the PR and traceability")
	}
	body := docs["release.yml"][strings.Index(docs["release.yml"], "softprops/action-gh-release"):]
	helm := strings.Index(body, "helm install olaitan ")
	if helm < 0 || !strings.Contains(body[helm:helm+300], "--namespace olaitan --create-namespace") {
		t.Error("the release notes' helm command does not install into --namespace olaitan --create-namespace (review F8)")
	}
}
