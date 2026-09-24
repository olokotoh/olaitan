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
		"Secret/olaitan-secrets",
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
		{"dist/install.yaml\n", "the GitHub release must attach install.yaml"},
		{"kubectl apply -f https://github.com/${{ github.repository }}/releases/download/${{ github.ref_name }}/install.yaml", "the release notes must show the kubectl command"},
	} {
		if !strings.Contains(wf, want.text) {
			t.Errorf("release.yml lacks %q: %s", want.text, want.why)
		}
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
	between := readme[helm:at]
	if at < helm || strings.Count(between, "\n") > 25 || strings.Contains(between, "\n## ") || strings.Contains(between, "\n### ") {
		t.Errorf("the kubectl command is not next to the helm command in the Install section (helm at byte %d, kubectl at byte %d)", helm, at)
	}
}
