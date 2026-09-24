//go:build helm

package helm_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Story 12.6: every image the chart deploys is pinned by tag AND digest.
//
// A tag alone is only hygiene: anyone who can push to the upstream
// repository can point it at other content, and Bitnami has already
// withdrawn every versioned free Redis tag once. The digest is what makes
// the install reproducible; the tag is kept beside it so a human reading
// the manifest knows what the digest is meant to be.
//
// This file IS the CI guard: the helm job runs `go test ./deploy/helm/...
// -tags=helm`, and the release workflow runs TestEveryRenderedImageIsPinned
// again against the staged chart after it stamps the Olaitan image digest
// (OLT_PIN_CHART_DIR), so neither a tree change nor a release can ship an
// unpinned image.

// ownImageRepo is the Olaitan image. It is the one image the tree cannot
// pin: the digest of an unreleased commit does not exist yet, and every
// local e2e flow runs a locally built image with pullPolicy Never, which
// has no registry digest to match. The release writes image.digest into
// the packaged chart (Story 12.6 D1).
const ownImageRepo = "ghcr.io/olokotoh/olaitan"

// pinnedImageRE is name:tag@sha256:<64 hex>. The name part follows the
// distribution reference grammar (optional registry host with port, then
// lowercase path components); the tag grammar is [\w][\w.-]{0,127}.
var pinnedImageRE = regexp.MustCompile(
	`^(?P<name>(?:[a-zA-Z0-9.-]+(?::[0-9]+)?/)?[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*)` +
		`:(?P<tag>[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})` +
		`@sha256:[a-f0-9]{64}$`)

// imagePinProblem returns "" for a pinned reference and a reason otherwise.
func imagePinProblem(ref string) string {
	name, digest, hasDigest := strings.Cut(ref, "@")
	// The tag is whatever follows the last ':' after the last '/', so a
	// registry port (host:5000/repo) is not mistaken for a tag.
	tag := ""
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		tag = name[i+1:]
	}
	switch {
	case ref == "":
		return "empty image reference"
	case tag == "" && !hasDigest:
		return "untagged (resolves to :latest)"
	case tag == "":
		return "digest without a tag (nobody can tell what the digest is meant to be)"
	case tag == "latest":
		return ":latest is not a version"
	case !hasDigest:
		return "tag without a digest (a tag can be re-pushed)"
	case !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(digest):
		return "malformed digest (want sha256:<64 lowercase hex>)"
	case !pinnedImageRE.MatchString(ref):
		return "not a valid name:tag@sha256 reference"
	}
	return ""
}

// TestImagePinClassifier proves the guard itself fails on every bad shape,
// so a green run means the images are pinned, not that the check is blind.
func TestImagePinClassifier(t *testing.T) {
	const d = "sha256:1cfc36e2e5e638243d8c722f72c954cd0ec4b15ee82fadbc718ce12e2b3c1652"
	good := []string{
		"nats:2.12.6-alpine@" + d,
		"docker.io/falcosecurity/falco:0.45.0-rc1@" + d,
		"registry.local:5000/team/redis:8.10.2-alpine@" + d,
		"ghcr.io/olokotoh/olaitan:v1.0.0-rc4@" + d,
	}
	bad := map[string]string{
		"nats":                           "untagged",
		"registry.local:5000/team/redis": "untagged",
		"nats:latest":                    ":latest",
		"nats:latest@" + d:               ":latest",
		"registry-1.docker.io/bitnami/redis:latest":    ":latest",
		"nats:2.12.6-alpine":                           "tag without a digest",
		"registry.local:5000/team/redis:8.10.2":        "tag without a digest",
		"nats@" + d:                                    "digest without a tag",
		"nats:2.12.6@sha256:abc":                       "malformed digest",
		"nats:2.12.6@sha256:" + strings.ToUpper(d[7:]): "malformed digest",
		"NATS:2.12.6@" + d:                             "not a valid",
		"":                                             "empty",
	}
	for _, ref := range good {
		if p := imagePinProblem(ref); p != "" {
			t.Errorf("imagePinProblem(%q) = %q, want pinned", ref, p)
		}
	}
	for ref, want := range bad {
		if p := imagePinProblem(ref); !strings.Contains(p, want) {
			t.Errorf("imagePinProblem(%q) = %q, want a problem containing %q", ref, p, want)
		}
	}
}

// renderedImage is one image reference and where it was found.
type renderedImage struct {
	ref   string
	where string
}

// collectImages returns every container image in a rendered stream: any
// `image:` string at any depth (Pods, Deployments, DaemonSets,
// StatefulSets, Jobs, helm test Pods, init and ephemeral containers alike)
// plus every env value whose name ends in _IMAGE, which is how the applog
// webhook learns the sidecar image it injects into other pods.
func collectImages(t *testing.T, rendered string) []renderedImage {
	t.Helper()
	var out []renderedImage
	dec := yaml.NewDecoder(strings.NewReader(rendered))
	for {
		var doc map[string]any
		if err := dec.Decode(&doc); err != nil {
			break
		}
		if doc == nil {
			continue
		}
		name, _ := dig(doc, "metadata", "name").(string)
		kind, _ := doc["kind"].(string)
		var walk func(v any, path string)
		walk = func(v any, path string) {
			switch x := v.(type) {
			case map[string]any:
				if s, ok := x["image"].(string); ok {
					out = append(out, renderedImage{s, fmt.Sprintf("%s/%s %s", kind, name, path)})
				}
				if n, ok := x["name"].(string); ok && strings.HasSuffix(n, "_IMAGE") {
					if s, ok := x["value"].(string); ok {
						out = append(out, renderedImage{s, fmt.Sprintf("%s/%s %s env %s", kind, name, path, n)})
					}
				}
				keys := make([]string, 0, len(x))
				for k := range x {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					walk(x[k], path+"."+k)
				}
			case []any:
				for i, e := range x {
					walk(e, fmt.Sprintf("%s[%d]", path, i))
				}
			}
		}
		walk(doc, "")
	}
	return out
}

// renderChartAt renders the chart in dir the way the suite's helpers do
// (a dummy Redis password, then the given args).
func renderChartAt(t *testing.T, dir string, args ...string) string {
	t.Helper()
	full := append([]string{"template", "olaitan", dir, "--set", "secrets.redisPassword=test-password"}, args...)
	cmd := exec.Command("helm", full...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("helm %v failed: %v\nstderr:\n%s", full, err, stderr.String())
	}
	return stdout.String()
}

// pinRenders is every render the guard checks: the default, the full
// profile (with the test stub for its per-install key material), the full
// profile under each hosted-LLM overlay, every committed standalone
// overlay, and the Falco kmod fallback (the only way the driver-loader
// image is rendered).
func pinRenders(t *testing.T, dir string, extra ...string) map[string]string {
	t.Helper()
	stub := filepath.Join(filepath.Dir(chartDir(t)), "testdata", "full-profile", "stub-key-material.yaml")
	with := func(args ...string) []string { return append(append([]string{}, extra...), args...) }
	full := []string{"--values", filepath.Join(dir, "values-full.yaml"), "--values", stub}

	out := map[string]string{
		"default":    renderChartAt(t, dir, with()...),
		"full":       renderChartAt(t, dir, with(full...)...),
		"falco-kmod": renderChartAt(t, dir, with("--set", "falco.driver.kind=kmod")...),
	}
	overlays, err := filepath.Glob(filepath.Join(dir, "values-*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range overlays {
		base := strings.TrimSuffix(filepath.Base(o), ".yaml")
		switch {
		case base == "values-full":
			// rendered above
		case strings.HasPrefix(base, "values-llm-"):
			// Hosted-model overlays are layered on the full profile.
			out["full+"+base] = renderChartAt(t, dir, with(append(full, "--values", o)...)...)
		default:
			out[base] = renderChartAt(t, dir, with("--values", o)...)
		}
	}
	return out
}

// TestEveryRenderedImageIsPinned is the Story 12.6 guard (AC1, AC2).
//
// In the tree, every third-party image must be name:tag@sha256 and the
// Olaitan image must be exactly repository:tag (the release adds the
// digest). With OLT_PIN_CHART_DIR set (the release workflow, pointing at
// the stamped staging chart) the Olaitan image must be pinned as well.
func TestEveryRenderedImageIsPinned(t *testing.T) {
	dir := chartDir(t)
	release := os.Getenv("OLT_PIN_CHART_DIR")
	if release != "" {
		dir = release
	}
	renders := pinRenders(t, dir)
	names := make([]string, 0, len(renders))
	for n := range renders {
		names = append(names, n)
	}
	sort.Strings(names)

	ownTagOnly := regexp.MustCompile(`^` + regexp.QuoteMeta(ownImageRepo) + `:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	seen := map[string]bool{}
	for _, name := range names {
		imgs := collectImages(t, renders[name])
		if len(imgs) == 0 {
			t.Errorf("%s: no images found; the walker is broken", name)
		}
		for _, img := range imgs {
			seen[img.ref] = true
			own := strings.HasPrefix(img.ref, ownImageRepo+":") || strings.HasPrefix(img.ref, ownImageRepo+"@") || img.ref == ownImageRepo
			if own && release == "" {
				if !ownTagOnly.MatchString(img.ref) {
					t.Errorf("%s: %s: Olaitan image %q, want %s:<tag> in the tree (the release stamps the digest)", name, img.where, img.ref, ownImageRepo)
				}
				continue
			}
			if p := imagePinProblem(img.ref); p != "" {
				t.Errorf("%s: %s: %q: %s", name, img.where, img.ref, p)
			}
		}
	}

	// The inventory this story pinned. If a subchart bump or a new
	// component adds an image, it shows up here as well as in the checks
	// above, so the reviewer sees the list change.
	var refs []string
	for r := range seen {
		refs = append(refs, r)
	}
	sort.Strings(refs)
	t.Logf("images across %d renders:\n  %s", len(renders), strings.Join(refs, "\n  "))
	for _, want := range []string{
		"docker.io/falcosecurity/falco:",
		"docker.io/falcosecurity/falcoctl:",
		"docker.io/falcosecurity/falco-driver-loader:",
		"docker.io/library/nats:",
		"docker.io/natsio/nats-server-config-reloader:",
		"docker.io/natsio/nats-box:",
		"docker.io/library/redis:",
		"ollama/ollama:",
		ownImageRepo + ":",
	} {
		found := false
		for _, r := range refs {
			// A release stamps the repository it pushed to (a fork pushes to
			// its own owner), so there the Olaitan image is any */olaitan.
			if strings.HasPrefix(r, want) || (release != "" && want == ownImageRepo+":" && strings.Contains(r, "/olaitan:")) {
				found = true
			}
		}
		if !found {
			t.Errorf("no rendered image starts with %q; the inventory changed, update this list on purpose", want)
		}
	}
}

// TestOlaitanImageDigest (AC3): with image.digest set, which is what the
// release writes into the packaged chart, every place the Olaitan image
// appears carries it, including the sidecar image the applog webhook
// injects into other pods. A malformed digest fails the render instead of
// shipping an unpullable reference.
func TestOlaitanImageDigest(t *testing.T) {
	const d = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	want := ownImageRepo + ":edge@" + d
	for name, rendered := range map[string]string{
		"default": helmTemplate(t, []string{"image.digest=" + d}),
		"full":    renderFullProfile(t, writeValues(t, "image:\n  digest: "+d+"\n")),
	} {
		n := 0
		for _, img := range collectImages(t, rendered) {
			if !strings.HasPrefix(img.ref, ownImageRepo) {
				continue
			}
			n++
			if img.ref != want {
				t.Errorf("%s: %s = %q, want %q", name, img.where, img.ref, want)
			}
		}
		if n == 0 {
			t.Errorf("%s: no Olaitan image rendered", name)
		}
	}

	// A tag override keeps the digest beside it; the doc says to change both.
	got := helmTemplate(t, []string{"image.tag=v9.9.9", "image.digest=" + d})
	if !strings.Contains(got, "image: "+ownImageRepo+":v9.9.9@"+d) {
		t.Errorf("image.tag + image.digest do not render repository:tag@digest")
	}

	// The tree default and the local e2e shape (tag set, digest empty) stay
	// repository:tag, so pullPolicy Never still matches a kind-loaded image.
	got = helmTemplate(t, []string{"image.repository=olaitan", "image.tag=dev", "image.pullPolicy=Never"})
	if !strings.Contains(got, "image: olaitan:dev\n") || strings.Contains(got, "olaitan:dev@") {
		t.Errorf("local e2e shape does not render the plain olaitan:dev reference")
	}

	args := []string{"template", "olaitan", chartDir(t), "--set", "secrets.redisPassword=x", "--set", "image.digest=sha256:abc"}
	cmd := exec.Command("helm", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil || !strings.Contains(stderr.String(), "image.digest must be sha256:<64 lowercase hex>") {
		t.Errorf("malformed image.digest rendered (err=%v), want a fail-fast; stderr:\n%s", err, stderr.String())
	}
}

// writeValues writes a throwaway values file and returns its path.
func writeValues(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
