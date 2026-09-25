package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Story 11.2a AC5: the CI grep guard against synthetic attack-event injection.
//
// The hard rule is that no scenario or test may publish fabricated events to
// NATS as a stand-in for a real attack (attacks run for real inside pods, via
// cmd/olaitan-eval/attack.go). This guard scans tests/e2e for the two shapes
// of synthetic attack injection and fails on any file that is not documented
// in the allow-list with a reason. It runs in the ordinary `go test ./...` CI
// job (no build tag), so a reintroduced synthetic attack publish fails CI.
//
// The guard is deliberately narrow: it flags synthetic ATTACK-event publishing
// (a raw.falco / raw.network publish, or use of the evalscenario.Events /
// evalscenario.StagedEvents attack-recipe generators). It does NOT flag
// legitimate NATS use: the production capturer draining the real bus
// (internal/eval/capture), the capturer integration test, benign-traffic
// generation, baseline-priming EvidencePackage preseeds, or metrics-sink
// publishes are all a real system using its real bus, not an attack stand-in.

// syntheticInjectionPatterns match a synthetic attack-event publication. A
// raw.falco / raw.network publish is a fabricated sensor event; the
// evalscenario attack-recipe generators exist only to build such events.
var syntheticInjectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`evalscenario\.(Events|StagedEvents)\(`),
	regexp.MustCompile(`(publishJS|PublishJS|\.Publish)\([^\n]*(RawFalcoSubject|RawNetworkSubject)`),
	regexp.MustCompile(`(publishJS|PublishJS|\.Publish)\([^\n]*"olaitan\.events\.raw\.(falco|network)"`),
}

type injectionHit struct {
	file string // basename
	line int
	text string
}

// scanSyntheticInjection walks dir for *.go files and returns every line that
// matches a synthetic-injection pattern, skipping // comment lines and the
// guard's own source so the guard does not flag its own pattern literals.
func scanSyntheticInjection(dir string) ([]injectionHit, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var hits []injectionHit
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		if e.Name() == "nats_injection_guard_test.go" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		for i, line := range strings.Split(string(raw), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
				continue
			}
			for _, re := range syntheticInjectionPatterns {
				if re.MatchString(line) {
					hits = append(hits, injectionHit{file: e.Name(), line: i + 1, text: trimmed})
					break
				}
			}
		}
	}
	return hits, nil
}

type injectionAllowlist struct {
	Allow []struct {
		Path   string `yaml:"path"`
		Reason string `yaml:"reason"`
	} `yaml:"allow"`
}

func loadInjectionAllowlist(t *testing.T, path string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read allow-list %q: %v", path, err)
	}
	var al injectionAllowlist
	if err := yaml.Unmarshal(raw, &al); err != nil {
		t.Fatalf("parse allow-list %q: %v", path, err)
	}
	out := make(map[string]string, len(al.Allow))
	for _, e := range al.Allow {
		if strings.TrimSpace(e.Path) == "" {
			t.Errorf("allow-list entry with empty path")
			continue
		}
		if strings.TrimSpace(e.Reason) == "" {
			t.Errorf("allow-list entry %q has no reason (a reason is required per entry)", e.Path)
		}
		out[e.Path] = e.Reason
	}
	return out
}

// TestNoSyntheticNATSInjection is the AC5 guard: every synthetic attack-event
// publish in tests/e2e must be documented in the allow-list with a reason, and
// no allow-list entry may be stale (listed but no longer injecting), so
// removing a file's injection forces removing its exemption.
func TestNoSyntheticNATSInjection(t *testing.T) {
	e2eDir := filepath.Join("..", "..", "tests", "e2e")
	allow := loadInjectionAllowlist(t, filepath.Join(e2eDir, "nats-injection-allowlist.yaml"))

	hits, err := scanSyntheticInjection(e2eDir)
	if err != nil {
		t.Fatalf("scan %q: %v", e2eDir, err)
	}

	matchedFiles := map[string]bool{}
	for _, h := range hits {
		matchedFiles[h.file] = true
		if _, ok := allow[h.file]; !ok {
			t.Errorf("synthetic attack-event injection not on the allow-list: %s:%d\n  %s\n  (drive the real attack via cmd/olaitan-eval/attack.go, or add %s to tests/e2e/nats-injection-allowlist.yaml with a reason)", h.file, h.line, h.text, h.file)
		}
	}

	// Stale-exemption check: an allow-listed file that no longer injects must
	// be removed from the allow-list so the guard locks it clean.
	var stale []string
	for path := range allow {
		if !matchedFiles[path] {
			stale = append(stale, path)
		}
	}
	sort.Strings(stale)
	for _, path := range stale {
		t.Errorf("stale allow-list entry %q: it no longer contains synthetic injection; remove it from tests/e2e/nats-injection-allowlist.yaml so the guard locks the file clean", path)
	}
}

// TestSyntheticInjectionGuardBites proves the scanner actually detects a
// synthetic publish (a green suite is not a blind check): a fixture file with
// a raw.falco publish and one with an evalscenario.Events call are both
// flagged, while a clean file and a commented-out publish are not.
func TestSyntheticInjectionGuardBites(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatalf("write fixture %q: %v", name, err)
		}
	}
	write("raw_publish_test.go", "package x\nfunc f(){ publishJS(t, js, \"olaitan.events.raw.falco\", p) }\n")
	write("recipe_test.go", "package x\nfunc g(){ events := evalscenario.Events(id, pod, ts); _ = events }\n")
	write("clean_test.go", "package x\nfunc h(){ println(\"no injection here\") }\n")
	write("commented_test.go", "package x\n// publishJS(t, js, \"olaitan.events.raw.network\", p) is described, not run\nfunc i(){}\n")

	hits, err := scanSyntheticInjection(dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	flagged := map[string]bool{}
	for _, h := range hits {
		flagged[h.file] = true
	}
	if !flagged["raw_publish_test.go"] {
		t.Errorf("guard did not flag a raw.falco publish")
	}
	if !flagged["recipe_test.go"] {
		t.Errorf("guard did not flag an evalscenario.Events attack-recipe call")
	}
	if flagged["clean_test.go"] {
		t.Errorf("guard falsely flagged a clean file")
	}
	if flagged["commented_test.go"] {
		t.Errorf("guard falsely flagged a commented-out publish")
	}
}
