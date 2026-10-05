package main

import (
	"io/fs"
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
// internal/eval/attack/attack.go). This guard scans tests/e2e for the two shapes
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
//
// Review round 3 (C9): the publish pattern is dot-all and tolerates a bounded
// argument span, so a call split across lines (the method on one line, the
// subject on another) is still caught; and it covers every NATS publish /
// request shape (Publish, PublishMsg, PublishAsync, PublishMsgAsync, Request,
// and the helper publishJS/PublishJS), longest method first so a prefix does
// not shadow a longer one.
var syntheticInjectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`evalscenario\.(?:Events|StagedEvents)\(`),
	regexp.MustCompile(`(?s)(?:publishJS|PublishJS|\.PublishMsgAsync|\.PublishAsync|\.PublishMsg|\.Publish|\.Request)\((?:[^()]|\([^()]*\)){0,400}?(?:RawFalcoSubject|RawNetworkSubject|"olaitan\.events\.raw\.(?:falco|network)")`),
}

type injectionHit struct {
	file string // path relative to the scanned root
	line int
	text string
}

// scanSyntheticInjection walks root RECURSIVELY for *.go files and returns every
// synthetic-injection match, skipping // comment lines and the guard's own
// source so the guard does not flag its own pattern literals. Matches may span
// lines (a publish whose subject is on a later line); the reported line is the
// match start and the text is its first line.
func scanSyntheticInjection(root string) ([]injectionHit, error) {
	var hits []injectionHit
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		if d.Name() == "nats_injection_guard_test.go" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = d.Name()
		}
		hits = append(hits, scanGoSource(filepath.ToSlash(rel), raw)...)
		return nil
	})
	return hits, err
}

// scanGoSource blanks full-line comments (keeping line numbers), then matches
// the synthetic-injection patterns across the file so a multi-line publish is
// caught. Hits are deduplicated by start line so overlapping patterns do not
// double-report one call.
func scanGoSource(name string, raw []byte) []injectionHit {
	lines := strings.Split(string(raw), "\n")
	san := make([]string, len(lines))
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "*") {
			san[i] = "" // drop commented-out publishes, keep the line slot
		} else {
			san[i] = line
		}
	}
	content := strings.Join(san, "\n")
	seen := map[int]bool{}
	var hits []injectionHit
	for _, re := range syntheticInjectionPatterns {
		for _, m := range re.FindAllStringIndex(content, -1) {
			line := strings.Count(content[:m[0]], "\n") + 1
			if seen[line] {
				continue
			}
			seen[line] = true
			first := content[m[0]:m[1]]
			if nl := strings.IndexByte(first, '\n'); nl >= 0 {
				first = first[:nl]
			}
			hits = append(hits, injectionHit{file: name, line: line, text: strings.TrimSpace(first)})
		}
	}
	return hits
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
			t.Errorf("synthetic attack-event injection not on the allow-list: %s:%d\n  %s\n  (drive the real attack via internal/eval/attack/attack.go, or add %s to tests/e2e/nats-injection-allowlist.yaml with a reason)", h.file, h.line, h.text, h.file)
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
	// Review round 3 (C9): a call split across lines, each alternative publish /
	// request shape, and a file in a subdirectory (recursive walk).
	write("multiline_test.go", "package x\nfunc m(){ js.Publish(\n\tRawFalcoSubject,\n\tpayload,\n) }\n")
	write("publishmsg_test.go", "package x\nfunc pm(){ js.PublishMsg(&nats.Msg{Subject: RawNetworkSubject}) }\n")
	write("publishasync_test.go", "package x\nfunc pa(){ js.PublishAsync(\"olaitan.events.raw.falco\", p) }\n")
	write("publishmsgasync_test.go", "package x\nfunc pma(){ js.PublishMsgAsync(&nats.Msg{Subject: RawFalcoSubject}) }\n")
	write("request_test.go", "package x\nfunc rq(){ nc.Request(RawNetworkSubject, p, d) }\n")
	sub := filepath.Join(dir, "nested")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sub, "deep_test.go"), []byte("package y\nfunc d(){ publishJS(t, js, \"olaitan.events.raw.network\", p) }\n"), 0o644); err != nil {
		t.Fatalf("write nested fixture: %v", err)
	}

	hits, err := scanSyntheticInjection(dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	flagged := map[string]bool{}
	for _, h := range hits {
		flagged[h.file] = true
	}
	for _, want := range []string{
		"raw_publish_test.go",
		"recipe_test.go",
		"multiline_test.go",
		"publishmsg_test.go",
		"publishasync_test.go",
		"publishmsgasync_test.go",
		"request_test.go",
		"nested/deep_test.go", // recursive walk
	} {
		if !flagged[want] {
			t.Errorf("guard did not flag %s", want)
		}
	}
	if flagged["clean_test.go"] {
		t.Errorf("guard falsely flagged a clean file")
	}
	if flagged["commented_test.go"] {
		t.Errorf("guard falsely flagged a commented-out publish")
	}
}
