package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// validManifestYAML is a minimal but VALID reproducibility envelope used
// by the happy-path and field-by-field fail-fast tests. It mirrors the
// committed eval/manifest.yaml shape with the eight NFR37 fields.
const validManifestYAML = `images:
  aggregator: ghcr.io/olokotoh/olaitan@sha256:2158bb18545621bc64d93dbeb1999a123bfdce638ea3e50c7fad60c00b711227
kubernetes_patch_version: 1.29.x
falco_rule_corpus_tag: falco-chart-8.0.2
sigma_corpus_git_sha: c7f7ff1f84cdfc41f725bede05eb230abfa2aba3
llm_model_version: claude-opus-4-8
random_seed: 0
sysctl_snapshot:
  kernel.unprivileged_bpf_disabled: "1"
cluster_bootstrap_script_git_sha: 89dde84be474c1b801c6c0cea8c3543f37a23332
`

// writeManifest writes content to a temp manifest file and returns its
// path.
func writeManifest(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write temp manifest: %v", err)
	}
	return path
}

func TestLoadManifest_HappyPath(t *testing.T) {
	path := writeManifest(t, validManifestYAML)
	m, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest: unexpected error: %v", err)
	}
	if got := m.Images["aggregator"]; !strings.HasPrefix(got, "ghcr.io/olokotoh/olaitan@sha256:") {
		t.Errorf("Images[aggregator] = %q; want digest-pinned reference", got)
	}
	if m.KubernetesPatchVersion != "1.29.x" {
		t.Errorf("KubernetesPatchVersion = %q; want 1.29.x", m.KubernetesPatchVersion)
	}
	if m.LLMModelVersion != "claude-opus-4-8" {
		t.Errorf("LLMModelVersion = %q; want claude-opus-4-8 (BI-3)", m.LLMModelVersion)
	}
	if m.RandomSeed == nil || *m.RandomSeed != 0 {
		t.Errorf("RandomSeed = %v; want pinned 0", m.RandomSeed)
	}
	if m.SigmaCorpusGitSHA == "" || m.FalcoRuleCorpusTag == "" || m.ClusterBootstrapScriptGitSHA == "" {
		t.Errorf("corpus/bootstrap pins must be populated")
	}
	if len(m.SysctlSnapshot) == 0 {
		t.Errorf("SysctlSnapshot must be populated")
	}
}

// TestLoadManifest_FailFast_EachField removes (or breaks) each required
// field in turn and asserts Validate fails with a field-named error (BI-4,
// the internal/config fail-fast precedent).
func TestLoadManifest_FailFast_EachField(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(string) string
		wantSub string
	}{
		{
			name:    "missing images",
			mutate:  func(s string) string { return stripBlock(s, "images:") },
			wantSub: "images",
		},
		{
			name:    "empty image digest",
			mutate:  func(s string) string { return replaceLine(s, "  aggregator:", "  aggregator: \"\"") },
			wantSub: "images.aggregator",
		},
		{
			name: "non-digest image reference",
			mutate: func(s string) string {
				return replaceLine(s, "  aggregator:", "  aggregator: ghcr.io/olokotoh/olaitan:latest")
			},
			wantSub: "digest-pinned",
		},
		{
			name:    "missing kubernetes_patch_version",
			mutate:  func(s string) string { return stripLine(s, "kubernetes_patch_version:") },
			wantSub: "kubernetes_patch_version",
		},
		{
			name: "unparseable kubernetes_patch_version",
			mutate: func(s string) string {
				return replaceLine(s, "kubernetes_patch_version:", "kubernetes_patch_version: not-a-version")
			},
			wantSub: "kubernetes_patch_version",
		},
		{
			name:    "missing falco_rule_corpus_tag",
			mutate:  func(s string) string { return stripLine(s, "falco_rule_corpus_tag:") },
			wantSub: "falco_rule_corpus_tag",
		},
		{
			name:    "missing sigma_corpus_git_sha",
			mutate:  func(s string) string { return stripLine(s, "sigma_corpus_git_sha:") },
			wantSub: "sigma_corpus_git_sha",
		},
		{
			name:    "missing llm_model_version",
			mutate:  func(s string) string { return stripLine(s, "llm_model_version:") },
			wantSub: "llm_model_version",
		},
		{
			name:    "missing random_seed",
			mutate:  func(s string) string { return stripLine(s, "random_seed:") },
			wantSub: "random_seed",
		},
		{
			name:    "missing sysctl_snapshot",
			mutate:  func(s string) string { return stripBlock(s, "sysctl_snapshot:") },
			wantSub: "sysctl_snapshot",
		},
		{
			name:    "missing cluster_bootstrap_script_git_sha",
			mutate:  func(s string) string { return stripLine(s, "cluster_bootstrap_script_git_sha:") },
			wantSub: "cluster_bootstrap_script_git_sha",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeManifest(t, tc.mutate(validManifestYAML))
			_, err := LoadManifest(path)
			if err == nil {
				t.Fatalf("LoadManifest: expected error for %s, got nil", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q does not name the field %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestLoadManifest_UnknownField_FailsFast(t *testing.T) {
	path := writeManifest(t, validManifestYAML+"bogus_typo_key: 1\n")
	if _, err := LoadManifest(path); err == nil {
		t.Fatalf("expected an error on an unknown manifest key, got nil")
	}
}

func TestLoadManifest_MissingFile(t *testing.T) {
	if _, err := LoadManifest(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatalf("expected an error for a missing manifest file, got nil")
	}
}

// TestManifest_SHA256_OverFileBytes asserts SHA256() hashes the exact
// committed file bytes (BI-5), so it equals sha256sum of the file.
func TestManifest_SHA256_OverFileBytes(t *testing.T) {
	content := validManifestYAML
	path := writeManifest(t, content)
	m, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	want := sha256.Sum256([]byte(content))
	if got := m.SHA256(); got != hex.EncodeToString(want[:]) {
		t.Errorf("SHA256() = %s; want %s (the file-bytes hash, BI-5)", got, hex.EncodeToString(want[:]))
	}
}

// TestManifest_SHA256_MatchesCommittedFixture pins SHA256() of the
// committed eval/manifest.yaml fixture == sha256sum of that file (BI-5).
// This proves a reader re-derives the hash with `sha256sum
// eval/manifest.yaml`.
func TestManifest_SHA256_MatchesCommittedFixture(t *testing.T) {
	path := committedManifestPath(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read committed manifest: %v", err)
	}
	m, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest(committed): %v", err)
	}
	want := sha256.Sum256(raw)
	if got := m.SHA256(); got != hex.EncodeToString(want[:]) {
		t.Errorf("committed manifest SHA256() = %s; want %s", got, hex.EncodeToString(want[:]))
	}
}

// committedManifestPath returns the repo-root eval/manifest.yaml path
// relative to this package dir (cmd/olaitan-eval/).
func committedManifestPath(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "eval", "manifest.yaml")
}

// --- small YAML-fixture mutation helpers --------------------------------

// stripLine removes the first line beginning (after trim) with prefix.
func stripLine(s, prefix string) string {
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), strings.TrimSpace(prefix)) {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// replaceLine replaces the first line beginning (after trim) with prefix
// by replacement.
func replaceLine(s, prefix, replacement string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), strings.TrimSpace(prefix)) {
			lines[i] = replacement
			break
		}
	}
	return strings.Join(lines, "\n")
}

// stripBlock removes the header line beginning with prefix and any
// following more-indented (child) lines, dropping the whole mapping block.
func stripBlock(s, prefix string) string {
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	skipping := false
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if !skipping && strings.HasPrefix(trimmed, strings.TrimSpace(prefix)) {
			skipping = true
			continue
		}
		if skipping {
			// Continue skipping indented child lines; stop at the next
			// top-level (column-0, non-empty, non-comment) key.
			if l == "" || strings.HasPrefix(l, " ") || strings.HasPrefix(trimmed, "#") {
				continue
			}
			skipping = false
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}
