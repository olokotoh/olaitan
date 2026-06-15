// Package main is the Olaitan evaluation harness binary (FR53-FR54).
//
// olaitan-eval orchestrates a single reproducible evaluation run from one
// eval/manifest.yaml reproducibility envelope (NFR37). It loads the
// envelope, computes its canonical SHA256 over the committed file bytes,
// runs a fail-closed digest-verification gate over the pinned artefacts,
// generates a sortable run_id, lays out runs/<run_id>/, and drives the
// configured number of trials through a fixed five-phase Runner loop
// (cluster reset -> warm -> scenario -> capture -> cleanup,
// architecture.md:712).
//
// Story 5.1 is the FOUNDATION of Epic 5: it freezes the harness shape and
// the five seam interfaces (ClusterController, ConfigOverlay, Scenario,
// Capturer, DigestVerifier). Stories 5.2-5.5 supply the rich
// implementations BEHIND those seams without reshaping the Runner loop or
// the interface signatures. Every placeholder method carries a
// `// Story 5.x:` TODO naming its owning story.
//
// This file holds the reproducibility-envelope reader and validator. It
// reuses the internal/config fail-fast precedent: LoadManifest reads the
// file, retains the exact bytes it read, unmarshals into a typed Manifest,
// and Validate rejects any missing or empty required field with a
// field-named error. SHA256 hashes the retained raw bytes (BI-5), so a
// reader re-derives the hash with `sha256sum eval/manifest.yaml` and YAML
// key-order / whitespace / comment drift never silently changes it.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Manifest is the typed mirror of eval/manifest.yaml, the NFR37
// reproducibility envelope. It pins the EIGHT NFR37 fields
// [Source: prd.md:603] so any evaluation run is fully reproducible from a
// single file. The YAML keys are the human-editable contract: the file is
// the single source of truth (BI-4) and the struct tags use its keys
// verbatim.
//
// rawBytes holds the exact file bytes LoadManifest read; SHA256 hashes
// THOSE (not a re-marshalled struct) so the hash is stable and
// re-derivable (BI-5). It is unexported so callers cannot mutate the
// hashed content out from under the recorded manifest_sha256.
type Manifest struct {
	// Images pins each logical image name to a repo@sha256:... digest
	// (NFR37 field 1: container image digests). The aggregator image plus
	// any sidecar/fixture images the run installs. Verified by the AC3
	// digest gate (imageDigestVerifier).
	Images map[string]string `yaml:"images"`
	// KubernetesPatchVersion pins the cluster patch level (NFR37 field 2),
	// e.g. "1.29.x" per architecture.md:79.
	KubernetesPatchVersion string `yaml:"kubernetes_patch_version"`
	// FalcoRuleCorpusTag pins the Falco rule corpus (NFR37 field 3). Its
	// digest verification is deferred (allow-listed) until the corpus is
	// harness-reachable (BI-6).
	FalcoRuleCorpusTag string `yaml:"falco_rule_corpus_tag"`
	// SigmaCorpusGitSHA pins the rules/ Sigma corpus commit (NFR37 field 4).
	SigmaCorpusGitSHA string `yaml:"sigma_corpus_git_sha"`
	// LLMModelVersion pins the analyst model (NFR37 field 5). Story 5.1
	// pins the REAL current model claude-opus-4-8 (the epic's
	// claude-opus-4-7-2026-MM-DD is STALE, BI-3); it is recorded + hashed
	// here and wired to the chart's analyst.model by Story 5.3/5.5, not
	// here.
	LLMModelVersion string `yaml:"llm_model_version"`
	// RandomSeed is threaded to any harness-side randomness for
	// determinism (NFR37 field 6). A pointer so Validate distinguishes
	// "operator omitted the field" (reject: the envelope must pin it) from
	// "operator pinned 0" (accept: a deterministic zero seed is a valid
	// choice).
	RandomSeed *int64 `yaml:"random_seed"`
	// SysctlSnapshot pins the host sysctl values (NFR37 field 7), either
	// inline as a map or as a path to a captured file. Modelled as a map
	// of key -> value; a single {path: <file>} entry expresses the
	// path-to-file form.
	SysctlSnapshot map[string]string `yaml:"sysctl_snapshot"`
	// ClusterBootstrapScriptGitSHA pins the deploy/demo/setup.sh bootstrap
	// commit (NFR37 field 8).
	ClusterBootstrapScriptGitSHA string `yaml:"cluster_bootstrap_script_git_sha"`

	// rawBytes is the exact content LoadManifest read; SHA256 hashes it
	// (BI-5). Unexported and never re-marshalled.
	rawBytes []byte
}

// k8sPatchVersionRe matches a Kubernetes patch-version pin of the form
// MAJOR.MINOR.PATCH or MAJOR.MINOR.x (architecture.md:79 pins e.g.
// "1.29.x"). Validate rejects anything else as unparseable.
var k8sPatchVersionRe = regexp.MustCompile(`^[0-9]+\.[0-9]+\.([0-9]+|x)$`)

// imageDigestRe matches a digest-pinned image reference of the form
// repo@sha256:<64-hex>. The reproducibility envelope pins images by
// digest, never by mutable tag, so a re-run resolves byte-identical
// content (NFR37).
var imageDigestRe = regexp.MustCompile(`^.+@sha256:[0-9a-f]{64}$`)

// LoadManifest reads the reproducibility envelope at path, retains the
// exact bytes it read (for the BI-5 hash), unmarshals into a Manifest, and
// fails fast via Validate. It mirrors the internal/config Load idiom:
// every boundary error is prefixed "manifest:" and wraps the cause.
func LoadManifest(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("manifest: read %q: %w", path, err)
	}
	var m Manifest
	// Strict decode so an unknown key (a typo in the human-edited
	// envelope) fails loudly rather than silently dropping a pin.
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest: parse %q: %w", path, err)
	}
	m.rawBytes = raw
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("manifest: validate %q: %w", path, err)
	}
	return &m, nil
}

// Validate enforces the NFR37 invariants and FAILS FAST on any missing or
// empty required field with a field-named error (BI-4, the internal/config
// precedent). The envelope must pin every one of the eight fields: a run
// that cannot name its image digests, its kernel/Kubernetes level, its
// rule corpora, its model, its seed, its sysctl snapshot, and its
// bootstrap commit is not reproducible (NFR37).
func (m *Manifest) Validate() error {
	if m == nil {
		return errors.New("manifest: validate: nil manifest")
	}
	if len(m.Images) == 0 {
		return errors.New("manifest: images: at least one image digest pin is required (NFR37)")
	}
	for name, ref := range m.Images {
		if strings.TrimSpace(name) == "" {
			return errors.New("manifest: images: an image entry has an empty logical name")
		}
		if strings.TrimSpace(ref) == "" {
			return fmt.Errorf("manifest: images.%s: digest pin is required and must be non-empty (NFR37)", name)
		}
		if !imageDigestRe.MatchString(ref) {
			return fmt.Errorf("manifest: images.%s: must be a digest-pinned reference of the form repo@sha256:<64-hex> for reproducibility (got %q)", name, ref)
		}
	}
	if strings.TrimSpace(m.KubernetesPatchVersion) == "" {
		return errors.New("manifest: kubernetes_patch_version: required (NFR37)")
	}
	if !k8sPatchVersionRe.MatchString(m.KubernetesPatchVersion) {
		return fmt.Errorf("manifest: kubernetes_patch_version: must be MAJOR.MINOR.PATCH or MAJOR.MINOR.x (got %q)", m.KubernetesPatchVersion)
	}
	if strings.TrimSpace(m.FalcoRuleCorpusTag) == "" {
		return errors.New("manifest: falco_rule_corpus_tag: required (NFR37)")
	}
	if strings.TrimSpace(m.SigmaCorpusGitSHA) == "" {
		return errors.New("manifest: sigma_corpus_git_sha: required (NFR37)")
	}
	if strings.TrimSpace(m.LLMModelVersion) == "" {
		return errors.New("manifest: llm_model_version: required (NFR37; pin the real current model claude-opus-4-8)")
	}
	if m.RandomSeed == nil {
		return errors.New("manifest: random_seed: required (NFR37; pin a deterministic seed, 0 is permitted)")
	}
	if len(m.SysctlSnapshot) == 0 {
		return errors.New("manifest: sysctl_snapshot: required (NFR37; pin the host sysctl values inline or as {path: <file>})")
	}
	for key, val := range m.SysctlSnapshot {
		if strings.TrimSpace(key) == "" {
			return errors.New("manifest: sysctl_snapshot: an entry has an empty key")
		}
		if strings.TrimSpace(val) == "" {
			return fmt.Errorf("manifest: sysctl_snapshot.%s: value is required and must be non-empty", key)
		}
	}
	if strings.TrimSpace(m.ClusterBootstrapScriptGitSHA) == "" {
		return errors.New("manifest: cluster_bootstrap_script_git_sha: required (NFR37)")
	}
	return nil
}

// SHA256 returns the lowercase-hex SHA256 of the COMMITTED file bytes
// LoadManifest read (BI-5). A reader re-derives it with
// `sha256sum eval/manifest.yaml`. Hashing the raw bytes (not a
// re-marshalled struct) means YAML key-order / comment / whitespace drift
// never silently changes the hash. The harness records this as
// manifest_sha256 in every run's metadata.yaml (AC3).
func (m *Manifest) SHA256() string {
	sum := sha256.Sum256(m.rawBytes)
	return hex.EncodeToString(sum[:])
}
