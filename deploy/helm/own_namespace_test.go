//go:build helm

package helm_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Story 12.8 (#227). On the 2026-10-20 live run a plain install into
// `default` scored its own pods and moved its own model-pull Job to
// RESTRICTED: correlator.neverScoreReleaseNamespace was false by default
// (Story 10.6). Since Story 12.7 turns every part on, a plain install must
// never score its own release namespace; the knob stays to override.
// ADR-2026-10-20-02.

func neverScoredIn(t *testing.T, rendered string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "olaitan.yaml")
	if err := os.WriteFile(path, []byte(extractEmbeddedConfigYAML(t, rendered)), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := configLoad(t, path)
	if err != nil {
		t.Fatalf("config does not load: %v", err)
	}
	return strings.Join(c.Detection.Correlator.NeverScoredNamespaces, ",")
}

func TestDefaultInstallNeverScoresItsReleaseNamespace(t *testing.T) {
	// helm template renders into "default", the live-run namespace.
	if got := neverScoredIn(t, helmTemplate(t, nil)); got != "olaitan,default" {
		t.Errorf("default render never_scored_namespaces = %q, want olaitan,default", got)
	}
	if got := neverScoredIn(t, helmTemplate(t, []string{"correlator.neverScoreReleaseNamespace=false"})); got != "olaitan" {
		t.Errorf("override =false never_scored_namespaces = %q, want olaitan", got)
	}
	// values-minimal is the pre-12.7 posture and the base for evaluation runs
	// comparable with earlier ones: it keeps the old behaviour.
	minimal := helmTemplateValues(t, filepath.Join(chartDir(t), "values-minimal.yaml"))
	if got := neverScoredIn(t, minimal); got != "olaitan" {
		t.Errorf("values-minimal never_scored_namespaces = %q, want olaitan", got)
	}
	// Every evaluation arm overlay pins the earlier behaviour too, like the
	// risk window (ADR-2026-10-19-02), so a campaign stays comparable.
	for _, f := range []string{"values-eval.yaml", "values-eval-f.yaml", "values-eval-rs.yaml", "values-eval-rsl.yaml", "values-eval-rslt-full.yaml", "values-eval-rslt-l1-l2.yaml", "values-eval-rslt-l1-only.yaml"} {
		if got := neverScoredIn(t, helmTemplateValues(t, filepath.Join(chartDir(t), f))); got != "olaitan" {
			t.Errorf("%s never_scored_namespaces = %q, want olaitan (pinned for comparability)", f, got)
		}
	}
}

// Review round 1: kube-system is never put on the never-scored list, even
// with the release there (SECURITY.md: a compromised CoreDNS or CNI agent
// would go unseen), and NOTES say why.
func TestKubeSystemIsNeverAddedToTheNeverScoredList(t *testing.T) {
	out, err := exec.Command("helm", "template", "olaitan", chartDir(t), "-n", "kube-system", "--set", "secrets.redisPassword=test-password").CombinedOutput()
	if err != nil {
		t.Fatalf("helm template -n kube-system: %v\n%s", err, out)
	}
	if got := neverScoredIn(t, string(out)); got != "olaitan" {
		t.Errorf("-n kube-system never_scored_namespaces = %q, want olaitan", got)
	}
	notes := renderNotesInNamespace(t, "kube-system")
	if !strings.Contains(notes, "kube-system is never") || strings.Contains(notes, "NOTHING in") || strings.Contains(notes, "neverScoreReleaseNamespace=true") {
		t.Errorf("kube-system notes do not explain that it stays scored; notes:\n%s", notes)
	}
}

func TestNotesSayTheReleaseNamespaceIsNotScored(t *testing.T) {
	def := renderNotes(t, nil)
	for _, want := range []string{"! NAMESPACE", `NOTHING in "default" is scored`, "correlator.neverScoreReleaseNamespace=false"} {
		if !strings.Contains(def, want) {
			t.Errorf("default notes for an install into default miss %q; notes:\n%s", want, def)
		}
	}
	if strings.Contains(def, "its own aggregator and") {
		t.Errorf("default notes still warn that Olaitan scores its own pods, which the default no longer does; notes:\n%s", def)
	}
	off := renderNotes(t, []string{"correlator.neverScoreReleaseNamespace=false"})
	if !strings.Contains(off, "its own aggregator and") || strings.Contains(off, "NOTHING in") {
		t.Errorf("with the override off the notes must warn about self-scoring, not about a blind namespace; notes:\n%s", off)
	}
}
