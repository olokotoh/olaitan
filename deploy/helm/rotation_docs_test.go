//go:build helm

package helm_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// docSection returns the text of a markdown file from the heading line
// that starts with heading up to the next heading of the same or a
// higher level. It fails the test if the heading is missing.
func docSection(t *testing.T, rel, heading string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(chartDir(t), rel))
	if err != nil {
		t.Fatal(err)
	}
	level := strings.IndexFunc(heading, func(r rune) bool { return r != '#' })
	lines := strings.Split(string(raw), "\n")
	start := -1
	for i, l := range lines {
		if start < 0 {
			if strings.HasPrefix(l, heading) {
				start = i
			}
			continue
		}
		if n := strings.IndexFunc(l, func(r rune) bool { return r != '#' }); n > 0 && n <= level && strings.HasPrefix(l[n:], " ") {
			return strings.Join(lines[start:i], "\n")
		}
	}
	if start < 0 {
		t.Fatalf("%s has no heading %q", rel, heading)
	}
	return strings.Join(lines[start:], "\n")
}

// oneLine collapses markdown line wrapping so phrase checks do not
// depend on where a paragraph happens to break.
func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// TestApplogRotationDocCoversFailurePolicyFail: review round 2 of #158
// (R2-1). The applog MutatingWebhookConfiguration has no objectSelector,
// so under failurePolicy Fail a caBundle switch while the old injector
// still serves the old cert makes the apiserver reject every Pod CREATE
// outside kube-system and kube-public, the injector's own replacement
// pods included. The doc must say that the three-step CA rotation is
// mandatory there and that caBundle and servingCert never change in the
// same upgrade.
func TestApplogRotationDocCoversFailurePolicyFail(t *testing.T) {
	sec := oneLine(docSection(t, "APPLOG.md", "### Rotating the serving cert"))
	for _, want := range []string{
		"failurePolicy: Fail",
		"mandatory",
		"never change `caBundle` and `servingCert` in the same upgrade",
		"the injector's own replacement pods",
	} {
		if !strings.Contains(sec, want) {
			t.Errorf("APPLOG.md 'Rotating the serving cert' does not say %q", want)
		}
	}
}

// TestAuditRotationDocCoversCostAndCAOrdering: review round 2 of #158
// (R2-2). An audit cert change rolls the collector DaemonSet, which
// restarts every source on each node in turn (the cost CNI.md already
// states), and a serving cert from a new CA must be preceded by an
// apiserver kubeconfig whose caBundle trusts old and new CAs.
func TestAuditRotationDocCoversCostAndCAOrdering(t *testing.T) {
	sec := oneLine(docSection(t, "AUDIT.md", "### Upgrading"))
	for _, want := range []string{
		"checksum/audit-tls",
		"brief gap",
		"old and new CA",
		"then the new CA alone",
		"clusterCAData",
	} {
		if !strings.Contains(sec, want) {
			t.Errorf("AUDIT.md 'Upgrading' does not say %q", want)
		}
	}
}
