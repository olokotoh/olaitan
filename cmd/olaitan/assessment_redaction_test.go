package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	responseaudit "github.com/olokotoh/olaitan/internal/response/audit"
	"github.com/olokotoh/olaitan/internal/schema"
)

// secretBearingPackage triggers the chain (severity-80 rule match) and
// carries an env secret value plus a JWT in the event material, so the
// redaction-at-the-audit-boundary guarantee (Story 3.14 AC3/AC4) can be
// asserted end to end.
func secretBearingPackage() schema.EvidencePackage {
	// A well-formed JWT (the canonical jwt.io example): header decodes to
	// {"alg":"HS256","typ":"JWT"}, so the redaction JWT detector fires.
	const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	return schema.EvidencePackage{
		PackageID:   "pkg-secret-1",
		WorkloadID:  "ns/Deployment/victim",
		RuleMatches: []schema.RuleMatch{{RuleID: "r1", Severity: "80", EventID: "e1"}},
		Events: []schema.Event{
			{
				ID:      "e1",
				Summary: jwt,
				Raw:     json.RawMessage(`{"API_KEY":"sk-supersecret-DEADBEEF","host":"10.0.0.1"}`),
			},
		},
	}
}

// TestBuildAssessmentInputRedactsSecrets is the AC3/AC4 adversarial proof:
// a package carrying a secret env value + a JWT yields an audit event whose
// serialised JSON contains neither, while redaction_applied is true and the
// (redacted) evidence is still present for correlation.
func TestBuildAssessmentInputRedactsSecrets(t *testing.T) {
	pkg := secretBearingPackage()
	res, err := scriptedFullChain(t).Run(context.Background(), pkg)
	if err != nil {
		t.Fatalf("chain.Run: %v", err)
	}
	in := buildAssessmentInput(pkg, res, time.Unix(1700000000, 0).UTC())
	if !in.RedactionApplied {
		t.Error("production path must set RedactionApplied=true (AC3)")
	}
	evt := responseaudit.AssessmentFromChain(in)
	blob, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(blob)
	for _, secret := range []string{"sk-supersecret-DEADBEEF", "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"} {
		if strings.Contains(s, secret) {
			t.Errorf("audit payload leaked a secret %q (redaction not applied at the audit boundary)\n%s", secret, s)
		}
	}
	// The redacted evidence must still be carried for SIEM correlation.
	if !strings.Contains(s, "pkg-secret-1") {
		t.Error("redacted_evidence must still carry the package_id for correlation")
	}
}

// TestBuildAssessmentInputAlwaysAppliesRedaction pins the AC3 invariant that
// the production projection never builds an input with RedactionApplied=false.
func TestBuildAssessmentInputAlwaysAppliesRedaction(t *testing.T) {
	pkg := triggeringPackage("80")
	res, err := scriptedFullChain(t).Run(context.Background(), pkg)
	if err != nil {
		t.Fatalf("chain.Run: %v", err)
	}
	if in := buildAssessmentInput(pkg, res, time.Now().UTC()); !in.RedactionApplied {
		t.Error("RedactionApplied=false on a production path")
	}
}
