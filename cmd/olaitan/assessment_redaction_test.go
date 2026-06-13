package main

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/agent/provider"
	"github.com/olokotoh/olaitan/internal/decision/analyst"
	"github.com/olokotoh/olaitan/internal/metrics"
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
	// The redacted evidence sub-object must still be carried (not just the
	// top-level package_id) so a SIEM can correlate; assert on the nested
	// field directly, and that the secret-bearing event was actually present.
	if evt.RedactedEvidence.PackageID != "pkg-secret-1" {
		t.Errorf("redacted_evidence must carry the package: %q", evt.RedactedEvidence.PackageID)
	}
	if len(evt.RedactedEvidence.Events) != 1 {
		t.Fatalf("redacted_evidence lost the event: %+v", evt.RedactedEvidence.Events)
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

// scriptedChainForMode builds a scripted chain truncated to the requested
// ablation mode so the audit projection can be exercised end to end per mode.
func scriptedChainForMode(t *testing.T, mode string) *analyst.Chain {
	t.Helper()
	sp := &scriptedProvider{byRole: map[provider.Role]string{
		provider.RoleL1:     `{"hypothesis":"crypto miner","cited_evidence":[{"event_id":"evt-1"}],"confidence":70}`,
		provider.RoleL2:     `{"verdict":"confirmed","verified_evidence":[{"event_id":"evt-1","finding":"confirmed"}],"confidence":66}`,
		provider.RoleSenior: `{"threat_type":"cryptomining","reasoning":"miner confirmed","confidence":80}`,
	}}
	reg := metrics.NewRegistry()
	l1, err := analyst.NewL1(sp, analyst.PromptSpec{System: "s", Version: "vL1"}, reg, nil)
	if err != nil {
		t.Fatal(err)
	}
	var l2 *analyst.L2
	var sr *analyst.Senior
	if mode == analyst.ChainModeL1L2 || mode == analyst.ChainModeFull {
		if l2, err = analyst.NewL2(sp, analyst.PromptSpec{System: "s", Version: "vL2"}, reg, nil); err != nil {
			t.Fatal(err)
		}
	}
	if mode == analyst.ChainModeFull {
		if sr, err = analyst.NewSenior(sp, analyst.PromptSpec{System: "s", Version: "vSR"}, reg, nil); err != nil {
			t.Fatal(err)
		}
	}
	chain, err := analyst.NewChain(l1, l2, sr, reg, nil)
	if err != nil {
		t.Fatal(err)
	}
	return chain
}

// TestBuildAssessmentInputAblationOmitsRolesEndToEnd runs REAL ablation chains
// (l1_only, l1_l2) through buildAssessmentInput and asserts the produced event
// omits the per-role entries and verdicts for roles that did not run (round-1
// edge-case: the omission logic was only tested against hand-built input).
func TestBuildAssessmentInputAblationOmitsRolesEndToEnd(t *testing.T) {
	cases := []struct {
		mode        string
		wantRoles   []string
		absentRoles []string
		wantL2      bool
		wantSenior  bool
	}{
		{analyst.ChainModeL1Only, []string{"l1"}, []string{"l2", "senior"}, false, false},
		{analyst.ChainModeL1L2, []string{"l1", "l2"}, []string{"senior"}, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			res, err := scriptedChainForMode(t, tc.mode).Run(context.Background(), triggeringPackage("80"))
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			in := buildAssessmentInput(triggeringPackage("80"), res, time.Now().UTC())
			for _, r := range tc.wantRoles {
				if in.PromptVersions[r] == "" {
					t.Errorf("%s: role %s missing from prompt_versions: %+v", tc.mode, r, in.PromptVersions)
				}
			}
			for _, r := range tc.absentRoles {
				if _, ok := in.PromptVersions[r]; ok {
					t.Errorf("%s: absent role %s present in prompt_versions: %+v", tc.mode, r, in.PromptVersions)
				}
				if _, ok := in.Providers[r]; ok {
					t.Errorf("%s: absent role %s present in providers", tc.mode, r)
				}
			}
			if (in.L2Verification != nil) != tc.wantL2 {
				t.Errorf("%s: l2_verification present=%v, want %v", tc.mode, in.L2Verification != nil, tc.wantL2)
			}
			if _, ok := in.PromptVersions["senior"]; ok != tc.wantSenior {
				t.Errorf("%s: senior present=%v, want %v", tc.mode, ok, tc.wantSenior)
			}
		})
	}
}

// TestNoProductionPathSkipsRedaction is the AC3 STATIC guard: no non-test Go
// source under cmd/ or internal/ may construct an assessment with redaction
// disabled. This catches a FUTURE production caller that sets
// RedactionApplied:false, which a runtime test over the single current caller
// would miss.
func TestNoProductionPathSkipsRedaction(t *testing.T) {
	needles := []string{"RedactionApplied: false", "RedactionApplied:false"}
	for _, root := range []string{"../../cmd", "../../internal"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			b, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			for _, n := range needles {
				if strings.Contains(string(b), n) {
					t.Errorf("%s sets %q in a production path (AC3: redaction must never be disabled)", path, n)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
}
