package falco_test

// Story 11.2d (#195), AC5: pin each S1-S3 OLT rule against a RECORDED REAL
// Falco alert, not a hand-written synthetic event. Each fixture under
// testdata/real-alerts/ is the exact JSON body Falco's http_output POSTed to
// the collector on a live cluster when the real attack ran (SA token values
// are never stored; the S2 fixture carries only the token path, length and
// hash). The test drives the SAME collector path the live pipeline uses
// (DecodeHTTPOutput -> Translate) and then the SAME decision-engine match path
// (matcher.NewResolver + rule.Detection.Matches), so a green result means the
// real alert, run through the real code, triggers its intended OLT rule.
//
// Before Story 11.2d these rules matched only the synthetic events in
// internal/decision/rules/testdata/scenarios/*/package.json; the real attacks
// produced no match (PR #194 live finding). If a fixture is missing this test
// FAILS (not skips): the whole point of the story is that the real alerts
// exist and match.

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	sigma "github.com/runreveal/sigmalite"

	"github.com/olokotoh/olaitan/internal/collector/falco"
	"github.com/olokotoh/olaitan/internal/decision/rules/matcher"
	"github.com/olokotoh/olaitan/internal/decision/rules/parser"
	"github.com/olokotoh/olaitan/internal/schema"
)

// tenantDeploymentPosture is the workload posture the correlator resolves
// read-on-demand from the live pod for a tenant-acme Deployment (the shape
// OLT-PRIV-001 / OLT-LATERAL-001 / OLT-CRED-002 key on). It is NOT part of the
// Falco alert; it comes from the K8s API at assembly time.
func tenantDeploymentPosture() *schema.WorkloadPosture {
	return &schema.WorkloadPosture{
		Identity: schema.WorkloadIdentity{
			Namespace: "tenant-acme",
			OwnerKind: "Deployment",
			OwnerName: "web",
		},
	}
}

func TestRealFalcoAlerts_TriggerTheirOLTRule(t *testing.T) {
	root := repoRoot(t)
	cases := []struct {
		name     string
		fixture  string // real Falco http_output body
		ruleFile string // the OLT rule it must trigger
	}{
		{"S1 privileged escape -> OLT-PRIV-001", "priv-001-cap-sys-admin.json", "rules/priv/OLT-PRIV-001.yaml"},
		{"S2 SA-token read -> OLT-CRED-001", "cred-001-sa-token-read.json", "rules/cred/OLT-CRED-001.yaml"},
		{"S2 metadata contact -> OLT-CRED-002", "cred-002-metadata-contact.json", "rules/cred/OLT-CRED-002.yaml"},
		{"S3 in-pod kubectl -> OLT-LATERAL-001", "lateral-001-kubectl-exec.json", "rules/lateral/OLT-LATERAL-001.yaml"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(root, "internal/collector/falco/testdata/real-alerts", tc.fixture))
			if err != nil {
				t.Fatalf("recorded real Falco alert missing (%s): %v\n(Story 11.2d requires the fixture be captured from a live cluster; a missing fixture is a red test, not a skip.)", tc.fixture, err)
			}
			resp, err := falco.DecodeHTTPOutput(body)
			if err != nil {
				t.Fatalf("DecodeHTTPOutput(%s): %v", tc.fixture, err)
			}
			ev, err := falco.Translate(resp, "eval-node")
			if err != nil {
				t.Fatalf("Translate(%s): %v", tc.fixture, err)
			}

			ruleBytes, err := os.ReadFile(filepath.Join(root, tc.ruleFile))
			if err != nil {
				t.Fatalf("read rule %s: %v", tc.ruleFile, err)
			}
			rule, err := parser.ParseRule(ruleBytes)
			if err != nil {
				t.Fatalf("ParseRule(%s): %v", tc.ruleFile, err)
			}

			resolver, entry, err := matcher.NewResolver(tenantDeploymentPosture(), matcher.EventFields(ev))
			if err != nil {
				t.Fatalf("NewResolver: %v", err)
			}
			opts := &sigma.MatchOptions{FieldResolver: resolver}
			if rule.Detection == nil || !rule.Detection.Matches(entry, opts) {
				t.Errorf("real Falco alert %q did NOT trigger %s through the real pipeline; event fields=%v",
					tc.fixture, rule.ID, matcher.EventFields(ev))
			}
		})
	}
}

// repoRoot walks up from this test file to the directory containing go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found walking up from test file")
		}
		dir = parent
	}
}
