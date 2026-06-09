package provider

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/olokotoh/olaitan/internal/schema"
)

// fakeProvider is the test-only stand-in for the not-yet-existing
// orchestrator callers (Story 3.2 BI-8): it proves the interface is
// implementable and exercisable without any concrete transport.
type fakeProvider struct {
	lastReq Request
	resp    Response
	err     error
}

func (f *fakeProvider) Name() string                 { return "fake" }
func (f *fakeProvider) Model() string                { return "fake-model-1" }
func (f *fakeProvider) MaxContextTokens() int        { return 1000 }
func (f *fakeProvider) ScoreCap() int                { return 35 }
func (f *fakeProvider) SupportsStreaming() bool      { return false }
func (f *fakeProvider) Health(context.Context) error { return f.err }

func (f *fakeProvider) Analyse(_ context.Context, req Request) (Response, error) {
	f.lastReq = req
	return f.resp, f.err
}

// Compile-time conformance: the fake satisfies the interface.
var _ Provider = (*fakeProvider)(nil)

func TestRoleValid(t *testing.T) {
	for _, r := range []Role{RoleL1, RoleL2, RoleSenior, RoleDFIR} {
		if !r.Valid() {
			t.Errorf("Role(%q).Valid() = false, want true", r)
		}
	}
	for _, r := range []Role{"", "L1", "analyst", "senior "} {
		if r.Valid() {
			t.Errorf("Role(%q).Valid() = true, want false", r)
		}
	}
}

func TestRequestCarriesRoleAndEvidence(t *testing.T) {
	fp := &fakeProvider{resp: Response{Raw: `{"ok":true}`, StopReason: "end_turn"}}
	req := Request{
		Role:    RoleSenior,
		Package: schema.EvidencePackage{PackageID: "pkg-1", WorkloadID: "wl-1"},
		Prompt:  Prompt{System: "sys", User: "user"},
		Schema:  JSONSchema(`{"type":"object"}`),
		PriorAssessment: &schema.ThreatAssessment{
			ThreatType: "crypto_miner",
			Mode:       schema.ModeLLM,
		},
	}
	resp, err := fp.Analyse(context.Background(), req)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if resp.Raw != `{"ok":true}` {
		t.Errorf("Raw = %q", resp.Raw)
	}
	if fp.lastReq.Role != RoleSenior {
		t.Errorf("role not threaded: got %q", fp.lastReq.Role)
	}
	if fp.lastReq.Package.PackageID != "pkg-1" {
		t.Errorf("package not threaded: got %q", fp.lastReq.Package.PackageID)
	}
	if fp.lastReq.PriorAssessment == nil || fp.lastReq.PriorAssessment.ThreatType != "crypto_miner" {
		t.Errorf("prior assessment not threaded: %+v", fp.lastReq.PriorAssessment)
	}
}

func TestFakeProviderErrorPath(t *testing.T) {
	sentinel := errors.New("boom")
	fp := &fakeProvider{err: sentinel}
	if _, err := fp.Analyse(context.Background(), Request{Role: RoleL1}); !errors.Is(err, sentinel) {
		t.Errorf("Analyse err = %v, want sentinel", err)
	}
	if err := fp.Health(context.Background()); !errors.Is(err, sentinel) {
		t.Errorf("Health err = %v, want sentinel", err)
	}
}

// TestRingImportGuard enforces the BI-1.4 import-direction rule in-tree:
// internal/agent/provider/... must not depend on the decision, response,
// correlator, collector, or report/dfir rings, and internal/report/redact
// must not grow a back-edge onto this package (no cycle). The same guard
// runs in CI; keeping it as a test makes the rule fail close to the
// offending change.
func TestRingImportGuard(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go binary not on PATH")
	}

	forbidden := []string{
		"github.com/olokotoh/olaitan/internal/decision",
		"github.com/olokotoh/olaitan/internal/response",
		"github.com/olokotoh/olaitan/internal/correlator",
		"github.com/olokotoh/olaitan/internal/collector",
		"github.com/olokotoh/olaitan/internal/report/dfir",
		"github.com/olokotoh/olaitan/internal/report/archive",
	}
	deps := goListDeps(t, "github.com/olokotoh/olaitan/internal/agent/provider/...")
	for _, f := range forbidden {
		for _, d := range deps {
			if d == f || strings.HasPrefix(d, f+"/") {
				t.Errorf("internal/agent/provider depends on forbidden package %s", d)
			}
		}
	}

	redactDeps := goListDeps(t, "github.com/olokotoh/olaitan/internal/report/redact/...")
	for _, d := range redactDeps {
		if strings.HasPrefix(d, "github.com/olokotoh/olaitan/internal/agent/provider") {
			t.Errorf("internal/report/redact has a back-edge onto %s (cycle risk)", d)
		}
	}
}

func goListDeps(t *testing.T, pattern string) []string {
	t.Helper()
	out, err := exec.Command("go", "list", "-deps", pattern).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			t.Fatalf("go list -deps %s: %v\n%s", pattern, err, ee.Stderr)
		}
		t.Fatalf("go list -deps %s: %v", pattern, err)
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n")
}
