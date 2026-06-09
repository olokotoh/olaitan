package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/schema"
)

func TestDefaultRoleTimeoutsContract(t *testing.T) {
	want := map[Role]time.Duration{
		RoleL1:     30 * time.Second,
		RoleL2:     30 * time.Second,
		RoleSenior: 60 * time.Second,
		RoleDFIR:   120 * time.Second,
	}
	got := DefaultRoleTimeouts()
	if len(got) != len(want) {
		t.Fatalf("DefaultRoleTimeouts has %d entries, want %d", len(got), len(want))
	}
	for role, d := range want {
		if got[role] != d {
			t.Errorf("DefaultRoleTimeouts[%s] = %v, want %v", role, got[role], d)
		}
	}
	// Fresh map per call: one provider's test seam must not leak into
	// another provider's table.
	got[RoleL1] = time.Second
	if DefaultRoleTimeouts()[RoleL1] != 30*time.Second {
		t.Error("DefaultRoleTimeouts returns a shared map; mutation leaked across calls")
	}
}

func TestResolveStatusMapping(t *testing.T) {
	sentinelPermanent := errors.New("permanent-class")
	isPermanent := func(err error) bool { return errors.Is(err, sentinelPermanent) }
	parent := context.Background()

	t.Run("success", func(t *testing.T) {
		cctx, cancel := context.WithTimeout(parent, time.Minute)
		defer cancel()
		if got := ResolveStatus(nil, isPermanent, cctx, parent); got != StatusSuccess {
			t.Errorf("got %q, want %q", got, StatusSuccess)
		}
	})

	t.Run("role deadline is timeout", func(t *testing.T) {
		cctx, cancel := context.WithTimeout(parent, time.Nanosecond)
		defer cancel()
		<-cctx.Done()
		err := fmt.Errorf("retry: ctx cancelled during op: %w", context.DeadlineExceeded)
		if got := ResolveStatus(err, isPermanent, cctx, parent); got != StatusTimeout {
			t.Errorf("got %q, want %q", got, StatusTimeout)
		}
	})

	t.Run("parent cancellation is transient, never timeout", func(t *testing.T) {
		pctx, pcancel := context.WithCancel(context.Background())
		cctx, cancel := context.WithTimeout(pctx, time.Minute)
		defer cancel()
		pcancel()
		err := fmt.Errorf("retry: ctx cancelled during op: %w", context.DeadlineExceeded)
		if got := ResolveStatus(err, isPermanent, cctx, pctx); got != StatusTransient {
			t.Errorf("got %q, want %q (shutdown path)", got, StatusTransient)
		}
	})

	t.Run("permanent", func(t *testing.T) {
		cctx, cancel := context.WithTimeout(parent, time.Minute)
		defer cancel()
		err := fmt.Errorf("wrapped: %w", sentinelPermanent)
		if got := ResolveStatus(err, isPermanent, cctx, parent); got != StatusPermanent {
			t.Errorf("got %q, want %q", got, StatusPermanent)
		}
	})

	t.Run("exhausted retries are transient", func(t *testing.T) {
		cctx, cancel := context.WithTimeout(parent, time.Minute)
		defer cancel()
		err := errors.New("retry: max attempts (3) exhausted: upstream 529")
		if got := ResolveStatus(err, isPermanent, cctx, parent); got != StatusTransient {
			t.Errorf("got %q, want %q", got, StatusTransient)
		}
	})
}

func TestBuildAnalystContent(t *testing.T) {
	pkg := schema.EvidencePackage{PackageID: "pkg-7", WorkloadID: "ns/app"}
	req := Request{
		Role:   RoleL2,
		Prompt: Prompt{User: "verify this hypothesis"},
		Schema: JSONSchema(`{"type":"object","required":["verdict"]}`),
		PriorAssessment: &schema.ThreatAssessment{
			ThreatType: "crypto_miner",
			Mode:       schema.ModeLLM,
		},
	}
	content, err := BuildAnalystContent(pkg, req)
	if err != nil {
		t.Fatalf("BuildAnalystContent: %v", err)
	}
	for _, want := range []string{
		"verify this hypothesis",
		"<evidence_package>",
		`"package_id":"pkg-7"`,
		"</evidence_package>",
		"<prior_assessment>",
		"crypto_miner",
		"</prior_assessment>",
		`"required":["verdict"]`,
	} {
		if !strings.Contains(content, want) {
			t.Errorf("content missing %q", want)
		}
	}

	// Optional parts are genuinely optional.
	minimal, err := BuildAnalystContent(schema.EvidencePackage{}, Request{Role: RoleL1, Prompt: Prompt{User: "triage"}})
	if err != nil {
		t.Fatalf("BuildAnalystContent minimal: %v", err)
	}
	if strings.Contains(minimal, "<prior_assessment>") {
		t.Error("minimal content carries a prior_assessment block")
	}
	if strings.Contains(minimal, "JSON Schema") {
		t.Error("minimal content carries a schema instruction")
	}
	if !strings.Contains(minimal, "<evidence_package>") {
		t.Error("minimal content missing the evidence block (it always serialises)")
	}
}
