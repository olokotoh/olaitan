package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/olokotoh/olaitan/internal/schema"
)

// This file hosts the transport semantics every concrete Provider shares
// (Story 3.3 BI-5 hoist out of the Story 3.2 Claude implementation): the
// bounded outcome enum for olaitan_llm_calls_total, the AC-mandated
// per-role timeout table, the final-outcome status mapping, and the
// analyst user-turn composition. Hoisting (rather than per-provider
// copy-paste) keeps the Claude and OpenAI-compatible providers
// byte-parallel where the spec demands identical behaviour.

// Metric status label values (the bounded outcome enum, Story 3.2 BI-4).
const (
	StatusSuccess   = "success"
	StatusTransient = "transient_failure"
	StatusPermanent = "permanent_failure"
	StatusTimeout   = "timeout"
)

// DefaultRoleTimeouts returns the AC-mandated per-role TOTAL retry budget
// (Story 3.2 AC2: 30s l1, 30s l2, 60s senior, 120s dfir-reserved). A fresh
// map is returned per call so one provider's test seam cannot mutate
// another provider's table. Story 3.8 makes these config-routable.
func DefaultRoleTimeouts() map[Role]time.Duration {
	return map[Role]time.Duration{
		RoleL1:     30 * time.Second,
		RoleL2:     30 * time.Second,
		RoleSenior: 60 * time.Second,
		RoleDFIR:   120 * time.Second,
	}
}

// ResolveStatus maps the final outcome of a retried provider call onto the
// bounded status enum (Story 3.2 BI-3.2/BI-5.2): success when err is nil;
// timeout when the per-role deadline itself fired (parent context still
// alive, so a process shutdown is never misreported as a role timeout);
// permanent_failure when the provider's isPermanent classifier matches;
// transient_failure otherwise (exhausted retries, transport errors,
// parent-context cancellation).
func ResolveStatus(err error, isPermanent func(error) bool, callCtx, parentCtx context.Context) string {
	switch {
	case err == nil:
		return StatusSuccess
	case errors.Is(err, context.DeadlineExceeded) &&
		callCtx.Err() != nil && parentCtx.Err() == nil:
		return StatusTimeout
	case isPermanent(err):
		return StatusPermanent
	default:
		return StatusTransient
	}
}

// BuildAnalystContent composes the user-turn text every provider
// transports (Story 3.2 BI-9 / Story 3.3 BI-2.1, byte-compatible across
// providers): the orchestrator's user prompt, the REDACTED evidence
// package in a tagged block, the optional prior assessment, and the
// output-contract instruction. The caller passes the redacted copy; this
// function never sees the un-redacted package.
func BuildAnalystContent(redacted schema.EvidencePackage, req Request) (string, error) {
	evidence, err := json.Marshal(redacted)
	if err != nil {
		return "", fmt.Errorf("provider: marshal redacted evidence: %w", err)
	}

	var sb strings.Builder
	sb.WriteString(req.Prompt.User)
	sb.WriteString("\n\n<evidence_package>\n")
	sb.Write(evidence)
	sb.WriteString("\n</evidence_package>")
	if req.PriorAssessment != nil {
		prior, perr := json.Marshal(req.PriorAssessment)
		if perr != nil {
			return "", fmt.Errorf("provider: marshal prior assessment: %w", perr)
		}
		sb.WriteString("\n\n<prior_assessment>\n")
		sb.Write(prior)
		sb.WriteString("\n</prior_assessment>")
	}
	if len(req.Schema) > 0 {
		sb.WriteString("\n\nRespond with a single JSON document conforming to this JSON Schema and nothing else:\n")
		sb.Write(req.Schema)
	}
	return sb.String(), nil
}
