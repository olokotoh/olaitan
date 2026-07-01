package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
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
// another provider's table.
//
// DW3.8-1 (config-routability): the AC defaults are calibrated for the
// Claude baseline. A slower cloud provider (e.g. an OpenAI-compatible
// endpoint under load) can exceed them, so OLT_LLM_ROLE_TIMEOUT_MULTIPLIER
// scales every per-role default by a positive float. Unset/empty/invalid
// (<= 0 or unparseable) leaves the AC defaults byte-identical, so existing
// callers and tests observe no change.
func DefaultRoleTimeouts() map[Role]time.Duration {
	m := roleTimeoutMultiplier()
	scale := func(d time.Duration) time.Duration {
		return time.Duration(float64(d) * m)
	}
	return map[Role]time.Duration{
		RoleL1:     scale(30 * time.Second),
		RoleL2:     scale(30 * time.Second),
		RoleSenior: scale(60 * time.Second),
		RoleDFIR:   scale(120 * time.Second),
	}
}

// roleTimeoutMultiplier reads OLT_LLM_ROLE_TIMEOUT_MULTIPLIER (DW3.8-1) as
// a positive float scaling the per-role default timeouts. Absent, empty,
// unparseable, or non-positive all resolve to 1.0 (the AC-mandated
// defaults, unchanged).
func roleTimeoutMultiplier() float64 {
	v := strings.TrimSpace(os.Getenv("OLT_LLM_ROLE_TIMEOUT_MULTIPLIER"))
	if v == "" {
		return 1.0
	}
	m, err := strconv.ParseFloat(v, 64)
	if err != nil || m <= 0 {
		return 1.0
	}
	return m
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

// escapeAngleBrackets rewrites every '<' byte in a marshalled JSON
// document to the JSON string escape sequence \u003c. In valid JSON a
// literal '<' can only occur inside a string literal, so the rewrite is
// JSON-equivalent; afterwards the document cannot contain the angle
// bracket the framing delimiters below depend on (DW3.3-1, Story 3.5
// BI-7). encoding/json already escapes '<' in the strings it encodes
// itself, but json.RawMessage fields (schema.Event.Raw) pass through
// marshalling verbatim, so the guarantee must be enforced here.
func escapeAngleBrackets(doc []byte) []byte {
	return bytes.ReplaceAll(doc, []byte("<"), []byte(`\u003c`))
}

// BuildAnalystContent composes the user-turn text every provider
// transports (Story 3.2 BI-9 / Story 3.3 BI-2.1, byte-compatible across
// providers): the orchestrator's user prompt, the REDACTED evidence
// package in a tagged block, the optional L1 hypothesis (Story 3.6
// BI-2, the L2/Senior re-examination input), the optional L2
// verification (Story 3.7 BI-3, the Senior challenge input), the
// optional prior assessment, and the output-contract instruction. The
// caller passes the redacted copy; this function never sees the
// un-redacted package.
//
// Framing hardening (DW3.3-1, Story 3.5 BI-7 / 3.6 BI-2 / 3.7 BI-3):
// the evidence, prior-hypothesis, prior-verification and
// prior-assessment payloads are angle-bracket-escaped after marshalling
// so no payload byte can close (or open) a framing tag; a defensive
// invariant check rejects any payload that somehow retains a '<'. The
// framing tags themselves and the req.Schema block are NOT escaped:
// the schema is repo-owned trusted content (the committed role schema),
// never attacker-influenced evidence.
func BuildAnalystContent(redacted schema.EvidencePackage, req Request) (string, error) {
	evidence, err := json.Marshal(redacted)
	if err != nil {
		return "", fmt.Errorf("provider: marshal redacted evidence: %w", err)
	}
	evidence = escapeAngleBrackets(evidence)
	if bytes.IndexByte(evidence, '<') >= 0 {
		return "", errors.New("provider: evidence payload retained a '<' after escaping")
	}

	var sb strings.Builder
	sb.WriteString(req.Prompt.User)
	sb.WriteString("\n\n<evidence_package>\n")
	sb.Write(evidence)
	sb.WriteString("\n</evidence_package>")
	if req.PriorHypothesis != nil {
		hyp, herr := json.Marshal(req.PriorHypothesis)
		if herr != nil {
			return "", fmt.Errorf("provider: marshal prior hypothesis: %w", herr)
		}
		hyp = escapeAngleBrackets(hyp)
		if bytes.IndexByte(hyp, '<') >= 0 {
			return "", errors.New("provider: prior hypothesis retained a '<' after escaping")
		}
		sb.WriteString("\n\n<l1_hypothesis>\n")
		sb.Write(hyp)
		sb.WriteString("\n</l1_hypothesis>")
	}
	if req.PriorVerification != nil {
		ver, verr := json.Marshal(req.PriorVerification)
		if verr != nil {
			return "", fmt.Errorf("provider: marshal prior verification: %w", verr)
		}
		ver = escapeAngleBrackets(ver)
		if bytes.IndexByte(ver, '<') >= 0 {
			return "", errors.New("provider: prior verification retained a '<' after escaping")
		}
		sb.WriteString("\n\n<l2_verification>\n")
		sb.Write(ver)
		sb.WriteString("\n</l2_verification>")
	}
	if req.PriorAssessment != nil {
		prior, perr := json.Marshal(req.PriorAssessment)
		if perr != nil {
			return "", fmt.Errorf("provider: marshal prior assessment: %w", perr)
		}
		prior = escapeAngleBrackets(prior)
		if bytes.IndexByte(prior, '<') >= 0 {
			return "", errors.New("provider: prior assessment retained a '<' after escaping")
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
