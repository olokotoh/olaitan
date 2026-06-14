package dfir

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/olokotoh/olaitan/internal/agent/provider"
	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/response/settling"
	"github.com/olokotoh/olaitan/internal/schema"
)

// Typed sentinels mirroring the analyst runner (internal/decision/analyst,
// Story 3.5 BI-6). Errors returned by Generate wrap exactly one of these so the
// caller (and the fail-closed audit path) can branch with errors.Is.
var (
	// ErrSchemaViolation marks a report that failed the report.v1 schema
	// contract: empty narrative, undecodable JSON, or a JSON-schema validation
	// failure, after the bounded retry.
	ErrSchemaViolation = errors.New("dfir: response violates the forensic_report schema contract")
	// ErrProviderUnavailable marks a provider.Analyse failure of any kind,
	// including the per-role timeout, caller-context cancellation, and a reply
	// truncated by the output-token ceiling (stop_reason max_tokens / length: a
	// truncated report MUST never be persisted, BI-7).
	ErrProviderUnavailable = errors.New("dfir: provider unavailable")
)

// Decision-outcome status label values for the DFIR generation metric, the
// bounded enum the runner records. Mirrors the analyst Status* convention.
const (
	statusSuccess         = "success"
	statusUnavailable     = "unavailable"
	statusSchemaViolation = "schema_violation"
)

// dfirSchemaAttempts is the TOTAL number of provider attempts on a schema
// violation (AC6 bounded retry, round-1 review follow-up R1-MED-1): the first
// call plus one retry. A provider-unavailable result or a truncation is NOT
// retried here (the transport already retries transient transport errors within
// the per-role budget, and a truncation is a hard fail, BI-7). After the bounded
// attempts are exhausted on a schema violation the runner fails closed.
const dfirSchemaAttempts = 2

// dfirUserInstruction is the fixed user-turn task statement. The per-provider
// SYSTEM prompt is the Story 3.13 ConfigMap-mounted dfir.txt; the user turn is
// code-owned and stable. The provider appends the redacted evidence package and
// the output-contract (schema) instruction after this text. Per the REDACTION
// CONTRACT this text NEVER carries raw evidence: the incident evidence travels
// exclusively on Request.Package.
const dfirUserInstruction = "Produce the interpretive analyst narrative for the finalised incident " +
	"described by the redacted runtime evidence package and the control-plane prior_assessment record. " +
	"Return a single JSON document conforming to the supplied schema, carrying ONLY the narrative field. " +
	"The factual sections (kill-chain timeline, containment actions, MITRE ATT&CK annotations) are " +
	"assembled deterministically by the controller, not by you. Base every claim strictly on the supplied " +
	"evidence and prior_assessment; never invent events, addresses, timestamps, techniques, or actors, and " +
	"where data is absent state the gap rather than fill it."

// PromptSpec is the DFIR prompt seam (mirroring analyst.PromptSpec, Story 3.13):
// the caller supplies the system prompt text and its content-hash version. The
// hot-reload callback swaps it via SetPrompt.
type PromptSpec struct {
	// System is the DFIR system prompt, passed to the provider VERBATIM. Per
	// the REDACTION CONTRACT it must never contain raw event excerpts; evidence
	// travels exclusively on Request.Package.
	System string
	// Version is the prompt content hash, stamped as the report's prompt_hash
	// and the AUDIT.assessments "dfir" prompt version (AC2/AC5).
	Version string
}

// Incident is the DFIR runner's input: the IncidentFinalised event (the
// invocation trigger) plus the redacted-by-the-provider evidence package and the
// persisted Senior ThreatAssessment (BI-9). The evidence package carries the
// WorkloadPosture and the events; the ThreatAssessment carries the ATT&CK
// techniques and kill-chain stage. All raw evidence is on Package, where the
// provider's pre-send Redact() guards it (AC4). A nil Assessment is tolerated (a
// finalisation may carry no persisted assessment); the report then omits the
// technique annotations.
type Incident struct {
	Event      settling.IncidentFinalised
	Package    schema.EvidencePackage
	Assessment *schema.ThreatAssessment
}

// ReportPublisher announces a generated report on REPORTS.generated (AC5). The
// one-method seam lets the agent's tests inject a capturing fake without a real
// NATS connection (the AssessmentAuditPublisher precedent).
type ReportPublisher interface {
	PublishReportGenerated(ctx context.Context, evt ReportGenerated) error
}

// AuditRecorder records the DFIR call in AUDIT.assessments via the role-keyed
// "dfir" maps, alongside the existing l1/l2/senior keys (AC5). The seam keeps
// this package free of an internal/response/audit import on the failure path
// projection; the cmd caller supplies a concrete recorder.
type AuditRecorder interface {
	RecordDFIRAssessment(ctx context.Context, rec DFIRAuditRecord) error
}

// DFIRAuditRecord is the ring-clean projection the AuditRecorder serialises onto
// AUDIT.assessments. It carries only schema-typed / plain fields; nothing here
// references the audit package. RedactedEvidence is the package AFTER the
// provider's Redact() (the bytes the LLM saw), NOT the raw package. Status is
// the bounded outcome enum: a fail-closed degrade records the failure so the
// audit trail covers it (OA5).
type DFIRAuditRecord struct {
	PackageID        string
	WorkloadID       string
	PromptVersion    string
	Provider         string
	Model            string
	Status           string
	RedactedEvidence schema.EvidencePackage
	Now              time.Time
}

// Agent is the DFIR forensic-report runner. Construct with NewDFIR; drive one
// finalisation with Generate (the consumer loop in main.go owns the JetStream
// fetch/ack discipline and the idempotency cursor).
type Agent struct {
	provider provider.Provider
	// spec is hot-swappable (Story 3.13): the prompt-store reload callback
	// calls SetPrompt to swap the ConfigMap-loaded DFIR prompt and its hash
	// without rebuilding the agent. Generate loads the current spec at call
	// time, so a reload is picked up on the NEXT call.
	spec    atomic.Pointer[PromptSpec]
	reports ReportPublisher
	audit   AuditRecorder
	schema  *jsonschema.Schema
	gen     *prometheus.CounterVec
	genSecs prometheus.Histogram
	log     *slog.Logger
	now     func() time.Time
	// seen tracks finalisations already reported this process, keyed on
	// settling.FinalisedMsgID, so a JetStream redelivery does not emit a second
	// report (BI-10 consumer-side idempotency; the LimitsPolicy stream can
	// redeliver an un-acked or post-dedup-window duplicate).
	seenMu sync.Mutex
	seen   map[string]struct{}
}

// schemaCompiler compiles the embedded report schema exactly once per process
// (the analyst schemaCompiler precedent); a compile failure is a build-artifact
// corruption and fails every constructor with the same error.
type schemaCompiler struct {
	once sync.Once
	sch  *jsonschema.Schema
	err  error
}

func (c *schemaCompiler) compiled() (*jsonschema.Schema, error) {
	c.once.Do(func() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(forensicSchemaJSON))
		if err != nil {
			c.err = fmt.Errorf("dfir: unmarshal embedded forensic_report schema: %w", err)
			return
		}
		comp := jsonschema.NewCompiler()
		if err := comp.AddResource("forensic_report_schema.json", doc); err != nil {
			c.err = fmt.Errorf("dfir: add forensic_report resource: %w", err)
			return
		}
		sch, err := comp.Compile("forensic_report_schema.json")
		if err != nil {
			c.err = fmt.Errorf("dfir: compile forensic_report schema: %w", err)
			return
		}
		c.sch = sch
	})
	return c.sch, c.err
}

var reportSchema = &schemaCompiler{}

// SetPrompt atomically swaps the DFIR system prompt and its version (Story 3.13
// hot-reload). Safe for concurrent callers against Generate.
func (a *Agent) SetPrompt(spec PromptSpec) { a.spec.Store(&spec) }

// currentSpec returns the active prompt spec (never nil after NewDFIR).
func (a *Agent) currentSpec() PromptSpec {
	if sp := a.spec.Load(); sp != nil {
		return *sp
	}
	return PromptSpec{}
}

// NewDFIR builds the DFIR agent on an already-constructed provider (per-role
// provider selection is the wiring layer's job, mirroring NewL1/NewSenior). The
// reports publisher and audit recorder are the AC5 emission seams; either may be
// nil in a degraded wiring (the agent still generates and renders, just does not
// announce/audit). It registers (or re-uses) the DFIR generation metric family.
func NewDFIR(p provider.Provider, spec PromptSpec, reports ReportPublisher, audit AuditRecorder, reg *metrics.Registry, log *slog.Logger) (*Agent, error) {
	if p == nil {
		return nil, errors.New("dfir: nil provider")
	}
	if log == nil {
		log = slog.Default()
	}
	sch, err := reportSchema.compiled()
	if err != nil {
		return nil, err
	}
	gen, err := reg.RegisterCounterVec("olaitan_dfir_reports_total",
		"DFIR forensic-report generation outcomes by status {success, unavailable, schema_violation} (Story 4.4 FR43).",
		[]string{"status"})
	if err != nil {
		return nil, fmt.Errorf("dfir: generation metric: %w", err)
	}
	// NFR7 observability seam (BI-11): the FSM-finalisation -> report-generated
	// latency against the 10s p99 end-to-end target. The S3 persist tail is
	// Story 4.6; 4.4 owns the dominant generation share.
	genSecs, err := reg.RegisterHistogram("olaitan_dfir_report_generation_seconds", "",
		"DFIR forensic-report generation latency in seconds, from agent invocation to rendered report (Story 4.4, NFR7 p99 <= 10s end-to-end).",
		nil, prometheus.DefBuckets)
	if err != nil {
		return nil, fmt.Errorf("dfir: generation-latency metric: %w", err)
	}
	a := &Agent{
		provider: p,
		reports:  reports,
		audit:    audit,
		schema:   sch,
		gen:      gen,
		genSecs:  genSecs,
		log:      log,
		now:      func() time.Time { return time.Now().UTC() },
		seen:     make(map[string]struct{}),
	}
	a.spec.Store(&spec)
	return a, nil
}

// ProviderName exposes the DFIR provider's metric label.
func (a *Agent) ProviderName() string { return a.provider.Name() }

// Generate runs one DFIR report for inc and returns the rendered artifact (the
// announced ReportGenerated metadata is published as a side effect). It is
// IDEMPOTENT on settling.FinalisedMsgID(inc.Event): a redelivery of the same
// finalisation drops-and-returns (reported=false) without a second provider call
// or a second emission (BI-10).
//
// FAIL-CLOSED + AUDIT (OA5): a provider-unavailable result, a truncated reply,
// or a schema failure after the bounded retry generates NO report, records the
// failure in AUDIT.assessments, and returns the wrapped sentinel. The caller
// acks the message regardless (a malformed report is never persisted).
//
// TRUST-BOUND FENCE (BI-12): Generate produces an ARTIFACT + a metric ONLY. It
// makes no GuardCappedConfidence call, holds no LLMCappedConfidence field, and
// never feeds the ThreatScore or the FSM.
func (a *Agent) Generate(ctx context.Context, inc Incident) (rendered string, reported bool, err error) {
	msgID := settling.FinalisedMsgID(inc.Event)
	if a.alreadySeen(msgID) {
		a.log.Info("dfir: duplicate finalisation, dropping (idempotency)",
			"incident_id", inc.Event.PackageID, "workload_id", inc.Event.WorkloadID, "msg_id", msgID)
		return "", false, nil
	}

	spec := a.currentSpec()
	start := time.Now()
	report, gerr := a.callAndValidate(ctx, inc, spec)
	latency := time.Since(start)

	if gerr != nil {
		status := statusUnavailable
		if errors.Is(gerr, ErrSchemaViolation) {
			status = statusSchemaViolation
		}
		a.record(status, inc, spec, latency)
		// Mark seen even on failure: the message is acked (fail-closed), so a
		// redelivery must not re-attempt and re-fail the same finalisation.
		a.markSeen(msgID)
		return "", false, gerr
	}

	rendered = report.Render(inc.Event)
	a.markSeen(msgID)
	a.record(statusSuccess, inc, spec, latency)

	// Announce on REPORTS.generated (AC5). The URL is the COMPUTED
	// content-addressed key (OA4); the durable write is Story 4.6.
	if a.reports != nil {
		sha := reportSHA256(rendered)
		evt := ReportGenerated{
			SchemaVersion: SchemaVersionReportGenerated,
			IncidentID:    report.IncidentID,
			WorkloadID:    inc.Event.WorkloadID,
			ReportSHA256:  sha,
			ReportURL:     contentAddressedKey(report.ReportGeneratedAt, sha),
			FinalFSMState: report.FinalFSMState,
			GeneratedAt:   report.ReportGeneratedAt,
		}
		if perr := a.reports.PublishReportGenerated(ctx, evt); perr != nil {
			// A failed announce is logged but not fatal: the report was
			// generated; the durable write (Story 4.6) is the system of record.
			a.log.Warn("dfir: report announcement publish failed",
				"incident_id", report.IncidentID, "err", perr)
		}
	}
	return rendered, true, nil
}

// callAndValidate issues the provider call (transport owns redaction, transport
// retry, and the per-role 120s budget), checks for truncation, validates the
// JSON against the embedded schema, and stamps the deterministic front-matter
// from the incident (AC2: sourced, not invented). It returns the assembled
// ForensicReport or a wrapped sentinel.
//
// Grounding (round-1 review follow-up R1-HIGH-1): the narrative is grounded via
// the contract-safe Request.PriorAssessment channel (Olaitan's own verdict,
// angle-escaped by the transport), chosen by groundingAssessment. The evidence
// still travels exclusively on Request.Package; the fixed Prompt carries no
// incident specifics, so the redaction contract stays intact.
//
// AC6 bounded retry (round-1 review follow-up R1-MED-1): a SCHEMA violation
// retries the provider call up to dfirSchemaAttempts total times before failing
// closed. A provider-unavailable result or a truncation is NOT retried here.
func (a *Agent) callAndValidate(ctx context.Context, inc Incident, spec PromptSpec) (ForensicReport, error) {
	var zero ForensicReport

	// Choose the grounding assessment ONCE (its Reasoning carries the
	// pod-name-free, event-id-free transition summary; techniques source off it).
	grounding := groundingAssessment(inc)

	req := provider.Request{
		Role:    provider.RoleDFIR,
		Package: inc.Package,
		Prompt:  provider.Prompt{System: spec.System, User: dfirUserInstruction},
		// Defensive copy: the embedded backing array is shared with the
		// compiled validator; a misbehaving provider mutating req.Schema in
		// place must not corrupt every later call.
		Schema: provider.JSONSchema(bytes.Clone(forensicSchemaJSON)),
		// PriorAssessment is the contract-safe grounding channel: Olaitan's own
		// verdict (NOT raw runtime evidence), framing-escaped by the transport.
		PriorAssessment: grounding,
	}

	var report ForensicReport
	var lastErr error
	for attempt := 1; attempt <= dfirSchemaAttempts; attempt++ {
		resp, err := a.provider.Analyse(ctx, req)
		if err != nil {
			// Provider failures are NOT retried here (the transport already
			// retried transient transport errors within the budget).
			return zero, fmt.Errorf("%w: %w", ErrProviderUnavailable, err)
		}
		// A reply cut off by the output-token ceiling is a hard FAILURE: a
		// truncated report must never be persisted, and it is NOT retried (BI-7).
		if isTruncated(resp.StopReason) {
			return zero, fmt.Errorf("%w: report truncated by the output-token ceiling (stop_reason=%q)", ErrProviderUnavailable, resp.StopReason)
		}

		rep, perr := parseForensicReport(a.schema, resp.Raw)
		if perr != nil {
			lastErr = fmt.Errorf("%w: %w", ErrSchemaViolation, perr)
			a.log.Warn("dfir: schema violation, retrying within bounded budget",
				"incident_id", inc.Event.PackageID, "attempt", attempt, "max_attempts", dfirSchemaAttempts, "err", perr)
			continue
		}
		report = rep
		// Capture the response-derived model id off the successful attempt.
		report.DFIRModel = firstNonEmpty(resp.Model, a.provider.Model())
		lastErr = nil
		break
	}
	if lastErr != nil {
		// Bounded retries exhausted on a schema violation: fail closed.
		return zero, lastErr
	}

	// Force-stamp the deterministic front-matter from the authoritative incident
	// (AC2): these fields are SOURCED, not whatever the model returned, so a
	// model that hallucinates a final_state or a technique cannot influence the
	// report header. Only the narrative remains the validated model output:
	// the posture findings are ALSO force-stamped from the package
	// WorkloadPosture (round-2 review follow-up: posture is unsourceable by the
	// model, so a model finding would be a hallucination), discarding any model
	// value. Techniques source off the SAME chosen grounding assessment (real ->
	// populated; synthesized -> empty -> the renderer prints "not recorded").
	report.SchemaVersion = SchemaVersionForensicReport
	report.IncidentID = inc.Event.PackageID
	report.FinalFSMState = inc.Event.FinalState
	report.ThreatScoreAtDecision = inc.Event.ThreatScore
	report.AttackTechniques = techniquesFromAssessment(grounding)
	// Force-stamp the posture findings from the package WorkloadPosture,
	// DISCARDING any model-supplied value (round-2 review follow-up: posture is
	// unsourceable by the model, so a model finding would be a hallucination, PO
	// Option A). In the 4.4 prod case the package carries no posture, so this is
	// nil and the renderer prints the honest "not recorded" line.
	report.ContributingPostureFindings = postureFindings(inc.Package)
	report.ContainmentActions = containmentFromHistory(inc.Event)
	report.ReportGeneratedAt = a.now()
	report.PromptHash = spec.Version
	report.DFIRProvider = a.provider.Name()
	return report, nil
}

// groundingAssessment chooses the ThreatAssessment that grounds the DFIR
// narrative (round-1 review follow-up R1-HIGH-1). If the incident carries a
// persisted assessment (the real/test enrichment path, carrying real
// MitreTechniques) it is used as-is. Otherwise it synthesises a MINIMAL
// assessment from the event: the recommended state is the final state, the total
// confidence is the threat score, and the reasoning is a deterministic,
// pod-name-free and event-id-free chronological summary of the FSM history (the
// same control-plane facts the timeline renders). MitreTechniques is nil and the
// kill-chain stage is empty, so techniques render as the honest "not recorded"
// gap (PO Option A). This is contract-safe: PriorAssessment is Olaitan's own
// verdict, NOT raw runtime evidence, and the transport angle-escapes it.
func groundingAssessment(inc Incident) *schema.ThreatAssessment {
	if inc.Assessment != nil {
		return inc.Assessment
	}
	return &schema.ThreatAssessment{
		RecommendedState: schema.PodSecurityState(inc.Event.FinalState),
		Confidence:       schema.ConfidenceScore{Total: inc.Event.ThreatScore},
		Reasoning:        historySummary(inc.Event),
	}
}

// historySummary renders the FSM transition history as a deterministic,
// pod-name-free, event-id-free chronological prose summary (the same control-
// plane facts as the rendered timeline). It NEVER includes pod names or raw
// event ids, so it is safe to carry on the PriorAssessment grounding channel.
func historySummary(evt settling.IncidentFinalised) string {
	if len(evt.History) == 0 {
		return "No FSM transition history was recorded for this incident; the workload settled in " +
			firstNonEmpty(evt.FinalState, "an unrecorded final state") + "."
	}
	var b strings.Builder
	b.WriteString("FSM transition history (control-plane facts only): ")
	for i, tr := range evt.History {
		if i > 0 {
			b.WriteString("; ")
		}
		ts := "unknown-time"
		if !tr.Timestamp.IsZero() {
			ts = tr.Timestamp.UTC().Format(time.RFC3339)
		}
		from := firstNonEmpty(strings.TrimSpace(string(tr.FromState)), "(none)")
		to := firstNonEmpty(strings.TrimSpace(string(tr.ToState)), "(none)")
		reason := firstNonEmpty(strings.TrimSpace(tr.Reason), "(no reason recorded)")
		fmt.Fprintf(&b, "at %s %s -> %s (reason: %s, confidence: %g)", ts, from, to, reason, tr.Confidence)
	}
	b.WriteString(".")
	return b.String()
}

// record increments the generation outcome counter, observes the latency
// histogram, projects the AUDIT.assessments "dfir" row, and emits one structured
// log line. Failure outcomes log at Warn so operators can filter on level.
func (a *Agent) record(status string, inc Incident, spec PromptSpec, latency time.Duration) {
	a.gen.WithLabelValues(status).Inc()
	a.genSecs.Observe(latency.Seconds())
	level := slog.LevelInfo
	if status != statusSuccess {
		level = slog.LevelWarn
	}
	a.log.Log(context.Background(), level, "dfir report generation",
		"incident_id", inc.Event.PackageID,
		"workload_id", inc.Event.WorkloadID,
		"provider", a.provider.Name(),
		"model", a.provider.Model(),
		"status", status,
		"latency_ms", latency.Milliseconds(),
		"prompt_version", spec.Version,
	)
	if a.audit == nil {
		return
	}
	// Project the DFIR row onto AUDIT.assessments via the role-keyed maps
	// (AC5). The RedactedEvidence reproduces the bytes the LLM saw by running
	// the same pure Redact() the provider ran; the cmd-side recorder performs
	// that projection so this package keeps no audit/redact import on the hot
	// path. We pass the RAW package here and the recorder redacts it (the
	// AssessmentInput contract: RedactionApplied is set true by the recorder).
	rec := DFIRAuditRecord{
		PackageID:        inc.Event.PackageID,
		WorkloadID:       inc.Event.WorkloadID,
		PromptVersion:    spec.Version,
		Provider:         a.provider.Name(),
		Model:            a.provider.Model(),
		Status:           status,
		RedactedEvidence: inc.Package,
		Now:              a.now(),
	}
	actx, cancel := context.WithTimeout(context.WithoutCancel(context.Background()), 2*time.Second)
	defer cancel()
	if aerr := a.audit.RecordDFIRAssessment(actx, rec); aerr != nil {
		a.log.Warn("dfir: assessment audit publish failed",
			"incident_id", inc.Event.PackageID, "err", aerr)
	}
}

// alreadySeen reports whether msgID has been processed; markSeen records it.
func (a *Agent) alreadySeen(msgID string) bool {
	a.seenMu.Lock()
	defer a.seenMu.Unlock()
	_, ok := a.seen[msgID]
	return ok
}

func (a *Agent) markSeen(msgID string) {
	a.seenMu.Lock()
	defer a.seenMu.Unlock()
	a.seen[msgID] = struct{}{}
}

// techniquesFromAssessment sources the ATT&CK technique annotations from the
// persisted ThreatAssessment.MitreTechniques (BI-8: reused, not invented). A nil
// assessment yields nil.
func techniquesFromAssessment(a *schema.ThreatAssessment) []string {
	if a == nil || len(a.MitreTechniques) == 0 {
		return nil
	}
	out := make([]string, 0, len(a.MitreTechniques))
	for _, t := range a.MitreTechniques {
		if strings.TrimSpace(t) != "" {
			out = append(out, t)
		}
	}
	return out
}

// postureFindings derives the contributing-posture finding strings from the
// package WorkloadPosture (round-2 review follow-up: force-stamped, NEVER
// model-supplied, so the model cannot fabricate posture it has no data for, PO
// Option A). A nil WorkloadPosture (the 4.4 prod case: the finalisation carries
// no posture snapshot) yields nil, and the renderer prints the honest "not
// recorded" line. This is deliberately MINIMAL: it surfaces the unambiguous,
// directly-readable posture facts (cluster-role bindings, over-broad RBAC verbs,
// privileged container contexts) and does NOT attempt a full posture analysis
// (the enrichment is the deferred follow-up). When posture is present but
// unavailable, the honest unavailable class is surfaced rather than a finding.
func postureFindings(pkg schema.EvidencePackage) []string {
	p := pkg.WorkloadPosture
	if p == nil {
		return nil
	}
	if p.Unavailable {
		reason := firstNonEmpty(strings.TrimSpace(p.UnavailableReason), "unknown")
		return []string{"posture unavailable (" + reason + ")"}
	}
	var out []string
	for _, crb := range p.ClusterRoleBindings {
		name := firstNonEmpty(strings.TrimSpace(crb.RoleName), strings.TrimSpace(crb.Name))
		if name == "" {
			continue
		}
		out = append(out, "cluster-role binding grants "+name)
	}
	for _, rb := range p.RoleBindings {
		name := firstNonEmpty(strings.TrimSpace(rb.RoleName), strings.TrimSpace(rb.Name))
		if name == "" {
			continue
		}
		out = append(out, "role binding grants "+name)
	}
	for _, csc := range p.ContainerSecurityContexts {
		if csc.Privileged != nil && *csc.Privileged {
			name := firstNonEmpty(strings.TrimSpace(csc.ContainerName), "(unnamed container)")
			out = append(out, "privileged container security context on "+name)
		}
	}
	return out
}

// containmentFromHistory derives the containment actions Olaitan took from the
// FSM transition history (AC3): every distinct non-CLEAN ToState reached, in
// order, rendered as a human-readable action. An empty history (the controller
// never blocks finalisation on history, BI-9) falls back to the final state
// alone, so the report always names at least the settled containment.
func containmentFromHistory(evt settling.IncidentFinalised) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, tr := range evt.History {
		st := string(tr.ToState)
		if st == "" || st == "CLEAN" {
			continue
		}
		if _, dup := seen[st]; dup {
			continue
		}
		seen[st] = struct{}{}
		out = append(out, "applied "+st)
	}
	if len(out) == 0 && evt.FinalState != "" {
		out = append(out, "applied "+evt.FinalState)
	}
	return out
}

// firstNonEmpty returns a if non-empty, else b.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// isTruncated reports whether the provider stop reason marks an
// output-token-ceiling truncation (case-insensitive; the analyst convention).
// "max_tokens" (claude), "length" (openai_compat / ollama).
func isTruncated(stopReason string) bool {
	return strings.EqualFold(stopReason, "max_tokens") || strings.EqualFold(stopReason, "length")
}
