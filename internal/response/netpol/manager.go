// Package netpol implements the Story 2.4 RESTRICTED-state
// NetworkPolicyManager (FR33/NFR6). When the response-ring FSM transitions
// a workload into RESTRICTED, the manager applies a Kubernetes
// NetworkPolicy that allows egress only to the RFC 1918 private ranges, the
// cluster pod/service CIDRs, and operator-supplied extra CIDRs, and blocks
// all other (external) egress, so a suspect workload cannot exfiltrate to
// the internet while internal cluster traffic continues to flow.
//
// The manager is a fsm.TransitionSink: it is fanned out alongside the
// Story 2.3 Redis persistence sink via fsm.MultiSink (BI-3). Publish is
// non-blocking (it enqueues onto a bounded channel); a background Run
// worker performs the K8s apply, so the FSM goroutine is never blocked on
// the API server (BI-4). A periodic reconcile garbage-collects policies
// whose workload has been deleted (AC4, BI-10).
//
// Ring discipline (BI-2): this package is Ring 4 (response) and takes a
// kubernetes.Interface directly. It does NOT import internal/collector/* or
// internal/decision/*; the posture NetworkPolicy reader is a copy reference
// only.
package netpol

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	networkingv1 "k8s.io/api/networking/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"

	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/schema"
)

// defaults for the bounded queue and reconcile cadence.
const (
	defaultQueueSize         = 256
	defaultReconcileInterval = 30 * time.Second
)

// errNilClientset is returned by New when cs is nil.
var errNilClientset = errors.New("netpol: nil clientset")

// StateOracle is the one-method seam the reconcile backstop uses to learn a
// workload's CURRENT FSM target so it can converge the workload's managed
// NetworkPolicies to that target's desired-set membership (Story 2.6, BI-2c).
// It is defined HERE (in netpol) rather than imported from internal/response/fsm
// so the Manager depends on a structural one-method interface, not the whole
// fsm.Machine: the package body stays Ring-clean and unit tests can inject a
// fake oracle without constructing an FSM. *fsm.Machine satisfies it via its
// exported CurrentState method, wired at the cmd/olaitan call site.
//
// CurrentState returns the workload's current state and ok=true when the FSM
// is actively tracking the workload, or (StateClean, false) when the FSM has
// no opinion (never-seen workload, or a workload not restored after an FSM
// restart). A nil oracle falls back to the shipped Story 2.5 reconcile
// behaviour (BI-2c), so the seam is optional.
type StateOracle interface {
	CurrentState(workloadID string) (schema.PodSecurityState, bool)
}

// Story 2.8 audit action values (BI-9). These label which kind of cluster
// mutation an AUDIT.policies event records. They are defined HERE (in netpol)
// so the manager emits them at its real mutation points without importing the
// audit/subjects packages; the audit adapter maps them onto the wire event.
const (
	// AuditActionApply is a real NetworkPolicy create or update (result
	// applied), NOT an idempotent noop (BI-9).
	AuditActionApply = "apply"
	// AuditActionSupersedeDelete is an inline or reconcile delete of a policy
	// superseded by a tighter/looser target (escalation/de-escalation residue).
	AuditActionSupersedeDelete = "supersede_delete"
	// AuditActionDeescalationRemove is a de-escalation removal of a workload's
	// managed policies (SUSPICIOUS/CLEAN, or the reconcile de-escalation
	// residue), emitted once per converged removal (BI-9).
	AuditActionDeescalationRemove = "deescalation_remove"
	// AuditActionGCDelete is an orphan-GC delete of a policy whose owner is gone.
	AuditActionGCDelete = "gc_delete"
)

// Story 2.8 policy_kind and spec_summary closed enums (BI-4.3/BI-11). policy_kind
// reflects which deterministic-name family the policy belongs to; spec_summary is
// a compact rendering of the policy shape, NOT a full-object diff.
const (
	AuditPolicyKindRestricted  = "restricted"
	AuditPolicyKindQuarantined = "quarantined"

	AuditSpecEgressAllowlist = "egress_allowlist"
	AuditSpecDenyAll         = "deny_all"
	AuditSpecRemoved         = "removed"
)

// PolicyAuditEvent carries the facts the manager already knows at each real
// mutation point so the audit adapter can project them onto the AUDIT.policies
// wire event (Story 2.8, BI-3.1). It is a netpol-package struct so the manager
// builds it without importing internal/nats or internal/subjects.
type PolicyAuditEvent struct {
	// Action is one of the AuditAction* constants (BI-9).
	Action string
	// WorkloadID, Namespace, PolicyName identify the mutated policy.
	WorkloadID string
	Namespace  string
	PolicyName string
	// PolicyKind is restricted/quarantined (BI-4.3), derived from the policy
	// name family.
	PolicyKind string
	// FSMState is the FSM state that caused this mutation (BI-3.4).
	FSMState string
	// Result is the apply-result string (applied/superseded/removed/gc_deleted)
	// mirroring the metric the mutation counts (BI-9).
	Result string
	// SpecSummary is the compact policy-shape enum (BI-4.3/BI-11):
	// egress_allowlist / deny_all / removed.
	SpecSummary string
	// PackageID is the triggering package id when present.
	PackageID string
}

// PolicyAuditPublisher is the Story 2.8 one-method audit seam (BI-3). The
// manager calls PublishPolicyAudit at each real mutation point so a NATS-backed
// adapter (wired at cmd/olaitan, living in internal/response/audit) can publish
// an append-only AUDIT.policies event. It is defined HERE rather than imported
// so netpol gains NO internal/nats or internal/subjects import and stays
// Ring-clean, exactly like the StateOracle precedent above. PublishPolicyAudit
// MUST be NON-blocking (fire-and-forget): a NATS stall must never wedge the
// apply worker and delay an NFR6-critical NetworkPolicy apply (BI-5.3). A nil
// publisher means no audit (off-by-default, the nil-oracle precedent).
type PolicyAuditPublisher interface {
	PublishPolicyAudit(evt PolicyAuditEvent)
}

// Config configures a Manager.
type Config struct {
	// ClusterCIDRs are the cluster pod/service CIDRs allowed for egress.
	ClusterCIDRs []string
	// ExtraAllowedCIDRs are additional operator-allowed egress CIDRs.
	ExtraAllowedCIDRs []string
	// ExcludedNamespaces are never enforced (e.g. kube-system, the Olaitan
	// namespace). A transition for a workload in one of these is skipped.
	ExcludedNamespaces []string
	// ReconcileInterval is the orphan-GC cadence; defaults to 30s.
	ReconcileInterval time.Duration
	// QueueSize bounds the Publish buffer; defaults to 256.
	QueueSize int
}

// Manager applies and garbage-collects RESTRICTED NetworkPolicies.
type Manager struct {
	cs          kubernetes.Interface
	log         *slog.Logger
	now         func() time.Time
	egressRules []networkingv1.NetworkPolicyEgressRule
	excluded    map[string]struct{}
	reconcile   time.Duration
	queue       chan schema.StateTransition

	// oracle is the optional FSM-target query seam (Story 2.6, BI-2c). When
	// non-nil, the reconcile backstop converges each workload's managed
	// policies to the desired set of the workload's CURRENT FSM target. When
	// nil, the backstop retains the shipped Story 2.5 "quarantine object wins"
	// supersession behaviour so the change is backward-compatible. Set once at
	// wiring time via SetStateOracle; never mutated after Run starts.
	oracle StateOracle

	// audit is the optional Story 2.8 audit seam (BI-3). When non-nil, the
	// manager fires a non-blocking PublishPolicyAudit at each real mutation
	// point (apply/supersede/de-escalation/gc) so the mutation is recorded on
	// the append-only AUDIT.policies subject. nil = no audit (off-by-default,
	// the nil-oracle precedent). Set once at wiring time via
	// SetPolicyAuditPublisher, before Run; read-only for the worker thereafter.
	audit PolicyAuditPublisher

	applySeconds prometheus.Histogram
	applyTotal   *prometheus.CounterVec
}

// New constructs a Manager. cs must be non-nil. registry may be nil to skip
// metric registration (test fixtures). The egress allow-list is precomputed
// once from RFC 1918 plus the configured cluster and extra CIDRs.
func New(cfg Config, cs kubernetes.Interface, registry *metrics.Registry, log *slog.Logger) (*Manager, error) {
	if cs == nil {
		return nil, errNilClientset
	}
	if log == nil {
		log = slog.Default()
	}
	allow := make([]string, 0, len(rfc1918)+len(cfg.ClusterCIDRs)+len(cfg.ExtraAllowedCIDRs))
	allow = append(allow, rfc1918...)
	allow = append(allow, cfg.ClusterCIDRs...)
	allow = append(allow, cfg.ExtraAllowedCIDRs...)

	excluded := make(map[string]struct{}, len(cfg.ExcludedNamespaces))
	for _, ns := range cfg.ExcludedNamespaces {
		excluded[ns] = struct{}{}
	}

	reconcile := cfg.ReconcileInterval
	if reconcile <= 0 {
		reconcile = defaultReconcileInterval
	}
	qsize := cfg.QueueSize
	if qsize <= 0 {
		qsize = defaultQueueSize
	}

	m := &Manager{
		cs:          cs,
		log:         log,
		now:         time.Now,
		egressRules: buildEgressRules(allow),
		excluded:    excluded,
		reconcile:   reconcile,
		queue:       make(chan schema.StateTransition, qsize),
	}
	if registry != nil {
		if err := m.registerMetrics(registry); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// SetStateOracle installs the optional FSM-target query seam (Story 2.6,
// BI-2c). It is a setter rather than a New parameter because the FSM Machine
// is constructed AFTER the Manager in cmd/olaitan (the Manager is a sink fanned
// into the very Machine that would be the oracle), so wiring at construction
// would be a chicken-and-egg. Call it once, before Run starts, while the
// Manager is still single-threaded; the field is then read-only for the worker.
// A nil oracle leaves the shipped Story 2.5 reconcile behaviour in place.
func (m *Manager) SetStateOracle(o StateOracle) {
	m.oracle = o
}

// SetPolicyAuditPublisher installs the optional Story 2.8 audit seam (BI-3).
// Like SetStateOracle, it is a setter rather than a New parameter because the
// audit adapter is wired at cmd/olaitan after the manager exists, and is
// installed once before Run starts while the Manager is still single-threaded;
// the field is then read-only for the worker. A nil publisher leaves auditing
// off (the nil-oracle precedent), so the seam is fully optional and Ring-clean.
func (m *Manager) SetPolicyAuditPublisher(p PolicyAuditPublisher) {
	m.audit = p
}

// auditPolicy fires a non-blocking audit event when a publisher is installed
// (BI-3/BI-5.3). It is a guarded no-op when m.audit == nil. It is called only
// at real mutation success/converge points (BI-9), AFTER the mutation succeeds
// and AFTER m.count(result), so the audit mirrors exactly what the metric
// counts and never claims a mutation that did not happen.
func (m *Manager) auditPolicy(evt PolicyAuditEvent) {
	if m.audit == nil {
		return
	}
	m.audit.PublishPolicyAudit(evt)
}

// policyKindFor reports the audit policy_kind enum (BI-4.3) for the FSM state
// whose desired set the policy belongs to. RESTRICTED renders the egress
// allow-list (restricted); QUARANTINED renders the deny-all (quarantined).
func policyKindFor(state schema.PodSecurityState) string {
	if state == schema.StateQuarantined {
		return AuditPolicyKindQuarantined
	}
	return AuditPolicyKindRestricted
}

// specSummaryFor reports the audit spec_summary enum (BI-4.3/BI-11) for an
// applied policy of the given state: deny_all for QUARANTINED, egress_allowlist
// for RESTRICTED.
func specSummaryFor(state schema.PodSecurityState) string {
	if state == schema.StateQuarantined {
		return AuditSpecDenyAll
	}
	return AuditSpecEgressAllowlist
}

// auditReconcileDelete emits a Story 2.8 AUDIT.policies event for a reconcile-
// driven delete (BI-9). The mutation facts come from the live policy object:
// fsm_state is the policy's own AnnFSMState annotation (the FSM state that
// caused the policy to exist, BI-3.4), policy_kind is derived from it, and the
// spec_summary is "removed" because this records a delete. No package_id is
// available on the reconcile path (no triggering EvidencePackage). Called only
// after the delete succeeds and after m.count(result) (BI-9), so the audit
// mirrors exactly what the metric counts and never records a phantom mutation.
func (m *Manager) auditReconcileDelete(np *networkingv1.NetworkPolicy, action, result string) {
	m.auditPolicy(PolicyAuditEvent{
		Action:      action,
		WorkloadID:  np.Annotations[AnnWorkloadID],
		Namespace:   np.Namespace,
		PolicyName:  np.Name,
		PolicyKind:  policyKindFor(schema.PodSecurityState(np.Annotations[AnnFSMState])),
		FSMState:    np.Annotations[AnnFSMState],
		Result:      result,
		SpecSummary: AuditSpecRemoved,
	})
}

func (m *Manager) registerMetrics(r *metrics.Registry) error {
	h, err := r.RegisterHistogram(
		"olaitan_response_network_policy_apply_seconds",
		"",
		"End-to-end latency from the FSM RESTRICTED/QUARANTINED transition timestamp to NetworkPolicy apply completion (Story 2.4, NFR6 p99 <= 1s).",
		nil,
		[]float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5},
	)
	if err != nil {
		return err
	}
	m.applySeconds = h

	cv, err := r.RegisterCounterVec(
		"olaitan_response_network_policy_apply_total",
		"Cumulative NetworkPolicy enforcement actions labelled by result: applied, noop, error, skipped, dropped, gc_deleted, superseded, removed (Story 2.4/2.6, FR33/FR35). removed counts a de-escalation removal of a workload's managed policies (SUSPICIOUS/CLEAN inline path, or a reconcile delete driven by the workload's FSM target dropping below the policy's state).",
		[]string{"result"},
	)
	if err != nil {
		return err
	}
	m.applyTotal = cv
	// Pre-initialise every known result label to 0 so alert PromQL has a
	// stable zero series from process startup, rather than a label series that
	// only materialises on first occurrence. "removed" is the Story 2.6
	// de-escalation removal label (BI-7).
	for _, result := range []string{"applied", "noop", "error", "skipped", "dropped", "gc_deleted", "superseded", "removed"} {
		cv.WithLabelValues(result).Add(0)
	}
	return nil
}

// count increments the apply-result counter when metrics are registered.
func (m *Manager) count(result string) {
	if m.applyTotal != nil {
		m.applyTotal.WithLabelValues(result).Inc()
	}
}

// enforcedState reports whether a transition INTO state has a managed-policy
// desired set the manager converges to by APPLYING a policy (Story 2.5/2.6,
// BI-1). It is true for RESTRICTED (Story 2.4 egress allow-list) and
// QUARANTINED (Story 2.5 deny-all). The sibling removalState (below) covers the
// states whose desired set is EMPTY (SUSPICIOUS/CLEAN), which the manager
// converges to by REMOVING policies. Under the Story 2.6 desired-state-per-target
// model each enforced target DEFINES the managed set: entering RESTRICTED also
// removes any quarantine policy (deleteSupersededQuarantine), and entering
// QUARANTINED removes any restricted policy (deleteSupersededRestricted), so the
// two enforced states own a one-policy desired set and the two removal states
// own the empty set. Publish enqueues a transition when EITHER predicate holds;
// every other ToState (only PRESERVED_KILLED remains, which Evaluate never
// produces) is dropped.
func enforcedState(s schema.PodSecurityState) bool {
	return s == schema.StateRestricted || s == schema.StateQuarantined
}

// removalState reports whether a transition INTO state has an EMPTY managed-policy
// desired set (Story 2.6, BI-1/BI-4): SUSPICIOUS is a sensing-only state with no
// NetworkPolicy isolation, and CLEAN is fully recovered, so for both the manager
// REMOVES every Olaitan-managed policy for the workload (CLEAN additionally
// verifies absence, BI-5). It is the sibling of enforcedState in the
// desired-state-per-target model.
func removalState(s schema.PodSecurityState) bool {
	return s == schema.StateSuspicious || s == schema.StateClean
}

// Publish is the fsm.TransitionSink seam (BI-3, BI-5). It acts on a transition
// INTO any state with a defined managed-policy desired set: the enforced states
// (RESTRICTED/QUARANTINED) that APPLY a policy, and the removal states
// (SUSPICIOUS/CLEAN) that REMOVE all managed policies (Story 2.6, BI-1). It
// enqueues for the async worker without blocking the FSM goroutine; on a full
// queue it drops with a metric rather than stalling the hot path (BI-4).
func (m *Manager) Publish(st schema.StateTransition) {
	if !enforcedState(st.ToState) && !removalState(st.ToState) {
		return
	}
	select {
	case m.queue <- st:
	default:
		m.log.Warn("netpol: apply queue full; dropping transition", "workload_id", st.WorkloadID, "to_state", st.ToState)
		m.count("dropped")
	}
}

// Run is the background worker (BI-4). It applies queued RESTRICTED/QUARANTINED
// transitions and runs the orphan-GC reconcile on a ticker. Wire it into
// the errgroup. It returns nil on graceful context cancellation.
func (m *Manager) Run(ctx context.Context) error {
	ticker := time.NewTicker(m.reconcile)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case st := <-m.queue:
			m.handle(ctx, st)
		case <-ticker.C:
			m.reconcileGC(ctx)
		}
	}
}

// handle resolves the workload's pod selector and applies the RESTRICTED/QUARANTINED
// policy idempotently, recording the apply latency against the transition
// timestamp for the NFR6 budget (AC2).
func (m *Manager) handle(ctx context.Context, st schema.StateTransition) {
	ref, err := parseWorkloadID(st.WorkloadID)
	if err != nil {
		m.log.Warn("netpol: cannot parse workload id; skipping", "workload_id", st.WorkloadID, "err", err)
		m.count("error")
		return
	}
	if _, skip := m.excluded[ref.namespace]; skip {
		m.count("skipped")
		return
	}

	// De-escalation removal (Story 2.6, BI-4/BI-5): SUSPICIOUS and CLEAN have an
	// EMPTY managed-policy desired set, so the manager REMOVES both managed
	// policies for the workload rather than applying one. This branch runs
	// BEFORE resolveSelector: removal needs no podSelector, and a de-escalating
	// workload whose owner is being torn down could fail selector resolution,
	// yet its policies must still be cleared. CLEAN additionally verifies absence
	// via a follow-up read (BI-5).
	if removalState(st.ToState) {
		m.removeManaged(ctx, ref, st.WorkloadID, st.PackageID, st.ToState == schema.StateClean)
		return
	}

	sel, err := m.resolveSelector(ctx, ref)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// The workload was deleted before we could enforce; nothing to do.
			m.count("skipped")
			return
		}
		if isNonEnforceable(err) {
			// Non-transient, non-enforceable outcomes: an unsupported owner
			// kind (including CronJob, which has no spec.selector), an
			// unlabelled orphan pod, or an owner that resolves to an empty
			// selector (which would block the whole namespace). None of these
			// are failures to enforce a policy we could have applied; count
			// them as skipped and log at debug, not error level.
			m.log.Debug("netpol: workload not enforceable; skipping apply",
				"workload_id", st.WorkloadID, "owner_kind", ref.ownerKind, "err", err)
			m.count("skipped")
			return
		}
		// A genuine transient API error (timeout, 5xx, conflict): count as
		// error so the alert fires and the FSM re-emit retries.
		m.log.Warn("netpol: cannot resolve pod selector; skipping apply",
			"workload_id", st.WorkloadID, "owner_kind", ref.ownerKind, "err", err)
		m.count("error")
		return
	}

	np := m.buildPolicy(ref, sel, st)
	result, err := m.apply(ctx, np)
	if err != nil {
		m.log.Warn("netpol: apply failed", "workload_id", st.WorkloadID, "policy", np.Name, "err", err)
		m.count("error")
		return
	}
	// NFR6 budget: record latency only on a successful apply/noop, never on
	// the error path, so failed-apply durations do not skew the histogram.
	// The QUARANTINED apply feeds the same histogram as RESTRICTED (AC3).
	if m.applySeconds != nil && !st.Timestamp.IsZero() {
		m.applySeconds.Observe(m.now().Sub(st.Timestamp).Seconds())
	}
	m.count(result)
	m.log.Info("netpol: policy applied",
		"workload_id", st.WorkloadID, "policy", np.Name, "namespace", np.Namespace, "to_state", st.ToState, "result", result)

	// Story 2.8 audit (BI-9): emit AUDIT.policies on a REAL apply (applied =
	// create/update) only, NOT a noop (an idempotent re-apply that changed
	// nothing in the cluster is not a mutation and would flood the stream on
	// every reconcile of an unchanged policy). fsm_state is st.ToState, the
	// transition that drove the apply (BI-3.4). Emitted after m.count so the
	// audit mirrors the metric.
	if result == "applied" {
		m.auditPolicy(PolicyAuditEvent{
			Action:      AuditActionApply,
			WorkloadID:  st.WorkloadID,
			Namespace:   np.Namespace,
			PolicyName:  np.Name,
			PolicyKind:  policyKindFor(st.ToState),
			FSMState:    string(st.ToState),
			Result:      result,
			SpecSummary: specSummaryFor(st.ToState),
			PackageID:   st.PackageID,
		})
	}

	// Atomic replacement (BI-5): ONLY after the QUARANTINED deny-all policy is
	// confirmed applied do we best-effort delete the superseded RESTRICTED
	// policy for the same workload. Apply-before-delete is the load-bearing
	// invariant because it is MONOTONICALLY TIGHTENING. Kubernetes
	// NetworkPolicies are additive allow-lists: while both policies select the
	// pod, ingress is denied immediately (only the QUARANTINED policy declares
	// the Ingress policyType, with no allow rules), and egress remains the UNION
	// of both policies' allows, i.e. still the RESTRICTED allow-list
	// (RFC1918/cluster/DNS) - the deny-all does NOT subtract or override those
	// allows. Egress only tightens to deny-all once the RESTRICTED policy is
	// removed. There is therefore never a window LESS protected than RESTRICTED,
	// and never a policy-less window. A failed inline delete does NOT fail the
	// QUARANTINED enforcement: ingress is already denied, but a LINGERING
	// RESTRICTED policy keeps egress at the allow-list level, so the workload is
	// not yet fully isolated. The reconcile backstop (reconcileGC, FIX A) removes
	// a restricted policy a failed inline delete left behind within one reconcile
	// interval, converging egress to deny-all; orphan GC alone would NOT reap it
	// while the owner still exists.
	// Defense-in-depth gate (apply-before-delete made explicit): only supersede
	// the restricted policy when the quarantine apply CONFIRMED the deny-all is
	// present. "applied" = created/updated; "noop" = an idempotent re-apply that
	// matched the live deny-all (so it is confirmed present). Any other result
	// (or an error path, which early-returns above) MUST NOT delete the
	// restricted policy: deleting it after a failed/absent quarantine apply would
	// leave a malicious workload unprotected. The upstream error early-returns
	// already guarantee this, but the gate states the invariant at the call site.
	if st.ToState == schema.StateQuarantined && (result == "applied" || result == "noop") {
		m.deleteSupersededRestricted(ctx, ref, st.WorkloadID, st.PackageID)
	}

	// De-escalation relaxation (Story 2.6, BI-2/BI-2a/BI-3): the EXACT MIRROR of
	// the escalation supersession above. On entering RESTRICTED, ONLY after the
	// restricted egress-only policy is CONFIRMED applied do we best-effort delete
	// the superseded QUARANTINED deny-all for the same workload. Apply-before-delete
	// is load-bearing here for the OPPOSITE reason: deleting the deny-all before
	// the restricted apply would momentarily revert the workload to NO Olaitan
	// egress restriction (fully open egress). During the brief overlap the
	// workload is selected by both policies: egress is already at the relaxed
	// restricted allow-list (the deny-all contributes no egress allows), and
	// ingress stays denied until the deny-all is gone, so the overlap is, if
	// anything, STRICTER than the final RESTRICTED state and never policy-less.
	// The same applied/noop gate as the QUARANTINED branch guarantees a failed
	// restricted apply early-returns above and never deletes the deny-all, so a
	// workload is never left with neither policy. A failed inline quarantine
	// delete self-heals via the FSM-target-aware reconcile backstop (BI-2c).
	if st.ToState == schema.StateRestricted && (result == "applied" || result == "noop") {
		m.deleteSupersededQuarantine(ctx, ref, st.WorkloadID, st.PackageID)
	}
}

// deleteSupersededRestricted best-effort deletes the RESTRICTED policy a
// QUARANTINED transition supersedes (BI-5 step 3). It MUST be called only
// after the quarantine apply has returned success (apply-before-delete). A
// NotFound is success (the workload may have skipped RESTRICTED, or the policy
// was already GC'd). A real delete failure is logged at WARN and swallowed so
// the QUARANTINED enforcement does not fail. Note that until the RESTRICTED
// policy is gone, egress remains at the RESTRICTED allow-list level: Kubernetes
// NetworkPolicies are additive allow-lists, so the deny-all QUARANTINED policy
// denies ingress immediately but does NOT subtract the RESTRICTED policy's
// egress allows. The reconcile backstop (reconcileGC, FIX A) guarantees a
// restricted policy this best-effort delete fails to remove is reaped within
// one reconcile interval, converging egress to deny-all (BI-7, Open Assumption 4).
func (m *Manager) deleteSupersededRestricted(ctx context.Context, ref workloadRef, workloadID, packageID string) {
	name := policyNameFor(schema.StateRestricted, workloadID)
	err := m.cs.NetworkingV1().NetworkPolicies(ref.namespace).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			m.log.Debug("netpol: no superseded RESTRICTED policy to delete",
				"workload_id", workloadID, "policy", name, "namespace", ref.namespace)
			return
		}
		m.log.Warn("netpol: failed to delete superseded RESTRICTED policy; quarantine still enforced",
			"workload_id", workloadID, "policy", name, "namespace", ref.namespace, "err", err)
		return
	}
	m.log.Info("netpol: deleted superseded RESTRICTED policy after quarantine apply",
		"workload_id", workloadID, "policy", name, "namespace", ref.namespace)
	// Story 2.8 audit (BI-9): a real RESTRICTED-policy delete superseded by the
	// QUARANTINED escalation. fsm_state is the NEW target that triggered the
	// supersession (QUARANTINED, BI-3.4); the deleted object is the restricted
	// policy. Emitted only on a successful delete (a NotFound early-returns
	// above), never on a failed one, so the audit never claims a phantom
	// mutation (BI-9).
	m.auditPolicy(PolicyAuditEvent{
		Action:      AuditActionSupersedeDelete,
		WorkloadID:  workloadID,
		Namespace:   ref.namespace,
		PolicyName:  name,
		PolicyKind:  AuditPolicyKindRestricted,
		FSMState:    string(schema.StateQuarantined),
		Result:      "superseded",
		SpecSummary: AuditSpecRemoved,
		PackageID:   packageID,
	})
}

// deleteSupersededQuarantine best-effort deletes the QUARANTINED deny-all
// policy a RESTRICTED de-escalation supersedes (Story 2.6, BI-2/BI-2a/BI-3): the
// EXACT MIRROR of deleteSupersededRestricted. It MUST be called only after the
// restricted apply has returned success (apply-before-delete). A NotFound is
// success (the workload may never have been quarantined, or the deny-all was
// already removed). A real delete failure is logged at WARN and swallowed so the
// RESTRICTED enforcement does not fail; until the deny-all is gone the workload
// stays slightly STRICTER than RESTRICTED (ingress denied), never less protected,
// and the FSM-target-aware reconcile backstop reaps the lingering deny-all within
// one reconcile interval (BI-2c, BI-6). The inline delete is silent best-effort
// accounting-wise (mirror of the escalation path): the meaningful action is the
// restricted apply, already counted (BI-7).
func (m *Manager) deleteSupersededQuarantine(ctx context.Context, ref workloadRef, workloadID, packageID string) {
	name := policyNameFor(schema.StateQuarantined, workloadID)
	err := m.cs.NetworkingV1().NetworkPolicies(ref.namespace).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			m.log.Debug("netpol: no superseded QUARANTINED policy to delete",
				"workload_id", workloadID, "policy", name, "namespace", ref.namespace)
			return
		}
		m.log.Warn("netpol: failed to delete superseded QUARANTINED policy; restricted still enforced",
			"workload_id", workloadID, "policy", name, "namespace", ref.namespace, "err", err)
		return
	}
	m.log.Info("netpol: deleted superseded QUARANTINED policy after restricted apply",
		"workload_id", workloadID, "policy", name, "namespace", ref.namespace)
	// Story 2.8 audit (BI-9): the EXACT MIRROR of deleteSupersededRestricted for
	// the RESTRICTED de-escalation. fsm_state is the NEW target that triggered
	// the supersession (RESTRICTED, BI-3.4); the deleted object is the
	// quarantined deny-all. Emitted only on a successful delete.
	m.auditPolicy(PolicyAuditEvent{
		Action:      AuditActionSupersedeDelete,
		WorkloadID:  workloadID,
		Namespace:   ref.namespace,
		PolicyName:  name,
		PolicyKind:  AuditPolicyKindQuarantined,
		FSMState:    string(schema.StateRestricted),
		Result:      "superseded",
		SpecSummary: AuditSpecRemoved,
		PackageID:   packageID,
	})
}

// removeManaged converges a workload's managed-policy set to EMPTY on a
// SUSPICIOUS/CLEAN de-escalation (Story 2.6, BI-4/BI-5). It deletes BOTH the
// RESTRICTED and QUARANTINED policies for the workload, treating IsNotFound on
// each as success (a workload that was never isolated, or one a prior step
// already cleared, is a successful no-op, never an error - BI-5). It does NOT
// resolve a podSelector (removal must proceed even when the owner is being torn
// down, BI-4); the excluded-namespace skip is applied by the caller. When verify
// is true (CLEAN, AC3) it follows each delete with a Get to confirm absence and,
// on a stray surviving policy, re-deletes once and re-Gets; a policy that still
// survives counts error and is left for the reconcile backstop (BI-6). A
// transient delete error counts error and logs WARN; the workload self-heals at
// the next reconcile. On full convergence it counts removed.
func (m *Manager) removeManaged(ctx context.Context, ref workloadRef, workloadID, packageID string, verify bool) {
	names := []string{
		policyNameFor(schema.StateRestricted, workloadID),
		policyNameFor(schema.StateQuarantined, workloadID),
	}
	api := m.cs.NetworkingV1().NetworkPolicies(ref.namespace)
	failed := false
	deleted := 0
	for _, name := range names {
		err := api.Delete(ctx, name, metav1.DeleteOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			m.log.Warn("netpol: de-escalation removal delete failed",
				"workload_id", workloadID, "policy", name, "namespace", ref.namespace, "err", err)
			failed = true
			continue
		}
		deleted++
	}

	if verify {
		// CLEAN absence verification (BI-5): confirm each managed policy is gone
		// via a follow-up Get. A survivor (a delete that returned success but did
		// not take effect, or a pre-existing object a NotFound delete missed) is
		// re-deleted once and re-checked; if it persists, it is left for the
		// reconcile backstop and counted as a failure.
		for _, name := range names {
			if _, gerr := api.Get(ctx, name, metav1.GetOptions{}); apierrors.IsNotFound(gerr) {
				continue
			} else if gerr != nil {
				// A transient read error: cannot confirm absence this cycle; let
				// the reconcile backstop reap and re-verify.
				m.log.Warn("netpol: de-escalation removal verification read failed",
					"workload_id", workloadID, "policy", name, "namespace", ref.namespace, "err", gerr)
				failed = true
				continue
			}
			// Still present: re-delete once.
			m.log.Warn("netpol: managed policy survived CLEAN removal; re-deleting",
				"workload_id", workloadID, "policy", name, "namespace", ref.namespace)
			if derr := api.Delete(ctx, name, metav1.DeleteOptions{}); derr != nil && !apierrors.IsNotFound(derr) {
				m.log.Warn("netpol: CLEAN removal re-delete failed",
					"workload_id", workloadID, "policy", name, "namespace", ref.namespace, "err", derr)
				failed = true
				continue
			}
			if _, gerr := api.Get(ctx, name, metav1.GetOptions{}); !apierrors.IsNotFound(gerr) {
				m.log.Warn("netpol: managed policy still present after CLEAN re-delete; reconcile will reap",
					"workload_id", workloadID, "policy", name, "namespace", ref.namespace, "err", gerr)
				failed = true
			}
		}
	}

	if failed {
		m.count("error")
		return
	}
	// Both policies confirmed absent (whether we deleted them or they were
	// already gone). A removal-with-nothing-to-remove is a successful no-op
	// counted removed, never error (BI-5, Open Assumption 3).
	m.count("removed")
	m.log.Info("netpol: de-escalation removed managed policies",
		"workload_id", workloadID, "namespace", ref.namespace,
		"deleted", deleted, "verified", verify)
	// Story 2.8 audit (BI-9): ONE deescalation_remove line per converged
	// removal of a workload's managed SET (not one per individual policy
	// delete), emitted only on the removed-converge path, never on the
	// failed/error path above. fsm_state is the de-escalation target
	// (CLEAN when verify, else SUSPICIOUS, BI-3.4); policy_name/policy_kind
	// are left empty because this records a set removal, not a single object.
	target := schema.StateSuspicious
	if verify {
		target = schema.StateClean
	}
	m.auditPolicy(PolicyAuditEvent{
		Action:      AuditActionDeescalationRemove,
		WorkloadID:  workloadID,
		Namespace:   ref.namespace,
		FSMState:    string(target),
		Result:      "removed",
		SpecSummary: AuditSpecRemoved,
		PackageID:   packageID,
	})
}

// apply performs an idempotent get-then-create-or-update (BI-6). Re-applying
// an identical desired state is a no-op; update races are retried on
// conflict via client-go's RetryOnConflict.
func (m *Manager) apply(ctx context.Context, np *networkingv1.NetworkPolicy) (string, error) {
	api := m.cs.NetworkingV1().NetworkPolicies(np.Namespace)
	existing, err := api.Get(ctx, np.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		if _, cerr := api.Create(ctx, np, metav1.CreateOptions{}); cerr != nil {
			if apierrors.IsAlreadyExists(cerr) {
				// Lost a create race; fall through to the update path.
				return m.update(ctx, np)
			}
			return "", cerr
		}
		return "applied", nil
	}
	if err != nil {
		return "", err
	}
	if policyEqual(existing, np) {
		return "noop", nil
	}
	return m.update(ctx, np)
}

// update overwrites the managed labels, annotations, and spec on the live
// object under RetryOnConflict, preserving the resourceVersion the apiserver
// expects.
func (m *Manager) update(ctx context.Context, np *networkingv1.NetworkPolicy) (string, error) {
	api := m.cs.NetworkingV1().NetworkPolicies(np.Namespace)
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		cur, gerr := api.Get(ctx, np.Name, metav1.GetOptions{})
		if gerr != nil {
			return gerr
		}
		if cur.Labels == nil {
			cur.Labels = map[string]string{}
		}
		for k, v := range np.Labels {
			cur.Labels[k] = v
		}
		if cur.Annotations == nil {
			cur.Annotations = map[string]string{}
		}
		for k, v := range np.Annotations {
			cur.Annotations[k] = v
		}
		cur.Spec = np.Spec
		_, uerr := api.Update(ctx, cur, metav1.UpdateOptions{})
		return uerr
	}); err != nil {
		return "", err
	}
	return "applied", nil
}

// policyEqual reports whether the live policy already carries the desired
// spec and managed labels/annotations, so a re-apply is a no-op. The desired
// labels/annotations must be a subset of the live ones (the apiserver may
// add its own); the spec must be semantically equal.
func policyEqual(existing, desired *networkingv1.NetworkPolicy) bool {
	if !apiequality.Semantic.DeepEqual(existing.Spec, desired.Spec) {
		return false
	}
	return mapContains(existing.Labels, desired.Labels) &&
		mapContains(existing.Annotations, desired.Annotations)
}

// mapContains reports whether super contains every key/value in sub.
func mapContains(super, sub map[string]string) bool {
	for k, v := range sub {
		if super[k] != v {
			return false
		}
	}
	return true
}

// reconcileGC lists every Olaitan-managed NetworkPolicy cluster-wide and
// performs two independent housekeeping passes (AC4, BI-10):
//
//  1. Desired-state backstop (Story 2.6, BI-2c, the FSM-target-aware rework of
//     the Story 2.5 supersession pass). For each managed policy, the reconciler
//     asks the FSM oracle for the workload's CURRENT target and deletes any
//     policy that is NOT part of that target's managed-policy desired set:
//     - target QUARANTINED  => desired set is {quarantine present, restricted
//     absent}; a lingering RESTRICTED policy is the escalation residue and
//     is deleted (count superseded). This is exactly the shipped Story 2.5
//     backstop.
//     - target RESTRICTED   => desired set is {restricted present, quarantine
//     absent}; a lingering QUARANTINED deny-all is the DE-ESCALATION residue
//     and is deleted (count removed). This is the NEW direction: it converges
//     the QUARANTINED->RESTRICTED overlap WITHOUT re-deleting the
//     freshly-applied restricted policy, which the old "quarantine object
//     wins" heuristic would have done backwards.
//     - target SUSPICIOUS/CLEAN => desired set is empty; BOTH the restricted
//     and quarantine policies are stale and, while the owner still EXISTS,
//     are deleted (count removed) so a failed inline removal self-heals
//     (BI-6). If the owner is gone the orphan pass below reaps them as
//     gc_deleted instead.
//     Not-ok (the oracle has NO entry for the workload) rule: the backstop does
//     NOT delete the policy. A managed policy can exist transiently before the
//     FSM map is populated, and after an FSM restart that did not restore a
//     workload the oracle returns not-ok though a live, still-running workload's
//     policy lingers; aggressively deleting on a missing FSM entry would strip
//     protection from a workload the FSM simply lost track of. We therefore leave
//     the orphan-GC pass (owner NotFound) as the SOLE authority for not-ok
//     workloads: if the owner is truly gone the policy is reaped as gc_deleted;
//     if the owner still exists the policy is retained until the FSM next
//     evaluates the workload and the backstop gains an opinion.
//     When oracle == nil the reconciler falls back to the shipped Story 2.5
//     behaviour (a RESTRICTED policy whose workload also has a live QUARANTINED
//     policy OBJECT is superseded), so the change is backward-compatible.
//
//  2. Orphan GC: a managed policy whose workload owner no longer exists is
//     deleted (the original AC4 behaviour). Owner existence is observed through
//     the API server (the authoritative source); a transient list/resolve error
//     leaves the policy for a later cycle rather than risking a wrong delete.
//     This pass is UNCHANGED and is the authority for not-ok workloads.
//
// A policy that is BOTH stale-by-desired-state AND orphaned is deleted (either
// reason suffices); the desired-state pass runs first so the deletion is logged
// and counted under its specific result.
func (m *Manager) reconcileGC(ctx context.Context) {
	list, err := m.cs.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{LabelSelector: managedBySelector})
	if err != nil {
		m.log.Warn("netpol: gc list failed", "err", err)
		return
	}

	// Fallback discriminator for the nil-oracle path (shipped Story 2.5
	// behaviour): which workloads currently have a live QUARANTINED policy
	// object. Only built and consulted when oracle == nil.
	var quarantinedByWID map[string]string
	if m.oracle == nil {
		quarantinedByWID = make(map[string]string)
		for i := range list.Items {
			np := &list.Items[i]
			if np.Annotations[AnnFSMState] != string(schema.StateQuarantined) {
				continue
			}
			if wid := np.Annotations[AnnWorkloadID]; wid != "" {
				quarantinedByWID[wid] = np.Name
			}
		}
	}

	for i := range list.Items {
		np := &list.Items[i]
		// GC operates only on policies carrying our managed-by label (the List
		// selector guarantees this). The excluded-namespaces filter intentionally
		// does NOT apply here: it stops us applying NEW policies in those
		// namespaces, but a policy Olaitan already created there must still be
		// collectable once orphaned or stale. Skipping excluded namespaces would
		// strand our own policies permanently if a namespace were excluded after a
		// policy was applied.
		wid := np.Annotations[AnnWorkloadID]
		if wid == "" {
			continue
		}

		// Desired-state backstop. When stale-by-desired-state deletes the policy,
		// continue to the next policy; when it leaves the policy, fall through to
		// the orphan-GC pass.
		if m.reconcileDesiredState(ctx, np, wid, quarantinedByWID) {
			continue
		}

		// Orphan GC: delete the policy once its owner no longer exists. This is
		// the sole authority for not-ok workloads (BI-2c not-ok rule).
		ref, err := parseWorkloadID(wid)
		if err != nil {
			continue
		}
		exists, err := m.ownerExists(ctx, ref)
		if err != nil {
			// Transient; leave the policy and retry next cycle.
			continue
		}
		if exists {
			continue
		}
		if derr := m.cs.NetworkingV1().NetworkPolicies(np.Namespace).Delete(ctx, np.Name, metav1.DeleteOptions{}); derr != nil {
			if !apierrors.IsNotFound(derr) {
				m.log.Warn("netpol: gc delete failed", "policy", np.Name, "namespace", np.Namespace, "err", derr)
				continue
			}
		}
		m.log.Info("netpol: garbage-collected orphan policy",
			"policy", np.Name, "namespace", np.Namespace, "workload_id", wid)
		m.count("gc_deleted")
		m.auditReconcileDelete(np, AuditActionGCDelete, "gc_deleted")
	}
}

// reconcileDesiredState applies the FSM-target-aware desired-state backstop to a
// single managed policy (Story 2.6, BI-2c). It returns true when it DELETED the
// policy (the caller skips the orphan pass) and false when it left the policy in
// place (the caller falls through to orphan GC). See reconcileGC's doc for the
// per-target dispositions and the not-ok rule.
func (m *Manager) reconcileDesiredState(ctx context.Context, np *networkingv1.NetworkPolicy, wid string, quarantinedByWID map[string]string) bool {
	policyState := np.Annotations[AnnFSMState]

	// Nil-oracle fallback: shipped Story 2.5 "quarantine object wins"
	// supersession. A RESTRICTED policy whose workload also has a live
	// QUARANTINED policy object is superseded.
	if m.oracle == nil {
		if policyState != string(schema.StateRestricted) {
			return false
		}
		quarantineName, superseded := quarantinedByWID[wid]
		if !superseded {
			return false
		}
		if !m.reconcileDelete(ctx, np) {
			return false
		}
		m.log.Info("netpol: reconcile removed superseded RESTRICTED policy",
			"workload_id", wid, "namespace", np.Namespace,
			"restricted_policy", np.Name, "quarantine_policy", quarantineName)
		m.count("superseded")
		m.auditReconcileDelete(np, AuditActionSupersedeDelete, "superseded")
		return true
	}

	target, ok := m.oracle.CurrentState(wid)
	if !ok {
		// FSM has no opinion: leave the policy to the orphan-GC authority
		// (BI-2c not-ok rule) rather than stripping protection from a workload
		// the FSM merely lost track of.
		return false
	}

	switch target {
	case schema.StateQuarantined:
		// Escalation residue: a lingering RESTRICTED policy is not in the
		// QUARANTINED desired set.
		if policyState != string(schema.StateRestricted) {
			return false
		}
		if !m.reconcileDelete(ctx, np) {
			return false
		}
		m.log.Info("netpol: reconcile removed superseded RESTRICTED policy (target QUARANTINED)",
			"workload_id", wid, "namespace", np.Namespace, "policy", np.Name)
		m.count("superseded")
		m.auditReconcileDelete(np, AuditActionSupersedeDelete, "superseded")
		return true
	case schema.StateRestricted:
		// De-escalation residue: a lingering QUARANTINED deny-all is not in the
		// RESTRICTED desired set. Crucially the restricted policy itself is NOT
		// deleted, so a reconcile tick during the QUARANTINED->RESTRICTED overlap
		// cannot undo the freshly-applied restricted policy (BI-2b).
		if policyState != string(schema.StateQuarantined) {
			return false
		}
		if !m.reconcileDelete(ctx, np) {
			return false
		}
		m.log.Info("netpol: reconcile removed stale QUARANTINED policy on de-escalation (target RESTRICTED)",
			"workload_id", wid, "namespace", np.Namespace, "policy", np.Name)
		m.count("removed")
		m.auditReconcileDelete(np, AuditActionDeescalationRemove, "removed")
		return true
	default:
		// target SUSPICIOUS/CLEAN: empty desired set. Both managed policies are
		// stale. While the owner still exists, delete them here (count removed) so
		// a failed inline removal self-heals (BI-6); if the owner is gone, leave
		// the policy for the orphan pass to reap as gc_deleted.
		ref, err := parseWorkloadID(wid)
		if err != nil {
			return false
		}
		exists, err := m.ownerExists(ctx, ref)
		if err != nil || !exists {
			// Transient error, or owner gone: defer to the orphan-GC pass.
			return false
		}
		if !m.reconcileDelete(ctx, np) {
			return false
		}
		m.log.Info("netpol: reconcile removed stale managed policy on de-escalation (target below RESTRICTED)",
			"workload_id", wid, "namespace", np.Namespace, "policy", np.Name, "target", string(target))
		m.count("removed")
		m.auditReconcileDelete(np, AuditActionDeescalationRemove, "removed")
		return true
	}
}

// reconcileDelete best-effort deletes a managed policy during a reconcile pass.
// It returns true when the policy is gone (deleted now or already absent) and
// false on a real (non-NotFound) delete error, which is logged at WARN and left
// for the next reconcile tick.
func (m *Manager) reconcileDelete(ctx context.Context, np *networkingv1.NetworkPolicy) bool {
	if derr := m.cs.NetworkingV1().NetworkPolicies(np.Namespace).Delete(ctx, np.Name, metav1.DeleteOptions{}); derr != nil {
		if !apierrors.IsNotFound(derr) {
			m.log.Warn("netpol: reconcile desired-state delete failed", "policy", np.Name, "namespace", np.Namespace, "err", derr)
			return false
		}
	}
	return true
}
