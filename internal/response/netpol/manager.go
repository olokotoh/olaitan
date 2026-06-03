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
		"Cumulative NetworkPolicy enforcement actions labelled by result: applied, noop, error, skipped, dropped, gc_deleted, superseded (Story 2.4, FR33).",
		[]string{"result"},
	)
	if err != nil {
		return err
	}
	m.applyTotal = cv
	// Pre-initialise every known result label to 0 so alert PromQL has a
	// stable zero series from process startup, rather than a label series that
	// only materialises on first occurrence.
	for _, result := range []string{"applied", "noop", "error", "skipped", "dropped", "gc_deleted", "superseded"} {
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

// enforcedState reports whether a transition INTO state triggers a managed
// NetworkPolicy (Story 2.5, BI-1). The manager acts on RESTRICTED (Story 2.4
// egress allow-list) and QUARANTINED (Story 2.5 deny-all) and ignores every
// other target state. De-escalation removal (QUARANTINED->RESTRICTED, ->CLEAN)
// is Story 2.6 and is deliberately NOT triggered here.
func enforcedState(s schema.PodSecurityState) bool {
	return s == schema.StateRestricted || s == schema.StateQuarantined
}

// Publish is the fsm.TransitionSink seam (BI-3, BI-5). It acts only on a
// transition INTO an enforced state (RESTRICTED or QUARANTINED) and enqueues
// it for the async worker without blocking the FSM goroutine; on a full queue
// it drops with a metric rather than stalling the hot path (BI-4).
func (m *Manager) Publish(st schema.StateTransition) {
	if !enforcedState(st.ToState) {
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
		m.deleteSupersededRestricted(ctx, ref, st.WorkloadID)
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
func (m *Manager) deleteSupersededRestricted(ctx context.Context, ref workloadRef, workloadID string) {
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
//  1. Supersession backstop (Story 2.5, FIX A): any RESTRICTED policy whose
//     workload also currently has a QUARANTINED policy is deleted as
//     superseded, regardless of whether its owner still exists. A workload in
//     QUARANTINED must not retain a RESTRICTED policy: while the RESTRICTED
//     policy lingers its Egress allow-list still permits egress to the
//     RFC1918/cluster/DNS CIDRs (Kubernetes NetworkPolicies are additive
//     allow-lists, so the deny-all QUARANTINED policy does NOT subtract those
//     allows), and orphan GC would never reap it while the owner exists. This
//     pass makes the inline best-effort supersession (the fast path) eventually
//     consistent: a failed inline delete self-heals within one reconcile
//     interval (default 30s).
//
//  2. Orphan GC: a managed policy whose workload owner no longer exists is
//     deleted (the original AC4 behaviour). Owner existence is observed through
//     the API server (the authoritative source); a transient list/resolve error
//     leaves the policy for a later cycle rather than risking a wrong delete.
//
// A RESTRICTED policy that is BOTH superseded AND orphaned is deleted (either
// reason suffices); the superseded pass runs first so the deletion is logged
// and counted as a supersession.
func (m *Manager) reconcileGC(ctx context.Context) {
	list, err := m.cs.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{LabelSelector: managedBySelector})
	if err != nil {
		m.log.Warn("netpol: gc list failed", "err", err)
		return
	}

	// First, identify which workloads currently have a QUARANTINED policy. We
	// key by workload_id read from the AnnWorkloadID annotation; the
	// AnnFSMState == QUARANTINED annotation is the robust discriminator (the
	// olaitan-quarantined- name prefix is an equivalent signal). The name of
	// the superseding quarantine policy is retained for the supersession log.
	quarantinedByWID := make(map[string]string)
	for i := range list.Items {
		np := &list.Items[i]
		if np.Annotations[AnnFSMState] != string(schema.StateQuarantined) {
			continue
		}
		if wid := np.Annotations[AnnWorkloadID]; wid != "" {
			quarantinedByWID[wid] = np.Name
		}
	}

	for i := range list.Items {
		np := &list.Items[i]
		// GC operates only on policies carrying our managed-by label (the List
		// selector guarantees this). The excluded-namespaces filter intentionally
		// does NOT apply here: it stops us applying NEW policies in those
		// namespaces, but a policy Olaitan already created there must still be
		// collectable once orphaned or superseded. Skipping excluded namespaces
		// would strand our own policies permanently if a namespace were excluded
		// after a policy was applied.
		wid := np.Annotations[AnnWorkloadID]
		if wid == "" {
			continue
		}

		// Supersession backstop: a RESTRICTED policy for a workload that now has
		// a QUARANTINED policy must be removed (independent of owner existence).
		if np.Annotations[AnnFSMState] == string(schema.StateRestricted) {
			if quarantineName, superseded := quarantinedByWID[wid]; superseded {
				if derr := m.cs.NetworkingV1().NetworkPolicies(np.Namespace).Delete(ctx, np.Name, metav1.DeleteOptions{}); derr != nil {
					if !apierrors.IsNotFound(derr) {
						m.log.Warn("netpol: superseded restricted delete failed", "policy", np.Name, "namespace", np.Namespace, "err", derr)
						continue
					}
				}
				m.log.Info("netpol: reconcile removed superseded RESTRICTED policy",
					"workload_id", wid, "namespace", np.Namespace,
					"restricted_policy", np.Name, "quarantine_policy", quarantineName)
				m.count("superseded")
				continue
			}
		}

		// Orphan GC: delete the policy once its owner no longer exists.
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
	}
}
