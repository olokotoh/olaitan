package override

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/response/fsm"
	"github.com/olokotoh/olaitan/internal/schema"
)

// Config carries the controller's tunables (from config.OverrideConfig).
type Config struct {
	// PollInterval is the reconcile cadence (default 15s, BI-1).
	PollInterval time.Duration
	// DefaultTTL is applied when the TTL annotation is absent or unparseable
	// (default 1h, BI-8).
	DefaultTTL time.Duration
	// ExcludedNamespaces are skipped by the poll (the response-ring
	// self-protection list, mirrored from ResponseConfig.ExcludedNamespaces).
	ExcludedNamespaces []string
}

// Controller is the Story 2.7 operator-override poll/reconcile controller.
type Controller struct {
	cs        kubernetes.Interface
	store     *Store
	machine   *fsm.Machine
	publisher OverridePublisher
	log       *slog.Logger

	poll       time.Duration
	defaultTTL time.Duration
	excluded   map[string]struct{}

	rejected *prometheus.CounterVec

	// consumed records, per workload_id, the override SIGNATURE whose native
	// Redis TTL has already elapsed (the hard-deadline release, FIX 2/FR39).
	// While a workload+signature is here, a STILL-PRESENT annotation carrying
	// that same signature does NOT re-pin (no oscillation). The entry is
	// cleared when the annotation is removed (manual removal) or its signature
	// changes (operator edit/re-apply). The set is in-memory only: after a
	// controller restart a still-present already-expired annotation re-pins
	// once (re-arm), which is acceptable (documented in docs/runbook.md).
	consumed map[string]string

	// lastActive tracks the workloads whose override key was present in Redis
	// on the PREVIOUS tick. A workload that was active last tick, is still
	// desired this tick, but whose key is now GONE is a native-TTL expiry
	// (the hard-deadline release, FIX 2).
	lastActive map[string]struct{}

	// now is injectable for tests (defaults to time.Now).
	now func() time.Time
}

// desired is one workload's resolved desired override from the live
// annotations on this poll tick.
type desired struct {
	workloadID string
	state      schema.PodSecurityState
	ttl        time.Duration
	ttlSeconds int
	operatorID string
	source     string
	// rejectReason is non-empty when the requested state is invalid; the
	// reconcile emits a rejected event instead of pinning.
	rejectReason string
	requestedRaw string
}

// signature is the per-workload override identity (state, ttl). It is compared
// against the active Redis record's signature to decide whether an override is
// UNCHANGED (do nothing, let the hard-deadline TTL count down) or EDITED
// (re-apply with a fresh native TTL + fresh applied_at). The operator id is
// deliberately EXCLUDED (FIX 4): an operator-id change alone must NOT re-pin or
// re-arm the TTL.
func (d desired) signature() string {
	return string(d.state) + "|" + strconv.Itoa(d.ttlSeconds)
}

// signatureOf computes the signature of an active Redis record so it can be
// compared against the desired signature (FIX 2).
func signatureOf(rec OverrideRecord) string {
	return string(rec.RequestedState) + "|" + strconv.Itoa(rec.TTLSeconds)
}

// New constructs a Controller. cs, store, machine, and publisher must be
// non-nil; registry may be nil (test fixtures skip metric registration).
func New(cfg Config, cs kubernetes.Interface, store *Store, machine *fsm.Machine, publisher OverridePublisher, registry *metrics.Registry, log *slog.Logger) (*Controller, error) {
	if cs == nil {
		return nil, fmt.Errorf("override: nil clientset")
	}
	if store == nil {
		return nil, fmt.Errorf("override: nil store")
	}
	if machine == nil {
		return nil, fmt.Errorf("override: nil fsm machine")
	}
	if publisher == nil {
		return nil, fmt.Errorf("override: nil publisher")
	}
	if log == nil {
		log = slog.Default()
	}
	poll := cfg.PollInterval
	if poll <= 0 {
		poll = 15 * time.Second
	}
	ttl := cfg.DefaultTTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	excluded := make(map[string]struct{}, len(cfg.ExcludedNamespaces))
	for _, ns := range cfg.ExcludedNamespaces {
		excluded[ns] = struct{}{}
	}
	c := &Controller{
		cs:         cs,
		store:      store,
		machine:    machine,
		publisher:  publisher,
		log:        log,
		poll:       poll,
		defaultTTL: ttl,
		excluded:   excluded,
		consumed:   map[string]string{},
		lastActive: map[string]struct{}{},
		now:        time.Now,
	}
	if registry != nil {
		if err := c.registerMetrics(registry); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (c *Controller) registerMetrics(r *metrics.Registry) error {
	cv, err := r.RegisterCounterVec(
		"olaitan_response_override_rejected_total",
		"Cumulative number of operator-override requests refused, labelled by reason: state_unavailable (a real-but-unimplemented state such as PRESERVED_KILLED) or invalid_state (an unknown/typo'd state). Story 2.7, FR38/FR39, AC5.",
		[]string{"reason"},
	)
	if err != nil {
		return err
	}
	// Pre-initialise both reason label values to 0 so alert PromQL has a
	// stable zero series from startup (the netpol pre-init precedent).
	for _, reason := range []string{ReasonStateUnavailable, ReasonInvalidState} {
		cv.WithLabelValues(reason).Add(0)
	}
	c.rejected = cv
	return nil
}

// Run is the poll/reconcile loop (BI-1). It LISTs annotated pods on a ticker,
// reconciles the desired override set against Redis + the FSM, and returns nil
// on graceful context cancellation. Wire it into the errgroup.
func (c *Controller) Run(ctx context.Context) error {
	ticker := time.NewTicker(c.poll)
	defer ticker.Stop()
	// Reconcile once immediately so an override applied while the controller
	// was down is picked up without waiting a full poll interval.
	c.reconcile(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			c.reconcile(ctx)
		}
	}
}

// reconcile runs one poll tick (EDGE-TRIGGERED, FIX 2). It computes the DESIRED
// override set from the live pod annotations and the CURRENT (active) set from
// Redis, then APPLIES new/edited overrides (the native Redis TTL is a HARD
// DEADLINE measured from first application, NOT a refreshing lease) and detects
// releases (hard-deadline TTL expiry, manual annotation removal). Invalid
// targets are rejected (BI-5). Workloads whose desired state could NOT be
// positively determined this tick (a transient owner/resolve error, FIX 1) are
// EXCLUDED from release candidates.
func (c *Controller) reconcile(ctx context.Context) {
	desiredSet, rejections, indeterminate, resolveIncomplete, err := c.computeDesired(ctx)
	if err != nil {
		c.log.Warn("override: list pods failed; skipping tick", "err", err)
		return
	}

	// Emit rejections (no pin, no Redis write; BI-5).
	for _, rej := range rejections {
		c.emitRejection(ctx, rej)
	}

	current, err := c.store.ListActive(ctx)
	if err != nil {
		// FIX 3: honour the log. On a scan error we cannot trust the active
		// set, so we SKIP the apply phase (which depends on the active
		// signature) AND the release-detection phase this tick. Both resume on
		// the next successful scan. lastActive is left untouched so the next
		// good tick's expiry detection is not corrupted by this gap.
		c.log.Warn("override: list active overrides failed; skipping apply + release detection this tick", "err", err)
		return
	}

	// Phase 1: HARD-DEADLINE TTL expiry (FIX 2/FR39). Run BEFORE apply so a
	// still-present annotation whose native TTL just elapsed is marked consumed
	// and is NOT re-pinned by the apply phase this tick.
	c.detectHardDeadlineExpiry(desiredSet, current, indeterminate)

	// Phase 2: apply (edge-triggered): for each desired workload decide
	// NEW / EDITED / UNCHANGED / CONSUMED and act accordingly.
	for wl, d := range desiredSet {
		c.applyDesired(ctx, wl, d, current)
	}

	// Phase 3: MANUAL removal release (AC4): a pinned/active workload that is
	// POSITIVELY not desired this tick. Skipped entirely when the resolve was
	// incomplete (FIX 1): a transient resolve error means the desired set may
	// be missing a workload we cannot key, so we must not treat any absence as
	// a removal. The (safer) hard-deadline phase still ran above because it is
	// gated on a positive Redis key disappearance, unaffected by resolve gaps.
	if resolveIncomplete {
		c.log.Warn("override: workload-id resolve incomplete this tick; skipping manual-removal release detection (pins retained)")
	} else {
		c.detectManualRemovals(ctx, desiredSet, current, indeterminate)
	}

	// Record the active set for the next tick's hard-deadline expiry detection.
	nextActive := make(map[string]struct{}, len(current))
	for wl := range current {
		nextActive[wl] = struct{}{}
	}
	c.lastActive = nextActive
}

// computeDesired LISTs pods cluster-wide (honouring ExcludedNamespaces) and
// resolves each annotated pod to its desired override, applying the pod-over-
// owner precedence and the most-isolating tie-break for conflicting pods of
// the same owner (BI-9). Invalid targets are returned separately as rejections.
//
// A workload whose desired state could NOT be positively determined this tick
// (a non-NotFound owner-read or workload-id-resolve error, FIX 1) is added to
// the indeterminate set so the caller never releases it: only a POSITIVELY
// confirmed absence (pod listed, annotation confirmed absent) is a release.
func (c *Controller) computeDesired(ctx context.Context) (desiredSet map[string]desired, rejections []desired, indeterminate map[string]struct{}, resolveIncomplete bool, err error) {
	pods, lerr := c.cs.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if lerr != nil {
		return nil, nil, nil, false, fmt.Errorf("override: list pods: %w", lerr)
	}

	desiredSet = map[string]desired{}
	indeterminate = map[string]struct{}{}

	for i := range pods.Items {
		pod := &pods.Items[i]
		if _, skip := c.excluded[pod.Namespace]; skip {
			continue
		}
		// Resolve the canonical workload_id FIRST so a positively-determined
		// absence (and an indeterminate owner-read error) can both be keyed on
		// it.
		workloadID, rerr := resolveWorkloadID(ctx, c.cs, pod)
		if rerr != nil {
			// FIX 1: a transient (non-NotFound) resolve error means we cannot
			// even key this pod's workload (the owner walk failed), so we
			// cannot precisely mark it indeterminate. Set the tick-wide
			// resolveIncomplete flag so the manual-removal phase is SKIPPED
			// entirely this tick (no workload is released on an unproven
			// absence). The hard-deadline phase is unaffected (it keys on a
			// positive Redis key disappearance, not on the desired set's
			// completeness).
			resolveIncomplete = true
			c.log.Warn("override: resolve workload_id failed; tick resolve incomplete (will not treat absences as removals)", "namespace", pod.Namespace, "pod", pod.Name, "err", rerr)
			continue
		}
		// Read the operative annotation: pod-level wins over owner-level (BI-9).
		// A transient owner-read error makes the desired state indeterminate.
		stateRaw, ttlRaw, operatorRaw, source, oerr := c.operativeAnnotation(ctx, pod)
		if oerr != nil {
			indeterminate[workloadID] = struct{}{}
			c.log.Warn("override: owner annotation read failed; marking indeterminate (will not release)", "workload_id", workloadID, "err", oerr)
			continue
		}
		if stateRaw == "" {
			continue
		}

		state := schema.PodSecurityState(stateRaw)
		if !validOverrideTarget(state) {
			reason := ReasonInvalidState
			if state == schema.StatePreservedKilled {
				reason = ReasonStateUnavailable
			}
			rejections = append(rejections, desired{
				workloadID:   workloadID,
				state:        state,
				source:       source,
				rejectReason: reason,
				requestedRaw: stateRaw,
			})
			continue
		}

		ttl, ttlSeconds := c.parseTTL(ttlRaw, workloadID)
		d := desired{
			workloadID: workloadID,
			state:      state,
			ttl:        ttl,
			ttlSeconds: ttlSeconds,
			operatorID: operatorRaw,
			source:     source,
		}
		// Most-isolating tie-break for conflicting pods of the same owner.
		if prev, ok := desiredSet[workloadID]; ok && prev.state != d.state {
			if stateOrder(prev.state) >= stateOrder(d.state) {
				c.log.Warn("override: conflicting per-pod annotations for one workload; keeping most-isolating",
					"workload_id", workloadID, "kept", prev.state, "dropped", d.state)
				continue
			}
			c.log.Warn("override: conflicting per-pod annotations for one workload; keeping most-isolating",
				"workload_id", workloadID, "kept", d.state, "dropped", prev.state)
		}
		desiredSet[workloadID] = d
	}
	// A workload that ended up positively desired this tick is NOT
	// indeterminate even if some other pod of it raced an error.
	for wl := range desiredSet {
		delete(indeterminate, wl)
	}
	return desiredSet, rejections, indeterminate, resolveIncomplete, nil
}

// operativeAnnotation returns the (state, ttl, operator, source) the override
// should use for pod, with the pod annotation winning over the owner
// annotation (BI-9). The returned error is non-nil only on a transient
// (non-NotFound) owner-read failure (FIX 1): the caller marks the workload
// indeterminate so it is never released on an unproven absence. An owner that
// simply carries no annotation returns ("", "", "", "", nil).
func (c *Controller) operativeAnnotation(ctx context.Context, pod *corev1.Pod) (state, ttl, operator, source string, err error) {
	if v, ok := pod.Annotations[AnnotationState]; ok && v != "" {
		return v, pod.Annotations[AnnotationTTL], pod.Annotations[AnnotationOperator], SourcePod, nil
	}
	ownerAnns, oerr := ownerAnnotations(ctx, c.cs, pod)
	if oerr != nil {
		return "", "", "", "", oerr
	}
	if v, ok := ownerAnns[AnnotationState]; ok && v != "" {
		return v, ownerAnns[AnnotationTTL], ownerAnns[AnnotationOperator], SourceOwner, nil
	}
	return "", "", "", "", nil
}

// parseTTL parses the override-ttl annotation, defaulting to the configured
// default on absent/unparseable/non-positive values (BI-8, not a rejection).
func (c *Controller) parseTTL(raw, workloadID string) (time.Duration, int) {
	if raw == "" {
		return c.defaultTTL, int(c.defaultTTL.Seconds())
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		c.log.Warn("override: unparseable or non-positive ttl annotation; defaulting",
			"workload_id", workloadID, "ttl", raw, "default", c.defaultTTL)
		return c.defaultTTL, int(c.defaultTTL.Seconds())
	}
	return d, int(d.Seconds())
}

// applyDesired implements the EDGE-TRIGGERED apply rule for one desired
// workload (FIX 2). The native Redis TTL is a HARD DEADLINE measured from first
// application, NOT a refreshing lease, so it is NEVER re-written for an
// unchanged override; it is only (re-)written on a NEW request or an operator
// EDIT (a signature change). The four cases:
//
//   - active key exists AND signature unchanged => DO NOTHING (let the
//     hard-deadline TTL count down; do NOT refresh it).
//   - active key exists AND signature changed (operator edited the annotation)
//     => re-apply: Pin(new state), write the key with the NEW native TTL, emit
//     an applied event with a FRESH applied_at (so the NATS msgID differs and
//     the event is not deduped away, FIX 5); clear any consumed marker.
//   - no active key AND this workload+signature is already consumed (its
//     hard-deadline TTL elapsed while the annotation stayed present) => DO
//     NOTHING (no re-pin oscillation).
//   - no active key AND not consumed => NEW request => Pin + write key (native
//     TTL) + emit applied event. A changed signature also clears a stale
//     consumed marker so a re-applied annotation re-arms.
func (c *Controller) applyDesired(ctx context.Context, workloadID string, d desired, current map[string]OverrideRecord) {
	sig := d.signature()
	active, isActive := current[workloadID]

	if isActive && signatureOf(active) == sig {
		// Unchanged active override: hard deadline counts down untouched.
		// Defensive: ensure the in-memory pin is still in place (e.g. after a
		// restart that rehydrated the active key but not the pin flag); Pin is
		// idempotent and emits no transition when already pinned to the state.
		if s, pinned := c.machine.IsPinned(workloadID); !pinned || s != d.state {
			if err := c.machine.Pin(workloadID, d.state, d.operatorID); err != nil {
				c.log.Warn("override: re-pin (rehydrate) failed", "workload_id", workloadID, "state", d.state, "err", err)
			}
		}
		return
	}

	if !isActive {
		// No active key. If this exact workload+signature was consumed (its
		// hard-deadline TTL elapsed with the annotation still present), do
		// nothing: the still-present annotation must NOT re-pin (FR39).
		if csig, ok := c.consumed[workloadID]; ok && csig == sig {
			return
		}
	}

	// NEW request or operator EDIT: (re-)pin, (re-)write the key with a FRESH
	// native TTL and a FRESH applied_at. A signature change clears any consumed
	// marker so the new override re-arms.
	delete(c.consumed, workloadID)

	before, _ := c.machine.CurrentState(workloadID)
	prevPinned, wasPinned := c.machine.IsPinned(workloadID)
	alreadyPinnedSame := wasPinned && prevPinned == d.state

	if err := c.machine.Pin(workloadID, d.state, d.operatorID); err != nil {
		// A validated state should never be rejected here; log defensively.
		c.log.Warn("override: pin failed", "workload_id", workloadID, "state", d.state, "err", err)
		return
	}

	appliedAt := c.now().UTC()
	rec := OverrideRecord{
		RequestedState: d.state,
		TTLSeconds:     d.ttlSeconds,
		OperatorID:     d.operatorID,
		AppliedAt:      appliedAt,
		Source:         d.source,
	}
	if err := c.store.Put(ctx, workloadID, rec, d.ttl); err != nil {
		c.log.Warn("override: redis put failed", "workload_id", workloadID, "err", err)
		return
	}

	// A re-pin that did NOT change the FSM state and did NOT change the
	// signature would be a no-op; but reaching here means the signature DID
	// change (edit) or the key was absent (new/re-arm), both of which are a
	// genuine applied event the operator/audit should see. The fresh applied_at
	// guarantees a distinct NATS msgID (FIX 5). alreadyPinnedSame is retained
	// only to annotate the log.
	c.log.Info("override: applied", "workload_id", workloadID, "state", d.state, "ttl_seconds", d.ttlSeconds, "was_pinned_same", alreadyPinnedSame)

	evt := OverrideApplied{
		WorkloadID:     workloadID,
		RequestedState: string(d.state),
		BeforeState:    string(before),
		TTLSeconds:     d.ttlSeconds,
		OperatorID:     d.operatorID,
		Source:         d.source,
		Rejected:       false,
		AppliedAtNs:    appliedAt.UnixNano(),
	}
	if err := c.publisher.PublishOverride(ctx, evt); err != nil {
		c.log.Warn("override: publish applied failed", "workload_id", workloadID, "err", err)
	}
}

// detectHardDeadlineExpiry handles the FR39 hard-deadline release (FIX 2): a
// workload that is STILL desired (the annotation is present) but whose active
// Redis key has GONE since the previous tick has reached its hard deadline.
// ReleasePin and ADD the workload+signature to the in-memory consumed set so
// the still-present annotation does NOT re-pin this tick or later. Run BEFORE
// the apply phase so the consumed marker suppresses a same-tick re-pin.
// Indeterminate workloads (FIX 1) are skipped.
func (c *Controller) detectHardDeadlineExpiry(desiredSet map[string]desired, current map[string]OverrideRecord, indeterminate map[string]struct{}) {
	for wl, d := range desiredSet {
		if _, ind := indeterminate[wl]; ind {
			continue
		}
		_, stillActive := current[wl]
		_, wasActive := c.lastActive[wl]
		if !stillActive && wasActive {
			resumed, ok := c.machine.ReleasePin(wl)
			c.consumed[wl] = d.signature()
			c.log.Info("override: released (hard-deadline ttl expiry)", "workload_id", wl, "resumed_from", resumed, "was_pinned", ok)
		}
	}
}

// detectManualRemovals handles the AC4 manual-removal release: a pinned/active
// workload that is POSITIVELY not desired this tick (annotation confirmed
// absent) with its key still present. ReleasePin + DeleteOverride + clear any
// consumed marker. The candidate set is the union of the Redis-active set and
// the FSM pin set. Indeterminate workloads (FIX 1) are skipped: their absence
// is unproven, so a pinned QUARANTINED workload is never spuriously
// un-isolated. The caller skips this phase entirely when the resolve was
// incomplete this tick.
func (c *Controller) detectManualRemovals(ctx context.Context, desiredSet map[string]desired, current map[string]OverrideRecord, indeterminate map[string]struct{}) {
	candidates := map[string]struct{}{}
	for wl := range current {
		candidates[wl] = struct{}{}
	}
	for wl := range c.machine.PinnedWorkloads() {
		candidates[wl] = struct{}{}
	}
	// Also consider consumed-but-no-longer-pinned workloads: a hard-deadline
	// release leaves a consumed marker but no pin/key, so its annotation
	// removal would otherwise leave a stale consumed marker that suppresses a
	// later re-add. Including them here clears the marker on positive removal.
	for wl := range c.consumed {
		candidates[wl] = struct{}{}
	}
	for wl := range candidates {
		if _, stillDesired := desiredSet[wl]; stillDesired {
			continue
		}
		if _, ind := indeterminate[wl]; ind {
			continue
		}
		resumed, ok := c.machine.ReleasePin(wl)
		// The annotation is positively gone; clear Redis (no-op if the key
		// already expired) and drop any consumed marker so a future re-add
		// re-pins.
		if err := c.store.Delete(ctx, wl); err != nil {
			c.log.Warn("override: redis delete on manual removal failed", "workload_id", wl, "err", err)
		}
		delete(c.consumed, wl)
		c.log.Info("override: released (annotation removed)", "workload_id", wl, "resumed_from", resumed, "was_pinned", ok)
	}
}

// emitRejection publishes a rejected OVERRIDES.applied event and increments
// the rejection counter (BI-5). It pins nothing and writes no Redis key.
func (c *Controller) emitRejection(ctx context.Context, d desired) {
	if c.rejected != nil {
		c.rejected.WithLabelValues(d.rejectReason).Inc()
	}
	before, _ := c.machine.CurrentState(d.workloadID)
	evt := OverrideApplied{
		WorkloadID:     d.workloadID,
		RequestedState: d.requestedRaw,
		BeforeState:    string(before),
		Source:         d.source,
		Rejected:       true,
		Reason:         d.rejectReason,
	}
	if err := c.publisher.PublishOverride(ctx, evt); err != nil {
		c.log.Warn("override: publish rejection failed", "workload_id", d.workloadID, "err", err)
	}
	c.log.Warn("override: rejected", "workload_id", d.workloadID, "requested_state", d.requestedRaw, "reason", d.rejectReason)
}
