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

	// lastRejected records, per workload_id, the last REJECTED requested-state
	// signature ("reason|requested") already emitted+counted (FIX 5, round 2).
	// A standing invalid annotation is then counted ONCE rather than once per
	// poll, keeping the rejected_total counter consistent with the deduped NATS
	// event. The entry is cleared when the workload stops being rejected (it
	// becomes valid, indeterminate-free desired, or disappears).
	lastRejected map[string]string

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
		cs:           cs,
		store:        store,
		machine:      machine,
		publisher:    publisher,
		log:          log,
		poll:         poll,
		defaultTTL:   ttl,
		excluded:     excluded,
		consumed:     map[string]string{},
		lastRejected: map[string]string{},
		now:          time.Now,
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
	desiredSet, rejections, indeterminate, resolveFailed, err := c.computeDesired(ctx)
	if err != nil {
		c.log.Warn("override: list pods failed; skipping tick", "err", err)
		return
	}

	// A workload that became VALID (now desired) clears any stale rejected
	// marker, so a later regression to the same invalid value re-counts (FIX 5).
	for wl := range desiredSet {
		delete(c.lastRejected, wl)
	}

	// Emit rejections (no pin, no Redis write; BI-5). Counted/emitted only on a
	// NEW or CHANGED rejection signature per workload (FIX 5) so a standing
	// invalid annotation counts once, consistent with the deduped NATS event.
	for _, rej := range rejections {
		c.emitRejection(ctx, rej)
	}

	current, err := c.store.ListActive(ctx)
	if err != nil {
		// FIX 3: on a scan error we cannot trust the active set, so we SKIP the
		// apply phase (which depends on the active signature) AND the
		// release-detection phases this tick. Both resume on the next
		// successful scan.
		c.log.Warn("override: list active overrides failed; skipping apply + release detection this tick", "err", err)
		return
	}

	// Phase 1: HARD-DEADLINE TTL expiry (FIX 1, round 2). Run BEFORE apply so a
	// still-present annotation whose native TTL just elapsed is marked consumed
	// and is NOT re-pinned by the apply phase this tick. Authoritative detection:
	// the FSM pin set is the authority for "we believe this is pinned"; a
	// currently-pinned, still-desired workload with NO active Redis key has
	// reached its hard deadline (no dependence on a two-tick lastActive capture).
	c.detectHardDeadlineExpiry(desiredSet, current, indeterminate)

	// Phase 2: apply (edge-triggered): for each desired workload decide
	// NEW / EDITED / UNCHANGED / CONSUMED and act accordingly.
	for wl, d := range desiredSet {
		c.applyDesired(ctx, wl, d, current)
	}

	// Phase 3: MANUAL removal release (AC4): a pinned/active workload that is
	// not in the desired set this tick. Each candidate's removal is CONFIRMED by
	// a direct owner read (FIX 2(b)) before release, so an owner scaled to zero
	// (no live pods, empty pod list) but still annotated is NOT spuriously
	// released. Per-workload indeterminate protection (FIX 2(a)) replaces the
	// old tick-wide resolve veto: a positively-resolved, confirmed-absent
	// workload is released even if some other pod errored this tick.
	c.detectManualRemovals(ctx, desiredSet, current, indeterminate, resolveFailed)

	// Phase 4: prune the in-memory consumed/last-rejected maps so a sustained
	// outage cannot grow them unbounded (FIX 4 backstop).
	c.pruneInMemory(desiredSet, current, rejections)
}

// pruneInMemory is the FIX 4 (round 2) defensive backstop: on each successful
// tick it drops consumed/lastRejected entries for workloads that are no longer
// relevant (neither desired, nor currently pinned, nor carrying an active Redis
// key), so a sustained Redis/resolve outage that leaves stale entries cannot
// grow the maps without bound. The normal release/apply paths already clear
// entries on the happy path; this is purely a safety cap.
func (c *Controller) pruneInMemory(desiredSet map[string]desired, current map[string]OverrideRecord, rejections []desired) {
	relevant := func(wl string) bool {
		if _, ok := desiredSet[wl]; ok {
			return true
		}
		if _, ok := current[wl]; ok {
			return true
		}
		if _, pinned := c.machine.IsPinned(wl); pinned {
			return true
		}
		return false
	}
	for wl := range c.consumed {
		if !relevant(wl) {
			delete(c.consumed, wl)
		}
	}
	// A lastRejected entry must SURVIVE while its workload is STILL being
	// rejected this tick (that is the whole point of the dedup, FIX 5): a
	// standing invalid annotation is neither desired, pinned, nor active, so the
	// generic relevance test alone would wrongly prune it every tick and the
	// counter would tick on every poll. Keep it for currently-rejected
	// workloads; drop it only when the workload is neither rejected nor relevant.
	stillRejected := make(map[string]struct{}, len(rejections))
	for _, rej := range rejections {
		stillRejected[rej.workloadID] = struct{}{}
	}
	for wl := range c.lastRejected {
		if _, rej := stillRejected[wl]; rej {
			continue
		}
		if !relevant(wl) {
			delete(c.lastRejected, wl)
		}
	}
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
func (c *Controller) computeDesired(ctx context.Context) (desiredSet map[string]desired, rejections []desired, indeterminate map[string]struct{}, resolveFailed bool, err error) {
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
			// A transient (non-NotFound) resolve error means we cannot key this
			// pod's workload (the owner walk failed), so we DROP it from the
			// desired set this tick and raise resolveFailed. For an OWNER-sourced
			// pin the per-workload owner-confirm GET in detectManualRemovals (FIX
			// 2(b)) is the authoritative guard (the owner read there finds the
			// annotation still present and skips the release). For a POD-sourced
			// pin the owner object carries no annotation, so resolveFailed is
			// what protects it: a pod-sourced candidate is treated as
			// indeterminate while a resolve failed this tick (the pod exists but
			// could not be keyed, an unproven absence). The hard-deadline phase
			// is unaffected (it keys on the FSM pin set + a missing Redis key).
			resolveFailed = true
			c.log.Warn("override: resolve workload_id failed; dropping pod from desired set this tick (release guarded by owner-confirm + resolveFailed)", "namespace", pod.Namespace, "pod", pod.Name, "err", rerr)
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
	return desiredSet, rejections, indeterminate, resolveFailed, nil
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

// detectHardDeadlineExpiry handles the FR39 hard-deadline release with
// AUTHORITATIVE absolute-deadline detection (FIX 1, round 2). A workload has
// reached its hard deadline when it is CURRENTLY PINNED in the FSM (the pin set
// is the authority for "we believe this is pinned"), STILL desired this tick
// (its annotation is present, i.e. in desiredSet), has NO active Redis key this
// tick (the missing key IS the deadline signal, since the native TTL elapsed),
// and is NOT indeterminate. On detection: ReleasePin + mark the
// workload+signature consumed so the still-present annotation does NOT re-pin.
// Run BEFORE the apply phase so the consumed marker suppresses a same-tick
// re-pin.
//
// This removes the old two-tick lastActive dependence, which MISSED two cases:
// (a) ttl < pollInterval (the key is written and expires within one poll gap,
// so it is never captured in lastActive => an infinite re-pin loop), and (b) a
// SCAN/GET race in ListActive that drops the key on the very tick it would have
// been "last active" => a pin stranded forever. The FSM pin set plus the
// absent Redis key are both authoritative and need no prior-tick capture.
func (c *Controller) detectHardDeadlineExpiry(desiredSet map[string]desired, current map[string]OverrideRecord, indeterminate map[string]struct{}) {
	for wl, d := range desiredSet {
		if _, ind := indeterminate[wl]; ind {
			continue
		}
		if _, pinned := c.machine.IsPinned(wl); !pinned {
			// Not (yet) pinned: this is a fresh apply, not a deadline expiry.
			continue
		}
		if _, stillActive := current[wl]; stillActive {
			// The key is still live: the hard deadline has not elapsed.
			continue
		}
		resumed, ok := c.machine.ReleasePin(wl)
		c.consumed[wl] = d.signature()
		c.log.Info("override: released (hard-deadline ttl expiry)", "workload_id", wl, "resumed_from", resumed, "was_pinned", ok)
	}
}

// detectManualRemovals handles the AC4 manual-removal release: a pinned/active
// workload that is not in the desired set this tick. The candidate set is the
// union of the Redis-active set, the FSM pin set, and the consumed set (so a
// hard-deadline-released workload's later annotation removal clears its stale
// consumed marker). For each candidate not desired this tick:
//
//   - Indeterminate workloads (FIX 2(a)) are skipped: a per-workload owner-read
//     error this tick leaves the desired state unproven. This is now PER
//     WORKLOAD, not a tick-wide veto: a positively-resolved, confirmed-absent
//     workload is still releasable even if some OTHER pod errored.
//   - Before releasing, the removal is CONFIRMED by a direct owner read (FIX
//     2(b)): parse the workload_id, GET the owner, and check it does NOT carry
//     the override annotation. This fixes the owner-scaled-to-zero / rollout-
//     churn false positive where a workload has zero live pods this tick (a
//     successful-but-empty list) yet the owner still carries the annotation.
//     Owner NotFound or owner-present-without-annotation => confirmed removal =>
//     release. Owner-present-WITH-annotation => not a removal (pods merely
//     absent) => skip. Owner GET error (non-NotFound) or unparseable id =>
//     indeterminate => skip.
func (c *Controller) detectManualRemovals(ctx context.Context, desiredSet map[string]desired, current map[string]OverrideRecord, indeterminate map[string]struct{}, resolveFailed bool) {
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
		// A POD-sourced override whose pod could not be resolved this tick is an
		// unproven absence: the owner object carries no annotation (the
		// annotation lived on the pod), so the owner-confirm below would falsely
		// read "removed". Skip it while a resolve failed this tick (FIX 2(a)
		// per-workload protection for the pod-sourced case).
		if resolveFailed {
			if rec, active := current[wl]; active && rec.Source == SourcePod {
				c.log.Warn("override: pod-sourced pin unresolvable this tick (resolve error); retaining pin (indeterminate)", "workload_id", wl)
				continue
			}
		}
		// Confirm the annotation is GENUINELY gone via a direct owner read
		// before treating the pod absence as a removal (FIX 2(b)).
		switch confirmOwnerAnnotation(ctx, c.cs, wl) {
		case ownerStillAnnotated:
			c.log.Info("override: candidate has zero live pods but owner still annotated; retaining pin (not a removal)", "workload_id", wl)
			continue
		case ownerIndeterminate:
			c.log.Warn("override: could not confirm owner annotation removal; retaining pin (indeterminate)", "workload_id", wl)
			continue
		case ownerRemovalConfirmed:
			// fall through to release.
		}
		resumed, ok := c.machine.ReleasePin(wl)
		// The annotation is confirmed gone; clear Redis (no-op if the key
		// already expired) and drop any consumed marker so a future re-add
		// re-pins.
		if err := c.store.Delete(ctx, wl); err != nil {
			c.log.Warn("override: redis delete on manual removal failed", "workload_id", wl, "err", err)
		}
		delete(c.consumed, wl)
		c.log.Info("override: released (annotation removed)", "workload_id", wl, "resumed_from", resumed, "was_pinned", ok)
	}
}

// emitRejection publishes a rejected OVERRIDES.applied event and increments the
// rejection counter (BI-5), but only on a NEW or CHANGED rejection for that
// workload (FIX 5, round 2). The NATS event is server-side deduped on
// workload+reason+state, so a standing invalid annotation would otherwise emit
// one event but increment the counter every poll. Tracking the last-rejected
// signature per workload makes the counter consistent with the event: a
// standing misconfiguration counts ONCE; a re-emit happens only when the
// operator changes the (still-invalid) requested value. It pins nothing and
// writes no Redis key.
func (c *Controller) emitRejection(ctx context.Context, d desired) {
	sig := d.rejectReason + "|" + d.requestedRaw
	if prev, ok := c.lastRejected[d.workloadID]; ok && prev == sig {
		// Already emitted+counted this exact standing rejection; do not
		// re-count or re-emit (consistent with the deduped NATS event).
		return
	}
	c.lastRejected[d.workloadID] = sig

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
