package override

import (
	"context"
	"fmt"
	"log/slog"
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

// reconcile runs one poll tick: it computes the DESIRED override set from the
// live pod annotations and the CURRENT set from Redis, then applies/refreshes
// active overrides, releases native-TTL-expired and manually-removed
// overrides, and rejects invalid targets (BI-4/BI-5/BI-8/BI-9).
func (c *Controller) reconcile(ctx context.Context) {
	desiredSet, rejections, err := c.computeDesired(ctx)
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
		c.log.Warn("override: list active overrides failed; skipping release detection", "err", err)
		current = map[string]OverrideRecord{}
	}

	// Apply / refresh desired overrides (BI-8 idempotency).
	for wl, d := range desiredSet {
		c.applyDesired(ctx, wl, d)
	}

	// Release detection (BI-4): a workload pinned in the FSM (or recorded in
	// Redis) but no longer desired is a release.
	c.detectReleases(ctx, desiredSet, current)
}

// computeDesired LISTs pods cluster-wide (honouring ExcludedNamespaces) and
// resolves each annotated pod to its desired override, applying the pod-over-
// owner precedence and the most-isolating tie-break for conflicting pods of
// the same owner (BI-9). Invalid targets are returned separately as rejections.
func (c *Controller) computeDesired(ctx context.Context) (map[string]desired, []desired, error) {
	pods, err := c.cs.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("override: list pods: %w", err)
	}

	desiredSet := map[string]desired{}
	var rejections []desired

	for i := range pods.Items {
		pod := &pods.Items[i]
		if _, skip := c.excluded[pod.Namespace]; skip {
			continue
		}
		// Read the operative annotation: pod-level wins over owner-level (BI-9).
		stateRaw, ttlRaw, source := c.operativeAnnotation(ctx, pod)
		if stateRaw == "" {
			continue
		}
		workloadID, rerr := resolveWorkloadID(ctx, c.cs, pod)
		if rerr != nil {
			c.log.Warn("override: resolve workload_id failed; skipping pod", "namespace", pod.Namespace, "pod", pod.Name, "err", rerr)
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
	return desiredSet, rejections, nil
}

// operativeAnnotation returns the (state, ttl, source) the override should use
// for pod, with the pod annotation winning over the owner annotation (BI-9).
func (c *Controller) operativeAnnotation(ctx context.Context, pod *corev1.Pod) (state, ttl, source string) {
	if v, ok := pod.Annotations[AnnotationState]; ok && v != "" {
		return v, pod.Annotations[AnnotationTTL], SourcePod
	}
	ownerAnns := ownerAnnotations(ctx, c.cs, pod)
	if v, ok := ownerAnns[AnnotationState]; ok && v != "" {
		return v, ownerAnns[AnnotationTTL], SourceOwner
	}
	return "", "", ""
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

// applyDesired pins the FSM and writes/refreshes the Redis key for one desired
// override. The pin transition emit is idempotent (BI-8): Pin only emits when
// the pin state changes; the Redis TTL is refreshed on every tick so the
// native TTL tracks the annotation's continued presence.
func (c *Controller) applyDesired(ctx context.Context, workloadID string, d desired) {
	// Idempotency (BI-8): if the workload is already pinned to the desired
	// state, this is an unchanged re-apply. Refresh the Redis TTL (so the
	// native TTL tracks the annotation's continued presence) but do NOT
	// re-emit the pin transition or a fresh applied event.
	_, alreadyPinned := c.machine.IsPinned(workloadID)
	prev, hadRecord, _ := c.store.Get(ctx, workloadID)
	pinnedSame := false
	if s, ok := c.machine.IsPinned(workloadID); ok && s == d.state {
		pinnedSame = true
	}

	// Capture the before-state for the event BEFORE the pin mutates current.
	before, _ := c.machine.CurrentState(workloadID)

	if err := c.machine.Pin(workloadID, d.state, d.operatorID); err != nil {
		// A validated state should never be rejected here; log defensively.
		c.log.Warn("override: pin failed", "workload_id", workloadID, "state", d.state, "err", err)
		return
	}

	appliedAt := c.now().UTC()
	// Preserve the original applied_at across idempotent re-applies so the
	// dedup id is stable and the audit trail records the first application.
	if hadRecord {
		appliedAt = prev.AppliedAt
	}
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

	// On an unchanged idempotent re-apply (already pinned to the same state
	// AND the Redis record already existed) we have only refreshed the TTL;
	// suppress the duplicate applied event to avoid sink/audit churn (BI-8).
	if alreadyPinned && pinnedSame && hadRecord {
		return
	}

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

// detectReleases handles the two non-applied poll outcomes (BI-4): a Redis key
// gone (native-TTL expiry) and an annotation removed while the Redis key is
// still present (manual removal). Both call ReleasePin; manual removal also
// deletes the Redis key. The desired set is the still-valid overrides; any
// pinned-or-recorded workload not in it is a release candidate.
func (c *Controller) detectReleases(ctx context.Context, desiredSet map[string]desired, current map[string]OverrideRecord) {
	// Union of workloads recorded in Redis and pinned in the FSM, minus the
	// still-desired set, are release candidates. We drive off the Redis set
	// (manual removal: key present, annotation gone) and the FSM pin set
	// (native-TTL expiry: key gone, pin still held).
	candidates := map[string]struct{}{}
	for wl := range current {
		candidates[wl] = struct{}{}
	}
	for wl := range c.machine.PinnedWorkloads() {
		candidates[wl] = struct{}{}
	}

	for wl := range candidates {
		if _, stillDesired := desiredSet[wl]; stillDesired {
			continue
		}
		_, keyPresent := current[wl]
		resumed, ok := c.machine.ReleasePin(wl)
		if keyPresent {
			// Manual removal (AC4): clear Redis immediately.
			if err := c.store.Delete(ctx, wl); err != nil {
				c.log.Warn("override: redis delete on manual removal failed", "workload_id", wl, "err", err)
			}
			c.log.Info("override: released (annotation removed)", "workload_id", wl, "resumed_from", resumed, "was_pinned", ok)
		} else {
			// Native-TTL expiry: Redis already dropped the key.
			c.log.Info("override: released (ttl expiry)", "workload_id", wl, "resumed_from", resumed, "was_pinned", ok)
		}
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
