package settling

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/schema"
)

// defaultWindow is the settling window when Config.Window is non-positive
// (FR42/NFR7). The config layer already defaults to 60s; this is the
// belt-and-braces default for a directly-constructed Controller (tests).
const defaultWindow = 60 * time.Second

// defaultQueueSize bounds the Publish enqueue buffer. A transition is a small
// struct and the FSM fans out at most one per actual change; 256 gives generous
// slack so Publish never blocks the FSM goroutine on a slow Run drain.
const defaultQueueSize = 256

// Publisher is the one-method publish seam (the audit AuditTransitionPublisher
// precedent) so the controller's tests inject a capturing fake without a real
// NATS connection. The implementation publishes to subjects.IncidentFinalised
// via PublishJS with the BI-8 dedup msg id.
type Publisher interface {
	PublishIncidentFinalised(ctx context.Context, evt IncidentFinalised) error
}

// HistoryReader is the optional restart-safe FSM-history source (Open
// Assumption 2). When non-nil the controller reads the durable Redis history
// at finalisation, so a controller restart mid-incident still publishes the
// full history. When nil the controller falls back to the transitions it
// observed in-process. *fsm.Store satisfies it via LoadHistory.
type HistoryReader interface {
	LoadHistory(ctx context.Context, workloadID string) ([]schema.StateTransition, error)
}

// Config configures a Controller.
type Config struct {
	// Window is the settling window (default 60s, FR42/NFR7): how long a
	// workload must stay stable in a non-CLEAN state before finalisation.
	Window time.Duration
	// QueueSize bounds the Publish buffer; defaults to 256.
	QueueSize int
	// HistoryReadTimeout bounds a single persisted-history READ at finalisation;
	// defaults to 2s. A read that exceeds it falls back to the in-process
	// history rather than blocking the drainer. (Historical note: this field
	// was previously misnamed HistoryWriteTimeout; the settling controller only
	// ever READS history, it never writes it.)
	HistoryReadTimeout time.Duration
	// PublishTimeout bounds a single PublishJS at finalisation; defaults to 2s.
	PublishTimeout time.Duration
}

// pending is the per-workload settling candidate the Run goroutine tracks
// between arming a timer and firing it. It carries everything needed to build
// the IncidentFinalised event so finalisation needs no FSM accessor (BI-7).
type pending struct {
	finalState  schema.PodSecurityState
	threatScore float64
	packageID   string
	workloadID  string
	// gen is the timer generation stamped on this pending when its timer was last
	// armed/re-armed. It is drawn from the controller's LIFETIME-MONOTONIC counter
	// (Controller.nextGen), so it is unique across the whole controller lifetime
	// and is NEVER reset or reused, even across CLEAN cycles or new pending
	// instances. onFire ignores any expiry signal whose gen does not match the
	// current pending gen, so a stale expiry from a superseded (already-Stop()ed
	// but already-fired) timer becomes a no-op. A lifetime-monotonic gen closes
	// BOTH the round-1 re-arm race AND the round-2 aliasing-across-CLEAN race: a
	// stale fire's gen can never equal any FUTURE pending's gen, because nextGen
	// strictly increases and is never reset (the round-1 per-pending gen reset to
	// 0 on a new pending re-opened that race across a CLEAN cycle).
	gen uint64
	// observed accumulates the transitions seen in-process for this incident,
	// used as the history source when no persisted HistoryReader is wired (Open
	// Assumption 2 fallback). Reset on a CLEAN cycle.
	observed []schema.StateTransition
}

// firedSignal is the per-expiry message the timer's AfterFunc posts back to the
// Run select loop. It carries BOTH the workload id and the generation captured
// when the timer was armed, so onFire can distinguish a live expiry from a
// stale one left behind by a superseded timer (HIGH round-1).
type firedSignal struct {
	wid string
	gen uint64
}

// Controller is the settling-window sink + background drainer (BI-1/BI-2). It
// is a fsm.TransitionSink fanned out via fsm.MultiSink: Publish is NON-BLOCKING
// and enqueues every observed transition onto a bounded channel; the single Run
// worker owns the per-workload timer map, the in-process history accumulation,
// and the once-only finalised set, and does the synchronous PublishJS on timer
// expiry OFF the FSM hot path. This mirrors the Story 4.2 forensics controller
// discipline (Publish enqueues, Run owns the lifecycle).
type Controller struct {
	pub     Publisher
	history HistoryReader
	log     *slog.Logger
	now     func() time.Time

	window         time.Duration
	historyTimeout time.Duration
	publishTimeout time.Duration

	// dropped counts transitions dropped on a full Publish queue, labelled by
	// edge ("clean" vs "non_clean"). A dropped CLEAN is the dangerous case (a
	// since-stabilised workload can still be falsely finalised by its armed
	// timer), so operators alert on edge="clean" (MED round-1). Nil when no
	// metrics registry was wired (e.g. unit tests).
	dropped *prometheus.CounterVec

	// queue carries observed transitions from Publish to Run. Run is the SOLE
	// owner of all mutable state below, so there are no locks: the timer map,
	// pending map, and finalised set are touched only on the Run goroutine.
	queue chan schema.StateTransition
	// fired carries the (workload id, generation) of an expired timer from the
	// timer's own AfterFunc goroutine back into the Run select loop, so the
	// actual publish (and the finalised check-and-set) happens single-threaded
	// on Run. The generation lets Run reject a stale expiry (HIGH round-1).
	fired chan firedSignal

	// nextGen is the LIFETIME-MONOTONIC timer-generation counter. It is owned by
	// the Run goroutine (all arming happens on Run, so it needs no lock) and is
	// incremented on EVERY arm/re-arm; the post-increment value is stamped onto
	// the pending and captured in the AfterFunc closure. Because it strictly
	// increases and is NEVER reset or reused, a stale fire's captured gen can
	// never equal any future pending's gen, across CLEAN cycles, re-arms, or new
	// pending instances. This closes both the round-1 re-arm race and the round-2
	// aliasing-across-CLEAN race (round-2 HIGH).
	nextGen uint64
}

// New constructs a Controller. pub must be non-nil. history may be nil to fall
// back to in-process history accumulation (Open Assumption 2). log defaults to
// slog.Default when nil.
func New(cfg Config, pub Publisher, history HistoryReader, log *slog.Logger) (*Controller, error) {
	if pub == nil {
		return nil, fmt.Errorf("settling: nil publisher")
	}
	if log == nil {
		log = slog.Default()
	}
	window := cfg.Window
	if window <= 0 {
		window = defaultWindow
	}
	qsize := cfg.QueueSize
	if qsize <= 0 {
		qsize = defaultQueueSize
	}
	historyTimeout := cfg.HistoryReadTimeout
	if historyTimeout <= 0 {
		historyTimeout = 2 * time.Second
	}
	publishTimeout := cfg.PublishTimeout
	if publishTimeout <= 0 {
		publishTimeout = 2 * time.Second
	}
	return &Controller{
		pub:            pub,
		history:        history,
		log:            log,
		now:            func() time.Time { return time.Now().UTC() },
		window:         window,
		historyTimeout: historyTimeout,
		publishTimeout: publishTimeout,
		queue:          make(chan schema.StateTransition, qsize),
		fired:          make(chan firedSignal, qsize),
	}, nil
}

// RegisterMetrics registers the settling-window metric families on the shared
// registry, pre-initialising the labelled series to 0 so alert PromQL has a
// stable zero series from process startup (the netpol/forensics precedent). It
// is OPTIONAL: a controller with no registry (unit tests) silently skips the
// drop counters. Call it once before Run.
func (c *Controller) RegisterMetrics(r *metrics.Registry) error {
	dc, err := r.RegisterCounterVec(
		"olaitan_settling_dropped_total",
		"Cumulative transitions dropped because the settling Publish queue was full, labelled by edge: non_clean (a settling timer was not re-armed for this escalation; benign, the next edge re-arms) or clean (DANGEROUS: a dropped CLEAN leaves an armed timer that may falsely finalise a since-stabilised workload; alert on edge=\"clean\") (Story 4.3 round-1 follow-up).",
		[]string{"edge"},
	)
	if err != nil {
		return err
	}
	c.dropped = dc
	for _, edge := range []string{"clean", "non_clean"} {
		dc.WithLabelValues(edge).Add(0)
	}
	return nil
}

// Publish is the fsm.TransitionSink seam (BI-2). It is NON-BLOCKING: it only
// enqueues the observed transition for the Run drainer and never touches the
// timer map / finalised set (those are owned single-threaded by Run). On a full
// queue it drops with a warning rather than stalling the FSM goroutine. The
// arm/reset/cancel decision is made on Run, keyed on whether ToState is CLEAN.
func (c *Controller) Publish(st schema.StateTransition) {
	select {
	case c.queue <- st:
	default:
		// A dropped transition is the only way a finalisation can be missed; the
		// queue is sized for the expected transition rate, so a drop indicates a
		// burst beyond that sizing or a stalled drainer. We log rather than block
		// (the FSM hot path must never stall on the settling sink).
		//
		// MED (round-1): a dropped CLEAN edge is the dangerous case. A workload
		// that de-escalated to CLEAN but whose CLEAN edge was dropped keeps its
		// armed timer, which then FALSELY finalises a since-stabilised workload.
		// A dropped non-CLEAN edge is benign (the next edge re-arms; at worst the
		// candidate final state lags one edge). So we split the metric by edge and
		// elevate a dropped CLEAN to an alert-level (Error) log so operators can
		// detect the rare false-finalisation condition. We do NOT make Publish
		// blocking: preservation-priority requires the FSM hot path never stall.
		if st.ToState == schema.StateClean {
			if c.dropped != nil {
				c.dropped.WithLabelValues("clean").Inc()
			}
			c.log.Error("settling: queue full; dropped a CLEAN edge (armed timer may falsely finalise a since-stabilised workload)",
				"workload_id", st.WorkloadID, "from_state", string(st.FromState))
			return
		}
		if c.dropped != nil {
			c.dropped.WithLabelValues("non_clean").Inc()
		}
		c.log.Warn("settling: queue full; dropping transition (settling timer not re-armed for this edge)",
			"workload_id", st.WorkloadID, "to_state", string(st.ToState))
	}
}

// Run is the background drainer (BI-2). It owns the per-workload timer map, the
// pending-candidate map, and the once-only finalised set, all touched only on
// this goroutine (no locks). It arms/resets a timer on each non-CLEAN
// transition, cancels on CLEAN (clearing the finalised marker so a later new
// incident re-finalises, AC4), and publishes IncidentFinalised on timer expiry.
// Wire it into the errgroup; it returns nil on graceful context cancellation.
func (c *Controller) Run(ctx context.Context) error {
	timers := make(map[string]*time.Timer)
	pendings := make(map[string]*pending)
	finalised := make(map[string]struct{})

	// stopAll halts any outstanding timers on shutdown so their AfterFunc does
	// not fire into a closed loop.
	defer func() {
		for _, t := range timers {
			t.Stop()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			// In-flight settling timers are ABANDONED on shutdown: their workloads
			// are still isolated by the Story 2.4-4.1 enforcement (a non-CLEAN FSM
			// state persists in Redis), and a restart re-arms the window off the
			// first transition observed after recovery. We do not publish on
			// shutdown (an incomplete window is not a finalisation).
			return nil
		case st := <-c.queue:
			c.onTransition(st, timers, pendings, finalised)
		case sig := <-c.fired:
			c.onFire(ctx, sig, timers, pendings, finalised)
		}
	}
}

// onTransition handles one observed transition on the Run goroutine: a CLEAN
// ToState cancels the timer and clears all per-workload state (AC4); any other
// (non-CLEAN) ToState (re)arms the timer with the new candidate final state and
// score (AC1/AC2), and accumulates the transition for the in-process history
// fallback.
func (c *Controller) onTransition(st schema.StateTransition, timers map[string]*time.Timer, pendings map[string]*pending, finalised map[string]struct{}) {
	wid := st.WorkloadID
	if st.ToState == schema.StateClean {
		// AC4: de-escalation to CLEAN cancels the timer and clears the finalised
		// marker so a LATER new incident for the same workload re-finalises. A
		// stale in-flight expiry from the just-Stop()ed timer is rejected by onFire
		// on the lifetime-monotonic gen mismatch alone: the pending (and its gen)
		// is deleted here, and any future re-armed pending will carry a STRICTLY
		// GREATER gen drawn from c.nextGen, so the stale fire can never match it
		// (round-2 HIGH: a per-pending gen reset on a fresh pending re-opened this
		// race across a CLEAN cycle; the monotonic counter closes it).
		if t, ok := timers[wid]; ok {
			t.Stop()
			delete(timers, wid)
		}
		delete(pendings, wid)
		// CLEAN is the ONLY edge that clears the once-only finalised marker: a
		// CLEAN cycle ends the incident, so a later new non-CLEAN incident for the
		// same workload re-finalises (AC4). A non-CLEAN escalation must NOT clear
		// it (MED round-1: once-only across escalation-after-finalisation).
		delete(finalised, wid)
		return
	}

	// MED (round-1): once-only across escalation-after-finalisation. If this
	// workload's CURRENT incident has already been finalised (no intervening
	// CLEAN reset it), a further non-CLEAN escalation (e.g. QUARANTINED ->
	// PRESERVED_KILLED) must NOT re-finalise the same ongoing incident. We still
	// accumulate the transition into the in-process history (so a later, post-
	// CLEAN incident's fallback history is complete), but we do NOT re-arm a
	// timer. Only a CLEAN cycle (above) resets finalisation.
	if _, done := finalised[wid]; done {
		if p, ok := pendings[wid]; ok {
			p.observed = append(p.observed, st)
		}
		return
	}

	// Open Assumption 3 (pinned/overridden workloads): an operator override into
	// a non-CLEAN state arrives here as an ordinary StateTransition (TriggerType
	// "override", Reason operator_override) and is treated IDENTICALLY to an
	// automated escalation. A pinned QUARANTINED/PRESERVED_KILLED workload stable
	// past the settling window is a real incident worth a DFIR report, so it
	// finalises. No special-casing: the window's contract is "stable in a
	// non-CLEAN state past the window", regardless of how the state arose.
	//
	// AC1/AC2: (re)arm the per-workload timer for the configured window with the
	// new candidate final state. Stopping any prior timer first means a rapidly
	// de-escalating or oscillating incident never accrues the full window
	// against a stale candidate (the FSM's own stateEnteredAt re-stamp analogue).
	if t, ok := timers[wid]; ok {
		t.Stop()
	}
	p, ok := pendings[wid]
	if !ok {
		p = &pending{workloadID: wid}
		pendings[wid] = p
	}
	// HIGH (round-1 + round-2): stamp a LIFETIME-MONOTONIC generation on EVERY
	// re-arm. The previous timer was just Stop()ed, but Stop returns false if its
	// AfterFunc had already begun; such a stale expiry carries the OLD gen and is
	// rejected by onFire. Drawing from c.nextGen (never reset, never reused, owned
	// by this single Run goroutine) means the stamped gen is unique for the whole
	// controller lifetime, so a stale fire can never alias a FUTURE pending's gen
	// even across a CLEAN cycle (round-2 HIGH). The captured gen below is the only
	// one onFire will honour.
	c.nextGen++
	p.gen = c.nextGen
	p.finalState = st.ToState
	// MED (round-1): override-triggered finalisation can carry an empty PackageID
	// and zero Confidence (an operator pin need not re-run an evaluation). Prefer
	// the values from THIS transition, but if a field is unpopulated on an
	// override edge, retain the last non-empty/non-zero value already captured
	// for this incident (from a prior automated escalation, when one exists). The
	// genuine-empty case for a pinned-from-the-start incident is accepted and
	// documented at finalisation (see onFire). [Open Assumption 3]
	if st.PackageID != "" {
		p.packageID = st.PackageID
	}
	if st.Confidence != 0 {
		p.threatScore = st.Confidence
	}
	p.observed = append(p.observed, st)

	gen := p.gen
	widCopy := wid
	timers[wid] = time.AfterFunc(c.window, func() {
		// Hand the expiry back to the Run select loop; the publish + finalised
		// check-and-set happen single-threaded there. A non-blocking send: if the
		// fired buffer is full (extreme backlog) we drop, and the next transition
		// will re-arm. The captured gen lets onFire reject a stale expiry.
		select {
		case c.fired <- firedSignal{wid: widCopy, gen: gen}:
		default:
		}
	})
}

// onFire handles a timer expiry on the Run goroutine: if the workload is still
// pending (no intervening CLEAN cancelled it) and not already finalised,
// publish exactly one IncidentFinalised and mark it finalised (once-only,
// BI-8). The timer entry is consumed.
func (c *Controller) onFire(ctx context.Context, sig firedSignal, timers map[string]*time.Timer, pendings map[string]*pending, finalised map[string]struct{}) {
	wid := sig.wid

	p, ok := pendings[wid]
	if !ok {
		// An intervening CLEAN cancelled this incident between the AfterFunc firing
		// and this select iteration (AC4 race): nothing to finalise. Do NOT touch
		// timers[wid]: a CLEAN already deleted it, and a NEW non-CLEAN edge may
		// have re-armed a live timer we must not orphan.
		return
	}
	// HIGH (round-1 + round-2): reject a STALE expiry. The signal carries the gen
	// captured when its timer was armed; if the current pending gen has moved on,
	// this expiry belongs to a superseded (Stop()ed-but-already-fired) timer. Treat
	// it as a no-op so we neither publish for the NEW candidate (whose window has
	// NOT elapsed) nor delete the live re-armed timer entry. Because the gen is
	// LIFETIME-MONOTONIC (Controller.nextGen, never reset), this also rejects a
	// stale fire buffered across a CLEAN cycle: incident A's stale gen can never
	// equal a later incident B's gen for the same workload (round-2 HIGH).
	if sig.gen != p.gen {
		return
	}
	if _, done := finalised[wid]; done {
		// Already finalised this incident instance; do not double-publish (BI-8
		// in-memory once-only guard, backstopped by JetStream WithMsgID dedup).
		return
	}
	// This expiry matches the live generation, so its timer has fired and is
	// consumed: drop the map entry now (a stale entry would otherwise leak). The
	// gen check above guaranteed we are not deleting a re-armed live timer.
	delete(timers, wid)

	finalisedAt := c.now()
	// MED (round-1): an override/pinned-from-the-start incident may still carry an
	// empty package_id and zero threat_score (no automated evaluation ever ran).
	// We accept an empty package_id as VALID-FOR-PINNED rather than dropping the
	// finalisation: a pinned QUARANTINED/PRESERVED_KILLED workload stable past the
	// window is a real incident worth a DFIR report (Open Assumption 3). The
	// committed JSON schema does not require package_id to be non-empty, and
	// FinalisedMsgID stays unique even when package_id is "" because it leads with
	// the always-present workload_id (round-2 LOW: two distinct empty-package_id
	// workloads finalising at the same nanosecond no longer collide), so dedup is
	// not weakened. We log the empty-package_id case so operators can correlate the
	// pinned finalisation.
	if p.packageID == "" {
		c.log.Info("settling: finalising a pinned incident with empty package_id (no automated evaluation ran; valid-for-pinned, dedup falls to finalised_at)",
			"workload_id", wid, "final_state", string(p.finalState))
	}
	evt := IncidentFinalised{
		SchemaVersion: SchemaVersionIncidentFinalised,
		PackageID:     p.packageID,
		WorkloadID:    p.workloadID,
		FinalState:    string(p.finalState),
		ThreatScore:   p.threatScore,
		FinalisedAt:   finalisedAt,
		History:       c.resolveHistory(ctx, p),
	}

	if err := c.publish(ctx, evt); err != nil {
		// A publish failure does NOT mark the incident finalised, so the NEXT
		// transition (or a re-arm) can retry. A NATS outage therefore defers the
		// finalisation rather than losing it silently. We do not block the loop on
		// a retry here (the FSM keeps producing transitions); the WithMsgID dedup
		// makes a later successful publish of the same incident idempotent.
		c.log.Warn("settling: publish IncidentFinalised failed; will retry on next edge",
			"workload_id", wid, "final_state", evt.FinalState, "err", err)
		return
	}
	finalised[wid] = struct{}{}
	// LOW (round-1): drop the pending candidate now that it is published. The
	// in-process history accumulation is no longer needed (it was a fallback for
	// THIS finalisation, now done), and the once-only marker is carried by the
	// finalised set, not the pending. This bounds the pendings map to actively-
	// settling (not-yet-finalised) workloads; the common terminal PRESERVED_KILLED
	// case no longer accumulates a pending forever. A later escalation-after-
	// finalisation (no CLEAN) re-creates a pending only to accumulate history and
	// is short-circuited by the finalised check in onTransition; a CLEAN cycle
	// clears the finalised marker so a new incident re-arms from scratch.
	//
	// finalised[wid] is retained as the once-only marker; its retention is bounded
	// by the count of distinct-ever-finalised workloads that never subsequently
	// went CLEAN. For the terminal-kill common case this is the live killed-pod
	// population, which is itself bounded by the cluster; a CLEAN cycle GCs it.
	delete(pendings, wid)
	c.log.Info("settling: incident finalised",
		"workload_id", wid, "final_state", evt.FinalState, "threat_score", evt.ThreatScore,
		"history_len", len(evt.History))
}

// resolveHistory returns the FSM history for the event. It PREFERS the durable
// Redis-backed history (restart-safe, Open Assumption 2) when a HistoryReader
// is wired and the read succeeds and is non-empty; otherwise it falls back to
// the transitions observed in-process for this incident. The controller never
// blocks finalisation on the history read: a read error or timeout falls back.
func (c *Controller) resolveHistory(ctx context.Context, p *pending) []schema.StateTransition {
	if c.history != nil {
		hctx, cancel := context.WithTimeout(ctx, c.historyTimeout)
		hist, err := c.history.LoadHistory(hctx, p.workloadID)
		cancel()
		if err != nil {
			c.log.Warn("settling: persisted history read failed; using in-process history",
				"workload_id", p.workloadID, "err", err)
		} else if len(hist) > 0 {
			return hist
		}
	}
	// Fallback: the in-process accumulation. Copy so the event does not alias
	// the pending slice (the pending is cleared/reused on a CLEAN cycle).
	if len(p.observed) == 0 {
		return nil
	}
	out := make([]schema.StateTransition, len(p.observed))
	copy(out, p.observed)
	return out
}

// publish performs the synchronous PublishJS with a bounded deadline.
func (c *Controller) publish(ctx context.Context, evt IncidentFinalised) error {
	pctx, cancel := context.WithTimeout(ctx, c.publishTimeout)
	defer cancel()
	return c.pub.PublishIncidentFinalised(pctx, evt)
}

// FinalisedMsgID derives the JetStream WithMsgID dedup id for an IncidentFinalised
// event (BI-8, Open Assumption 5): workload_id + ":" + package_id + ":" + the
// finalising-transition timestamp (FinalisedAt, nanoseconds). The workload_id +
// package_id make the dedup per-incident; the timestamp discriminator means a
// legitimately NEW incident for the same workload after a CLEAN cycle (a distinct
// finalisation) is NOT suppressed by the 2-minute dedup window, while a drainer
// re-publish / restart-replay of the SAME finalisation (same workload_id +
// package_id + same FinalisedAt) IS server-side deduplicated. It is exported so
// the NATS-backed Publisher derives the same id the controller intends.
//
// LOW (round-2): workload_id is folded in as the leading discriminator because a
// pinned-from-the-start incident carries an EMPTY package_id (the override-
// retention change in round-1 made empty-package_id a fully supported path). With
// only "package_id:nanos", two DISTINCT pinned workloads finalising at the same
// nanosecond would collide on ":<nanos>" and JetStream WithMsgID would suppress
// the second, silently dropping a real incident. workload_id is always present
// and is the natural per-incident disambiguator, and same-incident replay dedup
// stays intact (same workload_id + package_id + FinalisedAt).
func FinalisedMsgID(evt IncidentFinalised) string {
	return evt.WorkloadID + ":" + evt.PackageID + ":" + strconv.FormatInt(evt.FinalisedAt.UnixNano(), 10)
}
