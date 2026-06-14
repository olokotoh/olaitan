package settling

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

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
	// HistoryWriteTimeout bounds a single persisted-history read at finalisation;
	// defaults to 2s. A read that exceeds it falls back to the in-process
	// history rather than blocking the drainer.
	HistoryWriteTimeout time.Duration
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
	// observed accumulates the transitions seen in-process for this incident,
	// used as the history source when no persisted HistoryReader is wired (Open
	// Assumption 2 fallback). Reset on a CLEAN cycle.
	observed []schema.StateTransition
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

	// queue carries observed transitions from Publish to Run. Run is the SOLE
	// owner of all mutable state below, so there are no locks: the timer map,
	// pending map, and finalised set are touched only on the Run goroutine.
	queue chan schema.StateTransition
	// fired carries the workload id of an expired timer from the timer's own
	// AfterFunc goroutine back into the Run select loop, so the actual publish
	// (and the finalised check-and-set) happens single-threaded on Run.
	fired chan string
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
	historyTimeout := cfg.HistoryWriteTimeout
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
		fired:          make(chan string, qsize),
	}, nil
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
		case wid := <-c.fired:
			c.onFire(ctx, wid, timers, pendings, finalised)
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
		// marker so a LATER new incident for the same workload re-finalises.
		if t, ok := timers[wid]; ok {
			t.Stop()
			delete(timers, wid)
		}
		delete(pendings, wid)
		delete(finalised, wid)
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
	p.finalState = st.ToState
	p.threatScore = st.Confidence
	p.packageID = st.PackageID
	p.observed = append(p.observed, st)
	// A new non-CLEAN edge means the workload is moving again, so any prior
	// finalised marker for THIS incident must be cleared: a re-arm represents a
	// state change, and the surviving candidate may differ at the next expiry.
	delete(finalised, wid)

	widCopy := wid
	timers[wid] = time.AfterFunc(c.window, func() {
		// Hand the expiry back to the Run select loop; the publish + finalised
		// check-and-set happen single-threaded there. A non-blocking send: if the
		// fired buffer is full (extreme backlog) we drop, and the next transition
		// will re-arm.
		select {
		case c.fired <- widCopy:
		default:
		}
	})
}

// onFire handles a timer expiry on the Run goroutine: if the workload is still
// pending (no intervening CLEAN cancelled it) and not already finalised,
// publish exactly one IncidentFinalised and mark it finalised (once-only,
// BI-8). The timer entry is consumed.
func (c *Controller) onFire(ctx context.Context, wid string, timers map[string]*time.Timer, pendings map[string]*pending, finalised map[string]struct{}) {
	// The timer fired; drop its map entry (a stale entry would otherwise leak).
	delete(timers, wid)

	p, ok := pendings[wid]
	if !ok {
		// An intervening CLEAN cancelled this incident between the AfterFunc firing
		// and this select iteration (AC4 race): nothing to finalise.
		return
	}
	if _, done := finalised[wid]; done {
		// Already finalised this incident instance; do not double-publish (BI-8
		// in-memory once-only guard, backstopped by JetStream WithMsgID dedup).
		return
	}

	finalisedAt := c.now()
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
// event (BI-8, Open Assumption 5): package_id + ":" + the finalising-transition
// timestamp (FinalisedAt, nanoseconds). The package_id makes the dedup
// per-incident; the timestamp discriminator means a legitimately NEW incident
// for the same workload after a CLEAN cycle (a distinct finalisation) is NOT
// suppressed by the 2-minute dedup window, while a drainer re-publish / restart-
// replay of the SAME finalisation (same package_id + same FinalisedAt) IS
// server-side deduplicated. It is exported so the NATS-backed Publisher derives
// the same id the controller intends.
func FinalisedMsgID(evt IncidentFinalised) string {
	return evt.PackageID + ":" + strconv.FormatInt(evt.FinalisedAt.UnixNano(), 10)
}
