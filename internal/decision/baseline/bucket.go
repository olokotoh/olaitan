package baseline

import (
	"time"

	"github.com/olokotoh/olaitan/internal/schema"
)

const (
	// BucketWidth is the fixed time base every metric is sampled on
	// (Story 10.12 D2): one tumbling minute per workload on the
	// aggregator's clock. audit_events_per_min is exactly the bucket
	// count; the other metrics are per-minute counts or sums.
	BucketWidth = time.Minute

	// restartWindow is the trailing window container_restarts_per_hour
	// counts over, sampled once per bucket.
	restartWindow = time.Hour

	// idleEvictAfter stops tracking a workload that has produced no
	// event for this long. Its Welford and warm-up state stay in Redis
	// and resume on its next event; only the in-memory zero-fill stops.
	idleEvictAfter = time.Hour

	// maxGapFill caps how many empty minutes are back-filled with zero
	// samples when a tracker is advanced after a long pause (for example
	// the aggregator was paused by the scheduler). It equals
	// idleEvictAfter in minutes, so a tracked workload is never
	// back-filled for longer than it would have been zero-filled live.
	maxGapFill = int(idleEvictAfter / BucketWidth)

	// maxIDsPerBucket bounds the per-bucket event-ID dedupe set. Past it,
	// further events are still counted, just not de-duplicated; a
	// JetStream redelivery storm larger than this inside one minute is
	// far outside the NFR1 envelope.
	maxIDsPerBucket = 50000
)

// bucket accumulates one workload's events for one minute.
type bucket struct {
	start     time.Time
	ids       map[string]struct{}
	execPaths map[string]struct{}
	dests     map[string]struct{}
	bytesOut  float64
	audit     int
	restart   bool
	events    int
}

func newBucket(start time.Time) *bucket {
	return &bucket{
		start:     start,
		ids:       map[string]struct{}{},
		execPaths: map[string]struct{}{},
		dests:     map[string]struct{}{},
	}
}

// tracker is the in-memory per-workload state the engine keeps between
// buckets. It is owned by the engine's single processing goroutine.
type tracker struct {
	namespace  string
	key        string // the workload token in baseline:<ns>:<key>:metrics
	workloadID string // the correlator workload id, passed to FireBaselineDeviation
	identity   schema.WorkloadIdentity
	podUID     string
	lastEvent  time.Time
	cur        *bucket
	// prevIDs is the previous minute's event-ID set, so a redelivery that
	// crosses a minute boundary is still counted once.
	prevIDs map[string]struct{}
	// restarts maps a restarted container key to the time its restart
	// was first observed, pruned to restartWindow.
	restarts map[string]time.Time
}

// sample is one closed bucket, ready for evaluation.
type sample struct {
	at      time.Time
	values  map[string]float64
	restart bool
}

// add folds one event into the bucket and the tracker. ownActor reports
// whether an audit actor is one of Olaitan's own identities; audit events
// by such an actor are not workload behaviour (Story 10.12 D3).
func (tr *tracker) add(ev *schema.Event, now time.Time, ownActor func(string) bool) {
	b := tr.cur
	if ev.ID != "" {
		if _, dup := b.ids[ev.ID]; dup {
			return
		}
		if _, dup := tr.prevIDs[ev.ID]; dup {
			return
		}
		if len(b.ids) < maxIDsPerBucket {
			b.ids[ev.ID] = struct{}{}
		}
	}
	b.events++
	// The latest pod UID, so a deviation after a rollout names a live pod.
	if ev.Pod.UID != "" {
		tr.podUID = ev.Pod.UID
	}
	switch ev.Source {
	case schema.SourceFalco:
		if p := execPath(decodeRaw(ev)); p != "" {
			b.execPaths[p] = struct{}{}
		}
	case schema.SourceNetwork:
		if ev.Category != schema.CategoryFlow {
			return
		}
		raw := decodeRaw(ev)
		if flowReportedByDestination(ev, raw) {
			return
		}
		if d := flowDestination(raw); d != "" {
			b.dests[d] = struct{}{}
		}
		if n, ok := flowBytesOut(raw); ok {
			b.bytesOut += n
		}
	case schema.SourceAudit:
		if ownActor(auditActor(decodeRaw(ev))) {
			return
		}
		b.audit++
	case schema.SourceRuntime:
		if key, ok := restartedContainer(ev); ok {
			if _, seen := tr.restarts[key]; !seen {
				tr.restarts[key] = now
				b.restart = true
			}
		}
	}
}

// close turns the bucket into a sample. live reports whether a metric's
// source has been seen cluster-wide; a metric whose source has not is
// left out of the sample rather than recorded as zero.
func (tr *tracker) close(b *bucket, live func(schema.EventSource) bool) sample {
	end := b.start.Add(BucketWidth)
	for k, t := range tr.restarts {
		if !t.After(end.Add(-restartWindow)) {
			delete(tr.restarts, k)
		}
	}
	all := map[string]float64{
		MetricOutboundUniqueDst: float64(len(b.dests)),
		MetricDistinctExecPaths: float64(len(b.execPaths)),
		MetricOutboundBytes:     b.bytesOut,
		MetricAuditEventsPerMin: float64(b.audit),
		MetricRestartsPerHour:   float64(len(tr.restarts)),
	}
	values := make(map[string]float64, len(all))
	for m, v := range all {
		if live(metricSource[m]) {
			values[m] = v
		}
	}
	return sample{at: end, values: values, restart: b.restart}
}
