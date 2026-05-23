package baseline

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultWarmupDuration is the AC3 explicit "default 30 minutes"
// during which observations on a restarted workload are recorded
// into Welford state but no anomaly results are emitted.
const DefaultWarmupDuration = 30 * time.Minute

// WarmupConfig configures the per-workload warm-up window.
//
// Duration is hot-reloadable via config.Manager.Subscribe: the engine
// re-reads the field on the cadence of the live config; there is no
// Deployment-spec dependency on the value so a helm upgrade --set
// baselines.warmupDuration=15m propagates without restarting the
// aggregator (Story 1.15 rules.enabled restart-required carve-out
// does NOT apply here).
type WarmupConfig struct {
	Duration time.Duration
}

// DurationOrDefault returns Duration when positive, DefaultWarmupDuration
// otherwise. Used by the engine so a zero-valued WarmupConfig (e.g.
// from a partially-constructed test fixture) does not collapse the
// warm-up window to zero seconds.
func (c WarmupConfig) DurationOrDefault() time.Duration {
	if c.Duration > 0 {
		return c.Duration
	}
	return DefaultWarmupDuration
}

// warmupCacheEntry records the cache snapshot for a single workload.
// startedAt is the time the warm-up began; duration is the cached
// window length captured at Begin time so a mid-window hot-reload of
// WarmupConfig.Duration does not retroactively shorten or extend an
// active warm-up.
type warmupCacheEntry struct {
	startedAt time.Time
	duration  time.Duration
}

// nowFunc allows tests to inject a deterministic clock. The default
// is time.Now; tests assign a closure capturing a virtual current
// time.
type nowFunc func() time.Time

// Warmup is the per-workload warm-up controller. It owns an
// in-process sync.Map cache (workloadID -> warmupCacheEntry) and a
// reference to the durable Store. IsActive is the engine hot-path
// check; Begin is the cold path called once per restart event.
//
// Cardinality envelope: one cache entry per warm-up-active workload.
// At MVP scale (≤100 workloads per cluster) the cache is bounded
// even when every workload restarts simultaneously, and entries are
// reaped lazily when IsActive observes the window has elapsed.
type Warmup struct {
	store *Store
	cfg   atomic.Pointer[WarmupConfig]
	cache sync.Map
	now   nowFunc
}

// NewWarmup constructs a Warmup. Returns an error when store is nil
// so the engine constructor catches the misconfiguration at start-up.
// The supplied WarmupConfig is captured by pointer for hot-reload;
// future config updates use SetConfig.
func NewWarmup(store *Store, cfg WarmupConfig) (*Warmup, error) {
	if store == nil {
		return nil, errors.New("baseline: warmup: store is nil")
	}
	w := &Warmup{store: store, now: time.Now}
	w.cfg.Store(&cfg)
	return w, nil
}

// SetConfig replaces the warm-up window length. Called by the config
// manager's hot-reload callback. The active warm-ups in cache retain
// their captured duration, so a mid-window shortening cannot
// retroactively end a warm-up; only new Begin calls observe the new
// duration.
func (w *Warmup) SetConfig(cfg WarmupConfig) {
	w.cfg.Store(&cfg)
}

// SetNow overrides the clock for tests. Not safe for production use.
func (w *Warmup) SetNow(fn nowFunc) {
	if fn != nil {
		w.now = fn
	}
}

// IsActive reports whether the workload is currently inside an
// active warm-up window. Cache hits are O(1); cache misses fall
// through to the persisted Store so a controller restart does not
// lose warm-up state. AC4 explicit "warm-up state survives the
// restart" lives behind this fall-through.
//
// The cache is reaped lazily: an expired cache entry is deleted on
// the IsActive call that observes it.
func (w *Warmup) IsActive(ctx context.Context, namespace, pod string) (bool, error) {
	now := w.now().UTC()
	key := namespace + "/" + pod
	if cached, ok := w.cache.Load(key); ok {
		entry := cached.(warmupCacheEntry)
		if now.Sub(entry.startedAt) < entry.duration {
			return true, nil
		}
		w.cache.Delete(key)
		return false, nil
	}
	startedAt, duration, present, err := w.store.LoadWarmup(ctx, namespace, pod)
	if err != nil {
		return false, fmt.Errorf("baseline: warmup IsActive: %w", err)
	}
	if !present {
		return false, nil
	}
	if now.Sub(startedAt) >= duration {
		return false, nil
	}
	w.cache.Store(key, warmupCacheEntry{startedAt: startedAt, duration: duration})
	return true, nil
}

// Begin records a new warm-up window starting at now() for the
// workload. The durable Store is written first, then the cache; a
// crash after the SaveWarmup but before the cache.Store leaves the
// authoritative state in Redis where the next IsActive call (after
// controller restart) reloads it via the store fall-through path.
// Inverting this order would risk a cache-only entry that vanishes
// on restart, defeating AC4. Copilot C2 corrected the prior
// docstring which described the inverted order.
func (w *Warmup) Begin(ctx context.Context, namespace, pod string) error {
	dur := w.cfg.Load().DurationOrDefault()
	now := w.now().UTC()
	if err := w.store.SaveWarmup(ctx, namespace, pod, now, dur); err != nil {
		return fmt.Errorf("baseline: warmup Begin: %w", err)
	}
	key := namespace + "/" + pod
	w.cache.Store(key, warmupCacheEntry{startedAt: now, duration: dur})
	return nil
}

// ActiveWorkloads returns the namespace/pod pairs currently
// warm-up-active in cache. Used by the warmup_active gauge reader.
// Output ordering is non-deterministic (sync.Map.Range); callers
// requiring deterministic order sort the result themselves.
func (w *Warmup) ActiveWorkloads() []MetricKey {
	now := w.now().UTC()
	var out []MetricKey
	w.cache.Range(func(k, v any) bool {
		entry := v.(warmupCacheEntry)
		if now.Sub(entry.startedAt) >= entry.duration {
			w.cache.Delete(k)
			return true
		}
		key := k.(string)
		var ns, pod string
		for i := 0; i < len(key); i++ {
			if key[i] == '/' {
				ns = key[:i]
				pod = key[i+1:]
				break
			}
		}
		out = append(out, MetricKey{Namespace: ns, Pod: pod})
		return true
	})
	return out
}
