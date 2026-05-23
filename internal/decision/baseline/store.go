package baseline

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/olokotoh/olaitan/internal/keys"
	redisclient "github.com/olokotoh/olaitan/internal/redis"
)

// MetricKey identifies a single per-workload, per-metric Welford
// stream. Used in tests and as the typed input to Store helpers; in
// production the engine iterates the defaultExtractors registry and
// builds keys by combining the workload identity with the metric name.
type MetricKey struct {
	Namespace string
	Pod       string
	Metric    string
}

// warmupFieldStartedAtNs and warmupFieldDurationNs are the two field
// names persisted alongside the per-metric Welford triplets in the
// same Redis hash. Co-locating warm-up state with metric state means
// every Save round-trip covers both halves, so a process crash mid
// restart-handling cannot leave one half stale.
const (
	warmupFieldStartedAtNs = "warmup.started_at_ns"
	warmupFieldDurationNs  = "warmup.duration_ns"
)

// Store persists per-workload Welford state into the baseline family
// hash baseline:<namespace>:<pod>:metrics. All five metrics for a
// workload live in a single hash, packed via prefixed field names
// (<metric>.count, <metric>.mean, <metric>.m2), so one HGETALL and
// one HSET cover the whole per-workload state per evaluation.
//
// The 48h TTL is enforced by the existing SetBaselineMetrics setter
// in internal/redis/setters.go; this package never writes via Raw().
type Store struct {
	client *redisclient.Client
}

// NewStore constructs a Store. Returns an error when client is nil
// so the engine constructor catches the misconfiguration at start-up
// rather than crashing on the first inbound package.
func NewStore(client *redisclient.Client) (*Store, error) {
	if client == nil {
		return nil, errors.New("baseline: store: redis client is nil")
	}
	return &Store{client: client}, nil
}

// Load reads the baseline hash for a workload and returns one
// Welford per metric in the supplied metric-name set. A missing key
// is NOT an error: a never-seen workload starts cold with zero
// Welfords for every metric. The returned map is keyed by metric
// name and always contains an entry for every requested metric
// (zero state when the field set is absent).
func (s *Store) Load(ctx context.Context, namespace, pod string, metricNames []string) (map[string]*Welford, error) {
	out := make(map[string]*Welford, len(metricNames))
	for _, m := range metricNames {
		out[m] = &Welford{}
	}
	key, err := keys.BaselineMetrics(namespace, pod)
	if err != nil {
		return nil, fmt.Errorf("baseline: store load: %w", err)
	}
	rdb := s.client.Raw()
	if rdb == nil {
		return nil, redisclient.ErrClientClosed
	}
	all, err := rdb.HGetAll(ctx, key).Result()
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			return out, nil
		}
		return nil, fmt.Errorf("baseline: hgetall %q: %w", key, err)
	}
	if len(all) == 0 {
		return out, nil
	}
	for _, m := range metricNames {
		fields := map[string]string{}
		if v, ok := all[m+".count"]; ok {
			fields["count"] = v
		}
		if v, ok := all[m+".mean"]; ok {
			fields["mean"] = v
		}
		if v, ok := all[m+".m2"]; ok {
			fields["m2"] = v
		}
		if err := out[m].UnmarshalRedisHash(fields); err != nil {
			return nil, fmt.Errorf("baseline: unmarshal metric %q: %w", m, err)
		}
	}
	return out, nil
}

// Save writes the supplied per-metric Welford state into the workload's
// baseline hash via SetBaselineMetrics so the 48h family TTL is
// refreshed atomically with the HSET. The fields slice is sorted by
// metric name for deterministic ordering across runs (relevant when a
// future story diffs successive Saves for debug surfaces). The HSET is
// a full overwrite of the supplied fields; existing fields not in the
// payload (e.g. warmup.* when only Save is called) are preserved by
// Redis's HSET semantics.
func (s *Store) Save(ctx context.Context, namespace, pod string, baselines map[string]*Welford) error {
	if len(baselines) == 0 {
		return errors.New("baseline: save: empty baselines")
	}
	key, err := keys.BaselineMetrics(namespace, pod)
	if err != nil {
		return fmt.Errorf("baseline: store save: %w", err)
	}
	names := make([]string, 0, len(baselines))
	for name := range baselines {
		names = append(names, name)
	}
	sort.Strings(names)
	fields := make(map[string]any, len(baselines)*3)
	for _, name := range names {
		w := baselines[name]
		if w == nil {
			w = &Welford{}
		}
		hash := w.MarshalRedisHash()
		for k, v := range hash {
			fields[name+"."+k] = v
		}
	}
	if err := s.client.SetBaselineMetrics(ctx, key, fields); err != nil {
		return fmt.Errorf("baseline: save %q: %w", key, err)
	}
	return nil
}

// LoadWarmup reads the warm-up state persisted alongside the
// per-metric Welford fields. Returns (zeroTime, 0, false, nil) when
// the workload has no warm-up entry; returns the persisted state
// when both warmup.started_at_ns and warmup.duration_ns are present.
// Active is computed by the caller from startedAt+duration vs now;
// LoadWarmup is purely a deserialisation surface.
func (s *Store) LoadWarmup(ctx context.Context, namespace, pod string) (startedAt time.Time, duration time.Duration, present bool, err error) {
	key, err := keys.BaselineMetrics(namespace, pod)
	if err != nil {
		return time.Time{}, 0, false, fmt.Errorf("baseline: load warmup: %w", err)
	}
	rdb := s.client.Raw()
	if rdb == nil {
		return time.Time{}, 0, false, redisclient.ErrClientClosed
	}
	all, err := rdb.HGetAll(ctx, key).Result()
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			return time.Time{}, 0, false, nil
		}
		return time.Time{}, 0, false, fmt.Errorf("baseline: hgetall %q: %w", key, err)
	}
	startedStr, hasStarted := all[warmupFieldStartedAtNs]
	durStr, hasDur := all[warmupFieldDurationNs]
	if !hasStarted || !hasDur {
		return time.Time{}, 0, false, nil
	}
	startedNs, err := strconv.ParseInt(startedStr, 10, 64)
	if err != nil {
		return time.Time{}, 0, false, fmt.Errorf("baseline: parse warmup started_at_ns %q: %w", startedStr, err)
	}
	durNs, err := strconv.ParseInt(durStr, 10, 64)
	if err != nil {
		return time.Time{}, 0, false, fmt.Errorf("baseline: parse warmup duration_ns %q: %w", durStr, err)
	}
	return time.Unix(0, startedNs).UTC(), time.Duration(durNs), true, nil
}

// SaveWarmup writes the warm-up state into the workload's baseline
// hash, refreshing the 48h family TTL via SetBaselineMetrics. The
// HSET is a partial update; existing per-metric fields in the same
// hash are preserved.
func (s *Store) SaveWarmup(ctx context.Context, namespace, pod string, startedAt time.Time, duration time.Duration) error {
	if startedAt.IsZero() {
		return errors.New("baseline: save warmup: started_at is zero")
	}
	if duration <= 0 {
		return fmt.Errorf("baseline: save warmup: duration must be > 0 (got %s)", duration)
	}
	key, err := keys.BaselineMetrics(namespace, pod)
	if err != nil {
		return fmt.Errorf("baseline: save warmup: %w", err)
	}
	fields := map[string]any{
		warmupFieldStartedAtNs: strconv.FormatInt(startedAt.UTC().UnixNano(), 10),
		warmupFieldDurationNs:  strconv.FormatInt(int64(duration), 10),
	}
	if err := s.client.SetBaselineMetrics(ctx, key, fields); err != nil {
		return fmt.Errorf("baseline: save warmup %q: %w", key, err)
	}
	return nil
}
