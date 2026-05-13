package posture

import (
	"sync"
	"time"

	"github.com/olokotoh/olaitan/internal/schema"
)

// cache is an in-memory TTL cache keyed by workload identity. It is
// safe for concurrent use; reads acquire a read-lock, writes acquire
// a write-lock. Stale entries are evicted lazily on Get under the
// write-lock (upgrade-on-hit) so the cache never grows unboundedly
// during long-running aggregator pods.
//
// The cache is NOT bounded by entry count. The design assumption is
// that an aggregator's active workload set is O(100) per the
// MVP/Growth cluster scale; at ~2 KiB per posture struct that is
// ~200 KiB, well inside the NFR10 1 GB aggregator memory budget.
// If a future cluster scale increase requires bounding, swap to an
// lru.Cache in a single-file change.
//
// Hit counting is the Client's responsibility: Client.cacheHits is
// the single authoritative counter and is what Client.PostureCacheHits
// reports. The cache deliberately does NOT track hits itself to keep
// the counter contract single-source and rule out the
// double-counting risk that two counters would invite.
type cache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
}

type cacheEntry struct {
	posture   *schema.WorkloadPosture
	expiresAt time.Time
}

func newCache() *cache {
	return &cache{entries: make(map[string]cacheEntry)}
}

// Get returns the cached posture for workloadID if a fresh entry
// exists. The freshness check uses now(); callers can inject a clock
// in tests. A stale entry is deleted lazily under the write-lock and
// the call returns (nil, false). Hit counting is up to the caller
// (Client.cacheHits is the authoritative counter for the package).
func (c *cache) Get(workloadID string, now func() time.Time) (*schema.WorkloadPosture, bool) {
	c.mu.RLock()
	entry, ok := c.entries[workloadID]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}

	t := now()
	if t.Before(entry.expiresAt) {
		return entry.posture, true
	}

	// Stale: lazy-evict under the write-lock. Re-check under the
	// write-lock in case a concurrent Put refreshed the entry while
	// we were waiting on the lock.
	c.mu.Lock()
	defer c.mu.Unlock()
	if cur, stillOK := c.entries[workloadID]; stillOK && t.Before(cur.expiresAt) {
		// Refreshed by a concurrent Put; honour it.
		return cur.posture, true
	}
	delete(c.entries, workloadID)
	return nil, false
}

// Put inserts or refreshes the cached posture for workloadID with
// expiry now()+ttl. A zero or negative ttl results in an immediately-
// expired entry (effectively a no-op once the entry is first read).
func (c *cache) Put(workloadID string, posture *schema.WorkloadPosture, ttl time.Duration, now func() time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[workloadID] = cacheEntry{
		posture:   posture,
		expiresAt: now().Add(ttl),
	}
}

// Reset clears the cache for test purity. Concurrent-use safe.
func (c *cache) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]cacheEntry)
}

// Len returns the current entry count. Concurrent-use safe.
func (c *cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
