// Package podidentity keeps a node-scoped, watch-fed map from container ID
// to the pod that owns the container (namespace, name, UID).
//
// Why it exists (Story 11.2d, #195): the pinned Falco does not fill
// k8s.ns.name / k8s.pod.name for pods created after Falco started. Their
// alerts reach the collector with a container.id and no pod, the correlator
// drops them as host events, and a real attack is never attributed to its
// workload. The collector fills the pod from this cache before it
// translates the alert (maintainer decision, 2026-09-25).
//
// Design:
//
//   - One informer per collector pod, LIST+WATCH on pods with the field
//     selector spec.nodeName=<this node>, so each collector only holds the
//     pods on its own node. Events for pods on other nodes are ignored too,
//     as defence in depth.
//   - The per-alert path never calls the API: Resolve reads the in-memory
//     map. The only API traffic is the informer's LIST and WATCH, each with
//     a client-side deadline (ListTimeout, WatchTimeout), so a hung
//     apiserver cannot hold a request forever (Epic 14 finding #86).
//   - Bounded memory: the informer stores a stripped pod (identity and
//     container IDs only), entries go when their pod is deleted or stops
//     reporting the container, and the map has a hard cap (MaxEntries);
//     a container over the cap is not cached and is counted.
//   - The race where Falco's alert arrives before the watch has delivered
//     the pod: Resolve waits up to MissWait for the map to change, then
//     gives up and records a short-lived negative entry so later alerts
//     from the same unknown container do not wait again. The negative set
//     is bounded (NegativeMax) and an entry is dropped the moment the
//     container becomes known.
package podidentity

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// KeyLength is the length of the container ID prefix the cache keys on.
// Falco reports container.id as the first 12 hex characters of the
// runtime's container ID; the kubelet reports the full 64. Keying both on
// the 12-character prefix makes them meet.
const KeyLength = 12

// Defaults for Config fields left zero.
const (
	DefaultMaxEntries   = 2048
	DefaultMissWait     = time.Second
	DefaultNegativeTTL  = 30 * time.Second
	DefaultNegativeMax  = 1024
	DefaultListTimeout  = 30 * time.Second
	DefaultWatchTimeout = 10 * time.Minute
)

// Identity is the pod a container belongs to.
type Identity struct {
	Namespace string
	Name      string
	UID       string
}

// Config holds the cache knobs. NodeName is required.
type Config struct {
	// NodeName scopes the watch to pods on this node (spec.nodeName).
	NodeName string

	// MaxEntries is the hard cap on cached container IDs. Zero means
	// DefaultMaxEntries. A node runs at most the kubelet's maxPods (110
	// by default) pods, a few containers each, so the default leaves
	// ample headroom; hitting it is counted in CapRejected.
	MaxEntries int

	// MissWait bounds how long Resolve waits for an unknown container to
	// appear (the alert-before-watch race). Zero disables the wait.
	// Negative means DefaultMissWait.
	MissWait time.Duration

	// NegativeTTL is how long a container that missed after the wait is
	// remembered as unknown, so its next alerts do not wait again. Zero
	// means DefaultNegativeTTL.
	NegativeTTL time.Duration

	// NegativeMax caps the remembered unknown containers. Zero means
	// DefaultNegativeMax.
	NegativeMax int

	// ListTimeout and WatchTimeout are client-side deadlines on the
	// informer's LIST and on each WATCH. Zero means the defaults.
	ListTimeout  time.Duration
	WatchTimeout time.Duration
}

// Cache maps container IDs on this node to their pods. Construct with New,
// start with Run, query with Resolve.
type Cache struct {
	cs  kubernetes.Interface
	cfg Config
	log *slog.Logger

	mu      sync.RWMutex
	byKey   map[string]entry
	byPod   map[types.UID][]string
	neg     map[string]time.Time
	changed chan struct{} // closed and replaced on every add

	synced atomic.Pointer[func() bool]

	size          atomic.Int64
	hits          atomic.Int64
	misses        atomic.Int64
	waitRecovered atomic.Int64
	capRejected   atomic.Int64
	atCap         atomic.Bool

	nowFn func() time.Time
}

type entry struct {
	id Identity
}

// New validates cfg and returns a Cache that is not yet running.
func New(cs kubernetes.Interface, cfg Config, log *slog.Logger) (*Cache, error) {
	if cs == nil {
		return nil, errors.New("podidentity: nil clientset")
	}
	if cfg.NodeName == "" {
		return nil, errors.New("podidentity: NodeName is empty")
	}
	if cfg.MaxEntries < 0 || cfg.NegativeMax < 0 {
		return nil, errors.New("podidentity: MaxEntries and NegativeMax must not be negative")
	}
	if log == nil {
		log = slog.Default()
	}
	if cfg.MaxEntries == 0 {
		cfg.MaxEntries = DefaultMaxEntries
	}
	if cfg.MissWait < 0 {
		cfg.MissWait = DefaultMissWait
	}
	if cfg.NegativeTTL <= 0 {
		cfg.NegativeTTL = DefaultNegativeTTL
	}
	if cfg.NegativeMax == 0 {
		cfg.NegativeMax = DefaultNegativeMax
	}
	if cfg.ListTimeout <= 0 {
		cfg.ListTimeout = DefaultListTimeout
	}
	if cfg.WatchTimeout <= 0 {
		cfg.WatchTimeout = DefaultWatchTimeout
	}
	return &Cache{
		cs:      cs,
		cfg:     cfg,
		log:     log,
		byKey:   make(map[string]entry),
		byPod:   make(map[types.UID][]string),
		neg:     make(map[string]time.Time),
		changed: make(chan struct{}),
		nowFn:   time.Now,
	}, nil
}

// Key normalises any container ID form to the cache key: the runtime
// prefix (containerd://, docker://, cri-o://) is dropped, the ID is
// lowercased and cut to KeyLength. It returns "" for anything that cannot
// be a container ID: empty, Falco's "host" and "<NA>", too short, or not
// hex.
func Key(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if len(s) < KeyLength {
		return ""
	}
	s = s[:KeyLength]
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return ""
		}
	}
	return s
}

// NewListWatch builds the node-scoped pod ListWatch with client-side
// deadlines on LIST and WATCH. It opts out of the streaming WatchList
// mode so the initial sync is a plain LIST that ListTimeout bounds.
func NewListWatch(cs kubernetes.Interface, nodeName string, listTimeout, watchTimeout time.Duration) *ListWatch {
	sel := fields.OneTermEqualSelector("spec.nodeName", nodeName).String()
	return &ListWatch{ListWatch: cache.ListWatch{
		ListWithContextFunc: func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
			opts.FieldSelector = sel
			lctx, cancel := context.WithTimeout(ctx, listTimeout)
			defer cancel()
			return cs.CoreV1().Pods(metav1.NamespaceAll).List(lctx, opts)
		},
		WatchFuncWithContext: func(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
			opts.FieldSelector = sel
			// The server ends the watch at TimeoutSeconds; the client
			// deadline a little later catches a connection that went
			// silent without closing.
			secs := int64(watchTimeout / time.Second)
			if secs < 1 {
				secs = 1
			}
			if opts.TimeoutSeconds == nil || *opts.TimeoutSeconds > secs {
				opts.TimeoutSeconds = &secs
			}
			wctx, cancel := context.WithTimeout(ctx, watchTimeout+watchTimeout/10)
			w, err := cs.CoreV1().Pods(metav1.NamespaceAll).Watch(wctx, opts)
			if err != nil {
				cancel()
				return nil, err
			}
			return &cancelOnStop{Interface: w, cancel: cancel}, nil
		},
	}}
}

// ListWatch is a cache.ListWatch that reports it does not support the
// streaming WatchList semantics, so the reflector does a bounded LIST.
type ListWatch struct {
	cache.ListWatch
}

// IsWatchListSemanticsUnSupported makes client-go fall back to LIST+WATCH.
func (*ListWatch) IsWatchListSemanticsUnSupported() bool { return true }

type cancelOnStop struct {
	watch.Interface
	cancel context.CancelFunc
}

func (c *cancelOnStop) Stop() {
	c.Interface.Stop()
	c.cancel()
}

// Run starts the informer and blocks until ctx is done.
func (c *Cache) Run(ctx context.Context) error {
	inf := cache.NewSharedIndexInformer(
		NewListWatch(c.cs, c.cfg.NodeName, c.cfg.ListTimeout, c.cfg.WatchTimeout),
		&corev1.Pod{}, 0, cache.Indexers{})
	if err := inf.SetTransform(stripPod); err != nil {
		return fmt.Errorf("podidentity: set transform: %w", err)
	}
	if _, err := inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { c.upsert(obj) },
		UpdateFunc: func(_, obj any) { c.upsert(obj) },
		DeleteFunc: func(obj any) { c.remove(obj) },
	}); err != nil {
		return fmt.Errorf("podidentity: add handler: %w", err)
	}
	hasSynced := inf.HasSynced
	c.synced.Store(&hasSynced)
	go func() {
		if cache.WaitForCacheSync(ctx.Done(), inf.HasSynced) {
			c.log.Info("podidentity: pod watch synced", "node", c.cfg.NodeName, "containers", c.Size())
		}
	}()
	c.log.Info("podidentity: starting node-scoped pod watch",
		"node", c.cfg.NodeName, "max_entries", c.cfg.MaxEntries, "miss_wait", c.cfg.MissWait)
	inf.RunWithContext(ctx)
	return nil
}

// HasSynced reports whether the informer finished its initial LIST.
func (c *Cache) HasSynced() bool {
	f := c.synced.Load()
	return f != nil && (*f)()
}

// Resolve returns the pod owning containerID (any form Key accepts). On a
// miss it waits up to MissWait, or until ctx ends, for the pod to arrive.
// It never calls the API.
func (c *Cache) Resolve(ctx context.Context, containerID string) (Identity, bool) {
	key := Key(containerID)
	if key == "" {
		return Identity{}, false
	}
	var timer *time.Timer
	waited := false
	for {
		c.mu.RLock()
		e, ok := c.byKey[key]
		changed := c.changed
		negAt, neg := c.neg[key]
		c.mu.RUnlock()
		if ok {
			c.hits.Add(1)
			if waited {
				c.waitRecovered.Add(1)
			}
			if timer != nil {
				timer.Stop()
			}
			return e.id, true
		}
		if !waited && (c.cfg.MissWait == 0 || (neg && c.nowFn().Sub(negAt) < c.cfg.NegativeTTL)) {
			// No wait configured, or this container already missed
			// recently: answer at once.
			c.misses.Add(1)
			return Identity{}, false
		}
		if timer == nil {
			timer = time.NewTimer(c.cfg.MissWait)
		}
		waited = true
		select {
		case <-changed:
			continue
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
		}
		// Last look: the pod may have landed as the timer fired.
		c.mu.RLock()
		e, ok = c.byKey[key]
		c.mu.RUnlock()
		if ok {
			c.hits.Add(1)
			c.waitRecovered.Add(1)
			return e.id, true
		}
		c.remember(key)
		c.misses.Add(1)
		return Identity{}, false
	}
}

// remember records key as recently unknown, within NegativeMax.
func (c *Cache) remember(key string) {
	now := c.nowFn()
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, known := c.byKey[key]; known {
		return
	}
	if _, ok := c.neg[key]; !ok && len(c.neg) >= c.cfg.NegativeMax {
		for k, at := range c.neg {
			if now.Sub(at) >= c.cfg.NegativeTTL {
				delete(c.neg, k)
			}
		}
		if len(c.neg) >= c.cfg.NegativeMax {
			// Still full of live entries: forget the oldest one.
			var oldK string
			var oldAt time.Time
			for k, at := range c.neg {
				if oldK == "" || at.Before(oldAt) {
					oldK, oldAt = k, at
				}
			}
			delete(c.neg, oldK)
		}
	}
	c.neg[key] = now
}

// upsert applies the current container set of a pod.
func (c *Cache) upsert(obj any) {
	p, ok := obj.(*corev1.Pod)
	if !ok || p.UID == "" {
		return
	}
	if p.Spec.NodeName != c.cfg.NodeName {
		// The field selector already filters these; this guards a
		// clientset that ignores it and a pod rescheduled away.
		c.removeUID(p.UID)
		return
	}
	id := Identity{Namespace: p.Namespace, Name: p.Name, UID: string(p.UID)}
	want := containerKeys(p)

	c.mu.Lock()
	old := c.byPod[p.UID]
	keep := make([]string, 0, len(want))
	wantSet := make(map[string]struct{}, len(want))
	for _, k := range want {
		wantSet[k] = struct{}{}
	}
	for _, k := range old {
		if _, still := wantSet[k]; !still {
			if e, ok := c.byKey[k]; ok && e.id.UID == id.UID {
				delete(c.byKey, k)
			}
		}
	}
	added, rejected := 0, 0
	for _, k := range want {
		if e, ok := c.byKey[k]; ok {
			if e.id != id {
				c.byKey[k] = entry{id: id}
			}
			keep = append(keep, k)
			continue
		}
		if len(c.byKey) >= c.cfg.MaxEntries {
			rejected++
			continue
		}
		c.byKey[k] = entry{id: id}
		delete(c.neg, k)
		keep = append(keep, k)
		added++
	}
	if len(keep) == 0 {
		delete(c.byPod, p.UID)
	} else {
		c.byPod[p.UID] = keep
	}
	c.size.Store(int64(len(c.byKey)))
	if added > 0 {
		close(c.changed)
		c.changed = make(chan struct{})
	}
	c.mu.Unlock()

	if rejected > 0 {
		c.capRejected.Add(int64(rejected))
		if c.atCap.CompareAndSwap(false, true) {
			c.log.Warn("podidentity: container cache is full; new containers on this node will not be attributed (see olaitan_sensor_falco_pod_identity_cap_rejected_total)",
				"max_entries", c.cfg.MaxEntries, "pod", p.Namespace+"/"+p.Name)
		}
	} else if added > 0 {
		c.atCap.Store(false)
	}
}

// remove drops every entry of a deleted pod.
func (c *Cache) remove(obj any) {
	if t, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = t.Obj
	}
	p, ok := obj.(*corev1.Pod)
	if !ok {
		return
	}
	c.removeUID(p.UID)
}

func (c *Cache) removeUID(uid types.UID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, k := range c.byPod[uid] {
		if e, ok := c.byKey[k]; ok && e.id.UID == string(uid) {
			delete(c.byKey, k)
		}
	}
	delete(c.byPod, uid)
	c.size.Store(int64(len(c.byKey)))
}

// containerKeys lists the cache keys of every container the pod reports:
// regular, init and ephemeral, plus the previous instance of a restarted
// container so a late alert from it still resolves.
func containerKeys(p *corev1.Pod) []string {
	var out []string
	seen := map[string]struct{}{}
	add := func(raw string) {
		if k := Key(raw); k != "" {
			if _, dup := seen[k]; !dup {
				seen[k] = struct{}{}
				out = append(out, k)
			}
		}
	}
	for _, list := range [][]corev1.ContainerStatus{
		p.Status.InitContainerStatuses,
		p.Status.ContainerStatuses,
		p.Status.EphemeralContainerStatuses,
	} {
		for _, s := range list {
			add(s.ContainerID)
			if t := s.LastTerminationState.Terminated; t != nil {
				add(t.ContainerID)
			}
		}
	}
	return out
}

// stripPod keeps only what the cache reads, so the informer's store holds
// a few hundred bytes per pod instead of the full object.
func stripPod(obj any) (any, error) {
	p, ok := obj.(*corev1.Pod)
	if !ok {
		return obj, nil
	}
	strip := func(in []corev1.ContainerStatus) []corev1.ContainerStatus {
		if len(in) == 0 {
			return nil
		}
		out := make([]corev1.ContainerStatus, 0, len(in))
		for _, s := range in {
			cs := corev1.ContainerStatus{ContainerID: s.ContainerID}
			if t := s.LastTerminationState.Terminated; t != nil && t.ContainerID != "" {
				cs.LastTerminationState.Terminated = &corev1.ContainerStateTerminated{ContainerID: t.ContainerID}
			}
			out = append(out, cs)
		}
		return out
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       p.Namespace,
			Name:            p.Name,
			UID:             p.UID,
			ResourceVersion: p.ResourceVersion,
		},
		Spec: corev1.PodSpec{NodeName: p.Spec.NodeName},
		Status: corev1.PodStatus{
			InitContainerStatuses:      strip(p.Status.InitContainerStatuses),
			ContainerStatuses:          strip(p.Status.ContainerStatuses),
			EphemeralContainerStatuses: strip(p.Status.EphemeralContainerStatuses),
		},
	}, nil
}

// Size is the number of cached container IDs.
func (c *Cache) Size() int64 { return c.size.Load() }

// Hits counts Resolve calls that found the pod.
func (c *Cache) Hits() int64 { return c.hits.Load() }

// Misses counts Resolve calls that did not.
func (c *Cache) Misses() int64 { return c.misses.Load() }

// WaitRecovered counts hits that needed the bounded wait (the alert came
// before the watch delivered the pod). A subset of Hits.
func (c *Cache) WaitRecovered() int64 { return c.waitRecovered.Load() }

// CapRejected counts containers not cached because the map was full.
func (c *Cache) CapRejected() int64 { return c.capRejected.Load() }

// NegativeSize is the number of containers remembered as unknown.
func (c *Cache) NegativeSize() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.neg)
}
