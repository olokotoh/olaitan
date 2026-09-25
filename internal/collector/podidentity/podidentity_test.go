package podidentity_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"

	"github.com/olokotoh/olaitan/internal/collector/podidentity"
)

const node = "node-a"

// 64-hex container IDs as the kubelet reports them in pod status.
const (
	idMain      = "ba197754b7bc5f0e9d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e"
	idInit      = "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9"
	idEphemeral = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
	idOther     = "1234567890ab1234567890ab1234567890ab1234567890ab1234567890ab1234"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type podOpt func(*corev1.Pod)

func onNode(n string) podOpt { return func(p *corev1.Pod) { p.Spec.NodeName = n } }

func containers(ids ...string) podOpt {
	return func(p *corev1.Pod) {
		for _, id := range ids {
			p.Status.ContainerStatuses = append(p.Status.ContainerStatuses, corev1.ContainerStatus{Name: "c", ContainerID: id})
		}
	}
}

func newPod(ns, name, uid string, opts ...podOpt) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID(uid)},
		Spec: corev1.PodSpec{
			NodeName:   node,
			Containers: []corev1.Container{{Name: "c", Image: "busybox"}},
		},
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

// startCache runs a Cache against cs and waits until its informer synced.
func startCache(t *testing.T, cs kubernetes.Interface, mut func(*podidentity.Config)) *podidentity.Cache {
	t.Helper()
	cfg := podidentity.Config{NodeName: node, MissWait: 0}
	if mut != nil {
		mut(&cfg)
	}
	c, err := podidentity.New(cs, cfg, quietLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = c.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	deadline := time.Now().Add(5 * time.Second)
	for !c.HasSynced() {
		if time.Now().After(deadline) {
			t.Fatal("informer did not sync within 5s")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return c
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestKey_NormalisesRuntimePrefixesAndShortIDs(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"containerd://" + idMain, idMain[:12]},
		{"docker://" + idMain, idMain[:12]},
		{"cri-o://" + idMain, idMain[:12]},
		{idMain, idMain[:12]},
		{idMain[:12], idMain[:12]}, // Falco's short container.id
		{"  CONTAINERD://" + strings.ToUpper(idMain) + " ", idMain[:12]},
		{"host", ""},
		{"<NA>", ""},
		{"", ""},
		{"containerd://", ""},
		{"abc", ""},                         // too short to be a container ID
		{"zzzzzzzzzzzz", ""},                // not hex
		{"containerd://" + idMain[:11], ""}, // truncated
	}
	for _, tc := range cases {
		if got := podidentity.Key(tc.in); got != tc.want {
			t.Errorf("Key(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNew_Validates(t *testing.T) {
	if _, err := podidentity.New(nil, podidentity.Config{NodeName: node}, quietLog()); err == nil {
		t.Error("nil clientset accepted")
	}
	if _, err := podidentity.New(fake.NewClientset(), podidentity.Config{}, quietLog()); err == nil {
		t.Error("empty NodeName accepted")
	}
	if _, err := podidentity.New(fake.NewClientset(), podidentity.Config{NodeName: node, MaxEntries: -1}, quietLog()); err == nil {
		t.Error("negative MaxEntries accepted")
	}
}

func TestResolve_AllContainerKindsAndIDForms(t *testing.T) {
	p := newPod("tenant-acme", "web-1", "uid-1", containers("containerd://"+idMain))
	p.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: "init", ContainerID: "docker://" + idInit}}
	p.Status.EphemeralContainerStatuses = []corev1.ContainerStatus{{Name: "dbg", ContainerID: "cri-o://" + idEphemeral}}
	c := startCache(t, fake.NewClientset(p), nil)

	want := podidentity.Identity{Namespace: "tenant-acme", Name: "web-1", UID: "uid-1"}
	for _, q := range []string{
		idMain[:12], idMain, "containerd://" + idMain, // main container, all forms
		idInit[:12], "docker://" + idInit, // init container
		idEphemeral[:12], idEphemeral, // ephemeral (kubectl debug) container
	} {
		got, ok := c.Resolve(context.Background(), q)
		if !ok || got != want {
			t.Errorf("Resolve(%q) = %+v, %v; want %+v, true", q, got, ok, want)
		}
	}
	if c.Hits() != 7 || c.Misses() != 0 {
		t.Errorf("hits=%d misses=%d, want 7/0", c.Hits(), c.Misses())
	}
	if c.Size() != 3 {
		t.Errorf("size = %d, want 3 (one entry per container)", c.Size())
	}
}

func TestResolve_ContainerWithoutIDYetIsSkipped(t *testing.T) {
	// A container that has not started has an empty containerID.
	p := newPod("tenant-acme", "web-1", "uid-1", containers("", "containerd://"+idMain))
	c := startCache(t, fake.NewClientset(p), nil)
	if c.Size() != 1 {
		t.Errorf("size = %d, want 1", c.Size())
	}
}

func TestCache_IsNodeScoped(t *testing.T) {
	mine := newPod("tenant-acme", "web-1", "uid-1", containers("containerd://"+idMain))
	// The fake clientset ignores field selectors, so it hands the cache a
	// pod from another node too. The cache must still ignore it.
	theirs := newPod("tenant-acme", "web-2", "uid-2", onNode("node-b"), containers("containerd://"+idOther))
	cs := fake.NewClientset(mine, theirs)

	var mu sync.Mutex
	var listSel, watchSel []string
	cs.PrependReactor("list", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		mu.Lock()
		defer mu.Unlock()
		listSel = append(listSel, a.(k8stesting.ListAction).GetListRestrictions().Fields.String())
		if ns := a.GetNamespace(); ns != "" {
			t.Errorf("list scoped to namespace %q, want all namespaces on this node", ns)
		}
		return false, nil, nil
	})
	cs.PrependWatchReactor("pods", func(a k8stesting.Action) (bool, watch.Interface, error) {
		mu.Lock()
		defer mu.Unlock()
		watchSel = append(watchSel, a.(k8stesting.WatchAction).GetWatchRestrictions().Fields.String())
		return false, nil, nil
	})

	c := startCache(t, cs, nil)
	eventually(t, "the watch to start", func() bool { mu.Lock(); defer mu.Unlock(); return len(watchSel) > 0 })

	mu.Lock()
	for _, s := range append(append([]string{}, listSel...), watchSel...) {
		if s != "spec.nodeName="+node {
			t.Errorf("request field selector = %q, want spec.nodeName=%s", s, node)
		}
	}
	mu.Unlock()
	if _, ok := c.Resolve(context.Background(), idOther[:12]); ok {
		t.Error("resolved a container of a pod on another node")
	}
	if _, ok := c.Resolve(context.Background(), idMain[:12]); !ok {
		t.Error("did not resolve a container on this node")
	}
}

func TestResolve_RaceAlertBeforePodIsSeen(t *testing.T) {
	cs := fake.NewClientset()
	c := startCache(t, cs, func(cfg *podidentity.Config) { cfg.MissWait = 3 * time.Second })

	type result struct {
		id podidentity.Identity
		ok bool
	}
	res := make(chan result, 1)
	go func() {
		id, ok := c.Resolve(context.Background(), idMain[:12])
		res <- result{id, ok}
	}()
	time.Sleep(100 * time.Millisecond) // the alert is already waiting
	p := newPod("tenant-acme", "web-1", "uid-1", containers("containerd://"+idMain))
	if _, err := cs.CoreV1().Pods("tenant-acme").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-res:
		if !r.ok || r.id.Name != "web-1" {
			t.Fatalf("Resolve = %+v, %v; want the pod that appeared during the wait", r.id, r.ok)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Resolve did not return when the pod appeared")
	}
	if c.WaitRecovered() != 1 || c.Hits() != 1 || c.Misses() != 0 {
		t.Errorf("wait_recovered=%d hits=%d misses=%d, want 1/1/0", c.WaitRecovered(), c.Hits(), c.Misses())
	}
}

func TestResolve_BoundedWaitThenNegativeCache(t *testing.T) {
	cs := fake.NewClientset()
	c := startCache(t, cs, func(cfg *podidentity.Config) {
		cfg.MissWait = 200 * time.Millisecond
		cfg.NegativeTTL = time.Minute
	})

	start := time.Now()
	if _, ok := c.Resolve(context.Background(), idMain[:12]); ok {
		t.Fatal("resolved an unknown container")
	}
	if el := time.Since(start); el < 200*time.Millisecond || el > 2*time.Second {
		t.Errorf("first miss took %s, want about the 200ms bound", el)
	}
	// A second alert from the same unknown container does not wait again.
	start = time.Now()
	if _, ok := c.Resolve(context.Background(), idMain[:12]); ok {
		t.Fatal("resolved an unknown container")
	}
	if el := time.Since(start); el > 100*time.Millisecond {
		t.Errorf("repeat miss took %s; a recent miss must not wait again", el)
	}
	if c.Misses() != 2 {
		t.Errorf("misses = %d, want 2", c.Misses())
	}
	// When the pod does show up, the negative entry must not hide it.
	p := newPod("tenant-acme", "web-1", "uid-1", containers("containerd://"+idMain))
	if _, err := cs.CoreV1().Pods("tenant-acme").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the pod to be cached", func() bool { return c.Size() == 1 })
	if _, ok := c.Resolve(context.Background(), idMain[:12]); !ok {
		t.Error("a negative entry hid a container that is now known")
	}
}

func TestResolve_ZeroWaitMissesImmediately(t *testing.T) {
	c := startCache(t, fake.NewClientset(), func(cfg *podidentity.Config) { cfg.MissWait = 0 })
	start := time.Now()
	if _, ok := c.Resolve(context.Background(), idMain[:12]); ok {
		t.Fatal("resolved an unknown container")
	}
	if el := time.Since(start); el > 100*time.Millisecond {
		t.Errorf("zero MissWait still waited %s", el)
	}
}

func TestResolve_ContextCancelEndsTheWait(t *testing.T) {
	c := startCache(t, fake.NewClientset(), func(cfg *podidentity.Config) { cfg.MissWait = 10 * time.Second })
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, ok := c.Resolve(ctx, idMain[:12]); ok {
		t.Fatal("resolved an unknown container")
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("Resolve ignored its context and waited %s", el)
	}
}

func TestResolve_UnresolvableIDNeverWaits(t *testing.T) {
	c := startCache(t, fake.NewClientset(), func(cfg *podidentity.Config) { cfg.MissWait = 10 * time.Second })
	start := time.Now()
	for _, q := range []string{"", "host", "<NA>"} {
		if _, ok := c.Resolve(context.Background(), q); ok {
			t.Errorf("resolved %q", q)
		}
	}
	if el := time.Since(start); el > 100*time.Millisecond {
		t.Errorf("an ID that can never be a container waited %s", el)
	}
}

func TestCache_EvictsOnPodDelete(t *testing.T) {
	p := newPod("tenant-acme", "web-1", "uid-1", containers("containerd://"+idMain, "containerd://"+idOther))
	cs := fake.NewClientset(p)
	c := startCache(t, cs, nil)
	if c.Size() != 2 {
		t.Fatalf("size = %d, want 2", c.Size())
	}
	if err := cs.CoreV1().Pods("tenant-acme").Delete(context.Background(), "web-1", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the deleted pod's entries to go", func() bool { return c.Size() == 0 })
	if _, ok := c.Resolve(context.Background(), idMain[:12]); ok {
		t.Error("a deleted pod still resolves")
	}
}

func TestCache_UpdateTracksRestartsAndDropsGoneContainers(t *testing.T) {
	p := newPod("tenant-acme", "web-1", "uid-1", containers("containerd://"+idMain))
	cs := fake.NewClientset(p)
	c := startCache(t, cs, nil)

	// Restart: the kubelet reports the new container ID and keeps the old
	// one under lastState.terminated. A late alert from the old container
	// must still resolve.
	p2 := p.DeepCopy()
	p2.Status.ContainerStatuses = []corev1.ContainerStatus{{
		Name:        "c",
		ContainerID: "containerd://" + idOther,
		LastTerminationState: corev1.ContainerState{
			Terminated: &corev1.ContainerStateTerminated{ContainerID: "containerd://" + idMain},
		},
	}}
	if _, err := cs.CoreV1().Pods("tenant-acme").UpdateStatus(context.Background(), p2, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the restarted container to be cached", func() bool { return c.Size() == 2 })
	for _, id := range []string{idMain, idOther} {
		if _, ok := c.Resolve(context.Background(), id[:12]); !ok {
			t.Errorf("container %s does not resolve after the restart", id[:12])
		}
	}

	// A later status that no longer mentions the old container drops it.
	p3 := p2.DeepCopy()
	p3.Status.ContainerStatuses[0].LastTerminationState = corev1.ContainerState{}
	if _, err := cs.CoreV1().Pods("tenant-acme").UpdateStatus(context.Background(), p3, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the gone container to be dropped", func() bool { return c.Size() == 1 })
	if _, ok := c.Resolve(context.Background(), idMain[:12]); ok {
		t.Error("a container the pod no longer reports still resolves")
	}
}

func TestCache_HardCap(t *testing.T) {
	p := newPod("tenant-acme", "web-1", "uid-1", containers("containerd://"+idMain, "containerd://"+idOther, "containerd://"+idInit))
	cs := fake.NewClientset(p)
	c := startCache(t, cs, func(cfg *podidentity.Config) { cfg.MaxEntries = 2 })

	if c.Size() != 2 {
		t.Errorf("size = %d, want the cap 2", c.Size())
	}
	if c.CapRejected() != 1 {
		t.Errorf("cap_rejected = %d, want 1", c.CapRejected())
	}
	// Deleting the pod frees its entries; a new pod fits again.
	if err := cs.CoreV1().Pods("tenant-acme").Delete(context.Background(), "web-1", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "eviction", func() bool { return c.Size() == 0 })
	q := newPod("tenant-acme", "web-2", "uid-2", containers("containerd://"+idEphemeral))
	if _, err := cs.CoreV1().Pods("tenant-acme").Create(context.Background(), q, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the new pod to be cached", func() bool { return c.Size() == 1 })
	if _, ok := c.Resolve(context.Background(), idEphemeral[:12]); !ok {
		t.Error("a pod added after eviction does not resolve")
	}
}

func TestCache_NegativeCacheIsBounded(t *testing.T) {
	c := startCache(t, fake.NewClientset(), func(cfg *podidentity.Config) {
		cfg.MissWait = time.Millisecond
		cfg.NegativeMax = 4
	})
	for i := 0; i < 50; i++ {
		id := strings.Repeat("0", 10) + string("0123456789abcdef"[i%16]) + string("0123456789abcdef"[i/16])
		c.Resolve(context.Background(), id)
	}
	if n := c.NegativeSize(); n > 4 {
		t.Errorf("negative cache holds %d entries, want at most 4", n)
	}
}

// Epic 14 finding #86: kube calls without a timeout stalled a loop. The
// informer's LIST and WATCH must give up on a hung apiserver on their own.
func TestListWatch_TimesOutAgainstAHungAPIServer(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	cs, err := kubernetes.NewForConfig(&rest.Config{Host: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	lw := podidentity.NewListWatch(cs, node, 150*time.Millisecond, 150*time.Millisecond)

	start := time.Now()
	if _, err := lw.ListWithContext(context.Background(), metav1.ListOptions{}); err == nil {
		t.Error("LIST against a hung apiserver returned no error")
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Errorf("LIST took %s, want it bounded by the 150ms timeout", el)
	}

	start = time.Now()
	w, err := lw.WatchWithContext(context.Background(), metav1.ListOptions{})
	if err == nil {
		// Headers may never come; if a watch did open, it must still end.
		select {
		case <-w.ResultChan():
		case <-time.After(3 * time.Second):
			t.Error("WATCH on a hung apiserver never ended")
		}
		w.Stop()
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Errorf("WATCH took %s, want it bounded", el)
	}
}
