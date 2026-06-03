package override

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/olokotoh/olaitan/internal/metrics"
	redisclient "github.com/olokotoh/olaitan/internal/redis"
	"github.com/olokotoh/olaitan/internal/response/fsm"
	"github.com/olokotoh/olaitan/internal/schema"
)

// counterValue reads a single labelled counter sample from the registry's
// gatherer (the override rejected_total CounterVec is unexported).
func counterValue(t *testing.T, reg *metrics.Registry, name, reason string) float64 {
	t.Helper()
	mfs, err := reg.Gatherer().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "reason" && lp.GetValue() == reason {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	t.Fatalf("counter %s{reason=%q} not found", name, reason)
	return 0
}

// --- fakes / helpers ---

// fakePublisher records published events for assertions (BI-10 seam).
type fakePublisher struct {
	mu     sync.Mutex
	events []OverrideApplied
}

func (p *fakePublisher) PublishOverride(_ context.Context, evt OverrideApplied) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, evt)
	return nil
}

func (p *fakePublisher) all() []OverrideApplied {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]OverrideApplied, len(p.events))
	copy(out, p.events)
	return out
}

// recordingSink captures FSM transitions so a test can prove the pin routes
// through the sink (BI-7) without depending on the netpol manager.
type recordingSink struct {
	mu sync.Mutex
	t  []schema.StateTransition
}

func (s *recordingSink) Publish(st schema.StateTransition) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.t = append(s.t, st)
}

func (s *recordingSink) transitions() []schema.StateTransition {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]schema.StateTransition, len(s.t))
	copy(out, s.t)
	return out
}

func startMiniredis(t *testing.T) *miniredis.Miniredis {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	return mr
}

func newRedisStore(t *testing.T, mr *miniredis.Miniredis) (*Store, *redisclient.Client) {
	t.Helper()
	cfg := redisclient.DefaultConfig()
	cfg.Addr = mr.Addr()
	cli, err := redisclient.NewClient(cfg)
	if err != nil {
		t.Fatalf("redis client: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close(context.Background()) })
	store, err := NewStore(cli)
	if err != nil {
		t.Fatalf("override store: %v", err)
	}
	return store, cli
}

func newMachine(t *testing.T) *fsm.Machine {
	t.Helper()
	// A nil manager degrades the FSM to the Story 2.2 default thresholds
	// (20/40/70). The override controller tests only exercise Pin/ReleasePin/
	// IsPinned/CurrentState, which are threshold-independent.
	m, err := fsm.New(nil, nil, fsm.NopSink{}, nil)
	if err != nil {
		t.Fatalf("fsm.New: %v", err)
	}
	return m
}

// deploymentPod builds a pod owned by a ReplicaSet owned by a Deployment, so
// resolveWorkloadID yields ns/Deployment/<name>. annotations are applied to
// the pod.
func deploymentPod(ns, name string, anns map[string]string) (*corev1.Pod, []runtime.Object) {
	rsName := name + "-rs"
	depName := name
	trueVal := true
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      rsName,
			Namespace: ns,
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "apps/v1", Kind: "Deployment", Name: depName, Controller: &trueVal},
			},
		},
	}
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: depName, Namespace: ns},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name + "-abc",
			Namespace:   ns,
			Annotations: anns,
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rsName, Controller: &trueVal},
			},
		},
	}
	return pod, []runtime.Object{rs, dep, pod}
}

func newController(t *testing.T, objs []runtime.Object, store *Store, machine *fsm.Machine, pub OverridePublisher, reg *metrics.Registry) *Controller {
	t.Helper()
	cs := fake.NewSimpleClientset(objs...)
	c, err := New(Config{
		PollInterval: time.Second,
		DefaultTTL:   time.Hour,
	}, cs, store, machine, pub, reg, nil)
	if err != nil {
		t.Fatalf("New controller: %v", err)
	}
	return c
}

const depWorkloadID = "default/Deployment/web"

// --- tests ---

func TestReconcile_AnnotationPinsAndWritesRedis(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	store, _ := newRedisStore(t, mr)
	machine := newMachine(t)
	pub := &fakePublisher{}

	_, objs := deploymentPod("default", "web", map[string]string{
		AnnotationState: "RESTRICTED",
		AnnotationTTL:   "30m",
	})
	c := newController(t, objs, store, machine, pub, nil)

	c.reconcile(ctx)

	if s, pinned := machine.IsPinned(depWorkloadID); !pinned || s != schema.StateRestricted {
		t.Fatalf("IsPinned = (%s, %v), want (RESTRICTED, true)", s, pinned)
	}
	rec, ok, err := store.Get(ctx, depWorkloadID)
	if err != nil || !ok {
		t.Fatalf("store.Get = (%v, %v, %v), want present", rec, ok, err)
	}
	if rec.RequestedState != schema.StateRestricted {
		t.Errorf("redis record state = %s, want RESTRICTED", rec.RequestedState)
	}
	// AC3: native TTL ~30m on the override key.
	key := "override:" + depWorkloadID
	ttl := mr.TTL(key)
	if ttl != 30*time.Minute {
		t.Errorf("override key TTL = %s, want 30m", ttl)
	}
	// An applied event published with rejected=false.
	evts := pub.all()
	if len(evts) != 1 || evts[0].Rejected || evts[0].RequestedState != "RESTRICTED" {
		t.Fatalf("published events = %+v, want one applied RESTRICTED event", evts)
	}
}

func TestReconcile_DefaultTTLWhenAbsent(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	store, _ := newRedisStore(t, mr)
	machine := newMachine(t)
	pub := &fakePublisher{}

	_, objs := deploymentPod("default", "web", map[string]string{
		AnnotationState: "QUARANTINED",
	})
	c := newController(t, objs, store, machine, pub, nil)
	c.reconcile(ctx)

	key := "override:" + depWorkloadID
	if ttl := mr.TTL(key); ttl != time.Hour {
		t.Errorf("default TTL = %s, want 1h", ttl)
	}
}

func TestReconcile_MalformedTTLDefaultsNotRejected(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	store, _ := newRedisStore(t, mr)
	machine := newMachine(t)
	pub := &fakePublisher{}

	_, objs := deploymentPod("default", "web", map[string]string{
		AnnotationState: "RESTRICTED",
		AnnotationTTL:   "not-a-duration",
	})
	c := newController(t, objs, store, machine, pub, nil)
	c.reconcile(ctx)

	if _, pinned := machine.IsPinned(depWorkloadID); !pinned {
		t.Fatal("malformed TTL must NOT reject the override; pin expected")
	}
	if ttl := mr.TTL("override:" + depWorkloadID); ttl != time.Hour {
		t.Errorf("malformed TTL defaulted to %s, want 1h", ttl)
	}
}

func TestReconcile_TTLExpiryReleases(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	store, _ := newRedisStore(t, mr)
	machine := newMachine(t)
	pub := &fakePublisher{}

	_, objs := deploymentPod("default", "web", map[string]string{
		AnnotationState: "RESTRICTED",
		AnnotationTTL:   "30m",
	})
	c := newController(t, objs, store, machine, pub, nil)
	c.reconcile(ctx)
	if _, pinned := machine.IsPinned(depWorkloadID); !pinned {
		t.Fatal("expected pin after first reconcile")
	}

	// Simulate the operator removing the annotation AND the native TTL having
	// expired: drop the Redis key (FastForward past the TTL) and the pod
	// annotation. The release path: key gone -> ReleasePin.
	mr.FastForward(31 * time.Minute)
	// Replace the clientset's pod with an un-annotated one so the desired set
	// is empty (the annotation is gone too).
	_, cleanObjs := deploymentPod("default", "web", nil)
	c2 := newController(t, cleanObjs, store, machine, pub, nil)
	c2.reconcile(ctx)

	if _, pinned := machine.IsPinned(depWorkloadID); pinned {
		t.Fatal("native-TTL expiry must release the pin")
	}
}

func TestReconcile_ManualRemovalReleasesAndClearsRedis(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	store, _ := newRedisStore(t, mr)
	machine := newMachine(t)
	pub := &fakePublisher{}

	_, objs := deploymentPod("default", "web", map[string]string{
		AnnotationState: "RESTRICTED",
		AnnotationTTL:   "30m",
	})
	c := newController(t, objs, store, machine, pub, nil)
	c.reconcile(ctx)

	// Annotation removed BEFORE TTL expiry (Redis key still present).
	_, cleanObjs := deploymentPod("default", "web", nil)
	c2 := newController(t, cleanObjs, store, machine, pub, nil)
	c2.reconcile(ctx)

	if _, pinned := machine.IsPinned(depWorkloadID); pinned {
		t.Fatal("manual removal must release the pin")
	}
	if _, ok, _ := store.Get(ctx, depWorkloadID); ok {
		t.Fatal("manual removal must clear the Redis key immediately (AC4)")
	}
}

func TestReconcile_RejectsPreservedKilled(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	store, _ := newRedisStore(t, mr)
	machine := newMachine(t)
	pub := &fakePublisher{}
	reg := metrics.NewRegistry()

	_, objs := deploymentPod("default", "web", map[string]string{
		AnnotationState: "PRESERVED_KILLED",
	})
	c := newController(t, objs, store, machine, pub, reg)
	c.reconcile(ctx)

	if _, pinned := machine.IsPinned(depWorkloadID); pinned {
		t.Fatal("PRESERVED_KILLED must NOT pin")
	}
	if _, ok, _ := store.Get(ctx, depWorkloadID); ok {
		t.Fatal("rejected override must NOT write Redis")
	}
	evts := pub.all()
	if len(evts) != 1 || !evts[0].Rejected || evts[0].Reason != ReasonStateUnavailable {
		t.Fatalf("events = %+v, want one rejected event reason=state_unavailable", evts)
	}
	if got := counterValue(t, reg, "olaitan_response_override_rejected_total", "state_unavailable"); got != 1 {
		t.Errorf("rejected counter{state_unavailable} = %v, want 1", got)
	}
}

func TestReconcile_RejectsUnknownState(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	store, _ := newRedisStore(t, mr)
	machine := newMachine(t)
	pub := &fakePublisher{}
	reg := metrics.NewRegistry()

	_, objs := deploymentPod("default", "web", map[string]string{
		AnnotationState: "BOGUS",
	})
	c := newController(t, objs, store, machine, pub, reg)
	c.reconcile(ctx)

	evts := pub.all()
	if len(evts) != 1 || !evts[0].Rejected || evts[0].Reason != ReasonInvalidState {
		t.Fatalf("events = %+v, want one rejected event reason=invalid_state", evts)
	}
	if got := counterValue(t, reg, "olaitan_response_override_rejected_total", "invalid_state"); got != 1 {
		t.Errorf("rejected counter{invalid_state} = %v, want 1", got)
	}
}

func TestReconcile_IdempotentReapply(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	store, _ := newRedisStore(t, mr)
	machine := newMachine(t)
	pub := &fakePublisher{}

	_, objs := deploymentPod("default", "web", map[string]string{
		AnnotationState: "RESTRICTED",
		AnnotationTTL:   "30m",
	})
	c := newController(t, objs, store, machine, pub, nil)
	c.reconcile(ctx)
	c.reconcile(ctx)
	c.reconcile(ctx)

	// Only ONE applied event despite three ticks (idempotent re-apply; BI-8).
	if n := len(pub.all()); n != 1 {
		t.Fatalf("applied events after 3 idempotent ticks = %d, want 1", n)
	}
	// The Redis key is still present (TTL refreshed each tick).
	if ttl := mr.TTL("override:" + depWorkloadID); ttl != 30*time.Minute {
		t.Errorf("TTL after re-apply = %s, want refreshed 30m", ttl)
	}
}

func TestReconcile_ExcludedNamespaceSkipped(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	store, _ := newRedisStore(t, mr)
	machine := newMachine(t)
	pub := &fakePublisher{}

	_, objs := deploymentPod("kube-system", "web", map[string]string{
		AnnotationState: "RESTRICTED",
	})
	cs := fake.NewSimpleClientset(objs...)
	c, err := New(Config{
		PollInterval:       time.Second,
		DefaultTTL:         time.Hour,
		ExcludedNamespaces: []string{"kube-system"},
	}, cs, store, machine, pub, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.reconcile(ctx)

	if _, pinned := machine.IsPinned("kube-system/Deployment/web"); pinned {
		t.Fatal("excluded namespace must be skipped")
	}
	if n := len(pub.all()); n != 0 {
		t.Fatalf("excluded namespace produced %d events, want 0", n)
	}
}

func TestReconcile_PodOverOwnerPrecedence(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	store, _ := newRedisStore(t, mr)
	machine := newMachine(t)
	pub := &fakePublisher{}

	// Owner (Deployment) annotated QUARANTINED, pod annotated RESTRICTED.
	// Pod wins (BI-9).
	pod, objs := deploymentPod("default", "web", map[string]string{
		AnnotationState: "RESTRICTED",
	})
	_ = pod
	// Annotate the Deployment QUARANTINED.
	for _, o := range objs {
		if dep, ok := o.(*appsv1.Deployment); ok {
			dep.Annotations = map[string]string{AnnotationState: "QUARANTINED"}
		}
	}
	c := newController(t, objs, store, machine, pub, nil)
	c.reconcile(ctx)

	if s, pinned := machine.IsPinned(depWorkloadID); !pinned || s != schema.StateRestricted {
		t.Fatalf("IsPinned = (%s, %v), want (RESTRICTED, true) - pod annotation must win", s, pinned)
	}
}

func TestReconcile_OwnerAnnotationApplies(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	store, _ := newRedisStore(t, mr)
	machine := newMachine(t)
	pub := &fakePublisher{}

	// Only the Deployment is annotated; the pod is not.
	_, objs := deploymentPod("default", "web", nil)
	for _, o := range objs {
		if dep, ok := o.(*appsv1.Deployment); ok {
			dep.Annotations = map[string]string{AnnotationState: "QUARANTINED", AnnotationTTL: "45m"}
		}
	}
	c := newController(t, objs, store, machine, pub, nil)
	c.reconcile(ctx)

	if s, pinned := machine.IsPinned(depWorkloadID); !pinned || s != schema.StateQuarantined {
		t.Fatalf("IsPinned = (%s, %v), want (QUARANTINED, true) from owner annotation", s, pinned)
	}
	if ttl := mr.TTL("override:" + depWorkloadID); ttl != 45*time.Minute {
		t.Errorf("owner-annotation TTL = %s, want 45m", ttl)
	}
}

func TestReconcile_MostIsolatingTieBreak(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	store, _ := newRedisStore(t, mr)
	machine := newMachine(t)
	pub := &fakePublisher{}

	// Two pods of the SAME Deployment with conflicting annotations.
	trueVal := true
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: "web-rs", Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "web", Controller: &trueVal}},
		},
	}
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"}}
	podA := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "web-a", Namespace: "default",
		Annotations:     map[string]string{AnnotationState: "RESTRICTED"},
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "web-rs", Controller: &trueVal}},
	}}
	podB := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "web-b", Namespace: "default",
		Annotations:     map[string]string{AnnotationState: "QUARANTINED"},
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "web-rs", Controller: &trueVal}},
	}}
	cs := fake.NewSimpleClientset(rs, dep, podA, podB)
	c, err := New(Config{PollInterval: time.Second, DefaultTTL: time.Hour}, cs, store, machine, pub, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.reconcile(ctx)

	// Most-isolating (QUARANTINED) wins.
	if s, pinned := machine.IsPinned(depWorkloadID); !pinned || s != schema.StateQuarantined {
		t.Fatalf("IsPinned = (%s, %v), want (QUARANTINED, true) - most-isolating tie-break", s, pinned)
	}
}

func TestStore_PutGetDeleteRoundTrip(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	store, _ := newRedisStore(t, mr)

	rec := OverrideRecord{
		RequestedState: schema.StateRestricted,
		TTLSeconds:     1800,
		OperatorID:     "alice",
		AppliedAt:      time.Now().UTC().Truncate(time.Nanosecond),
		Source:         SourcePod,
	}
	if err := store.Put(ctx, depWorkloadID, rec, 30*time.Minute); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, ok, err := store.Get(ctx, depWorkloadID)
	if err != nil || !ok {
		t.Fatalf("Get = (%v, %v, %v)", got, ok, err)
	}
	if got.RequestedState != rec.RequestedState || got.OperatorID != "alice" || got.Source != SourcePod {
		t.Errorf("round-trip = %+v, want %+v", got, rec)
	}
	active, err := store.ListActive(ctx)
	if err != nil {
		t.Fatalf("ListActive: %v", err)
	}
	if _, present := active[depWorkloadID]; !present {
		t.Errorf("ListActive missing %q: %v", depWorkloadID, active)
	}
	if err := store.Delete(ctx, depWorkloadID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok, _ := store.Get(ctx, depWorkloadID); ok {
		t.Error("Get after Delete should be absent")
	}
}

func TestStore_ListActiveExpiry(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	store, _ := newRedisStore(t, mr)

	rec := OverrideRecord{RequestedState: schema.StateRestricted, TTLSeconds: 1800, AppliedAt: time.Now().UTC(), Source: SourcePod}
	if err := store.Put(ctx, depWorkloadID, rec, 30*time.Minute); err != nil {
		t.Fatalf("Put: %v", err)
	}
	mr.FastForward(31 * time.Minute)
	active, err := store.ListActive(ctx)
	if err != nil {
		t.Fatalf("ListActive: %v", err)
	}
	if len(active) != 0 {
		t.Errorf("ListActive after TTL expiry = %v, want empty", active)
	}
}

// --- identity / store / publisher coverage ---

func TestResolveWorkloadID_Variants(t *testing.T) {
	ctx := context.Background()
	trueVal := true
	cases := []struct {
		name string
		objs []runtime.Object
		pod  *corev1.Pod
		want string
	}{
		{
			name: "orphan pod (no controller)",
			pod:  &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "lonely"}},
			want: "ns/Pod/lonely",
		},
		{
			name: "statefulset",
			pod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
				Namespace: "ns", Name: "db-0",
				OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "StatefulSet", Name: "db", Controller: &trueVal}},
			}},
			want: "ns/StatefulSet/db",
		},
		{
			name: "job without cronjob",
			objs: []runtime.Object{batchJob("ns", "batch", "")},
			pod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
				Namespace: "ns", Name: "batch-x",
				OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: "batch", Controller: &trueVal}},
			}},
			want: "ns/Job/batch",
		},
		{
			name: "job owned by cronjob",
			objs: []runtime.Object{batchJob("ns", "batch", "nightly")},
			pod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
				Namespace: "ns", Name: "batch-x",
				OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: "batch", Controller: &trueVal}},
			}},
			want: "ns/CronJob/nightly",
		},
		{
			name: "replicaset without deployment",
			objs: []runtime.Object{replicaSet("ns", "rs", "")},
			pod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
				Namespace: "ns", Name: "rs-x",
				OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "rs", Controller: &trueVal}},
			}},
			want: "ns/ReplicaSet/rs",
		},
		{
			name: "replicaset owner not found -> orphan",
			pod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
				Namespace: "ns", Name: "rs-x",
				OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "missing", Controller: &trueVal}},
			}},
			want: "ns/Pod/rs-x",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewSimpleClientset(tc.objs...)
			got, err := resolveWorkloadID(ctx, cs, tc.pod)
			if err != nil {
				t.Fatalf("resolveWorkloadID: %v", err)
			}
			if got != tc.want {
				t.Errorf("resolveWorkloadID = %q, want %q", got, tc.want)
			}
		})
	}
}

func batchJob(ns, name, cronParent string) *batchv1.Job {
	trueVal := true
	j := &batchv1.Job{}
	j.Namespace = ns
	j.Name = name
	if cronParent != "" {
		j.OwnerReferences = []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "CronJob", Name: cronParent, Controller: &trueVal}}
	}
	return j
}

func replicaSet(ns, name, depParent string) *appsv1.ReplicaSet {
	trueVal := true
	rs := &appsv1.ReplicaSet{}
	rs.Namespace = ns
	rs.Name = name
	if depParent != "" {
		rs.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: depParent, Controller: &trueVal}}
	}
	return rs
}

func TestPublisher_NilClientRejected(t *testing.T) {
	if _, err := NewNATSPublisher(nil); err == nil {
		t.Fatal("NewNATSPublisher(nil) = nil error, want rejection")
	}
}

func TestStore_NilClientRejected(t *testing.T) {
	if _, err := NewStore(nil); err == nil {
		t.Fatal("NewStore(nil) = nil error, want rejection")
	}
}

func TestRun_ReturnsOnContextCancel(t *testing.T) {
	mr := startMiniredis(t)
	store, _ := newRedisStore(t, mr)
	machine := newMachine(t)
	pub := &fakePublisher{}
	_, objs := deploymentPod("default", "web", nil)
	c := newController(t, objs, store, machine, pub, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v, want nil on ctx cancel", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return on ctx cancel")
	}
}

func TestNew_NilArgsRejected(t *testing.T) {
	mr := startMiniredis(t)
	store, _ := newRedisStore(t, mr)
	machine := newMachine(t)
	pub := &fakePublisher{}
	cs := fake.NewSimpleClientset()

	if _, err := New(Config{}, nil, store, machine, pub, nil, nil); err == nil {
		t.Error("nil clientset must be rejected")
	}
	if _, err := New(Config{}, cs, nil, machine, pub, nil, nil); err == nil {
		t.Error("nil store must be rejected")
	}
	if _, err := New(Config{}, cs, store, nil, pub, nil, nil); err == nil {
		t.Error("nil machine must be rejected")
	}
	if _, err := New(Config{}, cs, store, machine, nil, nil, nil); err == nil {
		t.Error("nil publisher must be rejected")
	}
}

func TestOwnerAnnotations_Variants(t *testing.T) {
	ctx := context.Background()
	trueVal := true
	anns := map[string]string{AnnotationState: "RESTRICTED"}

	t.Run("statefulset owner", func(t *testing.T) {
		ss := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "db", Annotations: anns}}
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "db-0",
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "StatefulSet", Name: "db", Controller: &trueVal}}}}
		cs := fake.NewSimpleClientset(ss)
		if got := ownerAnnotations(ctx, cs, pod); got[AnnotationState] != "RESTRICTED" {
			t.Errorf("statefulset owner annotations = %v", got)
		}
	})
	t.Run("daemonset owner", func(t *testing.T) {
		ds := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "agent", Annotations: anns}}
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "agent-x",
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "DaemonSet", Name: "agent", Controller: &trueVal}}}}
		cs := fake.NewSimpleClientset(ds)
		if got := ownerAnnotations(ctx, cs, pod); got[AnnotationState] != "RESTRICTED" {
			t.Errorf("daemonset owner annotations = %v", got)
		}
	})
	t.Run("job owner", func(t *testing.T) {
		job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "batch", Annotations: anns}}
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "batch-x",
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: "batch", Controller: &trueVal}}}}
		cs := fake.NewSimpleClientset(job)
		if got := ownerAnnotations(ctx, cs, pod); got[AnnotationState] != "RESTRICTED" {
			t.Errorf("job owner annotations = %v", got)
		}
	})
	t.Run("cronjob owner", func(t *testing.T) {
		cj := &batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "nightly", Annotations: anns}}
		job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "batch",
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "CronJob", Name: "nightly", Controller: &trueVal}}}}
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "batch-x",
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: "batch", Controller: &trueVal}}}}
		cs := fake.NewSimpleClientset(cj, job)
		if got := ownerAnnotations(ctx, cs, pod); got[AnnotationState] != "RESTRICTED" {
			t.Errorf("cronjob owner annotations = %v", got)
		}
	})
	t.Run("replicaset without deployment owner", func(t *testing.T) {
		rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "rs", Annotations: anns}}
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "rs-x",
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "rs", Controller: &trueVal}}}}
		cs := fake.NewSimpleClientset(rs)
		if got := ownerAnnotations(ctx, cs, pod); got[AnnotationState] != "RESTRICTED" {
			t.Errorf("rs owner annotations = %v", got)
		}
	})
	t.Run("orphan pod has no owner annotations", func(t *testing.T) {
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "lonely"}}
		cs := fake.NewSimpleClientset()
		if got := ownerAnnotations(ctx, cs, pod); got != nil {
			t.Errorf("orphan owner annotations = %v, want nil", got)
		}
	})
}

func TestStore_ListActiveSkipsMalformed(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	store, cli := newRedisStore(t, mr)
	// Write a valid record and a malformed one (wrong schema_version).
	if err := store.Put(ctx, depWorkloadID, OverrideRecord{RequestedState: schema.StateRestricted, AppliedAt: time.Now()}, time.Hour); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := cli.SetOverride(ctx, "override:default/Deployment/bad", map[string]any{"schema_version": "nope"}, time.Hour); err != nil {
		t.Fatalf("seed malformed: %v", err)
	}
	active, err := store.ListActive(ctx)
	if err != nil {
		t.Fatalf("ListActive: %v", err)
	}
	if _, ok := active[depWorkloadID]; !ok {
		t.Error("valid record missing")
	}
	if _, ok := active["default/Deployment/bad"]; ok {
		t.Error("malformed record must be skipped")
	}
}
