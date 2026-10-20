package correlator

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"

	"github.com/olokotoh/olaitan/internal/correlator/window"
	"github.com/olokotoh/olaitan/internal/schema"
)

// Story 10.12: the correlator hands every attributed event to the
// baseline engine. The Goldmane aggregate resolution itself is Story
// 11.2b's (goldmane_aggregate.go, resolve_goldmane_aggregate_test.go).
func deploymentPodObjects() []any {
	isController := true
	return []any{
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "tenant-acme", UID: "dep-uid"}},
		&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{
			Name: "web-bd846c7f", Namespace: "tenant-acme", UID: "rs-uid",
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "web", UID: "dep-uid", Controller: &isController}},
		}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: "web-bd846c7f-zdhz7", Namespace: "tenant-acme", GenerateName: "web-bd846c7f-", UID: "pod-uid",
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "web-bd846c7f", UID: "rs-uid", Controller: &isController}},
		}},
		// A different set in the same namespace must not match.
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "web-other-x1", Namespace: "tenant-acme", GenerateName: "web-other-"}},
	}
}

func newResolveCorrelator(objs ...any) (*Correlator, *kubefake.Clientset) {
	rt := make([]any, 0, len(objs))
	rt = append(rt, objs...)
	kube := kubefake.NewSimpleClientset()
	for _, o := range rt {
		switch v := o.(type) {
		case *corev1.Pod:
			_ = kube.Tracker().Add(v)
		case *appsv1.ReplicaSet:
			_ = kube.Tracker().Add(v)
		case *appsv1.Deployment:
			_ = kube.Tracker().Add(v)
		}
	}
	c := &Correlator{
		kube:             kube,
		identityCacheTTL: 30 * time.Second,
		window:           window.NewStore(time.Minute),
		log:              slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	c.minSources.Store(2)
	c.windowNanos.Store(int64(time.Minute))
	return c, kube
}

type recordingObserver struct {
	got []Observed
}

type Observed struct {
	WorkloadID string
	Identity   schema.WorkloadIdentity
	EventID    string
}

func (r *recordingObserver) ObserveEvent(workloadID string, identity schema.WorkloadIdentity, ev schema.Event) {
	r.got = append(r.got, Observed{workloadID, identity, ev.ID})
}

// Story 10.12 D1: every attributed event reaches the observer, including
// a Goldmane flow from an aggregate; host events and never-scored
// namespaces do not.
func TestAddEventFeedsObserverAfterAttribution(t *testing.T) {
	c, _ := newResolveCorrelator(deploymentPodObjects()...)
	c.SetNeverScoredNamespaces([]string{"olaitan"})
	obs := &recordingObserver{}
	c.SetEventObserver(obs)
	events := []schema.Event{
		{ID: "flow-1", Source: schema.SourceNetwork, Category: schema.CategoryFlow, Pod: schema.PodRef{Namespace: "tenant-acme", Name: "web-bd846c7f-*"}},
		{ID: "host-1", Source: schema.SourceFalco, Category: schema.CategorySyscall, Pod: schema.PodRef{}},
		{ID: "own-1", Source: schema.SourceAudit, Category: schema.CategoryAudit, Pod: schema.PodRef{Namespace: "olaitan", Name: "olaitan-aggregator-0"}},
	}
	for _, ev := range events {
		if _, err := c.AddEvent(context.Background(), ev); err != nil {
			t.Fatalf("AddEvent(%s): %v", ev.ID, err)
		}
	}
	if len(obs.got) != 1 {
		t.Fatalf("observer got %d events, want 1 (only the attributed flow): %+v", len(obs.got), obs.got)
	}
	// Since Story 11.2b the resolved flow also enters the window
	// (detection); the observer sees it under the same owner id.
	if n := len(c.window.Snapshot("tenant-acme/Deployment/web").Events); n != 1 {
		t.Fatalf("resolved aggregate flow: %d window events, want 1", n)
	}
	if o := obs.got[0]; o.EventID != "flow-1" || o.WorkloadID != "tenant-acme/Deployment/web" || o.Identity.OwnerName != "web" {
		t.Fatalf("observer got %+v, want flow-1 attributed to tenant-acme/Deployment/web", o)
	}
	c.SetEventObserver(nil)
	if _, err := c.AddEvent(context.Background(), schema.Event{ID: "flow-2", Source: schema.SourceNetwork, Category: schema.CategoryFlow, Pod: schema.PodRef{Namespace: "tenant-acme", Name: "web-bd846c7f-*"}}); err != nil {
		t.Fatalf("AddEvent without observer: %v", err)
	}
	if len(obs.got) != 1 {
		t.Fatal("a removed observer still received events")
	}
}
