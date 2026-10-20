package posture_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/olokotoh/olaitan/internal/collector/posture"
	olaitanschema "github.com/olokotoh/olaitan/internal/schema"
)

// Story 12.8 (#226). Calico Goldmane names a set of pods by their shared
// GenerateName plus "*" ("steady-6c8f4c97cc-*"). On the 2026-10-20 live run
// every baseline package led by such a flow lost its posture: the assembler
// handed Get a stub pod with the aggregate name, the owner walk found no
// owner, and keys.PodFallbackID rejected the "*" ("posture: workload-id
// builder failed"). Get now resolves the aggregate with the same resolver the
// correlator uses (PR #205).

func aggregateLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), &buf
}

func steadyDeployment(withPod bool) *fake.Clientset {
	objs := []runtime.Object{
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "steady", Namespace: "olt-bl"}},
		newReplicaSetOwnedByDeployment("steady-6c8f4c97cc", "olt-bl", "steady"),
	}
	if withPod {
		objs = append(objs, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "steady-6c8f4c97cc-q2w9z", GenerateName: "steady-6c8f4c97cc-", Namespace: "olt-bl",
				OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "steady-6c8f4c97cc", Controller: boolPtrLocal(true)}},
			},
			Spec: corev1.PodSpec{ServiceAccountName: "steady"},
		})
	}
	return fake.NewSimpleClientset(objs...)
}

// aggregateStub is what the assembler builds on the cache-warm baseline path:
// a pod carrying only the aggregate name and the namespace.
func aggregateStub() *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "steady-6c8f4c97cc-*", Namespace: "olt-bl"}}
}

func assertNoKeyRejection(t *testing.T, logs string) {
	t.Helper()
	for _, bad := range []string{"workload-id builder failed", "disallowed character"} {
		if strings.Contains(logs, bad) {
			t.Errorf("Get logged %q for a Goldmane aggregate; logs:\n%s", bad, logs)
		}
	}
}

func TestGet_GoldmaneAggregateResolvesToRepresentativePod(t *testing.T) {
	log, buf := aggregateLogger()
	c, err := posture.New(defaultCfg(time.Date(2026, 10, 20, 14, 2, 0, 0, time.UTC)), steadyDeployment(true), log)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Get(context.Background(), aggregateStub())
	if err != nil {
		t.Fatalf("Get on an aggregate with a live pod: %v", err)
	}
	if got.Unavailable {
		t.Fatalf("posture Unavailable (%s) although a pod of the set is live", got.UnavailableReason)
	}
	if got.Identity.OwnerKind != "Deployment" || got.Identity.OwnerName != "steady" || got.OrphanPod {
		t.Errorf("identity = %+v orphan=%v, want Deployment/steady", got.Identity, got.OrphanPod)
	}
	if got.ServiceAccount != "steady" {
		t.Errorf("ServiceAccount = %q, want the representative pod's steady", got.ServiceAccount)
	}
	assertNoKeyRejection(t, buf.String())

	// The entry is keyed by the owner's workload id, the same key a Falco
	// event's real pod uses: a second Get by the real pod is a cache hit.
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "steady-6c8f4c97cc-q2w9z", Namespace: "olt-bl",
		OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "steady-6c8f4c97cc", Controller: boolPtrLocal(true)}},
	}}
	if _, err := c.Get(context.Background(), pod); err != nil {
		t.Fatal(err)
	}
	if c.PostureCacheHits() != 1 {
		t.Errorf("cache hits = %d, want 1 (aggregate and real pod share the Deployment key)", c.PostureCacheHits())
	}
}

func TestGet_GoldmaneAggregateWithOnlyAReplicaSetKeepsTheOwner(t *testing.T) {
	log, buf := aggregateLogger()
	c, err := posture.New(defaultCfg(time.Now()), steadyDeployment(false), log)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Get(context.Background(), aggregateStub())
	if err == nil {
		t.Fatal("Get with no live pod returned no error; there is no pod to take a posture from")
	}
	if got == nil || !got.Unavailable || got.UnavailableReason != olaitanschema.PostureUnavailableNotFound {
		t.Fatalf("got %+v, want an Unavailable not_found posture", got)
	}
	if got.Identity.OwnerKind != "Deployment" || got.Identity.OwnerName != "steady" || got.OrphanPod {
		t.Errorf("identity = %+v orphan=%v, want the resolved Deployment/steady", got.Identity, got.OrphanPod)
	}
	assertNoKeyRejection(t, buf.String())
}

func TestGet_UnresolvableGoldmaneAggregateIsNotFoundNotAKeyError(t *testing.T) {
	log, buf := aggregateLogger()
	c, err := posture.New(defaultCfg(time.Now()), fake.NewSimpleClientset(), log)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Get(context.Background(), aggregateStub())
	if err == nil {
		t.Fatal("Get on an aggregate nothing backs returned no error")
	}
	if got == nil || !got.Unavailable || got.UnavailableReason != olaitanschema.PostureUnavailableNotFound {
		t.Fatalf("got %+v, want an Unavailable not_found posture", got)
	}
	assertNoKeyRejection(t, buf.String())
}

func TestGoldmaneAggregatePrefix(t *testing.T) {
	cases := map[string]struct {
		prefix string
		ok     bool
	}{
		"web-bd846c7f-*":     {"web-bd846c7f-", true},
		"fluent-bit-*":       {"fluent-bit-", true},
		"web-bd846c7f-kx8cv": {"", false},
		"*":                  {"", false},
		"we*b-*":             {"", false},
		"web-*-x":            {"", false},
		"":                   {"", false},
		"**":                 {"", false},
		"-*":                 {"-", true}, // CheckAggregateRef rejects it
	}
	for name, want := range cases {
		got, ok := posture.GoldmaneAggregatePrefix(name)
		if got != want.prefix || ok != want.ok {
			t.Errorf("GoldmaneAggregatePrefix(%q) = %q, %v; want %q, %v", name, got, ok, want.prefix, want.ok)
		}
	}
}

// A non-pod endpoint ("-" namespace) is not a pod set: permanent, and not
// counted as an apiserver error.
func TestGet_NonPodGoldmaneEndpointIsPermanentNotAnAPIError(t *testing.T) {
	log, buf := aggregateLogger()
	c, err := posture.New(defaultCfg(time.Now()), fake.NewSimpleClientset(), log)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Get(context.Background(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pub-*", Namespace: "-"}})
	if err == nil || got == nil || got.UnavailableReason != olaitanschema.PostureUnavailablePermanent {
		t.Fatalf("got %+v, %v; want an Unavailable permanent posture and an error", got, err)
	}
	if c.PostureAPIErrors() != 0 {
		t.Errorf("api errors = %d, want 0 (no apiserver call was made)", c.PostureAPIErrors())
	}
	assertNoKeyRejection(t, buf.String())
}

// Review round 1 (Story 12.8): a pod that only shares the GenerateName (no
// controller, or a controller of another name) is never the representative,
// so it can neither make the set unresolvable nor lend its ServiceAccount to
// the workload's posture. A web- set never matches a web-canary- pod, and a
// finished pod is used only when nothing live is left.
func TestResolveGoldmaneAggregate_PicksOnlyALivePodOfTheNamedController(t *testing.T) {
	ctrl := func(kind, name string) []metav1.OwnerReference {
		return []metav1.OwnerReference{{Kind: kind, Name: name, Controller: boolPtrLocal(true)}}
	}
	pod := func(name, gen, sa string, owners []metav1.OwnerReference, phase corev1.PodPhase) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: name, GenerateName: gen, Namespace: "olt-bl", OwnerReferences: owners},
			Spec:       corev1.PodSpec{ServiceAccountName: sa},
			Status:     corev1.PodStatus{Phase: phase},
		}
	}
	cs := fake.NewSimpleClientset(
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "steady", Namespace: "olt-bl"}},
		newReplicaSetOwnedByDeployment("steady-6c8f4c97cc", "olt-bl", "steady"),
		// Sorted before the real pod; LIST order is by name.
		pod("steady-6c8f4c97cc-aaaaa", "steady-6c8f4c97cc-", "bare", nil, corev1.PodRunning),
		pod("steady-6c8f4c97cc-aaaab", "steady-6c8f4c97cc-", "forged", ctrl("ReplicaSet", "other-rs"), corev1.PodRunning),
		pod("steady-6c8f4c97cc-aaaac", "steady-6c8f4c97cc-", "finished", ctrl("ReplicaSet", "steady-6c8f4c97cc"), corev1.PodSucceeded),
		pod("steady-6c8f4c97cc-canary-x", "steady-6c8f4c97cc-canary-", "canary", ctrl("ReplicaSet", "steady-6c8f4c97cc-canary"), corev1.PodRunning),
		pod("steady-6c8f4c97cc-zzzzz", "steady-6c8f4c97cc-", "steady", ctrl("ReplicaSet", "steady-6c8f4c97cc"), corev1.PodRunning),
	)
	id, rep, err := posture.ResolveGoldmaneAggregate(context.Background(), cs, "olt-bl", "steady-6c8f4c97cc-")
	if err != nil {
		t.Fatal(err)
	}
	if rep == nil || rep.Spec.ServiceAccountName != "steady" || id.OwnerKind != "Deployment" || id.OwnerName != "steady" {
		t.Fatalf("got %+v from pod %+v, want Deployment/steady from the live steady pod", id, rep)
	}

	// With only the finished pod of the set left, it still names the owner.
	cs2 := fake.NewSimpleClientset(
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "steady", Namespace: "olt-bl"}},
		newReplicaSetOwnedByDeployment("steady-6c8f4c97cc", "olt-bl", "steady"),
		pod("steady-6c8f4c97cc-aaaaa", "steady-6c8f4c97cc-", "bare", nil, corev1.PodRunning),
		pod("steady-6c8f4c97cc-aaaac", "steady-6c8f4c97cc-", "finished", ctrl("ReplicaSet", "steady-6c8f4c97cc"), corev1.PodSucceeded),
	)
	if _, rep, err := posture.ResolveGoldmaneAggregate(context.Background(), cs2, "olt-bl", "steady-6c8f4c97cc-"); err != nil || rep == nil || rep.Spec.ServiceAccountName != "finished" {
		t.Fatalf("finished-only set: rep %+v err %v, want the finished pod", rep, err)
	}
}

// Review round 1: a late flow whose pods are gone still gets the owner's
// posture while the cache holds it.
func TestGet_GoldmaneAggregateWithNoPodUsesTheOwnersCachedPosture(t *testing.T) {
	cs := steadyDeployment(true)
	c, err := posture.New(defaultCfg(time.Date(2026, 10, 20, 14, 2, 0, 0, time.UTC)), cs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(context.Background(), aggregateStub()); err != nil {
		t.Fatal(err)
	}
	if err := cs.CoreV1().Pods("olt-bl").Delete(context.Background(), "steady-6c8f4c97cc-q2w9z", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	got, err := c.Get(context.Background(), aggregateStub())
	if err != nil || got == nil || got.Unavailable || got.ServiceAccount != "steady" {
		t.Fatalf("got %+v, %v; want the cached Deployment posture", got, err)
	}
	// A bypass asks for a fresh posture, which needs a live pod.
	if got, err := c.Get(context.Background(), aggregateStub(), posture.WithBypassCache()); err == nil || got == nil || !got.Unavailable {
		t.Fatalf("bypass with no live pod: got %+v, %v; want Unavailable and an error", got, err)
	}
}

func TestCheckAggregateRefRejectsWhatCannotBeAPodSet(t *testing.T) {
	for _, tc := range []struct{ ns, prefix string }{{"-", "pub-"}, {"olt-bl", "-"}, {"olt-bl", ""}} {
		if err := posture.CheckAggregateRef(tc.ns, tc.prefix); err == nil {
			t.Errorf("CheckAggregateRef(%q, %q) = nil, want an error", tc.ns, tc.prefix)
		}
	}
	if err := posture.CheckAggregateRef("olt-bl", "steady-6c8f4c97cc-"); err != nil {
		t.Errorf("valid ref rejected: %v", err)
	}
}

// Review round 2: an Indexed Job's pods carry the GenerateName
// "<job>-<index>-", so Goldmane reports "<job>-<index>-*"; the controller is
// the Job itself. A ReplicaSet "<x>-0" is not an Indexed Job.
func TestResolveGoldmaneAggregate_IndexedJob(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "train", Namespace: "olt-bl"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: "train-0-x7k2p", GenerateName: "train-0-", Namespace: "olt-bl",
			OwnerReferences: []metav1.OwnerReference{{Kind: "Job", Name: "train", Controller: boolPtrLocal(true)}},
		}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: "web-0-x7k2p", GenerateName: "web-0-", Namespace: "olt-bl",
			OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "web", Controller: boolPtrLocal(true)}},
		}},
	)
	id, rep, err := posture.ResolveGoldmaneAggregate(context.Background(), cs, "olt-bl", "train-0-")
	if err != nil || rep == nil || id.OwnerKind != "Job" || id.OwnerName != "train" {
		t.Fatalf("indexed Job aggregate: %+v, pod %v, err %v; want Job/train", id, rep, err)
	}
	if _, rep, err := posture.ResolveGoldmaneAggregate(context.Background(), cs, "olt-bl", "web-0-"); err == nil || rep != nil {
		t.Fatalf("a ReplicaSet named web owning web-0- pods must not pass the Job-index rule: pod %v err %v", rep, err)
	}
	// Round 3: the index must be digits only.
	for _, gen := range []string{"train-canary-", "train-0a-"} {
		cs := fake.NewSimpleClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: gen + "x7k2p", GenerateName: gen, Namespace: "olt-bl",
			OwnerReferences: []metav1.OwnerReference{{Kind: "Job", Name: "train", Controller: boolPtrLocal(true)}},
		}})
		if _, rep, err := posture.ResolveGoldmaneAggregate(context.Background(), cs, "olt-bl", gen); err == nil || rep != nil {
			t.Errorf("%s* owned by Job train passed the Job-index rule: pod %v err %v", gen, rep, err)
		}
	}
}
