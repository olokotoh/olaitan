package posture_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
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
