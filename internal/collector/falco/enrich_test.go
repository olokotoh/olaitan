package falco

// Story 11.2d (#195): collector-side pod identity enrichment. Falco does not
// fill k8s.ns.name / k8s.pod.name for pods created after Falco started, so
// the attack alerts reach the collector with a container.id and no pod. The
// collector fills the pod from its own node-scoped cache (container ID ->
// pod) before Translate, so the correlator can attribute the alert to the
// workload instead of dropping it as a host event.

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fakeResolver is a PodIdentityResolver backed by a fixed map. It records
// every container ID it was asked about so tests can assert it was (or was
// not) consulted.
type fakeResolver struct {
	mu    sync.Mutex
	pods  map[string]PodIdentity
	calls []string
}

func (f *fakeResolver) ResolvePodIdentity(_ context.Context, containerID string) (PodIdentity, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, containerID)
	id, ok := f.pods[containerID]
	return id, ok
}

func (f *fakeResolver) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// realAlert loads one of the recorded REAL Falco alerts captured live on
// 2026-09-25. The S2 SA-token alert carries container.id=ba197754b7bc with
// k8s.ns.name and k8s.pod.name null: exactly the gap this enrichment closes.
func realAlert(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "real-alerts", name))
	if err != nil {
		t.Fatalf("read real alert %s: %v", name, err)
	}
	return b
}

var attackPod = PodIdentity{Namespace: "tenant-acme", Name: "web-7d9c8b6f5-x2k4q", UID: "0b3f6c2e-5a1d-4f7e-9c8b-2d4e6f8a0b1c"}

func TestEnrichPodIdentity_RealAlertGetsThePodFromTheCache(t *testing.T) {
	resp, err := DecodeHTTPOutput(realAlert(t, "cred-001-sa-token-read.json"))
	if err != nil {
		t.Fatalf("DecodeHTTPOutput: %v", err)
	}
	if _, ok := resp.GetOutputFields()["k8s.ns.name"]; ok {
		t.Fatal("precondition: the recorded real alert must have no k8s.ns.name (Falco left it null)")
	}
	r := &fakeResolver{pods: map[string]PodIdentity{"ba197754b7bc": attackPod}}

	if !EnrichPodIdentity(context.Background(), resp, r) {
		t.Fatal("EnrichPodIdentity returned false for a container alert the cache knows")
	}
	ev, err := Translate(resp, "eval-node")
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if ev.Pod.Namespace != attackPod.Namespace || ev.Pod.Name != attackPod.Name || ev.Pod.UID != attackPod.UID {
		t.Errorf("pod = %+v, want %+v on node eval-node", ev.Pod, attackPod)
	}
	if ev.Pod.Node != "eval-node" {
		t.Errorf("pod.node = %q, want eval-node", ev.Pod.Node)
	}
	var raw struct {
		Pairs        [][2]string       `json:"output_fields"`
		OutputFields map[string]string `json:"-"`
	}
	if err := json.Unmarshal(ev.Raw, &raw); err != nil {
		t.Fatalf("raw: %v", err)
	}
	raw.OutputFields = map[string]string{}
	for _, kv := range raw.Pairs {
		raw.OutputFields[kv[0]] = kv[1]
	}
	if raw.OutputFields[EnrichedByField] != EnrichedByPodCache {
		t.Errorf("raw output_fields[%s] = %q, want %q so an analyst can tell the pod came from the collector, not Falco",
			EnrichedByField, raw.OutputFields[EnrichedByField], EnrichedByPodCache)
	}
	// The field mapping is unchanged: the event half the OLT rule needs is
	// still there after enrichment.
	if raw.OutputFields["fd.name"] != "/var/run/secrets/kubernetes.io/serviceaccount/token" {
		t.Errorf("fd.name changed by enrichment: %q", raw.OutputFields["fd.name"])
	}
}

func TestEnrichPodIdentity_EventIDIsUnchanged(t *testing.T) {
	// JetStream dedup keys on the event ID. Enrichment must not change it,
	// or a Falco retry of the same alert enriched on one attempt and missed
	// on the other would publish twice.
	plain, err := DecodeHTTPOutput(realAlert(t, "cred-001-sa-token-read.json"))
	if err != nil {
		t.Fatal(err)
	}
	enriched, err := DecodeHTTPOutput(realAlert(t, "cred-001-sa-token-read.json"))
	if err != nil {
		t.Fatal(err)
	}
	EnrichPodIdentity(context.Background(), enriched, &fakeResolver{pods: map[string]PodIdentity{"ba197754b7bc": attackPod}})
	a, _ := Translate(plain, "n")
	b, _ := Translate(enriched, "n")
	if a.ID != b.ID {
		t.Errorf("enrichment changed the event ID: %s -> %s", a.ID, b.ID)
	}
}

func TestEnrichPodIdentity_LeavesFalcoIdentityAlone(t *testing.T) {
	resp, err := DecodeHTTPOutput(realAlert(t, "cred-001-sa-token-read.json"))
	if err != nil {
		t.Fatal(err)
	}
	resp.OutputFields["k8s.ns.name"] = "from-falco"
	resp.OutputFields["k8s.pod.name"] = "pod-from-falco"
	r := &fakeResolver{pods: map[string]PodIdentity{"ba197754b7bc": attackPod}}
	if EnrichPodIdentity(context.Background(), resp, r) {
		t.Error("enriched an alert Falco had already attributed")
	}
	if r.callCount() != 0 {
		t.Errorf("cache consulted %d times for an alert that needs no enrichment", r.callCount())
	}
	if resp.OutputFields["k8s.ns.name"] != "from-falco" {
		t.Errorf("Falco's namespace overwritten: %q", resp.OutputFields["k8s.ns.name"])
	}
}

func TestEnrichPodIdentity_NotAContainer(t *testing.T) {
	for name, cid := range map[string]*string{
		"no container.id":   nil,
		"empty":             ptr(""),
		"host":              ptr("host"),
		"falco placeholder": ptr("<NA>"),
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := DecodeHTTPOutput(realAlert(t, "cred-001-sa-token-read.json"))
			if err != nil {
				t.Fatal(err)
			}
			delete(resp.OutputFields, "container.id")
			if cid != nil {
				resp.OutputFields["container.id"] = *cid
			}
			r := &fakeResolver{pods: map[string]PodIdentity{"host": attackPod, "": attackPod}}
			if EnrichPodIdentity(context.Background(), resp, r) {
				t.Error("enriched an alert that has no container")
			}
			if r.callCount() != 0 {
				t.Errorf("cache consulted for a non-container alert (%d calls)", r.callCount())
			}
		})
	}
}

func TestEnrichPodIdentity_PlaceholderIdentityCountsAsMissing(t *testing.T) {
	// Falco renders a missing field as "<NA>" in some output formats.
	resp, err := DecodeHTTPOutput(realAlert(t, "cred-001-sa-token-read.json"))
	if err != nil {
		t.Fatal(err)
	}
	resp.OutputFields["k8s.ns.name"] = "<NA>"
	resp.OutputFields["k8s.pod.name"] = "<NA>"
	r := &fakeResolver{pods: map[string]PodIdentity{"ba197754b7bc": attackPod}}
	if !EnrichPodIdentity(context.Background(), resp, r) {
		t.Fatal("did not enrich an alert whose k8s fields are <NA>")
	}
	if resp.OutputFields["k8s.ns.name"] != attackPod.Namespace || resp.OutputFields["k8s.pod.name"] != attackPod.Name {
		t.Errorf("fields = %v", resp.OutputFields)
	}
}

func TestEnrichPodIdentity_MissLeavesTheAlertUnchanged(t *testing.T) {
	resp, err := DecodeHTTPOutput(realAlert(t, "cred-001-sa-token-read.json"))
	if err != nil {
		t.Fatal(err)
	}
	before := len(resp.OutputFields)
	r := &fakeResolver{pods: map[string]PodIdentity{}}
	if EnrichPodIdentity(context.Background(), resp, r) {
		t.Error("reported enrichment on a cache miss")
	}
	if r.callCount() != 1 {
		t.Errorf("cache calls = %d, want 1", r.callCount())
	}
	if len(resp.OutputFields) != before {
		t.Errorf("a miss changed output_fields: %v", resp.OutputFields)
	}
}

func TestEnrichPodIdentity_NilResolverIsANoop(t *testing.T) {
	resp, err := DecodeHTTPOutput(realAlert(t, "cred-001-sa-token-read.json"))
	if err != nil {
		t.Fatal(err)
	}
	if EnrichPodIdentity(context.Background(), resp, nil) {
		t.Error("nil resolver enriched")
	}
}

// The adapter wires the resolver in before Translate: a real alert POSTed
// by Falco with null k8s fields is published with the pod filled in.
func TestAdapter_EnrichesBeforeTranslate(t *testing.T) {
	pub := &recordingPub{}
	r := &fakeResolver{pods: map[string]PodIdentity{"ba197754b7bc": attackPod}}
	a := newRunningAdapter(t, pub, func(c *Config) { c.PodIdentity = r })

	rec := post(t, a, pathPrefix+testToken, "application/json", realAlert(t, "cred-001-sa-token-read.json"))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	deadline := time.Now().Add(2 * time.Second)
	for pub.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if pub.count() != 1 {
		t.Fatalf("published %d events, want 1", pub.count())
	}
	pub.mu.Lock()
	ev := pub.events[0]
	pub.mu.Unlock()
	if ev.Pod.Namespace != "tenant-acme" || ev.Pod.Name != attackPod.Name || ev.Pod.UID != attackPod.UID {
		t.Errorf("published pod = %+v, want the attack pod", ev.Pod)
	}
}

// The metrics snapshot heartbeat is not an alert and must never touch the
// cache (and never wait on it).
func TestAdapter_HeartbeatSkipsEnrichment(t *testing.T) {
	pub := &recordingPub{}
	r := &fakeResolver{pods: map[string]PodIdentity{}}
	a := newTestAdapter(t, pub, func(c *Config) { c.PodIdentity = r })
	rec := post(t, a, pathPrefix+testToken, "application/json", fixture(t, "http_output_metrics_snapshot.json"))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d", rec.Code)
	}
	if r.callCount() != 0 {
		t.Errorf("heartbeat consulted the pod cache %d times", r.callCount())
	}
}

func ptr(s string) *string { return &s }
