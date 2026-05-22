package matcher

import (
	"strings"
	"testing"

	"github.com/olokotoh/olaitan/internal/schema"
)

func TestResolver_K8sRoutesToPosture(t *testing.T) {
	posture := &schema.WorkloadPosture{
		Identity: schema.WorkloadIdentity{
			Namespace: "tenant-acme",
			OwnerKind: "Deployment",
			OwnerName: "web",
		},
		ServiceAccount: "default",
	}
	r, _, err := NewResolver(posture, map[string]string{
		"process.exe": "/usr/local/bin/xmrig",
	})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	if got := r.Resolve("k8s.pod.namespace", nil); len(got) != 1 || got[0] != "tenant-acme" {
		t.Errorf("Resolve(k8s.pod.namespace) = %v, want [tenant-acme]", got)
	}
	if got := r.Resolve("k8s.workload.owner_kind", nil); len(got) != 1 || got[0] != "Deployment" {
		t.Errorf("Resolve(k8s.workload.owner_kind) = %v, want [Deployment]", got)
	}
}

func TestResolver_NonK8sRoutesToEventFields(t *testing.T) {
	r, _, err := NewResolver(nil, map[string]string{
		"process.exe":      "/usr/local/bin/xmrig",
		"network.dst_port": "3333",
	})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	if got := r.Resolve("process.exe", nil); len(got) != 1 || got[0] != "/usr/local/bin/xmrig" {
		t.Errorf("Resolve(process.exe) = %v, want [/usr/local/bin/xmrig]", got)
	}
	if got := r.Resolve("network.dst_port", nil); len(got) != 1 || got[0] != "3333" {
		t.Errorf("Resolve(network.dst_port) = %v, want [3333]", got)
	}
}

func TestResolver_MissingKeyReturnsNil(t *testing.T) {
	r, _, err := NewResolver(nil, map[string]string{"a": "1"})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	if got := r.Resolve("nope", nil); got != nil {
		t.Errorf("Resolve(missing) = %v, want nil", got)
	}
	if got := r.Resolve("k8s.absent", nil); got != nil {
		t.Errorf("Resolve(k8s.absent) = %v, want nil", got)
	}
}

func TestResolver_CaseFoldedLookup(t *testing.T) {
	r, _, err := NewResolver(nil, map[string]string{"Process.EXE": "binary"})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	for _, q := range []string{"process.exe", "PROCESS.EXE", "Process.Exe"} {
		if got := r.Resolve(q, nil); len(got) != 1 || got[0] != "binary" {
			t.Errorf("Resolve(%s) = %v, want [binary]", q, got)
		}
	}
}

func TestResolver_EventKeyCaseCollisionRejected(t *testing.T) {
	_, _, err := NewResolver(nil, map[string]string{"Image": "a", "image": "b"})
	if err == nil {
		t.Fatalf("expected error on case-colliding event keys, got nil")
	}
	if !strings.Contains(err.Error(), "collides on case") {
		t.Errorf("error = %q, want substring 'collides on case'", err.Error())
	}
}

func TestResolver_NilPostureSurfacesAllK8sLookupsAsNil(t *testing.T) {
	r, _, err := NewResolver(nil, nil)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	if got := r.Resolve("k8s.pod.namespace", nil); got != nil {
		t.Errorf("Resolve(k8s.pod.namespace) = %v on nil posture, want nil", got)
	}
}

func TestResolver_EntryFieldsMirrorPreservesOriginalCase(t *testing.T) {
	_, entry, err := NewResolver(nil, map[string]string{
		"Process.EXE":      "binary",
		"Network.dst_port": "3333",
	})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	if v, ok := entry.Fields["Process.EXE"]; !ok || v != "binary" {
		t.Errorf("entry.Fields[Process.EXE] = %q, ok=%v, want %q true", v, ok, "binary")
	}
	if v, ok := entry.Fields["Network.dst_port"]; !ok || v != "3333" {
		t.Errorf("entry.Fields[Network.dst_port] = %q, ok=%v, want %q true", v, ok, "3333")
	}
}

func TestPostureFields_ProjectsCanonicalKeys(t *testing.T) {
	p := &schema.WorkloadPosture{
		Identity: schema.WorkloadIdentity{
			Namespace: "ns",
			OwnerKind: "Deployment",
			OwnerName: "web",
			PodName:   "web-abc",
		},
		ServiceAccount: "default",
	}
	out := PostureFields(p)
	want := map[string]string{
		"k8s.pod.namespace":       "ns",
		"k8s.workload.owner_kind": "Deployment",
		"k8s.workload.owner_name": "web",
		"k8s.pod.name":            "web-abc",
		"k8s.pod.serviceaccount":  "default",
	}
	for k, v := range want {
		if got := out[k]; got != v {
			t.Errorf("PostureFields[%s] = %q, want %q", k, got, v)
		}
	}
}

func TestPostureFields_NilPostureEmptyMap(t *testing.T) {
	if got := PostureFields(nil); len(got) != 0 {
		t.Errorf("PostureFields(nil) = %v, want empty", got)
	}
}

func TestEventFields_FlattensRawJSON(t *testing.T) {
	ev := schema.Event{
		ID:       "evt-1",
		Source:   schema.SourceFalco,
		Category: schema.CategorySyscall,
		Raw:      []byte(`{"process.exe":"xmrig","network.dst_port":3333}`),
	}
	out := EventFields(ev)
	if out["process.exe"] != "xmrig" {
		t.Errorf("process.exe = %q, want xmrig", out["process.exe"])
	}
	if out["network.dst_port"] != "3333" {
		t.Errorf("network.dst_port = %q, want %q (int stringified)", out["network.dst_port"], "3333")
	}
	if out["event.source"] != string(schema.SourceFalco) {
		t.Errorf("event.source = %q, want %q", out["event.source"], string(schema.SourceFalco))
	}
}
