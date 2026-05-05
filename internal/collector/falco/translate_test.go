package falco

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/olokotoh/olaitan/internal/collector/falco/falcopb"
	"github.com/olokotoh/olaitan/internal/schema"
)

// fixedNow is a deterministic timestamp used across translate tests so the
// resulting Event.Timestamp comparisons are stable across CI runners.
var fixedNow = time.Date(2026, 5, 4, 14, 30, 0, 0, time.UTC)

// makeResponse builds a falcopb.Response with sensible defaults that
// individual tests override field-by-field.
func makeResponse(overrides func(*falcopb.Response)) *falcopb.Response {
	r := &falcopb.Response{
		Time:     timestamppb.New(fixedNow),
		Priority: falcopb.Priority_NOTICE,
		Rule:     "Terminal shell in container",
		Output:   "shell spawned in container (user=root container_id=abc123)",
		OutputFields: map[string]string{
			"k8s.pod.name":  "payments-7f8b9c-xyz",
			"k8s.ns.name":   "payments",
			"k8s.pod.uid":   "00000000-0000-0000-0000-000000000001",
			"proc.exe":      "/bin/bash",
			"proc.pid":      "12345",
			"evt.uuid":      "evt-12345-abcdef",
		},
		Hostname: "node-01",
		Tags:     []string{"shell", "terminal", "T1059"},
		Source:   "syscall",
	}
	if overrides != nil {
		overrides(r)
	}
	return r
}

func TestTranslate_HappyPath(t *testing.T) {
	r := makeResponse(nil)
	ev, err := Translate(r, "node-01")
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if ev.ID != "evt-12345-abcdef" {
		t.Errorf("ID: got %q, want %q (from output_fields[evt.uuid])", ev.ID, "evt-12345-abcdef")
	}
	if !ev.Timestamp.Equal(fixedNow) {
		t.Errorf("Timestamp: got %v, want %v", ev.Timestamp, fixedNow)
	}
	if ev.Source != schema.SourceFalco {
		t.Errorf("Source: got %q, want %q", ev.Source, schema.SourceFalco)
	}
	if ev.Category != schema.CategorySyscall {
		t.Errorf("Category: got %q, want %q", ev.Category, schema.CategorySyscall)
	}
	if ev.Pod.Name != "payments-7f8b9c-xyz" {
		t.Errorf("Pod.Name: got %q", ev.Pod.Name)
	}
	if ev.Pod.Namespace != "payments" {
		t.Errorf("Pod.Namespace: got %q", ev.Pod.Namespace)
	}
	if ev.Pod.UID != "00000000-0000-0000-0000-000000000001" {
		t.Errorf("Pod.UID: got %q", ev.Pod.UID)
	}
	if ev.Pod.Node != "node-01" {
		t.Errorf("Pod.Node: got %q, want node-01 (from caller-supplied hostname)", ev.Pod.Node)
	}
	if ev.Severity != "notice" {
		t.Errorf("Severity: got %q, want %q", ev.Severity, "notice")
	}
	if ev.Summary == "" {
		t.Error("Summary: empty")
	}
	// Tags are passed through verbatim.
	if len(ev.Tags) != 3 || ev.Tags[0] != "shell" {
		t.Errorf("Tags: got %v, want [shell terminal T1059]", ev.Tags)
	}
	// Raw must marshal as JSON and contain the rule + tags + output_fields.
	if len(ev.Raw) == 0 {
		t.Fatal("Raw: empty")
	}
	var raw map[string]any
	if err := json.Unmarshal(ev.Raw, &raw); err != nil {
		t.Fatalf("Raw: invalid JSON: %v", err)
	}
	if raw["rule"] != "Terminal shell in container" {
		t.Errorf("Raw.rule: got %v", raw["rule"])
	}
}

func TestTranslate_DeterministicIDFallback(t *testing.T) {
	// When evt.uuid is absent, the ID is computed deterministically from
	// stable fields (time, proc.pid, proc.exe, output). Translating the
	// same Response twice must yield the same ID.
	r := makeResponse(func(r *falcopb.Response) {
		delete(r.OutputFields, "evt.uuid")
	})

	ev1, err := Translate(r, "node-01")
	if err != nil {
		t.Fatal(err)
	}
	ev2, err := Translate(r, "node-01")
	if err != nil {
		t.Fatal(err)
	}
	if ev1.ID != ev2.ID {
		t.Errorf("Translate not deterministic: id1=%q id2=%q", ev1.ID, ev2.ID)
	}
	if ev1.ID == "" {
		t.Error("fallback ID empty")
	}
	// Fallback IDs are 32-hex-char (128-bit) SHA-256 prefixes; the
	// length was widened from 16 in the Story 1.6 review patch pass to
	// give collision-resistance well past the architecture's per-source
	// lifetime event budget.
	if len(ev1.ID) != 32 {
		t.Errorf("fallback ID length: got %d, want 32 (128-bit SHA-256 prefix)", len(ev1.ID))
	}
}

func TestTranslate_DifferentInputsYieldDifferentIDs(t *testing.T) {
	r1 := makeResponse(func(r *falcopb.Response) { delete(r.OutputFields, "evt.uuid") })
	r2 := makeResponse(func(r *falcopb.Response) {
		delete(r.OutputFields, "evt.uuid")
		r.Output = "different output"
	})
	ev1, _ := Translate(r1, "node-01")
	ev2, _ := Translate(r2, "node-01")
	if ev1.ID == ev2.ID {
		t.Errorf("expected different IDs, got %q for both", ev1.ID)
	}
}

func TestTranslate_HostEventWithoutPodFields(t *testing.T) {
	// Falco emits some events without Kubernetes context (e.g. host-mount
	// detections from the bare-metal runtime); the adapter must produce a
	// valid Event with PodRef zeroed for those.
	r := makeResponse(func(r *falcopb.Response) {
		delete(r.OutputFields, "k8s.pod.name")
		delete(r.OutputFields, "k8s.ns.name")
		delete(r.OutputFields, "k8s.pod.uid")
	})
	ev, err := Translate(r, "node-01")
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if ev.Pod.Name != "" || ev.Pod.Namespace != "" || ev.Pod.UID != "" {
		t.Errorf("Pod fields should be empty for host events: %+v", ev.Pod)
	}
	if ev.Pod.Node != "node-01" {
		t.Errorf("Pod.Node should still be the caller hostname, got %q", ev.Pod.Node)
	}
}

func TestTranslate_MissingTimeReturnsError(t *testing.T) {
	r := makeResponse(func(r *falcopb.Response) { r.Time = nil })
	_, err := Translate(r, "node-01")
	if err == nil {
		t.Fatal("expected error for missing Time, got nil")
	}
	if !strings.Contains(err.Error(), "falco:") {
		t.Errorf("error not prefixed falco:: %q", err.Error())
	}
}

func TestTranslate_RejectsPreEpochTimestamp(t *testing.T) {
	// Falco emitting Timestamp{Seconds:0} (Unix epoch) or any value
	// before 2010 indicates either an unset Time or severe clock skew;
	// either way the event would mis-bucket downstream so reject early.
	cases := []struct {
		name string
		t    time.Time
	}{
		{"unix-epoch", time.Unix(0, 0).UTC()},
		{"pre-epoch-1969", time.Date(1969, 12, 31, 23, 59, 59, 0, time.UTC)},
		{"pre-floor-2009", time.Date(2009, 6, 1, 0, 0, 0, 0, time.UTC)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := makeResponse(func(r *falcopb.Response) { r.Time = timestamppb.New(tc.t) })
			_, err := Translate(r, "node-01")
			if err == nil {
				t.Fatalf("Translate accepted pre-epoch timestamp %v", tc.t)
			}
			if !strings.Contains(err.Error(), "before") {
				t.Errorf("expected pre-epoch error to mention 'before', got %q", err.Error())
			}
		})
	}
}

func TestTranslate_RawHasFalcoHostnameAndDeterministicOutputFields(t *testing.T) {
	// The Raw payload must include falco_hostname (Falco's view of the
	// host, separate from the caller-supplied K8S_NODE_NAME) and must be
	// byte-identical across repeated translations of the same Response.
	r := makeResponse(func(r *falcopb.Response) {
		r.Hostname = "falco-view-of-node-01"
	})
	ev1, err := Translate(r, "node-01")
	if err != nil {
		t.Fatal(err)
	}
	ev2, err := Translate(r, "node-01")
	if err != nil {
		t.Fatal(err)
	}
	if string(ev1.Raw) != string(ev2.Raw) {
		t.Errorf("Raw payload not deterministic across translations:\nfirst:  %s\nsecond: %s",
			string(ev1.Raw), string(ev2.Raw))
	}
	if !strings.Contains(string(ev1.Raw), `"falco_hostname":"falco-view-of-node-01"`) {
		t.Errorf("Raw missing falco_hostname: %s", string(ev1.Raw))
	}
}

func TestTranslate_NilResponseReturnsError(t *testing.T) {
	_, err := Translate(nil, "node-01")
	if err == nil {
		t.Fatal("Translate(nil): expected error, got nil")
	}
}

func TestTranslate_EmptyOutputFields(t *testing.T) {
	// Some Falco rules emit responses with no output_fields. The adapter
	// must not panic; Raw must marshal to a JSON object (possibly empty)
	// rather than null so downstream consumers can rely on the contract.
	r := makeResponse(func(r *falcopb.Response) {
		r.OutputFields = nil
		// Without evt.uuid we'll hit the fallback ID path; that's fine.
	})
	ev, err := Translate(r, "node-01")
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if len(ev.Raw) == 0 {
		t.Fatal("Raw: empty")
	}
	if string(ev.Raw)[:1] != "{" {
		t.Errorf("Raw not a JSON object: %s", string(ev.Raw))
	}
}

func TestTranslate_PrioritySeverityMapping(t *testing.T) {
	cases := []struct {
		p    falcopb.Priority
		want string
	}{
		{falcopb.Priority_EMERGENCY, "emergency"},
		{falcopb.Priority_ALERT, "alert"},
		{falcopb.Priority_CRITICAL, "critical"},
		{falcopb.Priority_ERROR, "error"},
		{falcopb.Priority_WARNING, "warning"},
		{falcopb.Priority_NOTICE, "notice"},
		{falcopb.Priority_INFORMATIONAL, "informational"},
		{falcopb.Priority_DEBUG, "debug"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			r := makeResponse(func(r *falcopb.Response) { r.Priority = tc.p })
			ev, err := Translate(r, "node-01")
			if err != nil {
				t.Fatal(err)
			}
			if ev.Severity != tc.want {
				t.Errorf("Priority %v -> Severity %q, want %q", tc.p, ev.Severity, tc.want)
			}
		})
	}
}
