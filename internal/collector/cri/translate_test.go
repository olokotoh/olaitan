package cri

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"

	"github.com/olokotoh/olaitan/internal/schema"
)

// fixedNow is the deterministic translate-time wall clock used by
// tests below. Pinning it keeps the CreatedAt-based timestamp
// assertions stable across CI runners.
var fixedNow = time.Date(2026, 5, 5, 14, 30, 0, 0, time.UTC)

// nowNanos returns fixedNow as a CRI-style nanosecond Unix epoch.
func nowNanos() int64 { return fixedNow.UnixNano() }

// makeEvent builds a CRI event with sensible defaults that individual
// tests override field-by-field. The default sandbox is in the READY
// state with attempt=0 so the happy-path tests do not pick up the
// sandbox:notready or attempt:N tags by accident.
func makeEvent(overrides func(*runtimeapi.ContainerEventResponse)) *runtimeapi.ContainerEventResponse {
	ev := &runtimeapi.ContainerEventResponse{
		ContainerId:        "abc123def4567890aabbccddeeff0011",
		ContainerEventType: runtimeapi.ContainerEventType_CONTAINER_STARTED_EVENT,
		CreatedAt:          nowNanos(),
		PodSandboxStatus: &runtimeapi.PodSandboxStatus{
			Id:        "sandbox-id-001",
			State:     runtimeapi.PodSandboxState_SANDBOX_READY,
			CreatedAt: nowNanos() - int64(time.Second),
			Metadata: &runtimeapi.PodSandboxMetadata{
				Name:      "payments-7f8b9c-xyz",
				Namespace: "payments",
				Uid:       "00000000-0000-0000-0000-000000000001",
				Attempt:   0,
			},
			Labels: map[string]string{
				"app.kubernetes.io/name":    "payments",
				"app.kubernetes.io/version": "1.2.3",
				"my-private-label":          "should-not-leak",
			},
		},
		ContainersStatuses: []*runtimeapi.ContainerStatus{
			{
				Id:        "abc123def4567890aabbccddeeff0011",
				State:     runtimeapi.ContainerState_CONTAINER_RUNNING,
				CreatedAt: nowNanos() - int64(time.Second),
				StartedAt: nowNanos(),
				ImageRef:  "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
			},
		},
	}
	if overrides != nil {
		overrides(ev)
	}
	return ev
}

func TestTranslate_HappyPath_Started(t *testing.T) {
	ev := makeEvent(nil)
	got, err := Translate(ev, "node-01")
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if got.Source != schema.SourceRuntime {
		t.Errorf("Source: got %q, want %q (binding interpretation: AC1 'source containerd' maps to SourceRuntime)",
			got.Source, schema.SourceRuntime)
	}
	if got.Category != schema.CategoryLifecycle {
		t.Errorf("Category: got %q, want %q", got.Category, schema.CategoryLifecycle)
	}
	if got.Pod.Name != "payments-7f8b9c-xyz" {
		t.Errorf("Pod.Name: got %q", got.Pod.Name)
	}
	if got.Pod.Namespace != "payments" {
		t.Errorf("Pod.Namespace: got %q", got.Pod.Namespace)
	}
	if got.Pod.UID != "00000000-0000-0000-0000-000000000001" {
		t.Errorf("Pod.UID: got %q", got.Pod.UID)
	}
	if got.Pod.Node != "node-01" {
		t.Errorf("Pod.Node: got %q, want node-01", got.Pod.Node)
	}
	if got.Severity != "informational" {
		t.Errorf("Severity: got %q, want informational", got.Severity)
	}
	if !got.Timestamp.Equal(fixedNow) {
		t.Errorf("Timestamp: got %v, want %v", got.Timestamp, fixedNow)
	}
	if !strings.Contains(got.Summary, "STARTED") {
		t.Errorf("Summary: %q does not contain event-type marker", got.Summary)
	}
	if !strings.Contains(got.Summary, "abc123def456") {
		t.Errorf("Summary: %q does not contain 12-char short container id", got.Summary)
	}
	if got.ID == "" || len(got.ID) != 32 {
		t.Errorf("ID: got %q (len=%d), want 32 hex chars", got.ID, len(got.ID))
	}
}

func TestTranslate_HappyPath_Created(t *testing.T) {
	ev := makeEvent(func(e *runtimeapi.ContainerEventResponse) {
		e.ContainerEventType = runtimeapi.ContainerEventType_CONTAINER_CREATED_EVENT
	})
	got, err := Translate(ev, "node-01")
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if !containsTag(got.Tags, "event_type:created") {
		t.Errorf("Tags: missing event_type:created (got %v)", got.Tags)
	}
}

func TestTranslate_HappyPath_Stopped(t *testing.T) {
	ev := makeEvent(func(e *runtimeapi.ContainerEventResponse) {
		e.ContainerEventType = runtimeapi.ContainerEventType_CONTAINER_STOPPED_EVENT
	})
	got, err := Translate(ev, "node-01")
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if !containsTag(got.Tags, "event_type:stopped") {
		t.Errorf("Tags: missing event_type:stopped (got %v)", got.Tags)
	}
}

func TestTranslate_HappyPath_Deleted(t *testing.T) {
	ev := makeEvent(func(e *runtimeapi.ContainerEventResponse) {
		e.ContainerEventType = runtimeapi.ContainerEventType_CONTAINER_DELETED_EVENT
	})
	got, err := Translate(ev, "node-01")
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if !containsTag(got.Tags, "event_type:deleted") {
		t.Errorf("Tags: missing event_type:deleted (got %v)", got.Tags)
	}
}

func TestTranslate_RejectsNilEvent(t *testing.T) {
	if _, err := Translate(nil, "node-01"); err == nil {
		t.Fatal("Translate(nil): expected error, got nil")
	}
}

func TestTranslate_RejectsZeroTimestamp(t *testing.T) {
	ev := makeEvent(func(e *runtimeapi.ContainerEventResponse) { e.CreatedAt = 0 })
	_, err := Translate(ev, "node-01")
	if !errors.Is(err, ErrInvalidTimestamp) {
		t.Fatalf("Translate: got %v, want ErrInvalidTimestamp", err)
	}
}

func TestTranslate_RejectsNegativeTimestamp(t *testing.T) {
	ev := makeEvent(func(e *runtimeapi.ContainerEventResponse) { e.CreatedAt = -1 })
	_, err := Translate(ev, "node-01")
	if !errors.Is(err, ErrInvalidTimestamp) {
		t.Fatalf("Translate: got %v, want ErrInvalidTimestamp", err)
	}
}

func TestTranslate_RejectsPreEpochTimestamp(t *testing.T) {
	// year 1990 in nanos: well before minValidEventTime (2010).
	ev := makeEvent(func(e *runtimeapi.ContainerEventResponse) {
		e.CreatedAt = time.Date(1990, time.January, 1, 0, 0, 0, 0, time.UTC).UnixNano()
	})
	_, err := Translate(ev, "node-01")
	if !errors.Is(err, ErrInvalidTimestamp) {
		t.Fatalf("Translate: got %v, want ErrInvalidTimestamp", err)
	}
}

func TestTranslate_RejectsFutureTimestamp(t *testing.T) {
	ev := makeEvent(func(e *runtimeapi.ContainerEventResponse) {
		e.CreatedAt = time.Now().Add(48 * time.Hour).UnixNano()
	})
	_, err := Translate(ev, "node-01")
	if !errors.Is(err, ErrInvalidTimestamp) {
		t.Fatalf("Translate: got %v, want ErrInvalidTimestamp", err)
	}
}

func TestTranslate_RejectsEmptyContainerID(t *testing.T) {
	ev := makeEvent(func(e *runtimeapi.ContainerEventResponse) { e.ContainerId = "" })
	_, err := Translate(ev, "node-01")
	if !errors.Is(err, ErrInvalidContainerID) {
		t.Fatalf("Translate: got %v, want ErrInvalidContainerID", err)
	}
}

func TestTranslate_RejectsUnknownEventType(t *testing.T) {
	ev := makeEvent(func(e *runtimeapi.ContainerEventResponse) {
		e.ContainerEventType = runtimeapi.ContainerEventType(99)
	})
	_, err := Translate(ev, "node-01")
	if !errors.Is(err, ErrUnknownEventType) {
		t.Fatalf("Translate: got %v, want ErrUnknownEventType", err)
	}
}

func TestTranslate_NilSandboxStatus_GracefulDegradation(t *testing.T) {
	ev := makeEvent(func(e *runtimeapi.ContainerEventResponse) { e.PodSandboxStatus = nil })
	got, err := Translate(ev, "node-01")
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if got.Pod.Name != "" || got.Pod.Namespace != "" || got.Pod.UID != "" {
		t.Errorf("Pod: got %+v, want empty Name/Namespace/UID", got.Pod)
	}
	if got.Pod.Node != "node-01" {
		t.Errorf("Pod.Node: got %q, want node-01 (always populated)", got.Pod.Node)
	}
}

func TestTranslate_NilMetadata_GracefulDegradation(t *testing.T) {
	ev := makeEvent(func(e *runtimeapi.ContainerEventResponse) { e.PodSandboxStatus.Metadata = nil })
	got, err := Translate(ev, "node-01")
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if got.Pod.Name != "" || got.Pod.Namespace != "" || got.Pod.UID != "" {
		t.Errorf("Pod: got %+v, want empty Name/Namespace/UID", got.Pod)
	}
}

func TestTranslate_DeterministicEventID(t *testing.T) {
	ev1 := makeEvent(nil)
	ev2 := makeEvent(nil)
	a, err := Translate(ev1, "node-01")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Translate(ev2, "node-01")
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != b.ID {
		t.Errorf("ID determinism: got %q vs %q", a.ID, b.ID)
	}
}

func TestTranslate_DeterministicEventID_SurvivesStrip(t *testing.T) {
	// Build a small event and a large event with the same identity
	// tuple; the stable ID is derived from container_id, event_type,
	// and created_at, so the strip path must NOT change ev.ID.
	small := makeEvent(nil)
	large := makeEvent(func(e *runtimeapi.ContainerEventResponse) {
		// Inflate the labels map to exceed the 32 KiB raw budget.
		bigVal := strings.Repeat("X", 1024)
		for i := 0; i < 64; i++ {
			e.PodSandboxStatus.Labels["app.kubernetes.io/big-"+strings.Repeat("z", i+1)] = bigVal
		}
	})
	a, err := Translate(small, "node-01")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Translate(large, "node-01")
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != b.ID {
		t.Errorf("ID: got %q vs %q (strip decision must not change ID)", a.ID, b.ID)
	}
	// Sanity-check that the large event actually triggered the strip
	// path by inspecting the raw payload.
	var raw map[string]any
	if err := json.Unmarshal(b.Raw, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	if raw["_stripped"] != true {
		t.Errorf("expected strip flag to be set on large event; raw=%+v", raw["_stripped"])
	}
}

func TestTranslate_ShortContainerID_NoPanic(t *testing.T) {
	ev := makeEvent(func(e *runtimeapi.ContainerEventResponse) { e.ContainerId = "ab" })
	got, err := Translate(ev, "node-01")
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if !strings.Contains(got.Summary, "container=ab") {
		t.Errorf("Summary: %q does not contain short container id without truncation", got.Summary)
	}
}

func TestTranslate_StripsLargeRawPayload(t *testing.T) {
	ev := makeEvent(func(e *runtimeapi.ContainerEventResponse) {
		// Inflate the containers_statuses with a huge image-ref blob.
		bigImage := "sha256:" + strings.Repeat("a", 50_000)
		e.ContainersStatuses = []*runtimeapi.ContainerStatus{
			{Id: e.ContainerId, ImageRef: bigImage, Message: "boom"},
		}
	})
	got, err := Translate(ev, "node-01")
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if len(got.Raw) > rawSizeBudget {
		t.Errorf("Raw size: got %d bytes, want <= %d", len(got.Raw), rawSizeBudget)
	}
	// The strip should have dropped the inflated image ref.
	var raw map[string]any
	if err := json.Unmarshal(got.Raw, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	if raw["_stripped"] != true {
		t.Errorf("_stripped flag missing on over-budget event; raw=%v", raw)
	}
	statuses, ok := raw["container_statuses"].([]any)
	if !ok || len(statuses) != 1 {
		t.Fatalf("container_statuses: got %T %v", raw["container_statuses"], raw["container_statuses"])
	}
	first := statuses[0].(map[string]any)
	if img, exists := first["image"]; exists && img.(string) != "" {
		t.Errorf("image field: got %q, want empty after strip", img)
	}
}

func TestTranslate_AttemptZero_NoTag(t *testing.T) {
	ev := makeEvent(nil)
	got, err := Translate(ev, "node-01")
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range got.Tags {
		if strings.HasPrefix(tag, "attempt:") {
			t.Errorf("Tags: unexpected attempt tag for Attempt==0 (got %q)", tag)
		}
	}
}

func TestTranslate_AttemptNonZero_TaggedRestart(t *testing.T) {
	ev := makeEvent(func(e *runtimeapi.ContainerEventResponse) {
		e.PodSandboxStatus.Metadata.Attempt = 3
	})
	got, err := Translate(ev, "node-01")
	if err != nil {
		t.Fatal(err)
	}
	if !containsTag(got.Tags, "attempt:3") {
		t.Errorf("Tags: missing attempt:3 (got %v)", got.Tags)
	}
}

func TestTranslate_SandboxNotReady_TagApplied(t *testing.T) {
	ev := makeEvent(func(e *runtimeapi.ContainerEventResponse) {
		e.PodSandboxStatus.State = runtimeapi.PodSandboxState_SANDBOX_NOTREADY
	})
	got, err := Translate(ev, "node-01")
	if err != nil {
		t.Fatal(err)
	}
	if !containsTag(got.Tags, "sandbox:notready") {
		t.Errorf("Tags: missing sandbox:notready (got %v)", got.Tags)
	}
}

func TestTranslate_LabelsCopied_NotAlias(t *testing.T) {
	ev := makeEvent(nil)
	got, err := Translate(ev, "node-01")
	if err != nil {
		t.Fatal(err)
	}
	// Mutate the source label map; the published tags must not change.
	ev.PodSandboxStatus.Labels["app.kubernetes.io/name"] = "MUTATED"
	for _, tag := range got.Tags {
		if tag == "app.kubernetes.io/name:MUTATED" {
			t.Errorf("Tags aliased the proto labels map; got %q", tag)
		}
	}
}

func TestTranslate_NonAllowlistedLabelsDropped(t *testing.T) {
	ev := makeEvent(nil)
	got, err := Translate(ev, "node-01")
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range got.Tags {
		if strings.HasPrefix(tag, "my-private-label") {
			t.Errorf("Tags: leaked non-whitelisted label %q", tag)
		}
	}
}

func TestTranslate_AllowlistedLabelsForwarded(t *testing.T) {
	ev := makeEvent(nil)
	got, err := Translate(ev, "node-01")
	if err != nil {
		t.Fatal(err)
	}
	if !containsTag(got.Tags, "app.kubernetes.io/name:payments") {
		t.Errorf("Tags: missing app.kubernetes.io/name (got %v)", got.Tags)
	}
	if !containsTag(got.Tags, "app.kubernetes.io/version:1.2.3") {
		t.Errorf("Tags: missing app.kubernetes.io/version (got %v)", got.Tags)
	}
}

func TestTranslate_RawIsValidJSON(t *testing.T) {
	ev := makeEvent(nil)
	got, err := Translate(ev, "node-01")
	if err != nil {
		t.Fatal(err)
	}
	var any map[string]any
	if err := json.Unmarshal(got.Raw, &any); err != nil {
		t.Fatalf("Raw is not valid JSON: %v\nraw=%s", err, string(got.Raw))
	}
	if any["container_id"] != ev.ContainerId {
		t.Errorf("Raw.container_id: got %v, want %s", any["container_id"], ev.ContainerId)
	}
}

func TestTranslate_DifferentEventsYieldDifferentIDs(t *testing.T) {
	a, err := Translate(makeEvent(nil), "node-01")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Translate(makeEvent(func(e *runtimeapi.ContainerEventResponse) {
		e.ContainerEventType = runtimeapi.ContainerEventType_CONTAINER_STOPPED_EVENT
	}), "node-01")
	if err != nil {
		t.Fatal(err)
	}
	if a.ID == b.ID {
		t.Errorf("IDs collided: started and stopped events share %q", a.ID)
	}
}

// containsTag is a small assertion helper.
func containsTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}

// TestTranslate_StripPathTruncatesLongMessage verifies the P5 fix:
// when the un-stripped marshal exceeds rawSizeBudget, the strip path
// caps each ContainersStatuses[i].Message at maxStrippedMessageLen.
// Pre-P5 a 4 KiB Message survived the strip pass and could push the
// post-strip body past rawSizeBudget, tripping a permanent oversize
// publish error with no second strip pass.
func TestTranslate_StripPathTruncatesLongMessage(t *testing.T) {
	longMsg := strings.Repeat("E", 4*1024)
	bigImage := strings.Repeat("a", 8*1024)
	ev := makeEvent(func(e *runtimeapi.ContainerEventResponse) {
		e.ContainersStatuses = []*runtimeapi.ContainerStatus{}
		for i := 0; i < 4; i++ {
			e.ContainersStatuses = append(e.ContainersStatuses,
				&runtimeapi.ContainerStatus{
					Id:       "container-" + string(rune('a'+i)),
					ImageRef: bigImage,
					Message:  longMsg,
				},
			)
		}
	})
	got, err := Translate(ev, "node-01")
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	// The Raw must be marked _stripped, and every container message
	// inside it must be at most maxStrippedMessageLen.
	if !strings.Contains(string(got.Raw), `"_stripped":true`) {
		t.Errorf("expected _stripped:true in Raw; got: %s", string(got.Raw))
	}
	var canon rawCanonical
	if err := json.Unmarshal(got.Raw, &canon); err != nil {
		t.Fatalf("unmarshal Raw: %v", err)
	}
	for i, cs := range canon.ContainerStatuses {
		if len(cs.Message) > maxStrippedMessageLen {
			t.Errorf("ContainerStatuses[%d].Message len = %d, want <= %d (P5 truncation)",
				i, len(cs.Message), maxStrippedMessageLen)
		}
	}
}

// TestTranslate_SanitizesLabelControlChars verifies the P17 fix: a
// label value containing newlines or NUL bytes must be stripped
// before it reaches the published Tags. Pre-P17 the value passed
// through verbatim and could derail downstream tag-string parsers.
func TestTranslate_SanitizesLabelControlChars(t *testing.T) {
	ev := makeEvent(func(e *runtimeapi.ContainerEventResponse) {
		e.PodSandboxStatus.Labels["app.kubernetes.io/component"] = "evil\nhello\x00world\rmore"
	})
	got, err := Translate(ev, "node-01")
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	for _, tag := range got.Tags {
		if strings.ContainsAny(tag, "\n\r\x00") {
			t.Errorf("tag %q still carries control characters after P17 sanitization", tag)
		}
	}
}

// TestTranslate_SanitizesLabelLengthCap verifies the P17 length cap:
// label values larger than maxSanitizedTagLen (256) are truncated.
func TestTranslate_SanitizesLabelLengthCap(t *testing.T) {
	ev := makeEvent(func(e *runtimeapi.ContainerEventResponse) {
		e.PodSandboxStatus.Labels["app.kubernetes.io/component"] = strings.Repeat("Z", 4*1024)
	})
	got, err := Translate(ev, "node-01")
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	var found bool
	for _, tag := range got.Tags {
		if strings.HasPrefix(tag, "app.kubernetes.io/component:") {
			value := strings.TrimPrefix(tag, "app.kubernetes.io/component:")
			if len(value) > maxSanitizedTagLen {
				t.Errorf("label value len = %d, want <= %d (P17 cap)", len(value), maxSanitizedTagLen)
			}
			found = true
		}
	}
	if !found {
		t.Error("expected app.kubernetes.io/component tag, got none")
	}
}

// TestTranslate_SanitizesSummaryControlChars verifies the P18 fix:
// pod name / namespace control characters must not leak into the
// rendered Summary line. Pre-P18 a malicious pod name carrying \n
// could split a structured log line into two records.
func TestTranslate_SanitizesSummaryControlChars(t *testing.T) {
	ev := makeEvent(func(e *runtimeapi.ContainerEventResponse) {
		e.PodSandboxStatus.Metadata.Name = "evil\npayments"
		e.PodSandboxStatus.Metadata.Namespace = "tenant\x00alpha"
	})
	got, err := Translate(ev, "node-01")
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if strings.ContainsAny(got.Summary, "\n\r\x00") {
		t.Errorf("Summary still carries control characters after P18 sanitization: %q", got.Summary)
	}
}
