package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"

	"github.com/olokotoh/olaitan/internal/schema"
)

// fixedNow gives deterministic timestamps to assertions; well after
// minValidEventTime and well within maxFutureSkew of any plausible
// wall clock used by `go test`.
var fixedNow = time.Date(2026, time.May, 1, 12, 0, 0, 0, time.UTC)

const testNode = "node-test-01"

// validEvent returns a baseline ResponseComplete audit Event covering
// the happy-path field shape. Tests mutate fields on the returned
// pointer to drive specific edge cases.
func validEvent() *auditv1.Event {
	return &auditv1.Event{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Event",
			APIVersion: "audit.k8s.io/v1",
		},
		Level:      auditv1.LevelRequestResponse,
		AuditID:    types.UID("11111111-1111-4111-8111-111111111111"),
		Stage:      auditv1.StageResponseComplete,
		RequestURI: "/api/v1/namespaces/default/pods/nginx-abc",
		Verb:       "delete",
		User:       authnv1.UserInfo{Username: "alice"},
		SourceIPs:  []string{"10.0.0.5"},
		UserAgent:  "kubectl/1.29.0 (linux/amd64) kubernetes/abc1234",
		ObjectRef: &auditv1.ObjectReference{
			Resource:   "pods",
			Namespace:  "default",
			Name:       "nginx-abc",
			UID:        "22222222-2222-4222-8222-222222222222",
			APIVersion: "v1",
		},
		RequestReceivedTimestamp: metav1.NewMicroTime(fixedNow),
		StageTimestamp:           metav1.NewMicroTime(fixedNow.Add(50 * time.Millisecond)),
		Annotations: map[string]string{
			"authorization.k8s.io/decision": "allow",
		},
	}
}

func TestTranslate_HappyPath(t *testing.T) {
	t.Parallel()
	ev := validEvent()

	got, err := Translate(ev, testNode)
	if err != nil {
		t.Fatalf("happy-path translate returned error: %v", err)
	}
	if got.ID != string(ev.AuditID) {
		t.Errorf("ID: got %q, want %q", got.ID, ev.AuditID)
	}
	if got.Source != schema.SourceAudit {
		t.Errorf("Source: got %q, want %q", got.Source, schema.SourceAudit)
	}
	if got.Category != schema.CategoryAudit {
		t.Errorf("Category: got %q, want %q", got.Category, schema.CategoryAudit)
	}
	if !got.Timestamp.Equal(fixedNow) {
		t.Errorf("Timestamp: got %s, want %s", got.Timestamp, fixedNow)
	}
	if got.Pod.Name != "nginx-abc" || got.Pod.Namespace != "default" || got.Pod.Node != testNode {
		t.Errorf("Pod: got %+v, want Name=nginx-abc/Namespace=default/Node=%s", got.Pod, testNode)
	}
	if got.Pod.UID != "22222222-2222-4222-8222-222222222222" {
		t.Errorf("Pod.UID: got %q", got.Pod.UID)
	}
	wantSummary := "delete default/pods/nginx-abc by alice"
	if got.Summary != wantSummary {
		t.Errorf("Summary: got %q, want %q", got.Summary, wantSummary)
	}
	if got.Severity != "informational" {
		t.Errorf("Severity for plain pods/delete: got %q, want informational", got.Severity)
	}
	wantTags := []string{
		"verb:delete",
		"resource:pods",
		"stage:ResponseComplete",
		"decision:allow",
	}
	if !slicesEqualUnordered(got.Tags, wantTags) {
		t.Errorf("Tags: got %v, want (any order) %v", got.Tags, wantTags)
	}
}

func TestTranslate_RejectsZeroTimestamp(t *testing.T) {
	t.Parallel()
	ev := validEvent()
	ev.RequestReceivedTimestamp = metav1.MicroTime{}
	_, err := Translate(ev, testNode)
	if err == nil {
		t.Fatal("expected error for zero timestamp, got nil")
	}
	if !strings.Contains(err.Error(), "before") {
		t.Errorf("expected error mentioning 'before' floor, got %v", err)
	}
}

func TestTranslate_RejectsFutureTimestamp(t *testing.T) {
	t.Parallel()
	ev := validEvent()
	// 25h in the future is past maxFutureSkew (24h).
	ev.RequestReceivedTimestamp = metav1.NewMicroTime(time.Now().Add(25 * time.Hour))
	_, err := Translate(ev, testNode)
	if err == nil {
		t.Fatal("expected error for far-future timestamp, got nil")
	}
	if !strings.Contains(err.Error(), "future") {
		t.Errorf("expected error mentioning 'future', got %v", err)
	}
}

func TestTranslate_RejectsEmptyAuditID(t *testing.T) {
	t.Parallel()
	ev := validEvent()
	ev.AuditID = ""
	_, err := Translate(ev, testNode)
	if err == nil {
		t.Fatal("expected error for empty AuditID, got nil")
	}
	if !strings.Contains(err.Error(), "AuditID") {
		t.Errorf("expected error mentioning AuditID, got %v", err)
	}
}

func TestTranslate_NonResponseCompleteStage_ReturnsSentinel(t *testing.T) {
	t.Parallel()
	for _, stage := range []auditv1.Stage{
		auditv1.StageRequestReceived,
		auditv1.StageResponseStarted,
		auditv1.StagePanic,
	} {
		stage := stage
		t.Run(string(stage), func(t *testing.T) {
			t.Parallel()
			ev := validEvent()
			ev.Stage = stage
			_, err := Translate(ev, testNode)
			if !errors.Is(err, ErrSkipNonResponseComplete) {
				t.Errorf("stage %q: got err=%v, want ErrSkipNonResponseComplete", stage, err)
			}
		})
	}
}

func TestTranslate_PodResource_PopulatesPodRef(t *testing.T) {
	t.Parallel()
	ev := validEvent()
	got, err := Translate(ev, testNode)
	if err != nil {
		t.Fatalf("translate err: %v", err)
	}
	if got.Pod.Name != "nginx-abc" {
		t.Errorf("Pod.Name: got %q want nginx-abc", got.Pod.Name)
	}
	if got.Pod.UID != "22222222-2222-4222-8222-222222222222" {
		t.Errorf("Pod.UID: got %q", got.Pod.UID)
	}
}

func TestTranslate_NonPodResource_ZeroesPodNameUID(t *testing.T) {
	t.Parallel()
	ev := validEvent()
	ev.ObjectRef = &auditv1.ObjectReference{
		Resource:   "rolebindings",
		APIGroup:   "rbac.authorization.k8s.io",
		APIVersion: "v1",
		Namespace:  "kube-system",
		Name:       "system:viewer",
		UID:        "33333333-3333-4333-8333-333333333333",
	}
	got, err := Translate(ev, testNode)
	if err != nil {
		t.Fatalf("translate err: %v", err)
	}
	if got.Pod.Name != "" {
		t.Errorf("non-pod Pod.Name should be empty, got %q", got.Pod.Name)
	}
	if got.Pod.UID != "" {
		t.Errorf("non-pod Pod.UID should be empty, got %q", got.Pod.UID)
	}
	if got.Pod.Namespace != "kube-system" {
		t.Errorf("Pod.Namespace: got %q, want kube-system", got.Pod.Namespace)
	}
	if got.Severity != "warning" {
		t.Errorf("rolebindings/delete should bump severity to warning, got %q", got.Severity)
	}
}

func TestTranslate_ClusterScopedResource_ZeroesNamespace(t *testing.T) {
	t.Parallel()
	ev := validEvent()
	ev.ObjectRef = &auditv1.ObjectReference{
		Resource:   "clusterrolebindings",
		APIGroup:   "rbac.authorization.k8s.io",
		APIVersion: "v1",
		Name:       "cluster-admin",
	}
	got, err := Translate(ev, testNode)
	if err != nil {
		t.Fatalf("translate err: %v", err)
	}
	if got.Pod.Namespace != "" {
		t.Errorf("cluster-scoped Pod.Namespace should be empty, got %q", got.Pod.Namespace)
	}
	if got.Pod.Name != "" || got.Pod.UID != "" {
		t.Errorf("cluster-scoped Pod.Name/UID should be empty, got %+v", got.Pod)
	}
	if got.Pod.Node != testNode {
		t.Errorf("Pod.Node should always be set, got %q", got.Pod.Node)
	}
}

func TestTranslate_StripsLargeRequestObject(t *testing.T) {
	t.Parallel()
	ev := validEvent()
	// Build a 70 KiB body -- past the 64 KiB combined cap. Use valid
	// runtime.Unknown so json.Marshal doesn't fail.
	bigBytes := make([]byte, 70*1024)
	for i := range bigBytes {
		bigBytes[i] = 'x'
	}
	ev.RequestObject = &runtime.Unknown{
		TypeMeta: runtime.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		Raw:      bigBytes,
	}

	got, err := Translate(ev, testNode)
	if err != nil {
		t.Fatalf("translate err: %v", err)
	}
	if !bytes.Contains(got.Raw, []byte(`"_stripped":true`)) {
		t.Errorf("expected _stripped=true marker in Raw, got %s", string(got.Raw))
	}
	if !bytes.Contains(got.Raw, []byte(`"gvk":"v1,Secret"`)) {
		t.Errorf("expected GVK to survive strip, got %s", string(got.Raw))
	}
	// The 70 KiB body must NOT appear inline.
	if bytes.Contains(got.Raw, bigBytes[:1024]) {
		t.Errorf("oversize body should be stripped from Raw")
	}
}

func TestTranslate_DeterministicEventID(t *testing.T) {
	t.Parallel()
	ev := validEvent()
	ev.Annotations = map[string]string{
		"a-annot": "val-a",
		"z-annot": "val-z",
		"m-annot": "val-m",
	}
	a, err := Translate(ev, testNode)
	if err != nil {
		t.Fatalf("translate err: %v", err)
	}
	b, err := Translate(ev, testNode)
	if err != nil {
		t.Fatalf("translate err: %v", err)
	}
	if a.ID != b.ID {
		t.Errorf("Event.ID should be deterministic, got %q vs %q", a.ID, b.ID)
	}
	// Raw must also be byte-equal because annotations are sorted.
	if !bytes.Equal(a.Raw, b.Raw) {
		t.Errorf("Raw should be byte-equal for the same input, got\n%s\nvs\n%s", a.Raw, b.Raw)
	}
}

func TestTranslate_TagsCopied_NotAlias(t *testing.T) {
	t.Parallel()
	ev := validEvent()
	got, err := Translate(ev, testNode)
	if err != nil {
		t.Fatalf("translate err: %v", err)
	}
	// Mutate the source Annotations map; got.Tags must not change.
	original := append([]string(nil), got.Tags...)
	ev.Annotations["authorization.k8s.io/decision"] = "forbid"
	if !slicesEqual(got.Tags, original) {
		t.Errorf("Tags should not alias source memory; got %v, want %v after source mutation", got.Tags, original)
	}
}

func TestTranslate_ForbidDecisionTagged(t *testing.T) {
	t.Parallel()
	ev := validEvent()
	ev.Annotations = map[string]string{"authorization.k8s.io/decision": "forbid"}
	got, err := Translate(ev, testNode)
	if err != nil {
		t.Fatalf("translate err: %v", err)
	}
	if !sliceContains(got.Tags, "decision:forbid") {
		t.Errorf("expected decision:forbid tag, got %v", got.Tags)
	}
}

func TestTranslate_AnonymousUser(t *testing.T) {
	t.Parallel()
	ev := validEvent()
	ev.User = authnv1.UserInfo{}
	got, err := Translate(ev, testNode)
	if err != nil {
		t.Fatalf("translate err: %v", err)
	}
	if !strings.Contains(got.Summary, "<anonymous>") {
		t.Errorf("expected <anonymous> in summary, got %q", got.Summary)
	}
}

// TestTranslate_NilObjectRef covers non-resource API paths
// (/healthz, /version) where ObjectRef is nil.
func TestTranslate_NilObjectRef(t *testing.T) {
	t.Parallel()
	ev := validEvent()
	ev.ObjectRef = nil
	ev.RequestURI = "/healthz"
	ev.Verb = "get"
	got, err := Translate(ev, testNode)
	if err != nil {
		t.Fatalf("translate err: %v", err)
	}
	if !strings.Contains(got.Summary, "/healthz") {
		t.Errorf("expected RequestURI fallback, got summary %q", got.Summary)
	}
	if got.Pod.Namespace != "" || got.Pod.Name != "" {
		t.Errorf("nil ObjectRef should leave Pod ns/name empty, got %+v", got.Pod)
	}
}

func TestTranslate_NilEvent(t *testing.T) {
	t.Parallel()
	_, err := Translate(nil, testNode)
	if err == nil {
		t.Fatal("expected error for nil event")
	}
}

func TestTranslate_SecretsAccessIsWarning(t *testing.T) {
	t.Parallel()
	ev := validEvent()
	ev.Verb = "get"
	ev.ObjectRef = &auditv1.ObjectReference{
		Resource:   "secrets",
		Namespace:  "kube-system",
		Name:       "bootstrap-token",
		APIVersion: "v1",
	}
	got, err := Translate(ev, testNode)
	if err != nil {
		t.Fatalf("translate err: %v", err)
	}
	if got.Severity != "warning" {
		t.Errorf("secrets/get should be warning, got %q", got.Severity)
	}
}

func TestTranslate_PodsExecIsWarning(t *testing.T) {
	t.Parallel()
	ev := validEvent()
	ev.Verb = "create"
	ev.ObjectRef = &auditv1.ObjectReference{
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Name:        "shell-target",
		APIVersion:  "v1",
	}
	got, err := Translate(ev, testNode)
	if err != nil {
		t.Fatalf("translate err: %v", err)
	}
	if got.Severity != "warning" {
		t.Errorf("pods/exec should be warning, got %q", got.Severity)
	}
	if !sliceContains(got.Tags, "resource:pods/exec") {
		t.Errorf("expected resource:pods/exec tag, got %v", got.Tags)
	}
}

// TestTranslate_RawIsValidJSON sanity-checks that Raw round-trips
// through the JSON decoder. Story 1.6 patch precedent: an unparseable
// Raw blob silently corrupts downstream consumers.
func TestTranslate_RawIsValidJSON(t *testing.T) {
	t.Parallel()
	ev := validEvent()
	got, err := Translate(ev, testNode)
	if err != nil {
		t.Fatalf("translate err: %v", err)
	}
	var dst map[string]any
	if err := json.Unmarshal(got.Raw, &dst); err != nil {
		t.Fatalf("Raw is not valid JSON: %v\n%s", err, got.Raw)
	}
	if dst["auditID"] != string(ev.AuditID) {
		t.Errorf("Raw.auditID: got %v, want %s", dst["auditID"], ev.AuditID)
	}
}

// --- helpers (test-only) ---

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func slicesEqualUnordered(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		seen[s]--
		if seen[s] < 0 {
			return false
		}
	}
	return true
}

func sliceContains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
