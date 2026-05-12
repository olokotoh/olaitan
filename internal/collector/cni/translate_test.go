package cni

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/olokotoh/olaitan/internal/collector/cni/goldmanepb"
	"github.com/olokotoh/olaitan/internal/schema"
)

// validFixture returns a freshly-constructed valid FlowResult with
// realistic field values. Each test mutates the fixture and asserts
// the targeted edge case in isolation; sharing one builder keeps the
// happy-path expectation maintainable across cases.
func validFixture() *goldmanepb.FlowResult {
	return &goldmanepb.FlowResult{
		Id: 42,
		Flow: &goldmanepb.Flow{
			StartTime:             time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC).Unix(),
			EndTime:               time.Date(2026, 5, 12, 10, 0, 15, 0, time.UTC).Unix(),
			PacketsIn:             12,
			PacketsOut:            9,
			BytesIn:               1024,
			BytesOut:              768,
			NumConnectionsStarted: 3,
			Key: &goldmanepb.FlowKey{
				SourceNamespace:      "spike-traffic",
				SourceName:           "curl-loop-",
				SourceType:           goldmanepb.EndpointType_WorkloadEndpoint,
				DestNamespace:        "spike-traffic",
				DestName:             "nginx-",
				DestType:             goldmanepb.EndpointType_WorkloadEndpoint,
				DestServiceNamespace: "spike-traffic",
				DestServiceName:      "web",
				DestPort:             80,
				Proto:                "tcp",
				Action:               goldmanepb.Action_Allow,
				Reporter:             goldmanepb.Reporter_Src,
			},
		},
	}
}

func TestTranslate_HappyPath(t *testing.T) {
	fr := validFixture()
	ev, err := Translate(fr, "", 0)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}

	if ev.ID != "calico-flow-1778580000-42" {
		t.Errorf("ID: got %q, want calico-flow-<start>-42", ev.ID)
	}
	if ev.Source != schema.SourceNetwork {
		t.Errorf("Source: got %q, want %q", ev.Source, schema.SourceNetwork)
	}
	if ev.Category != schema.CategoryFlow {
		t.Errorf("Category: got %q, want %q", ev.Category, schema.CategoryFlow)
	}
	if ev.Severity != "informational" {
		t.Errorf("Severity: got %q, want informational", ev.Severity)
	}
	if ev.Pod.Namespace != "spike-traffic" || ev.Pod.Name != "curl-loop-" {
		t.Errorf("Pod: got %+v, want spike-traffic/curl-loop-", ev.Pod)
	}
	if !strings.Contains(ev.Summary, "spike-traffic/curl-loop- -> spike-traffic/nginx-:80") {
		t.Errorf("Summary missing expected hop info: %q", ev.Summary)
	}
	if !strings.Contains(ev.Summary, "allow") || !strings.Contains(ev.Summary, "src") {
		t.Errorf("Summary missing action/reporter: %q", ev.Summary)
	}

	wantTags := map[string]bool{
		"proto:tcp":                  false,
		"action:allow":               false,
		"reporter:src":               false,
		"src-type:workload":          false,
		"dst-type:workload":          false,
		"dst-port:80":                false,
		"svc:spike-traffic/web":      false,
		"conns-started:3":            false,
		"pod_name_kind:generatename": false,
	}
	for _, tg := range ev.Tags {
		if _, ok := wantTags[tg]; ok {
			wantTags[tg] = true
		}
	}
	for k, v := range wantTags {
		if !v {
			t.Errorf("Tags missing %q (have %v)", k, ev.Tags)
		}
	}
}

func TestTranslate_NilCases(t *testing.T) {
	cases := []struct {
		name string
		fr   *goldmanepb.FlowResult
	}{
		{"nil FlowResult", nil},
		{"nil Flow", &goldmanepb.FlowResult{Id: 1}},
		{"nil FlowKey", &goldmanepb.FlowResult{Id: 1, Flow: &goldmanepb.Flow{StartTime: time.Now().Unix()}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Translate(tc.fr, "", 0)
			if !errors.Is(err, ErrNilFlowResult) {
				t.Errorf("got %v, want errors.Is(_, ErrNilFlowResult)", err)
			}
		})
	}
}

func TestTranslate_ZeroTimestamp_Rejected(t *testing.T) {
	fr := validFixture()
	fr.Flow.StartTime = 0
	_, err := Translate(fr, "", 0)
	if !errors.Is(err, ErrInvalidTimestamp) {
		t.Fatalf("got %v, want errors.Is(_, ErrInvalidTimestamp)", err)
	}
}

func TestTranslate_PreEpochTimestamp_Rejected(t *testing.T) {
	fr := validFixture()
	fr.Flow.StartTime = time.Date(2009, 12, 31, 23, 59, 59, 0, time.UTC).Unix()
	_, err := Translate(fr, "", 0)
	if !errors.Is(err, ErrInvalidTimestamp) {
		t.Fatalf("got %v, want errors.Is(_, ErrInvalidTimestamp)", err)
	}
}

func TestTranslate_FarFutureTimestamp_Rejected(t *testing.T) {
	// Pin nowFunc so the case is deterministic regardless of host clock.
	prev := nowFunc
	defer func() { nowFunc = prev }()
	nowFunc = func() time.Time { return time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC) }

	fr := validFixture()
	fr.Flow.StartTime = time.Date(2026, 5, 14, 0, 0, 0, 0, time.UTC).Unix() // 48h in the future
	_, err := Translate(fr, "", 0)
	if !errors.Is(err, ErrInvalidTimestamp) {
		t.Fatalf("got %v, want errors.Is(_, ErrInvalidTimestamp)", err)
	}
}

func TestTranslate_ProtoUnknown_DefaultsToUnknown(t *testing.T) {
	fr := validFixture()
	fr.Flow.Key.Proto = ""
	ev, err := Translate(fr, "", 0)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if !containsTag(ev.Tags, "proto:unknown") {
		t.Errorf("missing proto:unknown tag (have %v)", ev.Tags)
	}
}

func TestTranslate_ActionUnspecified_StillTranslates(t *testing.T) {
	fr := validFixture()
	fr.Flow.Key.Action = goldmanepb.Action_ActionUnspecified
	ev, err := Translate(fr, "", 0)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if !containsTag(ev.Tags, "action:unspecified") {
		t.Errorf("missing action:unspecified tag (have %v)", ev.Tags)
	}
}

func TestTranslate_DestPortZero_RetainsFlow(t *testing.T) {
	fr := validFixture()
	fr.Flow.Key.DestPort = 0
	fr.Flow.Key.Proto = "icmp"
	ev, err := Translate(fr, "", 0)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if !containsTag(ev.Tags, "dst-port:0") {
		t.Errorf("missing dst-port:0 tag (have %v)", ev.Tags)
	}
}

func TestTranslate_DestPortOutOfUint16Range_TagsAsInvalid(t *testing.T) {
	fr := validFixture()
	fr.Flow.Key.DestPort = 1 << 17
	ev, err := Translate(fr, "", 0)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if !containsTag(ev.Tags, "dst-port:invalid") {
		t.Errorf("missing dst-port:invalid tag (have %v)", ev.Tags)
	}
}

func TestTranslate_EmptySourceAndNamespace_TagsUnknownSource(t *testing.T) {
	fr := validFixture()
	fr.Flow.Key.SourceName = ""
	fr.Flow.Key.SourceNamespace = ""
	fr.Flow.Key.SourceType = goldmanepb.EndpointType_Network
	ev, err := Translate(fr, "", 0)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if ev.Pod.Name != "" || ev.Pod.Namespace != "" {
		t.Errorf("Pod: got %+v, want zero PodRef", ev.Pod)
	}
	if !containsTag(ev.Tags, "unknown_source:true") {
		t.Errorf("missing unknown_source:true tag (have %v)", ev.Tags)
	}
}

func TestTranslate_DeterministicEventID(t *testing.T) {
	fr := validFixture()
	a, err := Translate(fr, "", 0)
	if err != nil {
		t.Fatalf("Translate a: %v", err)
	}
	b, err := Translate(fr, "", 0)
	if err != nil {
		t.Fatalf("Translate b: %v", err)
	}
	if a.ID != b.ID {
		t.Errorf("non-deterministic ID: %q vs %q", a.ID, b.ID)
	}
}

func TestTranslate_OversizeRaw_RejectedAsErrEventTooLarge(t *testing.T) {
	fr := validFixture()
	// Pad SourceName with a long string so the marshalled event blows
	// past a tiny cap. SanitizeForTag caps individual tags but not the
	// PodRef.Name on the Event itself; this is what trips the size
	// guard.
	fr.Flow.Key.SourceName = strings.Repeat("x", 4000)
	_, err := Translate(fr, "", 1024)
	if !errors.Is(err, ErrEventTooLarge) {
		t.Errorf("got %v, want errors.Is(_, ErrEventTooLarge)", err)
	}
}

func TestTranslate_RoundTripJSON_SemanticallyStable(t *testing.T) {
	fr := validFixture()
	ev, err := Translate(fr, "", 0)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	// marshal -> unmarshal -> re-marshal. Byte-equality fails because
	// Go marshals struct fields in declaration order while a decoded
	// map re-marshals alphabetically; the two encodings carry the
	// same information.
	first, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("first marshal: %v", err)
	}
	var a any
	if err := json.Unmarshal(first, &a); err != nil {
		t.Fatalf("unmarshal first: %v", err)
	}
	second, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	var b any
	if err := json.Unmarshal(second, &b); err != nil {
		t.Fatalf("unmarshal second: %v", err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Errorf("round-trip semantic mismatch:\n  first:  %s\n  second: %s", first, second)
	}
}

func TestTranslate_RawIsValidJSON(t *testing.T) {
	fr := validFixture()
	ev, err := Translate(fr, "", 0)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(ev.Raw, &obj); err != nil {
		t.Errorf("Raw is not valid JSON: %v", err)
	}
}

func TestTranslate_NoSvcTagWhenServiceEmpty(t *testing.T) {
	fr := validFixture()
	fr.Flow.Key.DestServiceName = ""
	fr.Flow.Key.DestServiceNamespace = ""
	ev, err := Translate(fr, "", 0)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	for _, tg := range ev.Tags {
		if strings.HasPrefix(tg, "svc:") {
			t.Errorf("unexpected svc tag with empty service: %q", tg)
		}
	}
}

func TestTranslate_NoConnsStartedTagWhenZero(t *testing.T) {
	fr := validFixture()
	fr.Flow.NumConnectionsStarted = 0
	ev, err := Translate(fr, "", 0)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	for _, tg := range ev.Tags {
		if strings.HasPrefix(tg, "conns-started:") {
			t.Errorf("unexpected conns-started tag with zero value: %q", tg)
		}
	}
}

func TestSanitizeForTag_StripsControlChars(t *testing.T) {
	in := "abc\x00def\nghi"
	out := sanitizeForTag(in)
	if out != "abcdefghi" {
		t.Errorf("got %q, want %q", out, "abcdefghi")
	}
}

func TestSanitizeForTag_PreservesTab(t *testing.T) {
	in := "abc\tdef"
	out := sanitizeForTag(in)
	if out != "abc\tdef" {
		t.Errorf("got %q, want %q", out, "abc\tdef")
	}
}

func TestSanitizeForTag_Caps256Bytes(t *testing.T) {
	in := strings.Repeat("a", 300)
	out := sanitizeForTag(in)
	if len(out) != 256 {
		t.Errorf("len: got %d, want 256", len(out))
	}
}

// TestSanitizeForTag_UTF8RuneBoundary_TruncatesCleanly locks in
// the P13 fix: truncation must walk back to the preceding rune
// boundary so a multi-byte UTF-8 sequence is never split. The
// test pads the input with 3-byte runes (中 "中") so the 256
// byte cap falls in the middle of a rune sequence.
func TestSanitizeForTag_UTF8RuneBoundary_TruncatesCleanly(t *testing.T) {
	// 256/3 = 85 full runes (255 bytes); the 86th rune's first
	// byte would land at index 255, mid-rune. The truncator must
	// walk back to 255 and stop.
	in := strings.Repeat("中", 100) // 300 bytes of UTF-8
	out := sanitizeForTag(in)
	if !utf8.ValidString(out) {
		t.Errorf("truncated output is not valid UTF-8: %q (len=%d)", out, len(out))
	}
	if len(out) > maxSanitizedTagLen {
		t.Errorf("truncated output exceeds cap: len=%d", len(out))
	}
}

// TestValidateTimestamp_EndTimeBeforeStartTime_TagAnomaly locks in
// the P9 fix: an inverted EndTime / StartTime pair flags
// time_anomaly:true via buildTags rather than rejecting the flow.
func TestValidateTimestamp_EndTimeBeforeStartTime_TagAnomaly(t *testing.T) {
	fr := validFixture()
	fr.Flow.EndTime = fr.Flow.StartTime - 60 // 60s BEFORE start
	ev, err := Translate(fr, "", 0)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if !containsTag(ev.Tags, "time_anomaly:true") {
		t.Errorf("missing time_anomaly:true tag for inverted end-time (have %v)", ev.Tags)
	}
}

// TestValidateTimestamp_EndTimeFarFuture_TagAnomaly: an EndTime
// more than 24h ahead of now also flags time_anomaly:true.
func TestValidateTimestamp_EndTimeFarFuture_TagAnomaly(t *testing.T) {
	prev := nowFunc
	defer func() { nowFunc = prev }()
	nowFunc = func() time.Time { return time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC) }
	fr := validFixture()
	fr.Flow.StartTime = time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC).Unix()
	fr.Flow.EndTime = time.Date(2026, 5, 14, 0, 0, 0, 0, time.UTC).Unix() // 48h future
	ev, err := Translate(fr, "", 0)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if !containsTag(ev.Tags, "time_anomaly:true") {
		t.Errorf("missing time_anomaly:true tag for far-future end-time (have %v)", ev.Tags)
	}
}

// TestTranslate_PodRefNode_PopulatedFromHostname locks in the P16
// fix: PodRef.Node must reflect the hostname passed to Translate
// (sourced from the K8S_NODE_NAME env var in production).
func TestTranslate_PodRefNode_PopulatedFromHostname(t *testing.T) {
	fr := validFixture()
	ev, err := Translate(fr, "node-7", 0)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if ev.Pod.Node != "node-7" {
		t.Errorf("Pod.Node: got %q, want %q", ev.Pod.Node, "node-7")
	}
}

// TestTranslate_Summary_NotDoublySanitised locks in the P21 fix:
// Summary is built from already-sanitised pieces and no longer
// passes through sanitizeForTag again, so it is not silently
// truncated at 256 bytes when the source/dest combination is long.
func TestTranslate_Summary_NotDoublySanitised(t *testing.T) {
	fr := validFixture()
	// Make src + dst long enough that the previous double-
	// sanitisation cap would have truncated. Each sanitised piece
	// is at most 256 bytes; the summary template adds ~30 bytes.
	fr.Flow.Key.SourceName = strings.Repeat("a", 200)
	fr.Flow.Key.DestName = strings.Repeat("b", 200)
	ev, err := Translate(fr, "", 1024*1024) // generous cap so size-guard doesn't fire
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if !strings.Contains(ev.Summary, strings.Repeat("a", 200)) {
		t.Errorf("summary did not retain full source name (post-P21 must not truncate at 256 bytes)\n  summary: %q", ev.Summary)
	}
	if !strings.Contains(ev.Summary, strings.Repeat("b", 200)) {
		t.Errorf("summary did not retain full dest name\n  summary: %q", ev.Summary)
	}
}

// TestTranslate_SourceLabels_AllowlistForwarded locks in the P28
// fix: K8s pod labels under the app.kubernetes.io/* and
// olaitan.io/* allowlists are forwarded as src-label / dst-label
// tags.
func TestTranslate_SourceLabels_AllowlistForwarded(t *testing.T) {
	fr := validFixture()
	fr.Flow.SourceLabels = []string{
		"app.kubernetes.io/name=nginx",
		"projectcalico.org/foo=bar", // NOT allowlisted; must be dropped
		"olaitan.io/role=server",
	}
	fr.Flow.DestLabels = []string{
		"app.kubernetes.io/component=db",
	}
	ev, err := Translate(fr, "", 0)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if !containsTag(ev.Tags, "src-label:app.kubernetes.io/name=nginx") {
		t.Errorf("missing src-label app.kubernetes.io/name=nginx (have %v)", ev.Tags)
	}
	if !containsTag(ev.Tags, "src-label:olaitan.io/role=server") {
		t.Errorf("missing src-label olaitan.io/role=server (have %v)", ev.Tags)
	}
	if !containsTag(ev.Tags, "dst-label:app.kubernetes.io/component=db") {
		t.Errorf("missing dst-label app.kubernetes.io/component=db (have %v)", ev.Tags)
	}
	for _, tg := range ev.Tags {
		if strings.Contains(tg, "projectcalico.org") {
			t.Errorf("non-allowlisted projectcalico.org label leaked: %q", tg)
		}
	}
}

// TestTranslate_PolicyTrace_TagsEmitted locks in the P29 fix:
// PolicyTrace.EnforcedPolicies / PendingPolicies become
// policy:<kind>/<ns>/<name>:<action> tags.
func TestTranslate_PolicyTrace_TagsEmitted(t *testing.T) {
	fr := validFixture()
	fr.Flow.Key.Policies = &goldmanepb.PolicyTrace{
		EnforcedPolicies: []*goldmanepb.PolicyHit{
			{Kind: goldmanepb.PolicyKind_CalicoNetworkPolicy, Namespace: "ns-a", Name: "deny-bad", Action: goldmanepb.Action_Deny},
		},
		PendingPolicies: []*goldmanepb.PolicyHit{
			{Kind: goldmanepb.PolicyKind_StagedNetworkPolicy, Namespace: "ns-a", Name: "staged-allow", Action: goldmanepb.Action_Allow},
		},
	}
	ev, err := Translate(fr, "", 0)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if !containsTag(ev.Tags, "policy:calico-np/ns-a/deny-bad:deny") {
		t.Errorf("missing enforced policy tag (have %v)", ev.Tags)
	}
	if !containsTag(ev.Tags, "policy:staged-np/ns-a/staged-allow:allow") {
		t.Errorf("missing pending policy tag (have %v)", ev.Tags)
	}
}

func containsTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}
