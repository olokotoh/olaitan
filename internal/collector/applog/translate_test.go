package applog

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/schema"
)

// fixedTimestamp returns a deterministic in-range timestamp used by the
// happy-path tests so the future-skew guard never trips.
func fixedTimestamp() time.Time {
	return time.Date(2026, 5, 8, 12, 0, 0, 123456789, time.UTC)
}

func samplePodRef() schema.PodRef {
	return schema.PodRef{
		Name:      "payments-7f8b9c",
		Namespace: "default",
		Node:      "node-1",
		UID:       "8d6b3f12-2a4c-4d3e-b8e8-1234567890ab",
	}
}

func TestTranslate_HappyPath_Stdout(t *testing.T) {
	rec := LineRecord{
		Line:      []byte("started up cleanly"),
		Stream:    "stdout",
		Timestamp: fixedTimestamp(),
		Pod:       samplePodRef(),
		Container: "payments",
		Offset:    1,
	}
	ev, err := Translate(rec)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if ev.Source != schema.SourceAppLog {
		t.Errorf("Source: got %q want %q", ev.Source, schema.SourceAppLog)
	}
	if ev.Category != schema.CategoryLog {
		t.Errorf("Category: got %q want %q", ev.Category, schema.CategoryLog)
	}
	if ev.Severity != "informational" {
		t.Errorf("Severity: got %q want %q", ev.Severity, "informational")
	}
	if ev.Pod != rec.Pod {
		t.Errorf("Pod: got %+v want %+v", ev.Pod, rec.Pod)
	}
	if !ev.Timestamp.Equal(rec.Timestamp) {
		t.Errorf("Timestamp: got %s want %s", ev.Timestamp, rec.Timestamp)
	}
	if len(ev.ID) != 32 {
		t.Errorf("ID len: got %d want 32 hex chars", len(ev.ID))
	}
	if !containsTag(ev.Tags, "stream:stdout") {
		t.Errorf("missing stream:stdout in Tags=%v", ev.Tags)
	}
	if !containsTag(ev.Tags, "container:payments") {
		t.Errorf("missing container:payments in Tags=%v", ev.Tags)
	}
}

func TestTranslate_HappyPath_Stderr(t *testing.T) {
	rec := LineRecord{
		Line:      []byte("WARN something happened"),
		Stream:    "stderr",
		Timestamp: fixedTimestamp(),
		Pod:       samplePodRef(),
		Container: "payments",
		Offset:    2,
	}
	ev, err := Translate(rec)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if !containsTag(ev.Tags, "stream:stderr") {
		t.Errorf("missing stream:stderr in Tags=%v", ev.Tags)
	}
}

func TestTranslate_RejectsNilLine(t *testing.T) {
	rec := LineRecord{
		Line:      nil,
		Stream:    "stdout",
		Timestamp: fixedTimestamp(),
		Pod:       samplePodRef(),
		Container: "payments",
	}
	_, err := Translate(rec)
	if !errors.Is(err, ErrNilLine) {
		t.Fatalf("err: got %v want %v", err, ErrNilLine)
	}
}

func TestTranslate_AcceptsEmptyLine(t *testing.T) {
	// Empty (zero-length but non-nil) lines are legal -- some
	// applications emit blank lines as separators.
	rec := LineRecord{
		Line:      []byte{},
		Stream:    "stdout",
		Timestamp: fixedTimestamp(),
		Pod:       samplePodRef(),
		Container: "payments",
	}
	ev, err := Translate(rec)
	if err != nil {
		t.Fatalf("Translate empty line: %v", err)
	}
	if string(ev.Raw) != `""` {
		t.Errorf("Raw: got %s want \"\"", ev.Raw)
	}
}

func TestTranslate_RejectsZeroTimestamp(t *testing.T) {
	rec := LineRecord{
		Line:      []byte("x"),
		Stream:    "stdout",
		Timestamp: time.Time{},
		Pod:       samplePodRef(),
		Container: "payments",
	}
	_, err := Translate(rec)
	if !errors.Is(err, ErrInvalidTimestamp) {
		t.Fatalf("err: got %v want ErrInvalidTimestamp", err)
	}
}

func TestTranslate_RejectsPreEpochTimestamp(t *testing.T) {
	rec := LineRecord{
		Line:      []byte("x"),
		Stream:    "stdout",
		Timestamp: time.Date(2009, 1, 1, 0, 0, 0, 0, time.UTC),
		Pod:       samplePodRef(),
		Container: "payments",
	}
	_, err := Translate(rec)
	if !errors.Is(err, ErrInvalidTimestamp) {
		t.Fatalf("err: got %v want ErrInvalidTimestamp", err)
	}
}

func TestTranslate_RejectsFutureTimestamp(t *testing.T) {
	rec := LineRecord{
		Line:      []byte("x"),
		Stream:    "stdout",
		Timestamp: time.Now().Add(48 * time.Hour),
		Pod:       samplePodRef(),
		Container: "payments",
	}
	_, err := Translate(rec)
	if !errors.Is(err, ErrInvalidTimestamp) {
		t.Fatalf("err: got %v want ErrInvalidTimestamp", err)
	}
}

func TestTranslate_RejectsUnknownStream(t *testing.T) {
	rec := LineRecord{
		Line:      []byte("x"),
		Stream:    "stdmaybe",
		Timestamp: fixedTimestamp(),
		Pod:       samplePodRef(),
		Container: "payments",
	}
	_, err := Translate(rec)
	if !errors.Is(err, ErrInvalidStream) {
		t.Fatalf("err: got %v want ErrInvalidStream", err)
	}
}

func TestTranslate_RejectsEmptyContainer(t *testing.T) {
	rec := LineRecord{
		Line:      []byte("x"),
		Stream:    "stdout",
		Timestamp: fixedTimestamp(),
		Pod:       samplePodRef(),
		Container: "",
	}
	_, err := Translate(rec)
	if !errors.Is(err, ErrEmptyContainer) {
		t.Fatalf("err: got %v want ErrEmptyContainer", err)
	}
}

func TestTranslate_DeterministicEventID(t *testing.T) {
	rec := LineRecord{
		Line:      []byte("hello world"),
		Stream:    "stdout",
		Timestamp: fixedTimestamp(),
		Pod:       samplePodRef(),
		Container: "payments",
		Offset:    42,
	}
	ev1, err := Translate(rec)
	if err != nil {
		t.Fatalf("Translate#1: %v", err)
	}
	ev2, err := Translate(rec)
	if err != nil {
		t.Fatalf("Translate#2: %v", err)
	}
	if ev1.ID != ev2.ID {
		t.Errorf("non-deterministic ID: %q vs %q", ev1.ID, ev2.ID)
	}
}

func TestTranslate_DistinctOffsetsProduceDistinctIDs(t *testing.T) {
	base := LineRecord{
		Line:      []byte("identical line"),
		Stream:    "stdout",
		Timestamp: fixedTimestamp(),
		Pod:       samplePodRef(),
		Container: "payments",
	}
	a := base
	a.Offset = 1
	b := base
	b.Offset = 2
	evA, err := Translate(a)
	if err != nil {
		t.Fatalf("Translate a: %v", err)
	}
	evB, err := Translate(b)
	if err != nil {
		t.Fatalf("Translate b: %v", err)
	}
	if evA.ID == evB.ID {
		t.Errorf("ID collision on different offsets: both=%q", evA.ID)
	}
}

func TestTranslate_LineLongerThan64KiB_Truncated(t *testing.T) {
	bigLine := make([]byte, MaxLineBytes+1024)
	for i := range bigLine {
		bigLine[i] = 'a'
	}
	rec := LineRecord{
		Line:      bigLine,
		Stream:    "stdout",
		Timestamp: fixedTimestamp(),
		Pod:       samplePodRef(),
		Container: "payments",
	}
	ev, err := Translate(rec)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if !containsTag(ev.Tags, "truncated:true") {
		t.Errorf("missing truncated:true in Tags=%v", ev.Tags)
	}
	// Raw is JSON-encoded string; its decoded length must equal MaxLineBytes.
	var decoded string
	if err := json.Unmarshal(ev.Raw, &decoded); err != nil {
		t.Fatalf("unmarshal Raw: %v", err)
	}
	if len(decoded) != MaxLineBytes {
		t.Errorf("decoded raw len: got %d want %d", len(decoded), MaxLineBytes)
	}
}

func TestTranslate_InvalidUTF8_Replaced(t *testing.T) {
	// 0xC3 0x28 is an invalid UTF-8 byte sequence.
	rec := LineRecord{
		Line:      []byte{'h', 'i', 0xC3, 0x28, '!'},
		Stream:    "stdout",
		Timestamp: fixedTimestamp(),
		Pod:       samplePodRef(),
		Container: "payments",
	}
	ev, err := Translate(rec)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if !containsTag(ev.Tags, "encoding:replaced") {
		t.Errorf("missing encoding:replaced in Tags=%v", ev.Tags)
	}
	var decoded string
	if err := json.Unmarshal(ev.Raw, &decoded); err != nil {
		t.Fatalf("unmarshal Raw: %v", err)
	}
	if !strings.Contains(decoded, "�") {
		t.Errorf("Raw missing replacement char U+FFFD: got %q", decoded)
	}
}

func TestTranslate_EmbeddedNUL_PreservedInRaw_StrippedInSummary(t *testing.T) {
	rec := LineRecord{
		Line:      []byte{'h', 'i', 0x00, 'b', 'y', 'e'},
		Stream:    "stdout",
		Timestamp: fixedTimestamp(),
		Pod:       samplePodRef(),
		Container: "payments",
	}
	ev, err := Translate(rec)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	var decoded string
	if err := json.Unmarshal(ev.Raw, &decoded); err != nil {
		t.Fatalf("unmarshal Raw: %v", err)
	}
	// NUL is preserved in Raw (legal UTF-8): the decoded string must
	// still contain the NUL byte.
	if !strings.ContainsRune(decoded, 0x00) {
		t.Errorf("Raw missing embedded NUL: %q", decoded)
	}
	// Summary must NOT contain a literal NUL byte (sanitizeForTag
	// strips control characters). The %q-quoted form in the Summary
	// would render NUL as \x00, but the source string passed to %q
	// must already be NUL-free.
	if strings.ContainsRune(ev.Summary, 0x00) {
		t.Errorf("Summary contains raw NUL: %q", ev.Summary)
	}
}

func TestTranslate_ControlCharsInLabel_Sanitized(t *testing.T) {
	rec := LineRecord{
		Line:      []byte("ok"),
		Stream:    "stdout",
		Timestamp: fixedTimestamp(),
		Pod:       samplePodRef(),
		Container: "payments",
		Labels: map[string]string{
			"app.kubernetes.io/name": "pay\nments\x00",
		},
	}
	ev, err := Translate(rec)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	for _, tag := range ev.Tags {
		if strings.ContainsRune(tag, '\n') || strings.ContainsRune(tag, 0x00) {
			t.Errorf("tag contains unsanitised control char: %q", tag)
		}
	}
}

func TestTranslate_NonOlaitanLabelsDropped(t *testing.T) {
	rec := LineRecord{
		Line:      []byte("ok"),
		Stream:    "stdout",
		Timestamp: fixedTimestamp(),
		Pod:       samplePodRef(),
		Container: "payments",
		Labels: map[string]string{
			"random/label":           "should-drop",
			"app.kubernetes.io/name": "should-keep",
			"olaitan.io/log-sidecar": "enabled",
		},
	}
	ev, err := Translate(rec)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if containsTagWithKey(ev.Tags, "random/label:") {
		t.Errorf("non-whitelisted label leaked into Tags=%v", ev.Tags)
	}
	if !containsTagWithKey(ev.Tags, "app.kubernetes.io/name:") {
		t.Errorf("whitelisted app.kubernetes.io/name dropped: Tags=%v", ev.Tags)
	}
	if !containsTagWithKey(ev.Tags, "olaitan.io/log-sidecar:") {
		t.Errorf("whitelisted olaitan.io/* dropped: Tags=%v", ev.Tags)
	}
}

func TestTranslate_IDDerivedFromTruncatedNotOriginal(t *testing.T) {
	bigLine := make([]byte, MaxLineBytes+10)
	for i := range bigLine {
		bigLine[i] = 'b'
	}
	rec := LineRecord{
		Line:      bigLine,
		Stream:    "stdout",
		Timestamp: fixedTimestamp(),
		Pod:       samplePodRef(),
		Container: "payments",
		Offset:    7,
	}
	ev, err := Translate(rec)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}

	// A second LineRecord whose Line is exactly the truncated form
	// (i.e. MaxLineBytes long) must produce the same ID.
	truncatedLine := bigLine[:MaxLineBytes]
	rec2 := rec
	rec2.Line = append([]byte(nil), truncatedLine...)
	ev2, err := Translate(rec2)
	if err != nil {
		t.Fatalf("Translate#2: %v", err)
	}
	if ev.ID != ev2.ID {
		t.Errorf("ID mismatch: original=%q truncated=%q", ev.ID, ev2.ID)
	}
	// Tag-presence assertion: the original (longer than MaxLineBytes)
	// must carry truncated:true; the deliberately-pre-truncated
	// re-translate must NOT carry it (its Line is exactly MaxLineBytes,
	// the truncation boundary, but never exceeded).
	if !containsTag(ev.Tags, "truncated:true") {
		t.Errorf("over-cap event missing truncated:true tag: tags=%v", ev.Tags)
	}
	if containsTag(ev2.Tags, "truncated:true") {
		t.Errorf("at-cap event unexpectedly carries truncated:true: tags=%v", ev2.Tags)
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

func containsTagWithKey(tags []string, prefix string) bool {
	for _, t := range tags {
		if strings.HasPrefix(t, prefix) {
			return true
		}
	}
	return false
}
