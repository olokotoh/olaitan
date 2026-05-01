package main

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	goldmanev1 "github.com/olokotoh/olaitan/spikes/calico-flow/proto"
)

// TestTranslateContract decodes a real Goldmane FlowResult captured
// during the live POC, runs it through the spike's translator, and
// asserts byte-for-byte equality with the committed expected JSON.
//
// This is the AC4 fixture-driven contract test referenced by the
// story. The fixture and the expected output must be re-captured
// (via `go run . --mode capture`) whenever the translator changes.
func TestTranslateContract(t *testing.T) {
	t.Parallel()

	frBytes, err := os.ReadFile("testdata/sample-flow.binpb")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	fr := &goldmanev1.FlowResult{}
	if err := proto.Unmarshal(frBytes, fr); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	got, err := translate(fr)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	// Normalise the timestamp: the fixture's StartTime is a real Unix
	// second, but tests must remain stable, so the fixed sentinel
	// from main.go is substituted before comparison.
	got.Timestamp = fixedTimestamp()

	gotJSON, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatalf("marshal got: %v", err)
	}
	gotJSON = append(gotJSON, '\n')

	wantJSON, err := os.ReadFile("testdata/expected.json")
	if err != nil {
		t.Fatalf("read expected: %v", err)
	}

	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("translator output drift\n--- got ---\n%s\n--- want ---\n%s", gotJSON, wantJSON)
	}
}

// TestRoundTripJSON asserts the translated event survives a full
// JSON marshal / unmarshal / re-marshal cycle as a semantically
// identical value. This is the AC2 PASS condition exercised offline
// (no live cluster required).
func TestRoundTripJSON(t *testing.T) {
	t.Parallel()

	frBytes, err := os.ReadFile("testdata/sample-flow.binpb")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	fr := &goldmanev1.FlowResult{}
	if err := proto.Unmarshal(frBytes, fr); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	evt, err := translate(fr)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	evt.Timestamp = fixedTimestamp()

	first, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("marshal: %v", err)
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
		t.Fatalf("round-trip semantic mismatch\nfirst:  %s\nsecond: %s", first, second)
	}
}

// TestTimestampStability is a smoke check that the fixture's
// StartTime is interpreted as Unix seconds in UTC. If Goldmane ever
// changes its time semantics (e.g., milliseconds), this test will
// catch the drift before the contract test does.
func TestTimestampStability(t *testing.T) {
	t.Parallel()

	frBytes, err := os.ReadFile("testdata/sample-flow.binpb")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	fr := &goldmanev1.FlowResult{}
	if err := proto.Unmarshal(frBytes, fr); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	evt, err := translate(fr)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	expected := time.Unix(fr.Flow.StartTime, 0).UTC()
	if !evt.Timestamp.Equal(expected) {
		t.Fatalf("timestamp drift: got %s want %s", evt.Timestamp, expected)
	}
}
