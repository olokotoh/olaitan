package cni

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/olokotoh/olaitan/internal/collector/cni/goldmanepb"
)

// updateExpectedJSON is the -update flag for TestUpdateExpectedJSON.
// When set, the test regenerates testdata/expected.json from the
// current Translate output. Lock the wall clock seam via the
// integration fixture's StartTime so the JSON is reproducible.
var updateExpectedJSON = flag.Bool("update", false, "regenerate testdata/expected.json from sample-flow.binpb")

// TestUpdateExpectedJSON is a no-op when -update is not passed. It
// is the maintenance entry point for the AC4 byte-stable fixture:
// run `go test ./internal/collector/cni/ -run TestUpdateExpectedJSON
// -update` to refresh the JSON after a Translate behavioural change
// is locked in elsewhere. The expected.json is consumed by the
// integration test TestIntegration_ConnectsAndPublishesOneFlow via
// bytes.Equal compare. Hostname is pinned to "integration-test-node"
// to match newIntegrationAdapter's Hostname value.
func TestUpdateExpectedJSON(t *testing.T) {
	if !*updateExpectedJSON {
		t.Skip("pass -update to regenerate testdata/expected.json")
	}
	data, err := os.ReadFile("testdata/sample-flow.binpb")
	if err != nil {
		t.Fatalf("read sample-flow.binpb: %v", err)
	}
	var fr goldmanepb.FlowResult
	if err := proto.Unmarshal(data, &fr); err != nil {
		t.Fatalf("unmarshal sample-flow.binpb: %v", err)
	}
	ev, err := Translate(&fr, "integration-test-node", 0)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	out, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile("testdata/expected.json", out, 0o644); err != nil {
		t.Fatalf("write expected.json: %v", err)
	}
	fmt.Fprintf(os.Stderr, "wrote testdata/expected.json (%d bytes)\n", len(out))
}
