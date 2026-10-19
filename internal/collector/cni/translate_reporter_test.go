package cni

import (
	"bufio"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/olokotoh/olaitan/internal/collector/cni/goldmanepb"
)

// Goldmane reports each connection twice, once per reporter, with the byte
// counters seen from that side: on the 2026-10-19 live run the Src record of
// an S4 beacon carried bytes_out 275 and the Dst record of the same
// connection bytes_out 164 (the sink's reply). network.bytes_out means bytes the source
// workload SENT, so only the Src record may carry it; the Dst record omits it
// rather than project the wrong direction into OLT-NET-001's small_payload
// check and the baseline. network.reporter keeps the reporter visible.
func TestTranslate_BytesOutOnlyFromSrcReporter_LiveFixture(t *testing.T) {
	f, err := os.Open("../../correlator/testdata/goldmane-s4-flows-live-2026-10-19.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec struct {
			Raw struct {
				ID   json.Number     `json:"id"`
				Flow json.RawMessage `json:"flow"`
			} `json:"raw"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		flow := &goldmanepb.Flow{}
		if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(rec.Raw.Flow, flow); err != nil {
			t.Fatal(err)
		}
		id, _ := rec.Raw.ID.Int64()
		ev, err := Translate(&goldmanepb.FlowResult{Id: id, Flow: flow}, "node", 0)
		if err != nil {
			t.Fatal(err)
		}
		var raw map[string]any
		if err := json.Unmarshal(ev.Raw, &raw); err != nil {
			t.Fatal(err)
		}
		switch flow.GetKey().GetReporter() {
		case goldmanepb.Reporter_Src:
			seen["src"] = true
			if raw["network.reporter"] != "src" {
				t.Errorf("src record: network.reporter = %v", raw["network.reporter"])
			}
			if want := strconv.FormatInt(flow.GetBytesOut(), 10); raw["network.bytes_out"] != want {
				t.Errorf("src record: network.bytes_out = %v, want the source's own %s", raw["network.bytes_out"], want)
			}
		case goldmanepb.Reporter_Dst:
			seen["dst"] = true
			if raw["network.reporter"] != "dst" {
				t.Errorf("dst record: network.reporter = %v", raw["network.reporter"])
			}
			if v, ok := raw["network.bytes_out"]; ok {
				t.Errorf("dst record projected network.bytes_out=%v; it is the destination's view, not the source's outbound bytes", v)
			}
			if raw["network.dst_port"] != "8443" {
				t.Errorf("dst record lost network.dst_port: %v", raw["network.dst_port"])
			}
		}
	}
	if !seen["src"] || !seen["dst"] {
		t.Fatalf("fixture must hold both reporter records, saw %v", seen)
	}
}
