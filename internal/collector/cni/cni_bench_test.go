//go:build integration

package cni

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	natsjs "github.com/nats-io/nats.go/jetstream"

	"github.com/olokotoh/olaitan/internal/collector/cni/goldmanepb"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// TestBench_NFR1ReceiveToPublishP99 measures receive-to-publish
// latency over 1000 fixture flows and hard-fails if p99 exceeds 50
// ms. The spike measured median ~257us / p99 ~1.70ms per record
// for translation alone; production embedded-NATS adds ~500us, so
// the realistic budget is around 5 ms. The 50 ms ceiling is NFR1.
//
// Setup is hoisted outside the timed loop (Story 1.2 M7 precedent):
// the gRPC client, the JSON encoder, the JetStream publisher, and
// the subject constant are all constructed before t0. Percentile
// index uses samples[(n-1)*99/100] per the off-by-one-safe form
// established by Story 1.2 review B3.
func TestBench_NFR1ReceiveToPublishP99(t *testing.T) {
	const target = 1000

	natsSrv := startTestNATS(t)
	conn, err := nats.Connect(natsSrv.ClientURL())
	if err != nil {
		t.Fatalf("nats.Connect: %v", err)
	}
	defer conn.Close()
	js, err := natsjs.New(conn)
	if err != nil {
		t.Fatalf("jetstream.New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, sc := range natsTestStreamConfigs() {
		if _, err := js.CreateOrUpdateStream(ctx, sc); err != nil {
			t.Fatalf("create stream %s: %v", sc.Name, err)
		}
	}

	// Build one fixture; mutate the per-iteration ID so JetStream's
	// 2-minute dedup window does not collapse the run.
	base := integrationFixture()
	// Translate once outside the timed loop to prime any package-
	// level lazy state (protojson MarshalOptions, etc).
	if _, terr := Translate(base, 0); terr != nil {
		t.Fatalf("warm-up translate: %v", terr)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	_ = log

	samples := make([]time.Duration, 0, target)
	for i := 0; i < target; i++ {
		fr := &goldmanepb.FlowResult{
			Id:   int64(1000 + i),
			Flow: base.Flow,
		}
		t0 := time.Now()
		ev, terr := Translate(fr, 0)
		if terr != nil {
			t.Fatalf("translate iter %d: %v", i, terr)
		}
		body, merr := json.Marshal(ev)
		if merr != nil {
			t.Fatalf("marshal iter %d: %v", i, merr)
		}
		pubCtx, pubCancel := context.WithTimeout(ctx, 2*time.Second)
		_, perr := js.Publish(pubCtx, subjects.RawNetwork, body, natsjs.WithMsgID(ev.ID))
		pubCancel()
		if perr != nil {
			t.Fatalf("publish iter %d: %v", i, perr)
		}
		samples = append(samples, time.Since(t0))
	}

	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	median := samples[(target-1)/2]
	p99 := samples[(target-1)*99/100]
	maxv := samples[target-1]
	minv := samples[0]

	fmt.Fprintf(os.Stderr, "cni bench: samples=%d min=%s median=%s p99=%s max=%s\n",
		target, minv, median, p99, maxv)

	if p99 > 50*time.Millisecond {
		t.Fatalf("NFR1 gate failed: p99=%s > 50ms", p99)
	}
}
