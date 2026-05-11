//go:build integration

package applog

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	natsjs "github.com/nats-io/nats.go/jetstream"

	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// startTestNATS spins up an embedded NATS server with JetStream so the
// integration test exercises the real publish path (NFR36: no
// mock-only ring boundaries).
func startTestNATS(t *testing.T) *natsserver.Server {
	t.Helper()
	opts := &natsserver.Options{
		Host:      "127.0.0.1",
		Port:      -1,
		JetStream: true,
		StoreDir:  t.TempDir(),
		NoLog:     true,
		NoSigs:    true,
	}
	srv, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatalf("start test nats: %v", err)
	}
	srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats server not ready")
	}
	t.Cleanup(srv.Shutdown)
	return srv
}

func testStreamConfigsForApplog() []natsjs.StreamConfig {
	return []natsjs.StreamConfig{
		{
			Name:       "EVENTS_RAW",
			Subjects:   []string{subjects.RawPrefix + ">"},
			MaxAge:     1 * time.Hour,
			MaxBytes:   1 * 1024 * 1024,
			Storage:    natsjs.MemoryStorage,
			Retention:  natsjs.LimitsPolicy,
			Duplicates: 2 * time.Minute,
		},
	}
}

// startTestAdapter wires up the adapter against an embedded NATS, with
// stdout / stderr backed by real os.Pipe FDs (NFR36: real boundary).
// Returns the writer ends so the test can pump fixture lines, the
// adapter, and a cancellation function that tears the run loop down.
type integrationHarness struct {
	stdoutW *os.File
	stderrW *os.File
	adapter *Adapter
	consumer natsjs.Consumer
	stream  natsjs.Stream
	js      natsjs.JetStream
	cancel  context.CancelFunc
	done    chan error
}

func startTestAdapter(t *testing.T) *integrationHarness {
	t.Helper()
	srv := startTestNATS(t)

	cfg := natsclient.DefaultConfig()
	cfg.URL = srv.ClientURL()
	cfg.Name = "applog-integration-test"
	nc, err := natsclient.NewClient(cfg)
	if err != nil {
		t.Fatalf("nats client: %v", err)
	}
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = nc.Close(closeCtx)
	})

	streamsCtx, streamsCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer streamsCancel()
	if err := natsclient.EnsureStreams(streamsCtx, nc.JetStream(), testStreamConfigsForApplog()); err != nil {
		t.Fatalf("ensure streams: %v", err)
	}

	stream, err := nc.JetStream().Stream(streamsCtx, "EVENTS_RAW")
	if err != nil {
		t.Fatalf("get stream: %v", err)
	}
	consumer, err := stream.CreateOrUpdateConsumer(streamsCtx, natsjs.ConsumerConfig{
		Name:          "applog-test-consumer",
		FilterSubject: subjects.RawAppLog,
		AckPolicy:     natsjs.AckExplicitPolicy,
	})
	if err != nil {
		t.Fatalf("create consumer: %v", err)
	}

	adapter, err := New(Config{
		StdoutPath:    "/dev/null/stdout-stub",
		StderrPath:    "/dev/null/stderr-stub",
		Pod:           schema.PodRef{Name: "test-pod", Namespace: "default", UID: "uid-test", Node: "node-1"},
		Container:     "test-app",
		ChannelBuffer: 64,
	}, nc, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("new adapter: %v", err)
	}

	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}

	off1 := &atomic.Int64{}
	off2 := &atomic.Int64{}
	rb := adapter.recBuilder()
	adapter.stdoutTailFn = func(ctx context.Context, sink chan<- LineRecord) error {
		closeDone := make(chan struct{})
		go func() {
			defer close(closeDone)
			<-ctx.Done()
			_ = stdoutR.Close()
		}()
		err := runReaderTail(ctx, stdoutR, "stdout", sink, adapter.shed, off1, adapter.nowFn, rb, adapter.log)
		<-closeDone
		return err
	}
	adapter.stderrTailFn = func(ctx context.Context, sink chan<- LineRecord) error {
		closeDone := make(chan struct{})
		go func() {
			defer close(closeDone)
			<-ctx.Done()
			_ = stderrR.Close()
		}()
		err := runReaderTail(ctx, stderrR, "stderr", sink, adapter.shed, off2, adapter.nowFn, rb, adapter.log)
		<-closeDone
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- adapter.Run(ctx) }()

	t.Cleanup(func() {
		cancel()
		<-done
		_ = stdoutW.Close()
		_ = stderrW.Close()
	})

	return &integrationHarness{
		stdoutW:  stdoutW,
		stderrW:  stderrW,
		adapter:  adapter,
		consumer: consumer,
		stream:   stream,
		js:       nc.JetStream(),
		cancel:   cancel,
		done:     done,
	}
}

// fetchN drains up to want events from the consumer within timeout.
// Returns the decoded schema.Event slice in the order received.
func fetchN(t *testing.T, h *integrationHarness, want int, timeout time.Duration) []schema.Event {
	t.Helper()
	got := make([]schema.Event, 0, want)
	deadline := time.Now().Add(timeout)
	for len(got) < want && time.Now().Before(deadline) {
		remaining := time.Until(deadline)
		if remaining > 500*time.Millisecond {
			remaining = 500 * time.Millisecond
		}
		batch, err := h.consumer.Fetch(want-len(got), natsjs.FetchMaxWait(remaining))
		if err != nil {
			continue
		}
		for msg := range batch.Messages() {
			var ev schema.Event
			if err := json.Unmarshal(msg.Data(), &ev); err != nil {
				t.Errorf("decode event: %v", err)
				continue
			}
			got = append(got, ev)
			_ = msg.Ack()
		}
	}
	return got
}

// TestIntegration_LFLineEnding_PublishedToRawAppLog covers the basic
// happy path: a single line on stdout round-trips through the real
// adapter into a real JetStream consumer.
func TestIntegration_LFLineEnding_PublishedToRawAppLog(t *testing.T) {
	h := startTestAdapter(t)
	if _, err := h.stdoutW.Write([]byte("hello world\n")); err != nil {
		t.Fatalf("write stdout: %v", err)
	}
	got := fetchN(t, h, 1, 5*time.Second)
	if len(got) != 1 {
		t.Fatalf("got %d events want 1", len(got))
	}
	if got[0].Source != schema.SourceAppLog {
		t.Errorf("Source: got %q want %q", got[0].Source, schema.SourceAppLog)
	}
	if got[0].Category != schema.CategoryLog {
		t.Errorf("Category: got %q want %q", got[0].Category, schema.CategoryLog)
	}
}

// TestIntegration_StdoutAndStderr_BothPublished asserts that both
// streams reach JetStream with their stream tag preserved.
func TestIntegration_StdoutAndStderr_BothPublished(t *testing.T) {
	h := startTestAdapter(t)
	if _, err := h.stdoutW.Write([]byte("from stdout\n")); err != nil {
		t.Fatalf("stdout: %v", err)
	}
	if _, err := h.stderrW.Write([]byte("from stderr\n")); err != nil {
		t.Fatalf("stderr: %v", err)
	}
	got := fetchN(t, h, 2, 5*time.Second)
	if len(got) != 2 {
		t.Fatalf("got %d events want 2", len(got))
	}
	streams := map[string]bool{}
	for _, ev := range got {
		for _, tag := range ev.Tags {
			if strings.HasPrefix(tag, "stream:") {
				streams[strings.TrimPrefix(tag, "stream:")] = true
			}
		}
	}
	if !streams["stdout"] || !streams["stderr"] {
		t.Errorf("expected both stream tags, got %v", streams)
	}
}

// TestIntegration_CRLFLineEnding asserts CRLF-terminated lines are
// stripped to the bare content before publish.
func TestIntegration_CRLFLineEnding(t *testing.T) {
	h := startTestAdapter(t)
	if _, err := h.stdoutW.Write([]byte("windows-line\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := fetchN(t, h, 1, 5*time.Second)
	if len(got) != 1 {
		t.Fatalf("got %d events want 1", len(got))
	}
	var raw string
	if err := json.Unmarshal(got[0].Raw, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	if raw != "windows-line" {
		t.Errorf("raw stripping CR: got %q want %q", raw, "windows-line")
	}
}

// TestIntegration_InvalidUTF8_ReplacedAndTagged asserts the adapter
// sanitises invalid UTF-8 sequences to U+FFFD and tags the event
// encoding:replaced.
func TestIntegration_InvalidUTF8_ReplacedAndTagged(t *testing.T) {
	h := startTestAdapter(t)
	bad := []byte{'h', 'i', 0xC3, 0x28, '!', '\n'}
	if _, err := h.stdoutW.Write(bad); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := fetchN(t, h, 1, 5*time.Second)
	if len(got) != 1 {
		t.Fatalf("got %d want 1", len(got))
	}
	hasReplaced := false
	for _, tag := range got[0].Tags {
		if tag == "encoding:replaced" {
			hasReplaced = true
		}
	}
	if !hasReplaced {
		t.Errorf("expected encoding:replaced tag, got Tags=%v", got[0].Tags)
	}
}

// TestIntegration_EmbeddedNUL_PreservedInRaw asserts NUL bytes survive
// the JSON round-trip in Event.Raw.
func TestIntegration_EmbeddedNUL_PreservedInRaw(t *testing.T) {
	h := startTestAdapter(t)
	withNUL := []byte{'h', 'i', 0x00, 'b', 'y', 'e', '\n'}
	if _, err := h.stdoutW.Write(withNUL); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := fetchN(t, h, 1, 5*time.Second)
	if len(got) != 1 {
		t.Fatalf("got %d want 1", len(got))
	}
	var raw string
	if err := json.Unmarshal(got[0].Raw, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	if !strings.ContainsRune(raw, 0x00) {
		t.Errorf("expected NUL preserved in Raw, got %q", raw)
	}
}

// TestIntegration_MsgIDDistinctOffsets is the byte-identical-line /
// distinct-offset path: stableEventID's offset participation produces
// different IDs for two writes of the same content, so JetStream
// dedup does NOT swallow either. Both events surface.
//
// (Renamed from TestIntegration_MsgIDDedup per the Story 1.9 code
// review: the original name asserted the opposite of dedup.)
func TestIntegration_MsgIDDistinctOffsets(t *testing.T) {
	h := startTestAdapter(t)
	if _, err := h.stdoutW.Write([]byte("dedup-line\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := h.stdoutW.Write([]byte("dedup-line\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := fetchN(t, h, 2, 5*time.Second)
	if len(got) != 2 {
		t.Fatalf("got %d events want 2 (offsets differ -> distinct IDs)", len(got))
	}
	if got[0].ID == got[1].ID {
		t.Errorf("expected distinct IDs across offsets; both=%q", got[0].ID)
	}
}

// TestIntegration_MsgIDDedup_TrueDedup directly publishes two events
// to the same JetStream stream with the SAME Nats-Msg-Id header and
// asserts that only one event surfaces -- this is the genuine dedup
// guarantee the adapter relies on for at-least-once-with-retry
// semantics. Goes around the Adapter so we can force the colliding
// MsgID; the Adapter never actually emits colliding IDs by design
// (stableEventID's per-stream offset participation guarantees
// distinct IDs even for byte-identical lines).
func TestIntegration_MsgIDDedup_TrueDedup(t *testing.T) {
	h := startTestAdapter(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ev := schema.Event{
		ID:        "fixed-dedup-id-0123456789abcdef0",
		Timestamp: time.Now(),
		Source:    schema.SourceAppLog,
		Pod:       schema.PodRef{Name: "p", Namespace: "ns", UID: "u"},
		Severity:  "informational",
		Category:  schema.CategoryLog,
		Summary:   "dedup-test",
	}
	for i := 0; i < 2; i++ {
		if _, err := h.js.Publish(ctx, subjects.RawAppLog, mustJSON(t, ev), natsjs.WithMsgID(ev.ID)); err != nil {
			t.Fatalf("publish#%d: %v", i, err)
		}
	}

	// Fetch with a 1-second wait window: dedup means only one of the
	// two publishes will become a stream message.
	got := fetchN(t, h, 2, 2*time.Second)
	if len(got) != 1 {
		t.Errorf("got %d events want 1 (JetStream dedup should swallow the second publish with the same Nats-Msg-Id)", len(got))
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// TestIntegration_BackpressureBurstDeliveredAgainstFastConsumer asserts
// that a large burst against a fast in-memory JetStream is delivered
// without OOM (the bounded channel + shed-state machinery does not
// starve the publish loop). LinesShed may or may not increment
// depending on CI hardware speed; the canonical stalled-consumer test
// lives in applog_test.go as TestRun_BackpressureShedding_SignalsViaCounter
// (slow-publisher fixture, deterministic assertion on LinesShed > 0).
//
// (Renamed from TestIntegration_BackpressureShedding_NoOOMUnderStall
// per the Story 1.9 code review: the original name claimed an OOM-
// stress assertion the test does not perform.)
func TestIntegration_BackpressureBurstDeliveredAgainstFastConsumer(t *testing.T) {
	h := startTestAdapter(t)

	go func() {
		for i := 0; i < 4096; i++ {
			_, _ = h.stdoutW.Write([]byte("burst\n"))
		}
		_ = h.stdoutW.Close()
	}()

	got := fetchN(t, h, 1024, 10*time.Second)
	if len(got) == 0 {
		t.Fatalf("got 0 events under burst; expected at least some")
	}
	t.Logf("burst delivered: published=%d shed=%d", len(got), h.adapter.LinesShed())
}
