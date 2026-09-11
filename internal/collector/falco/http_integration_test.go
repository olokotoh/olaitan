//go:build integration

package falco

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go/jetstream"

	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// TestIntegration_HTTPToJetStream crosses every real boundary the receiver
// has: a real TCP listener, a real POST of a captured Falco body, a real
// embedded JetStream, and a consumer reading EVENTS_RAW. It also checks the
// publish carries the event ID as Nats-Msg-Id, which is what makes a
// retried publish deduplicate.
func TestIntegration_HTTPToJetStream(t *testing.T) {
	srv, err := natsserver.NewServer(&natsserver.Options{Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats server not ready")
	}
	t.Cleanup(srv.Shutdown)

	nc, err := natsclient.NewClient(natsclient.ClientConfig{URL: srv.ClientURL(), Name: "falco-http-it"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = nc.Close(ctx)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := nc.JetStream().CreateStream(ctx, jetstream.StreamConfig{Name: "EVENTS_RAW", Subjects: []string{subjects.RawPrefix + ">"}}); err != nil {
		t.Fatal(err)
	}

	a, err := New(Config{ListenAddr: "127.0.0.1:0", Token: testToken, Hostname: "kind-node"}, nc, nil)
	if err != nil {
		t.Fatal(err)
	}
	runCtx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(runCtx) }()
	t.Cleanup(func() { stop(); <-done })
	for a.Addr() == "" {
		time.Sleep(10 * time.Millisecond)
	}

	body := fixture(t, "http_output_alert.json")
	for i := 0; i < 2; i++ { // the same alert twice: dedup by Nats-Msg-Id
		resp, err := http.Post("http://"+a.Addr()+"/falco/"+testToken, "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("POST %d: status %d", i, resp.StatusCode)
		}
	}

	cons, err := nc.JetStream().CreateOrUpdateConsumer(ctx, "EVENTS_RAW", jetstream.ConsumerConfig{FilterSubject: subjects.RawFalco, AckPolicy: jetstream.AckExplicitPolicy})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := cons.Next(jetstream.FetchMaxWait(3 * time.Second))
	if err != nil {
		t.Fatalf("no event on EVENTS_RAW: %v", err)
	}
	var ev schema.Event
	if err := json.Unmarshal(msg.Data(), &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Source != schema.SourceFalco || ev.Pod.Node != "kind-node" {
		t.Errorf("event = %+v", ev)
	}
	if got := msg.Headers().Get("Nats-Msg-Id"); got == "" || got != ev.ID {
		t.Errorf("Nats-Msg-Id = %q, want the event ID %q", got, ev.ID)
	}
	_ = msg.Ack()
	if _, err := cons.Next(jetstream.FetchMaxWait(time.Second)); err == nil {
		t.Error("the duplicate POST produced a second stream message; Nats-Msg-Id dedup is not working")
	}
}
