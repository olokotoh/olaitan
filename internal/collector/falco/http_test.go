package falco

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	natsjs "github.com/nats-io/nats.go/jetstream"

	"github.com/olokotoh/olaitan/internal/ratelimit"
	"github.com/olokotoh/olaitan/internal/retry"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// The two fixtures are real Falco http_output bodies, captured from Falco
// 0.45.0-rc1 (modern_ebpf) on 2026-09-11: the alert is a busybox container
// running `cat /etc/shadow`, the snapshot is Falco's own periodic metrics
// event. Only the node hostname was replaced. Hand-written JSON would encode
// what we believe Falco sends; these encode what it does send, including the
// null values and the 19-digit integers that a float64 decode would corrupt.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

const testToken = "0123456789abcdef0123456789abcdef"

type recordingPub struct {
	mu       sync.Mutex
	subjects []string
	events   []schema.Event
	err      error
}

func (p *recordingPub) PublishJS(_ context.Context, subject string, data any, _ ...natsjs.PublishOpt) (*natsjs.PubAck, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return nil, p.err
	}
	ev, ok := data.(schema.Event)
	if !ok {
		return nil, errors.New("recordingPub: data is not a schema.Event")
	}
	p.subjects = append(p.subjects, subject)
	p.events = append(p.events, ev)
	return &natsjs.PubAck{Stream: "EVENTS_RAW"}, nil
}

func (p *recordingPub) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.events)
}

func newTestAdapter(t *testing.T, pub natsPublisher, mut func(*Config)) *Adapter {
	t.Helper()
	cfg := Config{
		ListenAddr: "127.0.0.1:0",
		Token:      testToken,
		Hostname:   "kind-node",
		// One fast attempt keeps the transient-failure test quick.
		PublishRetry: retry.Strategy{Min: time.Millisecond, Max: time.Millisecond, Multiplier: 1, MaxAttempts: 1},
	}
	if mut != nil {
		mut(&cfg)
	}
	a, err := New(cfg, pub, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func post(t *testing.T, a *Adapter, path, ctype string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)
	return rec
}

// --- decode -----------------------------------------------------------

func TestDecodeHTTPOutput_RealAlertTranslatesLikeTheGRPCPathDid(t *testing.T) {
	resp, err := DecodeHTTPOutput(fixture(t, "http_output_alert.json"))
	if err != nil {
		t.Fatalf("DecodeHTTPOutput: %v", err)
	}
	ev, err := Translate(resp, "kind-node")
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if ev.Source != schema.SourceFalco || ev.Category != schema.CategorySyscall {
		t.Errorf("source/category = %s/%s, want falco/syscall", ev.Source, ev.Category)
	}
	if ev.Severity != "warning" {
		t.Errorf("severity = %q, want warning (Falco priority \"Warning\")", ev.Severity)
	}
	want := time.Date(2026, 9, 11, 5, 0, 42, 544857414, time.UTC)
	if !ev.Timestamp.Equal(want) {
		t.Errorf("timestamp = %s, want %s (nanoseconds must survive)", ev.Timestamp.Format(time.RFC3339Nano), want.Format(time.RFC3339Nano))
	}
	if !strings.Contains(ev.Summary, "file=/etc/shadow") {
		t.Errorf("summary is not Falco's rendered output: %q", ev.Summary)
	}
	if got := strings.Join(ev.Tags, ","); got != "T1555,container,filesystem,host,maturity_stable,mitre_credential_access" {
		t.Errorf("tags = %s", got)
	}
	if ev.Pod.Node != "kind-node" {
		t.Errorf("pod.node = %q, want the collector's node name", ev.Pod.Node)
	}

	fields := resp.GetOutputFields()
	if fields["proc.name"] != "cat" || fields["fd.name"] != "/etc/shadow" {
		t.Errorf("string fields lost: proc.name=%q fd.name=%q", fields["proc.name"], fields["fd.name"])
	}
	// A float64 decode turns 1789102842544857414 into 1789102842544857344.
	if got := fields["evt.time.iso8601"]; got != "1789102842544857414" {
		t.Errorf("evt.time.iso8601 = %q, want the exact integer", got)
	}
	if fields["user.uid"] != "0" || fields["user.loginuid"] != "-1" {
		t.Errorf("numeric fields: user.uid=%q user.loginuid=%q", fields["user.uid"], fields["user.loginuid"])
	}
	// null means Falco had no value. Dropping the key keeps the pod
	// reference empty instead of carrying a literal "null" or "<NA>".
	for _, k := range []string{"k8s.pod.name", "k8s.ns.name", "container.name"} {
		if v, ok := fields[k]; ok {
			t.Errorf("null field %s kept as %q; it should be absent", k, v)
		}
	}
	if ev.Pod.Name != "" || ev.Pod.Namespace != "" {
		t.Errorf("host-only event got a pod reference: %+v", ev.Pod)
	}
	var raw map[string]any
	if err := json.Unmarshal(ev.Raw, &raw); err != nil {
		t.Fatalf("raw is not JSON: %v", err)
	}
	if raw["rule"] != "Read sensitive file untrusted" || raw["source"] != "syscall" || raw["falco_hostname"] != "node-1" {
		t.Errorf("raw envelope wrong: rule=%v source=%v falco_hostname=%v", raw["rule"], raw["source"], raw["falco_hostname"])
	}
}

func TestDecodeHTTPOutput_IsDeterministic(t *testing.T) {
	a, err := DecodeHTTPOutput(fixture(t, "http_output_alert.json"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := DecodeHTTPOutput(fixture(t, "http_output_alert.json"))
	if err != nil {
		t.Fatal(err)
	}
	ea, _ := Translate(a, "n")
	eb, _ := Translate(b, "n")
	if ea.ID != eb.ID || !bytes.Equal(ea.Raw, eb.Raw) {
		t.Error("the same body produced different IDs or Raw bytes; JetStream dedup depends on a stable ID")
	}
}

func TestDecodeHTTPOutput_Rejects(t *testing.T) {
	cases := map[string]string{
		"not json":       `{"rule":`,
		"trailing value": `{"rule":"r","priority":"Warning","time":"2026-09-11T05:00:42Z","output":"o"} {}`,
		"no time":        `{"rule":"r","priority":"Warning","output":"o"}`,
		"bad time":       `{"rule":"r","priority":"Warning","time":"yesterday","output":"o"}`,
		"no rule":        `{"priority":"Warning","time":"2026-09-11T05:00:42Z","output":"o"}`,
		// Copilot review: Decoder.More() is false before a closing
		// delimiter, so these slipped through.
		"trailing brace":   `{"rule":"r","priority":"Warning","time":"2026-09-11T05:00:42Z","output":"o"}}`,
		"trailing bracket": `{"rule":"r","priority":"Warning","time":"2026-09-11T05:00:42Z","output":"o"}]`,
		"array body":       `[]`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeHTTPOutput([]byte(body)); err == nil {
				t.Errorf("accepted %s", body)
			}
		})
	}
}

func TestDecodeHTTPOutput_PriorityNames(t *testing.T) {
	for in, want := range map[string]string{
		"Emergency": "emergency", "Alert": "alert", "Critical": "critical", "Error": "error",
		"Warning": "warning", "Notice": "notice", "Informational": "informational", "Debug": "debug",
		// Falco writes the capitalised form; accept any case rather than
		// silently downgrading a CRITICAL written differently.
		"CRITICAL": "critical", "notice": "notice",
	} {
		body := `{"rule":"r","priority":"` + in + `","time":"2026-09-11T05:00:42Z","output":"o","output_fields":{}}`
		resp, err := DecodeHTTPOutput([]byte(body))
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		ev, err := Translate(resp, "n")
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if ev.Severity != want {
			t.Errorf("priority %q -> severity %q, want %q", in, ev.Severity, want)
		}
	}
	// An unknown priority must not become the enum zero value, which is
	// EMERGENCY.
	resp, err := DecodeHTTPOutput([]byte(`{"rule":"r","priority":"Bogus","time":"2026-09-11T05:00:42Z","output":"o"}`))
	if err != nil {
		t.Fatalf("unknown priority: %v", err)
	}
	if ev, _ := Translate(resp, "n"); ev.Severity == "emergency" {
		t.Error("unknown priority decoded as emergency")
	}
}

// --- New ---------------------------------------------------------------

func TestNew_Validation(t *testing.T) {
	ok := Config{ListenAddr: ":8765", Token: testToken, Hostname: "n"}
	if _, err := New(ok, &recordingPub{}, nil); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for name, mut := range map[string]func(*Config){
		"empty listen addr": func(c *Config) { c.ListenAddr = "" },
		"empty hostname":    func(c *Config) { c.Hostname = "" },
		"empty token":       func(c *Config) { c.Token = "" },
		// The chart generates 32 characters. A short token is almost
		// certainly a placeholder someone forgot to replace.
		"short token":                 func(c *Config) { c.Token = "changeme" },
		"token with a path separator": func(c *Config) { c.Token = testToken + "/x" },
	} {
		t.Run(name, func(t *testing.T) {
			c := ok
			mut(&c)
			if _, err := New(c, &recordingPub{}, nil); err == nil {
				t.Error("accepted")
			}
		})
	}
	if _, err := New(ok, nil, nil); err == nil {
		t.Error("accepted a nil publisher")
	}
}

func TestNew_RateLimitFallbackAndCallerLimiter(t *testing.T) {
	a := newTestAdapter(t, &recordingPub{}, nil)
	if a.Limiter() == nil || a.Limiter().Enabled() {
		t.Error("nil RateLimit should produce a disabled fallback limiter")
	}
	l, err := ratelimit.New(ratelimit.Options{Source: string(schema.SourceFalco), Node: "n", Enabled: true, Threshold: 10, Cooldown: time.Minute, SamplingRate: 0.5})
	if err != nil {
		t.Fatal(err)
	}
	b := newTestAdapter(t, &recordingPub{}, func(c *Config) { c.RateLimit = l })
	if b.Limiter() != l {
		t.Error("caller-supplied limiter was replaced")
	}
}

// --- handler -----------------------------------------------------------

func TestHandler_AcceptsARealAlertAndPublishesIt(t *testing.T) {
	pub := &recordingPub{}
	a := newTestAdapter(t, pub, nil)
	rec := post(t, a, "/falco/"+testToken, "application/json", fixture(t, "http_output_alert.json"))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("code = %d, want 204; body %q", rec.Code, rec.Body.String())
	}
	if pub.count() != 1 || pub.subjects[0] != subjects.RawFalco {
		t.Fatalf("published %d events to %v, want 1 to %s", pub.count(), pub.subjects, subjects.RawFalco)
	}
	if pub.events[0].Pod.Node != "kind-node" {
		t.Errorf("node = %q", pub.events[0].Pod.Node)
	}
	if a.EventsTotal() != 1 || a.AlertsReceivedTotal() != 1 {
		t.Errorf("EventsTotal=%d AlertsReceivedTotal=%d, want 1/1", a.EventsTotal(), a.AlertsReceivedTotal())
	}
	if a.RequestsByCode("204") != 1 {
		t.Errorf("requests{code=204} = %d", a.RequestsByCode("204"))
	}
}

func TestHandler_RejectsWithoutTheToken(t *testing.T) {
	body := fixture(t, "http_output_alert.json")
	for name, path := range map[string]string{
		"wrong token":   "/falco/" + strings.Repeat("x", len(testToken)),
		"token prefix":  "/falco/" + testToken[:16],
		"token + extra": "/falco/" + testToken + "x",
		"no token":      "/falco/",
	} {
		t.Run(name, func(t *testing.T) {
			pub := &recordingPub{}
			a := newTestAdapter(t, pub, nil)
			rec := post(t, a, path, "application/json", body)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("code = %d, want 401", rec.Code)
			}
			if pub.count() != 0 {
				t.Error("an unauthenticated request was published")
			}
			if a.RequestsByCode("401") != 1 {
				t.Errorf("requests{code=401} = %d", a.RequestsByCode("401"))
			}
			// The token must never be echoed back.
			if strings.Contains(rec.Body.String(), testToken) {
				t.Error("response body contains the token")
			}
		})
	}
	a := newTestAdapter(t, &recordingPub{}, nil)
	if rec := post(t, a, "/elsewhere", "application/json", body); rec.Code != http.StatusNotFound {
		t.Errorf("unknown path: code = %d, want 404", rec.Code)
	}
}

func TestHandler_RejectsBadRequests(t *testing.T) {
	path := "/falco/" + testToken
	t.Run("GET", func(t *testing.T) {
		a := newTestAdapter(t, &recordingPub{}, nil)
		rec := httptest.NewRecorder()
		a.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusMethodNotAllowed || a.RequestsByCode("405") != 1 {
			t.Errorf("code = %d, counted %d", rec.Code, a.RequestsByCode("405"))
		}
	})
	t.Run("content type", func(t *testing.T) {
		a := newTestAdapter(t, &recordingPub{}, nil)
		if rec := post(t, a, path, "text/plain", fixture(t, "http_output_alert.json")); rec.Code != http.StatusUnsupportedMediaType {
			t.Errorf("code = %d, want 415 (json_output must be on, or Falco sends plain text)", rec.Code)
		}
	})
	t.Run("oversized", func(t *testing.T) {
		a := newTestAdapter(t, &recordingPub{}, func(c *Config) { c.MaxPayloadBytes = 256 })
		if rec := post(t, a, path, "application/json", fixture(t, "http_output_alert.json")); rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("code = %d, want 413", rec.Code)
		}
	})
	t.Run("malformed", func(t *testing.T) {
		pub := &recordingPub{}
		a := newTestAdapter(t, pub, nil)
		if rec := post(t, a, path, "application/json", []byte(`{"rule":`)); rec.Code != http.StatusBadRequest {
			t.Errorf("code = %d, want 400", rec.Code)
		}
		if pub.count() != 0 {
			t.Error("malformed body was published")
		}
	})
}

func TestHandler_TransientPublishFailureIs503(t *testing.T) {
	pub := &recordingPub{err: errors.New("nats: timeout")}
	a := newTestAdapter(t, pub, nil)
	rec := post(t, a, "/falco/"+testToken, "application/json", fixture(t, "http_output_alert.json"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d, want 503", rec.Code)
	}
	if a.EventsTotal() != 0 {
		t.Error("a failed publish was counted as published")
	}
	if healthy, _ := a.Health().Status(); healthy {
		t.Error("source reported healthy while NATS is refusing publishes")
	}
}

func TestHandler_PermanentPublishFailureDropsWithoutRetryLoop(t *testing.T) {
	pub := &recordingPub{err: errors.New("nats: maximum payload exceeded")}
	a := newTestAdapter(t, pub, nil)
	rec := post(t, a, "/falco/"+testToken, "application/json", fixture(t, "http_output_alert.json"))
	// Falco does not retry, so a non-2xx gains nothing; the drop is logged
	// and counted instead.
	if rec.Code != http.StatusNoContent {
		t.Errorf("code = %d, want 204", rec.Code)
	}
	if a.PublishDrops() != 1 {
		t.Errorf("PublishDrops = %d, want 1", a.PublishDrops())
	}
}

func TestHandler_RateLimitedAlertIsAcceptedAndCounted(t *testing.T) {
	l, err := ratelimit.New(ratelimit.Options{Source: string(schema.SourceFalco), Node: "n", Enabled: true, Threshold: 1, Cooldown: time.Minute, SamplingRate: 0.01})
	if err != nil {
		t.Fatal(err)
	}
	pub := &recordingPub{}
	a := newTestAdapter(t, pub, func(c *Config) { c.RateLimit = l })
	for i := 0; i < 5; i++ {
		body := bytes.Replace(fixture(t, "http_output_alert.json"), []byte("544857414"), []byte("54485741"+string(rune('0'+i))), 1)
		if rec := post(t, a, "/falco/"+testToken, "application/json", body); rec.Code != http.StatusNoContent {
			t.Fatalf("alert %d: code = %d", i, rec.Code)
		}
	}
	if a.DroppedBySampling() == 0 {
		t.Error("an engaged breaker with sampling 0 dropped nothing")
	}
	if int64(pub.count())+a.DroppedBySampling() != 5 {
		t.Errorf("published %d + dropped %d != 5 received", pub.count(), a.DroppedBySampling())
	}
}

// --- heartbeat and health ----------------------------------------------

func TestHandler_MetricsSnapshotIsAHeartbeatNotAnEvent(t *testing.T) {
	pub := &recordingPub{}
	a := newTestAdapter(t, pub, nil)
	if healthy, _ := a.Health().Status(); healthy {
		t.Fatal("healthy before Falco has said anything")
	}
	rec := post(t, a, "/falco/"+testToken, "application/json", fixture(t, "http_output_metrics_snapshot.json"))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("code = %d", rec.Code)
	}
	if pub.count() != 0 {
		t.Error("Falco's internal metrics snapshot was published as a security event")
	}
	if a.HeartbeatsTotal() != 1 {
		t.Errorf("HeartbeatsTotal = %d", a.HeartbeatsTotal())
	}
	if healthy, _ := a.Health().Status(); !healthy {
		t.Error("a heartbeat did not mark the source healthy")
	}
}

func TestHealth_GoesStaleWhenHeartbeatsStop(t *testing.T) {
	now := time.Date(2026, 9, 11, 6, 0, 0, 0, time.UTC)
	a := newTestAdapter(t, &recordingPub{}, func(c *Config) { c.HeartbeatTimeout = 3 * time.Minute })
	a.nowFn = func() time.Time { return now }
	post(t, a, "/falco/"+testToken, "application/json", fixture(t, "http_output_metrics_snapshot.json"))
	a.checkStaleness()
	if healthy, _ := a.Health().Status(); !healthy {
		t.Fatal("fresh heartbeat reported unhealthy")
	}
	now = now.Add(2 * time.Minute)
	a.checkStaleness()
	if healthy, _ := a.Health().Status(); !healthy {
		t.Error("unhealthy inside the timeout")
	}
	now = now.Add(2 * time.Minute)
	a.checkStaleness()
	healthy, lastErr := a.Health().Status()
	if healthy {
		t.Error("still healthy 4 minutes after the last heartbeat with a 3 minute timeout")
	}
	if lastErr == nil || !strings.Contains(lastErr.Error(), "heartbeat") {
		t.Errorf("unhealthy reason should name the missing heartbeat, got %v", lastErr)
	}
	// Real alerts also prove Falco is alive.
	post(t, a, "/falco/"+testToken, "application/json", fixture(t, "http_output_alert.json"))
	a.checkStaleness()
	if healthy, _ := a.Health().Status(); !healthy {
		t.Error("an alert after the gap did not restore health")
	}
}

// --- Run ----------------------------------------------------------------

// TestRun_ServesOverRealHTTP drives the adapter the way Falco does: a real
// TCP listener, a real POST, then a clean shutdown on context cancellation.
func TestRun_ServesOverRealHTTP(t *testing.T) {
	pub := &recordingPub{}
	a := newTestAdapter(t, pub, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	var addr string
	deadline := time.Now().Add(5 * time.Second)
	for addr == "" && time.Now().Before(deadline) {
		addr = a.Addr()
		time.Sleep(10 * time.Millisecond)
	}
	if addr == "" {
		cancel()
		t.Fatal("adapter never bound a listener")
	}
	resp, err := http.Post("http://"+addr+"/falco/"+testToken, "application/json", bytes.NewReader(fixture(t, "http_output_alert.json")))
	if err != nil {
		cancel()
		t.Fatalf("POST: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent || pub.count() != 1 {
		t.Errorf("status %d, published %d", resp.StatusCode, pub.count())
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v on clean shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

func TestRun_ReportsABindFailure(t *testing.T) {
	a := newTestAdapter(t, &recordingPub{}, func(c *Config) { c.ListenAddr = "256.0.0.1:1" })
	if err := a.Run(context.Background()); err == nil {
		t.Error("Run succeeded on an unbindable address")
	}
}

// --- review round 1 ------------------------------------------------------

// Only Falco's metrics snapshot is a heartbeat. Other "internal" events,
// such as "Falco internal: syscall event drop", are security signal (an
// attacker can flood syscalls to blind Falco) and the gRPC path published
// them. The body is the real snapshot fixture with the rule renamed, since
// a drop alert cannot be provoked on demand.
func TestHandler_InternalAlertOtherThanSnapshotIsPublished(t *testing.T) {
	body := bytes.Replace(fixture(t, "http_output_metrics_snapshot.json"),
		[]byte(`"rule":"Falco internal: metrics snapshot"`),
		[]byte(`"rule":"Falco internal: syscall event drop"`), 1)
	if bytes.Equal(body, fixture(t, "http_output_metrics_snapshot.json")) {
		t.Fatal("fixture no longer carries the snapshot rule name")
	}
	pub := &recordingPub{}
	a := newTestAdapter(t, pub, nil)
	if rec := post(t, a, "/falco/"+testToken, "application/json", body); rec.Code != http.StatusNoContent {
		t.Fatalf("code = %d", rec.Code)
	}
	if pub.count() != 1 {
		t.Errorf("syscall-event-drop alert published %d times, want 1", pub.count())
	}
	if a.HeartbeatsTotal() != 0 {
		t.Error("a drop alert was counted as a heartbeat")
	}
}

// A heartbeat proves Falco is alive, not that alerts are getting through.
// While NATS refuses publishes the source must stay unhealthy, however
// many snapshots arrive; a successful publish is what clears it.
func TestHealth_HeartbeatDoesNotMaskPublishFailure(t *testing.T) {
	pub := &recordingPub{err: errors.New("nats: timeout")}
	a := newTestAdapter(t, pub, nil)
	snap := fixture(t, "http_output_metrics_snapshot.json")
	alert := fixture(t, "http_output_alert.json")

	post(t, a, "/falco/"+testToken, "application/json", snap)
	if healthy, _ := a.Health().Status(); !healthy {
		t.Fatal("first heartbeat did not mark healthy")
	}
	if rec := post(t, a, "/falco/"+testToken, "application/json", alert); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("alert code = %d, want 503", rec.Code)
	}
	post(t, a, "/falco/"+testToken, "application/json", snap)
	if healthy, _ := a.Health().Status(); healthy {
		t.Error("a heartbeat marked the source healthy while NATS is still refusing publishes")
	}

	pub.mu.Lock()
	pub.err = nil
	pub.mu.Unlock()
	post(t, a, "/falco/"+testToken, "application/json", alert)
	if healthy, _ := a.Health().Status(); !healthy {
		t.Error("a successful publish did not restore health")
	}
}

// Shutdown must outlast the detached publish budget, or main.go drains NATS
// under a handler still inside PublishJS.
func TestNew_ShutdownGraceCoversThePublishBudget(t *testing.T) {
	a := newTestAdapter(t, &recordingPub{}, nil)
	if a.cfg.ShutdownGrace <= a.cfg.PublishWallClockBudget {
		t.Errorf("ShutdownGrace %s <= PublishWallClockBudget %s", a.cfg.ShutdownGrace, a.cfg.PublishWallClockBudget)
	}
	b := newTestAdapter(t, &recordingPub{}, func(c *Config) {
		c.ShutdownGrace = time.Second
		c.PublishWallClockBudget = 10 * time.Second
	})
	if b.cfg.ShutdownGrace <= b.cfg.PublishWallClockBudget {
		t.Errorf("an explicit ShutdownGrace below the publish budget was kept: %s <= %s", b.cfg.ShutdownGrace, b.cfg.PublishWallClockBudget)
	}
}

// Copilot review: net/http runs handlers concurrently. The publish and the
// health update must stay sequenced, or a late failed publish can overwrite
// health after a later success. Many concurrent alerts against a publisher
// that fails every other call must leave health consistent with the LAST
// publish outcome.
func TestHandler_ConcurrentAlertsKeepHealthSequenced(t *testing.T) {
	pub := &togglePub{}
	a := newTestAdapter(t, pub, nil)
	body := fixture(t, "http_output_alert.json")
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			post(t, a, "/falco/"+testToken, "application/json", body)
		}()
	}
	wg.Wait()
	if pub.maxInFlight() > 1 {
		t.Errorf("%d publishes ran at once; the publish path must be sequential", pub.maxInFlight())
	}
	healthy, _ := a.Health().Status()
	if last := pub.lastOK(); healthy != last {
		t.Errorf("health=%v but the last publish ok=%v", healthy, last)
	}
}

// togglePub fails every other publish and records how many run at once.
type togglePub struct {
	mu       sync.Mutex
	n        int
	inFlight int
	peak     int
	last     bool
}

func (p *togglePub) PublishJS(_ context.Context, _ string, _ any, _ ...natsjs.PublishOpt) (*natsjs.PubAck, error) {
	p.mu.Lock()
	p.inFlight++
	if p.inFlight > p.peak {
		p.peak = p.inFlight
	}
	p.n++
	ok := p.n%2 == 0
	p.mu.Unlock()
	time.Sleep(time.Millisecond)
	p.mu.Lock()
	p.inFlight--
	p.last = ok
	p.mu.Unlock()
	if !ok {
		return nil, errors.New("nats: timeout")
	}
	return &natsjs.PubAck{}, nil
}

func (p *togglePub) maxInFlight() int { p.mu.Lock(); defer p.mu.Unlock(); return p.peak }
func (p *togglePub) lastOK() bool     { p.mu.Lock(); defer p.mu.Unlock(); return p.last }

// --- Story 10.3: canonical field projection -------------------------------

// The OLT rules name fields canonically (process.exe, file.path,
// user.username, network.dst_ip ...), and the rules resolver reads the
// top-level keys of Event.Raw. Falco's fields lived only inside
// output_fields, so no OLT rule could ever match a real Falco event
// (deferred "BI-1" since Story 1.16). Translate now projects them.
func TestTranslate_ProjectsCanonicalFieldsFromARealAlert(t *testing.T) {
	resp, err := DecodeHTTPOutput(fixture(t, "http_output_alert.json"))
	if err != nil {
		t.Fatal(err)
	}
	ev, err := Translate(resp, "kind-node")
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(ev.Raw, &raw); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{
		"process.exe":     "/bin/cat",
		"process.name":    "cat",
		"process.cmdline": "cat /etc/shadow",
		"process.parent":  "sh",
		"file.path":       "/etc/shadow",
		"user.username":   "root",
		"user.uid":        "0",
		"container.id":    "26f85eff83d7",
	} {
		if raw[k] != want {
			t.Errorf("Raw[%q] = %v, want %q", k, raw[k], want)
		}
	}
	// The event has no network endpoint, so no network key is invented.
	for _, k := range []string{"network.dst_ip", "network.dst_port"} {
		if _, ok := raw[k]; ok {
			t.Errorf("Raw has %s for a file event", k)
		}
	}
	// Falco's own fields stay, for forensics and existing consumers.
	if _, ok := raw["output_fields"]; !ok {
		t.Error("output_fields was dropped")
	}
}

func TestTranslate_ProjectsNetworkFieldsAndNotSocketNamesAsFiles(t *testing.T) {
	body := []byte(`{"hostname":"n","output":"o","priority":"Notice","rule":"Outbound","source":"syscall","time":"2026-09-11T05:00:42Z",` +
		`"output_fields":{"fd.name":"10.244.0.5:40000->169.254.169.254:80","fd.sip":"169.254.169.254","fd.sport":80,"fd.l4proto":"tcp","proc.exepath":"/usr/bin/curl"}}`)
	resp, err := DecodeHTTPOutput(body)
	if err != nil {
		t.Fatal(err)
	}
	ev, _ := Translate(resp, "n")
	var raw map[string]any
	_ = json.Unmarshal(ev.Raw, &raw)
	if raw["network.dst_ip"] != "169.254.169.254" || raw["network.dst_port"] != "80" || raw["network.protocol"] != "tcp" {
		t.Errorf("network projection = %v / %v / %v", raw["network.dst_ip"], raw["network.dst_port"], raw["network.protocol"])
	}
	if _, ok := raw["file.path"]; ok {
		t.Errorf("a socket name was projected as file.path: %v", raw["file.path"])
	}
}
