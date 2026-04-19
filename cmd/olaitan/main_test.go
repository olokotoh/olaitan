package main

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTestConfig drops a minimal valid olaitan.yaml into t.TempDir()
// so runRing has something config.NewManager can load without network.
// Keep the fields aligned with internal/config/config.go validation.
func writeTestConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "olaitan.yaml")
	body := `detection:
  confidence_bands:
    watch: 40
    alert: 70
    act: 90
  baseline_window: 24h
response:
  excluded_namespaces:
    - kube-system
analyst:
  provider: api
  api:
    endpoint: ""
    model: ""
    api_key_secret: olaitan-llm
  local:
    endpoint: ""
    model: ""
  score_cap: 35
  timeout: 10s
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write test config: %v", err)
	}
	return path
}

// pickFreePort mirrors the health package's helper — duplicated
// because main_test is package main and cannot import internal test
// utilities without exposing them publicly.
func pickFreePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pickFreePort: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func TestVersion(t *testing.T) {
	if version == "" {
		t.Error("version should not be empty")
	}
}

func TestRun_NoArgs_PrintsUsageAndExits1(t *testing.T) {
	code := run(nil, os.Stderr)
	if code != 1 {
		t.Errorf("exit code: got %d want 1", code)
	}
}

func TestRun_UnknownCommand_Exits2(t *testing.T) {
	code := run([]string{"not-a-real-command"}, os.Stderr)
	if code != 2 {
		t.Errorf("exit code: got %d want 2", code)
	}
}

func TestRun_Version_Exits0(t *testing.T) {
	if code := run([]string{"version"}, os.Stderr); code != 0 {
		t.Errorf("version exit code: got %d want 0", code)
	}
}

func TestRun_Help_Exits0(t *testing.T) {
	for _, arg := range []string{"help", "-h", "--help"} {
		if code := run([]string{arg}, os.Stderr); code != 0 {
			t.Errorf("%q exit code: got %d want 0", arg, code)
		}
	}
}

func TestRunRing_MissingConfig_Exits1(t *testing.T) {
	// Point --config at a path that does not exist — config.NewManager
	// must fail and runRing must map that to exit 1.
	code := runRing("collector", []string{"--config=/nonexistent/path/olaitan.yaml"}, os.Stderr)
	if code != 1 {
		t.Errorf("exit code on missing config: got %d want 1", code)
	}
}

func TestRunRing_GracefulShutdown(t *testing.T) {
	// Swap healthAddr to a free port for this test — production uses
	// :8080 which tests mustn't bind. Restore after.
	prevAddr := healthAddr
	healthAddr = pickFreePort(t)
	t.Cleanup(func() { healthAddr = prevAddr })

	cfgPath := writeTestConfig(t)

	// Start runRing in a goroutine. Send ourselves SIGTERM after the
	// health server has bound, and assert runRing returns 0 (graceful).
	done := make(chan int, 1)
	go func() {
		done <- runRing("aggregator", []string{"--config=" + cfgPath}, os.Stderr)
	}()

	// Poll until /healthz responds, proving the server is live.
	readyBy := time.Now().Add(3 * time.Second)
	for time.Now().Before(readyBy) {
		resp, err := http.Get("http://" + healthAddr + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				goto READY
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("health server never became ready at %s", healthAddr)
READY:

	// signal.NotifyContext in runRing listens for SIGINT+SIGTERM; send
	// SIGTERM to this process to trigger graceful shutdown.
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	if err := p.Signal(os.Interrupt); err != nil {
		t.Fatalf("signal: %v", err)
	}

	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("runRing exit code after SIGINT: got %d want 0", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("runRing did not exit within 5s of SIGINT")
	}
}
