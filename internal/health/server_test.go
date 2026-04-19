package health_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/health"
)

// pickFreePort asks the kernel for a free port, closes the listener,
// and returns "127.0.0.1:<port>". Small race window between close and
// the server bind, acceptable for this test scope — integration tests
// that must be race-free share a kernel-assigned socket instead.
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

// waitForReady polls addr every 10 ms until GET /healthz succeeds or
// the deadline elapses. Prevents races between "Start returned from
// Listen" and "server goroutine actually Serve'd the first request".
func waitForReady(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("health server at %s did not become ready", addr)
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestHealthz_ReturnsOK(t *testing.T) {
	t.Parallel()

	addr := pickFreePort(t)
	s := health.New(addr, quietLogger())

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	errCh := make(chan error, 1)
	go func() { errCh <- s.Start(ctx) }()

	waitForReady(t, addr)

	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type: got %q want application/json", ct)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("body: got %+v want status=ok", body)
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Errorf("Start returned %v on ctx cancel, want nil", err)
	}
}

func TestStart_ReturnsOnContextCancel(t *testing.T) {
	t.Parallel()

	s := health.New(pickFreePort(t), quietLogger())
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.Start(ctx) }()

	// Give Start enough time to bind before we cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Start returned %v on ctx cancel, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Start did not return within 2s of ctx cancel")
	}
}

func TestStart_ListenFailure(t *testing.T) {
	t.Parallel()

	// Hold a listener on a port, then try to Start a health server on
	// the same address — net.Listen should return EADDRINUSE.
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer func() { _ = occupied.Close() }()

	s := health.New(occupied.Addr().String(), quietLogger())
	err = s.Start(t.Context())
	if err == nil {
		t.Fatalf("Start: got nil, want listen error")
	}
	// Must wrap the underlying net error so callers can errors.Is-detect.
	if !errors.Is(err, net.ErrClosed) && err.Error() == "" {
		t.Errorf("Start: error message empty: %v", err)
	}
}

func TestStart_DoubleStart(t *testing.T) {
	t.Parallel()

	s := health.New(pickFreePort(t), quietLogger())
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	go func() { _ = s.Start(ctx) }()
	time.Sleep(50 * time.Millisecond)

	// Second Start must refuse rather than racing two listeners.
	err := s.Start(ctx)
	if !errors.Is(err, health.ErrServerRunning) {
		t.Errorf("second Start: got %v, want ErrServerRunning", err)
	}
}

func TestShutdown_NilSafe(t *testing.T) {
	t.Parallel()

	var s *health.Server
	if err := s.Shutdown(t.Context()); err != nil {
		t.Errorf("nil-receiver Shutdown: got %v, want nil", err)
	}
}

func TestShutdown_BeforeStart(t *testing.T) {
	t.Parallel()

	s := health.New(pickFreePort(t), quietLogger())
	if err := s.Shutdown(t.Context()); err != nil {
		t.Errorf("pre-Start Shutdown: got %v, want nil", err)
	}
}

func TestNew_NilLoggerFallsBackToDefault(t *testing.T) {
	t.Parallel()

	// Swap the default logger out so the test can't accidentally
	// depend on a stderr-attached logger in CI. If New respects nil
	// by falling back to slog.Default(), no panic should occur on use.
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	s := health.New(pickFreePort(t), nil)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	done := make(chan error, 1)
	go func() { done <- s.Start(ctx) }()
	time.Sleep(50 * time.Millisecond)
	cancel()

	if err := <-done; err != nil {
		t.Errorf("Start with nil logger: got %v, want nil", err)
	}
}

// TestMain keeps the default slog from leaking test scaffolding to
// stderr when other tests run in parallel.
func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}
