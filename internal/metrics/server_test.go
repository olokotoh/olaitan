package metrics_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/metrics"
)

// pickFreePort asks the kernel for a free port, closes the listener,
// and returns "127.0.0.1:<port>". Small race window between close and
// the server bind, acceptable for this test scope.
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

func waitForMetrics(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr + "/metrics")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("metrics server at %s did not become ready", addr)
}

func serverQuietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestServer_Start_ServesMetrics(t *testing.T) {
	t.Parallel()

	addr := pickFreePort(t)
	reg := metrics.NewRegistry()
	s := metrics.New(addr, serverQuietLogger(), reg)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	errCh := make(chan error, 1)
	go func() { errCh <- s.Start(ctx) }()

	waitForMetrics(t, addr)

	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Errorf("content-type: got %q, want text/plain prefix", ct)
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Errorf("Start returned %v on ctx cancel, want nil", err)
	}
}

func TestServer_Start_DoubleStartRejected(t *testing.T) {
	t.Parallel()

	addr := pickFreePort(t)
	s := metrics.New(addr, serverQuietLogger(), metrics.NewRegistry())
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	go func() { _ = s.Start(ctx) }()
	time.Sleep(50 * time.Millisecond)

	err := s.Start(ctx)
	if !errors.Is(err, metrics.ErrServerRunning) {
		t.Errorf("second Start: got %v, want ErrServerRunning", err)
	}
}

func TestServer_Start_NilRegistryRejected(t *testing.T) {
	t.Parallel()
	s := metrics.New(pickFreePort(t), serverQuietLogger(), nil)
	if err := s.Start(t.Context()); !errors.Is(err, metrics.ErrNilRegistry) {
		t.Errorf("Start with nil Registry: got %v, want ErrNilRegistry", err)
	}
}

func TestServer_Start_ListenFailure(t *testing.T) {
	t.Parallel()

	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer func() { _ = occupied.Close() }()

	s := metrics.New(occupied.Addr().String(), serverQuietLogger(), metrics.NewRegistry())
	err = s.Start(t.Context())
	if err == nil {
		t.Fatalf("Start: got nil, want listen error")
	}
	if !strings.HasPrefix(err.Error(), "metrics: ") {
		t.Errorf("Start error not prefixed with 'metrics: ': %v", err)
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		t.Errorf("Start error does not unwrap to *net.OpError: %v", err)
	}
}

func TestServer_Start_ReturnsOnContextCancel(t *testing.T) {
	t.Parallel()

	s := metrics.New(pickFreePort(t), serverQuietLogger(), metrics.NewRegistry())
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.Start(ctx) }()

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

func TestServer_NilReceiver(t *testing.T) {
	t.Parallel()
	var s *metrics.Server
	if err := s.Start(t.Context()); err != nil {
		t.Errorf("nil-receiver Start: got %v, want nil", err)
	}
	if err := s.Shutdown(t.Context()); err != nil {
		t.Errorf("nil-receiver Shutdown: got %v, want nil", err)
	}
	if addr := s.Addr(); addr != "" {
		t.Errorf("nil-receiver Addr: got %q, want empty", addr)
	}
}

func TestServer_Shutdown_BeforeStart(t *testing.T) {
	t.Parallel()
	s := metrics.New(pickFreePort(t), serverQuietLogger(), metrics.NewRegistry())
	if err := s.Shutdown(t.Context()); err != nil {
		t.Errorf("pre-Start Shutdown: got %v, want nil", err)
	}
}
