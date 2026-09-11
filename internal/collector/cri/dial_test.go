package cri

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/retry"
)

// Story 10.9, found live: with the containerd socket unreadable, the
// adapter logged "cri: adapter stopped" 10 seconds after starting and never
// tried again. defaultDial waited for Ready until its deadline and returned
// a context.DeadlineExceeded; retry.Do treats that as cancellation and
// stops, and Run treated it as a clean shutdown. A permission problem, a
// missing socket or containerd restarting at boot silently killed the
// sensor for the life of the pod.

func TestDefaultDial_PermissionIsReportedAsPermission(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses socket permissions")
	}
	sock := filepath.Join(t.TempDir(), "containerd.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	if err := os.Chmod(sock, 0o000); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = defaultDial(ctx, criDialTarget(sock))
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("err = %v, want fs.ErrPermission so the failure is named and terminal", err)
	}
	if !isTerminalConnectError(err) {
		t.Error("a permission error is not classified terminal")
	}
}

// silentSocket accepts connections and never speaks, so gRPC never reaches
// Ready and the real dial runs into its own deadline. It counts accepts.
func silentSocket(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "silent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var accepts atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			go func() { time.Sleep(5 * time.Second); _ = c.Close() }()
		}
	}()
	return sock, &accepts
}

func TestDefaultDial_TimeoutIsRetryableNotACancellation(t *testing.T) {
	sock, _ := silentSocket(t)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err := defaultDial(ctx, criDialTarget(sock))
	if err == nil {
		t.Fatal("dial to a silent socket reached Ready")
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		t.Errorf("err = %v wraps a context error; retry.Do would stop and Run would call it a clean shutdown", err)
	}
	if isTerminalConnectError(err) {
		t.Errorf("a dial timeout is terminal: %v", err)
	}
	missing := filepath.Join(t.TempDir(), "missing.sock")
	if _, err := defaultDial(ctx, criDialTarget(missing)); err == nil || isTerminalConnectError(err) || errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("missing socket: err = %v, want a retryable non-context error", err)
	}
}

// TestRun_KeepsRetryingWhileTheParentContextIsAlive drives Run with the REAL
// dial against a socket that never becomes Ready: the adapter must keep
// dialling until its own context ends, then return nil.
func TestRun_KeepsRetryingWhileTheParentContextIsAlive(t *testing.T) {
	sock, accepts := silentSocket(t)
	a, err := New(Config{
		SocketPath:   sock,
		Hostname:     "n",
		DialTimeout:  20 * time.Millisecond,
		ConnectRetry: retry.Strategy{Min: time.Millisecond, Max: 2 * time.Millisecond, Multiplier: 1, MaxAttempts: 0},
	}, &stubPublisher{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	if err := a.Run(ctx); err != nil {
		t.Errorf("Run = %v after its context ended, want nil", err)
	}
	if accepts.Load() < 4 {
		t.Errorf("only %d connection attempts in 400ms; the adapter gave up after the first dial timeout", accepts.Load())
	}
}
