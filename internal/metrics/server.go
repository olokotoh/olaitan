package metrics

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// ErrServerRunning is returned by Server.Start when a second concurrent
// Start is attempted on the same Server. Construct a fresh Server (via
// New) to re-start after a previous Start has returned.
var ErrServerRunning = errors.New("metrics: server already running")

// shutdownTimeout caps Shutdown's wait for inflight requests on SIGTERM.
// Mirrors the budget in internal/health.Server so the kubelet probe and
// the Prometheus scrape surface drain in roughly the same time window.
const shutdownTimeout = 5 * time.Second

// Server serves the Prometheus /metrics endpoint on addr. Lifecycle is
// modelled on internal/health.Server: single-shot Start that blocks
// until ctx is cancelled then graceful-shutdown with shutdownTimeout
// budget. Two Servers (this one and internal/health.Server) run in
// parallel under the same errgroup in cmd/olaitan/main.go.
type Server struct {
	addr string
	log  *slog.Logger
	reg  *Registry
	mu   sync.Mutex
	srv  *http.Server
	// boundAddr is the listener's actual address after a successful
	// Listen. Tests that bind to ":0" read this through Addr() to
	// discover the kernel-assigned port without racing the server
	// goroutine.
	boundAddr string
	running   atomic.Bool
}

// New constructs a Server bound to addr ("0.0.0.0:9090" or ":9090" for
// all interfaces). log may be nil (slog.Default() is substituted).
// reg must be non-nil; a nil Registry would expose no metrics, which
// is never useful and would mask a wiring bug.
func New(addr string, log *slog.Logger, reg *Registry) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{addr: addr, log: log, reg: reg}
}

// Start binds the listener, mounts /metrics on the Registry's handler,
// and blocks on ctx. On ctx.Done it initiates a graceful shutdown
// (shutdownTimeout budget) and returns nil. Returns ErrServerRunning if
// a Start is already in flight, ErrNilRegistry if the Server was
// constructed with a nil Registry, or a wrapped error if the listener
// fails to bind.
//
// Nil receiver is a silent no-op returning nil, mirroring the
// convention in internal/health and internal/config.
func (s *Server) Start(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if s.reg == nil {
		return ErrNilRegistry
	}
	if !s.running.CompareAndSwap(false, true) {
		return ErrServerRunning
	}
	defer s.running.Store(false)

	mux := http.NewServeMux()
	mux.Handle("/metrics", s.reg.Handler())

	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("metrics: listen %q: %w", s.addr, err)
	}

	s.mu.Lock()
	s.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	s.boundAddr = ln.Addr().String()
	s.mu.Unlock()

	serveErrCh := make(chan error, 1)
	go func() {
		if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErrCh <- fmt.Errorf("metrics: serve: %w", err)
			return
		}
		serveErrCh <- nil
	}()

	s.log.Info("metrics: listening", "addr", s.addr)

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		s.mu.Lock()
		srv := s.srv
		s.mu.Unlock()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			s.log.Error("metrics: shutdown", "err", err)
		}
		<-serveErrCh
		s.mu.Lock()
		s.srv = nil
		s.mu.Unlock()
		return nil
	case err := <-serveErrCh:
		s.mu.Lock()
		s.srv = nil
		s.mu.Unlock()
		return err
	}
}

// Addr returns the listener address; useful in tests that bind to
// "127.0.0.1:0" and need the kernel-assigned port to make requests.
// Returns the empty string before Start has bound or after Shutdown.
func (s *Server) Addr() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.srv == nil {
		return ""
	}
	return s.boundAddr
}

// Shutdown stops the server if it is running. Idempotent: a second
// Shutdown is a silent no-op; a Shutdown on a never-Started server is
// likewise a no-op. Nil-receiver safe.
func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	srv := s.srv
	s.mu.Unlock()
	if srv == nil {
		return nil
	}
	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("metrics: shutdown: %w", err)
	}
	return nil
}
