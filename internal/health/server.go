// Package health provides the Kubernetes-probe-facing HTTP /healthz
// server that kubelet uses to decide whether an Olaitan pod is alive
// and ready to receive traffic.
//
// Scope: this package ONLY serves the HTTP surface (liveness and
// readiness probes). The separate ring-health-reporting-over-NATS
// channel described in architecture.md:941 (HealthStatus struct
// published on olaitan.health.<ring>) belongs to Story 8.1 — do NOT
// conflate the two. That channel is about inter-ring observability;
// this one is about keeping kubelet from restart-looping the pod.
//
// Lifecycle: the server is single-shot. Start blocks until the supplied
// context is cancelled, then returns nil; a second Start on the same
// instance returns ErrServerRunning rather than racing two listeners.
//
// Error wrapping follows the repo convention: every exported boundary
// returns errors prefixed "health:" wrapping the underlying cause, so
// callers can grep logs and use errors.Is for sentinels.
package health

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// ErrServerRunning is returned by Server.Start when a second concurrent
// Start is attempted on the same Server. Construct a fresh Server (via
// New) to re-start after a previous Start has returned.
var ErrServerRunning = errors.New("health: server already running")

// shutdownTimeout caps Shutdown's wait for inflight requests on SIGTERM.
// Kubelet's default terminationGracePeriodSeconds is 30s; 5s leaves the
// rest of the graceful-shutdown budget (config watcher teardown, NATS
// drain in future rings) comfortably.
const shutdownTimeout = 5 * time.Second

// Server is a single-shot HTTP server serving /healthz on addr. Safe
// to construct with New even if Start is never called — the zero cost
// is a few bytes and no goroutines.
type Server struct {
	addr    string
	log     *slog.Logger
	srv     *http.Server
	running atomic.Bool
}

// New returns a Server bound to addr. addr follows net.Listen
// conventions (":8080" for all interfaces). log may be nil — in that
// case slog.Default() is used so callers can construct before their
// logger is wired.
func New(addr string, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{addr: addr, log: log}
}

// Start binds the listener, serves /healthz, and blocks on ctx. On
// ctx.Done it initiates a graceful shutdown (shutdownTimeout budget)
// and returns nil. Returns ErrServerRunning if a Start is already in
// flight, or a wrapped error if the listener fails to bind.
//
// Nil receiver is a silent no-op returning nil, mirroring the
// convention in internal/config (Manager.Watch on nil).
func (s *Server) Start(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if !s.running.CompareAndSwap(false, true) {
		return ErrServerRunning
	}
	defer s.running.Store(false)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)

	// Bind the listener explicitly so the caller gets a synchronous
	// "address already in use" error instead of it racing in the
	// background goroutine. ListenAndServe hides that failure mode.
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("health: listen %q: %w", s.addr, err)
	}

	s.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	serveErrCh := make(chan error, 1)
	go func() {
		if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErrCh <- fmt.Errorf("health: serve: %w", err)
			return
		}
		serveErrCh <- nil
	}()

	s.log.Info("health: listening", "addr", s.addr)

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := s.srv.Shutdown(shutdownCtx); err != nil {
			s.log.Error("health: shutdown", "err", err)
		}
		// Drain the serve goroutine before returning; otherwise it could
		// leak past the server's lifetime and race with the next Start.
		<-serveErrCh
		return nil
	case err := <-serveErrCh:
		return err
	}
}

// Shutdown stops the server if it is running. Idempotent: a second
// Shutdown is a silent no-op; a Shutdown on a never-Started server is
// likewise a no-op. Nil-receiver safe.
func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil || s.srv == nil {
		return nil
	}
	if err := s.srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("health: shutdown: %w", err)
	}
	return nil
}

// handleHealthz is the kubelet-facing handler. 200 + JSON body is
// enough for a liveness/readiness probe; the body is a sanity-check
// hook for `kubectl exec -- wget -qO- http://localhost:8080/healthz`
// during incident response.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// json.NewEncoder is slightly cheaper than Marshal + Write for a
	// fixed-shape payload; the body is small enough that the difference
	// is immaterial, but the signature is cleaner.
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
