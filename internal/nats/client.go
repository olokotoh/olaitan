package nats

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// ErrClientClosed is returned when a method is called on a Client whose
// connection is nil or closed.
var ErrClientClosed = errors.New("nats: client is closed")

// ClientConfig holds NATS connection settings.
// TLS configuration is not yet wired here — see deferred security story
// tracked in deferred-work.md for mTLS introduction under Epic 1.
type ClientConfig struct {
	URL              string
	Name             string
	MaxReconnects    int
	ReconnectWait    time.Duration
	ReconnectBufSize int // bytes buffered during reconnect; 0 uses NATS default
}

// DefaultConfig returns sensible defaults for NATS connection.
func DefaultConfig() ClientConfig {
	return ClientConfig{
		URL:              nats.DefaultURL,
		Name:             "olaitan",
		MaxReconnects:    -1, // unlimited
		ReconnectWait:    2 * time.Second,
		ReconnectBufSize: 8 * 1024 * 1024, // 8 MiB
	}
}

// Client wraps a NATS connection with publish/subscribe helpers and JetStream access.
type Client struct {
	conn *nats.Conn
	js   jetstream.JetStream
}

// NewClient connects to NATS and initialises JetStream.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.URL == "" {
		return nil, errors.New("nats: config: url is empty")
	}
	if cfg.ReconnectWait < 0 {
		return nil, errors.New("nats: config: reconnect-wait must be non-negative")
	}
	if cfg.ReconnectBufSize < 0 {
		return nil, errors.New("nats: config: reconnect-buf-size must be non-negative")
	}

	opts := []nats.Option{
		nats.Name(cfg.Name),
		nats.MaxReconnects(cfg.MaxReconnects),
		nats.ReconnectWait(cfg.ReconnectWait),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			slog.Warn("nats: disconnected", "err", err)
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			slog.Info("nats: reconnected", "url", nc.ConnectedUrl())
		}),
		nats.ClosedHandler(func(_ *nats.Conn) {
			slog.Info("nats: connection closed")
		}),
	}
	if cfg.ReconnectBufSize > 0 {
		opts = append(opts, nats.ReconnectBufSize(cfg.ReconnectBufSize))
	}

	nc, err := nats.Connect(cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("nats: connect: %w", err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("nats: jetstream: %w", err)
	}

	return &Client{conn: nc, js: js}, nil
}

// Publish marshals data as JSON and publishes to the given subject via core NATS.
// Use PublishJS for subjects covered by a JetStream stream to obtain a PubAck.
func (c *Client) Publish(subject string, data any) error {
	if c == nil || c.conn == nil {
		return ErrClientClosed
	}
	bytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("nats: marshal %q: %w", subject, err)
	}
	if err := c.conn.Publish(subject, bytes); err != nil {
		return fmt.Errorf("nats: publish %s: %w", subject, err)
	}
	return nil
}

// PublishJS publishes to a JetStream-backed subject and returns the PubAck,
// giving callers the at-least-once contract that core Publish cannot.
func (c *Client) PublishJS(ctx context.Context, subject string, data any) (*jetstream.PubAck, error) {
	if c == nil || c.js == nil {
		return nil, ErrClientClosed
	}
	bytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("nats: marshal %q: %w", subject, err)
	}
	ack, err := c.js.Publish(ctx, subject, bytes)
	if err != nil {
		return nil, fmt.Errorf("nats: publish-js %s: %w", subject, err)
	}
	return ack, nil
}

// Subscribe registers a handler for messages on the given subject.
// The handler is invoked on the NATS delivery goroutine; panics are recovered
// and logged to prevent one bad handler from crashing the process.
// Cancelling the context initiates a graceful drain: in-flight messages may
// still be delivered before the subscription is fully removed.
func (c *Client) Subscribe(ctx context.Context, subject string, handler func([]byte)) error {
	if c == nil || c.conn == nil {
		return ErrClientClosed
	}
	sub, err := c.conn.Subscribe(subject, func(msg *nats.Msg) {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("nats: subscribe handler panic",
					"subject", subject, "panic", r)
			}
		}()
		handler(msg.Data)
	})
	if err != nil {
		return fmt.Errorf("nats: subscribe %s: %w", subject, err)
	}

	go func() {
		<-ctx.Done()
		if err := sub.Drain(); err != nil {
			slog.Warn("nats: drain", "subject", subject, "err", err)
		}
	}()

	return nil
}

// JetStream returns the JetStream interface for advanced operations.
// Escape hatch: callers using this directly must uphold the wrapper's
// error-wrapping contract (`fmt.Errorf("nats: action: %w", err)`) themselves.
func (c *Client) JetStream() jetstream.JetStream {
	if c == nil {
		return nil
	}
	return c.js
}

// Conn returns the underlying NATS connection.
// Escape hatch: see JetStream.
func (c *Client) Conn() *nats.Conn {
	if c == nil {
		return nil
	}
	return c.conn
}

// Close drains and closes the NATS connection, honouring the context deadline
// for the drain wait. Returns a wrapped error if drain fails or the context
// expires before drain completes; falls back to a hard close in either case.
// Safe to call on a nil or already-closed client.
func (c *Client) Close(ctx context.Context) error {
	if c == nil || c.conn == nil || c.conn.IsClosed() {
		return nil
	}
	if err := c.conn.Drain(); err != nil {
		c.conn.Close()
		return fmt.Errorf("nats: close: %w", err)
	}
	for c.conn.Status() != nats.CLOSED {
		select {
		case <-ctx.Done():
			c.conn.Close()
			return fmt.Errorf("nats: close: %w", ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	return nil
}
