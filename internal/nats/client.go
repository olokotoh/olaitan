package nats

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// ClientConfig holds NATS connection settings.
type ClientConfig struct {
	URL           string
	Name          string
	MaxReconnects int
	ReconnectWait time.Duration
}

// DefaultConfig returns sensible defaults for NATS connection.
func DefaultConfig() ClientConfig {
	return ClientConfig{
		URL:           nats.DefaultURL,
		Name:          "olaitan",
		MaxReconnects: -1, // unlimited
		ReconnectWait: 2 * time.Second,
	}
}

// Client wraps a NATS connection with publish/subscribe helpers and JetStream access.
type Client struct {
	conn *nats.Conn
	js   jetstream.JetStream
}

// NewClient connects to NATS and initialises JetStream.
func NewClient(cfg ClientConfig) (*Client, error) {
	opts := []nats.Option{
		nats.Name(cfg.Name),
		nats.MaxReconnects(cfg.MaxReconnects),
		nats.ReconnectWait(cfg.ReconnectWait),
		nats.ReconnectBufSize(8 * 1024 * 1024), // 8MB buffer during reconnect
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

// Publish marshals data as JSON and publishes to the given subject.
func (c *Client) Publish(subject string, data any) error {
	bytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("nats: marshal: %w", err)
	}
	if err := c.conn.Publish(subject, bytes); err != nil {
		return fmt.Errorf("nats: publish %s: %w", subject, err)
	}
	return nil
}

// Subscribe registers a handler for messages on the given subject.
// The handler receives raw message data. Cancelling the context initiates a
// graceful drain: in-flight messages may still be delivered before the
// subscription is fully removed.
func (c *Client) Subscribe(ctx context.Context, subject string, handler func([]byte)) error {
	sub, err := c.conn.Subscribe(subject, func(msg *nats.Msg) {
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
func (c *Client) JetStream() jetstream.JetStream {
	return c.js
}

// Conn returns the underlying NATS connection.
func (c *Client) Conn() *nats.Conn {
	return c.conn
}

// Close drains and closes the NATS connection.
// If drain fails, it falls back to a hard close.
func (c *Client) Close() {
	if err := c.conn.Drain(); err != nil {
		slog.Warn("nats: drain failed, forcing close", "err", err)
		c.conn.Close()
	}
}
