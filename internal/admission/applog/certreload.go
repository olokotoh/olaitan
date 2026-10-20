package applog

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// DefaultCertReloadInterval is how often the injector re-reads its serving
// cert and key when WebhookConfig.CertReloadInterval is zero. The kubelet
// refreshes a mounted Secret on its own sync period plus its Secret cache
// delay (one to two minutes), so a few seconds here adds nothing noticeable
// to a rotation.
const DefaultCertReloadInterval = 10 * time.Second

// MinCertReloadInterval is the floor for CertReloadInterval: a smaller value
// turns the poll into a busy loop of file reads for no gain.
const MinCertReloadInterval = time.Second

// certReloader serves the injector's TLS certificate through
// tls.Config.GetCertificate and re-reads the key pair from disk on an
// interval (#157). A renewed Secret (cert-manager Path A, the certgen Job, or
// a Path B helm upgrade before the pods roll) reaches the mounted files
// through the kubelet's atomic ..data symlink swap; the running injector
// serves it on the next handshake after the next poll, with no restart.
//
// Polling, not inotify: the kubelet replaces the ..data symlink, so a watch
// on tls.crt itself sees no event, and a directory watch adds a dependency
// for no gain at this interval. A pair that does not parse, does not match,
// or whose leaf is not valid now (expired or not yet valid) is skipped and
// the last good pair keeps serving. A failure is logged when it first
// appears or changes, not on every tick, and a recovery is logged once.
type certReloader struct {
	certFile, keyFile string
	log               *slog.Logger
	now               func() time.Time

	mu      sync.RWMutex
	cert    *tls.Certificate
	certPEM []byte
	keyPEM  []byte

	lastErr string // watch goroutine only
}

// newCertReloader loads the pair once. A missing or broken pair at start-up
// is an error, as ListenAndServeTLS's was: the pod must not go Ready
// without a certificate.
func newCertReloader(certFile, keyFile string, log *slog.Logger) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile, log: log, now: time.Now}
	if _, err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *certReloader) read() (certPEM, keyPEM []byte, err error) {
	certPEM, err = os.ReadFile(r.certFile)
	if err != nil {
		return nil, nil, fmt.Errorf("applog/webhook: read serving cert %q: %w", r.certFile, err)
	}
	keyPEM, err = os.ReadFile(r.keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("applog/webhook: read serving key %q: %w", r.keyFile, err)
	}
	return certPEM, keyPEM, nil
}

// reload re-reads both files and swaps in the pair when it changed and is
// valid. It reports whether the served certificate changed.
func (r *certReloader) reload() (bool, error) {
	certPEM, keyPEM, err := r.read()
	if err != nil {
		return false, err
	}
	r.mu.RLock()
	same := r.cert != nil && bytes.Equal(certPEM, r.certPEM) && bytes.Equal(keyPEM, r.keyPEM)
	r.mu.RUnlock()
	if same {
		return false, nil
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		// The two reads can straddle the kubelet's ..data swap (old cert,
		// new key). Read once more before calling the pair broken.
		if certPEM, keyPEM, err = r.read(); err != nil {
			return false, err
		}
		if pair, err = tls.X509KeyPair(certPEM, keyPEM); err != nil {
			return false, fmt.Errorf("applog/webhook: serving key pair %q / %q: %w", r.certFile, r.keyFile, err)
		}
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return false, fmt.Errorf("applog/webhook: parse serving cert %q: %w", r.certFile, err)
	}
	if now := r.now(); now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return false, fmt.Errorf("applog/webhook: serving cert %q is not valid now (valid %s to %s)",
			r.certFile, leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	pair.Leaf = leaf
	r.mu.Lock()
	r.cert, r.certPEM, r.keyPEM = &pair, certPEM, keyPEM
	r.mu.Unlock()
	return true, nil
}

// GetCertificate is the tls.Config hook.
func (r *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cert, nil
}

// poll runs one reload and logs state changes only.
func (r *certReloader) poll() {
	changed, err := r.reload()
	switch {
	case err != nil:
		if msg := err.Error(); msg != r.lastErr {
			r.log.Warn("applog/webhook: serving cert reload failed; still serving the last good certificate", "err", err)
			r.lastErr = msg
		}
		return
	case r.lastErr != "":
		r.log.Info("applog/webhook: serving cert reload recovered")
		r.lastErr = ""
	}
	if changed {
		r.log.Info("applog/webhook: serving cert reloaded", "cert_file", r.certFile)
	}
}

// watch polls until ctx ends.
func (r *certReloader) watch(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.poll()
		}
	}
}
