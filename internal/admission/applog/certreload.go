package applog

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// DefaultCertReloadInterval is how often the injector re-reads its serving
// cert and key when WebhookConfig.CertReloadInterval is zero. The kubelet
// refreshes a mounted Secret on its own sync period (about a minute), so a
// few seconds here adds nothing noticeable to a rotation.
const DefaultCertReloadInterval = 10 * time.Second

// certReloader serves the injector's TLS certificate through
// tls.Config.GetCertificate and re-reads the key pair from disk on an
// interval (#157). A renewed Secret (cert-manager Path A, the certgen Job, or
// a Path B helm upgrade before the pods roll) reaches the mounted files
// through the kubelet's atomic ..data symlink swap; the running injector
// serves it on the next handshake after the next poll, with no restart.
//
// Polling, not inotify: the kubelet replaces the ..data symlink, so a watch
// on tls.crt itself sees no event, and a directory watch adds a dependency
// for no gain at this interval. A pair that does not parse or match (read
// mid-swap, or a bad Secret) is logged and skipped; the last good pair
// keeps serving.
type certReloader struct {
	certFile, keyFile string
	log               *slog.Logger

	mu      sync.RWMutex
	cert    *tls.Certificate
	certPEM []byte
	keyPEM  []byte
}

// newCertReloader loads the pair once. A missing or broken pair at start-up
// is an error, as ListenAndServeTLS's was: the pod must not go Ready
// without a certificate.
func newCertReloader(certFile, keyFile string, log *slog.Logger) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile, log: log}
	if _, err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// reload re-reads both files and swaps in the pair when it changed and is
// valid. It reports whether the served certificate changed.
func (r *certReloader) reload() (bool, error) {
	certPEM, err := os.ReadFile(r.certFile)
	if err != nil {
		return false, fmt.Errorf("applog/webhook: read serving cert %q: %w", r.certFile, err)
	}
	keyPEM, err := os.ReadFile(r.keyFile)
	if err != nil {
		return false, fmt.Errorf("applog/webhook: read serving key %q: %w", r.keyFile, err)
	}
	r.mu.RLock()
	same := r.cert != nil && bytes.Equal(certPEM, r.certPEM) && bytes.Equal(keyPEM, r.keyPEM)
	r.mu.RUnlock()
	if same {
		return false, nil
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return false, fmt.Errorf("applog/webhook: serving key pair %q / %q: %w", r.certFile, r.keyFile, err)
	}
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

// watch polls until ctx ends.
func (r *certReloader) watch(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			changed, err := r.reload()
			switch {
			case err != nil:
				r.log.Warn("applog/webhook: serving cert reload failed; still serving the last good certificate", "err", err)
			case changed:
				r.log.Info("applog/webhook: serving cert reloaded", "cert_file", r.certFile)
			}
		}
	}
}
