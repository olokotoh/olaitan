package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/olokotoh/olaitan/internal/certgen"
)

// runCertgen is `olaitan certgen`, the command the chart's certgen Job runs
// (Story 12.7, D1). It creates whatever audit-webhook and applog-injector TLS
// material is missing, in the cluster, and writes the matching CA into the
// webhook configurations' caBundle. Exit 0 on success, 1 on any failure (the
// Job's backoffLimit retries it).
func runCertgen(ctx context.Context, args []string, stderr io.Writer) int {
	log := slog.New(slog.NewJSONHandler(stderr, nil)).With("command", "certgen", "version", version)
	spec, err := parseCertgenFlags(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		log.Error("certgen: bad arguments", "err", err)
		return 1
	}
	cs, err := kubeClientFactory(log)
	if err != nil {
		log.Error("certgen: kube client", "err", err)
		return 1
	}
	if err := certgen.Run(ctx, cs, spec, log); err != nil {
		log.Error("certgen: failed", "err", err)
		return 1
	}
	log.Info("certgen: done")
	return 0
}

// parseCertgenFlags turns the Job's arguments into a certgen.Spec and
// validates it.
func parseCertgenFlags(args []string, stderr io.Writer) (certgen.Spec, error) {
	fs := flag.NewFlagSet("olaitan certgen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		spec                          certgen.Spec
		auditDNS, auditIPs, applogDNS string
		labels                        multiFlag
		validity                      time.Duration
		waitForWebhooks               time.Duration
	)
	fs.StringVar(&spec.Namespace, "namespace", "", "namespace the Secrets live in (the release namespace)")
	fs.StringVar(&spec.AuditSecret, "audit-secret", "", "audit receiver TLS Secret (tls.crt, tls.key, ca.crt)")
	fs.StringVar(&spec.AuditKubeconfigSecret, "audit-kubeconfig-secret", "", "Secret holding the kube-apiserver's audit webhook kubeconfig")
	fs.StringVar(&auditDNS, "audit-dns", "", "comma-separated DNS names for the audit serving cert")
	fs.StringVar(&auditIPs, "audit-ip", "", "comma-separated IP addresses for the audit serving cert")
	fs.StringVar(&spec.AuditServer, "audit-server", "", "host:port the kube-apiserver dials, written into the kubeconfig")
	fs.StringVar(&spec.ApplogSecret, "applog-secret", "", "applog injector TLS Secret (tls.crt, tls.key, ca.crt)")
	fs.StringVar(&applogDNS, "applog-dns", "", "comma-separated DNS names for the applog serving cert")
	fs.StringVar(&spec.MutatingWebhook, "mutating-webhook", "", "MutatingWebhookConfiguration whose caBundle gets the applog CA")
	fs.StringVar(&spec.ValidatingWebhook, "validating-webhook", "", "ValidatingWebhookConfiguration whose caBundle gets the audit CA")
	fs.Var(&labels, "label", "key=value label for every Secret created (repeatable)")
	fs.DurationVar(&validity, "validity", 0, "certificate validity (default ten years)")
	fs.DurationVar(&waitForWebhooks, "wait-for-webhooks", 0, "how long to wait for a webhook configuration to exist (default 2m)")
	if err := fs.Parse(args); err != nil {
		return certgen.Spec{}, err
	}
	spec.AuditDNSNames = splitList(auditDNS)
	spec.AuditIPs = splitList(auditIPs)
	spec.ApplogDNSNames = splitList(applogDNS)
	spec.Validity = validity
	spec.WaitForWebhooks = waitForWebhooks
	if len(labels) > 0 {
		spec.Labels = map[string]string{}
		for _, l := range labels {
			k, v, ok := strings.Cut(l, "=")
			if !ok || k == "" {
				return certgen.Spec{}, fmt.Errorf("--label %q: want key=value", l)
			}
			spec.Labels[k] = v
		}
	}
	if err := spec.Validate(); err != nil {
		return certgen.Spec{}, err
	}
	return spec, nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }
