//go:build helm

package helm_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// Issue #148. The applog injector and the audit receiver both load their
// serving certificate once, at start-up (ListenAndServeTLS with file
// paths). A `helm upgrade` that changes only the chart-rendered TLS Secret
// updates the Secret and, some time later, the files in the mounted
// volume, but the running process keeps serving the certificate it read at
// start-up. The applog MutatingWebhookConfiguration is failurePolicy:
// Ignore, so a stale serving cert fails open: every Pod is admitted with no
// sidecar and nothing is logged by the injector. Seen live during Story
// 10.5: 7m48s of silent non-injection until a manual rollout restart.
//
// The fix is a checksum of the rendered Secret's data on the pod template
// of every workload that mounts a chart-rendered TLS Secret, so a changed
// cert changes the pod template and the controller rolls the pods.
//
// Scope, and why each negative case exists:
//   - Only Secrets the chart renders are hashed. A Secret the chart does
//     not render (applog cert-manager Path A, Calico Path A
//     certManagerSecretName) is rotated by something outside helm, so a
//     render-time checksum could never see the change and would only
//     pretend to cover it.
//   - The hash covers the Secret's data, not the whole manifest, so a
//     chart-version bump (which changes the Secret's helm.sh/chart label)
//     does not roll the collector DaemonSet when no cert changed.

// podTemplateAnnotations returns the pod-template annotations of the
// named workload of the given kind, or nil when it has none. It fails the
// test when the workload is not in the render at all.
func podTemplateAnnotations(t *testing.T, rendered, kind, name string) map[string]string {
	t.Helper()
	for _, m := range findByKind(parseManifests(t, rendered), kind) {
		if m.Metadata.Name != name {
			continue
		}
		var w struct {
			Spec struct {
				Template struct {
					Metadata struct {
						Annotations map[string]string `yaml:"annotations"`
					} `yaml:"metadata"`
				} `yaml:"template"`
			} `yaml:"spec"`
		}
		if err := m.Raw.Decode(&w); err != nil {
			t.Fatalf("decode %s/%s: %v", kind, name, err)
		}
		return w.Spec.Template.Metadata.Annotations
	}
	t.Fatalf("%s %q not in render", kind, name)
	return nil
}

// replaceSet returns args with the --set whose key is key replaced by
// key=value (appended when absent), so a test can vary one TLS value
// while keeping every other required value.
func replaceSet(args []string, key, value string) []string {
	out := make([]string, 0, len(args)+1)
	for _, a := range args {
		if strings.HasPrefix(a, key+"=") {
			continue
		}
		out = append(out, a)
	}
	return append(out, key+"="+value)
}

var noSubcharts = []string{"falco.enabled=false", "nats.enabled=false", "redis.enabled=false"}

// checksumCase is one chart-rendered TLS Secret and the workload that
// mounts it.
type checksumCase struct {
	name       string
	base       []string
	kind       string
	workload   string
	annotation string
	// rotate lists the values whose change must roll the workload: every
	// key the rendered Secret carries.
	rotate []string
}

func checksumCases() []checksumCase {
	return []checksumCase{
		{
			name:       "applog",
			base:       append(append([]string{}, noSubcharts...), applogSidecarEnabledArgs()...),
			kind:       "Deployment",
			workload:   "olaitan-applog-injector",
			annotation: "checksum/applog-tls",
			rotate:     []string{"applogSidecar.tls.servingCert", "applogSidecar.tls.servingKey"},
		},
		{
			name:       "audit",
			base:       append(append([]string{}, noSubcharts...), auditWebhookEnabledArgs()...),
			kind:       "DaemonSet",
			workload:   "olaitan-collector",
			annotation: "checksum/audit-tls",
			rotate:     []string{"auditWebhook.servingCert", "auditWebhook.servingKey", "auditWebhook.clusterCAData"},
		},
		{
			name:       "calico-path-b",
			base:       append(append([]string{}, noSubcharts...), calicoSensorPathBArgs()...),
			kind:       "DaemonSet",
			workload:   "olaitan-collector",
			annotation: "checksum/cni-tls",
			rotate:     []string{"calicoSensor.tls.caBundle", "calicoSensor.tls.clientCert", "calicoSensor.tls.clientKey"},
		},
	}
}

// TestTLSSecretChangeRollsTheMountingWorkload: every value the rendered
// TLS Secret carries changes the mounting workload's pod template, and an
// unchanged value set renders the same checksum (no spurious rollouts).
func TestTLSSecretChangeRollsTheMountingWorkload(t *testing.T) {
	for _, tc := range checksumCases() {
		t.Run(tc.name, func(t *testing.T) {
			before := podTemplateAnnotations(t, helmTemplate(t, tc.base), tc.kind, tc.workload)[tc.annotation]
			if before == "" {
				t.Fatalf("%s %s carries no %s pod annotation, so a helm upgrade that rotates only the TLS Secret leaves the pods serving the old material",
					tc.kind, tc.workload, tc.annotation)
			}
			if len(before) != 64 {
				t.Errorf("%s = %q, want a 64-hex sha256", tc.annotation, before)
			}
			again := podTemplateAnnotations(t, helmTemplate(t, tc.base), tc.kind, tc.workload)[tc.annotation]
			if again != before {
				t.Errorf("same values rendered %s %q then %q: every upgrade would roll the pods", tc.annotation, before, again)
			}
			for _, key := range tc.rotate {
				args := replaceSet(tc.base, key, "cm90YXRlZA==")
				after := podTemplateAnnotations(t, helmTemplate(t, args), tc.kind, tc.workload)[tc.annotation]
				if after == before {
					t.Errorf("changing %s left %s at %q: the pods would keep the old material", key, tc.annotation, before)
				}
			}
		})
	}
}

// TestTLSChecksumCoversSecretDataOnly: the checksum is the sha256 of the
// rendered Secret's data and nothing else, so a change to the Secret's
// labels (the helm.sh/chart label moves on every chart-version bump) does
// not roll the collector DaemonSet when no cert changed. Proven by
// recomputing the hash from the rendered Secret's data in Go.
func TestTLSChecksumCoversSecretDataOnly(t *testing.T) {
	for _, tc := range checksumCases() {
		t.Run(tc.name, func(t *testing.T) {
			rendered := helmTemplate(t, tc.base)
			got := podTemplateAnnotations(t, rendered, tc.kind, tc.workload)[tc.annotation]
			secretName := map[string]string{
				"applog":        "olaitan-applog-injector-tls",
				"audit":         "olaitan-audit-tls",
				"calico-path-b": "olaitan-cni-tls",
			}[tc.name]
			var data map[string]string
			for _, m := range findByKind(parseManifests(t, rendered), "Secret") {
				if m.Metadata.Name != secretName {
					continue
				}
				var s struct {
					Data map[string]string `yaml:"data"`
				}
				if err := m.Raw.Decode(&s); err != nil {
					t.Fatalf("decode Secret %s: %v", secretName, err)
				}
				data = s.Data
			}
			if data == nil {
				t.Fatalf("Secret %s not in render", secretName)
			}
			if want := sha256OfSortedJSON(t, data); got != want {
				t.Errorf("%s = %q, want sha256 of the Secret's data %q", tc.annotation, got, want)
			}
		})
	}
}

// TestTLSChecksumAbsentWhenChartDoesNotRenderTheSecret: no checksum where
// the chart does not own the Secret, and none when the source is off.
func TestTLSChecksumAbsentWhenChartDoesNotRenderTheSecret(t *testing.T) {
	cases := []struct {
		name       string
		args       []string
		kind       string
		workload   string
		annotation string
	}{
		{
			name: "applog cert-manager Path A",
			args: append(append([]string{}, noSubcharts...),
				"applogSidecar.enabled=true",
				"applogSidecar.tls.certManagerEnabled=true",
				"applogSidecar.tls.issuerName=olaitan-ca"),
			kind: "Deployment", workload: "olaitan-applog-injector", annotation: "checksum/applog-tls",
		},
		{
			name: "calico Path A",
			args: append(append([]string{}, noSubcharts...),
				"calicoSensor.enabled=true",
				"calicoSensor.tls.certManagerSecretName=external-cni-tls"),
			kind: "DaemonSet", workload: "olaitan-collector", annotation: "checksum/cni-tls",
		},
		{
			name: "audit disabled",
			args: noSubcharts,
			kind: "DaemonSet", workload: "olaitan-collector", annotation: "checksum/audit-tls",
		},
		{
			name: "calico disabled",
			args: noSubcharts,
			kind: "DaemonSet", workload: "olaitan-collector", annotation: "checksum/cni-tls",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ann := podTemplateAnnotations(t, helmTemplate(t, tc.args), tc.kind, tc.workload)
			if v, ok := ann[tc.annotation]; ok {
				t.Errorf("%s %s carries %s=%q, but the chart does not render that Secret here", tc.kind, tc.workload, tc.annotation, v)
			}
		})
	}
}

// TestTLSChecksumKeepsPrometheusAnnotations: the collector's pod
// annotations block used to exist only for the scrape annotations. Adding
// checksums must not drop them, and turning scrape annotations off must
// not drop the checksums.
func TestTLSChecksumKeepsPrometheusAnnotations(t *testing.T) {
	args := append(append([]string{}, noSubcharts...), auditWebhookEnabledArgs()...)
	ann := podTemplateAnnotations(t, helmTemplate(t, args), "DaemonSet", "olaitan-collector")
	if ann["prometheus.io/scrape"] != "true" || ann["checksum/audit-tls"] == "" {
		t.Errorf("collector annotations = %v, want both prometheus.io/scrape and checksum/audit-tls", ann)
	}
	off := podTemplateAnnotations(t, helmTemplate(t, append(args, "metrics.scrapeAnnotations=false")), "DaemonSet", "olaitan-collector")
	if _, ok := off["prometheus.io/scrape"]; ok || off["checksum/audit-tls"] == "" {
		t.Errorf("with scrape annotations off, collector annotations = %v, want only checksum/audit-tls", off)
	}
}

// sha256OfSortedJSON is the Go twin of the chart's
// `.data | toJson | sha256sum`: encoding/json sorts map keys, exactly as
// helm's toJson does, so the two agree byte for byte.
func sha256OfSortedJSON(t *testing.T, data map[string]string) string {
	t.Helper()
	b, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
