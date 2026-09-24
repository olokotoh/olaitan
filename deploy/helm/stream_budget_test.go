//go:build helm

package helm_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/nats-io/nats.go/jetstream"
	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/api/resource"

	olnats "github.com/olokotoh/olaitan/internal/nats"
)

// Story 12.1 (issue #96). The first thing a stranger runs is the README
// command, which passes no values at all. On rc3 that install left the
// aggregator in CrashLoopBackOff:
//
//	ensure stream EVENTS_RAW: nats: API error: code=500 err_code=10047
//	description=insufficient storage resources available
//
// JetStream reserves each stream's MaxBytes against the server's
// max_file_store up front, so the sum of every stream's cap has to fit the
// store. Story 9.2 made that true on main by defaulting
// nats.streamMaxBytesOverride to 512 MiB, but nothing checked the sum: the
// stream count has since grown from 3 to 13, and one more stream, or a
// smaller store, would have brought #96 back without any test noticing.
// This test reads the numbers from the render and from the code that
// creates the streams, so it moves with both.

// streamBudget is what the aggregator will ask JetStream to reserve on the
// rendered install, and what the rendered NATS server will allow.
type streamBudget struct {
	override     string // OLT_NATS_STREAM_MAXBYTES_OVERRIDE as rendered ("" when absent)
	maxFileStore int64  // nats.conf jetstream.max_file_store
	maxMemStore  int64  // nats.conf jetstream.max_memory_store
	claim        int64  // the NATS StatefulSet's JetStream volume claim
}

// natsConfValue pulls one scalar out of the NATS chart's nats.conf. The file
// is NATS config syntax (JSON-like, but with bare sizes such as 10Gi and
// $VARIABLES), so it is not parsed as JSON.
func natsConfValue(conf, key string) (string, bool) {
	re := regexp.MustCompile(`"` + regexp.QuoteMeta(key) + `":\s*"?([^",\n]+)"?`)
	m := re.FindStringSubmatch(conf)
	if m == nil {
		return "", false
	}
	return strings.TrimSpace(m[1]), true
}

func parseSize(t *testing.T, what, v string) int64 {
	t.Helper()
	q, err := resource.ParseQuantity(v)
	if err != nil {
		t.Fatalf("%s %q is not a size: %v", what, v, err)
	}
	return q.Value()
}

// readStreamBudget walks the rendered manifests for the three numbers.
func readStreamBudget(t *testing.T, rendered string) streamBudget {
	t.Helper()
	var b streamBudget
	var overrides []string
	for _, m := range regexp.MustCompile(`- name: OLT_NATS_STREAM_MAXBYTES_OVERRIDE\s*\n\s*value:\s*"?([^"\n]*)"?`).
		FindAllStringSubmatch(rendered, -1) {
		overrides = append(overrides, strings.TrimSpace(m[1]))
	}
	for _, o := range overrides {
		if o != overrides[0] {
			t.Fatalf("the aggregator and the collector disagree on the stream cap: %v", overrides)
		}
	}
	if len(overrides) > 0 {
		b.override = overrides[0]
	}

	dec := yaml.NewDecoder(strings.NewReader(rendered))
	var sawConf, sawClaim bool
	for {
		var doc struct {
			Kind     string `yaml:"kind"`
			Metadata struct {
				Name string `yaml:"name"`
			} `yaml:"metadata"`
			Data map[string]string `yaml:"data"`
			Spec struct {
				VolumeClaimTemplates []struct {
					Metadata struct {
						Name string `yaml:"name"`
					} `yaml:"metadata"`
					Spec struct {
						Resources struct {
							Requests map[string]string `yaml:"requests"`
						} `yaml:"resources"`
					} `yaml:"spec"`
				} `yaml:"volumeClaimTemplates"`
			} `yaml:"spec"`
		}
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("decode rendered manifest: %v", err)
		}
		switch {
		case doc.Kind == "ConfigMap" && doc.Data["nats.conf"] != "":
			conf := doc.Data["nats.conf"]
			v, ok := natsConfValue(conf, "max_file_store")
			if !ok {
				t.Fatalf("nats.conf has no jetstream max_file_store:\n%s", conf)
			}
			b.maxFileStore = parseSize(t, "max_file_store", v)
			if v, ok := natsConfValue(conf, "max_memory_store"); ok {
				b.maxMemStore = parseSize(t, "max_memory_store", v)
			}
			sawConf = true
		case doc.Kind == "StatefulSet" && doc.Metadata.Name == "olaitan-nats":
			for _, vct := range doc.Spec.VolumeClaimTemplates {
				if s, ok := vct.Spec.Resources.Requests["storage"]; ok {
					b.claim = parseSize(t, "NATS volume claim", s)
					sawClaim = true
				}
			}
		}
	}
	if !sawConf || !sawClaim {
		t.Fatalf("render has no NATS config (%v) or no NATS volume claim (%v)", sawConf, sawClaim)
	}
	return b
}

// checkStreamBudget returns why JetStream would refuse the streams the
// aggregator creates, or nil when they fit.
func checkStreamBudget(t *testing.T, b streamBudget) error {
	t.Helper()
	// StreamConfigs reads the override from the environment, exactly as the
	// aggregator does in the pod.
	t.Setenv("OLT_NATS_STREAM_MAXBYTES_OVERRIDE", b.override)
	var sum int64
	var names, uncapped []string
	for _, c := range olnats.StreamConfigs() {
		if c.Storage != jetstream.FileStorage {
			// max_memory_store is 0 in the default render; a memory stream
			// would fail with the same err_code 10047.
			if b.maxMemStore == 0 {
				return fmt.Errorf("stream %s is memory storage but max_memory_store is 0", c.Name)
			}
			continue
		}
		if c.MaxBytes <= 0 {
			// No cap is an unbounded stream: it reserves nothing up front
			// but can fill the volume, and then every stream stops.
			uncapped = append(uncapped, c.Name)
			continue
		}
		sum += c.MaxBytes
		names = append(names, c.Name)
	}
	limit := b.maxFileStore
	if b.claim < limit {
		limit = b.claim
	}
	if sum > limit {
		return fmt.Errorf("%d streams reserve %d bytes (%.1f GiB) but the NATS file store allows %d (%.1f GiB, max_file_store %d, claim %d): %v",
			len(names), sum, float64(sum)/(1<<30), limit, float64(limit)/(1<<30), b.maxFileStore, b.claim, names)
	}
	if len(uncapped) > 0 {
		return fmt.Errorf("streams %v have no MaxBytes cap on this render (override %q), so they can fill the store", uncapped, b.override)
	}
	t.Logf("%d file streams reserve %.2f GiB of %.2f GiB (override %s bytes each)",
		len(names), float64(sum)/(1<<30), float64(limit)/(1<<30), b.override)
	return nil
}

// renderREADME renders the chart the way the README installs it: release
// olaitan, namespace olaitan, no values at all (no redis password either).
func renderREADME(t *testing.T, extra ...string) string {
	t.Helper()
	args := append([]string{"template", "olaitan", chartDir(t), "--namespace", "olaitan"}, extra...)
	cmd := exec.Command("helm", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("helm %v failed: %v\n%s", args, err, stderr.String())
	}
	return stdout.String()
}

// TestDefaultInstallStreamsFitTheNATSStore is issue #96's regression test:
// the README install creates every stream on the NATS the chart ships.
func TestDefaultInstallStreamsFitTheNATSStore(t *testing.T) {
	if err := checkStreamBudget(t, readStreamBudget(t, renderREADME(t))); err != nil {
		t.Fatalf("issue #96: the default install cannot create its streams: %v", err)
	}
}

// TestStreamBudgetCheckBites proves the check fails on the shapes that
// produced #96, so a green run above means something.
func TestStreamBudgetCheckBites(t *testing.T) {
	// rc3: no override, so production caps (10 + 50 + 100 GiB) against 10Gi.
	rc3 := readStreamBudget(t, renderREADME(t, "--set-string", "nats.streamMaxBytesOverride="))
	if rc3.override != "" {
		t.Fatalf("empty override still rendered %q", rc3.override)
	}
	if err := checkStreamBudget(t, rc3); err == nil {
		t.Error("the rc3 defaults (no stream cap) passed the budget check; it must fail")
	} else {
		t.Logf("rc3 shape rejected as expected: %v", err)
	}
	// A store smaller than the default reservation.
	small := readStreamBudget(t, renderREADME(t,
		"--set", "nats.config.jetstream.fileStore.pvc.size=2Gi"))
	if err := checkStreamBudget(t, small); err == nil {
		t.Errorf("a 2Gi store passed the budget check with %s-byte streams; it must fail", small.override)
	}
}
