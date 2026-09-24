//go:build helm

package helm_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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

// streamRings are the two workloads that call EnsureStreams
// (cmd/olaitan/main.go: the collector at startup, the aggregator in its
// run loop). Each creates every stream with the cap its own env gives it, so
// a ring that loses the override asks JetStream for production retention
// even when the other ring is capped.
var streamRings = []string{"Deployment/olaitan-aggregator", "DaemonSet/olaitan-collector"}

const overrideEnv = "OLT_NATS_STREAM_MAXBYTES_OVERRIDE"

// readStreamBudget walks the rendered manifests for the three numbers. It
// fails the test on a render it cannot read, and returns an error when the
// two stream rings do not carry the same cap.
func readStreamBudget(t *testing.T, rendered string) (streamBudget, error) {
	t.Helper()
	var b streamBudget
	type ring struct {
		seen   bool
		values []string
	}
	rings := map[string]*ring{}
	for _, r := range streamRings {
		rings[r] = &ring{}
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
				Template struct {
					Spec struct {
						Containers []struct {
							Env []struct {
								Name  string `yaml:"name"`
								Value string `yaml:"value"`
							} `yaml:"env"`
						} `yaml:"containers"`
					} `yaml:"spec"`
				} `yaml:"template"`
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
		if r, ok := rings[doc.Kind+"/"+doc.Metadata.Name]; ok {
			r.seen = true
			for _, c := range doc.Spec.Template.Spec.Containers {
				for _, e := range c.Env {
					if e.Name == overrideEnv {
						r.values = append(r.values, strings.TrimSpace(e.Value))
					}
				}
			}
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

	// Every ring must be rendered, carry the env at most once, and agree
	// with the other ring: both capped at the same value, or both uncapped.
	per := map[string]string{}
	for _, name := range streamRings {
		r := rings[name]
		if !r.seen {
			t.Fatalf("render has no %s, which creates the streams", name)
		}
		switch len(r.values) {
		case 0:
			per[name] = ""
		case 1:
			per[name] = r.values[0]
		default:
			return b, fmt.Errorf("%s sets %s %d times: %v", name, overrideEnv, len(r.values), r.values)
		}
	}
	first := per[streamRings[0]]
	for _, name := range streamRings[1:] {
		if per[name] != first {
			return b, fmt.Errorf("the stream rings disagree on the cap (%s %q, %s %q): the uncapped one asks JetStream for production retention and dies with err_code=10047",
				streamRings[0], first, name, per[name])
		}
	}
	b.override = first
	return b, nil
}

// mustReadStreamBudget is readStreamBudget for renders whose rings must agree.
func mustReadStreamBudget(t *testing.T, rendered string) streamBudget {
	t.Helper()
	b, err := readStreamBudget(t, rendered)
	if err != nil {
		t.Fatal(err)
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
	if err := checkStreamBudget(t, mustReadStreamBudget(t, renderREADME(t))); err != nil {
		t.Fatalf("issue #96: the default install cannot create its streams: %v", err)
	}
}

// TestStreamBudgetCheckBites proves the check fails on the shapes that
// produced #96, so a green run above means something.
func TestStreamBudgetCheckBites(t *testing.T) {
	// rc3: no override, so production caps (10 + 50 + 100 GiB) against 10Gi.
	rc3 := mustReadStreamBudget(t, renderREADME(t, "--set-string", "nats.streamMaxBytesOverride="))
	if rc3.override != "" {
		t.Fatalf("empty override still rendered %q", rc3.override)
	}
	if err := checkStreamBudget(t, rc3); err == nil {
		t.Error("the rc3 defaults (no stream cap) passed the budget check; it must fail")
	} else {
		t.Logf("rc3 shape rejected as expected: %v", err)
	}
	// A store smaller than the default reservation.
	small := mustReadStreamBudget(t, renderREADME(t,
		"--set", "nats.config.jetstream.fileStore.pvc.size=2Gi"))
	if err := checkStreamBudget(t, small); err == nil {
		t.Errorf("a 2Gi store passed the budget check with %s-byte streams; it must fail", small.override)
	}
	// One ring loses the cap: the collector DaemonSet renders no override
	// while the aggregator keeps it.
	docs := strings.Split(renderREADME(t), "\n---\n")
	dropped := 0
	for i, d := range docs {
		if strings.Contains(d, "kind: DaemonSet") && strings.Contains(d, "name: olaitan-collector\n") {
			before := d
			docs[i] = regexp.MustCompile(`\n\s*- name: `+overrideEnv+`\s*\n\s*value:[^\n]*`).ReplaceAllString(d, "")
			if docs[i] != before {
				dropped++
			}
		}
	}
	if dropped != 1 {
		t.Fatalf("could not drop the override from the collector DaemonSet (dropped %d)", dropped)
	}
	if _, err := readStreamBudget(t, strings.Join(docs, "\n---\n")); err == nil {
		t.Error("a render whose collector has no stream cap passed; that ring would request production retention")
	} else {
		t.Logf("one-ring render rejected as expected: %v", err)
	}
}

// natsSizeKey is a values key that NOTES or values.yaml offers for sizing
// the NATS store, e.g. nats.config.jetstream.fileStore.pvc.size.
var natsSizeKey = regexp.MustCompile(`nats(?:\.[A-Za-z]+)+\.size\b`)

// TestNotesNameTheKeyThatSizesTheNATSStore (Story 12.1 review). NOTES told
// operators to raise nats.persistence.size, which the bundled NATS chart
// ignores: the store and the claim stayed at 10Gi. An operator who cleared
// the stream cap and raised that key got #96 back. Every sizing key NOTES
// names, in both the capped and the uncapped branch, must move both the
// NATS max_file_store and the claim.
func TestNotesNameTheKeyThatSizesTheNATSStore(t *testing.T) {
	const want = "50Gi"
	wantBytes := parseSize(t, "want", want)
	for _, branch := range []struct {
		name string
		sets []string
	}{
		{"capped (default)", nil},
		{"uncapped", []string{"nats.streamMaxBytesOverride="}},
	} {
		notes := renderNotes(t, branch.sets)
		keys := natsSizeKey.FindAllString(notes, -1)
		if len(keys) == 0 {
			t.Errorf("%s: NOTES name no key for sizing the NATS store:\n%s", branch.name, notes)
			continue
		}
		for _, k := range keys {
			b := mustReadStreamBudget(t, renderREADME(t, "--set", k+"="+want))
			if b.maxFileStore != wantBytes || b.claim != wantBytes {
				t.Errorf("%s: NOTES say raise %s, but --set %s=%s renders max_file_store %d and claim %d (want %d for both)",
					branch.name, k, k, want, b.maxFileStore, b.claim, wantBytes)
			}
		}
	}
	values, err := os.ReadFile(filepath.Join(chartDir(t), "values.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(values), "nats.persistence.size") {
		t.Error("values.yaml still tells operators to raise nats.persistence.size, which the NATS chart ignores")
	}
}
