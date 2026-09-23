//go:build helm

package helm_test

import (
	"fmt"
	"testing"
)

// collectorEnv returns the collector container's plain env values.
func collectorEnv(t *testing.T, rendered string) map[string]string {
	t.Helper()
	pod := collectorDaemonSet(t, rendered)["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
	env := map[string]string{}
	for _, x := range pod["containers"].([]any) {
		c := x.(map[string]any)
		if c["name"] != "collector" {
			continue
		}
		for _, e := range c["env"].([]any) {
			em := e.(map[string]any)
			if v, ok := em["value"]; ok {
				env[fmt.Sprint(em["name"])] = fmt.Sprint(v)
			}
		}
	}
	return env
}

// Issue #135: the Falco alert buffer bounds reach the collector, with
// defaults, and a large --set value stays a plain integer (helm renders a
// bare float64 in scientific notation, which the collector would reject).
func TestCollectorFalcoBufferBounds(t *testing.T) {
	for _, tc := range []struct {
		name              string
		sets              []string
		wantAlerts, wantB string
	}{
		{"defaults", nil, "4096", "16777216"},
		{"overridden", []string{"falcoIngest.buffer.maxAlerts=50", "falcoIngest.buffer.maxBytes=1073741824"}, "50", "1073741824"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := collectorEnv(t, helmTemplate(t, tc.sets))
			if env["FALCO_BUFFER_MAX_ALERTS"] != tc.wantAlerts || env["FALCO_BUFFER_MAX_BYTES"] != tc.wantB {
				t.Errorf("FALCO_BUFFER_MAX_ALERTS=%q FALCO_BUFFER_MAX_BYTES=%q, want %s / %s",
					env["FALCO_BUFFER_MAX_ALERTS"], env["FALCO_BUFFER_MAX_BYTES"], tc.wantAlerts, tc.wantB)
			}
		})
	}
}
