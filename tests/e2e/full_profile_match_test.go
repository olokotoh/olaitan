//go:build e2e

package e2e_test

import "testing"

// TestAC2MatchAttributesEachSourceToItsAction pins the AC2 matcher without a
// cluster. The live test can only prove what its matcher lets through, so
// the matcher is where "an event caused by THIS action" is decided.
func TestAC2MatchAttributesEachSourceToItsAction(t *testing.T) {
	const pod, marker = "ac2-probe-42", "ac2-log-42"
	cases := []struct {
		name, source, body string
		want               bool
	}{
		{"falco event for the probe from the deliberate rule",
			"falco", `{"rule":"` + ac2FalcoRule + `","k8s.pod.name":"ac2-probe-42"}`, true},
		// The probe runs a shell loop and gets a sidecar injected, so other
		// Falco rules can name it too. Only the rule the action fires counts.
		{"falco event for the probe from some other rule",
			"falco", `{"rule":"Terminal shell in container","k8s.pod.name":"ac2-probe-42"}`, false},
		{"falco event from the deliberate rule on another pod",
			"falco", `{"rule":"` + ac2FalcoRule + `","k8s.pod.name":"other"}`, false},
		{"audit event naming the probe", "audit", `{"objectRef":{"name":"ac2-probe-42"}}`, true},
		{"applog line carrying the marker", "applog", `{"msg":"ac2-log-42 line 3"}`, true},
		{"network flow naming the probe", "network", `{"src_pod":"ac2-probe-42"}`, true},
		{"unrelated event", "runtime", `{"pod":"coredns"}`, false},
	}
	for _, c := range cases {
		if got := ac2Match(c.source, c.body, pod, marker); got != c.want {
			t.Errorf("%s: ac2Match = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestAC2CompleteCountsOnlyExpectedSources guards the wait loop: the raw
// wildcard can deliver subjects outside the five-source contract, and
// counting those let the loop stop early with a real source still missing.
func TestAC2CompleteCountsOnlyExpectedSources(t *testing.T) {
	hits := map[string]string{"falco": "x", "audit": "x", "runtime": "x", "network": "x", "posture": "x"}
	if ac2Complete(hits) {
		t.Fatal("ac2Complete = true with applog missing and an unexpected source present")
	}
	hits["applog"] = "x"
	if !ac2Complete(hits) {
		t.Fatal("ac2Complete = false with all five expected sources present")
	}
}
