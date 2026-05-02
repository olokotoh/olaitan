package main

import "testing"

func TestKubeletCheckpointURL(t *testing.T) {
	cases := []struct {
		name, base, node, ns, pod, ctr, want string
	}{
		{
			name: "kubectl-proxy default port",
			base: "http://localhost:18001",
			node: "olaitan-criu-spike-control-plane",
			ns:   "criu-spike",
			pod:  "busybox-target",
			ctr:  "busybox",
			want: "http://localhost:18001/api/v1/nodes/olaitan-criu-spike-control-plane/proxy/checkpoint/criu-spike/busybox-target/busybox",
		},
		{
			name: "trailing slash on base",
			base: "http://localhost:8001/",
			node: "n",
			ns:   "ns",
			pod:  "p",
			ctr:  "c",
			want: "http://localhost:8001/api/v1/nodes/n/proxy/checkpoint/ns/p/c",
		},
		{
			name: "names with characters needing path escape",
			base: "http://h",
			node: "node-with-dashes",
			ns:   "team:default",
			pod:  "pod_underscore",
			ctr:  "ctr.dotted",
			want: "http://h/api/v1/nodes/node-with-dashes/proxy/checkpoint/team:default/pod_underscore/ctr.dotted",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := kubeletCheckpointURL(tc.base, tc.node, tc.ns, tc.pod, tc.ctr)
			if got != tc.want {
				t.Errorf("\n  got:  %s\n  want: %s", got, tc.want)
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"abc", 5, "abc"},
		{"abcdef", 3, "abc…"},
		{"", 4, ""},
	}
	for _, tc := range cases {
		if got := truncate(tc.in, tc.n); got != tc.want {
			t.Errorf("truncate(%q,%d)=%q want %q", tc.in, tc.n, got, tc.want)
		}
	}
}
