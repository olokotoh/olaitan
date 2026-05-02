// Spike harness: invoke the kubelet checkpoint API for a given pod/container,
// time the call, and report PASS/FAIL with the wall-clock duration.
//
// The harness spawns `kubectl proxy` as a subprocess so the operator does
// not need to plumb client-cert authentication into the spike. It relies
// on the kubeconfig that the operator already has (KUBECONFIG env var or
// $HOME/.kube/config). This matches the operator's manual reproduction
// recipe in README.md exactly.
//
// Story 1.4 deliverable. NOT production code: see ../README.md and the
// referenced ADR for the chosen forensic-capture path that ships in
// internal/response/forensics/ under Story 4.2.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// kubeletCheckpointURL returns the kubectl-proxy-relative URL for the
// kubelet's checkpoint subresource on the given node, addressing the
// pod/container by namespace and name. The kubelet endpoint is
// POST /checkpoint/{namespace}/{pod}/{container} (alpha at K8s 1.29,
// beta at K8s 1.30); routing it through the apiserver's nodes/proxy
// subresource lets the harness reuse kubeconfig-resident credentials.
func kubeletCheckpointURL(proxyBase, node, namespace, pod, container string) string {
	return fmt.Sprintf(
		"%s/api/v1/nodes/%s/proxy/checkpoint/%s/%s/%s",
		strings.TrimRight(proxyBase, "/"),
		url.PathEscape(node),
		url.PathEscape(namespace),
		url.PathEscape(pod),
		url.PathEscape(container),
	)
}

type runResult struct {
	httpStatus int
	wallClock  time.Duration
	body       string
	err        error
}

func postCheckpoint(ctx context.Context, client *http.Client, target string) runResult {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, nil)
	if err != nil {
		return runResult{wallClock: time.Since(start), err: err}
	}
	resp, err := client.Do(req)
	if err != nil {
		return runResult{wallClock: time.Since(start), err: err}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return runResult{
		httpStatus: resp.StatusCode,
		wallClock:  time.Since(start),
		body:       strings.TrimSpace(string(body)),
	}
}

func waitForProxy(ctx context.Context, base string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	target := strings.TrimRight(base, "/") + "/healthz"
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return fmt.Errorf("kubectl proxy did not become ready within %s", timeout)
}

func main() {
	var (
		namespace  = flag.String("namespace", "criu-spike", "pod namespace")
		pod        = flag.String("pod", "busybox-target", "pod name")
		container  = flag.String("container", "busybox", "container name within the pod")
		node       = flag.String("node", "olaitan-criu-spike-control-plane", "node name (kubelet host)")
		runs       = flag.Int("runs", 3, "number of checkpoint attempts to time")
		proxyPort  = flag.Int("proxy-port", 18001, "local port for kubectl proxy")
		callTimeout = flag.Duration("timeout", 30*time.Second, "per-call timeout")
	)
	flag.Parse()

	if *runs < 1 {
		log.Fatalf("--runs must be >= 1, got %d", *runs)
	}

	proxyBase := "http://localhost:" + strconv.Itoa(*proxyPort)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxyCmd := exec.CommandContext(ctx, "kubectl", "proxy", "--port="+strconv.Itoa(*proxyPort))
	proxyCmd.Stdout = io.Discard
	proxyCmd.Stderr = io.Discard
	if err := proxyCmd.Start(); err != nil {
		log.Fatalf("failed to start kubectl proxy: %v", err)
	}
	defer func() {
		cancel()
		_ = proxyCmd.Wait()
	}()

	if err := waitForProxy(ctx, proxyBase, 5*time.Second); err != nil {
		log.Fatalf("proxy not ready: %v", err)
	}

	target := kubeletCheckpointURL(proxyBase, *node, *namespace, *pod, *container)
	fmt.Printf("Target: %s\n\n", target)

	httpClient := &http.Client{Timeout: *callTimeout}
	successes := 0
	results := make([]runResult, 0, *runs)

	for i := 1; i <= *runs; i++ {
		r := postCheckpoint(ctx, httpClient, target)
		results = append(results, r)
		switch {
		case r.err != nil:
			fmt.Printf("Run %d: ERROR after %s: %v\n", i, r.wallClock, r.err)
		case r.httpStatus == http.StatusOK:
			fmt.Printf("Run %d: PASS http=%d wall=%s\n", i, r.httpStatus, r.wallClock)
			successes++
		default:
			fmt.Printf("Run %d: FAIL http=%d wall=%s body=%q\n",
				i, r.httpStatus, r.wallClock, truncate(r.body, 240))
		}
	}

	fmt.Println()
	fmt.Printf("Summary: %d/%d successful checkpoints over %d runs.\n", successes, *runs, *runs)
	if successes == 0 {
		fmt.Println("Outcome: FAIL — no successful checkpoint. See ADR-2026-05-DD-NN for the documented fallback path.")
		os.Exit(2)
	}
	if successes < *runs {
		fmt.Println("Outcome: PARTIAL — at least one checkpoint succeeded but the run was not consistent.")
		os.Exit(3)
	}
	fmt.Println("Outcome: PASS — all attempts succeeded.")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
