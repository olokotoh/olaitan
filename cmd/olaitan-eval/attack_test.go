package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Story 11.2a red-first tests for the real in-cluster attack executor
// (attack.go). They inject a recording attackRunFunc so the exact kubectl
// argv is asserted WITHOUT a cluster (the overlay.go injectable-runner
// precedent), proving: the per-scenario plan applies the 11.1 target then
// runs the technique primitive(s) via kubectl exec; Cleanup deletes what
// Execute applied and runs even when a primitive errors; and S2 reads the
// SA token WITHOUT ever putting its value in argv, stdout, or a log line
// (length + hash only).

type recordedCall struct {
	name string
	args []string
}

// recordingRunner returns an attackRunFunc that records every call and
// returns canned stdout chosen by a matcher, plus an optional error for a
// call whose joined argv contains failOn (empty = never fail).
func recordingRunner(calls *[]recordedCall, stdoutFor func(args []string) string, failOn string) attackRunFunc {
	return func(ctx context.Context, name string, args ...string) (string, error) {
		*calls = append(*calls, recordedCall{name: name, args: append([]string(nil), args...)})
		if failOn != "" && strings.Contains(strings.Join(args, " "), failOn) {
			return "", fmt.Errorf("injected failure on %q", failOn)
		}
		if stdoutFor != nil {
			return stdoutFor(args), nil
		}
		return "", nil
	}
}

func harnessDir(slug string) string {
	return filepath.Join(scenariosTreeRoot(), slug)
}

func joinCall(c recordedCall) string {
	return c.name + " " + strings.Join(c.args, " ")
}

// firstCallContaining returns the index of the first recorded call whose
// joined argv contains sub, or -1.
func firstCallContaining(calls []recordedCall, sub string) int {
	for i, c := range calls {
		if strings.Contains(joinCall(c), sub) {
			return i
		}
	}
	return -1
}

func TestAttackExecutor_S1_AppliesTargetThenExecsEscapeThenCleansUp(t *testing.T) {
	var calls []recordedCall
	run := recordingRunner(&calls, nil, "")
	e, err := newAttackExecutor("s1", harnessDir("s1-container-escape"), run, testLogger())
	if err != nil {
		t.Fatalf("newAttackExecutor: %v", err)
	}
	e.settleWait = 0 // Story 11.2d: skip the 45s settle in unit tests
	if err := e.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if err := e.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	applyIdx := firstCallContaining(calls, "apply")
	execIdx := firstCallContaining(calls, "exec")
	delIdx := firstCallContaining(calls, "delete")
	if applyIdx < 0 {
		t.Fatalf("no kubectl apply recorded; calls=%v", calls)
	}
	if execIdx < 0 {
		t.Fatalf("no kubectl exec (escape primitive) recorded; calls=%v", calls)
	}
	if delIdx < 0 {
		t.Fatalf("no kubectl delete (cleanup) recorded; calls=%v", calls)
	}
	// Ordering: apply the target BEFORE the exec, and delete only in Cleanup
	// (after the exec).
	if applyIdx >= execIdx || execIdx >= delIdx {
		t.Errorf("expected apply(%d) < exec(%d) < delete(%d)", applyIdx, execIdx, delIdx)
	}
	// The apply targets the committed 11.1 workload manifest.
	if !strings.Contains(joinCall(calls[applyIdx]), filepath.Join("s1-container-escape", "manifests", "workload.yaml")) {
		t.Errorf("apply did not reference the s1 workload manifest: %s", joinCall(calls[applyIdx]))
	}
	// The exec targets the tenant-acme/web deployment.
	if !strings.Contains(joinCall(calls[execIdx]), "tenant-acme") || !strings.Contains(joinCall(calls[execIdx]), "web") {
		t.Errorf("exec did not target tenant-acme/web: %s", joinCall(calls[execIdx]))
	}
	// Cleanup is idempotent: it deletes with --ignore-not-found.
	if !strings.Contains(joinCall(calls[delIdx]), "--ignore-not-found") {
		t.Errorf("cleanup delete is not idempotent (no --ignore-not-found): %s", joinCall(calls[delIdx]))
	}
}

func TestAttackExecutor_CleanupRunsEvenWhenPrimitiveFails(t *testing.T) {
	var calls []recordedCall
	// Fail the exec primitive; Cleanup must still delete what was applied.
	run := recordingRunner(&calls, nil, "exec")
	e, err := newAttackExecutor("s1", harnessDir("s1-container-escape"), run, testLogger())
	if err != nil {
		t.Fatalf("newAttackExecutor: %v", err)
	}
	e.settleWait = 0 // Story 11.2d: skip the 45s settle in unit tests
	execErr := e.Execute(context.Background())
	if execErr == nil {
		t.Fatalf("expected Execute to surface the injected exec failure")
	}
	// Cleanup after a failed Execute still tears the target down.
	if err := e.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup after failed Execute: %v", err)
	}
	if firstCallContaining(calls, "delete") < 0 {
		t.Errorf("cleanup delete did not run after a failed primitive; calls=%v", calls)
	}
}

func TestAttackExecutor_S2_ReadsTokenWithoutPrintingItsValue(t *testing.T) {
	const fakeTokenValue = "eyJHEADER.PAYLOAD.SUPERSECRETSIGNATUREVALUE"
	const fakeHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	var calls []recordedCall
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	// The token step must emit ONLY length + hash from inside the pod. The
	// fake returns "<len>\n<hash>" for the token-read exec, and would return
	// the raw token only if the executor ever tried to cat it (it must not).
	stdoutFor := func(args []string) string {
		j := strings.Join(args, " ")
		if strings.Contains(j, "serviceaccount/token") {
			// The token READ step emits length + hash only.
			if strings.Contains(j, "sha256sum") || strings.Contains(j, "wc") {
				return "245\n" + fakeHash
			}
			// The API-use step captures the token into a shell var and prints
			// only the HTTP status; its stdout is a status code, not the token.
			if strings.Contains(j, "http_code") {
				return "200"
			}
			// Any OTHER command that touches the token path is a naive read
			// that would print the value: model the leak so the test catches
			// an executor that ever does this.
			return fakeTokenValue
		}
		return "200"
	}
	run := recordingRunner(&calls, stdoutFor, "")
	e, err := newAttackExecutor("s2", harnessDir("s2-credential-exfil"), run, logger)
	if err != nil {
		t.Fatalf("newAttackExecutor: %v", err)
	}
	e.settleWait = 0 // Story 11.2d: skip the 45s settle in unit tests
	if err := e.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	_ = e.Cleanup(context.Background())

	// The raw token value must NEVER appear in any recorded argv nor in any
	// log line.
	for _, c := range calls {
		if strings.Contains(joinCall(c), fakeTokenValue) {
			t.Errorf("token value leaked into a command argv: %s", joinCall(c))
		}
	}
	if strings.Contains(logBuf.String(), fakeTokenValue) {
		t.Errorf("token value leaked into a log line:\n%s", logBuf.String())
	}
	// The executor must record the token length and hash (proof it read the
	// token) without the value.
	if !strings.Contains(logBuf.String(), fakeHash) {
		t.Errorf("expected the token sha256 hash in the log; got:\n%s", logBuf.String())
	}
	// The token-read primitive uses a hashing/length read, not a bare cat.
	tokIdx := firstCallContaining(calls, "serviceaccount/token")
	if tokIdx < 0 {
		t.Fatalf("no serviceaccount/token read recorded; calls=%v", calls)
	}
	tokCall := joinCall(calls[tokIdx])
	if !strings.Contains(tokCall, "sha256sum") && !strings.Contains(tokCall, "wc") {
		t.Errorf("token read is not hash/length-only (bare cat leaks the value): %s", tokCall)
	}
	// S2 also requests the cloud metadata IP (OLT-CRED-002).
	if firstCallContaining(calls, "169.254.169.254") < 0 {
		t.Errorf("no metadata IP (169.254.169.254) request recorded; calls=%v", calls)
	}
	// S2 applies a dedicated least-privilege RBAC manifest.
	if firstCallContaining(calls, filepath.Join("s2-credential-exfil", "manifests", "rbac.yaml")) < 0 {
		t.Errorf("no least-privilege RBAC manifest applied for S2; calls=%v", calls)
	}
}

func TestAttackExecutor_S3_LaunchesKubectlNamedProcessInPod(t *testing.T) {
	var calls []recordedCall
	// targetPod resolves the concrete pod name via `kubectl get pod ... -o
	// jsonpath`; return one for that call so kubectl cp has a destination.
	stdoutFor := func(args []string) string {
		if strings.Contains(strings.Join(args, " "), "get pod") {
			return "web-6d4f9c7b8-abcde||Running\n"
		}
		return ""
	}
	run := recordingRunner(&calls, stdoutFor, "")
	e, err := newAttackExecutor("s3", harnessDir("s3-lateral-movement"), run, testLogger())
	if err != nil {
		t.Fatalf("newAttackExecutor: %v", err)
	}
	e.settleWait = 0                  // Story 11.2d: skip the 45s settle in unit tests
	e.kubectlBinary = "/fake/kubectl" // deterministic cp source in the unit test
	e.prepareKubectl = fakePrepareKubectl
	if err := e.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	_ = e.Cleanup(context.Background())

	// Story 11.2d: OLT-LATERAL-001 keys on a process whose exe ends /kubectl.
	// The prior primitive renamed the in-pod busybox to /tmp/kubectl, which
	// exited 127 (multicall dispatch) so no /kubectl process execd. The fix
	// uploads a REAL standalone kubectl with kubectl cp, then execs it. Assert
	// a real binary is uploaded (cp) to a /tmp/kubectl destination, and that
	// the primitive does NOT rename busybox.
	cpIdx := firstCallContaining(calls, "cp")
	if cpIdx < 0 || !strings.Contains(joinCall(calls[cpIdx]), "/tmp/kubectl") {
		t.Errorf("S3 did not upload a real kubectl to /tmp/kubectl via kubectl cp; calls=%v", calls)
	}
	if !strings.Contains(joinCall(calls[cpIdx]), "/fake/kubectl") {
		t.Errorf("S3 cp source is not the runner-host kubectl binary; calls=%v", calls)
	}
	if firstCallContaining(calls, "/tmp/kubectl version") < 0 {
		t.Errorf("S3 did not exec the uploaded /tmp/kubectl; calls=%v", calls)
	}
	for _, c := range calls {
		if strings.Contains(joinCall(c), "cp /bin/busybox") || strings.Contains(joinCall(c), "busybox /tmp/kubectl") {
			t.Errorf("S3 must not rename busybox (multicall exits 127): %s", joinCall(c))
		}
	}
}

// TestAttackExecutor_S3_UploadsAndExecsInTheSameLivePod: Story 11.2d kubeadm
// live run. S3 missed OLT-LATERAL-001 in 4 of 5 runs: the previous trial's
// web pod was still Terminating, the cp target was items[0] (that old pod),
// and the exec went through deploy/web to the NEW pod, which answered
// "sh: /tmp/kubectl: not found". The executor must skip terminating and
// non-Running pods, and upload to and exec in the one pod it resolved.
func TestAttackExecutor_S3_UploadsAndExecsInTheSameLivePod(t *testing.T) {
	var calls []recordedCall
	stdoutFor := func(args []string) string {
		if strings.Contains(strings.Join(args, " "), "get pod") {
			return "web-old-aaaaa|2026-09-28T11:02:20Z|Running\n" +
				"web-new-pending||Pending\n" +
				"web-new-bbbbb||Running\n"
		}
		return ""
	}
	e, err := newAttackExecutor("s3", harnessDir("s3-lateral-movement"), recordingRunner(&calls, stdoutFor, ""), testLogger())
	if err != nil {
		t.Fatalf("newAttackExecutor: %v", err)
	}
	e.settleWait = 0
	e.kubectlBinary = "/fake/kubectl"
	e.prepareKubectl = fakePrepareKubectl
	if err := e.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	cpIdx := firstCallContaining(calls, " cp ")
	if cpIdx < 0 || !strings.Contains(joinCall(calls[cpIdx]), "tenant-acme/web-new-bbbbb:/tmp/kubectl") {
		t.Fatalf("S3 did not upload to the live, non-terminating pod; calls=%v", calls)
	}
	execIdx := firstCallContaining(calls, "/tmp/kubectl version")
	if execIdx < 0 {
		t.Fatalf("S3 did not exec the uploaded kubectl; calls=%v", calls)
	}
	ex := joinCall(calls[execIdx])
	if !strings.Contains(ex, " web-new-bbbbb ") || strings.Contains(ex, "deploy/web") {
		t.Errorf("S3 exec must target the same pod it uploaded to, not deploy/web: %s", ex)
	}
}

func TestAttackExecutor_S3_FailsWhenNoLivePod(t *testing.T) {
	var calls []recordedCall
	stdoutFor := func(args []string) string {
		if strings.Contains(strings.Join(args, " "), "get pod") {
			return "web-old-aaaaa|2026-09-28T11:02:20Z|Running\n"
		}
		return ""
	}
	e, err := newAttackExecutor("s3", harnessDir("s3-lateral-movement"), recordingRunner(&calls, stdoutFor, ""), testLogger())
	if err != nil {
		t.Fatalf("newAttackExecutor: %v", err)
	}
	e.settleWait = 0
	e.kubectlBinary = "/fake/kubectl"
	e.prepareKubectl = fakePrepareKubectl
	if err := e.Execute(context.Background()); err == nil {
		t.Fatal("Execute succeeded with only a terminating pod; want an error")
	}
	if firstCallContaining(calls, " cp ") >= 0 {
		t.Errorf("S3 uploaded into a terminating pod; calls=%v", calls)
	}
}

// fakePrepareKubectl stands in for resolveUploadKubectl in unit tests that
// use a non-existent /fake/kubectl: it passes the path through unchanged.
func fakePrepareKubectl(path string) (string, string, error) { return path, "sha256-fake", nil }

// TestAttackExecutor_S3_DoesNotMaskAFailedKubectl: review round 1 (P1). The
// S3 in-pod command ended "| head -n 2; true", so a kubectl that never ran
// (not found, wrong arch, truncated upload) still reported success and the
// trial looked like a detection miss. The exit code must reach Execute.
func TestAttackExecutor_S3_DoesNotMaskAFailedKubectl(t *testing.T) {
	var calls []recordedCall
	stdoutFor := func(args []string) string {
		if strings.Contains(strings.Join(args, " "), "get pod") {
			return "web-new-bbbbb||Running\n"
		}
		return ""
	}
	e, err := newAttackExecutor("s3", harnessDir("s3-lateral-movement"), recordingRunner(&calls, stdoutFor, "/tmp/kubectl version"), testLogger())
	if err != nil {
		t.Fatalf("newAttackExecutor: %v", err)
	}
	e.settleWait = 0
	e.kubectlBinary = "/fake/kubectl"
	e.prepareKubectl = fakePrepareKubectl
	if err := e.Execute(context.Background()); err == nil {
		t.Fatal("Execute succeeded although the in-pod kubectl exec failed")
	}
	idx := firstCallContaining(calls, "/tmp/kubectl version")
	if idx < 0 {
		t.Fatalf("S3 did not exec kubectl; calls=%v", calls)
	}
	script := calls[idx].args[len(calls[idx].args)-1]
	if strings.Contains(script, "true") || strings.Contains(script, "| head") {
		t.Errorf("S3 in-pod script still masks the exit code: %q", script)
	}
}

// TestResolveUploadKubectl: review round 1 (P2) and decision D2. The runner
// uploads its own kubectl, so the path must resolve through symlinks and
// shims to a real ELF binary, and its sha256 is recorded for the run.
func TestResolveUploadKubectl(t *testing.T) {
	dir := t.TempDir()
	elf := filepath.Join(dir, "kubectl-real")
	if err := os.WriteFile(elf, []byte("\x7fELF\x02\x01\x01payload"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "kubectl")
	if err := os.Symlink(elf, link); err != nil {
		t.Fatal(err)
	}
	got, sum, err := resolveUploadKubectl(link)
	if err != nil {
		t.Fatalf("resolveUploadKubectl(symlink): %v", err)
	}
	if got != elf {
		t.Errorf("resolved %q, want the symlink target %q", got, elf)
	}
	if len(sum) != 64 {
		t.Errorf("sha256 = %q, want 64 hex chars", sum)
	}

	shim := filepath.Join(dir, "kubectl-shim")
	if err := os.WriteFile(shim, []byte("#!/bin/sh\nexec real-kubectl \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolveUploadKubectl(shim); err == nil {
		t.Error("a shell-script shim was accepted; want an error (it cannot run in the pod)")
	}
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "missing"), dangling); err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolveUploadKubectl(dangling); err == nil {
		t.Error("a dangling symlink was accepted; want an error")
	}
}

func TestNewAttackExecutor_RejectsUnknownScenario(t *testing.T) {
	if _, err := newAttackExecutor("s9", harnessDir("nope"), recordingRunner(&[]recordedCall{}, nil, ""), testLogger()); err == nil {
		t.Errorf("expected newAttackExecutor to reject an unknown scenario id")
	}
}

// TestAttackExecutor_ApplyRetriesTerminatingNamespace proves Execute rides out
// a transient "namespace is being terminated" apply race (left by a prior
// trial or test cleanup) rather than failing the run, and that a non-transient
// apply error is NOT retried.
func TestAttackExecutor_ApplyRetriesTerminatingNamespace(t *testing.T) {
	var applyAttempts int
	run := func(ctx context.Context, name string, args ...string) (string, error) {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "apply") {
			applyAttempts++
			if applyAttempts == 1 {
				return "", errDummy("Error from server (Forbidden): ... namespace tenant-acme because it is being terminated")
			}
		}
		return "", nil
	}
	e, err := newAttackExecutor("s1", harnessDir("s1-container-escape"), run, testLogger())
	if err != nil {
		t.Fatalf("newAttackExecutor: %v", err)
	}
	e.settleWait = 0               // Story 11.2d: skip the 45s settle in unit tests
	e.retryWait = time.Millisecond // do not sleep 5s in the unit test
	if err := e.Execute(context.Background()); err != nil {
		t.Fatalf("Execute should have retried past the terminating-namespace race: %v", err)
	}
	if applyAttempts < 2 {
		t.Errorf("apply attempts = %d; want >= 2 (a retry after the terminating-namespace error)", applyAttempts)
	}

	// A non-transient apply error must NOT be retried.
	var hardAttempts int
	hardRun := func(ctx context.Context, name string, args ...string) (string, error) {
		if strings.Contains(strings.Join(args, " "), "apply") {
			hardAttempts++
			return "", errDummy("error validating data: unknown field \"bogus\"")
		}
		return "", nil
	}
	e2, _ := newAttackExecutor("s1", harnessDir("s1-container-escape"), hardRun, testLogger())
	e2.retryWait = time.Millisecond
	e2.settleWait = 0
	if err := e2.Execute(context.Background()); err == nil {
		t.Fatalf("Execute should surface a non-transient apply error")
	}
	if hardAttempts != 1 {
		t.Errorf("hard apply attempts = %d; want 1 (no retry on a real manifest error)", hardAttempts)
	}
}

// TestAttackExecutor_CleanupIsSurgical proves Cleanup deletes the attacker
// resources by name and never deletes the shared tenant-acme Namespace.
func TestAttackExecutor_CleanupIsSurgical(t *testing.T) {
	var calls []recordedCall
	run := recordingRunner(&calls, nil, "")
	e, err := newAttackExecutor("s2", harnessDir("s2-credential-exfil"), run, testLogger())
	if err != nil {
		t.Fatalf("newAttackExecutor: %v", err)
	}
	e.settleWait = 0 // Story 11.2d: skip the 45s settle in unit tests
	if err := e.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if firstCallContaining(calls, "deployment/web") < 0 {
		t.Errorf("cleanup did not delete deployment/web; calls=%v", calls)
	}
	if firstCallContaining(calls, "serviceaccount/s2-attacker") < 0 {
		t.Errorf("S2 cleanup did not delete the least-privilege SA; calls=%v", calls)
	}
	for _, c := range calls {
		j := joinCall(c)
		if strings.Contains(j, "delete") && (strings.Contains(j, "namespace/") || strings.Contains(j, "delete namespace") || strings.Contains(j, " ns ")) {
			t.Errorf("cleanup must NOT delete the shared namespace: %s", j)
		}
		if strings.Contains(j, "delete") && !strings.Contains(j, "--ignore-not-found") {
			t.Errorf("cleanup delete is not idempotent: %s", j)
		}
	}
}

// TestAttackExecutor_SettlesBeforeCleanup proves Story 11.2d's
// settle-before-cleanup: Execute waits settleWait AFTER the primitive and
// BEFORE returning (so the caller's deferred Cleanup does not delete the pod
// before the correlator resolves workload posture off the live pod), and a
// cancelled context short-circuits the wait. The default settleWait is
// non-zero so a real run never deletes the target immediately.
func TestAttackExecutor_SettlesBeforeCleanup(t *testing.T) {
	var calls []recordedCall
	run := recordingRunner(&calls, nil, "")
	e, err := newAttackExecutor("s1", harnessDir("s1-container-escape"), run, testLogger())
	if err != nil {
		t.Fatalf("newAttackExecutor: %v", err)
	}
	if e.settleWait <= 0 {
		t.Fatalf("default settleWait must be positive so a real run does not delete the pod before posture resolves; got %s", e.settleWait)
	}
	e.settleWait = 60 * time.Millisecond
	start := time.Now()
	if err := e.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if elapsed := time.Since(start); elapsed < e.settleWait {
		t.Errorf("Execute returned after %s; expected to settle at least %s before returning", elapsed, e.settleWait)
	}

	// A cancelled context must short-circuit the settle so a shutdown is not
	// blocked for the full window.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e.settleWait = 10 * time.Second
	start = time.Now()
	_ = e.Execute(ctx)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("cancelled-context settle took %s; expected a prompt return", elapsed)
	}
}

// errDummy is a tiny error type for tests that need a specific message.
type errDummy string

func (e errDummy) Error() string { return string(e) }
