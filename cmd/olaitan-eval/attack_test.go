package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
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
	run := recordingRunner(&calls, nil, "")
	e, err := newAttackExecutor("s3", harnessDir("s3-lateral-movement"), run, testLogger())
	if err != nil {
		t.Fatalf("newAttackExecutor: %v", err)
	}
	if err := e.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	_ = e.Cleanup(context.Background())

	// OLT-LATERAL-001 keys on a process whose exe ends /kubectl inside the
	// tenant pod, so the S3 plan must launch a /kubectl-named process in-pod
	// (kubectl is the driver binary of every call, so the meaningful check is
	// that an exec primitive references a /kubectl path in-pod).
	if firstCallContaining(calls, "/tmp/kubectl") < 0 {
		t.Errorf("S3 did not launch a /kubectl-named process in-pod; calls=%v", calls)
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

// errDummy is a tiny error type for tests that need a specific message.
type errDummy string

func (e errDummy) Error() string { return string(e) }
