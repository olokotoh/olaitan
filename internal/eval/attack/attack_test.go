package attack

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Story 11.2a red-first tests for the real in-cluster attack executor
// (attack.go). They inject a recording RunFunc so the exact kubectl
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

// recordingRunner returns an RunFunc that records every call and
// returns canned stdout chosen by a matcher, plus an optional error for a
// call whose joined argv contains failOn (empty = never fail).
func recordingRunner(calls *[]recordedCall, stdoutFor func(args []string) string, failOn string) RunFunc {
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
	return filepath.Join("..", "..", "..", "deploy", "demo", "scenarios", slug)
}

// runningPodStdout wraps a stdout matcher so `kubectl get pod` always resolves
// one live, Running, non-terminating pod (Execute now resolves the target pod
// for every scenario before the primitive, review round 1 C3). extra answers
// the scenario-specific calls (token reads, version output); nil means "".
func runningPodStdout(extra func(args []string) string) func(args []string) string {
	return func(args []string) string {
		if strings.Contains(strings.Join(args, " "), "get pod") {
			return "web-6d4f9c7b8-abcde||Running\n"
		}
		if extra != nil {
			return extra(args)
		}
		return ""
	}
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
	run := recordingRunner(&calls, runningPodStdout(nil), "")
	e, err := New("s1", harnessDir("s1-container-escape"), run, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e.SettleWait = 0 // Story 11.2d: skip the 45s settle in unit tests
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
	// Fail the exec primitive; Cleanup must still delete what was applied. The
	// pod still resolves (get pod is not an exec) so the failure is the
	// primitive, not target bring-up.
	run := recordingRunner(&calls, runningPodStdout(nil), "exec")
	e, err := New("s1", harnessDir("s1-container-escape"), run, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e.SettleWait = 0 // Story 11.2d: skip the 45s settle in unit tests
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
	run := recordingRunner(&calls, runningPodStdout(stdoutFor), "")
	e, err := New("s2", harnessDir("s2-credential-exfil"), run, logger)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e.SettleWait = 0 // Story 11.2d: skip the 45s settle in unit tests
	if err := e.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	_ = e.Cleanup(context.Background())

	// Review round 1 (C1, AC4): the token must reach curl on stdin as the whole
	// Authorization header (-H @-), never in curl's argv. The prior
	// `-H "Authorization: Bearer $TOKEN"` put the value in %proc.cmdline.
	apiIdx := -1
	for i, c := range calls {
		j := joinCall(c)
		if strings.Contains(j, "curl") && strings.Contains(j, "http_code") && strings.Contains(j, "/secrets") {
			apiIdx = i
			break
		}
	}
	if apiIdx < 0 {
		t.Fatalf("no S2 kube-API curl recorded; calls=%v", calls)
	}
	apiCall := joinCall(calls[apiIdx])
	if !strings.Contains(apiCall, "-H @-") {
		t.Errorf("S2 kube-API curl must read the Authorization header from stdin (-H @-): %s", apiCall)
	}
	if strings.Contains(apiCall, `-H "Authorization`) || strings.Contains(apiCall, "Bearer $TOKEN") {
		t.Errorf("S2 kube-API curl still puts the token in argv: %s", apiCall)
	}

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
	e, err := New("s3", harnessDir("s3-lateral-movement"), run, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e.SettleWait = 0                  // Story 11.2d: skip the 45s settle in unit tests
	e.kubectlBinary = "/fake/kubectl" // deterministic cp source in the unit test
	e.PrepareKubectl = fakePrepareKubectl
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
	e, err := New("s3", harnessDir("s3-lateral-movement"), recordingRunner(&calls, stdoutFor, ""), testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e.SettleWait = 0
	e.kubectlBinary = "/fake/kubectl"
	e.PrepareKubectl = fakePrepareKubectl
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
	e, err := New("s3", harnessDir("s3-lateral-movement"), recordingRunner(&calls, stdoutFor, ""), testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e.SettleWait = 0
	e.kubectlBinary = "/fake/kubectl"
	e.PrepareKubectl = fakePrepareKubectl
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
	e, err := New("s3", harnessDir("s3-lateral-movement"), recordingRunner(&calls, stdoutFor, "/tmp/kubectl version"), testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e.SettleWait = 0
	e.kubectlBinary = "/fake/kubectl"
	e.PrepareKubectl = fakePrepareKubectl
	if err := e.Execute(context.Background()); err == nil {
		t.Fatal("Execute succeeded although the in-pod kubectl exec failed")
	}
	idx := firstCallContaining(calls, "/tmp/kubectl version")
	if idx < 0 {
		t.Fatalf("S3 did not exec kubectl; calls=%v", calls)
	}
	// The recording runner cannot run sh, so only the script text proves no
	// pipe or trailing command swallows kubectl's exit status.
	script := calls[idx].args[len(calls[idx].args)-1]
	if want := "chmod +x /tmp/kubectl && /tmp/kubectl version --client 2>&1"; script != want {
		t.Errorf("S3 in-pod script = %q, want exactly %q (nothing after kubectl may mask its exit code)", script, want)
	}
}

// writeELF writes a minimal ELF64 executable named name under dir. With
// interp it carries a PT_INTERP program header, i.e. it is dynamically
// linked and needs a loader the busybox target pod does not have.
func writeELF(t *testing.T, dir, name string, interp bool) string {
	t.Helper()
	var buf bytes.Buffer
	hdr := elf.Header64{
		Type: uint16(elf.ET_EXEC), Machine: uint16(elf.EM_X86_64), Version: uint32(elf.EV_CURRENT),
		Ehsize: 64, Phentsize: 56, Shentsize: 64,
	}
	copy(hdr.Ident[:], []byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)})
	loader := []byte("/lib64/ld-linux-x86-64.so.2\x00")
	if interp {
		hdr.Phoff, hdr.Phnum = 64, 1
	}
	if err := binary.Write(&buf, binary.LittleEndian, hdr); err != nil {
		t.Fatal(err)
	}
	if interp {
		prog := elf.Prog64{Type: uint32(elf.PT_INTERP), Off: 64 + 56, Filesz: uint64(len(loader)), Memsz: uint64(len(loader))}
		if err := binary.Write(&buf, binary.LittleEndian, prog); err != nil {
			t.Fatal(err)
		}
		buf.Write(loader)
	}
	buf.WriteString("payload")
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestResolveUploadKubectl: review rounds 1 (P2) and 2, decision D2. The
// runner uploads its own kubectl, so the path must resolve through symlinks
// to a real, statically linked kubectl, and the recorded sha256 must be the
// digest of the file that is uploaded.
func TestResolveUploadKubectl(t *testing.T) {
	dir := t.TempDir()
	real := writeELF(t, dir, "versions/1.34/bin/kubectl", false)
	link := filepath.Join(dir, "kubectl")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	got, sum, err := resolveUploadKubectl(link)
	if err != nil {
		t.Fatalf("resolveUploadKubectl(symlink): %v", err)
	}
	if got != real {
		t.Errorf("resolved %q, want the symlink target %q", got, real)
	}
	data, _ := os.ReadFile(real)
	if want := fmt.Sprintf("%x", sha256.Sum256(data)); sum != want {
		t.Errorf("sha256 = %q, want the digest of the uploaded file %q", sum, want)
	}

	for name, path := range map[string]string{
		// A script shim cannot run in the pod.
		"script shim": func() string {
			p := filepath.Join(dir, "shim", "kubectl")
			_ = os.MkdirAll(filepath.Dir(p), 0o755)
			_ = os.WriteFile(p, []byte("#!/bin/sh\nexec real-kubectl \"$@\"\n"), 0o755)
			return p
		}(),
		// snap, mise and aqua put a symlink named kubectl on PATH that
		// resolves to their own multicall ELF.
		"snap-style multicall target": func() string {
			target := writeELF(t, dir, "usr/bin/snap", false)
			p := filepath.Join(dir, "snap", "bin", "kubectl")
			_ = os.MkdirAll(filepath.Dir(p), 0o755)
			_ = os.Symlink(target, p)
			return p
		}(),
		// A dynamically linked kubectl has no loader in the busybox target.
		"dynamically linked": writeELF(t, dir, "nix/bin/kubectl", true),
		"dangling symlink": func() string {
			p := filepath.Join(dir, "dangling")
			_ = os.Symlink(filepath.Join(dir, "missing"), p)
			return p
		}(),
		"not on PATH": "",
	} {
		if _, _, err := resolveUploadKubectl(path); err == nil {
			t.Errorf("%s (%q) was accepted; want an error", name, path)
		}
	}
}

// TestAttackExecutor_S3_WithoutAStubUsesTheRealResolver: review round 2. An
// executor whose PrepareKubectl is unset must not panic; it resolves the
// kubectl itself.
func TestAttackExecutor_S3_WithoutAStubUsesTheRealResolver(t *testing.T) {
	var calls []recordedCall
	stdoutFor := func(args []string) string {
		if strings.Contains(strings.Join(args, " "), "get pod") {
			return "web-new-bbbbb||Running\n"
		}
		return ""
	}
	e, err := New("s3", harnessDir("s3-lateral-movement"), recordingRunner(&calls, stdoutFor, ""), testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e.SettleWait = 0
	e.kubectlBinary = writeELF(t, t.TempDir(), "kubectl", false)
	e.PrepareKubectl = nil
	if err := e.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if firstCallContaining(calls, "cp "+e.kubectlBinary) < 0 {
		t.Errorf("S3 did not upload the resolved kubectl %q; calls=%v", e.kubectlBinary, calls)
	}
}

// TestAttackExecutor_S3_LogsTheKubectlVersion: review round 2, decision D2
// ("log kubectl version + sha256 in the run"). The in-pod `version --client`
// output names the exact client that ran; its first line is logged.
func TestAttackExecutor_S3_LogsTheKubectlVersion(t *testing.T) {
	var calls []recordedCall
	stdoutFor := func(args []string) string {
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "get pod"):
			return "web-new-bbbbb||Running\n"
		case strings.Contains(joined, "/tmp/kubectl version"):
			return "Client Version: v1.34.12\nKustomize Version: v5.7.1\n"
		}
		return ""
	}
	var logs bytes.Buffer
	e, err := New("s3", harnessDir("s3-lateral-movement"), recordingRunner(&calls, stdoutFor, ""), slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e.SettleWait = 0
	e.kubectlBinary = "/fake/kubectl"
	e.PrepareKubectl = fakePrepareKubectl
	if err := e.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(logs.String(), `kubectl_version="Client Version: v1.34.12"`) {
		t.Errorf("the run log does not record the in-pod kubectl version:\n%s", logs.String())
	}
}

// TestAttackNamespaceIsInTheKubectlRuleScope: review round 2. The chart's
// kubectl rule and D3's exception only cover tenant- namespaces, so S3 is
// detected only while the attack namespace carries that prefix.
func TestAttackNamespaceIsInTheKubectlRuleScope(t *testing.T) {
	if !strings.HasPrefix(Namespace, "tenant-") {
		t.Fatalf("Namespace %q is outside the chart kubectl rule's tenant- scope", Namespace)
	}
	values, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "helm", "olaitan", "values.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(values), "k8s.ns.name startswith tenant-") {
		t.Error("the chart kubectl rule no longer scopes on tenant-; update Namespace and this test together")
	}
}

func TestNewAttackExecutor_RejectsUnknownScenario(t *testing.T) {
	if _, err := New("s9", harnessDir("nope"), recordingRunner(&[]recordedCall{}, nil, ""), testLogger()); err == nil {
		t.Errorf("expected New to reject an unknown scenario id")
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
		if strings.Contains(joined, "get pod") {
			return "web-6d4f9c7b8-abcde||Running\n", nil
		}
		if strings.Contains(joined, "apply") {
			applyAttempts++
			if applyAttempts == 1 {
				return "", errDummy("Error from server (Forbidden): ... namespace tenant-acme because it is being terminated")
			}
		}
		return "", nil
	}
	e, err := New("s1", harnessDir("s1-container-escape"), run, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e.SettleWait = 0               // Story 11.2d: skip the 45s settle in unit tests
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
	e2, err := New("s1", harnessDir("s1-container-escape"), hardRun, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e2.retryWait = time.Millisecond
	e2.SettleWait = 0
	if err := e2.Execute(context.Background()); err == nil {
		t.Fatalf("Execute should surface a non-transient apply error")
	}
	if hardAttempts != 1 {
		t.Errorf("hard apply attempts = %d; want 1 (no retry on a real manifest error)", hardAttempts)
	}
}

// newS1ForRetry builds an s1 executor with a tiny backoff and no settle for
// the target-bring-up retry tests.
func newS1ForRetry(t *testing.T, run RunFunc) *Executor {
	t.Helper()
	e, err := New("s1", harnessDir("s1-container-escape"), run, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e.SettleWait = 0
	e.retryWait = time.Millisecond // do not sleep the real 5s in the unit test
	return e
}

// TestEnsureTargetReady covers the drain-race retry (review round 3). The e2e
// RS smoke deletes the shared tenant-acme namespace with --wait=false right
// before the eval smoke, so the drain can sweep the Deployment mid-rollout
// ("object has been deleted"). Target bring-up re-applies and waits again, with
// exact counts and ordering, but a genuine timeout is NOT retried, the named
// mismatch is surfaced, and the loop is bounded.
func TestEnsureTargetReady(t *testing.T) {
	t.Run("re-applies past one mid-rollout sweep, exact counts and order", func(t *testing.T) {
		var calls []string
		var applyCount, rolloutCount int
		run := func(ctx context.Context, name string, args ...string) (string, error) {
			joined := strings.Join(args, " ")
			calls = append(calls, joined)
			switch {
			case strings.Contains(joined, "get pod"):
				return "web-6d4f9c7b8-abcde||Running\n", nil
			case strings.Contains(joined, "apply"):
				applyCount++
			case strings.Contains(joined, "rollout status"):
				rolloutCount++
				if rolloutCount == 1 {
					return "", errDummy("error: deployments.apps \"web\" has been deleted")
				}
			}
			return "", nil
		}
		e := newS1ForRetry(t, run)
		if err := e.Execute(context.Background()); err != nil {
			t.Fatalf("Execute should ride out one deletion race: %v", err)
		}
		if applyCount != 2 {
			t.Errorf("apply count = %d; want exactly 2 (initial + one re-apply)", applyCount)
		}
		if rolloutCount != 2 {
			t.Errorf("rollout count = %d; want exactly 2 (one race + one success)", rolloutCount)
		}
		// Order: the re-apply must come AFTER the first failed rollout.
		firstRollout, reApply := -1, -1
		seenApply := 0
		for i, c := range calls {
			if strings.Contains(c, "rollout status") && firstRollout < 0 {
				firstRollout = i
			}
			if strings.Contains(c, "apply") {
				seenApply++
				if seenApply == 2 {
					reApply = i
				}
			}
		}
		if firstRollout < 0 || reApply < 0 || reApply < firstRollout {
			t.Errorf("re-apply(%d) must follow the first rollout(%d)", reApply, firstRollout)
		}
	})

	t.Run("a genuine rollout timeout is not retried", func(t *testing.T) {
		var rollouts int
		run := func(ctx context.Context, name string, args ...string) (string, error) {
			joined := strings.Join(args, " ")
			if strings.Contains(joined, "get pod") {
				return "web-6d4f9c7b8-abcde||Running\n", nil
			}
			if strings.Contains(joined, "rollout status") {
				rollouts++
				return "", errDummy("error: timed out waiting for the condition")
			}
			return "", nil
		}
		e := newS1ForRetry(t, run)
		if err := e.Execute(context.Background()); err == nil {
			t.Fatal("Execute should surface a genuine rollout timeout")
		}
		if rollouts != 1 {
			t.Errorf("rollout attempts on a real timeout = %d; want 1 (no retry)", rollouts)
		}
	})

	t.Run("a drifted Deployment name is not a drain race", func(t *testing.T) {
		var rollouts int
		run := func(ctx context.Context, name string, args ...string) (string, error) {
			joined := strings.Join(args, " ")
			if strings.Contains(joined, "rollout status") {
				rollouts++
				return "", errDummy(`error: deployments.apps "api" not found`)
			}
			return "", nil
		}
		e := newS1ForRetry(t, run)
		if err := e.Execute(context.Background()); err == nil {
			t.Fatal("a missing, differently-named Deployment must not be retried as a drain race")
		}
		if rollouts != 1 {
			t.Errorf("rollout attempts on a name mismatch = %d; want 1 (no retry)", rollouts)
		}
	})

	t.Run("exhausts the bounded retries and returns the last error", func(t *testing.T) {
		var rollouts int
		run := func(ctx context.Context, name string, args ...string) (string, error) {
			joined := strings.Join(args, " ")
			if strings.Contains(joined, "get pod") {
				return "web-6d4f9c7b8-abcde||Running\n", nil
			}
			if strings.Contains(joined, "rollout status") {
				rollouts++
				return "", errDummy("error: object has been deleted")
			}
			return "", nil
		}
		e := newS1ForRetry(t, run)
		if err := e.Execute(context.Background()); err == nil {
			t.Fatal("a never-ending drain race must eventually fail, not loop forever")
		}
		if rollouts != applyRetries {
			t.Errorf("rollout attempts = %d; want applyRetries=%d (bounded)", rollouts, applyRetries)
		}
	})

	t.Run("cancel during backoff returns the context error with the last cause", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		run := func(c context.Context, name string, args ...string) (string, error) {
			joined := strings.Join(args, " ")
			if strings.Contains(joined, "rollout status") {
				cancel() // cancel just before the first backoff
				return "", errDummy("error: object has been deleted")
			}
			return "", nil
		}
		e := newS1ForRetry(t, run)
		e.retryWait = time.Hour // make the backoff block until the cancel fires
		err := e.Execute(ctx)
		if err == nil {
			t.Fatal("a cancel during backoff must fail")
		}
		if !strings.Contains(err.Error(), "wait target ready") || !strings.Contains(err.Error(), "last attempt") {
			t.Errorf("cancel error must wrap the rollout cause: %v", err)
		}
	})

	t.Run("waits out a still-terminating namespace before applying", func(t *testing.T) {
		var nsChecks, applies int
		run := func(ctx context.Context, name string, args ...string) (string, error) {
			joined := strings.Join(args, " ")
			switch {
			case strings.Contains(joined, "get ns"):
				nsChecks++
				if nsChecks == 1 {
					return "Terminating", nil
				}
				return "Active", nil
			case strings.Contains(joined, "get pod"):
				return "web-6d4f9c7b8-abcde||Running\n", nil
			case strings.Contains(joined, "apply"):
				applies++
			}
			return "", nil
		}
		e := newS1ForRetry(t, run)
		if err := e.Execute(context.Background()); err != nil {
			t.Fatalf("Execute should wait out the terminating namespace: %v", err)
		}
		if nsChecks < 2 {
			t.Errorf("namespace phase checks = %d; want >= 2 (waited out Terminating)", nsChecks)
		}
		if applies != 1 {
			t.Errorf("apply count = %d; want 1 (applied once the namespace settled)", applies)
		}
	})
}

// TestIsDeletionRaceError pins the round-3 R3-1 tightening: only the named
// Deployment and the named Namespace drain races are retried; a bare "not
// found", an unverified "no longer exists", and a real timeout are not.
func TestIsDeletionRaceError(t *testing.T) {
	races := []string{
		"error: object has been deleted",
		`deployments.apps "web" not found`,
		`Error from server (NotFound): namespaces "tenant-acme" not found`,
		"namespace tenant-acme is being terminated",
	}
	notRaces := []string{
		`deployments.apps "api" not found`,
		"error: the server could not find the requested resource",
		"configmaps \"x\" not found",
		"no longer exists",
		"timed out waiting for the condition",
		"",
	}
	for _, m := range races {
		if !isDeletionRaceError(errDummy(m)) {
			t.Errorf("want drain race for %q", m)
		}
	}
	for _, m := range notRaces {
		if m == "" {
			if isDeletionRaceError(nil) {
				t.Error("nil must not be a drain race")
			}
			continue
		}
		if isDeletionRaceError(errDummy(m)) {
			t.Errorf("must NOT be a drain race: %q", m)
		}
	}
}

const fakeSHA256Hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// s2TokenStdout answers the S2 token-read with a valid "<len>\n<hash>" and the
// kube-API / metadata steps with an HTTP status, plus the live pod.
func s2TokenStdout(extra func(args []string) string) func(args []string) string {
	return runningPodStdout(func(args []string) string {
		j := strings.Join(args, " ")
		if strings.Contains(j, "serviceaccount/token") && (strings.Contains(j, "sha256sum") || strings.Contains(j, "wc")) {
			return "245\n" + fakeSHA256Hex
		}
		if extra != nil {
			return extra(args)
		}
		return "200"
	})
}

// TestAttackExecutor_S2_ExecFailureFailsTheTrial pins round-3 R3-10: a kubectl
// exec that itself fails (pod swept, curl missing in the image) fails the
// trial, so a run is never recorded as executed with steps that did not run.
// An HTTP-level refusal (403) is a real attempt and stays a success.
func TestAttackExecutor_S2_ExecFailureFailsTheTrial(t *testing.T) {
	t.Run("kube-API exec failure fails the trial", func(t *testing.T) {
		run := func(ctx context.Context, name string, args ...string) (string, error) {
			j := strings.Join(args, " ")
			if strings.Contains(j, "get pod") {
				return "web-6d4f9c7b8-abcde||Running\n", nil
			}
			if strings.Contains(j, "serviceaccount/token") && (strings.Contains(j, "sha256sum") || strings.Contains(j, "wc")) {
				return "245\n" + fakeSHA256Hex, nil
			}
			if strings.Contains(j, "/secrets") { // the kube-API curl exec fails (pod gone / curl missing)
				return "", errDummy("command terminated with exit code 97")
			}
			return "", nil
		}
		e, err := New("s2", harnessDir("s2-credential-exfil"), run, testLogger())
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		e.SettleWait = 0
		if err := e.Execute(context.Background()); err == nil {
			t.Fatal("a failed kube-API exec must fail the trial")
		} else if !strings.Contains(err.Error(), "s2 kube-API use") {
			t.Errorf("error should name the kube-API step: %v", err)
		}
	})

	t.Run("an HTTP refusal is still a real attempt", func(t *testing.T) {
		run := recordingRunner(&[]recordedCall{}, s2TokenStdout(func(args []string) string {
			if strings.Contains(strings.Join(args, " "), "/secrets") {
				return "403"
			}
			return "200"
		}), "")
		e, err := New("s2", harnessDir("s2-credential-exfil"), run, testLogger())
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		e.SettleWait = 0
		if err := e.Execute(context.Background()); err != nil {
			t.Fatalf("a 403 is a real attempt, not a trial failure: %v", err)
		}
	})
}

// TestAttackExecutor_S2_RejectsAnUnprojectedToken pins round-1 C6: a token read
// that returns no real token (len 0 or a non-hash) fails the trial instead of
// logging a successful credential read.
func TestAttackExecutor_S2_RejectsAnUnprojectedToken(t *testing.T) {
	run := recordingRunner(&[]recordedCall{}, runningPodStdout(func(args []string) string {
		if strings.Contains(strings.Join(args, " "), "serviceaccount/token") {
			return "0\n" // no token projected
		}
		return "200"
	}), "")
	e, err := New("s2", harnessDir("s2-credential-exfil"), run, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e.SettleWait = 0
	if err := e.Execute(context.Background()); err == nil {
		t.Fatal("an unprojected token must fail the trial")
	} else if !strings.Contains(err.Error(), "unexpected shape") {
		t.Errorf("error should name the bad token shape: %v", err)
	}
}

func TestValidTokenShape(t *testing.T) {
	if !validTokenShape("245", fakeSHA256Hex) {
		t.Error("a positive length and 64-hex hash is a valid shape")
	}
	for _, c := range []struct{ len, hash string }{
		{"0", fakeSHA256Hex},             // empty token
		{"-5", fakeSHA256Hex},            // negative
		{"abc", fakeSHA256Hex},           // non-numeric length
		{"245", "deadbeef"},              // short hash
		{"245", strings.Repeat("g", 64)}, // non-hex hash
		{"", ""},
	} {
		if validTokenShape(c.len, c.hash) {
			t.Errorf("want invalid shape for len=%q hash=%q", c.len, c.hash)
		}
	}
}

// TestAttackExecutor_S1_GuardsAMissingNsenterAndRecordsRC pins round-1 C5: the
// S1 primitive hard-fails on a missing nsenter (exit 97) rather than masking it
// with a trailing `true`, and records nsenter's exit code.
func TestAttackExecutor_S1_GuardsAMissingNsenterAndRecordsRC(t *testing.T) {
	var calls []recordedCall
	run := recordingRunner(&calls, runningPodStdout(func(args []string) string {
		if strings.Contains(strings.Join(args, " "), "nsenter") {
			return "myhost\n[s1] nsenter rc=0\n"
		}
		return ""
	}), "")
	var logs bytes.Buffer
	e, err := New("s1", harnessDir("s1-container-escape"), run, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e.SettleWait = 0
	if err := e.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	idx := firstCallContaining(calls, "nsenter")
	if idx < 0 {
		t.Fatalf("no S1 nsenter primitive recorded; calls=%v", calls)
	}
	script := calls[idx].args[len(calls[idx].args)-1]
	if !strings.Contains(script, "command -v nsenter") || !strings.Contains(script, "exit 97") {
		t.Errorf("S1 primitive must hard-fail on a missing nsenter: %q", script)
	}
	if !strings.Contains(script, "nsenter rc=") {
		t.Errorf("S1 primitive must record nsenter's exit code: %q", script)
	}
	if !strings.Contains(logs.String(), "nsenter_rc=0") {
		t.Errorf("the run log must record the nsenter rc; got:\n%s", logs.String())
	}
}

// TestAttackExecutor_CleanupWaitsAndSurvivesCancel pins round-1 C2 + C4: Cleanup
// runs on a context detached from a cancelled parent (a Ctrl-C mid-run still
// reverses the attack) and WAITS for the delete (--wait=true) so the next trial
// is not raced by a draining pod.
func TestAttackExecutor_CleanupWaitsAndSurvivesCancel(t *testing.T) {
	var calls []recordedCall
	// A real kubectl would abort on a cancelled context; this fake does too, so
	// a delete that still runs proves Cleanup detached the parent cancel.
	run := func(ctx context.Context, name string, args ...string) (string, error) {
		calls = append(calls, recordedCall{name, append([]string(nil), args...)})
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", nil
	}
	e, err := New("s2", harnessDir("s2-credential-exfil"), run, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // parent already cancelled, as on a Ctrl-C
	if err := e.Cleanup(ctx); err != nil {
		t.Fatalf("Cleanup must survive a cancelled parent: %v", err)
	}
	delIdx := firstCallContaining(calls, "delete")
	if delIdx < 0 {
		t.Fatalf("Cleanup issued no delete despite the cancelled parent; calls=%v", calls)
	}
	for _, c := range calls {
		j := joinCall(c)
		if strings.Contains(j, "delete") {
			if !strings.Contains(j, "--wait=true") {
				t.Errorf("cleanup delete must wait for the delete to finish: %s", j)
			}
			if strings.Contains(j, "--wait=false") {
				t.Errorf("cleanup delete must not be fire-and-forget: %s", j)
			}
		}
	}
}

// TestAttackExecutor_CleanupIsSurgical proves Cleanup deletes the attacker
// resources by name and never deletes the shared tenant-acme Namespace.
func TestAttackExecutor_CleanupIsSurgical(t *testing.T) {
	var calls []recordedCall
	run := recordingRunner(&calls, nil, "")
	e, err := New("s2", harnessDir("s2-credential-exfil"), run, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e.SettleWait = 0 // Story 11.2d: skip the 45s settle in unit tests
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
// settle-before-cleanup: Execute waits SettleWait AFTER the primitive and
// BEFORE returning (so the caller's deferred Cleanup does not delete the pod
// before the correlator resolves workload posture off the live pod), and a
// cancelled context short-circuits the wait. The default SettleWait is
// non-zero so a real run never deletes the target immediately.
func TestAttackExecutor_SettlesBeforeCleanup(t *testing.T) {
	var calls []recordedCall
	run := recordingRunner(&calls, runningPodStdout(nil), "")
	e, err := New("s1", harnessDir("s1-container-escape"), run, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if e.SettleWait <= 0 {
		t.Fatalf("default SettleWait must be positive so a real run does not delete the pod before posture resolves; got %s", e.SettleWait)
	}
	e.SettleWait = 60 * time.Millisecond
	start := time.Now()
	if err := e.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if elapsed := time.Since(start); elapsed < e.SettleWait {
		t.Errorf("Execute returned after %s; expected to settle at least %s before returning", elapsed, e.SettleWait)
	}

	// A cancelled context must short-circuit the settle so a shutdown is not
	// blocked for the full window.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e.SettleWait = 10 * time.Second
	start = time.Now()
	_ = e.Execute(ctx)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("cancelled-context settle took %s; expected a prompt return", elapsed)
	}
}

// errDummy is a tiny error type for tests that need a specific message.
type errDummy string

func (e errDummy) Error() string { return string(e) }

// testLogger discards log output; tests that assert on a log line build
// their own buffer-backed logger.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
