package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"path/filepath"
	"strings"
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

// attackNamespace / attackWorkload / attackWaitTimeout / saTokenPath are the
// shared shape of the Story 11.1 targets: each S1-S3 target is a Deployment
// named `web` with selector app=web in the tenant-acme namespace, and the S2
// target projects its ServiceAccount token at the standard mount path.
const (
	attackNamespace   = "tenant-acme"
	attackWorkload    = "deploy/web"
	attackWaitTimeout = "120s"
	saTokenPath       = "/run/secrets/kubernetes.io/serviceaccount/token"
	kubeAPIHost       = "https://kubernetes.default.svc"
	metadataIP        = "169.254.169.254"
)

// attackRunFunc runs an external command (kubectl) and returns its trimmed
// stdout plus a clear error on a non-zero exit. Unlike overlayRunFunc
// (error-only) it returns stdout, because the executor needs the in-pod
// command output: specifically the S2 token LENGTH and HASH, which are the
// ONLY things derived from the token that ever leave the pod (the token
// value itself is never in argv, stdout, or a log line). It is the
// injectable shell-out the executor drives (the overlay.go precedent); main
// wires the real execAttackCmd, a unit test injects a recorder.
type attackRunFunc func(ctx context.Context, name string, args ...string) (string, error)

// execAttackCmd is the real attackRunFunc: it runs kubectl and returns
// trimmed stdout, folding stderr into a clear error on a non-zero exit. It
// is small and side-effecting, so it lives behind the injectable runCmd
// field and is exercised by the live e2e path (kind-full + kubeadm), not
// unit-tested directly.
func execAttackCmd(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// attackExecutor executes one scenario's real in-cluster technique (S1-S3)
// and reverses it. It is built per trial by the scenarioHarness behind the
// frozen Scenario seam.
type attackExecutor struct {
	scenarioID string
	dir        string
	// manifests are the files Execute applies, in apply order; Cleanup
	// deletes them in reverse. The workload is always present; S2 adds its
	// least-privilege RBAC manifest (design point DP1).
	manifests []string
	runCmd    attackRunFunc
	logger    *slog.Logger
}

// newAttackExecutor builds the executor for an S1-S3 scenario. An unknown or
// not-yet-implemented scenario (s4/s5 belong to Story 11.2b) is a hard error
// so a mis-wired scenario fails loudly rather than silently no-opping.
func newAttackExecutor(scenarioID, dir string, runCmd attackRunFunc, logger *slog.Logger) (*attackExecutor, error) {
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
		runCmd = execAttackCmd
	}
	var manifests []string
	if scenarioID == "s2" {
		// Apply the least-privilege RBAC (SA + Role, DP1) BEFORE the workload
		// so the s2-attacker ServiceAccount the pod binds to already exists.
		manifests = append(manifests, filepath.Join(dir, "manifests", "rbac.yaml"))
	}
	manifests = append(manifests, filepath.Join(dir, "manifests", "workload.yaml"))
	return &attackExecutor{
		scenarioID: scenarioID,
		dir:        dir,
		manifests:  manifests,
		runCmd:     runCmd,
		logger:     logger,
	}, nil
}

// Execute applies the target (and the S2 RBAC), waits for it Ready, then runs
// the scenario's technique primitive(s). It does NOT clean up; the caller
// (scenarioHarness.Run) defers Cleanup so teardown runs even on a primitive
// error (the Runner-loop BI-2 discipline).
func (e *attackExecutor) Execute(ctx context.Context) error {
	for _, m := range e.manifests {
		if _, err := e.runCmd(ctx, "kubectl", "apply", "-f", m); err != nil {
			return fmt.Errorf("apply %s: %w", m, err)
		}
	}
	if _, err := e.runCmd(ctx, "kubectl", "rollout", "status", attackWorkload, "-n", attackNamespace, "--timeout", attackWaitTimeout); err != nil {
		return fmt.Errorf("wait target ready: %w", err)
	}
	switch e.scenarioID {
	case "s1":
		return e.runS1(ctx)
	case "s2":
		return e.runS2(ctx)
	case "s3":
		return e.runS3(ctx)
	}
	return fmt.Errorf("attack executor: no primitive for scenario %q", e.scenarioID) // unreachable (newAttackExecutor gate)
}

// exec runs a shell script inside the target pod via kubectl exec.
func (e *attackExecutor) exec(ctx context.Context, script string) (string, error) {
	return e.runCmd(ctx, "kubectl", "exec", "-n", attackNamespace, attackWorkload, "--", "sh", "-c", script)
}

// runS1 executes the S1 container-escape technique (MITRE T1611 Escape to
// Host; also T1610). From the privileged (CAP_SYS_ADMIN / CAP_SYS_PTRACE)
// container it attempts to reach the host namespace / filesystem. The
// privileged process alone trips OLT-PRIV-001; the host-reach attempt is the
// T1611 flavour and a read of the host /proc view can also trip OLT-EXEC-001.
// The attempt is read-only recon (nothing on the host is modified), so it is
// reversible by deleting the pod.
func (e *attackExecutor) runS1(ctx context.Context) error {
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
func (e *attackExecutor) runS2(ctx context.Context) error {
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
		kubeAPIHost + "/api/v1/namespaces/" + attackNamespace + "/secrets"
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
// /kubectl in a tenant Deployment pod). The target ships no kubectl, so the
// attacker brings the binary; to avoid any egress (nothing leaves the
// cluster, hard rule) it copies the in-pod busybox to /tmp/kubectl and runs
// it, whose exe path ends /kubectl.
func (e *attackExecutor) runS3(ctx context.Context) error {
	script := "cp /bin/busybox /tmp/kubectl 2>/dev/null || cp \"$(command -v sh)\" /tmp/kubectl; " +
		"/tmp/kubectl echo '[s3] in-pod kubectl-named process (lateral movement / discovery)'"
	out, err := e.exec(ctx, script)
	if err != nil {
		return fmt.Errorf("s3 in-pod kubectl primitive: %w", err)
	}
	e.logger.Info("s3 technique executed",
		"mitre", "T1613", "also", "T1609", "rule", "OLT-LATERAL-001",
		"detail", "kubectl exec + in-pod /kubectl process", "out_len", len(out))
	return nil
}

// Cleanup deletes exactly what Execute applied, in reverse order, idempotent
// (--ignore-not-found). It is safe to call after a partial or failed Execute
// and safe to call more than once (AC2 reversibility). A delete error is
// returned but does not stop the other deletes.
func (e *attackExecutor) Cleanup(ctx context.Context) error {
	var firstErr error
	for i := len(e.manifests) - 1; i >= 0; i-- {
		m := e.manifests[i]
		if _, err := e.runCmd(ctx, "kubectl", "delete", "-f", m, "--ignore-not-found", "--wait=false"); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("delete %s: %w", m, err)
			}
			e.logger.Error("cleanup delete failed", "manifest", m, "err", err)
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
