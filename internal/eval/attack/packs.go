package attack

// Story 11.2c wires two THIRD-PARTY attack-technique packs into the real
// 11.2a in-cluster runner: falcosecurity/event-generator (syscall activity
// Falco matches) and DataDog Stratus Red Team (Kubernetes techniques the
// k8s-audit and Falco organs perceive). The packs live in NEW files in this
// package (D1): they reuse the Executor's RunFunc command seam and its
// kubectl primitives, but they do NOT touch the frozen s1-s5 Scenario switch
// in attack.go - that switch is Story 11.2b's (s4/s5), and keeping packs on
// a parallel seam means the two unmerged branches never collide.
//
// The honesty fence (D7): nothing in this package proves DETECTION. The unit
// tests prove we construct the right command, pin every image, cite MITRE
// from the tool (never mint it), and always revert. The real
// detonation -> sensor -> OLT -> isolation chain is proven ONLY at the
// reserved supervised live gate (packs_live_test.go, //go:build live).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// PackID names a third-party attack-technique pack.
type PackID string

const (
	// PackFalcoEventGen is falcosecurity/event-generator - a published,
	// directly pinnable image (D2) that generates Falco-matching syscalls.
	PackFalcoEventGen PackID = "falco-event-generator"
	// PackStratus is DataDog Stratus Red Team. Upstream ships no container
	// image (D2), so its techniques run from a wrapper image this repo builds
	// and pins, whose Dockerfile sha256-verifies the Stratus release binary.
	PackStratus PackID = "stratus-red-team"
)

// Organ is an Olaitan sensor: the thing that must perceive a technique for it
// to actually test the detector (D5, Dr. Quinn). A technique bound to no organ
// Olaitan has is out of scope - its silence is not a detection gap. Olaitan
// has three organs: Falco syscalls, k8s audit, and Calico Goldmane flows.
type Organ string

const (
	OrganFalco   Organ = "falco"   // syscalls (internal/collector/falco)
	OrganAudit   Organ = "audit"   // k8s audit log (internal/collector/audit)
	OrganNetwork Organ = "network" // Calico Goldmane flows (internal/collector/cni)
)

// mitreTechniqueRE is the MITRE ATT&CK technique-ID grammar: Txxxx with an
// optional .yyy sub-technique. It validates a technique ID WHEN one is set; an
// empty MitreTechniqueID is honest (the tool advertises only a tactic for most
// Stratus k8s techniques, AC3 forbids minting a technique number it does not).
var mitreTechniqueRE = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)

// pinnedImageRE is name:tag@sha256:<64 hex>, the same shape the Story 12.6
// chart guard enforces (deploy/helm/image_pin_test.go). It is restated here so
// the pack code can refuse an unpinned image at its source, and so the pack
// manifest pin-guard extension can reuse one predicate.
var pinnedImageRE = regexp.MustCompile(
	`^(?:[a-zA-Z0-9.-]+(?::[0-9]+)?/)?[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*` +
		`:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}` +
		`@sha256:[a-f0-9]{64}$`)

// imagePinShape returns "" for a tag@sha256-pinned reference and a reason
// otherwise (AC2). It rejects :latest and a digest-without-tag the same way
// the Story 12.6 guard does.
func imagePinShape(ref string) string {
	name, digest, hasDigest := strings.Cut(ref, "@")
	tag := ""
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		tag = name[i+1:]
	}
	switch {
	case ref == "":
		return "empty image reference"
	case tag == "" && !hasDigest:
		return "untagged (resolves to :latest)"
	case tag == "":
		return "digest without a tag (nobody can tell what the digest is meant to be)"
	case tag == "latest":
		return ":latest is not a version"
	case !hasDigest:
		return "tag without a digest (a tag can be re-pushed)"
	case !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(digest):
		return "malformed digest (want sha256:<64 lowercase hex>)"
	case !pinnedImageRE.MatchString(ref):
		return "not a valid name:tag@sha256 reference"
	}
	return ""
}

// Technique is one attack primitive from a third-party pack, bound to the
// Olaitan sensor organ it exercises (D5) and carrying the MITRE mapping CITED
// from the tool (D6/AC3), never minted in this file.
type Technique struct {
	// ID is the tool's own technique identifier, verbatim (e.g.
	// "k8s.credential-access.dump-secrets"). It is what we hand the CLI and
	// what the contract test (D6) checks still exists in the pinned catalogue.
	ID string
	// Pack is the pack this technique belongs to.
	Pack PackID
	// MitreTactics is always present: the MITRE ATT&CK tactic(s) the tool
	// advertises for this technique (e.g. "Credential Access").
	MitreTactics []string
	// MitreTechniqueID is "Txxxx[.yyy]" ONLY where the tool advertises a
	// specific technique (e.g. Stratus hostpath-volume -> T1611). Empty is
	// honest: most Stratus k8s techniques advertise a tactic only.
	MitreTechniqueID string
	// Organ is the Olaitan sensor expected to perceive this technique.
	Organ Organ
	// ExpectOLT names the OLT rule or detection path expected to fire; it is
	// the join key the live gate asserts on (D8). May be "" until a rule
	// exists, in which case the live gate records a correct non-detection.
	ExpectOLT string
	// Privileged is true for techniques restricted Pod Security Admission
	// rejects (hostPath, privileged pod) - they need a PSA-exempt namespace
	// and change the demonstrated threat model (D10), so they are gated.
	Privileged bool
}

// validate returns a non-nil error if the technique's MITRE citation is
// malformed. It enforces AC3's anti-minting rule structurally: a tactic is
// mandatory; a technique ID, when present, must be well formed.
func (t Technique) validate() error {
	if t.ID == "" {
		return errors.New("technique has empty ID")
	}
	if len(t.MitreTactics) == 0 {
		return fmt.Errorf("technique %q cites no MITRE tactic", t.ID)
	}
	if t.MitreTechniqueID != "" && !mitreTechniqueRE.MatchString(t.MitreTechniqueID) {
		return fmt.Errorf("technique %q has malformed MITRE technique ID %q (want Txxxx[.yyy])", t.ID, t.MitreTechniqueID)
	}
	if t.Organ == "" {
		return fmt.Errorf("technique %q is bound to no Olaitan sensor organ (out of scope; do not include it)", t.ID)
	}
	return nil
}

// StratusVersion is the Stratus Red Team release the technique IDs and MITRE
// citations are taken from (and the wrapper image builds, deploy/images/
// stratus). The contract fixture testdata/stratus-catalogue-v2.37.0.json is
// extracted from this version's docs.
const StratusVersion = "v2.37.0"

// stratusTechniques is the curated Stratus Red Team subset (D5): each entry is
// bound to an organ Olaitan actually has, and its MITRE mapping is cited from
// the tool's own source docs (DataDog/stratus-red-team/docs/attack-techniques/
// kubernetes/<id>.md) - verified 2026-10-11. Stratus advertises a tactic for
// all of these and a technique ID for hostpath-volume only. The two Privileged
// entries are gated behind a PSA-exempt namespace (D10); they are not in the
// default set the runner detonates.
var stratusTechniques = []Technique{
	{
		ID:           "k8s.credential-access.dump-secrets",
		Pack:         PackStratus,
		MitreTactics: []string{"Credential Access"},
		Organ:        OrganAudit, // list/get Secrets across the cluster -> audit
		ExpectOLT:    "",         // audit-plane rule; wired/confirmed at the live gate
	},
	{
		ID:           "k8s.credential-access.steal-serviceaccount-token",
		Pack:         PackStratus,
		MitreTactics: []string{"Credential Access"},
		Organ:        OrganFalco, // reads the projected SA token OFF DISK inside a pod -> Falco
		// The one technique with an honest keyed OLT expectation: OLT-CRED-001
		// fires on a projected-SA-token read by a non-system process, which is
		// exactly this technique. The live gate confirms it fires (and a
		// non-firing is a real finding, not a silent pass).
		ExpectOLT: "OLT-CRED-001",
	},
	{
		ID:           "k8s.persistence.create-admin-clusterrole",
		Pack:         PackStratus,
		MitreTactics: []string{"Persistence", "Privilege Escalation"},
		Organ:        OrganAudit, // create ClusterRole/Binding -> audit
		ExpectOLT:    "",
	},
	{
		ID:           "k8s.persistence.create-token",
		Pack:         PackStratus,
		MitreTactics: []string{"Persistence"},
		Organ:        OrganAudit, // create a long-lived token -> audit
		ExpectOLT:    "",
	},
	{
		ID:               "k8s.privilege-escalation.hostpath-volume",
		Pack:             PackStratus,
		MitreTactics:     []string{"Privilege Escalation"},
		MitreTechniqueID: "T1611", // Escape to Host - cited from this technique's References in the v2.37.0 doc (its structured Mappings list the tactic only); the one Stratus k8s technique that references a T-number
		Organ:            OrganAudit,
		ExpectOLT:        "",
		Privileged:       true, // restricted PSA rejects hostPath (D10)
	},
	{
		ID:           "k8s.privilege-escalation.privileged-pod",
		Pack:         PackStratus,
		MitreTactics: []string{"Privilege Escalation"},
		Organ:        OrganAudit,
		ExpectOLT:    "",
		Privileged:   true, // restricted PSA rejects privileged pods (D10)
	},
}

// StratusTechniques returns a copy of the curated Stratus subset so callers
// cannot mutate the package table.
func StratusTechniques() []Technique {
	out := make([]Technique, len(stratusTechniques))
	copy(out, stratusTechniques)
	return out
}

// DefaultPackWaitTimeout bounds how long Detonate waits for a technique Job to
// finish before it gives up (and still reverts). A field on PackRunner so a
// unit test can shrink it.
const DefaultPackWaitTimeout = 3 * time.Minute

// techniquesFor returns the curated table for a pack.
func techniquesFor(pack PackID) []Technique {
	switch pack {
	case PackStratus:
		return StratusTechniques()
	case PackFalcoEventGen:
		return EventGenTechniques()
	default:
		return nil
	}
}

// NewPackRunner builds a runner for a pack, keyed by the pack's curated
// technique table. runCmd is the 11.2a command seam (ExecCmd in the real
// path, a recorder in tests). The caller sets renderJob (and may override
// newRunID / waitTimeout); the real job renderer lands with the committed
// pack manifests.
func NewPackRunner(pack PackID, runCmd RunFunc, logger *slog.Logger) (*PackRunner, error) {
	techs := techniquesFor(pack)
	if len(techs) == 0 {
		return nil, fmt.Errorf("pack %q: no techniques registered", pack)
	}
	m := make(map[string]Technique, len(techs))
	for _, t := range techs {
		if err := t.validate(); err != nil {
			return nil, fmt.Errorf("pack %q: %w", pack, err)
		}
		m[t.ID] = t
	}
	r := &PackRunner{
		pack:        pack,
		runCmd:      runCmd,
		logger:      logger,
		techs:       m,
		waitTimeout: DefaultPackWaitTimeout,
		newRunID:    randRunID,
	}
	r.renderJob = r.defaultRenderJob
	return r, nil
}

// randRunID returns a short, lowercase, DNS-label-safe GENUINELY RANDOM suffix
// for a per-run namespace. It uses crypto/rand, not the clock: a time-derived
// suffix can collide across fast or concurrent runs, and a collision would let
// one run's teardown delete another run's still-live namespace (review round 1,
// Edge Case Hunter). On the vanishingly unlikely rand failure it falls back to
// the nanosecond clock so a run never blocks on entropy.
func randRunID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%012x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// PackRunner detonates a pack's technique through the 11.2a RunFunc seam and
// GUARANTEES a revert. It reuses the command seam rather than re-implementing
// kubectl, and never touches the s1-s5 switch (D1). Every technique runs in
// its own per-run Namespace so teardown is a single `kubectl delete namespace`
// whose success is the cheap, total "the cluster is clean" assertion (D8,
// Murat): if the namespace is gone, everything namespaced inside it is gone.
type PackRunner struct {
	pack   PackID
	runCmd RunFunc
	logger *slog.Logger
	techs  map[string]Technique

	// waitTimeout bounds the Job wait; defaults to DefaultPackWaitTimeout.
	waitTimeout time.Duration
	// newRunID returns a short unique suffix for the per-run namespace; a
	// field so a unit test gets a deterministic namespace name.
	newRunID func() string
	// renderJob writes the technique's Job manifest (pinned image + the
	// detonate command) and returns the path to apply. A field so a unit test
	// injects a fixture. The real renderer (defaultRenderJob) reads the
	// committed per-pack template under PacksRoot/<pack>/manifests/job.yaml.
	renderJob func(t Technique, ns string) (manifestPath string, err error)
	// PacksRoot is the directory holding committed per-pack manifests. Empty
	// defaults to deploy/demo/packs (relative to the runner's working dir).
	PacksRoot string
}

// eventGenActionPlaceholder and stratusTechniquePlaceholder are the tokens the
// committed Job templates carry; defaultRenderJob substitutes the concrete
// technique for them so one template serves every technique in a pack.
const (
	eventGenActionPlaceholder   = "OLT_EVENTGEN_ACTION"
	stratusTechniquePlaceholder = "OLT_STRATUS_TECHNIQUE"
)

// defaultRenderJob reads the committed per-pack Job template, substitutes the
// concrete technique, and writes the result to a temp file for `kubectl apply`.
// For Stratus it returns an explicit deferral error until the wrapper image is
// built and its manifest committed (the supervised build step), rather than
// pretending a manifest exists.
func (p *PackRunner) defaultRenderJob(t Technique, _ string) (string, error) {
	root := p.PacksRoot
	if root == "" {
		root = filepath.Join("deploy", "demo", "packs")
	}
	tmpl := filepath.Join(root, string(p.pack), "manifests", "job.yaml")
	raw, err := os.ReadFile(tmpl)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && p.pack == PackStratus {
			return "", fmt.Errorf("stratus job manifest %s not found: the wrapper image is built and pinned at the supervised build step (Story 11.2c); stratus detonation is deferred until then", tmpl)
		}
		return "", fmt.Errorf("read pack job template %s: %w", tmpl, err)
	}
	out := string(raw)
	switch p.pack {
	case PackFalcoEventGen:
		out = strings.ReplaceAll(out, eventGenActionPlaceholder, t.ID)
	case PackStratus:
		out = strings.ReplaceAll(out, stratusTechniquePlaceholder, t.ID)
	}
	f, err := os.CreateTemp("", "olt-pack-*.yaml")
	if err != nil {
		return "", fmt.Errorf("render job: temp file: %w", err)
	}
	if _, err := f.WriteString(out); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("render job: write: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("render job: close: %w", err)
	}
	return f.Name(), nil
}

// lookup returns the technique by ID.
func (p *PackRunner) lookup(id string) (Technique, bool) {
	t, ok := p.techs[id]
	return t, ok
}

// kubectl runs a kubectl subcommand through the injected seam.
func (p *PackRunner) kubectl(ctx context.Context, args ...string) (string, error) {
	return p.runCmd(ctx, "kubectl", args...)
}

// Detonate runs ONE technique in its own per-run Namespace and guarantees the
// Namespace is deleted afterwards, even if detonation fails (D4, Amelia).
//
// The revert is a deferred step with a named return and errors.Join, so:
//   - a detonate failure never skips the revert (defer),
//   - a revert failure surfaces even when detonate already failed (Join),
//   - an unknown technique returns BEFORE the defer registers, so no stray
//     namespace is created and nothing is left to clean up.
//
// Honesty fence (D7): a nil return means the technique Job ran to completion
// and the namespace was torn down. It does NOT mean Olaitan detected anything;
// that is asserted ONLY at the reserved live gate (packs_live_test.go).
func (p *PackRunner) Detonate(ctx context.Context, techID string) (err error) {
	t, ok := p.lookup(techID)
	if !ok {
		return fmt.Errorf("pack %q: unknown technique %q", p.pack, techID)
	}

	if p.renderJob == nil {
		return fmt.Errorf("pack %q: no job renderer configured", p.pack)
	}

	ns := fmt.Sprintf("olt-pack-%s", p.newRunID())

	// Guaranteed teardown. Registered only after the technique is known, so an
	// unknown technique creates nothing. context.WithoutCancel keeps the revert
	// running even when the detonation context was cancelled or timed out, but
	// it is layered with its OWN bounded timeout (+ an explicit --timeout) so a
	// namespace stuck Terminating cannot hang the revert forever - the sibling
	// 11.2a Cleanup pattern (review round 1, Edge Case Hunter / Blind Hunter).
	defer func() {
		revertCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), packRevertTimeout)
		defer cancel()
		if _, rerr := p.kubectl(revertCtx, "delete", "namespace", ns,
			"--ignore-not-found", "--wait=true", fmt.Sprintf("--timeout=%s", packRevertTimeout)); rerr != nil {
			err = errors.Join(err, fmt.Errorf("revert %s: delete namespace %s: %w", t.ID, ns, rerr))
		}
	}()

	if _, cerr := p.kubectl(ctx, "create", "namespace", ns); cerr != nil {
		return fmt.Errorf("detonate %s: create namespace %s: %w", t.ID, ns, cerr)
	}
	// Label the per-run namespace privileged for Pod Security Admission: the
	// attack pods run as root (event-generator writes /etc,/bin; Stratus
	// privileged techniques mount hostPath), which restricted PSA on a kubeadm
	// cluster rejects (review round 1, AC5 risk). The namespace is ephemeral and
	// torn down after the run, so the exemption is scoped to the attack, not the
	// tenant workloads.
	if _, lerr := p.kubectl(ctx, "label", "namespace", ns,
		"pod-security.kubernetes.io/enforce=privileged",
		"pod-security.kubernetes.io/warn=privileged", "--overwrite"); lerr != nil {
		return fmt.Errorf("detonate %s: label namespace %s privileged: %w", t.ID, ns, lerr)
	}

	manifest, rerr := p.renderJob(t, ns)
	if rerr != nil {
		return fmt.Errorf("detonate %s: render job: %w", t.ID, rerr)
	}
	defer func() { _ = os.Remove(manifest) }() // the rendered temp file is local scratch, not cluster state
	if _, aerr := p.kubectl(ctx, "apply", "-n", ns, "-f", manifest); aerr != nil {
		return fmt.Errorf("detonate %s: apply job: %w", t.ID, aerr)
	}

	timeout := p.waitTimeout
	if timeout <= 0 {
		timeout = DefaultPackWaitTimeout
	}
	if werr := p.waitForJob(ctx, ns, timeout); werr != nil {
		return fmt.Errorf("detonate %s: %w", t.ID, werr)
	}
	return nil
}

// packRevertTimeout bounds the teardown so a namespace stuck Terminating
// cannot hang the revert forever.
const packRevertTimeout = 90 * time.Second

// jobPollInterval is how often waitForJob polls the Job status.
const jobPollInterval = 3 * time.Second

// waitForJob polls the per-run namespace's Job(s) until one completes or FAILS,
// instead of `kubectl wait --for=condition=complete`, which never matches a
// Failed Job and would therefore burn the full timeout on any in-pod failure or
// ImagePullBackOff (review round 1, Edge Case Hunter). A failed Job returns
// immediately with its status, so the real cause surfaces fast rather than as a
// generic timeout.
func (p *PackRunner) waitForJob(ctx context.Context, ns string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		failed, _ := p.kubectl(ctx, "get", "job", "-n", ns, "-o", "jsonpath={.items[*].status.failed}")
		if strings.ContainsAny(failed, "123456789") {
			return fmt.Errorf("job in %s failed (status.failed=%q)", ns, failed)
		}
		succeeded, _ := p.kubectl(ctx, "get", "job", "-n", ns, "-o", "jsonpath={.items[*].status.succeeded}")
		if strings.ContainsAny(succeeded, "123456789") {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s waiting for job completion in %s (succeeded=%q failed=%q)", timeout, ns, succeeded, failed)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(jobPollInterval):
		}
	}
}
