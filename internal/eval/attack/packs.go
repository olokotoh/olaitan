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
	"errors"
	"fmt"
	"log/slog"
	"regexp"
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
		Organ:        OrganAudit, // reads the projected SA token; API access audited
		ExpectOLT:    "",
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
		MitreTechniqueID: "T1611", // Escape to Host - the ONE k8s technique Stratus pins to a T-number
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
	return &PackRunner{
		pack:        pack,
		runCmd:      runCmd,
		logger:      logger,
		techs:       m,
		waitTimeout: DefaultPackWaitTimeout,
		newRunID:    randRunID,
	}, nil
}

// randRunID returns a short, lowercase, DNS-label-safe unique suffix for a
// per-run namespace.
func randRunID() string {
	return fmt.Sprintf("%08x", time.Now().UnixNano()&0xffffffff)
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
	// detonate command) into ns and returns the path to apply. A field so a
	// unit test injects a fixture without the real committed manifests, which
	// land with the Dockerfile/manifest task. The real renderer reads the
	// committed per-pack template under deploy/demo/packs/<pack>/manifests.
	renderJob func(t Technique, ns string) (manifestPath string, err error)
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
	// unknown technique creates nothing. Uses context.WithoutCancel so a
	// cancelled or timed-out detonation still reverts rather than leaking
	// attack infrastructure on the cluster.
	defer func() {
		revertCtx := context.WithoutCancel(ctx)
		if _, rerr := p.kubectl(revertCtx, "delete", "namespace", ns, "--ignore-not-found", "--wait=true"); rerr != nil {
			err = errors.Join(err, fmt.Errorf("revert %s: delete namespace %s: %w", t.ID, ns, rerr))
		}
	}()

	if _, cerr := p.kubectl(ctx, "create", "namespace", ns); cerr != nil {
		return fmt.Errorf("detonate %s: create namespace %s: %w", t.ID, ns, cerr)
	}

	manifest, rerr := p.renderJob(t, ns)
	if rerr != nil {
		return fmt.Errorf("detonate %s: render job: %w", t.ID, rerr)
	}
	if _, aerr := p.kubectl(ctx, "apply", "-n", ns, "-f", manifest); aerr != nil {
		return fmt.Errorf("detonate %s: apply job: %w", t.ID, aerr)
	}

	timeout := p.waitTimeout
	if timeout <= 0 {
		timeout = DefaultPackWaitTimeout
	}
	if _, werr := p.kubectl(ctx, "wait", "-n", ns, "--for=condition=complete",
		"job", "--all", fmt.Sprintf("--timeout=%s", timeout)); werr != nil {
		return fmt.Errorf("detonate %s: wait for job: %w", t.ID, werr)
	}
	return nil
}
