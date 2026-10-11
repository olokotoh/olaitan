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
	"errors"
	"fmt"
	"log/slog"
	"regexp"
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

// PackRunner detonates a pack's technique through the 11.2a RunFunc seam and
// guarantees a revert. It reuses the command seam rather than re-implementing
// kubectl, and never touches the s1-s5 switch (D1).
type PackRunner struct {
	pack   PackID
	runCmd RunFunc
	logger *slog.Logger
	techs  map[string]Technique
}

// lookup returns the technique by ID.
func (p *PackRunner) lookup(id string) (Technique, bool) {
	t, ok := p.techs[id]
	return t, ok
}
