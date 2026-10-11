package attack

// falcosecurity/event-generator pack (Story 11.2c). event-generator is the
// REQUIRED spine of this story (D5, Dr. Quinn): it is a published, directly
// pinnable image that generates real syscall activity Olaitan's PRIMARY organ
// (Falco) is built to catch. Each technique here is one event-generator
// `syscall` action, and its MITRE mapping is CITED (AC3/D6) from the pinned
// Falco rules package the action trips - never minted. The citation is the
// committed fixture testdata/falco-rules-catalogue-5.2.0.json, extracted from
// falcosecurity/rules tag falco-rules-5.2.0; the contract test
// (TestEventGenMitreMatchesFalcoCatalogue) holds the table and the fixture in
// agreement, so a Falco-rules bump that renames a rule or re-tags its MITRE ID
// turns into a loud, located CI failure, not silent drift.

// EventGenImage is the pinned event-generator image (tag AND digest, D2/AC2).
// Resolved from Docker Hub 2026-10-11. The Story 12.6-style pin guard over the
// pack manifests re-checks this shape; kubectl pulls it by digest at the live
// gate.
const EventGenImage = "docker.io/falcosecurity/event-generator:0.13.0@sha256:885d150fb9e3f7a643a2c5234a04898bc4d08cddabdb18aa7be820ffece8f453"

// FalcoRulesVersion is the falcosecurity/rules release the event-generator
// MITRE citations are taken from. The deployment's falcoctl does not pin a
// rules version (it follows the latest), so 11.2c pins the CITATION here and
// recommends the chart pin falcoctl to this same version (see the story file).
const FalcoRulesVersion = "falco-rules-5.2.0"

// eventGenTechniques is the curated event-generator subset. Both are
// credential-access syscalls the default Falco ruleset tags with a specific
// technique ID, so unlike most Stratus k8s techniques these DO carry a MITRE
// technique number - cited verbatim from falco-rules-5.2.0 (2026-09-07):
//   - "Read sensitive file untrusted"      -> mitre_credential_access, T1555
//   - "Search Private Keys or Passwords"   -> mitre_credential_access, T1552.001
//
// The ID is the exact action identifier passed to `event-generator run`
// (confirmed against event-generator v0.13.0 source).
var eventGenTechniques = []Technique{
	{
		ID:               "syscall.ReadSensitiveFileUntrusted",
		Pack:             PackFalcoEventGen,
		MitreTactics:     []string{"Credential Access"},
		MitreTechniqueID: "T1555",
		Organ:            OrganFalco,
		ExpectOLT:        "", // Falco relays the alert; the OLT path is asserted at the live gate
	},
	{
		ID:               "syscall.SearchPrivateKeysOrPasswords",
		Pack:             PackFalcoEventGen,
		MitreTactics:     []string{"Credential Access"},
		MitreTechniqueID: "T1552.001",
		Organ:            OrganFalco,
		ExpectOLT:        "",
	},
}

// EventGenTechniques returns a copy of the curated event-generator subset.
func EventGenTechniques() []Technique {
	out := make([]Technique, len(eventGenTechniques))
	copy(out, eventGenTechniques)
	return out
}
