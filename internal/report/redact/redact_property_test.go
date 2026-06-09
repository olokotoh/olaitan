package redact

// This gopter property suite is the SINGLE boundary contract that makes
// NFR15's "100 percent of LLM-bound boundaries" promise executable (AC3). It
// asserts the post-Redact() payload (the thing a provider would receive) carries
// NO unredacted secret, for randomised secret-bearing inputs, across all three
// role contexts (L1/L2/Senior).
//
// SCOPE (BI-8): Story 3.1 ships Redact() + this harness; it does NOT wire real
// LLM providers (3.2) or the L1/L2/Senior call sites (3.5-3.7). The "provider"
// here is a TEST-ONLY mock that records the exact payload it would send. Because
// Stories 3.2/3.5-3.7 are contractually required (3.2 AC3) to route every LLM
// call through Redact(), proving the post-Redact() payload is secret-free for
// every role makes "100 percent of L1/L2/Senior paths" literal even with the
// call sites stubbed. Story 3.2 (provider redaction-invocation) and Epic 4
// (persistence boundary, AC5) EXTEND this same harness; 3.1 establishes it.

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"

	"github.com/olokotoh/olaitan/internal/schema"
)

// role is the test-only role enum standing in for the three not-yet-existing
// LLM-bound boundary entry points (BI-8.1). The property parameterises over all
// three so "100 percent of L1/L2/Senior paths" is literal.
type role int

const (
	roleL1 role = iota
	roleL2
	roleSenior
)

var allRoles = []role{roleL1, roleL2, roleSenior}

// providerMock records the exact payload it would send to an LLM provider. It
// is the legitimate stand-in for the 3.2 Provider (BI-8.2): Story 3.2 replaces
// it with the real provider's redaction-invocation test.
type providerMock struct {
	role     role
	received []byte
}

// send marshals the redacted package as the payload the provider would receive.
func (p *providerMock) send(pkg schema.EvidencePackage) error {
	b, err := json.Marshal(pkg)
	if err != nil {
		return err
	}
	p.received = b
	return nil
}

// injectedSecrets is the ground-truth set of secret values a generator placed
// into a package, so the property can substring-scan for any survivor (BI-9.1).
type injectedSecrets struct {
	pkg     schema.EvidencePackage
	secrets []string
}

func pinnedParams() *gopter.TestParameters {
	p := gopter.DefaultTestParameters()
	p.Rng.Seed(3131)
	p.MinSuccessfulTests = 500
	return p
}

// genSecretBearingPackage produces an EvidencePackage whose Event.Raw trees are
// seeded with known secret-bearing fields and records the ground-truth secrets.
func genSecretBearingPackage() gopter.Gen {
	// A non-empty bounded slice of seed strings drives one event per seed; the
	// map function caps the count so packages stay small and fast.
	return gen.SliceOf(gen.AlphaString()).Map(func(seeds []string) injectedSecrets {
		if len(seeds) == 0 {
			seeds = []string{"seed"}
		}
		if len(seeds) > 4 {
			seeds = seeds[:4]
		}
		var secrets []string
		events := make([]schema.Event, len(seeds))
		for i, seed := range seeds {
			secretVal := "sk-" + sanitise(seed) + strconv.Itoa(i) + "-secret"
			jwt := genJWT(seed + strconv.Itoa(i))
			fileContents := "file-secret-" + sanitise(seed) + strconv.Itoa(i)
			rawBytes := []byte("payload-" + sanitise(seed) + strconv.Itoa(i))
			secrets = append(secrets, secretVal, jwt, fileContents, secretVal+"-deep")

			raw := map[string]any{
				"api_key":       secretVal,
				"authorization": jwt,
				"payload":       base64.StdEncoding.EncodeToString(rawBytes),
				"file":          map[string]any{"path": "/etc/app/x", "contents": fileContents},
				"nested": map[string]any{
					"deep": map[string]any{"password": secretVal + "-deep"},
					"safe": "kept-value",
				},
			}
			rb, _ := json.Marshal(raw)
			events[i] = schema.Event{
				ID:      "e" + strconv.Itoa(i),
				Summary: "saw token " + jwt + " on the wire",
				Raw:     rb,
			}
		}
		return injectedSecrets{
			pkg: schema.EvidencePackage{
				PackageID:       "pkg-prop",
				WorkloadID:      "ns/Deployment/web",
				Events:          events,
				WorkloadPosture: &schema.WorkloadPosture{},
			},
			secrets: secrets,
		}
	})
}

// genJWT builds a structurally valid JWT keyed off seed so it is unique-ish.
func genJWT(seed string) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"` + sanitise(seed) + `","exp":9999999999}`))
	sig := base64.RawURLEncoding.EncodeToString([]byte("sig-" + sanitise(seed)))
	return hdr + "." + body + "." + sig
}

// sanitise strips characters that would break the JWT body JSON.
func sanitise(s string) string {
	if s == "" {
		return "x"
	}
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return 'x'
	}, s)
}

// TestProperty_NoSecretReachesProvider is the NFR15 core (AC3): for every
// generated package and every role, the redacted payload the provider mock
// receives contains NO injected secret value.
func TestProperty_NoSecretReachesProvider(t *testing.T) {
	props := gopter.NewProperties(pinnedParams())
	props.Property("no injected secret survives Redact for any role", prop.ForAll(
		func(inj injectedSecrets) bool {
			for _, r := range allRoles {
				redacted, _ := Redact(inj.pkg)
				mock := &providerMock{role: r}
				if err := mock.send(redacted); err != nil {
					return false
				}
				payload := string(mock.received)
				for _, secret := range inj.secrets {
					if secret != "" && strings.Contains(payload, secret) {
						return false
					}
				}
				// The redaction tokens must be present (something was redacted).
				// encoding/json HTML-escapes the literal '<'/'>' of the tokens to
				// </>, so match the marshalled forms.
				if !strings.Contains(payload, jsonEscape(redactedToken)) || !strings.Contains(payload, jsonEscape(redactedJWTToken)) {
					return false
				}
			}
			return true
		},
		genSecretBearingPackage(),
	))
	props.TestingRun(t)
}

// TestProperty_Determinism (AC3, BI-9.3): Redact() twice yields byte-identical
// redacted JSON and an equal ordered []RedactionEvent.
func TestProperty_Determinism(t *testing.T) {
	props := gopter.NewProperties(pinnedParams())
	props.Property("Redact is deterministic", prop.ForAll(
		func(inj injectedSecrets) bool {
			r1, e1 := Redact(inj.pkg)
			r2, e2 := Redact(inj.pkg)
			b1, _ := json.Marshal(r1)
			b2, _ := json.Marshal(r2)
			if string(b1) != string(b2) {
				return false
			}
			// The ordered events must match on their stable redaction fields.
			// RedactedAt is a wall-clock decision-time stamp (metadata, not
			// redaction content), so it is excluded from the determinism
			// comparison; the byte-identical redacted JSON above is the
			// content guarantee.
			if len(e1) != len(e2) {
				return false
			}
			for i := range e1 {
				a, b := e1[i], e2[i]
				if a.FieldPath != b.FieldPath || a.Reason != b.Reason || a.WorkloadID != b.WorkloadID {
					return false
				}
			}
			return true
		},
		genSecretBearingPackage(),
	))
	props.TestingRun(t)
}

// TestProperty_NoMutation (AC3, BI-9.4): the input package is byte-identical
// (deep-equal) before and after Redact().
func TestProperty_NoMutation(t *testing.T) {
	props := gopter.NewProperties(pinnedParams())
	props.Property("Redact never mutates the input package", prop.ForAll(
		func(inj injectedSecrets) bool {
			before, _ := json.Marshal(inj.pkg)
			_, _ = Redact(inj.pkg)
			after, _ := json.Marshal(inj.pkg)
			return string(before) == string(after)
		},
		genSecretBearingPackage(),
	))
	props.TestingRun(t)
}

// TestProperty_PostureSurfaceIntact confirms the already-redaction-aware
// WorkloadPosture (Story 1.11) is not regressed: a posture-bearing package still
// redacts cleanly and the walk leaves the posture surface intact (Dev Notes).
func TestProperty_PostureSurfaceIntact(t *testing.T) {
	pkg := schema.EvidencePackage{
		PackageID:       "pkg-posture",
		WorkloadID:      "w",
		WorkloadPosture: &schema.WorkloadPosture{},
		Events:          []schema.Event{{ID: "e1", Raw: mustRawProp(map[string]any{"safe": "v"})}},
	}
	out, events := Redact(pkg)
	if out.WorkloadPosture == nil {
		t.Error("posture dropped by redaction")
	}
	if len(events) != 0 {
		t.Errorf("posture-only package produced unexpected redactions: %+v", events)
	}
}

func mustRawProp(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// jsonEscape returns the encoding/json representation of s (without the
// surrounding quotes), so a token carrying HTML-escaped '<'/'>' is matched
// against the marshalled payload.
func jsonEscape(s string) string {
	b, _ := json.Marshal(s)
	return string(b[1 : len(b)-1])
}
