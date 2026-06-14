package redact

// Story 4.5 RedactText unit + property tests (AC1/AC2). RedactText is the
// EXPORTED text-redactor lifted from the SAME pattern engine the EvidencePackage
// walk uses (keyValueSecretScan + jwtScan + the key: value secret-key pass), so
// the persistence-bound path has no second redaction code path (BI-1). The
// property reuses the gopter harness shape (pinned seed 3131, MinSuccessfulTests
// >= 500, whole-string substring scan, token-presence + benign-survival,
// non-vacuous).

import (
	"strconv"
	"strings"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

func TestRedactText_KeyValueSecret(t *testing.T) {
	out, evts := RedactText("password=hunter2plaintext")
	if strings.Contains(out, "hunter2plaintext") {
		t.Errorf("secret survived: %q", out)
	}
	if !strings.Contains(out, redactedToken) {
		t.Errorf("token missing: %q", out)
	}
	if len(evts) != 1 || evts[0].Reason != ReasonSecretPattern {
		t.Errorf("want 1 secret_pattern event, got %+v", evts)
	}
}

func TestRedactText_ColonValueSecret(t *testing.T) {
	// The YAML front-matter shape.
	out, evts := RedactText(`api_key: "AKIAEXAMPLESECRETKEY"`)
	if strings.Contains(out, "AKIAEXAMPLESECRETKEY") {
		t.Errorf("secret survived: %q", out)
	}
	if !strings.Contains(out, redactedToken) || len(evts) != 1 {
		t.Errorf("want 1 redaction, got %q / %+v", out, evts)
	}
	// A list-item posture finding shape.
	out2, evts2 := RedactText("  - secret: leakedvalue123")
	if strings.Contains(out2, "leakedvalue123") || len(evts2) != 1 {
		t.Errorf("list-item secret not redacted: %q / %+v", out2, evts2)
	}
}

func TestRedactText_JWTAnywhere(t *testing.T) {
	jwt := validJWT(t)
	out, evts := RedactText("Authorization: Bearer " + jwt + " trailing")
	if strings.Contains(out, jwt) {
		t.Errorf("JWT survived: %q", out)
	}
	if !strings.Contains(out, redactedJWTToken) {
		t.Errorf("JWT token missing: %q", out)
	}
	foundJWT := false
	for _, e := range evts {
		if e.Reason == ReasonJWTBody {
			foundJWT = true
		}
	}
	if !foundJWT {
		t.Errorf("no jwt_body event: %+v", evts)
	}
}

func TestRedactText_BenignSurvives(t *testing.T) {
	// No over-redaction: a benign key=value, a bare URL, a colon with no secret
	// key, and ordinary prose all survive unchanged with no events.
	for _, in := range []string{
		"env=prod",
		"see https://example.com/path for details",
		"final_fsm_state: QUARANTINED",
		"The miner ran and was contained.",
		"threat_score_at_decision: 42.5",
	} {
		out, evts := RedactText(in)
		if out != in || len(evts) != 0 {
			t.Errorf("benign input over-redacted: %q -> %q (%+v)", in, out, evts)
		}
	}
}

func TestRedactText_MultiLine(t *testing.T) {
	in := strings.Join([]string{
		"benign line",
		"password=secretlinevalue",
		"final_fsm_state: QUARANTINED",
		"token: " + validJWT(t),
	}, "\n")
	out, evts := RedactText(in)
	if strings.Contains(out, "secretlinevalue") {
		t.Errorf("multi-line secret survived: %q", out)
	}
	if !strings.Contains(out, "benign line") || !strings.Contains(out, "QUARANTINED") {
		t.Errorf("benign lines lost: %q", out)
	}
	if len(evts) < 2 {
		t.Errorf("want >= 2 events across the lines, got %+v", evts)
	}
}

// genSecretBearingText seeds a planted secret into each of the four source-class
// text shapes and records the ground truth (the genSecretBearingPackage text
// analogue). The class is carried only to mirror the four-class coverage; the
// redactor treats all text uniformly through the ONE engine.
type secretBearingText struct {
	text    string
	secrets []string
}

func genSecretBearingText() gopter.Gen {
	return gen.SliceOf(gen.AlphaString()).Map(func(seeds []string) secretBearingText {
		if len(seeds) == 0 {
			seeds = []string{"seed"}
		}
		if len(seeds) > 4 {
			seeds = seeds[:4]
		}
		s := sanitise(seeds[0]) + strconv.Itoa(len(seeds))
		evidenceSecret := "evsecret-" + s
		llmJWT := genJWT("llm" + s)
		postureSecret := "postsecret-" + s
		auditSecret := "audsecret-" + s
		text := strings.Join([]string{
			"evidence: api_key=" + evidenceSecret,
			"llm_response: Authorization: Bearer " + llmJWT,
			"posture: secret=" + postureSecret,
			"audit: credential=" + auditSecret,
			"benign: env=prod",
		}, "\n")
		return secretBearingText{
			text:    text,
			secrets: []string{evidenceSecret, llmJWT, postureSecret, auditSecret},
		}
	})
}

// TestProperty_RedactTextNoSecretSurvives is the AC2 four-source-class property
// over the ONE text engine: no planted secret survives RedactText, the tokens
// are present (non-vacuous), and the benign env=prod survives.
func TestProperty_RedactTextNoSecretSurvives(t *testing.T) {
	props := gopter.NewProperties(pinnedParams())
	props.Property("no injected secret survives RedactText across the four source classes", prop.ForAll(
		func(sbt secretBearingText) bool {
			out, _ := RedactText(sbt.text)
			for _, secret := range sbt.secrets {
				if secret != "" && strings.Contains(out, secret) {
					return false
				}
			}
			if !strings.Contains(out, redactedToken) || !strings.Contains(out, redactedJWTToken) {
				return false
			}
			return strings.Contains(out, "env=prod")
		},
		genSecretBearingText(),
	))
	props.TestingRun(t)
}
