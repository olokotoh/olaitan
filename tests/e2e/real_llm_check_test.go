//go:build e2e

package e2e_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/olokotoh/olaitan/internal/config"
)

// Story 10.6: the live test can only prove what its checker refuses, so the
// checker is pinned here without a cluster, the same way the Story 10.5 AC2
// matcher is (full_profile_match_test.go).

// goodRealLLMRecord is an AUDIT.assessments v2 record shaped like the one a
// real full-mode chain run on the ollama family publishes: three roles
// contributed, every role recorded the configured provider and model, the
// model reported 85, and the ollama cap of 25 was applied.
const goodRealLLMRecord = `{
  "schema_version": "audit.assessments.v2",
  "package_id": "pkg-1",
  "workload_id": "ns/Deployment/victim",
  "mode": "full",
  "agents_available": ["l1", "l2", "senior"],
  "prompt_versions": {"l1": "aa", "l2": "bb", "senior": "cc"},
  "providers": {"l1": "ollama", "l2": "ollama", "senior": "ollama"},
  "models": {"l1": "qwen2.5:3b-instruct", "l2": "qwen2.5:3b-instruct", "senior": "qwen2.5:3b-instruct"},
  "threat_type": "credential_access",
  "raw_confidence": 85,
  "llm_capped_confidence": 25,
  "l1_hypothesis": {
    "schema_version": "l1_hypothesis.v1",
    "hypothesis": "A shell in the container read /etc/shadow.",
    "cited_evidence": [{"event_id": "ev-1", "note": "the read"}],
    "follow_up_probes": ["who ran the shell"],
    "confidence": 80
  },
  "l2_verification": {
    "schema_version": "l2_verification.v1",
    "verdict": "confirmed",
    "verified_evidence": [{"event_id": "ev-1", "finding": "the read is in the Falco event"}],
    "confidence": 82
  },
  "threat_assessment": {
    "threat_type": "credential_access",
    "confidence": 25,
    "recommended_state": "",
    "reasoning": "The read of /etc/shadow is a credential access attempt.",
    "mitre_techniques": ["T1003.008"],
    "kill_chain_stage": "credential-access",
    "mode": "llm",
    "raw_confidence": 85,
    "llm_capped_confidence": 25,
    "agents_available": ["l1", "l2", "senior"]
  },
  "redacted_evidence": {"package_id": "pkg-1", "events": [{"id": "ev-1", "source": "falco"}]},
  "redaction_applied": true
}`

var realLLMWantForTest = realLLMWant{Provider: "ollama", Model: "qwen2.5:3b-instruct", Cap: 25}

// mutate applies f to the decoded good record and re-encodes it.
func mutate(t *testing.T, f func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(goodRealLLMRecord), &m); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	f(m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRealLLMCheckAcceptsAGoodRecord(t *testing.T) {
	schemas := loadModelSchemas(t)
	if problems := checkRealLLMAssessment([]byte(goodRealLLMRecord), realLLMWantForTest, schemas); len(problems) != 0 {
		t.Fatalf("good record rejected:\n%s", strings.Join(problems, "\n"))
	}
}

func TestRealLLMCheckRejects(t *testing.T) {
	schemas := loadModelSchemas(t)
	cases := []struct {
		name string
		f    func(m map[string]any)
		want string
	}{
		{"not the full chain", func(m map[string]any) { m["mode"] = "l1_l2" }, "mode"},
		{"senior degraded out of the chain", func(m map[string]any) {
			m["agents_available"] = []any{"l1", "l2"}
		}, "agents_available"},
		{"provider not the configured one", func(m map[string]any) {
			m["providers"].(map[string]any)["l2"] = "openai"
		}, "providers[l2]"},
		{"model not the configured one", func(m map[string]any) {
			m["models"].(map[string]any)["senior"] = "fake"
		}, "models[senior]"},
		{"prompt version missing", func(m map[string]any) {
			delete(m["prompt_versions"].(map[string]any), "l1")
		}, "prompt_versions[l1]"},
		{"L1 output not schema-valid", func(m map[string]any) {
			m["l1_hypothesis"].(map[string]any)["verdict"] = "extra key"
		}, "l1_hypothesis"},
		{"L1 output missing", func(m map[string]any) { delete(m, "l1_hypothesis") }, "l1_hypothesis"},
		{"L2 output not schema-valid", func(m map[string]any) {
			m["l2_verification"].(map[string]any)["confidence"] = 400
		}, "l2_verification"},
		{"Senior output not schema-valid", func(m map[string]any) {
			m["threat_assessment"].(map[string]any)["reasoning"] = ""
		}, "threat_assessment"},
		{"Senior fell back to the unavailable degrade", func(m map[string]any) {
			m["threat_assessment"].(map[string]any)["llm_unavailable"] = true
		}, "llm_unavailable"},
		{"model confidence not above the cap, so the cap was never exercised", func(m map[string]any) {
			m["raw_confidence"] = 20
			m["llm_capped_confidence"] = 20
			m["threat_assessment"].(map[string]any)["raw_confidence"] = 20
			m["threat_assessment"].(map[string]any)["llm_capped_confidence"] = 20
		}, "raw_confidence"},
		{"cap not applied in the audit record", func(m map[string]any) {
			m["llm_capped_confidence"] = 85
		}, "llm_capped_confidence"},
		{"redaction not applied", func(m map[string]any) { m["redaction_applied"] = false }, "redaction_applied"},
		{"no Falco event in the evidence", func(m map[string]any) {
			m["redacted_evidence"] = map[string]any{"events": []any{map[string]any{"id": "ev-1", "source": "audit"}}}
		}, "falco"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			problems := checkRealLLMAssessment(mutate(t, tc.f), realLLMWantForTest, schemas)
			if len(problems) == 0 {
				t.Fatalf("record accepted; want a problem naming %q", tc.want)
			}
			if !strings.Contains(strings.Join(problems, "\n"), tc.want) {
				t.Errorf("problems do not name %q:\n%s", tc.want, strings.Join(problems, "\n"))
			}
		})
	}
}

// TestRealLLMCheckRejectsGarbage: a record that is not JSON is a problem,
// not a panic.
func TestRealLLMCheckRejectsGarbage(t *testing.T) {
	if problems := checkRealLLMAssessment([]byte("not json"), realLLMWantForTest, loadModelSchemas(t)); len(problems) == 0 {
		t.Fatal("garbage accepted")
	}
}

// Story 10.6 (DeepSeek run): what the audit record must say is derived
// from the live release's configuration, per family, so the same test
// proves the in-cluster model and a hosted one.
func TestRealLLMWantFollowsTheConfiguredFamily(t *testing.T) {
	cfg := func(f func(c *config.Config)) *config.Config {
		c := &config.Config{}
		c.Analyst.ScoreCap = 35
		f(c)
		return c
	}
	good := []struct {
		name string
		c    *config.Config
		want realLLMWant
	}{
		{"full profile: in-cluster ollama", cfg(func(c *config.Config) {
			c.Analyst.Provider = "local"
			c.Analyst.Local.Model = "qwen2.5:3b-instruct"
		}), realLLMWant{Provider: "ollama", Model: "qwen2.5:3b-instruct", Cap: 25}},
		{"deepseek overlay: openai family", cfg(func(c *config.Config) {
			c.Analyst.Provider = "api"
			c.Analyst.API.Endpoint = "https://api.deepseek.com/v1"
			c.Analyst.L1Provider, c.Analyst.L2Provider, c.Analyst.SeniorProvider = "openai", "openai", "openai"
			c.Analyst.L1Model, c.Analyst.L2Model, c.Analyst.SeniorModel = "deepseek-v4-pro", "deepseek-v4-pro", "deepseek-v4-pro"
			c.Analyst.Local.Model = "qwen2.5:3b-instruct" // the FR28 fallback stays configured
		}), realLLMWant{Provider: "openai", Model: "deepseek-v4-pro", Cap: 30}},
		// deepseek-chat is a vendor alias: DeepSeek answers it as
		// deepseek-flash (non-thinking), and the audit record stores the
		// model the vendor reports. The record must name that served id.
		{"deepseek overlay as shipped: the deepseek-chat alias", cfg(func(c *config.Config) {
			c.Analyst.Provider = "api"
			c.Analyst.API.Endpoint = "https://api.deepseek.com/v1"
			c.Analyst.L1Provider, c.Analyst.L2Provider, c.Analyst.SeniorProvider = "openai", "openai", "openai"
			c.Analyst.L1Model, c.Analyst.L2Model, c.Analyst.SeniorModel = "deepseek-chat", "deepseek-chat", "deepseek-chat"
		}), realLLMWant{Provider: "openai", Model: "deepseek-flash", Configured: "deepseek-chat", Cap: 30}},
		{"claude overlay: model from analyst.api.model", cfg(func(c *config.Config) {
			c.Analyst.Provider = "api"
			c.Analyst.L1Provider, c.Analyst.L2Provider, c.Analyst.SeniorProvider = "claude", "claude", "claude"
			c.Analyst.API.Model = "claude-haiku-4-5"
		}), realLLMWant{Provider: "claude", Model: "claude-haiku-4-5", Cap: 35}},
	}
	for _, tc := range good {
		t.Run(tc.name, func(t *testing.T) {
			got, err := wantFromConfig(tc.c)
			if err != nil {
				t.Fatalf("wantFromConfig: %v", err)
			}
			if got != tc.want {
				t.Errorf("want = %+v, expected %+v", got, tc.want)
			}
		})
	}

	bad := []struct {
		name, why string
		c         *config.Config
	}{
		{"rules only", "provider", cfg(func(c *config.Config) { c.Analyst.Provider = "none" })},
		{"roles on different families", "family", cfg(func(c *config.Config) {
			c.Analyst.Provider = "api"
			c.Analyst.L1Provider, c.Analyst.L2Provider, c.Analyst.SeniorProvider = "openai", "ollama", "openai"
			c.Analyst.L1Model, c.Analyst.SeniorModel = "deepseek-chat", "deepseek-chat"
			c.Analyst.Local.Model = "qwen2.5:3b-instruct"
		})},
		{"roles on different models", "model", cfg(func(c *config.Config) {
			c.Analyst.Provider = "api"
			c.Analyst.L1Provider, c.Analyst.L2Provider, c.Analyst.SeniorProvider = "openai", "openai", "openai"
			c.Analyst.L1Model, c.Analyst.L2Model, c.Analyst.SeniorModel = "deepseek-chat", "deepseek-chat", "deepseek-reasoner"
		})},
		{"openai role with no model", "model", cfg(func(c *config.Config) {
			c.Analyst.Provider = "api"
			c.Analyst.L1Provider, c.Analyst.L2Provider, c.Analyst.SeniorProvider = "openai", "openai", "openai"
		})},
		{"global cap tighter than the family cap", "score_cap", cfg(func(c *config.Config) {
			c.Analyst.ScoreCap = 20
			c.Analyst.Provider = "local"
			c.Analyst.Local.Model = "qwen2.5:3b-instruct"
		})},
		{"fake-llm endpoint left behind", "fake-llm", cfg(func(c *config.Config) {
			c.Analyst.Provider = "api"
			c.Analyst.API.Endpoint = "http://fake-llm.default.svc:8080/v1"
			c.Analyst.L1Provider, c.Analyst.L2Provider, c.Analyst.SeniorProvider = "openai", "openai", "openai"
			c.Analyst.L1Model, c.Analyst.L2Model, c.Analyst.SeniorModel = "m", "m", "m"
		})},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			got, err := wantFromConfig(tc.c)
			if err == nil {
				t.Fatalf("accepted as %+v; want an error naming %q", got, tc.why)
			}
			if !strings.Contains(err.Error(), tc.why) {
				t.Errorf("error %q does not name %q", err, tc.why)
			}
		})
	}
}

// The checker holds a hosted-model record to the openai cap of 30, not the
// ollama 25: a record capped at 25 under the openai family is wrong.
func TestRealLLMCheckUsesTheFamilyCap(t *testing.T) {
	schemas := loadModelSchemas(t)
	want := realLLMWant{Provider: "openai", Model: "deepseek-chat", Cap: 30}
	openai := func(capped int) func(m map[string]any) {
		return func(m map[string]any) {
			for _, k := range []string{"providers", "models"} {
				for _, r := range []string{"l1", "l2", "senior"} {
					v := "openai"
					if k == "models" {
						v = "deepseek-chat"
					}
					m[k].(map[string]any)[r] = v
				}
			}
			m["llm_capped_confidence"] = capped
			m["threat_assessment"].(map[string]any)["llm_capped_confidence"] = capped
			m["threat_assessment"].(map[string]any)["confidence"] = capped
		}
	}
	if p := checkRealLLMAssessment(mutate(t, openai(30)), want, schemas); len(p) != 0 {
		t.Fatalf("openai record capped at 30 rejected:\n%s", strings.Join(p, "\n"))
	}
	p := checkRealLLMAssessment(mutate(t, openai(25)), want, schemas)
	if !strings.Contains(strings.Join(p, "\n"), "cap 30") {
		t.Fatalf("openai record capped at 25 not rejected for the openai cap:\n%s", strings.Join(p, "\n"))
	}
}

// TestOllamaListID (review round 1, P6): the e2e reads the model's ID from
// `ollama list` and compares it with the ID values-full.yaml pins, so a
// re-pushed tag fails the proof instead of passing it with other weights.
func TestOllamaListID(t *testing.T) {
	list := "NAME                   ID              SIZE      MODIFIED\n" +
		"qwen2.5:3b-instruct    357c53fb659c    1.9 GB    2 minutes ago\n" +
		"llama3:latest          0123456789ab    4.7 GB    1 day ago\n"
	for _, c := range []struct{ model, want string }{
		{"qwen2.5:3b-instruct", "357c53fb659c"},
		{"llama3", "0123456789ab"},
		{"qwen2.5:7b-instruct", ""},
		{"ID", ""},
	} {
		if got := ollamaListID(list, c.model); got != c.want {
			t.Errorf("ollamaListID(%q) = %q, want %q", c.model, got, c.want)
		}
	}
	ids, err := profileExpectedModelIDs()
	if err != nil {
		t.Fatal(err)
	}
	if ids["qwen2.5:3b-instruct"] != "357c53fb659c" {
		t.Errorf("values-full expectedIds = %v, want qwen2.5:3b-instruct pinned to 357c53fb659c", ids)
	}
}
