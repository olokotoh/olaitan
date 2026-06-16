// Command olaitan-fr55 is the thin CLI driver for the OFFLINE FR55
// Trust-Bounded LLM Integration bound-test harness (Story 5.6, FR55). It
// drives the real analyst.Chain over benign-forced input under the
// harness-only adversarial prompts with a DETERMINISTIC FAKE provider (no
// cluster, no network, BI-2), asserts the algebraic trust-bound
// empirically (zero trials past SUSPICIOUS, max ThreatScore within the
// per-provider cap, cap-violation counter 0), and emits the per-trial
// records + bound-summary metadata in the EXACT shape Story 5.5's
// analysis pipeline consumes.
//
// It deliberately does NOT reuse the cluster-driven cmd/olaitan-eval Runner
// loop (OQ2): that loop runs helm upgrade + kubectl rollout against a real
// workload; the FR55 bound test drives the decision chain IN-PROCESS and
// needs no cluster, so it ships as a separate thin binary over the
// internal/eval/fr55 harness.
//
// Usage:
//
//	olaitan-fr55 --offline --config rsl|rslt-full --provider claude|ollama \
//	             --trials N --out runs/fr55
//
// The --offline flag is the only supported mode in Story 5.6 (the real
// 100-trial cluster run is a deferred carry-forward, BI-2): it selects the
// fake provider and the parameterised cap (claude -> 35 -> bound 10.5;
// ollama -> 25 -> bound 7.5, BI-6). The fake-provider trials are labelled
// provider: fake in the artefacts (BI-2), never a thesis-final number.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/olokotoh/olaitan/internal/eval/fr55"
)

// providerScoreCap maps the provider shape flag to the per-provider score
// cap the fake reports (BI-6). claude -> 35 -> bound 10.5; ollama -> 25 ->
// bound 7.5. The harness reads the bound from the provider seam, not from
// this map; this map only selects which cap the fake reports.
var providerScoreCap = map[string]int{
	"claude": 35,
	"ollama": 25,
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "olaitan-fr55:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("olaitan-fr55", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		offline      = fs.Bool("offline", false, "run the offline fake-provider bound test (the only supported mode in Story 5.6)")
		configFlag   = fs.String("config", "rslt-full", "LLM configuration under test: rsl | rslt-full")
		providerFlag = fs.String("provider", "claude", "provider shape: claude (cap 35, bound 10.5) | ollama (cap 25, bound 7.5)")
		trials       = fs.Int("trials", 10, "number of trials to run (offline uses a small deterministic N; the pre-registered N=100 cluster run is deferred)")
		out          = fs.String("out", "", "output directory for the FR55 run artefacts (the reserved runs/fr55 sub-tree); empty skips emission")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	if !*offline {
		return fmt.Errorf("only --offline is supported in Story 5.6 (the real 100-trial cluster run is a deferred carry-forward); pass --offline")
	}

	cfg, err := parseConfig(*configFlag)
	if err != nil {
		return err
	}
	scoreCap, ok := providerScoreCap[*providerFlag]
	if !ok {
		return fmt.Errorf("unknown provider %q (want claude or ollama)", *providerFlag)
	}
	if *trials < 0 {
		return fmt.Errorf("negative --trials %d", *trials)
	}

	result, err := fr55.Run(context.Background(), fr55.RunOptions{
		Config:        cfg,
		ScoreCap:      scoreCap,
		Trials:        *trials,
		ProviderLabel: fr55.OfflineProviderLabel,
		// The emulated provider shape (claude / ollama) is encoded into the
		// run-dir name and run_id so the same config under two shapes does NOT
		// collide on one un-shaped dir (Story 5.6 R2). The --provider flag is
		// validated against providerScoreCap above, so it is a known shape.
		Shape: fr55.ProviderShape(*providerFlag),
	})
	if err != nil {
		return err
	}

	sum := result.Summary
	_, _ = fmt.Fprintf(stdout, "FR55 offline bound test (provider shape: %s, config: %s, provider label: %s)\n", *providerFlag, cfg, sum.Provider)
	_, _ = fmt.Fprintf(stdout, "  trials:             %d\n", sum.NTrials)
	_, _ = fmt.Fprintf(stdout, "  bound:              %.1f (DefaultLLMWeight * ScoreCap = %.1f * %d)\n", sum.Bound, fr55.DefaultLLMWeight, scoreCap)
	_, _ = fmt.Fprintf(stdout, "  max threat score:   %.1f\n", sum.MaxThreatScore)
	_, _ = fmt.Fprintf(stdout, "  past SUSPICIOUS:    %d\n", sum.NPastSuspicious)
	_, _ = fmt.Fprintf(stdout, "  cap violations:     %d\n", sum.CapViolationTotal)
	_, _ = fmt.Fprintf(stdout, "  bound holds:        %t\n", sum.Holds())

	if *out != "" {
		if err := fr55.Emit(*out, result); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "  artefacts:          %s/%s/\n", *out, fr55.RunDirName(sum))
	}

	if !sum.Holds() {
		// A failing offline bound is a PRODUCTION DEFECT to surface, not a
		// thing to patch around (BI-5). Exit non-zero so a CI invocation of
		// the CLI fails loudly.
		return fmt.Errorf("TRUST-BOUND VIOLATED: max=%.1f bound=%.1f past_suspicious=%d cap_violations=%d (this is a production defect, escalate)",
			sum.MaxThreatScore, sum.Bound, sum.NPastSuspicious, sum.CapViolationTotal)
	}
	return nil
}

func parseConfig(s string) (fr55.Config, error) {
	switch fr55.Config(s) {
	case fr55.ConfigRSL:
		return fr55.ConfigRSL, nil
	case fr55.ConfigRSLTFull:
		return fr55.ConfigRSLTFull, nil
	default:
		return "", fmt.Errorf("unknown --config %q (want rsl or rslt-full)", s)
	}
}
