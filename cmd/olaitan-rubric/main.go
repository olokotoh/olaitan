// Command olaitan-rubric is the thin CLI driver for the OFFLINE DFIR rubric
// study harness (Story 5.7, RQ5). It generates the two report variants over a
// single SYNTHETIC S1 incident ((a) the Story-4.4 Olaitan DFIR LLM report,
// reused READ-ONLY with a synthetic narrative, and (b) a NEW no-LLM templated
// baseline), produces seeded blind-randomised variant pairs, emits the
// rubric.score.v1 scores artefact under the reserved runs/rubric/ sub-tree in
// the EXACT shape Story 5.5's analyse.build_rubric_rows consumes, and optionally
// writes the static-file rater workflow (the blinded reports + per-rater scoring
// sheets).
//
// It deliberately does NOT reuse the cluster-driven cmd/olaitan-eval Runner loop
// (OQ2): that loop runs helm upgrade + kubectl rollout against a real workload;
// the rubric harness generates reports + collects scores IN-PROCESS / via static
// files and needs no cluster, so it ships as a separate thin binary over the
// internal/eval/rubric harness (mirrors cmd/olaitan-fr55).
//
// THE CODE-ONLY-DEFER FENCE (BI-2): --offline is the only supported mode. It
// runs the single synthetic S1 incident with clearly-SYNTHETIC placeholder rater
// scores (labelled synthetic: true / rater: synthetic-* / rubric-offline- run
// dir), which are NEVER thesis-final. The REAL N>=3 raters x N=10
// cluster-captured incidents study is a DEFERRED carry-forward.
//
// Usage:
//
//	olaitan-rubric --offline --scenario s1 --raters 2 --out runs/rubric [--workflow]
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/olokotoh/olaitan/internal/eval/rubric"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "olaitan-rubric:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("olaitan-rubric", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		offline  = fs.Bool("offline", false, "run the offline single-synthetic-incident proof (the only supported mode in Story 5.7)")
		scenario = fs.String("scenario", "s1", "scenario label for the synthetic incident (offline proof uses s1)")
		raters   = fs.Int("raters", 2, "number of synthetic raters (>=2 so ICC has >=2 raters; the offline scores are synthetic, never thesis-final)")
		out      = fs.String("out", "", "output directory for the rubric run artefacts (the reserved runs/rubric sub-tree); empty skips emission")
		workflow = fs.Bool("workflow", false, "also write the static-file rater workflow (blinded reports + per-rater scoring sheets) under <out>/<run-dir>/workflow/")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	if !*offline {
		return fmt.Errorf("only --offline is supported in Story 5.7 (the real N>=3 x N=10 rater study is a deferred carry-forward); pass --offline")
	}
	if *raters < 0 {
		return fmt.Errorf("negative --raters %d", *raters)
	}

	result, err := rubric.RunOffline(rubric.Options{
		Scenario: *scenario,
		NRaters:  *raters,
	})
	if err != nil {
		return err
	}

	sum := result.Summary
	_, _ = fmt.Fprintf(stdout, "DFIR rubric offline proof (scenario: %s, synthetic: %t)\n", sum.Scenario, sum.Synthetic)
	_, _ = fmt.Fprintf(stdout, "  incidents:          %d (single synthetic S1; real N=10-per-scenario is deferred)\n", sum.NIncidents)
	_, _ = fmt.Fprintf(stdout, "  raters:             %d (synthetic-*; clearly-synthetic placeholder scores, never thesis-final)\n", sum.NRaters)
	_, _ = fmt.Fprintf(stdout, "  variants:           llm (Story-4.4 renderer, read-only) + templated (no-LLM baseline)\n")
	_, _ = fmt.Fprintf(stdout, "  blinded pairs:      %d (seeded from incident_id; un-blinding key kept separately)\n", len(result.Pairs))
	_, _ = fmt.Fprintf(stdout, "  rubric scores:      %d records (rubric.score.v1; 5 canonical dimensions)\n", len(result.Scores))

	if *out != "" {
		if err := rubric.Emit(*out, result); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "  artefacts:          %s/%s/\n", *out, rubric.RunDirName(sum))
		if *workflow {
			if err := rubric.EmitStaticWorkflow(*out, result); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(stdout, "  static workflow:    %s/%s/workflow/\n", *out, rubric.RunDirName(sum))
		}
	}
	return nil
}
