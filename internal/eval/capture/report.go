package capture

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// reportAnnouncement is the SUBSET of the REPORTS.generated wire event the
// report.md header surfaces (BI-5). It mirrors the producer fields
// (internal/report/dfir/report.go ReportGenerated) we display; the verbatim
// event is already preserved in the events-style drain, so this decode is a
// best-effort header projection, not a re-validation.
type reportAnnouncement struct {
	IncidentID    string `json:"incident_id"`
	WorkloadID    string `json:"workload_id"`
	ReportSHA256  string `json:"report_sha256"`
	ReportURL     string `json:"report_url"`
	FinalFSMState string `json:"final_fsm_state"`
	GeneratedAt   string `json:"generated_at"`
}

// writeReport assembles report.md from the captured REPORTS.generated
// announcement envelopes plus an HONEST no-S3 / no-report fallback (BI-5,
// OQ3). REPORTS.generated carries the report SHA256 + content-addressed URL,
// NOT the body, so the body fetch is Story 4.6 territory: when no S3 endpoint
// is configured (the in-process AC5 test) or no report was generated (the RS
// arm produces no DFIR report at all), report.md carries the available
// announcement metadata or an explicit no-report note. The file ALWAYS exists
// (AC5) and never pretends a body was fetched.
func writeReport(path string, reportEnvs []Envelope) error {
	var b strings.Builder
	b.WriteString("# Per-run DFIR report capture\n\n")

	if len(reportEnvs) == 0 {
		b.WriteString("No REPORTS.generated event was observed for this run.\n\n")
		b.WriteString("This is expected for arms that produce no DFIR report (for example the ")
		b.WriteString("RS arm, which runs no LLM investigation chain) and for the always-on ")
		b.WriteString("in-process capture test, which has no S3-compatible store configured. ")
		b.WriteString("No report body was fetched and none is fabricated (Story 5.4 BI-5).\n")
		return os.WriteFile(path, []byte(b.String()), 0o644)
	}

	fmt.Fprintf(&b, "Captured %d REPORTS.generated announcement(s). ", len(reportEnvs))
	b.WriteString("The announcement carries the report SHA256 + the content-addressed URL, ")
	b.WriteString("NOT the report body (the durable S3-compatible write is Story 4.6); no body ")
	b.WriteString("was fetched here, so the metadata header below is the honest record (BI-5).\n")

	for i := range reportEnvs {
		var a reportAnnouncement
		if err := json.Unmarshal(reportEnvs[i].Payload, &a); err != nil {
			// Preserve an unparseable announcement verbatim rather than
			// dropping it, so the file is still an honest record.
			fmt.Fprintf(&b, "\n## Announcement %d (raw)\n\n```json\n%s\n```\n", i+1, string(reportEnvs[i].Payload))
			continue
		}
		fmt.Fprintf(&b, "\n## Announcement %d\n\n", i+1)
		writeField(&b, "incident_id", a.IncidentID)
		writeField(&b, "workload_id", a.WorkloadID)
		writeField(&b, "final_fsm_state", a.FinalFSMState)
		writeField(&b, "report_sha256", a.ReportSHA256)
		writeField(&b, "report_url", a.ReportURL)
		writeField(&b, "generated_at", a.GeneratedAt)
		writeField(&b, "published_at", reportEnvs[i].PublishedAt)
	}

	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// writeField appends a `- **key:** value` line, omitting an empty value so the
// header does not assert a field the announcement did not carry.
func writeField(b *strings.Builder, key, val string) {
	if strings.TrimSpace(val) == "" {
		return
	}
	fmt.Fprintf(b, "- **%s:** %s\n", key, val)
}
