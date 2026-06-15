# Per-run DFIR report capture

No REPORTS.generated event was observed for this run.

This is expected for arms that produce no DFIR report (for example the RS arm, which runs no LLM investigation chain) and for the always-on in-process capture test, which has no S3-compatible store configured. No report body was fetched and none is fabricated (Story 5.4 BI-5).
