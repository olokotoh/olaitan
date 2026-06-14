# Prompt Changelog

Every change to a per-role analyst system prompt under
`internal/agent/prompts/defaults/*.txt` MUST be recorded here in the same
pull request (Story 3.13, NFR41). Prompt drift is research-relevant: it
affects evaluation reproducibility, so each revision is pinned to its
content hash and the assessments it produces carry that hash on
`AUDIT.assessments` (Story 3.14).

The content hash is the lowercase hex SHA-256 of the **canonical** prompt
text — the file bytes with trailing newlines trimmed, the same form the
controller loads and hashes. Compute it with:

```sh
printf '%s' "$(cat internal/agent/prompts/defaults/<role>.txt)" | sha256sum
```

CI (`hack/check-prompt-changelog.sh`) fails a PR that changes a prompt file
without an entry here naming the file's new hash.

| Role | File | Content hash (sha256) | Story | Notes |
|------|------|-----------------------|-------|-------|
| L1 | `l1.txt` | `7bbffc43f60c8eb29e51d7ac095220089838116d0ba788e321f5dc4a17d012ac` | 3.13 | Initial extraction from the Story 3.8 built-in default (byte-identical text; the version now travels as this content hash). |
| L2 | `l2.txt` | `b9c720828823e08cf6723de82ce056ab70b454e3393fea745d1db8f2409967c8` | 3.13 | Initial extraction from the Story 3.8 built-in default. |
| Senior | `senior.txt` | `c528d1524d22e2cd0ff20dd57021d39dc2582b5109f33fe7edd35796932b7da5` | 3.13 | Initial extraction from the Story 3.8 built-in default. |
| DFIR | `dfir.txt` | `bb9b519631bb8f9dabe72896b6039914481b28c3bfac9f2c546f2c4ed187cec6` | 4.4 | Real analyst-grade DFIR system prompt (replaces the Story 3.13 placeholder). Final-answer-only, thinking-disabled-aware, guides the FR43 report sections; the DFIR agent renders structured JSON to Markdown so the prompt requests the JSON document, not raw Markdown. |
