## Summary

<!-- Brief description of what this PR does -->

## FRs Addressed

<!-- List functional requirements covered, e.g. FR1, FR6 -->

## Traceability

traceability_updated: <!-- yes | no. yes if docs/traceability.md is updated in this PR; no if this PR adds no claim -->

prompt_changelog_updated: <!-- yes | n/a. yes if this PR changes any internal/agent/prompts/defaults/*.txt and docs/prompt-changelog.md records the new content hash(es) (NFR41); n/a if this PR changes no prompt files. CI (prompt-changelog job) enforces this. -->

### Traceability rationale

<!-- One or more lines explaining the claim added (when yes) or why this
     PR adds no claim (when no). Required when traceability_updated: no
     (the CI gate fails on an empty rationale). Encouraged when
     traceability_updated: yes (briefly state the claim added) so
     reviewers can find the new row at a glance, but the gate does not
     enforce it on the yes path. -->

## Testing Done

<!-- How was this tested? Unit tests, integration tests, manual verification -->

## Checklist

- [ ] Code compiles (`make build`)
- [ ] Tests pass (`make test`)
- [ ] Lint passes (`make lint`)
- [ ] Acceptance criteria from the story are met
- [ ] No secrets or credentials committed
- [ ] traceability_updated field is set and matrix-or-rationale is correct (NFR42)
- [ ] prompt_changelog_updated field is set; any prompt-file change has a docs/prompt-changelog.md entry with the new hash (NFR41)
