#!/usr/bin/env bash
#
# Traceability gate (NFR42).
#
# Reads the PR body, locates the `traceability_updated:` field, and enforces
# the matrix-or-rationale rule:
#
#   yes -> docs/traceability.md MUST appear in the PR's changed-files list.
#   no  -> the `### Traceability rationale` section MUST be non-empty after
#          stripping HTML comments and whitespace.
#
# Anything else (missing field, value other than yes|no) fails the build.
#
# Live mode (CI):
#   PR_NUMBER, GH_TOKEN required. Reads PR body via `gh pr view`, changed
#   files via `git diff --name-only origin/main...HEAD` (so a PR_BODY_FILE
#   override is not needed for the canonical run).
#
# Dry-run mode (tests):
#   --dry-run flag. PR_BODY_FILE and CHANGED_FILES_FILE provide the inputs.
#   This is what `.github/scripts/check-traceability.bats` exercises.

set -euo pipefail

dry_run=0
if [[ "${1:-}" == "--dry-run" ]]; then
  dry_run=1
fi

if [[ $dry_run -eq 1 ]]; then
  : "${PR_BODY_FILE:?PR_BODY_FILE required for --dry-run}"
  : "${CHANGED_FILES_FILE:?CHANGED_FILES_FILE required for --dry-run}"
  pr_body=$(cat "$PR_BODY_FILE")
  changed_files=$(cat "$CHANGED_FILES_FILE")
else
  : "${PR_NUMBER:?PR_NUMBER env var required (e.g. github.event.pull_request.number)}"
  pr_body=$(gh pr view "$PR_NUMBER" --json body --jq .body)
  changed_files=$(git diff --name-only origin/main...HEAD)
fi

# Normalise CRLF that GitHub sometimes emits.
pr_body=$(printf '%s' "$pr_body" | tr -d '\r')
changed_files=$(printf '%s' "$changed_files" | tr -d '\r')

# Strip HTML comments from $1, including comments that span multiple lines.
# Keeps surrounding text and writes the result to stdout.
strip_html_comments() {
  awk '
    BEGIN { in_comment = 0 }
    {
      line = $0
      out  = ""
      while (length(line) > 0) {
        if (in_comment) {
          idx = index(line, "-->")
          if (idx == 0) { line = ""; break }
          line = substr(line, idx + 3)
          in_comment = 0
          continue
        }
        idx = index(line, "<!--")
        if (idx == 0) { out = out line; line = ""; break }
        out = out substr(line, 1, idx - 1)
        rest = substr(line, idx + 4)
        end_idx = index(rest, "-->")
        if (end_idx == 0) { in_comment = 1; line = ""; break }
        line = substr(rest, end_idx + 3)
      }
      print out
    }
  '
}

# Locate the field. The PR template places it inside the "## Traceability"
# section but the gate accepts the line anywhere in the body so contributors
# can edit freely.
field_line=$(printf '%s\n' "$pr_body" | grep -E '^[[:space:]]*traceability_updated:' | head -n 1 || true)

if [[ -z "$field_line" ]]; then
  cat >&2 <<'MSG'
Traceability gate failed: traceability_updated field missing from PR body.
Add a line of the form `traceability_updated: yes` or `traceability_updated: no`
on its own line. The field is supplied automatically by .github/PULL_REQUEST_TEMPLATE.md
when a new PR is opened. See NFR42 for the matrix-or-rationale rule.
MSG
  exit 1
fi

# Extract the value: drop the field name, drop any inline HTML comment hint,
# trim whitespace.
value=$(printf '%s' "$field_line" \
  | sed -E 's/^[[:space:]]*traceability_updated:[[:space:]]*//' \
  | strip_html_comments \
  | awk '{$1=$1; print}')

case "$value" in
  yes)
    if printf '%s\n' "$changed_files" | grep -qx 'docs/traceability.md'; then
      echo "Traceability gate passed: yes path with matrix update."
      exit 0
    fi
    cat >&2 <<'MSG'
Traceability gate failed: PR declares `traceability_updated: yes` but
docs/traceability.md is not in the changed-files list. Either update the
matrix with a row for this PR's claim, or change the field to `no` with a
non-empty rationale. See NFR42 and docs/traceability.md.
MSG
    exit 1
    ;;
  no)
    rationale=$(printf '%s\n' "$pr_body" | awk '
      /^### Traceability rationale/ { capture = 1; next }
      /^## /                       { if (capture) capture = 0 }
      capture == 1                 { print }
    ')
    cleaned=$(printf '%s\n' "$rationale" \
      | strip_html_comments \
      | sed -E 's/^[[:space:]]+|[[:space:]]+$//g' \
      | grep -v '^$' || true)
    if [[ -z "$cleaned" ]]; then
      cat >&2 <<'MSG'
Traceability gate failed: PR declares `traceability_updated: no` but the
`### Traceability rationale` section is empty after stripping HTML comments.
Add at least one line stating which NFR or class of change exempts this PR
(e.g. "docs-only typo fix", "build-system tweak traced under NFR31"). See
NFR42.
MSG
      exit 1
    fi
    echo "Traceability gate passed: no path with non-empty rationale."
    exit 0
    ;;
  *)
    cat >&2 <<MSG
Traceability gate failed: traceability_updated must be exactly 'yes' or 'no'
(got: '$value'). See NFR42 and the PR template.
MSG
    exit 1
    ;;
esac
