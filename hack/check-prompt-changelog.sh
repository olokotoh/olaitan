#!/usr/bin/env bash
# check-prompt-changelog.sh — Story 3.13 AC4 CI gate.
#
# Fails when a PR changes any per-role default prompt under
# internal/agent/prompts/defaults/*.txt without recording the new content
# hash in docs/prompt-changelog.md. Prompt drift is research-relevant
# (NFR41): each revision must be pinned to its hash so evaluation runs stay
# reproducible and the AUDIT.assessments prompt-version trail is meaningful.
#
# The content hash is the canonical (trailing-newline-trimmed) SHA-256 of
# the file, matching internal/agent/prompts loader semantics. The bash
# command substitution $(cat f) strips trailing newlines, so it agrees with
# the loader's strings.TrimRight(s, "\n").
#
# Usage:
#   hack/check-prompt-changelog.sh [BASE_REF]
# BASE_REF defaults to origin/main. In CI pass the PR base branch.
set -euo pipefail

BASE_REF="${1:-origin/main}"
PROMPT_DIR="internal/agent/prompts/defaults"
CHANGELOG="docs/prompt-changelog.md"

# Resolve a merge-base diff so only the PR's own changes are considered.
if ! git rev-parse --verify --quiet "${BASE_REF}" >/dev/null; then
  echo "check-prompt-changelog: base ref '${BASE_REF}' not found; skipping (shallow clone?)." >&2
  exit 0
fi

mapfile -t CHANGED < <(git diff --name-only "${BASE_REF}"...HEAD -- "${PROMPT_DIR}/" | grep -E '\.txt$' || true)

if [ "${#CHANGED[@]}" -eq 0 ]; then
  echo "check-prompt-changelog: no prompt files changed; nothing to verify."
  exit 0
fi

if [ ! -f "${CHANGELOG}" ]; then
  echo "check-prompt-changelog: ${CHANGELOG} is missing but prompt files changed." >&2
  exit 1
fi

fail=0
for f in "${CHANGED[@]}"; do
  if [ ! -f "${f}" ]; then
    # File deleted in this PR — not a content revision; skip.
    continue
  fi
  hash="$(printf '%s' "$(cat "${f}")" | sha256sum | cut -d' ' -f1)"
  if grep -qF "${hash}" "${CHANGELOG}"; then
    echo "ok: ${f} -> ${hash} (documented)"
  else
    echo "FAIL: ${f} changed but its new content hash ${hash} is not in ${CHANGELOG}." >&2
    fail=1
  fi
done

if [ "${fail}" -ne 0 ]; then
  echo "" >&2
  echo "Add an entry to ${CHANGELOG} naming each changed prompt and its new hash (NFR41)." >&2
  exit 1
fi

echo "check-prompt-changelog: all changed prompts documented."
