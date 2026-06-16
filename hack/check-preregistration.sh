#!/usr/bin/env bash
# check-preregistration.sh -- Story 5.8 structural gate.
#
# Asserts that analysis/preregistration.md exists and carries the eight
# mandated section headings (BI-3) plus the confirmatory test registry marker.
# This is a STRUCTURAL gate only: it proves the sections are present, NOT that
# the statistics are correct (a human supervisor reviews the numbers). It fails
# non-zero if the file is missing or any mandated heading or the registry
# marker is absent, so a section cannot be silently dropped.
#
# Usage:
#   hack/check-preregistration.sh
set -euo pipefail

PREREG="analysis/preregistration.md"

if [ ! -f "${PREREG}" ]; then
  echo "check-preregistration: ${PREREG} is missing." >&2
  exit 1
fi

# The eight mandated section headings (BI-3) and the registry marker. Each
# entry is matched as a fixed string with grep -F so heading punctuation does
# not need escaping.
REQUIRED=(
  "## 1. Pre-registration metadata"
  "## 2. Research questions"
  "## 3. Per-RQ hypotheses"
  "## 4. Primary outcome metrics"
  "## 5. Statistical procedures, alpha, and Bonferroni structure"
  "## 6. Sample sizes"
  "## 7. Stopping rule"
  "## 8. Confirmatory-vs-exploratory contract and traceability contract"
  "prereg-registry-marker"
)

fail=0
for needle in "${REQUIRED[@]}"; do
  if grep -qF "${needle}" "${PREREG}"; then
    echo "ok: found '${needle}'"
  else
    echo "FAIL: ${PREREG} is missing required marker: '${needle}'" >&2
    fail=1
  fi
done

if [ "${fail}" -ne 0 ]; then
  echo "" >&2
  echo "analysis/preregistration.md must carry the eight mandated section headings (BI-3) and the confirmatory test registry marker (Story 5.8)." >&2
  exit 1
fi

echo "check-preregistration: all eight sections and the registry marker present."
