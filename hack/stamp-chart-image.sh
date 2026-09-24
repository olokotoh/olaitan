#!/usr/bin/env bash
# Story 12.6: write the Olaitan image a release pushed into a staged chart's
# values.yaml, so the published chart pins it by tag AND digest.
#
#   hack/stamp-chart-image.sh <src values.yaml> <dst values.yaml> <repository> <digest>
#
# Only the top-level `image:` block is touched: its first `repository:` line
# becomes <repository> (a fork pushes to its own owner, so the chart must
# name the repository the digest lives in) and its empty `digest: ""` line
# becomes <digest>. Exit 3 if either line is not found, so a reshuffled
# values.yaml fails the release instead of shipping an unstamped chart.
#
# The release workflow runs this after the image job pushes and signs; the
# helm test suite (TestReleaseStampPinsTheOlaitanImage) runs it on a copy of
# the chart on every CI run, so a break shows up before a release does.
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 <src values.yaml> <dst values.yaml> <repository> <digest>" >&2
  exit 2
fi
src=$1 dst=$2 repo=$3 digest=$4

[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] \
  || { echo "not a digest: '${digest}'" >&2; exit 1; }
[[ -n "$repo" && "$repo" != *[[:space:]]* ]] \
  || { echo "not a repository: '${repo}'" >&2; exit 1; }

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
awk -v repo="$repo" -v digest="$digest" '
  /^[^[:space:]#]/ { inimg = ($0 == "image:") }
  inimg && !r && /^  repository: / { print "  repository: " repo; r = 1; next }
  inimg && !d && /^  digest: ""$/ { print "  digest: \"" digest "\""; d = 1; next }
  { print }
  END { if (!r || !d) { print "image.repository or an empty image.digest line not found" > "/dev/stderr"; exit 3 } }
' "$src" > "$tmp"
mv "$tmp" "$dst"
trap - EXIT
