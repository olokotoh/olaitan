#!/usr/bin/env bash
# check-release-version.sh <tag>  (Story 12.1)
#
# Refuses a release tag that is not the chart version the tree carries.
# The README's `helm install ... --version X` is tied to Chart.yaml's
# version by deploy/helm/readme_install_test.go; release.yml runs this in
# its preflight so the tag is tied to the same number. Without it, a tag
# that differs from Chart.yaml publishes a chart the README never names.
#
# Chart.yaml's appVersion is not checked: the tree keeps it at `edge` on
# purpose (a tree install runs the image built from the tree), and the
# release stamps both fields from the tag into the packaged copy.
set -euo pipefail

tag="${1:-}"
if [[ "$tag" != v* ]]; then
  echo "release tag '${tag}' must be v<chart version>" >&2
  exit 1
fi
want="${tag#v}"

chart="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/deploy/helm/olaitan/Chart.yaml"
have="$(awk '/^version:/ { gsub(/["'\'']/, "", $2); print $2; exit }' "$chart")"
if [[ -z "$have" ]]; then
  echo "no version in ${chart#"$PWD"/}" >&2
  exit 1
fi
if [[ "$have" != "$want" ]]; then
  echo "refusing to release ${tag}: deploy/helm/olaitan/Chart.yaml version is ${have}." >&2
  echo "Bump Chart.yaml (and the README --version, which a helm test ties to it) in a PR, then tag v${have}." >&2
  exit 1
fi
echo "tag ${tag} matches Chart.yaml version ${have}"
