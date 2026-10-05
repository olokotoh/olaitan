#!/usr/bin/env bash
# validate-falco-rules.sh  (Story 11.2d, review round 2)
#
# Loads the Falco rules this chart ships into the Falco binary the chart pins
# and fails if Falco would refuse them. A rules file Falco rejects stops Falco
# at startup, and with it every detection, so this is a load test, not a lint.
#
# For each profile (default, kind, full) it renders the chart, reads the
# pinned Falco image and the pinned falco-rules package from the render,
# fetches that exact package from its registry, and runs `falco -V` over the
# package plus every file of the chart's falco-rules ConfigMap in the order
# Falco loads them (/etc/falco/falco_rules.yaml, then rules.d sorted by
# name). The chart's files override upstream rules by name (decision D3 and
# the kind overlays), so a rules package that renamed one fails here.
#
# Needs: helm, docker, curl, jq, python3 with PyYAML. Run from the repo root
# after `make helm-prepare helm-deps`.
set -euo pipefail

chart=${OLT_CHART_DIR:-deploy/helm/olaitan}
stub=deploy/helm/testdata/full-profile/stub-key-material.yaml
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

render() { # $1 profile -> $work/$1/render.yaml
  local args=(template olaitan "$chart" --set secrets.redisPassword=validate)
  case $1 in
    kind) args+=(-f "$chart/values-kind.yaml") ;;
    full) args+=(-f "$chart/values-full.yaml" -f "$stub") ;;
  esac
  mkdir -p "$work/$1/rules.d"
  helm "${args[@]}" >"$work/$1/render.yaml"
}

# Split the render: falco image, falco-rules ref, and the rules.d files.
extract() { # $1 profile
  python3 - "$work/$1" <<'PY'
import sys, yaml, os
d = sys.argv[1]
image = rules_ref = None
for doc in yaml.safe_load_all(open(os.path.join(d, "render.yaml"))):
    if not doc:
        continue
    kind, name = doc.get("kind"), doc["metadata"]["name"]
    if kind == "ConfigMap" and name.endswith("falco-rules"):
        for fname, body in doc["data"].items():
            open(os.path.join(d, "rules.d", fname), "w").write(body)
    if kind == "ConfigMap" and name.endswith("falco-falcoctl"):
        cfg = yaml.safe_load(doc["data"]["falcoctl.yaml"])
        refs = [r for r in cfg["artifact"]["install"]["refs"] if r.startswith("falco-rules:")]
        if len(refs) != 1:
            sys.exit(f"expected one falco-rules ref, got {refs}")
        rules_ref = refs[0]
    if kind == "DaemonSet" and name.endswith("-falco"):
        for c in doc["spec"]["template"]["spec"]["containers"]:
            if c["name"] == "falco":
                image = c["image"]
if not (image and rules_ref):
    sys.exit(f"render is missing the falco image ({image}) or the falco-rules ref ({rules_ref})")
open(os.path.join(d, "image"), "w").write(image)
open(os.path.join(d, "rules_ref"), "w").write(rules_ref)
PY
}

fetch_rules() { # $1 falco-rules:<tag> $2 dest dir
  local tag=${1#falco-rules:} repo=falcosecurity/rules/falco-rules token layer
  token=$(curl -fsS "https://ghcr.io/token?scope=repository:$repo:pull" | jq -r .token)
  layer=$(curl -fsS -H "Authorization: Bearer $token" \
    -H "Accept: application/vnd.oci.image.manifest.v1+json" \
    "https://ghcr.io/v2/$repo/manifests/$tag" | jq -r '.layers[0].digest')
  curl -fsSL -H "Authorization: Bearer $token" "https://ghcr.io/v2/$repo/blobs/$layer" | tar -xz -C "$2"
  test -s "$2/falco_rules.yaml"
}

fail=0
for profile in default kind full; do
  echo "== $profile =="
  render "$profile"
  extract "$profile"
  image=$(cat "$work/$profile/image")
  ref=$(cat "$work/$profile/rules_ref")
  fetch_rules "$ref" "$work/$profile"
  args=(-V /v/falco_rules.yaml)
  while IFS= read -r f; do args+=(-V "/v/rules.d/$f"); done \
    < <(find "$work/$profile/rules.d" -type f -printf '%f\n' | LC_ALL=C sort)
  echo "falco image: $image"
  echo "rules: $ref + $(find "$work/$profile/rules.d" -type f | wc -l) chart file(s)"
  if ! out=$(docker run --rm -v "$work/$profile:/v:ro" --entrypoint falco "$image" "${args[@]}" 2>&1); then
    echo "$out" | grep -vE '^\S+: +/etc/falco|\[libs\]|System info' >&2
    echo "FAIL: Falco refuses the $profile profile's rules" >&2
    fail=1
    continue
  fi
  # A warning loads, but it is a rule that no longer means what it says.
  if grep -q 'Warnings:' <<<"$out"; then
    echo "$out" | sed -n '/Warnings:/,$p' >&2
    echo "FAIL: Falco loads the $profile profile's rules with warnings" >&2
    fail=1
    continue
  fi
  echo "ok: $profile"
done
exit $fail
