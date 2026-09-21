#!/usr/bin/env bash
# Story 10.11 (#140 AC1). Bring up a kind cluster whose CNI is Calico,
# installed through the Tigera operator so Goldmane exists, and write the
# Path B mTLS values the Olaitan chart needs to reach it.
#
# The e2e cluster (hack/kind-config.yaml) runs kindnetd: it has no
# Goldmane at all and it accepts NetworkPolicy objects without enforcing
# them, so neither the Calico flow adapter (FR4) nor the release
# NetworkPolicy can be exercised there. This script builds the cluster
# that can, with hack/kind-calico-config.yaml.
#
# Usage:
#   hack/install-calico-kind.sh <out-dir>
#
# Environment overrides:
#   CLUSTER_NAME     kind cluster name           (default olaitan-calico)
#   KIND_NODE_IMAGE  kind node image             (default kindest/node:v1.30.0)
#   CALICO_VERSION   Calico / Tigera release     (default v3.31.5, floor v3.30)
#   KUBECONFIG       kubeconfig to create and read the cluster through
#   GOLDMANE_TIMEOUT seconds to wait for Goldmane (default 600)
#   KIND_CONFIG      kind config to create from  (default
#                    hack/kind-calico-config.yaml). Story 10.5 passes
#                    hack/kind-full.yaml so the full profile reuses this
#                    Calico bring-up rather than duplicating it. Any
#                    config given here MUST set disableDefaultCNI and
#                    carry a podSubnet, which is read out of it below.
#
# The pod CIDR is NOT an environment override: it has to agree between
# the kind cluster and Calico's IPPool, so hack/kind-calico-config.yaml
# holds it once and this script reads it from there. Change it in that
# file and the Installation below follows.
#
# It writes into <out-dir>, all readable by the owner only:
#   ca.crt              Tigera CA bundle PEM, the adapter verifies
#                       Goldmane's serving cert against it
#   client.crt          client certificate PEM the adapter presents
#   client.key          its private key
#   calico-values.yaml  the same three, base64-encoded on one line under
#                       calicoSensor.tls, ready for `helm install -f`
#
# Point <out-dir> somewhere OUTSIDE this repository: client.key can
# authenticate to Goldmane and nothing in a working tree should be able
# to reach a commit by accident.
#
# An existing cluster is REUSED, not recreated: re-running against the
# same cluster with a fresh out-dir is how you refresh the certificates
# after Tigera rotates them. The out-dir itself is never overwritten,
# because every file in it is key material.
set -euo pipefail

# Every output is key material or embeds it.
umask 077

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <out-dir>" >&2
    exit 2
fi

die() {
    echo "$0: $*" >&2
    exit 2
}

out_dir="$1"
cluster_name="${CLUSTER_NAME:-olaitan-calico}"
node_image="${KIND_NODE_IMAGE:-kindest/node:v1.30.0}"
calico_version="${CALICO_VERSION:-v3.31.5}"
goldmane_timeout="${GOLDMANE_TIMEOUT:-600}"

ok()   { echo "ok:   $*"; }
no()   { echo "no:   $*"; }
info() { echo "info: $*"; }

# Validate everything before creating a cluster or writing a file.
for tool in kind kubectl base64 sed mktemp; do
    command -v "$tool" >/dev/null 2>&1 || die "${tool} is not on PATH."
done
if ! printf '%s' "$cluster_name" | grep -Eq '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'; then
    die "CLUSTER_NAME is \"${cluster_name}\": want a lowercase DNS label."
fi
if ! printf '%s' "$calico_version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
    die "CALICO_VERSION is \"${calico_version}\": want a release tag such as v3.31.5."
fi
# Floor v3.30. Before it the operator's CRDs shipped inside
# tigera-operator.yaml and there is no operator-crds.yaml to fetch, so
# the CRD step below would 404 and the run would fail several minutes
# later with "no matches for kind Installation". Goldmane itself only
# exists from v3.31.5 anyway, which the adapter needs, but the manifest
# layout is the thing this script cannot work around.
calico_major="$(printf '%s' "$calico_version" | sed -E 's/^v([0-9]+)\.([0-9]+)\..*/\1/')"
calico_minor="$(printf '%s' "$calico_version" | sed -E 's/^v([0-9]+)\.([0-9]+)\..*/\2/')"
if [ "$calico_major" -lt 3 ] || { [ "$calico_major" -eq 3 ] && [ "$calico_minor" -lt 30 ]; }; then
    die "CALICO_VERSION is \"${calico_version}\": v3.30 is the floor, because operator-crds.yaml does not exist before it. Goldmane needs v3.31.5 or newer in any case."
fi
if ! printf '%s' "$goldmane_timeout" | grep -Eq '^[1-9][0-9]*$'; then
    die "GOLDMANE_TIMEOUT is \"${goldmane_timeout}\": want a positive whole number of seconds."
fi
# Guard EVERY output, not just two of them. An out-dir holding a stray
# ca.crt or client.crt from an interrupted run is still an out-dir whose
# contents would stop matching each other halfway through this one.
for f in ca.crt client.crt client.key calico-values.yaml; do
    if [ -e "${out_dir}/${f}" ]; then
        die "${out_dir} already holds ${f}. Refreshing writes different certificate material, and silently replacing the old set would leave an installed release pointing at material nobody can account for. Use an empty directory, or move the old one away first."
    fi
done

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
kind_config="${KIND_CONFIG:-${script_dir}/kind-calico-config.yaml}"
[ -f "$kind_config" ] || die "kind config not found at ${kind_config}."

# One source of truth for the pod CIDR: the kind config. Calico's
# Installation is given this same value below, because the two disagreeing
# is the failure this reads for. Calico would otherwise keep its own
# 192.168.0.0/16 default and hand pods addresses outside the cluster's
# podCIDR.
pod_cidr="$(sed -nE 's/^[[:space:]]*podSubnet:[[:space:]]*"?([^"[:space:]]+)"?.*/\1/p' "$kind_config" | head -n1)"
if ! printf '%s' "$pod_cidr" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$'; then
    die "cannot read an IPv4 podSubnet out of ${kind_config} (got \"${pod_cidr}\"). That file is where the pod CIDR is defined."
fi

context="kind-${cluster_name}"
kc() { kubectl --context "$context" "$@"; }

manifests="https://raw.githubusercontent.com/projectcalico/calico/${calico_version}/manifests"

tmp_dir=""
cleanup() { if [ -n "$tmp_dir" ]; then rm -rf "$tmp_dir"; fi; }
trap cleanup EXIT

# --- 1. the cluster ---------------------------------------------------

reusing=""
if kind get clusters 2>/dev/null | grep -Fxq "$cluster_name"; then
    reusing=yes
    info "kind cluster ${cluster_name} already exists; reusing it (this is the certificate-refresh path)."
    if [ -n "${KIND_NODE_IMAGE+set}" ]; then
        no "KIND_NODE_IMAGE=${node_image} is IGNORED on the reuse path: the node is already running whatever image it was created with. Delete the cluster (kind delete cluster --name ${cluster_name}) to change it."
    fi
    # An existing cluster may have been created from another kubeconfig.
    kind export kubeconfig --name "$cluster_name" >/dev/null
else
    info "creating kind cluster ${cluster_name} from ${kind_config} (default CNI disabled; pods stay pending until Calico lands). Pod CIDR ${pod_cidr}."
    kind create cluster \
        --name "$cluster_name" \
        --image "$node_image" \
        --config "$kind_config"
fi
kc cluster-info >/dev/null || die "cannot reach the cluster through context ${context}."

if [ -n "$reusing" ]; then
    # A cluster of the right NAME is not necessarily the right cluster.
    # Reusing an e2e-style kind cluster here is silent and wrong: kindnet
    # would still own the CNI, its pod CIDR is not this one, and the run
    # would end with certificate material that no Goldmane ever issued.
    if kc -n kube-system get daemonset kindnet >/dev/null 2>&1; then
        die "cluster ${cluster_name} runs kindnet, so it was NOT created from ${kind_config} and Calico cannot own its CNI. Delete it (kind delete cluster --name ${cluster_name}) or run with a different CLUSTER_NAME."
    fi
    existing_cidr="$(kc -n kube-system get pod -l component=kube-controller-manager \
        -o jsonpath='{.items[0].spec.containers[0].command[*]}' 2>/dev/null \
        | tr ' ' '\n' | sed -n 's/^--cluster-cidr=//p' | head -n1)"
    if [ -n "$existing_cidr" ] && [ "$existing_cidr" != "$pod_cidr" ]; then
        die "cluster ${cluster_name} was created with pod CIDR ${existing_cidr}, but ${kind_config} now says ${pod_cidr}. A cluster's pod CIDR cannot be changed in place. Delete it (kind delete cluster --name ${cluster_name}) and re-run."
    fi
    existing_pool="$(kc get installation default -o jsonpath='{.spec.calicoNetwork.ipPools[0].cidr}' 2>/dev/null || true)"
    if [ -n "$existing_pool" ] && [ "$existing_pool" != "$pod_cidr" ]; then
        die "the Installation on ${cluster_name} claims IPPool ${existing_pool}, but the cluster pod CIDR is ${pod_cidr}. An IPPool CIDR is immutable once Calico has created it, so this cannot be repaired in place. Delete the cluster (kind delete cluster --name ${cluster_name}) and re-run."
    fi
    # CALICO_VERSION cannot retro-install a different release either, and
    # the values header must name what is actually running rather than
    # what was asked for.
    installed_version="$(kc get installation default -o jsonpath='{.status.calicoVersion}' 2>/dev/null || true)"
    if [ -n "$installed_version" ] && [ "$installed_version" != "$calico_version" ]; then
        if [ -n "${CALICO_VERSION+set}" ]; then
            die "cluster ${cluster_name} is running Calico ${installed_version}, but CALICO_VERSION asks for ${calico_version}. This script does not upgrade Calico in place. Delete the cluster and re-run, or unset CALICO_VERSION to use what is installed."
        fi
        no "cluster ${cluster_name} is running Calico ${installed_version}, not the default ${calico_version}; using ${installed_version} for the manifests and the values header."
        calico_version="$installed_version"
        manifests="https://raw.githubusercontent.com/projectcalico/calico/${calico_version}/manifests"
    fi
fi
ok "cluster ${cluster_name} reachable, pod CIDR ${pod_cidr}."

# --- 2. Calico through the Tigera operator ----------------------------

# Since Calico v3.30 the operator's own CRDs ship in operator-crds.yaml,
# not in tigera-operator.yaml, and the operator does not install them
# itself. Without them the custom resources below fail with "no matches
# for kind Installation in version operator.tigera.io/v1", which is how
# this was found on a live kind cluster.
#
# `apply --server-side`, not `create`: these CRDs are too large for a
# client-side apply's last-applied annotation, which is why upstream
# documents `create`, but `create` also aborts on AlreadyExists, so an
# interrupted run that installed some of the CRDs could never be resumed.
# Server-side apply has no annotation limit and is idempotent.
info "installing the Tigera operator CRDs, Calico ${calico_version}."
kc apply --server-side --force-conflicts -f "${manifests}/operator-crds.yaml"
for crd in installations.operator.tigera.io goldmanes.operator.tigera.io whiskers.operator.tigera.io apiservers.operator.tigera.io; do
    if ! kc wait --for=condition=Established "crd/${crd}" --timeout=120s >/dev/null 2>&1; then
        die "CRD ${crd} was never established, so the Calico custom resources cannot be applied."
    fi
done
ok "Tigera operator CRDs established."

if kc -n tigera-operator get deployment tigera-operator >/dev/null 2>&1; then
    info "Tigera operator already installed; leaving it alone."
else
    info "installing the Tigera operator, Calico ${calico_version}."
    kc create -f "${manifests}/tigera-operator.yaml"
fi
if ! kc -n tigera-operator rollout status deployment/tigera-operator --timeout=300s; then
    no "the Tigera operator never became available."
    kc -n tigera-operator get pods
    die "no Tigera operator, so no Goldmane. Check the node can pull quay.io images."
fi
ok "Tigera operator available."

# The Installation, APIServer, Goldmane and Whisker CRs, with the IPPool
# CIDR replaced by this cluster's pod CIDR.
#
# Why not apply the upstream file as it stands: its Installation pins
# Calico's own default IPPool, 192.168.0.0/16. Whatever the kind config
# says, Calico would keep that pool and hand out pod addresses the
# cluster does not route. Why not patch afterwards: an IPPool CIDR is
# immutable once the operator has created it, so a patch is a race
# against the operator that the operator usually wins.
#
# So the objects are fetched, the one cidr line is substituted, and the
# result is applied. kubectl does the fetching (`--dry-run=client` reads
# the URL and prints the objects without contacting the API server for
# anything but the type mapping), so this needs no curl. Substitution is
# guarded: the upstream file carries exactly one `cidr:` line today, and
# if that ever stops being true this refuses to guess.
#
# `apply`, not `create`: an interrupted run leaves some of the four CRs
# behind, and `create` would abort on the first AlreadyExists while
# Goldmane, the one CR this script exists for, is still missing. Apply is
# idempotent over all four.
tmp_dir="$(mktemp -d)"
cr_upstream="${tmp_dir}/custom-resources-upstream.yaml"
cr_applied="${tmp_dir}/custom-resources.yaml"
if ! kc create -f "${manifests}/custom-resources.yaml" --dry-run=client -o yaml > "$cr_upstream"; then
    die "cannot read ${manifests}/custom-resources.yaml. Check the node has network access to raw.githubusercontent.com."
fi
cidr_lines="$(grep -c '^[[:space:]]*cidr:' "$cr_upstream" || true)"
if [ "$cidr_lines" != "1" ]; then
    die "expected exactly one 'cidr:' line in the Calico ${calico_version} custom resources, found ${cidr_lines}. Substituting the pod CIDR blind would be a guess; apply the manifest by hand with cidr ${pod_cidr} instead."
fi
sed -E "s#^([[:space:]]*cidr:[[:space:]]*).*#\1${pod_cidr}#" "$cr_upstream" > "$cr_applied"
grep -Fq "cidr: ${pod_cidr}" "$cr_applied" || die "the pod CIDR substitution did not take; refusing to apply an Installation whose IPPool does not match ${pod_cidr}."
info "applying the Calico custom resources (Installation with IPPool ${pod_cidr}, APIServer, Goldmane, Whisker)."
kc apply -f "$cr_applied"

# --- 3. wait for Goldmane --------------------------------------------

# The Deployment is created by the operator in response to the Goldmane
# CR, so it does not exist the instant the CR is applied and `rollout
# status` would fail outright. Wait for the object, then let rollout
# status judge readiness: it understands a Deployment that is progressing,
# stuck or rolling, which a readyReplicas comparison against the literal 1
# does not, and it reports why.
info "waiting up to ${goldmane_timeout}s for Goldmane to become ready."
goldmane_deadline=$((SECONDS + goldmane_timeout))
goldmane_trouble() {
    kc get tigerastatus 2>/dev/null || true
    kc -n calico-system get pods 2>/dev/null || true
    echo "FIX: Goldmane ships only with the operator install on Calico v3.31.5+." >&2
    echo "     Check the calico-node DaemonSet is running first (Goldmane has no" >&2
    echo "     network until the CNI is up), then read the operator's log:" >&2
    echo "     kubectl --context ${context} -n tigera-operator logs deployment/tigera-operator" >&2
}
until kc -n calico-system get deployment goldmane >/dev/null 2>&1; do
    if [ "$SECONDS" -ge "$goldmane_deadline" ]; then
        no "the operator never created the Goldmane Deployment within ${goldmane_timeout}s."
        goldmane_trouble
        exit 1
    fi
    sleep 5
done
remaining=$((goldmane_deadline - SECONDS))
if [ "$remaining" -lt 30 ]; then remaining=30; fi
if ! kc -n calico-system rollout status deployment/goldmane --timeout="${remaining}s"; then
    no "Goldmane never became ready."
    goldmane_trouble
    exit 1
fi
ok "Goldmane ready in calico-system."

# --- 4. the Path B certificate material -------------------------------

# Read everything into variables and validate it BEFORE any file is
# created. A redirection is a truncation: `kubectl ... > ca.crt` that
# fails has already emptied (or created) the file, so a failed read used
# to leave behind exactly the kind of half-written out-dir the guard at
# the top refuses to touch on the next run.
#
# The CA bundle lives in a ConfigMap, so it is already PEM text.
if ! ca_pem="$(kc -n calico-system get configmap tigera-ca-bundle \
        -o jsonpath='{.data.tigera-ca-bundle\.crt}')"; then
    die "cannot read the tigera-ca-bundle ConfigMap in calico-system."
fi

# The client pair lives in a Secret, so the same jsonpath yields base64,
# NOT PEM. Decode it here and let the encoder below put it back; reading
# a Secret field as if it were a ConfigMap field is the easy mistake,
# and it produces a values file that looks right and never handshakes.
#
# The identity borrowed is whisker-backend-key-pair. See CNI.md: on this
# cluster the collector authenticates to Goldmane AS Whisker, and a
# Goldmane-side audit cannot tell the two apart. That is acceptable for a
# dev sandbox and for nothing else.
if ! client_cert_pem="$(kc -n calico-system get secret whisker-backend-key-pair \
        -o 'jsonpath={.data.tls\.crt}' | base64 -d)"; then
    die "cannot read tls.crt from the whisker-backend-key-pair Secret in calico-system."
fi
if ! client_key_pem="$(kc -n calico-system get secret whisker-backend-key-pair \
        -o 'jsonpath={.data.tls\.key}' | base64 -d)"; then
    die "cannot read tls.key from the whisker-backend-key-pair Secret in calico-system."
fi

# The CA bundle is not bare PEM: Tigera prefixes each certificate with a
# "# certificate name: ..." comment line, so the marker is looked for
# anywhere in the material rather than on the first line.
for pair in "ca.crt:${ca_pem}" "client.crt:${client_cert_pem}" "client.key:${client_key_pem}"; do
    case "${pair#*:}" in
        *-----BEGIN*) ;;
        *) die "what the cluster returned for ${pair%%:*} is not PEM. Nothing here is usable; check the Calico install finished." ;;
    esac
done

mkdir -p "$out_dir"
printf '%s\n' "$ca_pem"          > "${out_dir}/ca.crt"
printf '%s\n' "$client_cert_pem" > "${out_dir}/client.crt"
printf '%s\n' "$client_key_pem"  > "${out_dir}/client.key"

# One line of base64 on GNU and BSD alike (BSD base64 has no -w0).
b64() { base64 < "$1" | tr -d '\n'; }

cat > "${out_dir}/calico-values.yaml" <<EOF
# Generated by hack/install-calico-kind.sh against kind cluster
# ${cluster_name}, Calico ${calico_version}, pod CIDR ${pod_cidr}. Pass
# with: helm install -f this file. This is Path B (operator-supplied
# PEMs), which is not rotation-aware: when Tigera rotates the material,
# re-run the script into a fresh directory and helm upgrade.
#
# The client identity is borrowed from Whisker, so to Goldmane this
# collector IS Whisker. Dev sandbox only. See CNI.md.
calicoSensor:
  enabled: true
  tls:
    caBundle: "$(b64 "${out_dir}/ca.crt")"
    clientCert: "$(b64 "${out_dir}/client.crt")"
    clientKey: "$(b64 "${out_dir}/client.key")"
EOF

ok "wrote ${out_dir}/calico-values.yaml"
echo "     ca.crt             Tigera CA bundle; the adapter verifies Goldmane's serving cert against it"
echo "     client.crt         client certificate the adapter presents to Goldmane"
echo "     client.key         its private key; it can authenticate to Goldmane, keep it out of the repo"
echo "     calico-values.yaml the three above, base64 on one line, under calicoSensor.tls"
echo
info "next: helm install olaitan deploy/helm/olaitan -f ${out_dir}/calico-values.yaml"
info "      then apply the traffic fixture so there are flows to read:"
info "      kubectl --context ${context} apply -f tests/e2e/fixtures/calico-flow-traffic.yaml"
