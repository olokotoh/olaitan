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
#   CALICO_VERSION   Calico / Tigera release     (default v3.31.5)
#   KUBECONFIG       kubeconfig to create and read the cluster through
#   GOLDMANE_TIMEOUT seconds to wait for Goldmane (default 600)
#
# It writes into <out-dir>, all readable by the owner only:
#   ca.crt              Tigera CA bundle PEM, the adapter verifies
#                       Goldmane's serving cert against it
#   client.crt          client certificate PEM the adapter presents
#   client.key          its private key
#   calico-values.yaml  the same three, base64-encoded on one line under
#                       calicoSensor.tls, ready for `helm install -f`
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
for tool in kind kubectl base64; do
    command -v "$tool" >/dev/null 2>&1 || die "${tool} is not on PATH."
done
if ! printf '%s' "$cluster_name" | grep -Eq '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'; then
    die "CLUSTER_NAME is \"${cluster_name}\": want a lowercase DNS label."
fi
if ! printf '%s' "$calico_version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
    die "CALICO_VERSION is \"${calico_version}\": want a release tag such as v3.31.5."
fi
if ! printf '%s' "$goldmane_timeout" | grep -Eq '^[1-9][0-9]*$'; then
    die "GOLDMANE_TIMEOUT is \"${goldmane_timeout}\": want a positive whole number of seconds."
fi
if [ -e "${out_dir}/calico-values.yaml" ] || [ -e "${out_dir}/client.key" ]; then
    die "${out_dir} already holds certificate material (calico-values.yaml or client.key). Refreshing writes a different certificate, and silently replacing the old one would leave an installed release pointing at material nobody can account for. Use an empty directory, or move the old one away first."
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
kind_config="${script_dir}/kind-calico-config.yaml"
[ -f "$kind_config" ] || die "kind config not found at ${kind_config}."

context="kind-${cluster_name}"
kc() { kubectl --context "$context" "$@"; }

manifests="https://raw.githubusercontent.com/projectcalico/calico/${calico_version}/manifests"

# --- 1. the cluster ---------------------------------------------------

if kind get clusters 2>/dev/null | grep -Fxq "$cluster_name"; then
    info "kind cluster ${cluster_name} already exists; reusing it (this is the certificate-refresh path)."
    # An existing cluster may have been created from another kubeconfig.
    kind export kubeconfig --name "$cluster_name" >/dev/null
else
    info "creating kind cluster ${cluster_name} from ${kind_config} (default CNI disabled; pods stay pending until Calico lands)."
    kind create cluster \
        --name "$cluster_name" \
        --image "$node_image" \
        --config "$kind_config"
fi
kc cluster-info >/dev/null || die "cannot reach the cluster through context ${context}."
ok "cluster ${cluster_name} reachable."

# --- 2. Calico through the Tigera operator ----------------------------

# The operator manifest carries CRDs too large for a client-side apply's
# last-applied annotation, which is why upstream documents `create`. On
# the refresh path the objects already exist, so install only what is
# missing rather than failing on an AlreadyExists.
# Since Calico v3.30 the operator's own CRDs ship in operator-crds.yaml,
# not in tigera-operator.yaml, and the operator does not install them
# itself. Without them the custom resources below fail with "no matches
# for kind Installation in version operator.tigera.io/v1", which is how
# this was found on a live kind cluster.
if kc get crd installations.operator.tigera.io >/dev/null 2>&1; then
    info "Tigera operator CRDs already present; leaving them alone."
else
    info "installing the Tigera operator CRDs, Calico ${calico_version}."
    kc create -f "${manifests}/operator-crds.yaml"
fi
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

if kc get installation default >/dev/null 2>&1; then
    info "Installation CR already present; leaving it alone."
else
    info "applying the Calico custom resources (Installation, APIServer, Goldmane, Whisker)."
    kc create -f "${manifests}/custom-resources.yaml"
fi

# --- 3. wait for Goldmane --------------------------------------------

info "waiting up to ${goldmane_timeout}s for Goldmane to become ready."
deadline=$((SECONDS + goldmane_timeout))
until [ "$(kc -n calico-system get deployment goldmane -o jsonpath='{.status.readyReplicas}' 2>/dev/null || true)" = "1" ]; do
    if [ "$SECONDS" -ge "$deadline" ]; then
        no "Goldmane is not ready after ${goldmane_timeout}s."
        kc get tigerastatus 2>/dev/null || true
        kc -n calico-system get pods 2>/dev/null || true
        echo "FIX: Goldmane ships only with the operator install on Calico v3.31.5+." >&2
        echo "     Check the calico-node DaemonSet is running first (Goldmane has no" >&2
        echo "     network until the CNI is up), then read the operator's log:" >&2
        echo "     kubectl --context ${context} -n tigera-operator logs deployment/tigera-operator" >&2
        exit 1
    fi
    sleep 5
done
ok "Goldmane ready in calico-system."

# --- 4. the Path B certificate material -------------------------------

mkdir -p "$out_dir"

# The CA bundle lives in a ConfigMap, so it is already PEM text.
if ! kc -n calico-system get configmap tigera-ca-bundle \
        -o jsonpath='{.data.tigera-ca-bundle\.crt}' > "${out_dir}/ca.crt"; then
    die "cannot read the tigera-ca-bundle ConfigMap in calico-system."
fi

# The client pair lives in a Secret, so the same jsonpath yields base64,
# NOT PEM. Decode it here and let the encoder below put it back; reading
# a Secret field as if it were a ConfigMap field is the easy mistake,
# and it produces a values file that looks right and never handshakes.
for pair in "tls.crt:client.crt" "tls.key:client.key"; do
    secret_key="${pair%%:*}"
    out_file="${pair##*:}"
    if ! kc -n calico-system get secret whisker-backend-key-pair \
            -o "jsonpath={.data.${secret_key//./\\.}}" | base64 -d > "${out_dir}/${out_file}"; then
        die "cannot read ${secret_key} from the whisker-backend-key-pair Secret in calico-system."
    fi
done

# The CA bundle is not bare PEM: Tigera prefixes each certificate with a
# "# certificate name: ..." comment line, so the marker is looked for
# anywhere in the file rather than on the first line.
for f in ca.crt client.crt client.key; do
    if ! grep -q -- "-----BEGIN" "${out_dir}/${f}"; then
        die "${out_dir}/${f} is not PEM. The cluster returned something unexpected; nothing here is usable."
    fi
done

# One line of base64 on GNU and BSD alike (BSD base64 has no -w0).
b64() { base64 < "$1" | tr -d '\n'; }

cat > "${out_dir}/calico-values.yaml" <<EOF
# Generated by hack/install-calico-kind.sh against kind cluster
# ${cluster_name}, Calico ${calico_version}. Pass with: helm install -f
# this file. This is Path B (operator-supplied PEMs), which is not
# rotation-aware: when Tigera rotates the material, re-run the script
# into a fresh directory and helm upgrade. See CNI.md.
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
