#!/usr/bin/env bash
# Story 10.5. Bring up the kind-full reference cluster: the one cluster
# where all five Olaitan sources run at once, with Falco ON and Calico
# enforcing NetworkPolicy for real.
#
# Usage:
#   hack/install-full-kind.sh <out-dir>
#
# <out-dir> receives private key material and MUST be outside this
# repository. Point it at a scratch directory.
#
# Environment overrides:
#   CLUSTER_NAME  kind cluster name              (default olaitan-full)
#   WORKERS       worker nodes to create         (default: as written in
#                 hack/kind-full.yaml, which is 2). Set WORKERS=1 on a
#                 host under ~16GB: the profile still installs, but
#                 cross-node Calico flows stop being exercised.
#   RELEASE       helm release name              (default olaitan)
#   NAMESPACE     target namespace               (default "default",
#                 matching the e2e suite; see below)
#   plus every override hack/install-calico-kind.sh accepts
#   (KIND_NODE_IMAGE, CALICO_VERSION, KUBECONFIG, GOLDMANE_TIMEOUT).
#
# Why this script exists rather than a documented sequence of commands:
# the kube-apiserver on kind is a static pod that refuses to start when
# its audit policy or webhook kubeconfig is missing. Both files must
# therefore be on disk BEFORE `kind create cluster` runs, which means the
# audit CA has to be generated before any node exists. That ordering is
# not something an operator should have to rediscover.
set -euo pipefail
umask 077

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

die() { echo "$0: $*" >&2; exit 2; }
info() { echo "==> $*"; }

[ "$#" -ge 1 ] || die "usage: $0 <out-dir>"
out_dir="$1"

cluster_name="${CLUSTER_NAME:-olaitan-full}"
release="${RELEASE:-olaitan}"
# "default", not "olaitan": the e2e suite hardcodes defaultNamespace =
# "default" (tests/e2e/rs_smoke_test.go) with no env override, and the AC1
# test lives in that suite. A profile that installs somewhere else cannot be
# asserted by the suite that is supposed to gate it.
namespace="${NAMESPACE:-default}"

for bin in kind kubectl helm openssl; do
    command -v "$bin" >/dev/null 2>&1 || die "missing required binary: ${bin}"
done

# Only the WORKERS path needs these, but check up front: failing after the CA
# and the certs are on disk leaves a half-built state and reports a Python
# traceback instead of this script's own error.
if [ -n "${WORKERS:-}" ]; then
    command -v python3 >/dev/null 2>&1 || die "WORKERS is set, which needs python3 to trim the node list"
    python3 -c 'import yaml' >/dev/null 2>&1 || die "WORKERS is set, which needs PyYAML (pip install pyyaml); it is not in the stdlib"
fi

# Canonicalise BEFORE the containment check and before the cd below. A
# relative <out-dir> would otherwise be validated against the invoking CWD and
# then resolved against the repo root by the cd, so key material could land
# inside the very working tree this check exists to keep it out of.
mkdir -p "$out_dir" || die "cannot create <out-dir> ${out_dir}"
out_dir="$(cd "$out_dir" && pwd)" || die "cannot resolve <out-dir>"

case "$out_dir" in
    "${repo_root}"|"${repo_root}"/*)
        die "<out-dir> is inside the repository (${out_dir}). It receives a private key that can authenticate to the apiserver audit path; keep it out of any working tree."
        ;;
esac

# hack/kind-full.yaml mounts ./hack/.audit-full into the control-plane node.
# kind resolves a relative extraMounts hostPath against the CWD of the kind
# process, NOT against the config file, so running this script from anywhere
# but the repo root would mount an empty directory somewhere else and the
# apiserver static pod would never start, reporting a missing policy file and
# blaming the file rather than the mount.
cd "$repo_root"

# --- 1. audit material, BEFORE the cluster exists ----------------------
# Mounted into the control-plane node at /etc/kubernetes/audit by the
# extraMounts block in hack/kind-full.yaml. The path is relative to the
# repo root there, so this location is load-bearing: moving it means
# editing both files.
audit_mount="${repo_root}/hack/.audit-full"
cert_dir="${out_dir}/audit-certs"

# Guard on every artifact this script later consumes, not just the CA. The CA
# is written first and the client pair several openssl calls later, so an
# interrupted first run leaves the CA behind; keying on it alone would take
# the reuse branch and then build a kubeconfig from files that do not exist.
audit_complete=true
for f in audit-ca.crt audit-client.crt audit-client.key audit-webhook-values.yaml; do
    [ -s "${cert_dir}/${f}" ] || audit_complete=false
done
if [ "$audit_complete" = false ] && [ -e "${cert_dir}/audit-ca.crt" ]; then
    # Incomplete but non-empty: an interrupted first run. audit-webhook-certs.sh
    # refuses to write into a directory that already holds a CA, so without
    # this the generate branch below would die every time and the script could
    # never make progress. Nothing has been signed by that CA yet (the client
    # pair is part of what is missing), so discarding it loses nothing.
    info "discarding an incomplete audit CA in ${cert_dir} and regenerating"
    rm -rf "$cert_dir"
fi

if [ "$audit_complete" = true ]; then
    info "reusing the audit CA already in ${cert_dir}"
else
    info "generating audit mTLS material for 127.0.0.1"
    # 127.0.0.1 because the apiserver dials its own node's loopback
    # through auditWebhook.hostPort. See values-full.yaml for why a node
    # IP cannot be used here.
    "${script_dir}/audit-webhook-certs.sh" "$cert_dir" 127.0.0.1 \
        "${release}-audit-webhook.${namespace}.svc"
fi

# Overwrite in place; do NOT rm -rf. On a re-run against an existing
# cluster this directory is already bind-mounted into the control-plane
# node at /etc/kubernetes/audit. Removing and recreating it replaces the
# inode, so the node's mount keeps pointing at the deleted one and the
# apiserver fails to find its policy on the next restart, with a message
# that blames the file rather than the mount.
mkdir -p "$audit_mount"

# The apiserver reads the policy as root but the file is bind-mounted
# read-only; 0644 matches what AUDIT.md prescribes for the kubeadm path.
cp "${repo_root}/config/audit-policy-default.yaml" "${audit_mount}/policy.yaml"
chmod 0644 "${audit_mount}/policy.yaml"

# Portable and fail-loud. BSD base64 has no -w0 (hack/audit-webhook-certs.sh
# says so explicitly), and a wrapped scalar silently corrupts the kubeconfig.
# The explicit die matters more: these calls sit inside heredocs, where cat
# exits 0 even when the substitution produced nothing, so a missing file would
# otherwise yield a kubeconfig with an EMPTY client key, bind-mounted straight
# into the apiserver.
b64() {
    # -s, not -r: a zero-byte file left by an interrupted openssl is perfectly
    # readable and base64s to the empty string, which is the failure this
    # guard exists to catch.
    [ -s "$1" ] || return 1
    base64 < "$1" | tr -d '\n'
}

# b64 CANNOT abort the script from inside a heredoc: $( ) runs in a subshell,
# so an exit there kills only the subshell and cat still returns 0, writing a
# kubeconfig with an empty client key straight into the apiserver. Every value
# is therefore materialised here, where `|| die` actually terminates the run.
b64_or_die() {
    # Name the directory the missing file is in. Both the audit and the applog
    # material go through here, and pointing an applog failure at the audit
    # directory would send the operator to delete the wrong keys.
    b64 "$1" || die "cannot read $1 (missing or empty). Its certificate directory is incomplete; delete $(dirname "$1") and re-run so the material is regenerated."
}

audit_ca_b64="$(b64_or_die "${cert_dir}/audit-ca.crt")"
audit_client_crt_b64="$(b64_or_die "${cert_dir}/audit-client.crt")"
audit_client_key_b64="$(b64_or_die "${cert_dir}/audit-client.key")"

cat > "${audit_mount}/webhook-kubeconfig.yaml" <<KUBECONFIG
# Generated by hack/install-full-kind.sh. Do not edit.
#
# The kube-apiserver presents the client certificate below to the Olaitan
# audit receiver and verifies the receiver against certificate-authority-data.
# One CA signs both sides (hack/audit-webhook-certs.sh); see that script
# for why two CAs silently rejected every connection.
apiVersion: v1
kind: Config
clusters:
  - name: olaitan-audit
    cluster:
      # The /audit path is load-bearing. The receiver muxes /audit and
      # /healthz (internal/collector/audit/audit.go); a bare host:port
      # returns 404 and the apiserver reports "the server could not find
      # the requested resource" while dropping every batch, with the TCP
      # connection succeeding the whole time. Note auditWebhook.serverAddress
      # in values.yaml is deliberately path-less: the chart appends the
      # path when it builds the in-cluster kubeconfig, so a hand-written
      # kubeconfig like this one has to add it itself.
      server: https://127.0.0.1:8443/audit
      certificate-authority-data: ${audit_ca_b64}
users:
  - name: kube-apiserver
    user:
      client-certificate-data: ${audit_client_crt_b64}
      client-key-data: ${audit_client_key_b64}
contexts:
  - name: olaitan-audit
    context:
      cluster: olaitan-audit
      user: kube-apiserver
current-context: olaitan-audit
KUBECONFIG
chmod 0600 "${audit_mount}/webhook-kubeconfig.yaml"
info "wrote ${audit_mount}/{policy.yaml,webhook-kubeconfig.yaml}"

# --- 1b. applog admission webhook serving cert -------------------------
# The applog sidecar is injected by a MutatingWebhookConfiguration, so the
# apiserver dials it over TLS and the chart requires servingCert/servingKey
# plus the caBundle it distributes. Unlike the audit webhook, no script in
# the repo generates this material, and the chart fails render without it
# (templates/applog-webhook-tls-secret.yaml). cert-manager is the other
# supported route (applogSidecar.tls.certManagerEnabled=true) and is the
# better answer for a real cluster; a self-signed pair keeps kind-full
# installable with no extra operator.
applog_dir="${out_dir}/applog-certs"
applog_svc="${release}-applog-injector.${namespace}.svc"

# Same completeness rule as the audit material above: reuse only when every
# file consumed below is present and non-empty. Keying on tls.crt alone let a
# zero-byte cert from an interrupted openssl take the reuse branch and then die
# in b64_or_die on every later run.
applog_complete=true
for f in ca.crt tls.crt tls.key; do
    [ -s "${applog_dir}/${f}" ] || applog_complete=false
done

if [ "$applog_complete" = true ]; then
    info "reusing the applog webhook cert already in ${applog_dir}"
else
    info "generating applog webhook CA + serving cert for ${applog_svc}"
    # Nothing outside this directory trusts an incomplete CA yet, so
    # discarding a partial one loses nothing.
    rm -rf "$applog_dir"
    mkdir -p "$applog_dir"
    # A CA and a serving cert it signs, NOT one self-signed cert used as
    # its own caBundle. A self-signed cert carries CA:TRUE but, once
    # keyUsage is pinned to digitalSignature+keyEncipherment for serverAuth,
    # it lacks keyCertSign; Go's crypto/x509 (which kube-apiserver uses)
    # then refuses to treat it as a CA and the TLS handshake fails. The
    # MutatingWebhookConfiguration ships failurePolicy: Ignore, so that
    # failure is SILENT: pods are admitted with no sidecar, no error and
    # no admission request in the injector log. Two certs cost nothing and
    # remove the whole failure mode.
    openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
        -keyout "${applog_dir}/ca.key" -out "${applog_dir}/ca.crt" \
        -subj "/CN=olaitan-applog-injector-ca" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        >/dev/null 2>&1

    openssl req -newkey rsa:2048 -nodes \
        -keyout "${applog_dir}/tls.key" -out "${applog_dir}/tls.csr" \
        -subj "/CN=${applog_svc}" >/dev/null 2>&1

    openssl x509 -req -in "${applog_dir}/tls.csr" \
        -CA "${applog_dir}/ca.crt" -CAkey "${applog_dir}/ca.key" \
        -CAcreateserial -days 365 -out "${applog_dir}/tls.crt" \
        -extfile <(printf '%s\n' \
            "subjectAltName=DNS:${applog_svc},DNS:${applog_svc}.cluster.local,DNS:${release}-applog-injector.${namespace}" \
            "keyUsage=critical,digitalSignature,keyEncipherment" \
            "extendedKeyUsage=serverAuth" \
            "basicConstraints=critical,CA:FALSE") \
        >/dev/null 2>&1
fi

applog_crt_b64="$(b64_or_die "${applog_dir}/tls.crt")"
applog_key_b64="$(b64_or_die "${applog_dir}/tls.key")"
applog_ca_b64="$(b64_or_die "${applog_dir}/ca.crt")"

cat > "${applog_dir}/applog-values.yaml" <<APPLOG
# Generated by hack/install-full-kind.sh. Do not edit, do not commit.
applogSidecar:
  tls:
    certManagerEnabled: false
    servingCert: "${applog_crt_b64}"
    servingKey: "${applog_key_b64}"
    caBundle: "${applog_ca_b64}"
APPLOG
chmod 0600 "${applog_dir}/applog-values.yaml"

# --- 2. kind config, optionally trimmed to WORKERS ---------------------
kind_config="${repo_root}/hack/kind-full.yaml"
if [ -n "${WORKERS:-}" ]; then
    [ "$WORKERS" -ge 1 ] 2>/dev/null || die "WORKERS must be at least 1, got \"${WORKERS}\". A control-plane-only cluster defeats the profile: the containerd sensor and the applog sidecar would only ever be exercised node-locally."
    trimmed="${out_dir}/kind-full-${WORKERS}w.yaml"
    python3 - "$kind_config" "$trimmed" "$WORKERS" <<'PY'
import sys, yaml
src, dst, workers = sys.argv[1], sys.argv[2], int(sys.argv[3])
doc = yaml.safe_load(open(src))
cp = [n for n in doc["nodes"] if n["role"] == "control-plane"]
w  = [n for n in doc["nodes"] if n["role"] == "worker"]
if workers > len(w):
    w = w + [{"role": "worker"}] * (workers - len(w))
doc["nodes"] = cp + w[:workers]
yaml.safe_dump(doc, open(dst, "w"), sort_keys=False)
PY
    kind_config="$trimmed"
    info "using ${WORKERS} worker node(s) (${kind_config})"
fi

# --- 3. cluster + Calico -----------------------------------------------
# Reuses the Story 10.11 bring-up rather than duplicating it; KIND_CONFIG
# is the override added for exactly this.
# install-calico-kind.sh refuses to write into a directory that already holds
# its material, so a second run into the same out-dir would die here, AFTER
# this script has already rewritten the audit kubeconfig on a live cluster.
# Skip the bring-up when its output is already present; that script reuses an
# existing cluster anyway, so there is nothing to redo.
# Both conditions, not just the marker file. `make e2e-full-down` deletes the
# cluster; if the out-dir survives, a marker-only check would skip cluster
# creation entirely and then run `helm --wait` against a cluster that is not
# there, failing 15 minutes later with a message about nothing relevant.
if [ -e "${out_dir}/calico/calico-values.yaml" ] && kind get clusters 2>/dev/null | grep -qx "$cluster_name"; then
    info "reusing cluster ${cluster_name} and the Calico material in ${out_dir}/calico"
else
    info "creating cluster ${cluster_name} and installing Calico"
    KIND_CONFIG="$kind_config" CLUSTER_NAME="$cluster_name" \
        "${script_dir}/install-calico-kind.sh" "${out_dir}/calico"
fi

# --- 4. the chart ------------------------------------------------------
info "installing ${release} with the full profile"
helm upgrade --install "$release" "${repo_root}/deploy/helm/olaitan" \
    --namespace "$namespace" --create-namespace \
    -f "${repo_root}/deploy/helm/olaitan/values-full.yaml" \
    -f "${out_dir}/calico/calico-values.yaml" \
    -f "${cert_dir}/audit-webhook-values.yaml" \
    -f "${applog_dir}/applog-values.yaml" \
    --wait --timeout 15m

info "installed. all five sources should report healthy within 5 minutes."
info ""
info "Health is PER NODE: the apiserver only dials the control-plane, and the"
info "containerd sensor only sees churn where pods land. No single collector"
info "pod reports all five, so check every pod and take the union. Do NOT use"
info "port-forward on the DaemonSet: it picks one arbitrary pod."
info ""
info "  for p in \$(kubectl -n ${namespace} get pods -l app.kubernetes.io/component=collector -o name); do"
info "    echo \"== \$p\"; kubectl -n ${namespace} port-forward \"\$p\" 9190:9090 >/dev/null 2>&1 &"
info "    sleep 3; curl -s localhost:9190/metrics | grep olaitan_source_healthy; kill %1"
info "  done"
info ""
info "Or run the assertion itself:  make e2e-full"
