#!/usr/bin/env bash
# deploy/demo/setup.sh — one-stop bootstrap for the Olaitan demo cluster.
#
# Prints (default) or applies (--apply) the commands needed to stand up a
# kubeadm cluster with Calico CNI and the Helm repos Olaitan's chart pulls
# from. Idempotent: every command safe to re-run; no state mutated on a
# dry-run pass.
#
# Source of truth: _bmad-output/planning-artifacts/architecture.md#Initialization-Sequence
# lines 118-141. Calico version pinned to v3.31.5 (the April 2026
# stable release; ADR-2026-04-30-01 + ADR-2026-05-12-01 in
# docs/deferred-decisions.md record the migration from the v3.29.0
# manifest install to the v3.31.5 Tigera operator install). Verify
# the tag redirect target at docs.tigera.io/calico/latest before
# each release.

set -euo pipefail
umask 022

CALICO_VERSION="v3.31.5"
TIGERA_OPERATOR_MANIFEST="https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/tigera-operator.yaml"
CALICO_CUSTOM_RESOURCES="https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/custom-resources.yaml"
POD_NETWORK_CIDR="192.168.0.0/16"

# Repo root resolves relative to this script, so `setup.sh` works from any cwd.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CHART_DIR="${REPO_ROOT}/deploy/helm/olaitan"

APPLY=false

usage() {
  cat <<EOF
Usage: $(basename "$0") [--apply] [-h|--help]

Bootstraps a kubeadm-based demo cluster for Olaitan.

By default, the script PRINTS the commands needed for cluster creation
(kubeadm init, Calico CNI install, worker kubeadm join) and exits. No
cluster state is mutated.

With --apply, the script additionally RUNS the operator-side commands
that do not require root on the control plane (helm repo add, helm
repo update, helm dependency update for the Olaitan chart).

  --apply       Run helm repo + dependency-update commands after printing
                the preflight instructions. Does NOT run kubeadm.
  -h, --help    Print this help and exit.

Pre-reqs on PATH: kubectl, helm. (kubeadm is only required on the
control-plane node when you actually execute the printed commands;
this script never invokes kubeadm itself.)
See deploy/helm/README.md for the full install flow.
EOF
}

# Fail fast if a required binary is missing, with an install hint pointing
# at the upstream install guide.
check_tool() {
  local tool="$1" hint="$2"
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "error: '$tool' not found on PATH" >&2
    echo "       install: $hint" >&2
    exit 1
  fi
}

# This script only ever runs operator-side commands — `helm repo add`,
# `helm dependency update`, optionally `make helm-prepare`. It prints
# kubeadm and kubectl-against-cluster commands but never invokes them.
# So the prereq list is the operator-side toolchain only; do not
# require `kubeadm` here (the operator running this from a workstation
# without kubeadm installed is the common case).
check_prereqs() {
  check_tool kubectl "https://kubernetes.io/docs/tasks/tools/#kubectl"
  check_tool helm    "https://helm.sh/docs/intro/install/"
}

# Preflight commands are always printed (never executed by this script) so
# the operator can review/modify them before running as root on the control
# plane. The worker-join command is shown as a template — operators
# substitute the actual token/discovery hash from their `kubeadm init` output.
print_preflight() {
  cat <<EOF
# ---------------------------------------------------------------------
# 1. Initialise the control plane (run as root on the control-plane node):
# ---------------------------------------------------------------------
sudo kubeadm init --pod-network-cidr=${POD_NETWORK_CIDR}

# After init, set up kubectl for your user:
mkdir -p \$HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf \$HOME/.kube/config
sudo chown \$(id -u):\$(id -g) \$HOME/.kube/config

# ---------------------------------------------------------------------
# 2. Install Calico CNI via the Tigera operator (pinned to ${CALICO_VERSION}).
# Goldmane (Story 1.10 CNI flow adapter prerequisite) ships only under
# the Tigera operator install path; the legacy manifest install does
# NOT produce a Goldmane Deployment. See deploy/helm/olaitan/CNI.md
# and docs/deferred-decisions.md (ADR-2026-04-30-01 / ADR-2026-05-12-01).
# ---------------------------------------------------------------------
kubectl apply -f ${TIGERA_OPERATOR_MANIFEST}
kubectl -n tigera-operator rollout status deployment/tigera-operator --timeout=180s
kubectl apply -f ${CALICO_CUSTOM_RESOURCES}
kubectl -n calico-system rollout status deployment/goldmane --timeout=300s
kubectl -n calico-system wait --for=condition=Ready pod -l k8s-app=calico-node --timeout=180s

# ---------------------------------------------------------------------
# 3. Join worker nodes (run the output from \`kubeadm init\` on each):
# ---------------------------------------------------------------------
# sudo kubeadm join <control-plane-host>:6443 --token <token> \\
#     --discovery-token-ca-cert-hash sha256:<hash>

EOF
}

# Helm repo operations run as the current user (no root needed). The OCI
# Bitnami registry for Redis needs no `helm repo add` — `helm dependency
# update` handles OCI transparently.
#
# The `make helm-prepare` step copies config/olaitan.yaml into the chart's
# files/ directory so Helm's `.Files.Get` can read it. Without this, the
# rendered config ConfigMap is empty and pods crash-loop on first start.
install_helm_repos() {
  echo "--> make helm-prepare (copy config/olaitan.yaml into chart)"
  make -C "${REPO_ROOT}" helm-prepare

  echo "--> helm repo add falcosecurity"
  helm repo add falcosecurity https://falcosecurity.github.io/charts

  echo "--> helm repo add nats"
  helm repo add nats https://nats-io.github.io/k8s/helm/charts/

  echo "--> helm repo update"
  helm repo update

  echo "--> helm dependency update ${CHART_DIR}"
  helm dependency update "${CHART_DIR}"
}

# --- Argument parsing -------------------------------------------------
for arg in "$@"; do
  case "$arg" in
    --apply)
      APPLY=true
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown flag: $arg" >&2
      echo >&2
      usage >&2
      exit 1
      ;;
  esac
done

# --- Execution --------------------------------------------------------
check_prereqs
print_preflight

if [[ "${APPLY}" == "true" ]]; then
  echo "# ---------------------------------------------------------------------"
  echo "# --apply: running helm repo + dependency-update commands"
  echo "# ---------------------------------------------------------------------"
  install_helm_repos
  echo
  echo "done. Next:  helm install olaitan ${CHART_DIR}"
else
  echo "# Re-run with --apply to install helm repos and fetch subchart deps."
fi
