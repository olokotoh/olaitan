#!/usr/bin/env bash
# deploy/demo/setup.sh — one-stop bootstrap for the Olaitan demo cluster.
#
# Prints (default) or applies (--apply) the commands needed to stand up a
# kubeadm cluster with Calico CNI and the Helm repos Olaitan's chart pulls
# from. Idempotent: every command safe to re-run; no state mutated on a
# dry-run pass.
#
# Source of truth: _bmad-output/planning-artifacts/architecture.md#Initialization-Sequence
# lines 118-141. Calico version pinned to v3.29.0 (April 2026) — verify the
# tag redirect target at docs.tigera.io/calico/latest before each release.

set -euo pipefail
umask 022

CALICO_VERSION="v3.29.0"
CALICO_MANIFEST="https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/calico.yaml"
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

Pre-reqs on PATH: kubectl, helm, kubeadm.
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

check_prereqs() {
  check_tool kubectl "https://kubernetes.io/docs/tasks/tools/#kubectl"
  check_tool helm    "https://helm.sh/docs/intro/install/"
  check_tool kubeadm "https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/"
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
# 2. Install Calico CNI (pinned to ${CALICO_VERSION}):
# ---------------------------------------------------------------------
kubectl apply -f ${CALICO_MANIFEST}

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
install_helm_repos() {
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
