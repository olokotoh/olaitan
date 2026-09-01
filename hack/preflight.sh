#!/usr/bin/env bash
# olaitan preflight -- answer "will this actually work on my cluster?" BEFORE installing.
#
# Olaitan is a security tool. The worst outcome is not failing to install; it is
# installing cleanly and then reporting containment it never achieved. This
# script probes the four things that decide whether a given cluster can run it
# honestly, and prints what will be ON, what will be OFF, and why.
#
# It makes no changes except a short-lived probe namespace, which it deletes.
#
# Exit 0 = can run (possibly degraded), 1 = a hard blocker, 2 = probe inconclusive.
set -uo pipefail

NS="${NS:-olaitan-preflight}"
KEEP_NS="${KEEP_NS:-false}"
B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; D=$'\033[2m'; X=$'\033[0m'
[ -t 1 ] || { B=""; G=""; Y=""; R=""; D=""; X=""; }

WARNINGS=0; BLOCKERS=0; INCONCLUSIVE=0
ok()    { echo "  ${G}yes${X}     $*"; }
no()    { echo "  ${Y}no${X}      $*"; WARNINGS=$((WARNINGS+1)); }
bad()   { echo "  ${R}BLOCKER${X} $*"; BLOCKERS=$((BLOCKERS+1)); }
info()  { echo "  ${D}$*${X}"; }

cleanup() { [ "$KEEP_NS" = "true" ] || kubectl delete ns "$NS" --wait=false >/dev/null 2>&1 || true; }
trap cleanup EXIT

command -v kubectl >/dev/null || { echo "kubectl is required"; exit 2; }
if ! kubectl version >/dev/null 2>&1; then
  echo "${R}Cannot reach a cluster.${X} Check your kubeconfig context."
  exit 2
fi

CTX="$(kubectl config current-context 2>/dev/null || echo '?')"
SRV="$(kubectl version -o json 2>/dev/null | grep -o '"gitVersion": *"[^"]*"' | tail -1 | cut -d'"' -f4)"
echo
echo "${B}Olaitan preflight${X}   context ${B}${CTX}${X}   server ${SRV:-unknown}"

# ---------------------------------------------------------------- distribution
echo
echo "${B}Cluster${X}"
NODE="$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)"
RUNTIME="$(kubectl get nodes -o jsonpath='{.items[0].status.nodeInfo.containerRuntimeVersion}' 2>/dev/null)"
OSIMG="$(kubectl get nodes -o jsonpath='{.items[0].status.nodeInfo.osImage}' 2>/dev/null)"
KERNEL="$(kubectl get nodes -o jsonpath='{.items[0].status.nodeInfo.kernelVersion}' 2>/dev/null)"
NODES="$(kubectl get nodes --no-headers 2>/dev/null | wc -l | tr -d ' ')"

DISTRO="unknown"
case "$CTX$OSIMG$RUNTIME$NODE" in
  *kind-*|*kind*)        DISTRO="kind" ;;
  *minikube*)            DISTRO="minikube" ;;
  *k3s*|*k3d*)           DISTRO="k3s" ;;
esac
[ "$DISTRO" = "unknown" ] && kubectl get nodes -o jsonpath='{.items[0].spec.providerID}' 2>/dev/null | grep -q '^aws://'   && DISTRO="eks"
[ "$DISTRO" = "unknown" ] && kubectl get nodes -o jsonpath='{.items[0].spec.providerID}' 2>/dev/null | grep -q '^azure://' && DISTRO="aks"
[ "$DISTRO" = "unknown" ] && kubectl get nodes -o jsonpath='{.items[0].spec.providerID}' 2>/dev/null | grep -q '^gce://'   && DISTRO="gke"
kubectl api-resources 2>/dev/null | grep -q securitycontextconstraints && DISTRO="openshift"

info "distribution : $DISTRO"
info "nodes        : $NODES   runtime: ${RUNTIME:-?}"
info "os / kernel  : ${OSIMG:-?} / ${KERNEL:-?}"

# ------------------------------------------------------------------ 1. storage
echo
echo "${B}1. Storage${X}  ${D}(NATS JetStream needs a PersistentVolume)${X}"
# The default-class annotation sits AFTER the name in the JSON object, so a
# grep -B window is unreliable (it silently reported "no default" on kind, which
# does ship one). Use jsonpath, which reads the object, not the text.
DEFSC="$(kubectl get storageclass -o jsonpath='{range .items[?(@.metadata.annotations.storageclass\.kubernetes\.io/is-default-class=="true")]}{.metadata.name}{"\n"}{end}' 2>/dev/null | head -1)"
if [ -z "$DEFSC" ]; then
  # beta annotation, still used by some older provisioners
  DEFSC="$(kubectl get storageclass -o jsonpath='{range .items[?(@.metadata.annotations.storageclass\.beta\.kubernetes\.io/is-default-class=="true")]}{.metadata.name}{"\n"}{end}' 2>/dev/null | head -1)"
fi
if [ -n "$DEFSC" ]; then
  ok "default StorageClass: ${B}${DEFSC}${X}"
else
  if [ "$(kubectl get storageclass --no-headers 2>/dev/null | wc -l | tr -d ' ')" -gt 0 ]; then
    bad "no DEFAULT StorageClass -- NATS JetStream's PVC will stay Pending forever"
    info "classes exist but none is marked default. Name one explicitly:"
    info "--set nats.persistence.storageClass=<name> --set reports.storageClass=<name>"
    [ "$DISTRO" = "eks" ] && info "EKS >=1.30 ships no default class by design (gp2 lost the annotation)."
  else
    bad "no StorageClass at all -- NATS JetStream cannot bind a volume"
    info "install a provisioner (k3s local-path, minikube addons enable storage-provisioner)"
    [ "$DISTRO" = "eks" ] && info "EKS: install the aws-ebs-csi-driver add-on; it needs its own IAM role (IRSA/Pod Identity)."
  fi
fi

# --------------------------------------------------------- 2. privileged pods
echo
echo "${B}2. Privileged workloads${X}  ${D}(Falco's kernel driver needs them)${X}"
kubectl create ns "$NS" >/dev/null 2>&1 || true

# Platforms that refuse privileged workloads by POLICY. Detected before the
# dry-run because the failure is a product decision, not a misconfiguration,
# and the remedy is different in kind.
case "$DISTRO" in
  gke)
    if kubectl get nodes -o jsonpath='{.items[*].metadata.labels}' 2>/dev/null | grep -q "autopilot"; then
      bad "GKE Autopilot BLOCKS privileged containers (Warden admission webhook)"
      info "Olaitan cannot run here. Use a GKE Standard cluster."
    fi ;;
  aks)
    if kubectl get ns 2>/dev/null | grep -q "azure-extensions\|aks-automatic"; then
      no "AKS Automatic enforces Baseline PSS and it CANNOT be turned off"
      info "privileged, hostPath and host namespaces are refused at admission."
      info "Only escape hatch: exclude this namespace from Deployment Safeguards."
    fi ;;
  eks)
    if kubectl get nodes -o jsonpath='{.items[*].metadata.labels}' 2>/dev/null | grep -q "fargate"; then
      bad "EKS Fargate does not support DaemonSets OR privileged containers"
      info "A Fargate profile matching this namespace SILENTLY swallows the"
      info "DaemonSet -- no scheduling, no error. Use EC2 node groups."
    fi ;;
esac

PSA="$(kubectl get ns "$NS" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}' 2>/dev/null)"
DRYRUN="$(kubectl -n "$NS" run psa-probe --image=busybox:1.36 --restart=Never --dry-run=server \
  --overrides='{"spec":{"containers":[{"name":"p","image":"busybox:1.36","securityContext":{"privileged":true}}]}}' \
  -- true 2>&1)"
if echo "$DRYRUN" | grep -qi "violat\|forbidden\|denied"; then
  bad "privileged pods are REJECTED by admission"
  info "$(echo "$DRYRUN" | head -2 | tail -1 | cut -c1-100)"
  info "Falco cannot run here. Use an external Falco (endpoints.falco) or a non-Autopilot cluster."
else
  ok "privileged pods are admitted${PSA:+  (namespace PSA enforce=$PSA)}"
fi
if [ "$DISTRO" = "openshift" ]; then
  no "OpenShift detected -- the collector DaemonSet needs an SCC allowing hostPath and any UID"
  info "the chart ships the binding: --set openshift.bindSCC=true (values-openshift.yaml sets it)"
  info "it binds ${B}hostmount-anyuid${X}, NOT privileged: Olaitan's own containers are"
  info "unprivileged, drop ALL capabilities and run read-only root filesystems."
  info "NOTE: stock hostmount-anyuid sets allowedCapabilities: null, so it REJECTS the"
  info "CHOWN the socket-permission container needs. See the header comment in"
  info "deploy/helm/olaitan/templates/openshift-scc-binding.yaml for the custom SCC."
fi

# ---------------------------------------------- 3. NetworkPolicy ENFORCEMENT
echo
echo "${B}3. NetworkPolicy enforcement${X}  ${D}(the isolation response depends on it)${X}"
if [ -x "$(dirname "$0")/check-netpol-enforcement.sh" ]; then
  if NS="${NS}-np" "$(dirname "$0")/check-netpol-enforcement.sh" >/tmp/olaitan-np.$$ 2>&1; then
    ok "policies are ENFORCED -- isolation will actually contain a workload"
  else
    case $? in
      1) bad "policies are NOT ENFORCED -- the API accepts them, the data plane ignores them"
         info "Olaitan would report a workload QUARANTINED while it still has network access."
         info "Keep response.networkPolicy.enabled=false (the default), or install Calico/Cilium." ;;
      *) no "enforcement probe inconclusive (see /tmp/olaitan-np.$$)"
         INCONCLUSIVE=$((INCONCLUSIVE+1)) ;;
    esac
  fi
  rm -f /tmp/olaitan-np.$$ 2>/dev/null
else
  no "probe script not found; run hack/check-netpol-enforcement.sh manually"
fi

# ------------------------------------------------------- 4. optional sources
echo
echo "${B}4. Optional detection sources${X}"
case "$DISTRO" in
  eks|aks|gke)
    no "K8s audit webhook: ${R}unavailable${X} on managed control planes"
    info "needs --audit-webhook-config-file on kube-apiserver, which $DISTRO does not expose."
    info "leave auditWebhook.enabled=false (the default)." ;;
  *)
    ok "K8s audit webhook: possible (you control the API server)"
    info "enable with auditWebhook.enabled=true + hack/audit-apiserver-patch.yaml" ;;
esac
case "$DISTRO" in
  k3s)  no "containerd socket lives at /run/k3s/containerd/containerd.sock on k3s"
        info "--set containerdSensor.socketPath=/run/k3s/containerd/containerd.sock" ;;
  *)    info "containerd sensor: off by default; socket assumed /run/containerd/containerd.sock" ;;
esac
if kubectl get crd 2>/dev/null | grep -q "tigera\|calico"; then
  ok "Calico detected -- the CNI flow adapter is available"
else
  info "Calico CNI flow adapter: off by default (needs Calico via the Tigera operator)"
fi

# ------------------------------------------------------- 5. host inotify room
# Falco watches container lifecycle through inotify. On a workstation running
# several clusters the per-user instance limit is exhausted before Falco starts
# and it dies with "could not initialize inotify handler" -- a HOST limit, not
# a cluster or chart problem, and invisible from kubectl. Hit on this very
# machine (128 instances vs kind's documented 512).
echo
echo "${B}5. Host limits${X}  ${D}(local clusters only -- Falco needs inotify room)${X}"
case "$DISTRO" in
  kind|minikube|k3s)
    INST="$(cat /proc/sys/fs/inotify/max_user_instances 2>/dev/null || echo '')"
    WATCH="$(cat /proc/sys/fs/inotify/max_user_watches 2>/dev/null || echo '')"
    if [ -z "$INST" ]; then
      info "cannot read /proc/sys/fs/inotify (not Linux, or a remote cluster)"
    elif [ "$INST" -lt 512 ] || [ "$WATCH" -lt 524288 ]; then
      no "inotify limits are low: instances=$INST (want >=512), watches=$WATCH (want >=524288)"
      info "Falco will die with 'could not initialize inotify handler'. Raise them:"
      info "sudo sysctl -w fs.inotify.max_user_instances=512 fs.inotify.max_user_watches=524288"
    else
      ok "inotify limits are sufficient (instances=$INST, watches=$WATCH)"
    fi ;;
  *) info "remote cluster -- host inotify limits are a node concern, not checkable from here" ;;
esac

# --------------------------------------------------------------------- verdict
echo
if [ "$BLOCKERS" -gt 0 ]; then
  echo "${R}${B}$BLOCKERS blocker(s)${X} and $WARNINGS caveat(s)."
  echo "Olaitan will install, but read the blockers above first -- at least one means"
  echo "it cannot do what it claims on this cluster."
  exit 1
fi
# Exit 2 = a probe could not reach a verdict. Distinct from "ready with
# caveats" on purpose: a caveat is something we KNOW, and an inconclusive
# probe is something we do not. Collapsing the two into exit 0 would have a
# script consuming this treat "we could not tell whether your CNI enforces"
# as "your cluster is fine", which for this tool is the wrong default.
if [ "$INCONCLUSIVE" -gt 0 ]; then
  echo "${Y}${B}$INCONCLUSIVE probe(s) inconclusive${X}, plus $WARNINGS caveat(s)."
  echo "Nothing here blocks the install, but at least one capability could not be"
  echo "established either way. Re-run the named probe before trusting that capability."
  exit 2
fi
if [ "$WARNINGS" -gt 0 ]; then
  echo "${G}${B}Ready${X}, with $WARNINGS caveat(s) noted above."
else
  echo "${G}${B}Ready.${X} Every capability Olaitan needs is present."
fi
echo
echo "Install:  ${B}helm install olaitan oci://ghcr.io/olokotoh/charts/olaitan \\"
echo "            --namespace olaitan --create-namespace${X}"
exit 0
