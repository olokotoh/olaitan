# Bootstrap a kubeadm cluster for Olaitan

This document describes how to stand up the three-node Ubuntu 22.04
cluster that Olaitan targets. It is the canonical written procedure;
`deploy/demo/setup.sh` is the executable companion that prints (and
optionally applies) the operator-side commands. Prefer running the
script in print mode first, reviewing the commands, then executing
them by hand on the control plane.

## Target topology

| Node | Role | RAM | vCPU | Disk |
| --- | --- | --- | --- | --- |
| `oltn-cp-1` | Control plane | 6 GB | 4 | 50 GB NVMe |
| `oltn-w-1` | Worker | 6 GB | 4 | 50 GB NVMe |
| `oltn-w-2` | Worker | 6 GB | 4 | 50 GB NVMe |

Source: PRD NFR1 and architecture.md tech-stack section. The 6 GB / 4
vCPU envelope is what the evaluation harness assumes when reporting
resource overhead.

## Versions pinned

| Component | Version | Notes |
| --- | --- | --- |
| Ubuntu Server | 22.04 LTS | kernel 6.5+ required for the Falco eBPF driver |
| containerd | 1.7.x | the kubeadm 1.29 default runtime |
| kubeadm / kubelet / kubectl | 1.29.x | matches `Chart.yaml` `kubeVersion: ">=1.29.0"` |
| Calico CNI | v3.29.0 | see `docs/deferred-decisions.md` for the v3.27 to v3.29.0 reconciliation |

## Prerequisites on every node

Run as root on each of the three nodes before `kubeadm init` or
`kubeadm join`:

```bash
# 1. Disable swap (kubelet requirement).
sudo swapoff -a
sudo sed -i.bak '/\sswap\s/s/^/#/' /etc/fstab

# 2. Load required kernel modules.
sudo tee /etc/modules-load.d/k8s.conf <<EOF
overlay
br_netfilter
EOF
sudo modprobe overlay
sudo modprobe br_netfilter

# 3. Enable IPv4 forwarding and bridge filtering.
sudo tee /etc/sysctl.d/99-kubernetes.conf <<EOF
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF
sudo sysctl --system

# 4. Verify kernel version is 6.5+ for the Falco eBPF driver.
uname -r
```

## Install containerd 1.7

```bash
sudo apt-get update
sudo apt-get install -y containerd

# Generate the default config and switch the cgroup driver to systemd
# (kubeadm 1.29 default).
sudo mkdir -p /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml >/dev/null
sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
sudo systemctl restart containerd
sudo systemctl enable containerd
```

## Install kubeadm 1.29

```bash
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl gpg

sudo mkdir -p -m 755 /etc/apt/keyrings
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.29/deb/Release.key \
  | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg

echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.29/deb/ /' \
  | sudo tee /etc/apt/sources.list.d/kubernetes.list

sudo apt-get update
sudo apt-get install -y kubelet kubeadm kubectl
sudo apt-mark hold kubelet kubeadm kubectl
```

## Re-running on a partially-initialised node

If `kubeadm init` was run previously on this node (failed install,
partial setup), reset before attempting again — `kubeadm init` is NOT
idempotent and will fail with "etcd already exists" or similar
cryptic errors when state from a prior run remains.

```bash
# Wipe kubeadm-managed state. Safe on a clean node (it just reports
# nothing to clean). Required between failed/aborted init attempts.
sudo kubeadm reset -f

# kubeadm reset leaves these behind by design — clean up so the next
# init starts fresh.
sudo rm -rf /etc/cni/net.d
sudo rm -rf $HOME/.kube
sudo iptables -F && sudo iptables -t nat -F && sudo iptables -t mangle -F && sudo iptables -X
```

Worker-side reset (before re-joining):

```bash
sudo kubeadm reset -f
sudo rm -rf /etc/cni/net.d
```

## Initialise the control plane

On the control-plane node only:

```bash
sudo kubeadm init --pod-network-cidr=192.168.0.0/16

# After init, set up kubectl for your user.
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
```

The `kubeadm init` output contains a `kubeadm join` command with a
token and discovery hash. Note it down; the worker nodes need it.

## Install Calico CNI

```bash
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.29.0/manifests/calico.yaml

# Wait for Calico pods to come up.
kubectl -n kube-system wait --for=condition=Ready pod -l k8s-app=calico-node --timeout=180s
```

Note: Calico is pinned at v3.29.0 (April 2026 release). The original
architecture document referenced v3.27. The bump and the reasons are
recorded in `docs/deferred-decisions.md`.

## Join worker nodes

On each worker, run the `kubeadm join` line printed by `kubeadm init`
on the control plane:

```bash
sudo kubeadm join <control-plane-host>:6443 \
  --token <token> \
  --discovery-token-ca-cert-hash sha256:<hash>
```

Verify all three nodes are `Ready`:

```bash
kubectl get nodes -o wide
```

## Install the Olaitan Helm chart

From your workstation (with kubeconfig pointing at the new cluster):

```bash
# Helm repos and subchart deps. Idempotent.
./deploy/demo/setup.sh --apply

# Default install. The chart installs Falco, NATS, and Redis as subcharts;
# disable any of those by overriding `<name>.enabled=false` if the
# operator already runs that infra.
helm install olaitan ./deploy/helm/olaitan
```

Verify the workloads come up:

```bash
kubectl get pods -l app.kubernetes.io/name=olaitan
```

## Verifying the procedure

A complete bootstrap is verified when all of the following hold:

1. `kubectl get nodes` shows three `Ready` nodes.
2. `kubectl get pods -A` has zero pods stuck in `CrashLoopBackOff`,
   `ImagePullBackOff`, or `Pending` for more than 60 seconds after the
   chart install completes.
3. `helm test olaitan` returns success (chart-level smoke test;
   Story 1.7 will add the audit-webhook reachability test).

## Limitations and known caveats

- This procedure assumes a clean install on hardware (or a hardware-like
  VM) with the resource envelope above. Cloud-provider managed clusters
  (EKS, GKE, AKS) are out of scope: their networking, audit, and CNI
  defaults differ enough that the chart's NetworkPolicy and (in Story
  1.7) audit-webhook wiring need different overlays.
- The eBPF kernel 6.5+ requirement is a hard floor for the Falco driver
  Olaitan ships with. On older kernels the Falco subchart can be
  reconfigured to use the kernel module, but Olaitan's evaluation
  numbers were collected under eBPF only.
- The Calico v3.29.0 manifest is the upstream `calico.yaml` (operator
  install). Production overlays may prefer the Tigera Operator install,
  which is not used by the evaluation harness.

## References

- `deploy/demo/setup.sh` — the executable companion to this document.
- `deploy/helm/README.md` — operator-facing chart configuration guide.
- `docs/deferred-decisions.md` — the Calico v3.27 to v3.29.0 ADR.
- Architecture: `_bmad-output/planning-artifacts/architecture.md` in
  the FYP repository.
