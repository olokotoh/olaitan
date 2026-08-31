# Evaluation cluster (Terraform)

Builds the three-node kubeadm cluster that `hack/bootstrap-kubeadm.md`
specifies, on AWS EC2, so an evaluation campaign can be run, torn down,
and rebuilt identically.

This stack takes you as far as three bootstrapped nodes. It deliberately
stops before `kubeadm init`: that step needs a join token that only
exists once the control plane is up, and the bootstrap document is
explicit that the operator should review and run those commands by hand.

## Quick start

```bash
cp example.tfvars terraform.tfvars   # set workstation_cidr to your /32
make init
make up
make wait          # nodes finish bootstrapping (and reboot if the kernel changed)
make versions      # confirm what actually landed on each node
make cp            # SSH to oltn-cp-1 and run kubeadm init
```

When you are between sessions:

```bash
make stop          # keeps the disks, stops the per-hour compute charge
make start         # public IPs will be new; private IPs are preserved
```

When the campaign is finished and `runs/` artefacts are pulled:

```bash
make down
```

## Why these choices

**Managed Kubernetes is not an option here.** EKS, GKE and AKS are ruled
out by `hack/bootstrap-kubeadm.md` itself. The blocking reason is Story
1.7: the audit webhook needs `--audit-policy-file` and
`--audit-webhook-config-file` on the kube-apiserver command line
(`hack/audit-apiserver-patch.yaml`). On a managed control plane you do
not own that process. EKS can ship audit logs to CloudWatch, which is a
different thing from delivering them to Olaitan's receiver. Calico via
the Tigera operator, which Story 1.10's flow adapter needs for Goldmane,
is a second conflict, against the AWS VPC CNI.

**One availability zone, on purpose.** The evaluation reports
time-to-detect. Cross-AZ hops would add latency to the measured quantity
and cost money for no scientific benefit.

**Node shape is capped by the account, not chosen freely.** See "The
CPU deviation" below. The spec is 4 vCPU / 6 GB; the default here is
m7i-flex.large at 2 vCPU / 8 GiB, because that is the largest thing the
account is permitted to launch.

**Public subnets, no NAT gateway.** The nodes need substantial egress,
but only while a campaign runs. A NAT gateway is about $32/month
standing. Auto-assigned public IPs cost $0.005/hour each and are
released when an instance stops, so a 15-hour campaign pays roughly
$0.22. Inbound is closed to everything except `workstation_cidr`.

## The CPU deviation

This cluster runs at HALF the specified CPU, and that is a property of
the AWS account, not a choice.

`hack/bootstrap-kubeadm.md` specifies 4 vCPU / 6 GB / 50 GB per node,
sourced from PRD NFR1, and says plainly that "the 6 GB / 4 vCPU envelope
is what the evaluation harness assumes when reporting resource
overhead".

An account on the post-July-2025 AWS Free plan cannot launch a 4 vCPU
instance. `RunInstances` rejects anything outside the free-tier-eligible
list with `InvalidParameterCombination`, no matter how much plan credit
is available. The complete permitted list in us-east-1:

| Type | vCPU | Memory |
| --- | --- | --- |
| m7i-flex.large | 2 | 8 GiB |
| c7i-flex.large | 2 | 4 GiB |
| t3.small | 2 | 2 GiB |
| t4g.small | 2 | 2 GiB |
| t3.micro | 2 | 1 GiB |
| t4g.micro | 2 | 1 GiB |

Every one of them is 2 vCPU. m7i-flex.large is the only one that clears
the 6 GB memory floor, so it is the default.

What this does and does not compromise:

- **Memory envelope: met.** 8 GiB against a 6 GB floor.
- **Detection correctness: largely unaffected.** Whether a scenario is
  detected, which FSM state it reaches, and the false-positive rate on
  the benign sweep are not CPU-bound outcomes.
- **Time-to-detect: affected under load.** MTTD includes queueing
  through NATS and Redis and the analyst tier. Half the CPU can inflate
  it, particularly on the fuller RSLT arms.
- **Resource overhead: measured off-spec.** This is the number the
  document explicitly ties to the envelope. Overhead measured on 2 vCPU
  is not the overhead of the specified node, and reporting it as such
  would be wrong.

Three honest ways forward:

1. **Run here and disclose it.** Amend the pre-registration the way A1
   and A2 already amend it for the model substitution, state the
   envelope actually used, and report overhead against 2 vCPU rather
   than claiming the 4 vCPU figure.
2. **Move the account off the Free plan.** Plan credits carry over, and
   the restriction lifts. This is the account owner's decision.
3. **Run the cluster somewhere without the restriction.** Any provider
   that will sell three 4 vCPU / 8 GB machines by the hour meets spec,
   and dedicated-vCPU shapes are better for overhead measurement than
   any burstable or flex instance in the table above.

Option 1 is legitimate if disclosed. It is not legitimate if silent.

## Two places the bootstrap document no longer reproduces

Both are handled in `user_data.sh.tftpl`, and both are worth folding
back into `hack/bootstrap-kubeadm.md`.

**containerd.** The document says `apt-get install -y containerd` and
expects 1.7.x. That is no longer what Ubuntu 22.04 gives you:

| Source | Version |
| --- | --- |
| jammy | 1.5.9-0ubuntu3 |
| jammy-updates | 2.2.1-0ubuntu1~22.04.2 |

Neither is the documented runtime, and containerd 2.x renames the CRI
plugin key that the document's `SystemdCgroup` edit targets. This stack
installs `containerd.io` from Docker's repository at an exact pinned
1.7.x and holds the package.

**Kernel.** The document sets a hard floor of 6.5+ for the Falco eBPF
driver, and warns that below it Falco falls back to a kernel module,
while the evaluation numbers were collected under eBPF only. Current
jammy AMIs already satisfy this: `ubuntu-jammy-22.04-amd64-server-20260826`
boots `6.8.0-1063-aws` out of the box, so the meta-package install is a
confirmation rather than a change, and the node does not reboot. It is
kept because the floor is worth pinning explicitly rather than
inheriting from whichever AMI the SSM pointer happens to resolve to, and
`user_data.sh.tftpl` now asserts the floor and fails the boot rather
than letting an old kernel through quietly.

## A gap in the reproducibility envelope

`eval/manifest.yaml` pins `kubernetes_patch_version` but pins neither
containerd nor the kernel. Both feed the CRI collector and the Falco
eBPF driver directly, so both can move detection results without
changing the manifest hash. This stack pins them as Terraform variables
and `make versions` prints what each node actually installed, from
`/etc/olaitan-bootstrap.json`. Consider promoting them to real manifest
fields and recording them in run metadata.

Note also that `kubernetes_patch_version` is `1.29.x`, a range rather
than a pin. The nodes here install exactly `1.29.15-1.1`.

## Cost

On an account still on the AWS Free plan, compute and storage here draw
down plan credits rather than billing a card, and the plan refuses
anything outside the free-tier-eligible list anyway.

| Item | Rate |
| --- | --- |
| 3 x m7i-flex.large, running | about $0.31/hour |
| 3 x 50 GB gp3, always | about $12/month |
| 3 x public IPv4, only while running | $0.015/hour |

A 200-run campaign is a few hours of wall clock. Budget 10 to 15 hours
of cluster uptime including bootstrap and reruns. `make stop` between
sessions is the difference between paying for disks and paying for a
cluster.

At spec on 3 x c5.xlarge the compute rate would be about $0.51/hour,
which the same credit balance would comfortably cover; the obstacle is
the plan restriction, not the money.

## Files

| File | Purpose |
| --- | --- |
| `versions.tf` | Terraform and provider constraints |
| `variables.tf` | Inputs, including every software pin |
| `main.tf` | VPC, subnet, security group, three nodes |
| `user_data.sh.tftpl` | Node bootstrap, the executable form of the prerequisite sections of `hack/bootstrap-kubeadm.md` |
| `outputs.tf` | Addresses, pinned versions, next steps |
| `Makefile` | Lifecycle: up, wait, versions, stop, start, down |

`.terraform.lock.hcl` is tracked on purpose. It pins provider checksums,
which is the kind of thing a reproducibility envelope should hold fixed.
State is not tracked; if this stack is ever shared, move state to an S3
backend with locking first.
