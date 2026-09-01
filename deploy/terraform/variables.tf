variable "region" {
  description = "AWS region. Kept single-region and single-AZ so node-to-node latency does not contaminate MTTD measurements."
  type        = string
  default     = "us-east-1"
}

variable "availability_zone" {
  description = "All three nodes share one AZ. Cross-AZ hops would add latency to the very number the evaluation reports, and cross-AZ data transfer costs money for no scientific gain."
  type        = string
  default     = "us-east-1a"
}

variable "profile" {
  # `default` rather than one developer's profile name, which nobody else
  # has configured.
  description = "Local AWS CLI profile to authenticate with."
  type        = string
  default     = "default"
}

variable "workstation_cidr" {
  description = "The ONLY CIDR allowed to reach SSH (22) and the Kubernetes API (6443). Set this to your workstation's public /32. There is deliberately no default: an accidental 0.0.0.0/0 on a cluster that runs live attack scenarios is not a mistake worth making convenient."
  type        = string

  validation {
    condition     = can(cidrhost(var.workstation_cidr, 0)) && var.workstation_cidr != "0.0.0.0/0"
    error_message = "workstation_cidr must be a valid CIDR and must not be 0.0.0.0/0."
  }
}

variable "key_name" {
  # No default. It used to default to one developer's key pair name, which
  # could only ever work for that account: AWS rejects an unknown key pair,
  # so anyone else got a confusing apply-time failure instead of being told
  # up front what to set. Required is the honest shape for a value only the
  # operator can know.
  description = "Name of an existing EC2 key pair in this account/region, for SSH access to the nodes. Required."
  type        = string
}

variable "node_instance_type" {
  description = <<-EOT
    Instance type for every node.

    The spec in hack/bootstrap-kubeadm.md is 4 vCPU / 6 GB, which
    c5.xlarge (4 vCPU / 8 GiB) would satisfy. It is NOT the default here,
    because an AWS account on the post-July-2025 Free plan cannot launch
    it: RunInstances rejects any type that is not free-tier-eligible with
    InvalidParameterCombination, regardless of available credit.

    Every free-tier-eligible type is 2 vCPU. m7i-flex.large is the
    largest of them at 2 vCPU / 8 GiB, so it clears the 6 GB memory
    floor but delivers HALF the specified CPU.

    This matters to the evaluation, not just to the bill. Resource
    overhead is one of the reported measures, and it is reported against
    the 4 vCPU / 6 GB envelope. Numbers collected here are collected on
    half that CPU. Detection correctness (MTTD ordering, FPR, FSM
    outcomes) is far less sensitive to it than throughput and overhead
    are, but the deviation is real and belongs in the write-up.

    To run at spec, the account has to leave the Free plan, or the
    cluster has to live somewhere without that restriction.
  EOT
  type        = string
  default     = "m7i-flex.large"
}

variable "worker_count" {
  description = "Number of worker nodes. The architecture's target topology is one control plane plus two workers."
  type        = number
  default     = 2
}

variable "root_volume_gb" {
  description = "Root volume size per node, in GB. The spec calls for 50 GB."
  type        = number
  default     = 50
}

variable "vpc_cidr" {
  description = "CIDR for the dedicated evaluation VPC. Must not overlap the Calico pod CIDR (192.168.0.0/16) that kubeadm init is given."
  type        = string
  default     = "10.77.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0)) && !startswith(var.vpc_cidr, "192.168.")
    error_message = "vpc_cidr must be a valid CIDR and must not sit inside 192.168.0.0/16, which is the Calico pod network."
  }
}

# --- Pinned software versions -------------------------------------------
#
# These are the reproducibility-relevant pins. `eval/manifest.yaml` records
# kubernetes_patch_version but does NOT currently pin containerd or the
# kernel, both of which the Falco eBPF driver and the CRI collector are
# sensitive to. They are pinned here so a rebuild is deterministic; see
# README.md for the argument that they belong in the manifest too.

variable "k8s_package_version" {
  description = "Exact apt version for kubeadm, kubelet and kubectl. 1.29.15-1.1 is the final 1.29 patch, matching the Chart.yaml kubeVersion floor of >=1.29.0."
  type        = string
  default     = "1.29.15-1.1"
}

variable "k8s_repo_minor" {
  description = "Minor-version stream of the pkgs.k8s.io apt repository."
  type        = string
  default     = "v1.29"
}

variable "containerd_version" {
  description = "Exact apt version of containerd.io from Docker's repository. Ubuntu 22.04's own 'containerd' package is NOT 1.7.x any more (jammy ships 1.5.9, jammy-updates has moved to 2.2.1), so following bootstrap-kubeadm.md's plain `apt-get install containerd` no longer produces the documented runtime."
  type        = string
  default     = "1.7.29-1~ubuntu.22.04~jammy"
}

variable "kernel_meta_package" {
  description = "Kernel meta-package to install. Ubuntu 22.04's default linux-aws kernel is 5.15, below the 6.5+ floor that bootstrap-kubeadm.md sets for the Falco eBPF driver. linux-aws-6.8 is the AWS-tuned 6.8 series."
  type        = string
  default     = "linux-aws-6.8"
}

variable "pod_network_cidr" {
  description = "Pod network CIDR passed to kubeadm init. Calico's default."
  type        = string
  default     = "192.168.0.0/16"
}

variable "ssh_private_key_path" {
  description = "Local path to the private key matching key_name, used only to render the `ssh` output. Nothing is read from it; it is a convenience so the printed command is copy-pasteable. Defaults to the conventional path for key_name."
  type        = string
  default     = ""
}
