# Provider and version constraints for the Olaitan evaluation cluster.
#
# The cluster this stack builds is the one `hack/bootstrap-kubeadm.md`
# specifies: three Ubuntu 22.04 nodes at 4 vCPU / 6 GB / 50 GB, running
# kubeadm 1.29 on containerd 1.7 with a kernel new enough for the Falco
# eBPF driver. Everything the evaluation harness assumes about the
# cluster envelope (PRD NFR1) is expressed here as pinned inputs, so a
# campaign can be rebuilt byte-for-byte from this directory.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region  = var.region
  profile = var.profile

  default_tags {
    tags = {
      Project   = "olaitan"
      Component = "eval-cluster"
      ManagedBy = "terraform"
    }
  }
}
