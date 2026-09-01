# Olaitan evaluation cluster: three kubeadm nodes in a dedicated VPC.
#
# Why a dedicated VPC and not the account's default one: the evaluation
# scenarios (S1 through S5) are live attack simulations. Running them
# next to anything else in a shared network is a needless risk, and a
# separate VPC costs nothing (internet gateways, subnets and route
# tables are free; only NAT gateways bill, and this stack has none).
#
# Why public subnets rather than private ones behind a NAT gateway: the
# nodes need heavy egress (apt, pkgs.k8s.io, GHCR, Calico manifests, the
# analyst model's API) but only for the hours a campaign is actually
# running. A NAT gateway is $32/month standing. Auto-assigned public IPs
# bill at $0.005/hour each and are released the moment an instance
# stops, so a 15-hour campaign pays about $0.22 instead. Inbound is
# closed to everything except var.workstation_cidr.

data "aws_ssm_parameter" "ubuntu_2204" {
  name = "/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id"
}

resource "aws_vpc" "eval" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "olaitan-eval" }
}

resource "aws_internet_gateway" "eval" {
  vpc_id = aws_vpc.eval.id

  tags = { Name = "olaitan-eval" }
}

resource "aws_subnet" "eval" {
  vpc_id                  = aws_vpc.eval.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 0)
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = true

  tags = { Name = "olaitan-eval" }
}

resource "aws_route_table" "eval" {
  vpc_id = aws_vpc.eval.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.eval.id
  }

  tags = { Name = "olaitan-eval" }
}

resource "aws_route_table_association" "eval" {
  subnet_id      = aws_subnet.eval.id
  route_table_id = aws_route_table.eval.id
}

# --- Security group ------------------------------------------------------
#
# Node-to-node is wide open WITHIN the group (kubeadm, etcd, the kubelet
# API, Calico BGP/VXLAN, NATS, Redis and the Falco gRPC socket between
# them span a range wide enough that enumerating ports would be a
# fiction). Everything from outside is denied except SSH and the API
# server, and only from the operator's own address.

resource "aws_security_group" "node" {
  name        = "olaitan-eval-node"
  description = "Olaitan evaluation cluster nodes"
  vpc_id      = aws_vpc.eval.id

  tags = { Name = "olaitan-eval-node" }
}

resource "aws_vpc_security_group_ingress_rule" "intra" {
  security_group_id            = aws_security_group.node.id
  referenced_security_group_id = aws_security_group.node.id
  ip_protocol                  = "-1"
  description                  = "All node-to-node traffic within the cluster"
}

resource "aws_vpc_security_group_ingress_rule" "ssh" {
  security_group_id = aws_security_group.node.id
  cidr_ipv4         = var.workstation_cidr
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
  description       = "SSH from the operator workstation only"
}

resource "aws_vpc_security_group_ingress_rule" "apiserver" {
  security_group_id = aws_security_group.node.id
  cidr_ipv4         = var.workstation_cidr
  from_port         = 6443
  to_port           = 6443
  ip_protocol       = "tcp"
  description       = "Kubernetes API from the operator workstation only"
}

resource "aws_vpc_security_group_egress_rule" "all" {
  security_group_id = aws_security_group.node.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
  description       = "Package, image and analyst-model egress"
}

# --- Nodes ---------------------------------------------------------------

locals {
  # aws_ssm_parameter marks every value sensitive because a parameter
  # MAY hold a secret. This one is a public AMI id, and it needs to be
  # readable in outputs so a campaign can record what it ran on.
  ami_id = nonsensitive(data.aws_ssm_parameter.ubuntu_2204.value)

  bootstrap = templatefile("${path.module}/user_data.sh.tftpl", {
    k8s_package_version = var.k8s_package_version
    k8s_repo_minor      = var.k8s_repo_minor
    containerd_version  = var.containerd_version
    kernel_meta_package = var.kernel_meta_package
  })

  # oltn-cp-1, oltn-w-1, oltn-w-2: the names hack/bootstrap-kubeadm.md uses.
  nodes = merge(
    { "oltn-cp-1" = "control-plane" },
    { for i in range(var.worker_count) : "oltn-w-${i + 1}" => "worker" },
  )
}

resource "aws_instance" "node" {
  for_each = local.nodes

  ami                    = local.ami_id
  instance_type          = var.node_instance_type
  subnet_id              = aws_subnet.eval.id
  vpc_security_group_ids = [aws_security_group.node.id]

  # EC2 drops any packet whose source/destination IP does not belong to the
  # instance. Every CNI overlay violates that by design: a VXLAN packet leaving
  # this node carries a POD IP (192.168.0.0/16), not the node's 10.77.0.0/24
  # address, so AWS silently discards it. No error, no log, no dropped-packet
  # counter -- the traffic simply never arrives.
  #
  # Left at the default (true) this produces a cluster that looks healthy and
  # is not: nodes Ready, pods Running, and any pod that needs a pod on ANOTHER
  # node fails. Observed on this exact module before the fix -- both CoreDNS
  # replicas landed on one node, so DNS worked there and timed out everywhere
  # else, which surfaced as "lookup olaitan-nats: i/o timeout" in the
  # aggregator, a Falco DaemonSet Running on 1 of 3 nodes, and Calico's own
  # APIService failing its discovery check.
  #
  # Required for kubeadm-on-EC2 with any overlay CNI (Calico VXLAN, flannel).
  # Managed services set it for you; a hand-rolled cluster must set it itself.
  source_dest_check = false
  key_name          = var.key_name
  user_data         = local.bootstrap

  # Changing the bootstrap script must rebuild the node. A half-migrated
  # kubeadm host is worse than a fresh one, and these are cattle.
  user_data_replace_on_change = true

  root_block_device {
    volume_size           = var.root_volume_gb
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  tags = {
    Name = each.key
    Role = each.value
  }
}
