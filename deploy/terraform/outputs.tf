output "control_plane" {
  description = "Control-plane node addresses."
  value = {
    name       = "oltn-cp-1"
    public_ip  = aws_instance.node["oltn-cp-1"].public_ip
    private_ip = aws_instance.node["oltn-cp-1"].private_ip
  }
}

output "workers" {
  description = "Worker node addresses, keyed by node name."
  value = {
    for name, inst in aws_instance.node : name => {
      public_ip  = inst.public_ip
      private_ip = inst.private_ip
    }
    if inst.tags["Role"] == "worker"
  }
}

output "instance_ids" {
  description = "All instance IDs, for the stop and start targets in the Makefile."
  value       = [for inst in aws_instance.node : inst.id]
}

output "ssh" {
  description = "Ready-to-paste SSH commands, one per node."
  value = {
    for name, inst in aws_instance.node :
    name => "ssh -i ~/.ssh/aslim-aws-ubuntu.pem ubuntu@${inst.public_ip}"
  }
}

output "pinned_versions" {
  description = "The software pins this cluster was built with. Record these in eval/manifest.yaml alongside kubernetes_patch_version, and in every run's metadata."
  value = {
    kubernetes = var.k8s_package_version
    containerd = var.containerd_version
    kernel     = var.kernel_meta_package
    ami        = local.ami_id
    node_shape = var.node_instance_type
  }
}

output "next_steps" {
  description = "What to run once the nodes finish bootstrapping."
  value       = <<-EOT
    1. Wait for bootstrap (each node installs a kernel and reboots):
         make wait

    2. On the control plane, initialise:
         sudo kubeadm init --pod-network-cidr=${var.pod_network_cidr}

       For the Story 1.7 audit webhook, place the policy and kubeconfig
       first and init with the patch instead, per deploy/helm/olaitan/AUDIT.md
       and hack/audit-apiserver-patch.yaml. Doing it now is far easier than
       retrofitting it onto a running control plane.

    3. Join each worker with the printed kubeadm join line.

    4. Install Calico v3.31.5 via the Tigera operator, then the chart.
       Both command sets are in hack/bootstrap-kubeadm.md.
  EOT
}
